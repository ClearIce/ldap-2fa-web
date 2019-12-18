# auth.py
from fido2.webauthn import PublicKeyCredentialRpEntity
from fido2.client import ClientData
from fido2.server import Fido2Server
from fido2.ctap2 import AttestationObject, AuthenticatorData, AttestedCredentialData
from fido2.utils import websafe_encode, websafe_decode
from fido2 import cbor

from flask import session, Blueprint, render_template, redirect, url_for, request, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import current_user, login_user, logout_user, login_required
from .models import User
from . import db

import ldap

auth = Blueprint('auth', __name__)

rp = PublicKeyCredentialRpEntity("localhost", "Demo server")

# What is the trade off for marking attestation?
#server = Fido2Server(rp)
server = Fido2Server(rp, attestation="direct") 
# attestation="direct" means we'll know the make/model and unique ID of the authenticator
# WITHOUT this, the authentication isn't working since the AAGUID is all zeroes and we get "Unknown credential ID" 
# Need to consider implications of this

def ldapQuery():
    # This should be in a separate module along with other LDAP CRUD ops
    SCOPE_SUBTREE = 2
    l = ldap.initialize('ldap://192.168.159.131:389')
    result = l.search_s('uid=clearice,ou=People,dc=testldap,dc=com', SCOPE_SUBTREE)
    ldap_encoded = result[0][1]['credential'][0]
    return ldap_encoded

def ldapStore(user, authenticator_data):
    print("TWO-FACTOR REGISTRATION: ", user, "\n", authenticator_data)
    

@auth.route('/login')
def login():
    return render_template('login.html')


@auth.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    user = User.query.filter_by(email=email).first()

    # check if user actually exists
    # take the user supplied password, hash it, and compare it to the hashed password in database
    if not user or not check_password_hash(user.password, password): 
        flash('Please check your login details and try again.')
        return redirect(url_for('auth.login')) # if user doesn't exist or password is wrong, reload the page

    # if the above check passes, then we know the user has the right credentials
    login_user(user, remember=remember)

    authenticator_data = ldapQuery()
    twofactor_enabled_for_user = (authenticator_data == "None" or authenticator_data == None)

    if twofactor_enabled_for_user:
        return redirect(url_for('auth.authenticate_begin'))
    else:
        flash('You should really register a Two Factor authenticator!')
        return redirect(url_for('main.profile'))


@auth.route('/signup')
def signup():
    return render_template('signup.html')


@auth.route('/signup', methods=['POST'])
def signup_post():

    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')

    user = User.query.filter_by(email=email).first() # if this returns a user, then the email already exists in database

    if user: # if a user is found, we want to redirect back to signup page so user can try again  
        flash('Email address already exists')
        return redirect(url_for('auth.signup'))

    # create new user with the form data. Hash the password so plaintext version isn't saved.
    new_user = User(email=email, name=name, password=generate_password_hash(password, method='sha256'))

    # add the new user to the database
    db.session.add(new_user)
    db.session.commit()

    return redirect(url_for('auth.login'))


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))


@auth.route("/api/register/begin", methods=["POST"])
@login_required
def register_begin():
    current_user.email # this is proxied to the User model in models.py, see /login method
    # The user id in this example app is a primary key, unsure if that is good for the id in register_begin

    # Logged in User ID / name would need to be verified from LDAP, don't just trust the user!
    
    # If we have a valid login, but no LDAP record, something is suspicious!

    registration_data, state = server.register_begin(
        {
            "id": b"user_id123",
            "name": "a_user123",
            "displayName": "A. User 123",
        },
        None,
        user_verification="discouraged",
        authenticator_attachment="cross-platform",
    )

    session["state"] = state # not sure what this represents yet, I don't think it needs to be stored?

    #print(registration_data)
    return cbor.encode(registration_data)


@auth.route("/api/register/complete", methods=["POST"])
@login_required
def register_complete():
    data = cbor.decode(request.get_data())
    client_data = ClientData(data["clientDataJSON"])
    att_obj = AttestationObject(data["attestationObject"])
    #print("clientData", client_data)
    #print("AttestationObject:", att_obj)

    auth_data = server.register_complete(session["state"], client_data, att_obj)

    encoded_creds = websafe_encode(auth_data.credential_data)
    #print("ENCODED CREDS: ", encodedCreds)
    # Then store encodedCreds to LDAP user profile
    ldapStore(current_user, encoded_creds)
    print("STORED CREDENTIAL:", current_user, encoded_creds)

    return cbor.encode({"status": "OK"})


@auth.route("/api/authenticate/begin", methods=["POST"])
# Should require another attribute that a Two-Factor authenticator is registered to the user
@login_required
def authenticate_begin():
    test = [AttestedCredentialData(websafe_decode(ldapQuery()))]
    print("TEST: ", test)

    auth_data, state = server.authenticate_begin(test)

    session["state"] = state
    return cbor.encode(auth_data)


@auth.route("/api/authenticate/complete", methods=["POST"])
# Should require another attribute that a Two-Factor authenticator is registered to the user
@login_required
def authenticate_complete():
    data = cbor.decode(request.get_data())
    credential_id = data["credentialId"]
    client_data = ClientData(data["clientDataJSON"])
    auth_data = AuthenticatorData(data["authenticatorData"])
    signature = data["signature"]

    #print("clientData", client_data)
    #print("AuthenticatorData", auth_data)

    server.authenticate_complete(
        session.pop("state"),
        None,
        credential_id,
        client_data,
        auth_data,
        signature,
    )
    print("ASSERTION OK")
    return cbor.encode({"status": "OK"})