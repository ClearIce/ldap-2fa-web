# main.py

from flask import session, Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required, current_user

import ldap

main = Blueprint('main', __name__)

def ldapQuery():
    # This should be in a separate module along with other LDAP CRUD ops
    SCOPE_SUBTREE = 2
    l = ldap.initialize('ldap://192.168.159.131:389')
    result = l.search_s('uid=clearice,ou=People,dc=testldap,dc=com', SCOPE_SUBTREE)
    ldap_encoded = result[0][1]['credential'][0]
    return ldap_encoded

@main.route('/')
def index():
    return render_template('index.html')

@main.route('/profile')
@login_required
def profile():
    authenticator_data = ldapQuery()
    print("authenticator_data: ", authenticator_data)

    twofactor_enabled_for_user = not (authenticator_data == b'None' or authenticator_data == None)
    print("twofactor_enabled_for_user: ", twofactor_enabled_for_user)

    if not twofactor_enabled_for_user:
        # User does not have a 2FA device
        flash('You should really register a Two Factor authenticator!')
        return redirect(url_for('main.profile'))    
    else:
        # User has a 2FA device but has not authenticated for session
        if not session['twofactor_authenticated']:
            return redirect(url_for('auth.twofactor'))

    # User has 2FA device and has authenticated for session
    return render_template('profile.html', name=current_user.name)
