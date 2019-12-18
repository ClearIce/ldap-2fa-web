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
    if current_user.is_authenticated:
        return redirect(url_for('main.profile'))

    return render_template('index.html')

@main.route('/profile')
@login_required
def profile():
    authenticator_data = ldapQuery()
    #print("authenticator_data: ", authenticator_data)

    twofactor_enabled_for_user = not (authenticator_data == b'None' or authenticator_data == None)
    print("twofactor_enabled_for_user: ", twofactor_enabled_for_user)

    if twofactor_enabled_for_user:
        if ('twofactor_authenticated' not in session) or (not session['twofactor_authenticated']):
            # User has not done 2FA yet
            print('NEED 2FA AUTHENTICATION')
            return redirect(url_for('auth.twofactor'))
        else:
            # 2FA device registered, and user has authenticated with it
            print('2FA AUTHED')
            flash('You are the most secure person in the world!')
            return render_template('profile.html', name=current_user.name, user_is_super_secure=True)
    elif not twofactor_enabled_for_user:
        # 2FA Not enabled, tell user to enable it
        print('NO 2FA DEVICE FOR USER')
        flash('You should really register a Two Factor authenticator!')
        return render_template('profile.html', name=current_user.name)


