import os
import sys
import logging

from flask import Flask, jsonify, request, flash, render_template, redirect, \
    make_response, url_for, render_template_string
from flask_login import LoginManager, current_user, login_user, logout_user, \
    UserMixin
from flask_jwt_extended import (
    jwt_optional, create_access_token,
    jwt_refresh_token_required, create_refresh_token, get_csrf_token,
    get_jwt_identity, set_access_cookies,
    set_refresh_cookies, unset_jwt_cookies
)
from flask_ldap3_login import LDAP3LoginManager
from flask_ldap3_login.forms import LDAPLoginForm
from qwc_services_core.jwt import jwt_manager
from qwc_services_core.tenant_handler import (
    TenantHandler, TenantPrefixMiddleware, TenantSessionInterface)


app = Flask(__name__)

jwt = jwt_manager(app)
app.secret_key = app.config['JWT_SECRET_KEY']


# https://flask-ldap3-login.readthedocs.io/en/latest/quick_start.html

# Hostname of your LDAP Server
app.config['LDAP_HOST'] = os.environ.get('LDAP_HOST', 'localhost')

# The port number of your LDAP server.
app.config['LDAP_PORT'] = int(os.environ.get('LDAP_PORT', 389))

# Set to True if your server uses SSL
app.config['LDAP_USE_SSL'] = os.environ.get('LDAP_USE_SSL', False)

# Base DN of your directory
app.config['LDAP_BASE_DN'] = os.environ.get(
    'LDAP_BASE_DN', 'dc=example,dc=org')

# Users DN to be prepended to the Base DN
app.config['LDAP_USER_DN'] = os.environ.get('LDAP_USER_DN', 'ou=users')

# Groups DN to be prepended to the Base DN
app.config['LDAP_GROUP_DN'] = os.environ.get('LDAP_GROUP_DN', 'ou=groups')

# Search for groups
app.config['LDAP_SEARCH_FOR_GROUPS'] = os.environ.get(
    'LDAP_SEARCH_FOR_GROUPS', False)
# Specifies what scope to search in when searching for a specific group
app.config['LDAP_GROUP_SEARCH_SCOPE'] = os.environ.get(
     'LDAP_GROUP_SEARCH_SCOPE', 'LEVEL')

# Specifies what object filter to apply when searching for groups.
app.config['LDAP_GROUP_OBJECT_FILTER'] = os.environ.get(
    'LDAP_GROUP_OBJECT_FILTER', '(objectclass=group)')
# Specifies the LDAP attribute where group members are declared.
app.config['LDAP_GROUP_MEMBERS_ATTR'] = os.environ.get(
    'LDAP_GROUP_MEMBERS_ATTR', 'uniqueMember')

# Specifies what scope to search in when searching for a specific user
app.config['LDAP_USER_SEARCH_SCOPE'] = os.environ.get(
    'LDAP_USER_SEARCH_SCOPE', 'LEVEL')

# The RDN attribute for your user schema on LDAP
app.config['LDAP_USER_RDN_ATTR'] = os.environ.get('LDAP_USER_RDN_ATTR', 'cn')

# The Attribute you want users to authenticate to LDAP with.
app.config['LDAP_USER_LOGIN_ATTR'] = os.environ.get(
    'LDAP_USER_LOGIN_ATTR', 'cn')

# Default is ldap3.ALL_ATTRIBUTES (*)
app.config['LDAP_GET_USER_ATTRIBUTES'] = os.environ.get(
    'LDAP_GET_USER_ATTRIBUTES', '*')  # app.config['LDAP_USER_LOGIN_ATTR']

# The Username to bind to LDAP with
app.config['LDAP_BIND_USER_DN'] = os.environ.get('LDAP_BIND_USER_DN', None)

# The Password to bind to LDAP with
app.config['LDAP_BIND_USER_PASSWORD'] = os.environ.get(
    'LDAP_BIND_USER_PASSWORD', None)

# Group name attribute in LDAP group response
LDAP_GROUP_NAME_ATTRIBUTE = os.environ.get('LDAP_GROUP_NAME_ATTRIBUTE', 'cn')

# Default is ldap3.ALL_ATTRIBUTES (*)
app.config['LDAP_GET_GROUP_ATTRIBUTES'] = os.environ.get(
    'LDAP_GET_GROUP_ATTRIBUTES', '*')  # LDAP_GROUP_NAME_ATTRIBUTE


app.config['DEBUG'] = os.environ.get('FLASK_ENV', '') == 'development'
if app.config['DEBUG']:
    logging.getLogger('flask_ldap3_login').setLevel(logging.DEBUG)


login_manager = LoginManager(app)              # Setup a Flask-Login Manager
ldap_manager = LDAP3LoginManager(app)          # Setup a LDAP3 Login Manager.


if os.environ.get('TENANT_HEADER'):
    app.wsgi_app = TenantPrefixMiddleware(
        app.wsgi_app, os.environ.get('TENANT_HEADER'))

if os.environ.get('TENANT_HEADER') or os.environ.get('TENANT_URL_RE'):
    app.session_interface = TenantSessionInterface(os.environ)


# Create a dictionary to store the users in when they authenticate.
users = {}


# Declare an Object Model for the user, and make it comply with the
# flask-login UserMixin mixin.
class User(UserMixin):
    def __init__(self, dn, username, info, groups):
        self.dn = dn
        self.username = username
        if groups:
            # LDAP query returns a dict like
            #   [{'cn': 'dl_qwc_login_r', ...}]
            group_names = [
                g.get(LDAP_GROUP_NAME_ATTRIBUTE)
                for g in groups if not None
            ]
        else:
            group_names = None
        self.groups = group_names
        app.logger.debug("LDAP username: %s" % username)
        app.logger.debug("LDAP info: %s" % info)
        app.logger.debug("LDAP Groups: %s" % groups)

    def __repr__(self):
        return self.dn

    def get_id(self):
        return self.dn


# Declare a User Loader for Flask-Login.
# Simply returns the User if it exists in our 'database', otherwise
# returns None.
@login_manager.user_loader
def load_user(id):
    if id in users:
        return users[id]
    return None


# Declare The User Saver for Flask-Ldap3-Login
# This method is called whenever a LDAPLoginForm() successfully validates.
# Here you have to save the user, and return it so it can be used in the
# login controller.
@ldap_manager.save_user
def save_user(dn, username, info, groups):
    user = User(dn, username, info, groups)
    users[dn] = user
    return user


# Declare some routes for usage to show the authentication process.
@app.route('/')
def home():
    # Redirect users who are not logged in.
    if not current_user or current_user.is_anonymous:
        return redirect(url_for('login'))

    # User is logged in, so show them a page with their cn and dn.
    template = """
    <h1>Welcome: {{ current_user.data.cn }}</h1>
    <h2>{{ current_user.dn }}</h2>
    """

    return render_template_string(template)


@app.route('/login', methods=['GET', 'POST'])
def login():
    target_url = request.args.get('url', '/')
    if current_user.is_authenticated:
        return redirect(target_url)
    form = LDAPLoginForm()
    if form.validate_on_submit():
        user = form.user
        # flask_login stores user in session
        login_user(user)
        app.logger.info("Logging in as user '%s'" % user.username)
        app.logger.info("Groups: %s" % user.groups)
        if user.groups:
            identity = {'username': user.username, 'groups': user.groups}
        else:
            identity = user.username
        # Create the tokens we will be sending back to the user
        access_token = create_access_token(identity)
        # refresh_token = create_refresh_token(identity)

        resp = make_response(redirect(target_url))
        # Set the JWTs and the CSRF double submit protection cookies
        # in this response
        set_access_cookies(resp, access_token)
        return resp
    return render_template('login.html', title='Sign In', form=form)


@app.route('/logout', methods=['GET', 'POST'])
@jwt_optional
def logout():
    target_url = request.args.get('url', '/')
    resp = make_response(redirect(target_url))
    unset_jwt_cookies(resp)
    logout_user()
    return resp


if __name__ == '__main__':
    app.run(host='localhost', port=5017, debug=True)
