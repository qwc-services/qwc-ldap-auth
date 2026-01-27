import os
import sys
import logging

from urllib.parse import urlparse
from flask import Flask, jsonify, request, flash, render_template, redirect, \
    make_response, url_for, render_template_string, get_flashed_messages, abort
from flask_login import LoginManager, current_user, login_user, logout_user, \
    UserMixin
from flask_jwt_extended import (
    create_access_token, create_refresh_token, get_csrf_token,
    set_access_cookies, set_refresh_cookies, unset_jwt_cookies
)
from flask_ldap3_login import LDAP3LoginManager, AuthenticationResponseStatus
from flask_ldap3_login.forms import LDAPLoginForm
import i18n
from qwc_services_core.auth import auth_manager, GroupNameMapper, optional_auth, get_identity
from qwc_services_core.config_models import ConfigModels
from qwc_services_core.database import DatabaseEngine
from qwc_services_core.runtime_config import RuntimeConfig
from qwc_services_core.tenant_handler import (
    TenantHandler, TenantPrefixMiddleware, TenantSessionInterface)


app = Flask(__name__)

app.config['JWT_COOKIE_SECURE'] = os.environ.get(
    'JWT_COOKIE_SECURE', 'False').lower() == 'true'
app.config['JWT_COOKIE_SAMESITE'] = os.environ.get(
    'JWT_COOKIE_SAMESITE', 'Lax')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = int(os.environ.get(
    'JWT_ACCESS_TOKEN_EXPIRES', 12*3600))

jwt = auth_manager(app)
app.secret_key = app.config['JWT_SECRET_KEY']

i18n.set('load_path', [os.path.join(
    os.path.dirname(__file__), 'translations')])
i18n.set('file_format', 'json')
SUPPORTED_LANGUAGES = ['en', 'de']
# *Enable* WTForms built-in messages translation
# https://wtforms.readthedocs.io/en/2.3.x/i18n/
app.config['WTF_I18N_ENABLED'] = False

# https://flask-ldap3-login.readthedocs.io/en/latest/quick_start.html

# Hostname of your LDAP Server
app.config['LDAP_HOST'] = os.environ.get('LDAP_HOST', 'localhost')

# The port number of your LDAP server.
app.config['LDAP_PORT'] = int(os.environ.get('LDAP_PORT', 389))

# Set to True if your server uses SSL
app.config['LDAP_USE_SSL'] = os.environ.get('LDAP_USE_SSL', 'False').lower() == 'true'

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
LDAP_USER_LOGIN_ATTR = os.environ.get('LDAP_USER_LOGIN_ATTR', 'cn')
app.config['LDAP_USER_LOGIN_ATTR'] = LDAP_USER_LOGIN_ATTR

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


if app.config['DEBUG']:
    logging.getLogger('flask_ldap3_login').setLevel(logging.DEBUG)


login_manager = LoginManager(app)              # Setup a Flask-Login Manager
ldap_manager = LDAP3LoginManager(app)          # Setup a LDAP3 Login Manager.


tenant_handler = TenantHandler(app.logger)

app.wsgi_app = TenantPrefixMiddleware(app.wsgi_app)
app.session_interface = TenantSessionInterface()


# Create a dictionary to store the users in when they authenticate.
users = {}


# Declare an Object Model for the user, and make it comply with the
# flask-login UserMixin mixin.
class User(UserMixin):
    def __init__(self, dn, username, info, groups):
        self.dn = dn

        # NOTE: get original LDAP username,
        #       as login username may be case insensitive
        ldap_username = info.get(LDAP_USER_LOGIN_ATTR)
        if ldap_username and isinstance(ldap_username, list):
            self.username = ldap_username[0]
        elif isinstance(ldap_username, str):
            self.username = ldap_username
        else:
            app.logger.warning(
                "Could not read attribute '%s' as username"
                % LDAP_USER_LOGIN_ATTR
            )
            self.username = username

        if groups:
            mapper = GroupNameMapper()
            # LDAP query returns a dict like
            #   [{'cn': 'dl_qwc_login_r', ...}]
            group_names = [
                mapper.mapped_group(g.get(LDAP_GROUP_NAME_ATTRIBUTE))
                for g in groups if not None
            ]
        else:
            group_names = []
        self.groups = group_names
        app.logger.debug("Login username: %s" % username)
        app.logger.debug("LDAP username: %s" % self.username)
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

    # User is logged in, so show them a page with their username and dn.
    template = """
    <h1>Welcome: {{ current_user.username }}</h1>
    <h2>{{ current_user.dn }}</h2>
    """

    return render_template_string(template)

@app.route('/identity')
@optional_auth
def index():
    return jsonify(get_identity())

@app.route('/login', methods=['GET', 'POST'])
def login():
    config_handler = RuntimeConfig("ldapAuth", app.logger)
    tenant = tenant_handler.tenant()
    config = config_handler.tenant_config(tenant)

    target_url = url_path(request.args.get('url', '/'))
    if current_user.is_authenticated:
        if current_user.groups:
            identity = {'username': current_user.username, 'groups': current_user.groups}
        else:
            identity = {'username': current_user.username}
        access_token = create_access_token(identity)
        resp = make_response(redirect(target_url))
        set_access_cookies(resp, access_token)
        return resp
    form = LDAPLoginForm(meta=wft_locales())
    form.logo = config.get("logo_image_url", {})
    form.background = config.get("background_image_url", {})

    if form.validate_on_submit():
        user = form.user
        # flask_login stores user in session
        login_user(user)
        app.logger.info("Logging in as user '%s'" % user.username)
        app.logger.info("Groups: %s" % user.groups)
        if user.groups:
            identity = {'username': user.username, 'groups': user.groups}
        else:
            identity = {'username': user.username}

        sync_user(config, user)

        # Create the tokens we will be sending back to the user
        access_token = create_access_token(identity)
        # refresh_token = create_refresh_token(identity)

        resp = make_response(redirect(target_url))
        # Set the JWTs and the CSRF double submit protection cookies
        # in this response
        set_access_cookies(resp, access_token)
        return resp
    elif form.submit():
        # Replace untranslated messages
        for field, errors in form.errors.items():
            if 'Invalid Username/Password.' in errors:
                errors.remove('Invalid Username/Password.')
                errors.append(i18n.t('auth.auth_failed'))

    login_hint = config.get('login_hint')
    if isinstance(login_hint, dict):
        login_hint = login_hint.get(
            i18n.get('locale'),
            login_hint.get('en', '')
        )

    return render_template('login.html', form=form, i18n=i18n,
                           title=i18n.t("auth.login_page_title"),
                           login_hint=login_hint)

def sync_user(config, ldap_user: User):
    db_url = config.get('db_url', 'postgresql:///?service=qwc_configdb')
    if db_url is None:
        return

    db_engine = DatabaseEngine()
    qwc_config_schema = config.get('qwc_config_schema', 'qwc_config')
    config_models = ConfigModels(
        db_engine, db_url,
        qwc_config_schema=qwc_config_schema,
    )

    UserType = config_models.model('users')
    UserInfoType = config_models.model('user_infos')

    with config_models.session() as db_session, db_session.begin():
        user = db_session.query(UserType).filter_by(name=ldap_user.username).first()

        if user is None:
            # create new user
            user = UserType()
            db_session.add(user)
            logging.debug(f"Create {ldap_user.username} in config DB")
        else:
            logging.debug(f"Update {ldap_user.username} in config DB")


        user.name = ldap_user.username
        # user.email = ldap_user.userinfo.get('email', '')

        user_info = user.user_info
        if user_info is None:
            # create new user_info
            user_info = UserInfoType()
            # assign to user
            user_info.user = user
            db_session.add(user_info)


@app.route('/verify_login', methods=['POST'])
def verify_login():
    """Verify user login (e.g. from basic auth header)."""
    req = request.form
    username = req.get('username')
    password = req.get('password')
    if username:
        result = ldap_manager.authenticate(username, password)

        if result.status == AuthenticationResponseStatus.success:
            user = ldap_manager._save_user(
                result.user_dn, result.user_id, result.user_info,
                result.user_groups
            )
            identity = {'username': user.username, 'groups': user.groups}
            # access_token = create_access_token(identity)
            return jsonify({"identity": identity})
        else:
            app.logger.info(
                "verify_login: Invalid username or password")
            abort(401)
    abort(401)


@app.route('/logout', methods=['GET', 'POST'])
@optional_auth
def logout():
    target_url = url_path(request.args.get('url', '/'))
    resp = make_response(redirect(target_url))
    unset_jwt_cookies(resp)
    logout_user()
    return resp


@app.route("/ready", methods=['GET'])
def ready():
    """ readyness probe endpoint """
    return jsonify({"status": "OK"})


@app.route("/healthz", methods=['GET'])
def healthz():
    """ liveness probe endpoint """
    return jsonify({"status": "OK"})


@app.before_request
def set_lang():
    i18n.set('locale',
             request.accept_languages.best_match(SUPPORTED_LANGUAGES) or 'en')


def wft_locales():
    return {'locales': [i18n.get('locale')]}


def url_path(url):
    """ Extract path and query parameters from URL """
    o = urlparse(url)
    parts = list(filter(None, [o.path, o.query]))
    return '?'.join(parts)


if __name__ == '__main__':
    app.logger.setLevel(logging.DEBUG)
    app.run(host='localhost', port=5017, debug=True)
