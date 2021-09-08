[![](https://github.com/qwc-services/qwc-ldap-auth/workflows/build/badge.svg)](https://github.com/qwc-services/qwc-ldap-auth/actions)
[![docker](https://img.shields.io/docker/v/sourcepole/qwc-ldap-auth?label=Docker%20image&sort=semver)](https://hub.docker.com/r/sourcepole/qwc-ldap-auth)

Authentication with LDAP/Active Directory
=========================================

Configuration
-------------

See also [flask-ldap3-login](https://flask-ldap3-login.readthedocs.io/en/latest/configuration.html)

ENV                             | default value           | description
--------------------------------|-------------------------|---------
`JWT_SECRET_KEY`                | `********`              | secret key for JWT token (same for all services) 
`LDAP_HOST`                     | `localhost`             | Hostname of your LDAP Server
`LDAP_PORT`                     | `389`                   | The port number of your LDAP server.
`LDAP_USE_SSL`                  | `False`                 | Set to True if your server uses SSL
`LDAP_BASE_DN`                  | `dc=example,dc=org`     | Base DN of your directory
`LDAP_USER_DN`                  | `ou=users`              | Users DN to be prepended to the Base DN
`LDAP_GROUP_DN`                 | `ou=groups`             | Groups DN to be prepended to the Base DN
`LDAP_SEARCH_FOR_GROUPS`        | `False`                 | Search for groups
`LDAP_GROUP_SEARCH_SCOPE`       | `LEVEL`                 | Specifies what scope to search in when searching for a specific group
`LDAP_USER_SEARCH_SCOPE`        | `LEVEL`                 | Specifies what scope to search in when searching for a specific user
`LDAP_USER_RDN_ATTR`            | `cn`                    | The RDN attribute for your user schema on LDAP
`LDAP_USER_LOGIN_ATTR`          | `cn`                    | The Attribute you want users to authenticate to LDAP with
`LDAP_BIND_USER_DN`             | `None`                  | The Username to bind to LDAP with
`LDAP_BIND_USER_PASSWORD`       | `None`                  | The Password to bind to LDAP with


Usage
-----

Run standalone application:

    python server.py

Endpoints:

    http://localhost:5017/login

    http://localhost:5017/logout


Development
-----------

Create a virtual environment:

    virtualenv --python=/usr/bin/python3 .venv

Activate virtual environment:

    source .venv/bin/activate

Install requirements:

    pip install -r requirements.txt

Start local service:

    python server.py
