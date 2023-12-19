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
`LDAP_GROUP_OBJECT_FILTER`      | `(objectclass=group)`   | Specifies what object filter to apply when searching for groups
`LDAP_GROUP_MEMBERS_ATTR`       | `uniqueMember`          | Specifies the LDAP attribute where group members are declared
`LDAP_GROUP_NAME_ATTRIBUTE`     | `cn`                    | Group name attribute in LDAP group response
`LDAP_GET_GROUP_ATTRIBUTES`     | `*` (ALL_ATTRIBUTES)    | Specifies which LDAP attributes to get when searching LDAP for a group/groups
`LDAP_USER_SEARCH_SCOPE`        | `LEVEL`                 | Specifies what scope to search in when searching for a specific user
`LDAP_USER_RDN_ATTR`            | `cn`                    | The RDN attribute for your user schema on LDAP
`LDAP_USER_LOGIN_ATTR`          | `cn`                    | The Attribute you want users to authenticate to LDAP with
`LDAP_BIND_USER_DN`             | `None`                  | The Username to bind to LDAP with
`LDAP_BIND_USER_PASSWORD`       | `None`                  | The Password to bind to LDAP with
`GROUP_MAPPINGS`                | `None`                  | Expressions for group name mapping


Usage
-----

Run standalone application:

    python src/server.py

Endpoints:

    http://localhost:5017/login

    http://localhost:5017/logout

    http://localhost:5017/verify_login


Development
-----------

Create a virtual environment:

    python3 -m venv .venv

Activate virtual environment:

    source .venv/bin/activate

Install requirements:

    pip install -r requirements.txt

Configure environment:

    echo FLASK_ENV=development >.flaskenv

Start local service:

    python src/server.py

Testing with https://github.com/rroemhild/docker-test-openldap

    docker run -d -p 10389:10389 -p 10636:10636 rroemhild/test-openldap:2.1

Start service:

    LDAP_PORT=10389 LDAP_BIND_USER_DN="cn=admin,dc=planetexpress,dc=com" LDAP_BIND_USER_PASSWORD=GoodNewsEveryone LDAP_BASE_DN="dc=planetexpress,dc=com" LDAP_USER_DN="ou=people" LDAP_GROUP_DN="ou=people" LDAP_SEARCH_FOR_GROUPS=True LDAP_GROUP_MEMBERS_ATTR="member" python src/server.py

* User: Philip J. Fry
* Password: fry

Service login test:

    curl http://localhost:5017/verify_login -d 'username=Philip J. Fry' -d 'password=fry'
