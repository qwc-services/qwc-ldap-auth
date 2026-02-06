[![](https://github.com/qwc-services/qwc-ldap-auth/workflows/build/badge.svg)](https://github.com/qwc-services/qwc-ldap-auth/actions)
[![docker](https://img.shields.io/docker/v/sourcepole/qwc-ldap-auth?label=Docker%20image&sort=semver)](https://hub.docker.com/r/sourcepole/qwc-ldap-auth)

QWC LDAP Auth Service
=====================

Authentication with LDAP/Active Directory.

Configuration
-------------

The static config files are stored as JSON files in `$CONFIG_PATH` with subdirectories for each tenant,
e.g. `$CONFIG_PATH/default/*.json`. The default tenant name is `default`.

### LDAP service config

* [JSON schema](schemas/qwc-ldap-auth.json)
* File location: `$CONFIG_PATH/<tenant>/ldapAuth.json`


### Environment variables

Config options in the config file can be overridden by equivalent uppercase environment variables.

In addition, the following environment variables are supported:

| Name                            | Default                 | Description
|---------------------------------|-------------------------|----------------------------------------------------
| `JWT_SECRET_KEY`                | `********`              | Secret key for JWT token (same for all services)
| `LDAP_HOST`                     | `localhost`             | Hostname of your LDAP Server
| `LDAP_PORT`                     | `389`                   | The port number of your LDAP server.
| `LDAP_USE_SSL`                  | `False`                 | Set to True if your server uses SSL
| `LDAP_BASE_DN`                  | `dc=example,dc=org`     | Base DN of your directory
| `LDAP_USER_DN`                  | `ou=users`              | Users DN to be prepended to the Base DN
| `LDAP_GROUP_DN`                 | `ou=groups`             | Groups DN to be prepended to the Base DN
| `LDAP_SEARCH_FOR_GROUPS`        | `False`                 | Search for groups
| `LDAP_GROUP_SEARCH_SCOPE`       | `LEVEL`                 | Specifies what scope to search in when searching for a specific group
| `LDAP_GROUP_OBJECT_FILTER`      | `(objectclass=group)`   | Specifies what object filter to apply when searching for groups
| `LDAP_GROUP_MEMBERS_ATTR`       | `uniqueMember`          | Specifies the LDAP attribute where group members are declared
| `LDAP_GROUP_NAME_ATTRIBUTE`     | `cn`                    | Group name attribute in LDAP group response
| `LDAP_GET_GROUP_ATTRIBUTES`     | `*` (ALL_ATTRIBUTES)    | Specifies which LDAP attributes to get when searching LDAP for a group/groups
| `LDAP_USER_SEARCH_SCOPE`        | `LEVEL`                 | Specifies what scope to search in when searching for a specific user
| `LDAP_USER_RDN_ATTR`            | `cn`                    | The RDN attribute for your user schema on LDAP
| `LDAP_USER_LOGIN_ATTR`          | `cn`                    | The Attribute you want users to authenticate to LDAP with
| `LDAP_BIND_USER_DN`             | `None`                  | The Username to bind to LDAP with
| `LDAP_BIND_USER_PASSWORD`       | `None`                  | The Password to bind to LDAP with
| `GROUP_MAPPINGS`                | `None`                  | Expressions for group name mapping

See also [flask-ldap3-login](https://flask-ldap3-login.readthedocs.io/en/latest/configuration.html)


## Customization

You can add a custom logo and a custom background image by setting the following `config` options:

```json
"config": {
  "background_image_url": "<url>",
  "logo_image_url": "<url>"
}
```

The specified URLs can be absolute or relative. For relative URLs, you can write i.e.

```json
"config": {
  "background_image_url": "/auth/static/background.jpg",
  "logo_image_url": "/auth/static/logo.jpg"
}
```

where `/auth` is the service mountpoint and place your custom images inside the `static` subfolder of the auth-service, or, if using docker and docker-compose, mount them accordingly:

    qwc-auth-service:
      [...]
      volumes:
        - ./volumes/assets/Background.jpg:/srv/qwc_service/static/background.jpg
        - ./volumes/assets/logo.png:/srv/qwc_service/static/logo.jpg

Run locally
-----------

Install dependencies and run:

    export CONFIG_PATH=<CONFIG_PATH>
    uv run src/server.py

To use configs from a `qwc-docker` setup, set `CONFIG_PATH=<...>/qwc-docker/volumes/config`.

Set `FLASK_DEBUG=1` for additional debug output.

Set `FLASK_RUN_PORT=<port>` to change the default port (default: `5000`).

Docker usage
------------

The Docker image is published on [Dockerhub](https://hub.docker.com/r/sourcepole/qwc-ldap-auth).

See sample [docker-compose.yml](https://github.com/qwc-services/qwc-docker/blob/master/docker-compose-example.yml) of [qwc-docker](https://github.com/qwc-services/qwc-docker).

Testing
-------

Testing with https://github.com/rroemhild/docker-test-openldap

    docker run -d -p 10389:10389 -p 10636:10636 rroemhild/test-openldap:2.1

Start service:

    LDAP_PORT=10389 LDAP_BIND_USER_DN="cn=admin,dc=planetexpress,dc=com" LDAP_BIND_USER_PASSWORD=GoodNewsEveryone LDAP_BASE_DN="dc=planetexpress,dc=com" LDAP_USER_DN="ou=people" LDAP_GROUP_DN="ou=people" LDAP_SEARCH_FOR_GROUPS=True LDAP_GROUP_MEMBERS_ATTR="member" uv run src/server.py

* User: Philip J. Fry
* Password: fry

Service login test:

    curl http://localhost:5017/verify_login -d 'username=Philip J. Fry' -d 'password=fry'
