Authentication with LDAP/Active Directory
=========================================

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
