"""
RePass demo website to demonstrate a service provider using
RePass.

Also see the file README.md in this directory for details.

Navigate to https://localhost:5000 using a web browser.
"""
from __future__ import absolute_import, print_function, unicode_literals

from app import create_app, db
from app.models import (Credential, RePassRecoveryApproval,
                        RePassRecoveryCredential, RePassRecoveryRequest, User)

app = create_app()


# make context available to easily query it from flask shell
@app.shell_context_processor
def make_shell_context():
    return {'db': db, 'User': User,
            'RePassRecoveryCredential': RePassRecoveryCredential,
            'RePassRecoveryRequest': RePassRecoveryRequest,
            'RePassRecoveryApproval': RePassRecoveryApproval,
            'Credential': Credential}


if __name__ == "__main__":
    print(__doc__)
    app.run(ssl_context="adhoc")
