# repass-demo-website
## Install
RePass client is written in [Python](https://www.python.org/).
Dependencies are managed using [Poetry](https://python-poetry.org/).
[Install Poetry](https://python-poetry.org/docs/#installation) and run:
```
poetry install
poetry shell
```

Then you are in a shell with all necessary [Python](https://www.python.org/) versions and dependencies installed.

Alternatively, you can install the requirements listed in requirements.txt by using your favourite tool.

## Usage
Run a local webserver by executing `python repass-demo-website.py` or `flask run --cert=adhoc`.
In the latter, the `--cert=adhoc` extension is obligatory, as FIDO2 will not work without TLS in most cases.

Then, navigate to `https://localhost:5000` with any browser.

In the following, the procedure for a RePass protocol flow is explained:
1. Enter any username, that does not exist in the database, and `register` using a FIDO2 token.
1. Navigate to the settings page by clicking your username on the top right, then selecting `Settings`.
1. Check the list of registered recovery credentials, if necessary selecting `Add`.
1. Enter the credential ID and a description.
1. Log out of the application.
1. Enter the username and enroll a recovery token by pressing `recover`.
1. On the next page (RePass Recovery Status Page), copy the URL for the recovery approver and forward it to the party running the [RePass client](https://github.com/kiliant/repass-client).
1. Login using the recovered credential.

