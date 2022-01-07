import hashlib
import json
import random
import string

from app import db, login_manager
from app.forms import LoginForm, RepassAddForm
from app.main import bp
from app.models import (Credential, RePassRecoveryApproval,
                        RePassRecoveryCredential, RePassRecoveryRequest, User)
from fido2 import cbor
from fido2.client import ClientData
from fido2.ctap2 import (AttestationObject, AttestedCredentialData,
                         AuthenticatorData)
from fido2.server import Fido2Server
from fido2.utils import websafe_decode, websafe_encode
from fido2.webauthn import (AuthenticatorAssertionResponse,
                            PublicKeyCredentialRpEntity)
from flask import (abort, flash, redirect, render_template, request, session,
                   url_for)
from flask_login import current_user, login_required, login_user, logout_user

rp = PublicKeyCredentialRpEntity("localhost", "Demo server")
server = Fido2Server(rp)


@bp.route("/", methods=["GET", "POST"])
def index():
    # for u, v in credentials.items():
    # print("========================")
    # print(f"User: {u}")
    # print(websafe_encode(v[0]))
    # print("========================")
    form = LoginForm()
    if form.validate_on_submit():
        if form.register.data:
            return render_template("register.html")
        elif form.authenticate.data:
            return render_template("authenticate.html")
        else:
            # fail
            pass
    return render_template("index.html", form=form)


@bp.route("/repass_rm/<credential_id>")
@login_required
def repass_rm(credential_id):
    rp_cred = RePassRecoveryCredential.query.filter_by(
        credential_id=credential_id).first()

    if rp_cred is None or rp_cred.user_id != current_user.id:
        abort(403)

    db.session.delete(rp_cred)
    db.session.commit()

    flash(
        f"Credential {rp_cred.credential_id} has been removed as recovery credential.")
    return redirect(url_for("main.settings"))


@bp.route("/repass_add", methods=["POST", "GET"])
@login_required
def repass_add():
    form = RepassAddForm()

    if form.validate_on_submit():
        repass_cred = RePassRecoveryCredential(
            credential_id=form.id.data, description=form.description.data, user_id=current_user.id)

        db.session.add(repass_cred)
        db.session.commit()
        return redirect(url_for("main.settings"))
    else:
        return render_template("repass_add.html", form=form)


@bp.route("/enroll_recovery/begin/<username>", methods=["POST"])
def recovery_enroll__begin(username):
    creds = []
    registration_data, state = server.register_begin(
        {
            "id": f"{random.randint(1,100000)}".encode(),
            "name": f"{username}",
            "displayName": f"{username}",
            "icon": "https://example.com/image.png",
        },
        creds,  # causes error once more than one creds are enrolled!!!
        user_verification="discouraged",
        authenticator_attachment="cross-platform",
    )

    session["state"] = state
    session["username"] = username
    # print("\n\n\n\n")
    # print(registration_data)
    # print("\n\n\n\n")
    return cbor.encode(registration_data)


@bp.route("/enroll_recovery/complete", methods=["POST"])
def recovery_enroll__complete():
    data = cbor.decode(request.get_data())
    client_data = ClientData(data["clientDataJSON"])
    att_obj = AttestationObject(data["attestationObject"])

    auth_data = server.register_complete(
        session["state"], client_data, att_obj)

    user = User.get_by_name(session["username"])
    credential = Credential(user_id=user.id)
    credential.websafe_credential = websafe_encode(auth_data.credential_data)

    id = hashlib.sha256(auth_data.credential_data.credential_id).hexdigest()
    # add enrolled credential to db, setup required data structures

    # TODO
    recreq = RePassRecoveryRequest(recovered_credential_id=id, user_id=user.id,
                                   recovered_websafe_credential=credential.websafe_credential,
                                   approvals_needed=user.approvals_needed)
    db.session.add(recreq)
    db.session.commit()

    # print("REGISTERED CREDENTIAL:", auth_data.credential_data)
    # return cbor.encode({"status": "OK", "next": url_for("main.settings")})
    return redirect(url_for("main.recovery_status", id=id))


@bp.route("/recovery_status/<id>")
def recovery_status(id):
    req = RePassRecoveryRequest.query.filter_by(
        recovered_credential_id=id).first()

    approving_creds = RePassRecoveryCredential.query.filter_by(
        user_id=req.user_id).all()

    return render_template("recovery_status.html", req=req, approving_creds=approving_creds)


@bp.route("/recovery_approve_begin/<rec_req_id>/<approver_id>")
def recovery_approve_begin(rec_req_id, approver_id):
    # validate approver_id
    rrr = RePassRecoveryRequest.query.filter_by(id=rec_req_id).first()
    u = User.query.filter_by(id=rrr.user_id).first()

    authorized_approvers = [i.credential_id for i in u.recovery_credentials]

    if approver_id not in authorized_approvers:
        abort(403)

    letters = string.ascii_lowercase
    chall = ''.join(random.choice(letters) for i in range(48))

    rec_req = RePassRecoveryRequest.query.filter_by(id=rec_req_id).first()

    # check whether approval has already been populated
    if (approval := RePassRecoveryApproval.query.filter_by(approving_credential_id=approver_id,
                                                           recovery_request_id=rec_req_id).first()) is not None:
        # has already been populated
        pass
        # print(approval)
    else:
        # fill data structures in db
        approval = RePassRecoveryApproval(
            recovery_request_id=rec_req.id,
            approving_credential_id=approver_id,
            challenge=chall)
        db.session.add(approval)
        db.session.commit()

    # send challenge to repass client

    return ({"challenge": approval.challenge}, 200)


@bp.route("/recovery_approve_complete/<rec_req_id>/<approver_id>", methods=["POST"])
def recovery_approve_complete(rec_req_id, approver_id):
    # TODO: only complete once all required approvals have been completed

    rrr = RePassRecoveryRequest.query.filter_by(id=rec_req_id).first()

    if rrr.status != "pending":
        # request has invalid status
        abort(500)

    data = json.loads(request.data)
    # print("++++++++")
    # print(data)
    # print("++++++++")

    ser = data["AAR"]
    cred = AttestedCredentialData(websafe_decode(data["cred"]))

    #cl_da = websafe_decode(data["client_data"])
    aar = AuthenticatorAssertionResponse(
        client_data=ClientData(websafe_decode(ser["client_data"])),
        signature=websafe_decode(ser["signature"]),
        credential_id=websafe_decode(ser["credential_id"]),
        authenticator_data=AuthenticatorData(
            websafe_decode(ser["authenticator_data"])),
        user_handle=None,
        extension_results={}
    )

    # print(aar)
    # print(cred)

    # we receive credential public information via the post request
    # we need to validate, whether the information is correct; matches the approver_id
    # TODO
    # print(RePassRecoveryApproval.query.filter_by(recovery_request_id=rec_req_id).filter_by(approving_credential_id=approver_id).first().challenge.encode())
    recovery_approval = RePassRecoveryApproval.query.filter_by(
        recovery_request_id=rec_req_id, approving_credential_id=approver_id).first()
    credentials = [cred]  # must be attestedCredentialData
    server = Fido2Server(
        {"id": "example.com", "name": "Example RP"}, attestation="direct")
    request_options, state = server.authenticate_begin(
        credentials, user_verification="discouraged", challenge=recovery_approval.challenge.encode())

    # print(state)

    # Complete authenticator
    try:
        server.authenticate_complete(
            state,
            credentials,
            aar.credential_id,
            aar.client_data,
            aar.authenticator_data,
            aar.signature,
        )

    except:
        abort(500)

    # successfully approved
    recovery_approval.attestation = json.dumps(data)
    db.session.add(recovery_approval)
    db.session.commit()

    # check for counts of approvals
    # TODO: it may be better to also check all attestations when finalizing
    successful_approvals = [i for i in rrr.approvals if i.attestation != None]
    
    if len(successful_approvals) >= rrr.approvals_needed:

        # check whether all necessary approvals have been submitted
        # if so: replace user's credential with the one of the request
        rrr.status = "completed"
        user_credential = Credential.query.filter_by(
            user_id=rrr.user_id).first()

        user_credential.websafe_credential = rrr.recovered_websafe_credential

        user_credential.credential_id = rrr.recovered_credential_id
        db.session.add(user_credential)
        db.session.add(rrr)
        db.session.commit()

        return "none"
    else:
        return "waiting for additional approvals"


@bp.route("/register/begin/<username>", methods=["POST"])
def register_begin(username):
    # fetch user's credentials
    user = User.query.filter_by(username=username).first()
    if user is not None:
        print("error: user already registered")
        abort(404)

    creds = []
    registration_data, state = server.register_begin(
        {
            "id": f"{random.randint(1,100000)}".encode(),
            "name": f"{username}",
            "displayName": f"{username}",
            "icon": "https://example.com/image.png",
        },
        creds,  # causes error once more than one creds are enrolled!!!
        user_verification="discouraged",
        authenticator_attachment="cross-platform",
    )

    session["state"] = state
    session["username"] = username
    # print("\n\n\n\n")
    # print(registration_data)
    # print("\n\n\n\n")
    return cbor.encode(registration_data)


@bp.route("/register/complete", methods=["POST"])
def register_complete():
    data = cbor.decode(request.get_data())
    client_data = ClientData(data["clientDataJSON"])
    att_obj = AttestationObject(data["attestationObject"])
    # print("clientData", client_data)
    # print("AttestationObject:", att_obj)

    auth_data = server.register_complete(
        session["state"], client_data, att_obj)

    # if session["username"] in credentials:
    #    credentials.append(auth_data.credential_data)
    # else:
    #    credentials[session["username"]] = [auth_data.credential_data]

    user = User(username=session["username"])
    db.session.add(user)
    db.session.commit()
    credential = Credential(user_id=user.id)
    credential.websafe_credential = websafe_encode(auth_data.credential_data)
    credential.credential_id = hashlib.sha256(
        auth_data.credential_data.credential_id).hexdigest()
    db.session.add(credential)
    db.session.commit()

    # login user
    login_user(user)

    # print("REGISTERED CREDENTIAL:", auth_data.credential_data)
    return cbor.encode({"status": "OK"})


@bp.route("/authenticate/begin/<username>", methods=["POST"])
def authenticate_begin(username):
    # if not credentials:
    #    abort(404)

    # get user's credentials
    # creds = credentials[username]
    user = User.query.filter_by(username=username).first()
    if user is None:
        abort(404)

    creds = []
    # print(user.credentials)
    for i in user.credentials:
        # print(i.websafe_credential)
        creds.append(AttestedCredentialData(
            websafe_decode(i.websafe_credential)))

    # print(creds)
    auth_data, state = server.authenticate_begin(creds)
    session["state"] = state
    session["username"] = username  # is this safe? username cntnd in state?
    return cbor.encode(auth_data)


@bp.route("/authenticate/complete", methods=["POST"])
def authenticate_complete():
    # if not credentials:
    #    abort(404)

    # creds = credentials[session["username"]]
    user = User.query.filter_by(username=session["username"]).first()
    if user is None:
        abort(404)

    creds = []
    for i in user.credentials:
        creds.append(AttestedCredentialData(
            websafe_decode(i.websafe_credential)))

    data = cbor.decode(request.get_data())
    credential_id = data["credentialId"]
    client_data = ClientData(data["clientDataJSON"])
    auth_data = AuthenticatorData(data["authenticatorData"])
    signature = data["signature"]
    # print("clientData", client_data)
    # print("AuthenticatorData", auth_data)

    server.authenticate_complete(
        session.pop("state"),
        creds,
        credential_id,
        client_data,
        auth_data,
        signature,
    )
    print("ASSERTION OK")
    login_user(user)
    flash("Login successful!")
    return cbor.encode({"status": "OK"})


@bp.route("/approvals_needed/<number>")
@login_required
def approvals_needed(number):
    current_user.approvals_needed = number
    db.session.add(current_user)
    db.session.commit()
    return cbor.encode({"status": "OK"})


@bp.route("/settings")
@login_required
def settings():
    return render_template("settings.html", cu=current_user, rp_avail=repass_available())


@bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("main.index"))


@bp.route("/login")
def login():
    return render_template("login.html")


def repass_available():
    if not current_user.is_authenticated:
        return False
    else:
        # check whether repass recovery is available for current user
        return len(current_user.recovery_credentials) > 0


@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)


@login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect('/login')
