import enum
from datetime import datetime

from flask_login import UserMixin

from app import db


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    approvals_needed = db.Column(db.Integer(), nullable=False, default=1)
    credentials = db.relationship(
        "Credential", backref=db.backref("user", lazy=True))
    recovery_credentials = db.relationship(
        "RePassRecoveryCredential", backref=db.backref("user", lazy=True))

    def __repr__(self):
        return f"""<User {self.username}>
                credentials: {self.credentials}
                recovery_credentials: {self.recovery_credentials}"""

    @staticmethod
    def get(user_id):
        return User.query.filter_by(id=user_id).first()

    @staticmethod
    def get_by_name(user_name):
        return User.query.filter_by(username=user_name).first()


class RePassRecoveryCredential(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    credential_id = db.Column(
        db.String, nullable=False, index=True)
    description = db.Column(db.String, nullable=False)
    date_added = db.Column(
        db.DateTime, default=datetime.utcnow, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)


class RePassRecoveryRequest(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    recovered_credential_id = db.Column(
        db.String, nullable=False, unique=True, index=True)
    recovered_websafe_credential = db.Column(db.String, nullable=False)
    created = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    status = db.Column(db.String, default="pending")
    approvals = db.relationship(
        "RePassRecoveryApproval", backref=db.backref("re_pass_recovery_request", lazy=True))
    approvals_needed = db.Column(db.Integer(), nullable=False, default=1)


class RePassRecoveryApproval(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    recovery_request_id = db.Column(db.Integer, db.ForeignKey(
        "re_pass_recovery_request.id"), nullable=False)
    approving_credential_id = db.Column(db.Integer, db.ForeignKey(
        "re_pass_recovery_credential.id"), nullable=False)
    challenge = db.Column(db.String, nullable=False)
    attestation = db.Column(db.String)


class Credential(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    credential_id = db.Column(
        db.String, nullable=False, unique=True, index=True)
    signature_count = db.Column(db.Integer, nullable=True)
    websafe_credential = db.Column(db.String)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
