import re

from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, ValidationError


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    register = SubmitField("Register")
    authenticate = SubmitField("Authenticate")


class RepassAddForm(FlaskForm):
    id = StringField("Credential ID", validators=[DataRequired()])
    description = StringField("Description", validators=[DataRequired()])
    add = SubmitField("Add")

    def validate_id(form, field):
        if not len(field.data) == 64 or not re.search("^[a-zA-Z0-9_]*$", field.data):
            raise ValidationError(
                "This does not look like a valid credential ID.")
