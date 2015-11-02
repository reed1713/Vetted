#/app/login/forms.py


from flask_wtf import Form
from wtforms import TextField, PasswordField
from wtforms.validators import DataRequired

class LoginForm(Form):
    name = TextField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])