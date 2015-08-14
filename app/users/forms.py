#/app/users/forms.py


from flask_wtf import Form
from wtforms import TextField, PasswordField, SelectField
from wtforms.validators import DataRequired, Length, EqualTo, Email


class RegisterForm(Form):
    name = TextField(
        'Username',
        validators=[DataRequired(), Length(min=6, max=25)]
    )
    email = TextField(
        'Email',
        validators=[DataRequired(), Email(), Length(min=6, max=40)]
    )
    password = PasswordField(
        'Password',
        validators=[DataRequired(), Length(min=6, max=40)])
    confirm = PasswordField(
        'Repeat Password',
        validators=[DataRequired(), EqualTo('password')]
    )
    role = SelectField(
        'role',
        choices=[('user', 'user'), ('admin', 'admin')]
    )

class LoginForm(Form):
    name = TextField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])