# app/status/forms.py

from flask_wtf import Form
from wtforms import TextField, DateField, IntegerField, SelectField, TextAreaField

from wtforms.validators import DataRequired, URL, Length, Optional


class EditScrape(Form):
    source = TextField('source')
    newlinei = TextAreaField('indicators', validators=[Optional()])
    strtags = TextField('tags', validators=[Optional()])
    notes = TextAreaField('notes', validators=[Optional()])
    status = SelectField(
        'status',
        validators=[DataRequired()],
        choices=[('open', 'open'), ('reviewing', 'reviewing'), ('vetted', 'vetted'), ('stale', 'stale')]
    	)
    priority = SelectField(
        'priority',
        validators=[DataRequired()],
        choices=[
            ('low', 'low'), ('medium', 'medium'), ('high', 'high')
        ]
    )