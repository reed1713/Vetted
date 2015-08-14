# app/lists/forms.py

from flask_wtf import Form
from wtforms import TextAreaField
from wtforms.validators import DataRequired

class whitelist_form(Form):
	whitelist_field = TextAreaField(
		validators=[DataRequired()],
		)
class keywordlist_form(Form):
	keywordlist_field = TextAreaField(
		validators=[DataRequired()],
		)
