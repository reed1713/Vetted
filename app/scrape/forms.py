# app/scrape/forms.py

from flask_wtf import Form
from wtforms import TextField, FileField, SelectField, TextAreaField, BooleanField
from wtforms.validators import DataRequired, Optional

class URLScrape(Form):
	N_BI_checkbx = BooleanField('Network - Bro Intel', default=True)
	N_S_checkbx = BooleanField('Network - Snort_Suricata', default=False)
	B_Y_checkbx = BooleanField('Binary - Yara', default=False)
	url = TextField(
		validators=[DataRequired()],
		)
	priority = SelectField(
		'priority',
		validators=[DataRequired()],
		choices=[
			('low', 'low'), ('medium', 'medium'), ('high', 'high')
		]
	)
class UploadScrape(Form):
	N_BI_checkbx = BooleanField('Network - Bro Intel', default=True)
	N_S_checkbx = BooleanField('Network - Snort_Suricata', default=False)
	B_Y_checkbx = BooleanField('Binary - Yara', default=False)
	uploadpath = FileField(        
		'upload',
		)
	source = TextField(
		'source',
		validators=[DataRequired()],
		)
	priority = SelectField(
		'priority',
		validators=[DataRequired()],
		choices=[
			('low', 'low'), ('medium', 'medium'), ('high', 'high')
		]
	)
class Manual(Form):
    source = TextField('source', validators=[DataRequired()])
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