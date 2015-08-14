# app/research/forms.py

from flask_wtf import Form
from wtforms import TextField, SelectField
from wtforms.validators import DataRequired

class feeds_form(Form):
	feedsrc = TextField(
		validators=[DataRequired()],
		)
	sourceconfidence = SelectField(
    	'feed confidence', 
    	validators=[DataRequired()], 
    	choices=[('3', 'low'), ('2', 'medium'), ('1', 'high')])
	feedsource_type = SelectField(
    	'feed type', 
    	validators=[DataRequired()], 
    	choices=[('tactical_intel', 'Tactical Intel'), ('strategic_intel', 'Strategic Intel')])

class feed_edit_form(Form):
	feedsource = TextField()
	sourceconfidence = SelectField(
    	'feed confidence', 
    	validators=[DataRequired()], 
    	choices=[('3', 'low'), ('2', 'medium'), ('1', 'high')])
	feedsource_type = SelectField(
	'feed type', 
	validators=[DataRequired()], 
	choices=[('tactical_intel', 'Tactical Intel'), ('strategic_intel', 'Strategic Intel')])