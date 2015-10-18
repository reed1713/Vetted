# app/lists/views.py

#################
#### imports ####
#################

from flask import flash, redirect, render_template, request, session, url_for, Blueprint, send_from_directory, jsonify
from sqlalchemy.exc import IntegrityError
from app.lists.forms import whitelist_form, keywordlist_form
from app import db, docs, app
from app.views import login_required
from app.models import Network_Bro_Intel_dt, User, Tag

#python lib
import os
import json

WLPATH = 'app/lists/whitelist.txt'
KWPATH = 'app/lists/keywords.txt'

################
#### helper ####
################

def r_whitelist(rwl=WLPATH):

	with open(rwl) as f:
		rlines = f.read()
		f.close()
		return rlines	

def w_whitelist(newwl, wwl=WLPATH):

	with open(wwl,'w') as f:
		f.write(newwl)
		f.close()

def r_keywordlist(rkw=KWPATH):

	with open(rkw) as f:
		rlines = f.read()
		f.close()
		return rlines	

def w_keywordlist(newkw, wkw=KWPATH):

	with open(wkw,'w') as f:
		f.write(newkw)
		f.close()

################
#### config ####
################

lists_blueprint = Blueprint(
    'lists', __name__,
    url_prefix='/lists',
    template_folder='templates',
    static_folder='static',
)

################
#### routes ####
################

@lists_blueprint.route('/whitelist/', methods=['GET', 'POST'])
@login_required
def whitelist_save():
	error = None
	if request.method == 'GET':
		whitelist_field = r_whitelist()
		form = whitelist_form(whitelist_field=whitelist_field)
		return render_template('whitelist.html',
			error=error,
			username=session['name'],
			form=form,
			whitelist_field=whitelist_field,
			)

	if request.method == 'POST':
		whitelist_field = r_whitelist()
		form = whitelist_form(whitelist_field=whitelist_field)		
		if form.validate_on_submit():
			writewl = form.whitelist_field.data
			w_whitelist(writewl)
			flash('updated whitelist.txt')
			return render_template('whitelist.html',
				error=error,
				username=session['name'],
				form=form,
				whitelist_field=whitelist_field,
				)

@lists_blueprint.route('/keywords/', methods=['GET', 'POST'])
@login_required
def keywordlist_save():
	error = None
	if request.method == 'GET':
		keywordlist_field = r_keywordlist()
		form = keywordlist_form(keywordlist_field=keywordlist_field)
		return render_template('keywordlist.html',
			error=error,
			username=session['name'],
			form=form,
			keywordlist_field=keywordlist_field,
			)

	if request.method == 'POST':
		keywordlist_field = r_keywordlist()
		form = keywordlist_form(keywordlist_field=keywordlist_field)		
		if form.validate_on_submit():
			writekw = form.keywordlist_field.data
			w_keywordlist(writekw)
			flash('updated keywords.txt')
			return render_template('keywordlist.html',
				error=error,
				username=session['name'],
				form=form,
				keywordlist_field=keywordlist_field,
				)