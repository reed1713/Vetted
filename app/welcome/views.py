# app/welcome/views.py

#################
#### imports ####
#################

from sqlalchemy import desc
from flask import flash, redirect, render_template, request, session, url_for, Blueprint, send_from_directory
from app import db
from app.views import login_required
from app.models import Network_Bro_Intel_dt, Network_Snort_dt, Binary_Yara_dt, Feeds

################
#### config ####
################

welcome_blueprint = Blueprint(
    'welcome', __name__,
    url_prefix='/welcome',
    template_folder='templates',
    static_folder='static',
)

################
#### routes ####
################

@welcome_blueprint.route('/welcome/')
@login_required
def welcome():
    error = None
    NBI_opencount = db.session.query(Network_Bro_Intel_dt).filter_by(status='open').count()
    NBI_reviewingcount = db.session.query(Network_Bro_Intel_dt).filter_by(status='reviewing').count()
    NBI_vettedcount = db.session.query(Network_Bro_Intel_dt).filter_by(status='vetted').count()
    NBI_stalecount = db.session.query(Network_Bro_Intel_dt).filter_by(status='stale').count()

    NS_opencount = db.session.query(Network_Snort_dt).filter_by(status='open').count()
    NS_reviewingcount = db.session.query(Network_Snort_dt).filter_by(status='reviewing').count()
    NS_vettedcount = db.session.query(Network_Snort_dt).filter_by(status='vetted').count()
    NS_stalecount = db.session.query(Network_Snort_dt).filter_by(status='stale').count()

    BY_opencount = db.session.query(Binary_Yara_dt).filter_by(status='open').count()
    BY_reviewingcount = db.session.query(Binary_Yara_dt).filter_by(status='reviewing').count()
    BY_vettedcount = db.session.query(Binary_Yara_dt).filter_by(status='vetted').count()
    BY_stalecount = db.session.query(Binary_Yara_dt).filter_by(status='stale').count()

    NBI_mostrecent = db.session.query(Network_Bro_Intel_dt).order_by(desc('created_date')).limit(10)
    NS_mostrecent = db.session.query(Network_Snort_dt).order_by(desc('created_date')).limit(10)
    BY_mostrecent = db.session.query(Binary_Yara_dt).order_by(desc('created_date')).limit(10)

    mostrecentlist = []
    for nbi in NBI_mostrecent:
        mostrecentlist.extend([[int(nbi.created_date.strftime("%s")) * 1000, nbi.created_date, nbi.source, nbi.d_type, nbi.status]])
    for ns in NS_mostrecent:
        mostrecentlist.extend([[int(ns.created_date.strftime("%s")) * 1000, ns.created_date, ns.source, ns.d_type, ns.status]])
    for by in BY_mostrecent:
        mostrecentlist.extend([[int(by.created_date.strftime("%s")) * 1000, by.created_date, by.source, by.d_type, by.status]])

    test = sorted(mostrecentlist, key=lambda x: x[0], reverse=True)
    finalsortedlist = test[-0:20]

    return render_template('welcome.html',
    		error=error,
    		username=session['name'],
            NBI_opencount=NBI_opencount,
            NBI_reviewingcount=NBI_reviewingcount,
            NBI_vettedcount=NBI_vettedcount,
            NBI_stalecount=NBI_stalecount,
            NS_opencount=NS_opencount,
            NS_reviewingcount=NS_reviewingcount,
            NS_vettedcount=NS_vettedcount,
            NS_stalecount=NS_stalecount,
            BY_opencount=BY_opencount,
            BY_reviewingcount=BY_reviewingcount,
            BY_vettedcount=BY_vettedcount,
            BY_stalecount=BY_stalecount,
            finalsortedlist=finalsortedlist,
            )

@welcome_blueprint.route('/documentation/')
@login_required
def documentation():
    error = None
    return render_template('documentation.html',
    		error=error,
    		username=session['name'],
            )    