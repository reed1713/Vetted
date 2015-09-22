# app/views.py

#################
#### imports ####
#################

from app import app
from app.models import *
from flask import flash, redirect, session, url_for, \
    render_template, request, jsonify, make_response, abort
from functools import wraps
from app.models import Network_Snort_dt
##########################
#### helper functions ####
##########################


def login_required(test):
    @wraps(test)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return test(*args, **kwargs)
        else:
            flash('you need to login first')
            return redirect(url_for('users.login'))
    return wrap

def admin(test):
    @wraps(test)
    def wrap(*args, **kwargs):
        if session['role'] == 'admin':
            return test(*args, **kwargs)
        else:
            flash('you need to be admin')
            return redirect(url_for('welcome.welcome'))
    return wrap

def apikey_required(view):

    '''
    allows access to the api if the user is already logged_in
    or if they supply their api_key
    '''

    @wraps(view)
    def wrapped_view(*args, **kwargs):

        if 'logged_in' in session:
            return view(*args, **kwargs)

        api_key = request.args.get('api_key', '')
        
        if api_key:
            key = User.query.filter_by(api_key=api_key).first()
            if key:
                return view(*args, **kwargs)
        else:
            abort(401)
    return wrapped_view

def cleantags(ormlist):

    '''
    removes the sqlalchemy garbage, and returns list of strings
    '''

    cleantags = []
    for o in ormlist:
        newo = str(o)
        cleantags.append(newo)
    return cleantags

def clean_NBI(nbijson):

    '''
    returns newline separated key : values
    '''
    if nbijson:
        li = []
        for t in nbijson:
            for k, v in t.iteritems():
                out = k.strip() + " : " + v.strip()
                li.append(out)
        return '\n'.join(li)
    else:
        return 
################
#### routes ####
################

@app.route('/', defaults={'page': 'index'})
def index(page):
    return(redirect(url_for('users.login')))

########################
#### error handlers ####
########################

@app.errorhandler(404)
def page_not_found(error):
    if app.debug is not True:
        now = datetime.datetime.now()
        r = request.url
        with open('error.log', 'a') as f:
            current_timestamp = now.strftime("%d-%m-%Y %H:%M:%S")
            f.write("\n404 error at {}: {} ".format(current_timestamp, r))
    return render_template('404.html', username=session['name']), 404

@app.errorhandler(500)
def internal_error(error):
    if app.debug is not True:
        now = datetime.datetime.now()
        r = request.url
        with open('error.log', 'a') as f:
            current_timestamp = now.strftime("%d-%m-%Y %H:%M:%S")
            f.write("\n500 error at {}: {} ".format(current_timestamp, r))
    return render_template('500.html', username=session['name']), 500

#######################
#### API Endpoints ####
#######################

    #########################
    ### Network Bro Intel ###
    #########################

# Get all bro intel vetted objects:
@app.route('/api/vetted/network_bro_intel/json/')
@apikey_required
def api_all_bro_intel_vetted():
    if request.method == 'GET':
        results = db.session.query(Network_Bro_Intel_dt).filter_by(status='vetted').offset(0).all()
        json_results = []
        if results:
            for result in results:
                t = result.tags
                ct = cleantags(t)
                data = {
                    'indicators': result.bro_intel_indicators,
                    'source': result.source,
                    'created_date' : result.created_date,
                    'tags' : ct,
                    'notes' : result.notes,
                    'type_hash' : result.type_hash,
                        }
                json_results.append(data)
                code = 200
        else:
            code = 404
        return make_response(jsonify(vetted=json_results), code)

# Get specified bro intel vetted object
@app.route('/api/vetted/network_bro_intel/json/<int:dt_id>')
@apikey_required
def api_bro_intel_vetted(dt_id):
    if request.method == 'GET':
        result = db.session.query(Network_Bro_Intel_dt).filter_by(id=dt_id, status='vetted').first()
        if result:
            t = result.tags
            ct = cleantags(t)
            result = {
                'indicators': result.bro_intel_indicators,
                'source': result.source,
                'created_date' : result.created_date,
                'tags' : ct,
                'notes' : result.notes,
                'type_hash' : result.type_hash,
            }
            code = 200
        else:
            result = {"sorry": "Element does not exist"}
            code = 404
        return make_response(jsonify(result), code)

    #####################
    ### Network Snort ###
    #####################

# Get all snort vetted objects:
@app.route('/api/vetted/network_snort/json/')
@apikey_required
def api_all_snort_vetted():
    if request.method == 'GET':
        results = db.session.query(Network_Snort_dt).filter_by(status='vetted').offset(0).all()
        json_results = []
        if results:
            for result in results:
                t = result.tags
                ct = cleantags(t)
                data = {
                    'indicators': result.snort_indicators,
                    'source': result.source,
                    'created_date' : result.created_date,
                    'tags' : ct,
                    'notes' : result.notes,
                    'type_hash' : result.type_hash,
                        }
                json_results.append(data)
                code = 200
        else:
            code = 404
        return make_response(jsonify(vetted=json_results), code)

# Get specified snort vetted object
@app.route('/api/vetted/network_snort/json/<int:dt_id>')
@apikey_required
def api_snort_vetted(dt_id):
    if request.method == 'GET':
        result = db.session.query(Network_Snort_dt).filter_by(id=dt_id, status='vetted').first()
        if result:
            t = result.tags
            ct = cleantags(t)
            result = {
                'indicators': result.snort_indicators,
                'source': result.source,
                'created_date' : result.created_date,
                'tags' : ct,
                'notes' : result.notes,
                'type_hash' : result.type_hash,
            }
            code = 200
        else:
            result = {"sorry": "Element does not exist"}
            code = 404
        return make_response(jsonify(result), code)

# POST updated snort indicators
@app.route('/api/vetted/network_snort/json/<string:type_hash>', methods=['POST'])
@apikey_required
def api_snort_vetted_post(type_hash):
    if request.method == 'POST':
        result = db.session.query(Network_Snort_dt).filter_by(type_hash=type_hash).first()
        data = request.data
        indicators = json.loads(data)
        if result:
            d_obj = Network_Snort_dt.query.get(result.id)
            d_obj.snort_indicators = indicators['indicators']
            db.session.commit()
            return make_response(str(200))
        else:
            abort(401)
        

    ###################
    ### Binary Yara ###
    ###################

# Get all yara vetted objects:
@app.route('/api/vetted/binary_yara/json/')
@apikey_required
def api_all_yara_vetted():
    if request.method == 'GET':
        results = db.session.query(Binary_Yara_dt).filter_by(status='vetted').offset(0).all()
        json_results = []
        if results:
            for result in results:
                t = result.tags
                ct = cleantags(t)
                data = {
                    'indicators': result.yara_indicators,
                    'source': result.source,
                    'created_date' : result.created_date,
                    'tags' : ct,
                    'notes' : result.notes,
                    'type_hash' : result.type_hash,
                        }
                json_results.append(data)
                code = 200
        else:
            code = 404
        return make_response(jsonify(vetted=json_results), code)

# Get specified yara vetted object
@app.route('/api/vetted/binary_yara/json/<int:dt_id>')
@apikey_required
def api_yara_vetted(dt_id):
    if request.method == 'GET':
        result = db.session.query(Binary_Yara_dt).filter_by(id=dt_id, status='vetted').first()
        if result:
            t = result.tags
            ct = cleantags(t)
            result = {
                'indicators': result.yara_indicators,
                'source': result.source,
                'created_date' : result.created_date,
                'tags' : ct,
                'notes' : result.notes,
                'type_hash' : result.type_hash,
            }
            code = 200
        else:
            result = {"sorry": "Element does not exist"}
            code = 404
        return make_response(jsonify(result), code)