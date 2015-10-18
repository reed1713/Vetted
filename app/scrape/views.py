# app/scrape/views.py

from flask import flash, redirect, render_template, request, session, url_for, Blueprint
from sqlalchemy.exc import IntegrityError, InvalidRequestError
from app.scrape.forms import URLScrape, UploadScrape, Manual
from app import db, docs
from app.views import login_required, clean_NBI
from app.models import Network_Bro_Intel_dt, Network_Snort_dt, Binary_Yara_dt, Tag
from werkzeug import secure_filename

#local helper methods
from scripts.Wpuller import cleanUrl, cleangetUrl, downloadedFilename, geturlResource
from scripts.IOCextractor import iocExtractor
from scripts.Igenerator import indicatorListofDicts
from scripts.Tkeywords import match_keyword
from scripts.Tconverter import texttoFile

#python lib
import os
import json
import hashlib
import re

#global vars
NBI_HASH_STRING = 'network_bro_intel'
NS_HASH_STRING = 'network_snort'
BY_HASH_STRING = 'binary_yara'

################
#### helper ####
################

def tolistofdicts(stringtoparse):

    roundone = [x.strip() for x in stringtoparse.split("\r\n")]
    roundtwo = [t.split(' : ') for t in roundone]
    lout = []
    if roundtwo == [[u'']]:
        return []
    else:
        for t, v in roundtwo:
            tester = {t : v}
            lout.append(tester)
    out = json.dumps(lout)
    newout = json.loads(out)
    return newout

def snort_sig_to_list(listofsigs):

    split_sigs = re.split(r'\r\n\r\n', listofsigs)
    addback = [x + '\r\n\r\n' for x in split_sigs[:-1]]
    final = addback + split_sigs[-1:]

    out = json.dumps(final)
    return json.loads(out)

def yara_sig_to_list(listofsigs):

    split_sigs = re.split(r'\r\n\}\r\n\r\n', listofsigs)
    addback = [x + '\r\n}\r\n\r\n' for x in split_sigs[:-1]]
    final = addback + split_sigs[-1:]

    out = json.dumps(final)
    return json.loads(out)

def hash_type(dt_type, source):
    return hashlib.md5(dt_type + source).hexdigest()

################
#### config ####
################

scrape_blueprint = Blueprint(
    'scrape', __name__,
    url_prefix='/scrape',
    template_folder='templates',
    static_folder='static'
)

################
#### routes ####
################

@scrape_blueprint.route('/auto/', methods=['GET', 'POST'])
@login_required
def scrape():
    error = None
    form = URLScrape(request.form)
    if request.method == 'POST':
        try:
            url = request.form['url']
            cleanget = cleangetUrl(url)
            filename = downloadedFilename(cleanget)
            _call_downloaded_url = geturlResource(cleanget)
            _call_create_txt_file = texttoFile(filename)
            txtfile = filename + ".txt"
            csvfile = filename + ".csv"
            cleaned_url = cleanUrl(cleanget)
            ktags = match_keyword(txtfile)
        except:
            error = "Unable to scrape that url. Check the address and that you're connected to the internet."
            return render_template('one_scrape_form.html',
                username=session['name'], 
                error=error,
                form=form,
                )
        error = []
        if form.N_BI_checkbx.data == True:
            nbi_out = iocExtractor(cleanget)
            if nbi_out == None:
                nbi_out = []
            result = Network_Bro_Intel_dt(
            source = cleaned_url,
            type_hash = hash_type(NBI_HASH_STRING, cleaned_url),
            priority = form.priority.data,
            bro_intel_indicators = nbi_out,
            created_by = session['name'],
            localfile = filename,
            localtxtfile = txtfile,
            localcsvfile = csvfile,
            tags = [],
            )
            result.str_tags = ktags
            try:
                db.session.add(result)
                db.session.commit()
                flash('successfully created network-bro_intel detection object')
            except IntegrityError:
                db.session.rollback()
                error_nbi = "source and network-bro_intel detection type object already exists."
                error.append(error_nbi)

        if form.N_S_checkbx.data == True:
            result = Network_Snort_dt(
            source = cleaned_url,
            type_hash = hash_type(NS_HASH_STRING, cleaned_url),
            priority = form.priority.data,
            created_by = session['name'],
            localfile = filename,
            localtxtfile = txtfile,
            localcsvfile = csvfile,
            tags = [],
            snort_indicators=[],
            )
            result.str_tags = ktags
            try:
                db.session.add(result)
                db.session.commit()
                flash('successfully created network-snort detection object')
            except IntegrityError:
                db.session.rollback()
                error_ns = "source and network-snort detection type object already exists."
                error.append(error_ns)
        if form.B_Y_checkbx.data == True:
            result = Binary_Yara_dt(
            source = cleaned_url,
            type_hash = hash_type(BY_HASH_STRING, cleaned_url),
            priority = form.priority.data,
            created_by = session['name'],
            localfile = filename,
            localtxtfile = txtfile,
            localcsvfile = csvfile,
            tags = [],
            yara_indicators=[],
            )
            result.str_tags = ktags
            try:
                db.session.add(result)
                db.session.commit()
                flash('successfully created binary-yara detection object')
            except IntegrityError:
                db.session.rollback()
                error_by = "source and binary-yara detection type object already exists."
                error.append(error_by)

        if form.N_BI_checkbx.data == True:
            return render_template('one_scrape_form.html', 
                    username=session['name'], 
                    form=form, 
                    multiple_errors=error,
                    ktags=ktags,
                    nbi_out=nbi_out,
                    )      
        return render_template('one_scrape_form.html', 
                username=session['name'], 
                form=form, 
                multiple_errors=error,
                ktags=ktags,
                )            
    if request.method == 'GET':
        return render_template('one_scrape_form.html', 
                username=session['name'], 
                form=form, 
                error=error,
                )

@scrape_blueprint.route('/upload/', methods=['POST', 'GET'])
@login_required
def upload_scrape():
    DOCS = 'app/documents/'
    error = None
    form = UploadScrape(request.form)
    if request.method == 'POST':
        file = request.files['uploadpath']
        if file:
            filename = secure_filename(file.filename)
            sourcename = form.source.data
            cleansourcename = cleanUrl(sourcename)
            cleansource = downloadedFilename(sourcename)
            txtfile = cleansource + ".txt"
            csvfile = cleansource + ".csv"
            if not os.path.exists(DOCS + cleansource):
                file.save(os.path.join(docs, filename))
                _call_create_txt_file = texttoFile(filename)
                oldfilepath = os.path.join(docs, filename)
                oldtxtfilepath = os.path.join(docs, filename + '.txt')
                newfilepath = os.path.join(docs, cleansource)
                newtxtfilepath = os.path.join(docs, txtfile)
                os.rename(oldtxtfilepath, newtxtfilepath)
                os.rename(oldfilepath, newfilepath)
                ktags = match_keyword(txtfile)
            else:
                flash('a file already exists for that source, omitting upload')
                ktags = match_keyword(txtfile)
                pass
            error = []
            if form.N_BI_checkbx.data == True:                    
                nbi_out = indicatorListofDicts(cleansource)
                if nbi_out == None:
                    nbi_out = []
                result = Network_Bro_Intel_dt(
                    source = cleansourcename,
                    type_hash = hash_type(NBI_HASH_STRING, cleansourcename),
                    bro_intel_indicators = nbi_out,
                    priority = form.priority.data,
                    created_by = session['name'],
                    localfile = cleansource,
                    localtxtfile = txtfile,
                    localcsvfile = csvfile,
                    tags = [],
                    )
                result.str_tags = ktags
                try:
                    db.session.add(result)
                    db.session.commit()
                    flash('successfully created network-bro_intel detection object')
                except IntegrityError:
                    db.session.rollback()
                    error_nbi = "source and network-bro_intel detection type object already exists."
                    error.append(error_nbi)

            if form.N_S_checkbx.data == True:
                result = Network_Snort_dt(
                source = cleansourcename,
                type_hash = hash_type(NS_HASH_STRING, cleansourcename),
                priority = form.priority.data,
                created_by = session['name'],
                localfile = cleansource,
                localtxtfile = txtfile,
                localcsvfile = csvfile,
                tags = [],
                snort_indicators=[],
                )
                result.str_tags = ktags
                try:
                    db.session.add(result)
                    db.session.commit()
                    flash('successfully created network-snort detection object')
                except IntegrityError:
                    db.session.rollback()
                    error_ns = "source and network-snort detection type object already exists."
                    error.append(error_ns)
            if form.B_Y_checkbx.data == True:
                result = Binary_Yara_dt(
                source = cleansourcename,
                type_hash = hash_type(BY_HASH_STRING, cleansourcename),
                priority = form.priority.data,
                created_by = session['name'],
                localfile = cleansource,
                localtxtfile = txtfile,
                localcsvfile = csvfile,
                tags = [],
                yara_indicators=[]
                )
                result.str_tags = ktags
                try:
                    db.session.add(result)
                    db.session.commit()
                    flash('successfully created binary-yara detection object')
                except IntegrityError:
                    db.session.rollback()
                    error_by = "source and binary-yara detection type object already exists."
                    error.append(error_by)

            if form.N_BI_checkbx.data == True:
                return render_template('upload_scrape_form.html', 
                        username=session['name'], 
                        form=form, 
                        multiple_errors=error,
                        ktags=ktags,
                        nbi_out=nbi_out,
                        )                      
            return render_template('upload_scrape_form.html', 
                    username=session['name'], 
                    form=form, 
                    multiple_errors=error,
                    ktags=ktags,
                    ) 
        else:
            error = "need to upload a file"
            return render_template('upload_scrape_form.html',
                            form=form,
                            error=error,
                            username=session['name'],
                            )
    if request.method == 'GET':
        return render_template('upload_scrape_form.html',
                            form=form,
                            error=error,
                            username=session['name'],
                            )

@scrape_blueprint.route('/manual/network_bro_intel/', methods=['GET', 'POST'])
@login_required
def manual_NBI():
    error = None
    form = Manual(request.form)
    if request.method == 'GET':
        return render_template('manual_NBI.html', 
            form=form, 
            error=error, 
            username=session['name'], 
        )
    if request.method == 'POST':
        cleansourcename = cleanUrl(form.source.data)
        indicators = tolistofdicts(form.newlinei.data)
        filename = downloadedFilename(cleansourcename)
        if indicators == None:
            indicators = []
        result = Network_Bro_Intel_dt(
            type_hash = hash_type(NBI_HASH_STRING, cleansourcename),
            status = form.status.data,
            source = cleansourcename,
            bro_intel_indicators = indicators,
            priority = form.priority.data,
            created_by = session['name'],
            tags = [],
            notes = form.notes.data,
            localcsvfile = filename + '.csv'
            )
        result.str_tags = form.strtags.data
        try:
            db.session.add(result)
            db.session.commit()
            flash('successfully created network-bro_intel detection object')
            return redirect(url_for('scrape.manual_NBI'))
        except IntegrityError:
            error = 'source and network-bro_intel detection type object already exists.'
            return render_template('manual_NBI.html', 
                form=form, 
                error=error, 
                username=session['name'],
            )

@scrape_blueprint.route('/manual/network_snort/', methods=['GET', 'POST'])
@login_required
def manual_NS():
    error = None
    form = Manual(request.form)
    if request.method == 'GET':
        return render_template('manual_NS.html', 
            form=form, 
            error=error, 
            username=session['name'], 
        )
    if request.method == 'POST':
        cleansourcename = cleanUrl(form.source.data)
        indicators = snort_sig_to_list(form.newlinei.data)
        filename = downloadedFilename(cleansourcename)
        if indicators == None:
            indicators = []
        result = Network_Snort_dt(
            type_hash = hash_type(NS_HASH_STRING, cleansourcename),
            status = form.status.data,
            source = cleansourcename,
            snort_indicators = indicators,
            priority = form.priority.data,
            created_by = session['name'],
            tags = [],
            notes = form.notes.data,
            localcsvfile = filename + '.csv'
            )
        result.str_tags = form.strtags.data
        try:
            db.session.add(result)
            db.session.commit()
            flash('successfully created network-snort detection object')
            return redirect(url_for('scrape.manual_NS'))
        except IntegrityError:
            error = 'source and network-snort detection type object already exists.'
            return render_template('manual_NS.html', 
                form=form, 
                error=error, 
                username=session['name'],
            )

@scrape_blueprint.route('/manual/binary_yara/', methods=['GET', 'POST'])
@login_required
def manual_BY():
    error = None
    form = Manual(request.form)
    if request.method == 'GET':
        return render_template('manual_BY.html', 
            form=form, 
            error=error, 
            username=session['name'], 
        )
    if request.method == 'POST':
        cleansourcename = cleanUrl(form.source.data)
        indicators = yara_sig_to_list(form.newlinei.data)
        filename = downloadedFilename(cleansourcename)
        if indicators == None:
            indicators = []
        result = Binary_Yara_dt(
            type_hash = hash_type(BY_HASH_STRING, cleansourcename),
            status = form.status.data,
            source = cleansourcename,
            yara_indicators = indicators,
            priority = form.priority.data,
            created_by = session['name'],
            tags = [],
            notes = form.notes.data,
            localcsvfile = filename + '.csv'
            )
        result.str_tags = form.strtags.data
        try:
            db.session.add(result)
            db.session.commit()
            flash('successfully created binary-yara detection object')
            return redirect(url_for('scrape.manual_BY'))
        except IntegrityError:
            error = 'source and binary-yara detection type object already exists.'
            return render_template('manual_BY.html', 
                form=form, 
                error=error, 
                username=session['name'],
            )