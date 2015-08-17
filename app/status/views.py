# app/status/views.py

#################
#### imports ####
#################

from flask import flash, redirect, render_template, request, session, url_for, Blueprint, send_from_directory, Response
from sqlalchemy.exc import IntegrityError
from app.status.forms import EditScrape
from app import db, docs
from app.views import login_required, admin, cleantags, clean_NBI
from app.models import Network_Bro_Intel_dt, Network_Snort_dt, Binary_Yara_dt

#python lib
import json

################
#### helper ####
################

def listtostring(list1):
    return str(list1).replace('[','').replace(']','')

def timeconvert(dt):
    newtime = dt.strftime('%Y-%m-%d') + ' ' + dt.strftime('%H:%M:%S.%f')
    return newtime

def csvify_NBI(csvfile, indicators, sources, times, tags, notes):
    import csv
    with open('app/documents/' + csvfile, 'wb') as outcsv:
        writer = csv.writer(outcsv, quoting=csv.QUOTE_ALL)
        writer.writerow(['indicators', 'type', 'source', 'tags', 'notes', 'created_date'])
        for t in indicators:
            for k, v in t.iteritems():
                writer.writerow([v, k, sources, tags, notes, times])

def csvify(csvfile, indicators, sources, times, tags, notes):
    import csv
    with open('app/documents/' + csvfile, 'wb') as outcsv:
        writer = csv.writer(outcsv, quoting=csv.QUOTE_ALL)
        writer.writerow(['indicators', 'source', 'tags', 'notes', 'created_date'])
        for t in indicators:
            writer.writerow([t, sources, tags, notes, times])

################
#### config ####
################

status_blueprint = Blueprint(
    'status', __name__,
    url_prefix='/status',
    template_folder='templates',
    static_folder='static',
)

################
#### routes ####
################

@status_blueprint.route('/view/<string:view_id>/')
@login_required
def view_status(view_id):
    error = None
    hash_id = view_id
    NBI_view_vetted_status = db.session.query(Network_Bro_Intel_dt)
    NS_view_vetted_status = db.session.query(Network_Snort_dt)
    BY_view_vetted_status = db.session.query(Binary_Yara_dt)

    for view in NBI_view_vetted_status:
        if view.type_hash == hash_id:
            newlinei = clean_NBI(view.bro_intel_indicators)
            strtags = listtostring(view.tags)
            form = EditScrape(obj=view,
                        newlinei=newlinei,
                        )
            return render_template('view_dt_form.html', 
                form=form, 
                error=error, 
                username=session['name'], 
                strtags=strtags,
                e=view,
                )
    for view in NS_view_vetted_status:
        if view.type_hash == hash_id:
            newlinei = ''.join(view.snort_indicators)
            strtags = listtostring(view.tags)
            form = EditScrape(obj=view,
                        newlinei=newlinei,
                        )
            return render_template('view_dt_form.html', 
                form=form, 
                error=error, 
                username=session['name'], 
                e=view,
                strtags=strtags,
                )
    for view in BY_view_vetted_status:
        if view.type_hash == hash_id:
            newlinei = ''.join(view.yara_indicators)
            strtags = listtostring(view.tags)
            form = EditScrape(obj=view,
                        newlinei=newlinei,
                        )
            return render_template('view_dt_form.html', 
                form=form, 
                error=error, 
                username=session['name'], 
                e=view,
                strtags=strtags,
                )

    ###################
    #### downloads ####
    ###################

@status_blueprint.route('/api/vetted/json/<string:source_id>')
@login_required
def jsondl(source_id):
    hash_id = source_id
    NBI_ids = db.session.query(Network_Bro_Intel_dt).filter_by(status='vetted')
    NS_ids = db.session.query(Network_Snort_dt).filter_by(status='vetted')
    BY_ids = db.session.query(Binary_Yara_dt).filter_by(status='vetted')

    for json_d in NBI_ids:
        if json_d.type_hash == hash_id:
            ct = cleantags(json_d.tags)
            fn = json_d.source + '.json'
            jtime = timeconvert(json_d.created_date)

            data = {
            'source': json_d.source,
            'indicators': json_d.bro_intel_indicators,
            'tags' : ct,
            'created_date' : jtime,
            'notes' : json_d.notes
            }

            f = json.dumps(data, indent=4, sort_keys=True)

            return Response(f, 
                mimetype='application/json',
                headers={'Content-Disposition':'attachment;filename=%s' % fn},
                )
    for json_d in NS_ids:
        if json_d.type_hash == hash_id:
            ct = cleantags(json_d.tags)
            fn = json_d.source + '.json'
            jtime = timeconvert(json_d.created_date)

            data = {
            'source': json_d.source,
            'indicators': json_d.snort_indicators,
            'tags' : ct,
            'created_date' : jtime,
            'notes' : json_d.notes
            }

            f = json.dumps(data, indent=4, sort_keys=True)

            return Response(f, 
                mimetype='application/json',
                headers={'Content-Disposition':'attachment;filename=%s' % fn},
                )
    for json_d in BY_ids:
        if json_d.type_hash == hash_id:
            ct = cleantags(json_d.tags)
            fn = json_d.source + '.json'
            jtime = timeconvert(json_d.created_date)

            data = {
            'source': json_d.source,
            'indicators': json_d.yara_indicators,
            'tags' : ct,
            'created_date' : jtime,
            'notes' : json_d.notes
            }

            f = json.dumps(data, indent=4, sort_keys=True)

            return Response(f, 
                mimetype='application/json',
                headers={'Content-Disposition':'attachment;filename=%s' % fn},
                )

@status_blueprint.route('/api/vetted/csv/<string:source_id>')
@login_required
def csvdl(source_id):
    error = None
    hash_id = source_id
    NBI_ids = db.session.query(Network_Bro_Intel_dt).filter_by(status='vetted')
    NS_ids = db.session.query(Network_Snort_dt).filter_by(status='vetted')
    BY_ids = db.session.query(Binary_Yara_dt).filter_by(status='vetted')

    for csv_d in NBI_ids:
        if csv_d.type_hash == hash_id:
            ct = cleantags(csv_d.tags)
            fn = csv_d.localcsvfile
            jtime = timeconvert(csv_d.created_date)
            csvify_NBI(fn, csv_d.bro_intel_indicators, csv_d.source, jtime, ct, csv_d.notes)
            return send_from_directory(
                    directory=docs, 
                    filename=fn,
                    as_attachment=True
                    )
    for csv_d in NS_ids:
        if csv_d.type_hash == hash_id:
            ct = cleantags(csv_d.tags)
            fn = csv_d.localcsvfile
            jtime = timeconvert(csv_d.created_date)
            csvify(fn, csv_d.snort_indicators, csv_d.source, jtime, ct, csv_d.notes)
            return send_from_directory(
                    directory=docs, 
                    filename=fn,
                    as_attachment=True
                    )
    for csv_d in BY_ids:
        if csv_d.type_hash == hash_id:
            ct = cleantags(csv_d.tags)
            fn = csv_d.localcsvfile
            jtime = timeconvert(csv_d.created_date)
            csvify(fn, csv_d.yara_indicators, csv_d.source, jtime, ct, csv_d.notes)
            return send_from_directory(
                    directory=docs, 
                    filename=fn,
                    as_attachment=True
                    )

@status_blueprint.route('/download/<path:filename>')
@login_required
def download(filename):
    error = None
    return send_from_directory(
            directory=docs, 
            filename=filename,
            as_attachment=True
            )

    ##########
    ## OPEN ##
    ##########

@status_blueprint.route('/open/')
@login_required
def open_status():
    error = None
    NBI_ids = db.session.query(Network_Bro_Intel_dt).filter_by(status='open')
    NS_ids = db.session.query(Network_Snort_dt).filter_by(status='open')
    BY_ids = db.session.query(Binary_Yara_dt).filter_by(status='open')
    return render_template('open_status_table.html',
    	NBI_ids=NBI_ids,
        NS_ids=NS_ids,
        BY_ids=BY_ids,
    	error=error,
    	username=session['name'],
    	)

@status_blueprint.route('/open/delete/<string:open_id>')
@login_required
def delete_open_status(open_id):
    hash_id = open_id
    NBI_delete_open_status = db.session.query(Network_Bro_Intel_dt)
    NS_delete_open_status = db.session.query(Network_Snort_dt)
    BY_delete_open_status = db.session.query(Binary_Yara_dt)

    for delete in NBI_delete_open_status:
        if delete.type_hash == hash_id:
            d = db.session.query(Network_Bro_Intel_dt).filter_by(id=delete.id)
            d.delete()
    for delete in NS_delete_open_status:
        if delete.type_hash == hash_id:
            d = db.session.query(Network_Snort_dt).filter_by(id=delete.id)
            d.delete()
    for delete in BY_delete_open_status:
        if delete.type_hash == hash_id:
            d = db.session.query(Binary_Yara_dt).filter_by(id=delete.id)
            d.delete()

    db.session.commit()
    flash('The detection object was deleted')
    return redirect(url_for('status.open_status'))


@status_blueprint.route('/open/edit/<string:open_id>/', methods=['GET', 'POST'])
@login_required
def edit_open_status(open_id):
    error = None
    hash_id = open_id
    NBI_edit_open_status = db.session.query(Network_Bro_Intel_dt)
    NS_edit_open_status = db.session.query(Network_Snort_dt)
    BY_edit_open_status = db.session.query(Binary_Yara_dt)

    for edit in NBI_edit_open_status:
        if edit.type_hash == hash_id:
            newlinei = clean_NBI(edit.bro_intel_indicators)
            strtags = listtostring(edit.tags)
            form = EditScrape(obj=edit,
                        strtags=strtags,
                        newlinei=newlinei,
                        )
            if request.method == 'POST':
                d_obj = Network_Bro_Intel_dt.query.get(edit.id)
                if form.newlinei.data:
                    d_obj.newline_indicators = form.newlinei.data
                else:
                    d_obj.bro_intel_indicators = []
                d_obj.notes = form.notes.data
                d_obj.priority = form.priority.data
                d_obj.status = form.status.data
                d_obj.str_tags = form.strtags.data      
                if d_obj.status == 'reviewing':
                    d_obj.in_review_by = session['name']
                elif d_obj.status == 'vetted':
                    d_obj.vetted_by = session['name']
                elif d_obj.status == 'stale':
                    d_obj.stale_by = session['name']
                try:
                    db.session.commit()
                    flash('The entry was successfully updated.')
                    return redirect(url_for('status.open_status'))
                except IntegrityError:
                    error = 'Sorry, that source name already exists.'
                    return render_template('edit_dt_form.html', 
                        form=form, 
                        error=error, 
                        username=session['name'], 
                        e=e
                    )
            return render_template('edit_dt_form.html', 
                form=form, 
                error=error, 
                username=session['name'], 
                e=edit,
                )
    for edit in NS_edit_open_status:
        if edit.type_hash == hash_id:
            newlinei = ''.join(edit.snort_indicators)
            strtags = listtostring(edit.tags)
            form = EditScrape(obj=edit,
                        strtags=strtags,
                        newlinei=newlinei,
                        )
            if request.method == 'POST':
                d_obj = Network_Snort_dt.query.get(edit.id)
                if form.newlinei.data:
                    d_obj.newline_indicators = form.newlinei.data
                else:
                    d_obj.snort_indicators = []
                d_obj.notes = form.notes.data
                d_obj.priority = form.priority.data
                d_obj.status = form.status.data
                d_obj.str_tags = form.strtags.data      
                if d_obj.status == 'reviewing':
                    d_obj.in_review_by = session['name']
                elif d_obj.status == 'vetted':
                    d_obj.vetted_by = session['name']
                elif d_obj.status == 'stale':
                    d_obj.stale_by = session['name']
                try:
                    db.session.commit()
                    flash('The entry was successfully updated.')
                    return redirect(url_for('status.open_status'))
                except IntegrityError:
                    error = 'Sorry, that source name already exists.'
                    return render_template('edit_dt_form.html', 
                        form=form, 
                        error=error, 
                        username=session['name'], 
                        e=e
                    )
            return render_template('edit_dt_form.html', 
                form=form, 
                error=error, 
                username=session['name'], 
                e=edit,
                )
    for edit in BY_edit_open_status:
        if edit.type_hash == hash_id:
            newlinei = ''.join(edit.yara_indicators)
            strtags = listtostring(edit.tags)
            form = EditScrape(obj=edit,
                        strtags=strtags,
                        newlinei=newlinei,
                        )
            if request.method == 'POST':
                d_obj = Binary_Yara_dt.query.get(edit.id)
                if form.newlinei.data:
                    d_obj.newline_indicators = form.newlinei.data
                else:
                    d_obj.yara_indicators = []
                d_obj.notes = form.notes.data
                d_obj.priority = form.priority.data
                d_obj.status = form.status.data
                d_obj.str_tags = form.strtags.data      
                if d_obj.status == 'reviewing':
                    d_obj.in_review_by = session['name']
                elif d_obj.status == 'vetted':
                    d_obj.vetted_by = session['name']
                elif d_obj.status == 'stale':
                    d_obj.stale_by = session['name']
                try:
                    db.session.commit()
                    flash('The entry was successfully updated.')
                    return redirect(url_for('status.open_status'))

                except IntegrityError:
                    error = 'Sorry, that source name already exists.'
                    return render_template('edit_dt_form.html', 
                        form=form, 
                        error=error, 
                        username=session['name'], 
                        e=e
                    )
            return render_template('edit_dt_form.html', 
                form=form, 
                error=error, 
                username=session['name'], 
                e=edit,
                )


     ###############
     ## REVIEWING ##
     ###############

@status_blueprint.route('/reviewing/')
@login_required
def reviewing_status():
    error = None
    NBI_ids = db.session.query(Network_Bro_Intel_dt).filter_by(status='reviewing')
    NS_ids = db.session.query(Network_Snort_dt).filter_by(status='reviewing')
    BY_ids = db.session.query(Binary_Yara_dt).filter_by(status='reviewing')
    return render_template('reviewing_status_table.html',
        NBI_ids=NBI_ids,
        NS_ids=NS_ids,
        BY_ids=BY_ids,
        error=error,
        username=session['name'],
        )

@status_blueprint.route('/reviewing/delete/<string:reviewing_id>')
@login_required
@admin
def delete_reviewing_status(reviewing_id):
    hash_id = reviewing_id
    NBI_delete_reviewing_status = db.session.query(Network_Bro_Intel_dt)
    NS_delete_reviewing_status = db.session.query(Network_Snort_dt)
    BY_delete_reviewing_status = db.session.query(Binary_Yara_dt)

    for delete in NBI_delete_reviewing_status:
        if delete.type_hash == hash_id:
            d = db.session.query(Network_Bro_Intel_dt).filter_by(id=delete.id)
            d.delete()
    for delete in NS_delete_reviewing_status:
        if delete.type_hash == hash_id:
            d = db.session.query(Network_Snort_dt).filter_by(id=delete.id)
            d.delete()
    for delete in BY_delete_reviewing_status:
        if delete.type_hash == hash_id:
            d = db.session.query(Binary_Yara_dt).filter_by(id=delete.id)
            d.delete()

    db.session.commit()
    flash('The detection object was deleted')
    return redirect(url_for('status.reviewing_status'))

@status_blueprint.route('/reviewing/edit/<string:reviewing_id>/')
@login_required
def edit_reviewing_button_status(reviewing_id):
    error = None
    hash_id = reviewing_id
    NBI_edit_reviewing_status = db.session.query(Network_Bro_Intel_dt)
    NS_edit_reviewing_status = db.session.query(Network_Snort_dt)
    BY_edit_reviewing_status = db.session.query(Binary_Yara_dt)

    for edit in NBI_edit_reviewing_status:
        if edit.type_hash == hash_id:
            newlinei = clean_NBI(edit.bro_intel_indicators)
            strtags = listtostring(edit.tags)
            form = EditScrape(obj=edit,
                        strtags=strtags,
                        newlinei=newlinei,
                        )
            if edit.status == 'open':
                edit.status = 'reviewing'
                edit.in_review_by = session['name']
                db.session.commit()
                flash("status updated to 'reviewing'")
            return render_template('edit_dt_form.html', 
                form=form, 
                error=error, 
                username=session['name'], 
                e=edit,
                strtags=strtags,
                newlinei=newlinei,
            )
    for edit in NS_edit_reviewing_status:
        if edit.type_hash == hash_id:
            newlinei = ''.join(edit.snort_indicators)
            strtags = listtostring(edit.tags)
            form = EditScrape(obj=edit,
                        strtags=strtags,
                        newlinei=newlinei,
                        )
            if edit.status == 'open':
                edit.status = 'reviewing'
                edit.in_review_by = session['name']
                db.session.commit()
                flash("status updated to 'reviewing'")
            return render_template('edit_dt_form.html', 
                form=form, 
                error=error, 
                username=session['name'], 
                e=edit,
                strtags=strtags,
                newlinei=newlinei,
            )
    for edit in BY_edit_reviewing_status:
        if edit.type_hash == hash_id:
            newlinei = ''.join(edit.yara_indicators)
            strtags = listtostring(edit.tags)
            form = EditScrape(obj=edit,
                        strtags=strtags,
                        newlinei=newlinei,
                        )
            if edit.status == 'open':
                edit.status = 'reviewing'
                edit.in_review_by = session['name']
                db.session.commit()
                flash("status updated to 'reviewing'")
            return render_template('edit_dt_form.html', 
                form=form, 
                error=error, 
                username=session['name'], 
                e=edit,
                strtags=strtags,
                newlinei=newlinei,
            )
@status_blueprint.route('/reviewing/edit/<string:reviewing_id>/', methods=['GET', 'POST'])
@login_required
def edit_reviewing_status(reviewing_id):
    error = None
    hash_id = reviewing_id
    NBI_edit_reviewing_status = db.session.query(Network_Bro_Intel_dt)
    NS_edit_reviewing_status = db.session.query(Network_Snort_dt)
    BY_edit_reviewing_status = db.session.query(Binary_Yara_dt)

    for edit in NBI_edit_reviewing_status:
        if edit.type_hash == hash_id:
            newlinei = clean_NBI(edit.bro_intel_indicators)
            strtags = listtostring(edit.tags)
            form = EditScrape(obj=edit,
                        strtags=strtags,
                        newlinei=newlinei,
                        )
            if request.method == 'POST':
                d_obj = Network_Bro_Intel_dt.query.get(edit.id)
                if form.newlinei.data:
                    d_obj.newline_indicators = form.newlinei.data
                else:
                    d_obj.bro_intel_indicators = []
                d_obj.notes = form.notes.data
                d_obj.priority = form.priority.data
                d_obj.status = form.status.data
                d_obj.str_tags = form.strtags.data      
                if d_obj.status == 'reviewing':
                    d_obj.in_review_by = session['name']
                elif d_obj.status == 'vetted':
                    d_obj.vetted_by = session['name']
                elif d_obj.status == 'stale':
                    d_obj.stale_by = session['name']
                try:
                    db.session.commit()
                    flash('The entry was successfully updated.')
                    return redirect(url_for('status.reviewing_status'))
                except IntegrityError:
                    error = 'Sorry, that source name already exists.'
                    return render_template('edit_dt_form.html', 
                        form=form, 
                        error=error, 
                        username=session['name'], 
                        e=e
                    )
            return render_template('edit_dt_form.html', 
                form=form, 
                error=error, 
                username=session['name'], 
                e=edit,
                )
    for edit in NS_edit_reviewing_status:
        if edit.type_hash == hash_id:
            newlinei = ''.join(edit.snort_indicators)
            strtags = listtostring(edit.tags)
            form = EditScrape(obj=edit,
                        strtags=strtags,
                        newlinei=newlinei,
                        )
            if request.method == 'POST':
                d_obj = Network_Snort_dt.query.get(edit.id)
                if form.newlinei.data:
                    d_obj.newline_indicators = form.newlinei.data
                else:
                    d_obj.snort_indicators = []
                d_obj.notes = form.notes.data
                d_obj.priority = form.priority.data
                d_obj.status = form.status.data
                d_obj.str_tags = form.strtags.data      
                if d_obj.status == 'reviewing':
                    d_obj.in_review_by = session['name']
                elif d_obj.status == 'vetted':
                    d_obj.vetted_by = session['name']
                elif d_obj.status == 'stale':
                    d_obj.stale_by = session['name']
                try:
                    db.session.commit()
                    flash('The entry was successfully updated.')
                    return redirect(url_for('status.reviewing_status'))
                except IntegrityError:
                    error = 'Sorry, that source name already exists.'
                    return render_template('edit_dt_form.html', 
                        form=form, 
                        error=error, 
                        username=session['name'], 
                        e=e
                    )
            return render_template('edit_dt_form.html', 
                form=form, 
                error=error, 
                username=session['name'], 
                e=edit,
                )
    for edit in BY_edit_reviewing_status:
        if edit.type_hash == hash_id:
            newlinei = ''.join(edit.yara_indicators)
            strtags = listtostring(edit.tags)
            form = EditScrape(obj=edit,
                        strtags=strtags,
                        newlinei=newlinei,
                        )
            if request.method == 'POST':
                d_obj = Binary_Yara_dt.query.get(edit.id)
                if form.newlinei.data:
                    d_obj.newline_indicators = form.newlinei.data
                else:
                    d_obj.yara_indicators = []
                d_obj.notes = form.notes.data
                d_obj.priority = form.priority.data
                d_obj.status = form.status.data
                d_obj.str_tags = form.strtags.data      
                if d_obj.status == 'reviewing':
                    d_obj.in_review_by = session['name']
                elif d_obj.status == 'vetted':
                    d_obj.vetted_by = session['name']
                elif d_obj.status == 'stale':
                    d_obj.stale_by = session['name']
                try:
                    db.session.commit()
                    flash('The entry was successfully updated.')
                    return redirect(url_for('status.reviewing_status'))

                except IntegrityError:
                    error = 'Sorry, that source name already exists.'
                    return render_template('edit_dt_form.html', 
                        form=form, 
                        error=error, 
                        username=session['name'], 
                        e=e
                    )
            return render_template('edit_dt_form.html', 
                form=form, 
                error=error, 
                username=session['name'], 
                e=edit,
                )


     ############
     ## VETTED ##
     ############

@status_blueprint.route('/vetted/')
@login_required
def vetted_status():
    error = None
    NBI_ids = db.session.query(Network_Bro_Intel_dt).filter_by(status='vetted')
    NS_ids = db.session.query(Network_Snort_dt).filter_by(status='vetted')
    BY_ids = db.session.query(Binary_Yara_dt).filter_by(status='vetted')
    return render_template('vetted_status_table.html',
        NBI_ids=NBI_ids,
        NS_ids=NS_ids,
        BY_ids=BY_ids,
        error=error,
        username=session['name'],
        )

@status_blueprint.route('/vetted/delete/<string:vetted_id>')
@login_required
@admin
def delete_vetted_status(vetted_id):
    hash_id = vetted_id
    NBI_delete_vetted_status = db.session.query(Network_Bro_Intel_dt)
    NS_delete_vetted_status = db.session.query(Network_Snort_dt)
    BY_delete_vetted_status = db.session.query(Binary_Yara_dt)

    for delete in NBI_delete_vetted_status:
        if delete.type_hash == hash_id:
            d = db.session.query(Network_Bro_Intel_dt).filter_by(id=delete.id)
            d.delete()
    for delete in NS_delete_vetted_status:
        if delete.type_hash == hash_id:
            d = db.session.query(Network_Snort_dt).filter_by(id=delete.id)
            d.delete()
    for delete in BY_delete_vetted_status:
        if delete.type_hash == hash_id:
            d = db.session.query(Binary_Yara_dt).filter_by(id=delete.id)
            d.delete()

    db.session.commit()
    flash('The detection object was deleted')
    return redirect(url_for('status.vetted_status'))

@status_blueprint.route('/vetted/edit/<string:vetted_id>/', methods=['GET', 'POST'])
@login_required
@admin
def edit_vetted_status(vetted_id):
    error = None
    hash_id = vetted_id
    NBI_edit_vetted_status = db.session.query(Network_Bro_Intel_dt)
    NS_edit_vetted_status = db.session.query(Network_Snort_dt)
    BY_edit_vetted_status = db.session.query(Binary_Yara_dt)

    for edit in NBI_edit_vetted_status:
        if edit.type_hash == hash_id:
            newlinei = clean_NBI(edit.bro_intel_indicators)
            strtags = listtostring(edit.tags)
            form = EditScrape(obj=edit,
                        strtags=strtags,
                        newlinei=newlinei,
                        )
            if request.method == 'POST':
                d_obj = Network_Bro_Intel_dt.query.get(edit.id)
                if form.newlinei.data:
                    d_obj.newline_indicators = form.newlinei.data
                else:
                    d_obj.bro_intel_indicators = []
                d_obj.notes = form.notes.data
                d_obj.priority = form.priority.data
                d_obj.status = form.status.data
                d_obj.str_tags = form.strtags.data      
                if d_obj.status == 'reviewing':
                    d_obj.in_review_by = session['name']
                elif d_obj.status == 'vetted':
                    d_obj.vetted_by = session['name']
                elif d_obj.status == 'stale':
                    d_obj.stale_by = session['name']
                try:
                    db.session.commit()
                    flash('The entry was successfully updated.')
                    return redirect(url_for('status.vetted_status'))
                except IntegrityError:
                    error = 'Sorry, that source name already exists.'
                    return render_template('edit_dt_form.html', 
                        form=form, 
                        error=error, 
                        username=session['name'], 
                        e=e
                    )
            return render_template('edit_dt_form.html', 
                form=form, 
                error=error, 
                username=session['name'], 
                e=edit,
                )
    for edit in NS_edit_vetted_status:
        if edit.type_hash == hash_id:
            newlinei = ''.join(edit.snort_indicators)
            strtags = listtostring(edit.tags)
            form = EditScrape(obj=edit,
                        strtags=strtags,
                        newlinei=newlinei,
                        )
            if request.method == 'POST':
                d_obj = Network_Snort_dt.query.get(edit.id)
                if form.newlinei.data:
                    d_obj.newline_indicators = form.newlinei.data
                else:
                    d_obj.snort_indicators = []
                d_obj.notes = form.notes.data
                d_obj.priority = form.priority.data
                d_obj.status = form.status.data
                d_obj.str_tags = form.strtags.data      
                if d_obj.status == 'reviewing':
                    d_obj.in_review_by = session['name']
                elif d_obj.status == 'vetted':
                    d_obj.vetted_by = session['name']
                elif d_obj.status == 'stale':
                    d_obj.stale_by = session['name']
                try:
                    db.session.commit()
                    flash('The entry was successfully updated.')
                    return redirect(url_for('status.vetted_status'))
                except IntegrityError:
                    error = 'Sorry, that source name already exists.'
                    return render_template('edit_dt_form.html', 
                        form=form, 
                        error=error, 
                        username=session['name'], 
                        e=e
                    )
            return render_template('edit_dt_form.html', 
                form=form, 
                error=error, 
                username=session['name'], 
                e=edit,
                )
    for edit in BY_edit_vetted_status:
        if edit.type_hash == hash_id:
            newlinei = ''.join(edit.yara_indicators)
            strtags = listtostring(edit.tags)
            form = EditScrape(obj=edit,
                        strtags=strtags,
                        newlinei=newlinei,
                        )
            if request.method == 'POST':
                d_obj = Binary_Yara_dt.query.get(edit.id)
                if form.newlinei.data:
                    d_obj.newline_indicators = form.newlinei.data
                else:
                    d_obj.yara_indicators = []
                d_obj.notes = form.notes.data
                d_obj.priority = form.priority.data
                d_obj.status = form.status.data
                d_obj.str_tags = form.strtags.data      
                if d_obj.status == 'reviewing':
                    d_obj.in_review_by = session['name']
                elif d_obj.status == 'vetted':
                    d_obj.vetted_by = session['name']
                elif d_obj.status == 'stale':
                    d_obj.stale_by = session['name']
                try:
                    db.session.commit()
                    flash('The entry was successfully updated.')
                    return redirect(url_for('status.vetted_status'))

                except IntegrityError:
                    error = 'Sorry, that source name already exists.'
                    return render_template('edit_dt_form.html', 
                        form=form, 
                        error=error, 
                        username=session['name'], 
                        e=e
                    )
            return render_template('edit_dt_form.html', 
                form=form, 
                error=error, 
                username=session['name'], 
                e=edit,
                )


    ###########
    ## STALE ##
    ###########

@status_blueprint.route('/stale/')
@login_required
def stale_status():
    error = None
    NBI_ids = db.session.query(Network_Bro_Intel_dt).filter_by(status='stale')
    NS_ids = db.session.query(Network_Snort_dt).filter_by(status='stale')
    BY_ids = db.session.query(Binary_Yara_dt).filter_by(status='stale')
    return render_template('stale_status_table.html',
        NBI_ids=NBI_ids,
        NS_ids=NS_ids,
        BY_ids=BY_ids,
        error=error,
        username=session['name'],
        )

@status_blueprint.route('/stale/delete/<string:stale_id>')
@login_required
@admin
def delete_stale_status(stale_id):
    hash_id = stale_id
    NBI_delete_stale_status = db.session.query(Network_Bro_Intel_dt)
    NS_delete_stale_status = db.session.query(Network_Snort_dt)
    BY_delete_stale_status = db.session.query(Binary_Yara_dt)

    for delete in NBI_delete_stale_status:
        if delete.type_hash == hash_id:
            d = db.session.query(Network_Bro_Intel_dt).filter_by(id=delete.id)
            d.delete()
    for delete in NS_delete_stale_status:
        if delete.type_hash == hash_id:
            d = db.session.query(Network_Snort_dt).filter_by(id=delete.id)
            d.delete()
    for delete in BY_delete_stale_status:
        if delete.type_hash == hash_id:
            d = db.session.query(Binary_Yara_dt).filter_by(id=delete.id)
            d.delete()

    db.session.commit()
    flash('The detection object was deleted')
    return redirect(url_for('status.stale_status'))

@status_blueprint.route('/stale/edit/<string:stale_id>/', methods=['GET', 'POST'])
@login_required
@admin
def edit_stale_status(stale_id):
    error = None
    hash_id = stale_id
    NBI_edit_stale_status = db.session.query(Network_Bro_Intel_dt)
    NS_edit_stale_status = db.session.query(Network_Snort_dt)
    BY_edit_stale_status = db.session.query(Binary_Yara_dt)

    for edit in NBI_edit_stale_status:
        if edit.type_hash == hash_id:
            newlinei = clean_NBI(edit.bro_intel_indicators)
            strtags = listtostring(edit.tags)
            form = EditScrape(obj=edit,
                        strtags=strtags,
                        newlinei=newlinei,
                        )
            if request.method == 'POST':
                d_obj = Network_Bro_Intel_dt.query.get(edit.id)
                if form.newlinei.data:
                    d_obj.newline_indicators = form.newlinei.data
                else:
                    d_obj.bro_intel_indicators = []
                d_obj.notes = form.notes.data
                d_obj.priority = form.priority.data
                d_obj.status = form.status.data
                d_obj.str_tags = form.strtags.data      
                if d_obj.status == 'reviewing':
                    d_obj.in_review_by = session['name']
                elif d_obj.status == 'vetted':
                    d_obj.vetted_by = session['name']
                elif d_obj.status == 'stale':
                    d_obj.stale_by = session['name']
                try:
                    db.session.commit()
                    flash('The entry was successfully updated.')
                    return redirect(url_for('status.stale_status'))
                except IntegrityError:
                    error = 'Sorry, that source name already exists.'
                    return render_template('edit_dt_form.html', 
                        form=form, 
                        error=error, 
                        username=session['name'], 
                        e=e
                    )
            return render_template('edit_dt_form.html', 
                form=form, 
                error=error, 
                username=session['name'], 
                e=edit,
                )
    for edit in NS_edit_stale_status:
        if edit.type_hash == hash_id:
            newlinei = ''.join(edit.snort_indicators)
            strtags = listtostring(edit.tags)
            form = EditScrape(obj=edit,
                        strtags=strtags,
                        newlinei=newlinei,
                        )
            if request.method == 'POST':
                d_obj = Network_Snort_dt.query.get(edit.id)
                if form.newlinei.data:
                    d_obj.newline_indicators = form.newlinei.data
                else:
                    d_obj.snort_indicators = []
                d_obj.notes = form.notes.data
                d_obj.priority = form.priority.data
                d_obj.status = form.status.data
                d_obj.str_tags = form.strtags.data      
                if d_obj.status == 'reviewing':
                    d_obj.in_review_by = session['name']
                elif d_obj.status == 'vetted':
                    d_obj.vetted_by = session['name']
                elif d_obj.status == 'stale':
                    d_obj.stale_by = session['name']
                try:
                    db.session.commit()
                    flash('The entry was successfully updated.')
                    return redirect(url_for('status.stale_status'))
                except IntegrityError:
                    error = 'Sorry, that source name already exists.'
                    return render_template('edit_dt_form.html', 
                        form=form, 
                        error=error, 
                        username=session['name'], 
                        e=e
                    )
            return render_template('edit_dt_form.html', 
                form=form, 
                error=error, 
                username=session['name'], 
                e=edit,
                )
    for edit in BY_edit_stale_status:
        if edit.type_hash == hash_id:
            newlinei = ''.join(edit.yara_indicators)
            strtags = listtostring(edit.tags)
            form = EditScrape(obj=edit,
                        strtags=strtags,
                        newlinei=newlinei,
                        )
            if request.method == 'POST':
                d_obj = Binary_Yara_dt.query.get(edit.id)
                if form.newlinei.data:
                    d_obj.newline_indicators = form.newlinei.data
                else:
                    d_obj.yara_indicators = []
                d_obj.notes = form.notes.data
                d_obj.priority = form.priority.data
                d_obj.status = form.status.data
                d_obj.str_tags = form.strtags.data      
                if d_obj.status == 'reviewing':
                    d_obj.in_review_by = session['name']
                elif d_obj.status == 'vetted':
                    d_obj.vetted_by = session['name']
                elif d_obj.status == 'stale':
                    d_obj.stale_by = session['name']
                try:
                    db.session.commit()
                    flash('The entry was successfully updated.')
                    return redirect(url_for('status.stale_status'))

                except IntegrityError:
                    error = 'Sorry, that source name already exists.'
                    return render_template('edit_dt_form.html', 
                        form=form, 
                        error=error, 
                        username=session['name'], 
                        e=e
                    )
            return render_template('edit_dt_form.html', 
                form=form, 
                error=error, 
                username=session['name'], 
                e=edit,
                )


    #########
    ## ALL ##
    #########

@status_blueprint.route('/all/')
@login_required
def all_status():
    error = None
    NBI_ids = db.session.query(Network_Bro_Intel_dt)
    NS_ids = db.session.query(Network_Snort_dt)
    BY_ids = db.session.query(Binary_Yara_dt)
    return render_template('all_status_table.html',
        NBI_ids=NBI_ids,
        NS_ids=NS_ids,
        BY_ids=BY_ids,
        error=error,
        username=session['name'],
        )

@status_blueprint.route('/all/delete/<string:all_id>')
@login_required
@admin
def delete_all_status(all_id):
    hash_id = all_id
    NBI_delete_all_status = db.session.query(Network_Bro_Intel_dt)
    NS_delete_all_status = db.session.query(Network_Snort_dt)
    BY_delete_all_status = db.session.query(Binary_Yara_dt)

    for delete in NBI_delete_all_status:
        if delete.type_hash == hash_id:
            d = db.session.query(Network_Bro_Intel_dt).filter_by(id=delete.id)
            d.delete()
    for delete in NS_delete_all_status:
        if delete.type_hash == hash_id:
            d = db.session.query(Network_Snort_dt).filter_by(id=delete.id)
            d.delete()
    for delete in BY_delete_all_status:
        if delete.type_hash == hash_id:
            d = db.session.query(Binary_Yara_dt).filter_by(id=delete.id)
            d.delete()

    db.session.commit()
    flash('The detection object was deleted')
    return redirect(url_for('status.all_status'))

@status_blueprint.route('/all/edit/<string:all_id>/', methods=['GET', 'POST'])
@login_required
@admin
def edit_all_status(all_id):
    error = None
    hash_id = all_id
    NBI_edit_all_status = db.session.query(Network_Bro_Intel_dt)
    NS_edit_all_status = db.session.query(Network_Snort_dt)
    BY_edit_all_status = db.session.query(Binary_Yara_dt)

    for edit in NBI_edit_all_status:
        if edit.type_hash == hash_id:
            newlinei = clean_NBI(edit.bro_intel_indicators)
            strtags = listtostring(edit.tags)
            form = EditScrape(obj=edit,
                        strtags=strtags,
                        newlinei=newlinei,
                        )
            if request.method == 'POST':
                d_obj = Network_Bro_Intel_dt.query.get(edit.id)
                if form.newlinei.data:
                    d_obj.newline_indicators = form.newlinei.data
                else:
                    d_obj.bro_intel_indicators = []
                d_obj.notes = form.notes.data
                d_obj.priority = form.priority.data
                d_obj.status = form.status.data
                d_obj.str_tags = form.strtags.data      
                if d_obj.status == 'reviewing':
                    d_obj.in_review_by = session['name']
                elif d_obj.status == 'vetted':
                    d_obj.vetted_by = session['name']
                elif d_obj.status == 'stale':
                    d_obj.stale_by = session['name']
                try:
                    db.session.commit()
                    flash('The entry was successfully updated.')
                    return redirect(url_for('status.all_status'))
                except IntegrityError:
                    error = 'Sorry, that source name already exists.'
                    return render_template('edit_dt_form.html', 
                        form=form, 
                        error=error, 
                        username=session['name'], 
                        e=e
                    )
            return render_template('edit_dt_form.html', 
                form=form, 
                error=error, 
                username=session['name'], 
                e=edit,
                )
    for edit in NS_edit_all_status:
        if edit.type_hash == hash_id:
            newlinei = ''.join(edit.snort_indicators)
            strtags = listtostring(edit.tags)
            form = EditScrape(obj=edit,
                        strtags=strtags,
                        newlinei=newlinei,
                        )
            if request.method == 'POST':
                d_obj = Network_Snort_dt.query.get(edit.id)
                if form.newlinei.data:
                    d_obj.newline_indicators = form.newlinei.data
                else:
                    d_obj.snort_indicators = []
                d_obj.notes = form.notes.data
                d_obj.priority = form.priority.data
                d_obj.status = form.status.data
                d_obj.str_tags = form.strtags.data      
                if d_obj.status == 'reviewing':
                    d_obj.in_review_by = session['name']
                elif d_obj.status == 'vetted':
                    d_obj.vetted_by = session['name']
                elif d_obj.status == 'stale':
                    d_obj.stale_by = session['name']
                try:
                    db.session.commit()
                    flash('The entry was successfully updated.')
                    return redirect(url_for('status.all_status'))
                except IntegrityError:
                    error = 'Sorry, that source name already exists.'
                    return render_template('edit_dt_form.html', 
                        form=form, 
                        error=error, 
                        username=session['name'], 
                        e=e
                    )
            return render_template('edit_dt_form.html', 
                form=form, 
                error=error, 
                username=session['name'], 
                e=edit,
                )
    for edit in BY_edit_all_status:
        if edit.type_hash == hash_id:
            newlinei = ''.join(edit.yara_indicators)
            strtags = listtostring(edit.tags)
            form = EditScrape(obj=edit,
                        strtags=strtags,
                        newlinei=newlinei,
                        )
            if request.method == 'POST':
                d_obj = Binary_Yara_dt.query.get(edit.id)
                if form.newlinei.data:
                    d_obj.newline_indicators = form.newlinei.data
                else:
                    d_obj.yara_indicators = []
                d_obj.notes = form.notes.data
                d_obj.priority = form.priority.data
                d_obj.status = form.status.data
                d_obj.str_tags = form.strtags.data      
                if d_obj.status == 'reviewing':
                    d_obj.in_review_by = session['name']
                elif d_obj.status == 'vetted':
                    d_obj.vetted_by = session['name']
                elif d_obj.status == 'stale':
                    d_obj.stale_by = session['name']
                try:
                    db.session.commit()
                    flash('The entry was successfully updated.')
                    return redirect(url_for('status.all_status'))

                except IntegrityError:
                    error = 'Sorry, that source name already exists.'
                    return render_template('edit_dt_form.html', 
                        form=form, 
                        error=error, 
                        username=session['name'], 
                        e=e
                    )
            return render_template('edit_dt_form.html', 
                form=form, 
                error=error, 
                username=session['name'], 
                e=edit,
                )