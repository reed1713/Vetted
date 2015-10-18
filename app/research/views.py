# app/research/views.py

#################
#### imports ####
#################

from flask import flash, redirect, render_template, request, session, url_for, Blueprint, send_from_directory, jsonify
from sqlalchemy.exc import InvalidRequestError, IntegrityError
from app.research.forms import feeds_form, feed_edit_form
from app import db, docs, app
from app.views import login_required, admin
from app.models import Feeds, Feed_source

#local helper methods
from scripts.Wpuller import checkfeed

#python lib
import feedparser
import time
import datetime

# length of time in days to pull and keep feeds
FEED_TIME = 7

################
#### helper ####
################


################
#### config ####
################

research_blueprint = Blueprint(
    'research', __name__,
    url_prefix='/research',
    template_folder='templates',
    static_folder='static',
)

################
#### routes ####
################


    ################
    ### TI Feeds ###
    ################


@research_blueprint.route('/TI_update_feeds/', methods=['GET', 'POST'])
@login_required
@admin
def TI_update_feeds():

    #delete feeds without a source
    feeds = db.session.query(Feeds).filter_by(feed_type='tactical_intel')
    for feed_s in feeds:
        if feed_s.feed_feedsource == None:
            feeds_to_delete = db.session.query(Feeds).filter_by(id=feed_s.id)
            feeds_to_delete.delete()
            db.session.commit()

    #update the feed pull time
    new_feedtime = db.session.query(Feed_source).filter_by(feedsource_type='tactical_intel')
    for n in new_feedtime:    
        cleantime = datetime.datetime.utcnow()
        n.feed_update_time = cleantime
        db.session.commit()

    #delete feeds older than the specified feed time
    old_feeds = db.session.query(Feeds).filter_by(feed_type='tactical_intel')
    for feed_time in old_feeds:
        pattern = '%Y-%m-%d' + ' ' + '%H:%M:%S'
        epoch = int(time.mktime(time.strptime(str(feed_time.feed_time), pattern)))
        if time.time() - epoch > (86400*FEED_TIME):
            feeds_delete = db.session.query(Feeds).filter_by(id=feed_time.id, feed_type='tactical_intel')
            feeds_delete.delete()
            db.session.commit()

    #pulls the feeds checks the time, if less than specified pull time
    #adds to db, if the record already exists its ignored
    test = db.session.query(Feed_source).filter_by(feedsource_type='tactical_intel')
    for t in test:
        entries = feedparser.parse(t.feedsource).entries
        for e in entries:
            try:
                if time.time() - time.mktime(e.published_parsed) < (86400*FEED_TIME):
                    feed_title = e['title']
                    feed_link = e['link']
                    feed_time_struct = e['published_parsed']
                    feed_time = datetime.datetime.fromtimestamp(time.mktime(feed_time_struct))           
                    result = Feeds(
                        feed_confidence = t.sourceconfidence,
                        feed_feedsource = t.feedsource,
                        feed_title = feed_title,
                        feed_link = feed_link,
                        feed_time = feed_time,
                        feed_type = 'tactical_intel',
                        )
                    try:
                        db.session.add(result)
                        db.session.commit()
                    except IntegrityError:
                        db.session.rollback()
            except AttributeError:
                pass


    flash('Feeds were successfully updated')
    return redirect(url_for('research.TI_research_feeds'))

@research_blueprint.route('/TI_update_read_feeds/<int:feed_id>')
@login_required
def TI_read_feeds(feed_id):

    f_id = feed_id
    update_feed_status = db.session.query(Feeds).filter_by(id=f_id)
    for u in update_feed_status:
        u.feed_status = False
    db.session.commit()
    flash('Article was moved to closed')
    return redirect(url_for('research.TI_research_feeds'))

@research_blueprint.route('/TI_feeds/')
@login_required
def TI_research_feeds():

    entries = db.session.query(Feeds).filter_by(feed_status=True).filter_by(feed_type='tactical_intel')

    ut = db.session.query(Feed_source.feed_update_time).filter_by(feedsource_type='tactical_intel').first()
    if ut:
        for u in ut:
            lt = u
            entries_sorted = sorted(
            entries, 
            key=lambda e: e.feed_confidence)

            return render_template(
                'TI_feeds.html',
                entries=entries_sorted,
                username=session['name'],
                lt = lt,
                )
    else:
        entries_sorted = sorted(
        entries,
        key=lambda e: e.feed_confidence)

        return render_template(
            'TI_feeds.html',
            entries=entries_sorted,
            username=session['name'],
            )

@research_blueprint.route('/TI_closed_feeds/')
@login_required
def TI_closed_feeds():

    entries = db.session.query(Feeds).filter_by(feed_status=False, feed_type='tactical_intel')

    ut = db.session.query(Feed_source.feed_update_time).filter_by(feedsource_type='tactical_intel').first()
    if ut:
        for u in ut:
            lt = u
            entries_sorted = sorted(
            entries, 
            key=lambda e: e.feed_confidence)

            return render_template(
                'TI_feeds_closed.html',
                entries=entries_sorted,
                username=session['name'],
                lt = lt,
                )
    else:
        entries_sorted = sorted(
        entries,
        key=lambda e: e.feed_confidence)

        return render_template(
            'TI_feeds_closed.html',
            entries=entries_sorted,
            username=session['name'],
            )

    ################
    ### SI Feeds ###
    ################

@research_blueprint.route('/SI_update_feeds/', methods=['GET', 'POST'])
@login_required
@admin
def SI_update_feeds():

    #delete feeds without a source
    feeds = db.session.query(Feeds).filter_by(feed_type='strategic_intel')
    for feed_s in feeds:
        if feed_s.feed_feedsource == None:
            feeds_to_delete = db.session.query(Feeds).filter_by(id=feed_s.id)
            feeds_to_delete.delete()
            db.session.commit()

    #update the feed pull time
    new_feedtime = db.session.query(Feed_source).filter_by(feedsource_type='strategic_intel')
    for n in new_feedtime:    
        cleantime = datetime.datetime.utcnow()
        n.feed_update_time = cleantime
        db.session.commit()

    #delete feeds older than the specified feed time
    old_feeds = db.session.query(Feeds).filter_by(feed_type='strategic_intel')
    for feed_time in old_feeds:
        pattern = '%Y-%m-%d' + ' ' + '%H:%M:%S'
        epoch = int(time.mktime(time.strptime(str(feed_time.feed_time), pattern)))
        if time.time() - epoch > (86400*FEED_TIME):
            feeds_delete = db.session.query(Feeds).filter_by(id=feed_time.id, feed_type='strategic_intel')
            feeds_delete.delete()
            db.session.commit()

    #pulls the feeds checks the time, if less than specified pull time
    #adds to db, if the record already exists its ignored
    test = db.session.query(Feed_source).filter_by(feedsource_type='strategic_intel')
    for t in test:
        entries = feedparser.parse(t.feedsource).entries
        for e in entries:
            try:
                if time.time() - time.mktime(e.published_parsed) < (86400*FEED_TIME):
                    feed_title = e['title']
                    feed_link = e['link']
                    feed_time_struct = e['published_parsed']
                    feed_time = datetime.datetime.fromtimestamp(time.mktime(feed_time_struct))           
                    result = Feeds(
                        feed_confidence = t.sourceconfidence,
                        feed_feedsource = t.feedsource,
                        feed_title = feed_title,
                        feed_link = feed_link,
                        feed_time = feed_time,
                        feed_type = 'strategic_intel',
                        )
                    try:
                        db.session.add(result)
                        db.session.commit()
                    except IntegrityError:
                        db.session.rollback()
            except AttributeError:
                pass


    flash('Feeds were successfully updated')
    return redirect(url_for('research.SI_research_feeds'))

@research_blueprint.route('/SI_update_read_feeds/<int:feed_id>')
@login_required
def SI_read_feeds(feed_id):

    f_id = feed_id
    update_feed_status = db.session.query(Feeds).filter_by(id=f_id)
    for u in update_feed_status:
        u.feed_status = False
    db.session.commit()
    flash('Article was moved to closed')
    return redirect(url_for('research.SI_research_feeds'))

@research_blueprint.route('/SI_feeds/')
@login_required
def SI_research_feeds():

    entries = db.session.query(Feeds).filter_by(feed_status=True).filter_by(feed_type='strategic_intel')

    ut = db.session.query(Feed_source.feed_update_time).filter_by(feedsource_type='strategic_intel').first()
    if ut:
        for u in ut:
            lt = u
            entries_sorted = sorted(
            entries, 
            key=lambda e: e.feed_confidence)

            return render_template(
                'SI_feeds.html',
                entries=entries_sorted,
                username=session['name'],
                lt = lt,
                )
    else:
        entries_sorted = sorted(
        entries,
        key=lambda e: e.feed_confidence)

        return render_template(
            'SI_feeds.html',
            entries=entries_sorted,
            username=session['name'],
            )

@research_blueprint.route('/SI_closed_feeds/')
@login_required
def SI_closed_feeds():

    entries = db.session.query(Feeds).filter_by(feed_status=False, feed_type='strategic_intel')

    ut = db.session.query(Feed_source.feed_update_time).filter_by(feedsource_type='strategic_intel').first()
    if ut:
        for u in ut:
            lt = u
            entries_sorted = sorted(
            entries, 
            key=lambda e: e.feed_confidence)

            return render_template(
                'SI_feeds_closed.html',
                entries=entries_sorted,
                username=session['name'],
                lt = lt,
                )
    else:
        entries_sorted = sorted(
        entries,
        key=lambda e: e.feed_confidence)

        return render_template(
            'SI_feeds_closed.html',
            entries=entries_sorted,
            username=session['name'],
            )

    ####################
    ### Feed Sources ###
    ####################

@research_blueprint.route('/list_feeds/')
@login_required
@admin
def list_feeds():
    error=None
    feed_src = db.session.query(Feed_source)
    return render_template('feed_sources.html',  
                error=error, 
                feed_src=feed_src, 
                username=session['name']
                )

@research_blueprint.route('/edit_feed/<int:feed_id>/', methods=['GET', 'POST'])
@login_required
@admin
def edit_feed(feed_id):
    error = None
    edit = db.session.query(Feed_source).filter_by(id=feed_id)
    form = feed_edit_form(request.form)

    for e in edit:
        form = feed_edit_form(obj=e,
                        )

    if request.method == 'GET':
        return render_template('edit_feed.html', 
            form=form, 
            error=error, 
            username=session['name'], 
            e=e,
            )

    if request.method == 'POST':
        edit_feed_s = Feed_source.query.get(feed_id)
        edit_feed_s.sourceconfidence = form.sourceconfidence.data
        edit_feed_s.feedsource_type = form.feedsource_type.data
        queryfeeds = db.session.query(Feeds).filter_by(feed_feedsource=edit_feed_s.feedsource)
        for q in queryfeeds:
            feeder = Feeds.query.get(q.id)
            feeder.feed_confidence = edit_feed_s.sourceconfidence
            feeder.feed_type = edit_feed_s.feedsource_type
        try:
            db.session.commit()
            flash('The feed source was successfully updated.')
            return redirect(url_for('research.list_feeds'))

        except IntegrityError:
            db.session.rollback()
            error = 'Sorry that feed source already exist.'
            return render_template('edit_feed.html', 
                form=form, 
                error=error, 
                username=session['name'],
                e=e
                )

@research_blueprint.route('/create_feed/', methods=['GET', 'POST'])
@login_required
@admin
def new_feed():
    error = None
    form = feeds_form(request.form)

    if request.method == 'POST':
        fs = form.feedsrc.data
        test = checkfeed(fs)
        if test != 'FAIL':
            new_feed = Feed_source(
                feedsource = form.feedsrc.data,
                sourceconfidence = form.sourceconfidence.data,
                feedsource_type = form.feedsource_type.data,
            )
            try:
                db.session.add(new_feed)
                db.session.commit()
                flash('Feed created')
                return redirect(url_for('research.list_feeds'))
            except IntegrityError:
                db.session.rollback()
                error = 'Sorry that feed source already exist.'
                return render_template('create_feed.html', 
                    form=form, 
                    error=error, 
                    username=session['name']
                    )
        else:
            error = 'python feedparser formatting issue with that source. use the \'checkfeed\' method in the Wpuller.py script to identify issue.'
            return render_template('create_feed.html',
                error=error,
                form=form, 
                username=session['name']
                )
    if request.method == 'GET':
        return render_template('create_feed.html', 
            form=form, 
            username=session['name']
            )

@research_blueprint.route('/delete/<int:feedsource_id>')
@login_required
@admin
def delete_feedsource(feedsource_id):
    error = None
    todelete = db.session.query(Feed_source).filter_by(id=feedsource_id)
    todelete.delete()
    try:
        db.session.commit()
        flash('The feed source was deleted')
        return redirect(url_for('research.list_feeds'))
    except InvalidRequestError:
        error = ("something broke")
        return redirect(url_for('research.list_feeds'))
