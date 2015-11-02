#app/models.py

from app import db

from sqlalchemy.dialects.postgresql import JSON
from sqlalchemy import Column, Integer, String, ForeignKey, Table
from sqlalchemy.orm import relationship, backref
from sqlalchemy.ext.associationproxy import association_proxy

#python lib
from datetime import datetime
import json
import re

#####################
## Detection Types ##
#####################


class Network_Bro_Intel_dt(db.Model):

    __tablename__ = 'N_bro_intel'

    id = db.Column(db.Integer, primary_key=True)
    type_hash = db.Column(db.String, unique=True)
    source = db.Column(db.String)
    bro_intel_indicators = db.Column(JSON)
    d_type = db.Column(db.String)
    tags = db.relationship('Tag', secondary=lambda: Nbro_intel_tags_relation_table)
    notes = db.Column(db.String)
    localfile = db.Column(db.String)
    localtxtfile = db.Column(db.String)
    localcsvfile = db.Column(db.String)
    created_date = db.Column(db.DateTime(), default=datetime.utcnow)
    created_by = db.Column(db.String, db.ForeignKey('users.name', ondelete='SET NULL'))
    in_review_by = db.Column(db.String, db.ForeignKey('users.name', ondelete='SET NULL'))
    vetted_by = db.Column(db.String, db.ForeignKey('users.name', ondelete='SET NULL'))
    stale_by = db.Column(db.String, db.ForeignKey('users.name', ondelete='SET NULL'))
    priority = db.Column(db.Integer, default=3)
    status = db.Column(db.String, default='open')

    def __init__(self,
        type_hash = None,
        source = None, 
        bro_intel_indicators = None,
        d_type = 'Network - Bro Intel',
        tags = None,
        notes = None,
        localcsvfile = None,
        localtxtfile = None,
        localfile = None,
        created_date = None,
        priority = None, 
        status = None,
        created_by = None, 
        in_review_by = None,
        vetted_by = None,
        stale_by = None,
        ):

        self.type_hash = type_hash
        self.source = source
        self.bro_intel_indicators = bro_intel_indicators
        self.d_type = d_type
        self.tags = tags
        self.notes = notes
        self.localfile = localfile
        self.localtxtfile = localtxtfile
        self.localcsvfile = localcsvfile
        self.created_date = created_date
        self.priority = priority
        self.status = status
        self.created_by = created_by
        self.in_review_by = in_review_by
        self.vetted_by = vetted_by
        self.stale_by = stale_by

    def __repr__(self):
        return '<id {}>'.format(self.id)

    #########################
    ### helper properties ###
    #########################

    network_bro_intel_tags = association_proxy('tags', 'tag_table')

    def _find_or_create_tag(self, tag):

        '''
        https://stackoverflow.com/questions/2310153/inserting-data-in-many-to-many-relationship-in-sqlalchemy
        '''

        q = Tag.query.filter_by(tag_string=tag)
        t = q.first()

        if not(t):
            t = Tag(tag)
        return t

    def _get_tags(self):
        return self.tags

    def _set_tags(self, value):

        while self.tags:
            del self.tags[0]

        if type(value) == unicode:   
            lvalue = value.split(',')
        else:
            lvalue = value

        for tag in lvalue:
            lt = tag.lower()
            ctag = lt.strip()
            self.tags.append(self._find_or_create_tag(ctag))

    str_tags = property(_get_tags,
                        _set_tags,
                        "Property str_tags is a simple wrapper for tags relation")

    def _get_i(self):

        return self.bro_intel_indicators

    def _set_i(self, value):

        while self.bro_intel_indicators:
            del self.bro_intel_indicators[0]

        svalue = value.split('\n')
        lout = []
        for v in svalue:
            strv = str(v)
            rs = strv.strip()
            try:
                newdict = dict(item.split(" : ") for item in rs.split("\n"))
                lout.append(newdict)
            except:
                pass
        out = json.dumps(lout)
        newout = json.loads(out)
        self.bro_intel_indicators = newout

    newline_indicators = property(_get_i, 
                                  _set_i, 
                                  "Property to clean json form output")

class Network_Snort_Suricata_dt(db.Model):

    __tablename__ = 'N_snort_suricata'

    id = db.Column(db.Integer, primary_key=True)
    type_hash = db.Column(db.String, unique=True)
    source = db.Column(db.String)
    snort_suricata_indicators = db.Column(JSON)
    d_type = db.Column(db.String)
    tags = db.relationship('Tag', secondary=lambda: Nsnort_suricata_tags_relation_table)
    notes = db.Column(db.String)
    localfile = db.Column(db.String)
    localtxtfile = db.Column(db.String)
    localcsvfile = db.Column(db.String)
    created_date = db.Column(db.DateTime(), default=datetime.utcnow)
    created_by = db.Column(db.String, db.ForeignKey('users.name', ondelete='SET NULL'))
    in_review_by = db.Column(db.String, db.ForeignKey('users.name', ondelete='SET NULL'))
    vetted_by = db.Column(db.String, db.ForeignKey('users.name', ondelete='SET NULL'))
    stale_by = db.Column(db.String, db.ForeignKey('users.name', ondelete='SET NULL'))
    priority = db.Column(db.Integer, default=3)
    status = db.Column(db.String, default='open')

    def __init__(self,
        type_hash = None,
        source = None, 
        snort_suricata_indicators = None,
        d_type = 'Network - Snort/Suricata',
        tags = None,
        notes = None,
        localcsvfile = None,
        localtxtfile = None,
        localfile = None,
        created_date = None,
        priority = None, 
        status = None,
        created_by = None, 
        in_review_by = None,
        vetted_by = None,
        stale_by = None,
        ):

        self.type_hash = type_hash
        self.source = source
        self.snort_suricata_indicators = snort_suricata_indicators
        self.d_type = d_type
        self.tags = tags
        self.notes = notes
        self.localfile = localfile
        self.localtxtfile = localtxtfile
        self.localcsvfile = localcsvfile
        self.created_date = created_date
        self.priority = priority
        self.status = status
        self.created_by = created_by
        self.in_review_by = in_review_by
        self.vetted_by = vetted_by
        self.stale_by = stale_by

    def __repr__(self):
        return '<id {}>'.format(self.id)

    #########################
    ### helper properties ###
    #########################

    network_snort_suricata_tags = association_proxy('tags', 'tag_table')

    def _find_or_create_tag(self, tag):

        '''
        https://stackoverflow.com/questions/2310153/inserting-data-in-many-to-many-relationship-in-sqlalchemy
        '''

        q = Tag.query.filter_by(tag_string=tag)
        t = q.first()

        if not(t):
            t = Tag(tag)
        return t

    def _get_tags(self):
        return self.tags

    def _set_tags(self, value):

        while self.tags:
            del self.tags[0]

        if type(value) == unicode:   
            lvalue = value.split(',')
        else:
            lvalue = value

        for tag in lvalue:
            lt = tag.lower()
            ctag = lt.strip()
            self.tags.append(self._find_or_create_tag(ctag))

    str_tags = property(_get_tags,
                        _set_tags,
                        "Property str_tags is a simple wrapper for tags relation")

    def _get_i(self):

        return self.snort_suricata_indicators

    def _set_i(self, value):

        split_sigs = re.split(r'\r\n\r\n', value)
        addback = [x.strip() + '\r\n\r\n' for x in split_sigs[:-1]]
        addbackagain = [x.strip() for x in split_sigs[-1:]]
        final = addback + addbackagain

        out = json.dumps(final)
        newout = json.loads(out)
        self.snort_suricata_indicators = newout

    newline_indicators = property(_get_i, 
                                  _set_i, 
                                  "Property to clean form output")


class Binary_Yara_dt(db.Model):

    __tablename__ = 'B_yara'

    id = db.Column(db.Integer, primary_key=True)
    type_hash = db.Column(db.String, unique=True)
    source = db.Column(db.String)
    bin_yara_indicators = db.Column(JSON)
    d_type = db.Column(db.String)
    tags = db.relationship('Tag', secondary=lambda: Byara_tags_relation_table)
    notes = db.Column(db.String)
    localfile = db.Column(db.String)
    localtxtfile = db.Column(db.String)
    localcsvfile = db.Column(db.String)
    created_date = db.Column(db.DateTime(), default=datetime.utcnow)
    created_by = db.Column(db.String, db.ForeignKey('users.name', ondelete='SET NULL'))
    in_review_by = db.Column(db.String, db.ForeignKey('users.name', ondelete='SET NULL'))
    vetted_by = db.Column(db.String, db.ForeignKey('users.name', ondelete='SET NULL'))
    stale_by = db.Column(db.String, db.ForeignKey('users.name', ondelete='SET NULL'))
    priority = db.Column(db.Integer, default=3)
    status = db.Column(db.String, default='open')

    def __init__(self,
        type_hash = None,
        source = None, 
        bin_yara_indicators = None,
        d_type = 'Binary - Yara',
        tags = None,
        notes = None,
        localcsvfile = None,
        localtxtfile = None,
        localfile = None,
        created_date = None,
        priority = None, 
        status = None,
        created_by = None, 
        in_review_by = None,
        vetted_by = None,
        stale_by = None,
        ):

        self.type_hash = type_hash
        self.source = source
        self.bin_yara_indicators = bin_yara_indicators
        self.d_type = d_type
        self.tags = tags
        self.notes = notes
        self.localfile = localfile
        self.localtxtfile = localtxtfile
        self.localcsvfile = localcsvfile
        self.created_date = created_date
        self.priority = priority
        self.status = status
        self.created_by = created_by
        self.in_review_by = in_review_by
        self.vetted_by = vetted_by
        self.stale_by = stale_by

    def __repr__(self):
        return '<id {}>'.format(self.id)

    #########################
    ### helper properties ###
    #########################

    binary_yara_tags = association_proxy('tags', 'tag_table')

    def _find_or_create_tag(self, tag):

        '''
        https://stackoverflow.com/questions/2310153/inserting-data-in-many-to-many-relationship-in-sqlalchemy
        '''

        q = Tag.query.filter_by(tag_string=tag)
        t = q.first()

        if not(t):
            t = Tag(tag)
        return t

    def _get_tags(self):
        return self.tags

    def _set_tags(self, value):

        while self.tags:
            del self.tags[0]

        if type(value) == unicode:   
            lvalue = value.split(',')
        else:
            lvalue = value

        for tag in lvalue:
            lt = tag.lower()
            ctag = lt.strip()
            self.tags.append(self._find_or_create_tag(ctag))

    str_tags = property(_get_tags,
                        _set_tags,
                        "Property str_tags is a simple wrapper for tags relation")

    def _get_i(self):

        return self.bin_yara_indicators

    def _set_i(self, value):

        split_sigs = re.split(r'\r\n\}\r\n\r\n', value)
        addback = [x.strip() + '\r\n}\r\n\r\n' for x in split_sigs[:-1]]
        addbackagain = [x.strip() for x in split_sigs[-1:]]
        final = addback + addbackagain

        out = json.dumps(final)
        newout = json.loads(out)
        self.bin_yara_indicators = newout

    newline_indicators = property(_get_i, 
                                  _set_i, 
                                  "Property to clean form output")


class Memory_Yara_dt(db.Model):

    __tablename__ = 'M_yara'

    id = db.Column(db.Integer, primary_key=True)
    type_hash = db.Column(db.String, unique=True)
    source = db.Column(db.String)
    mem_yara_indicators = db.Column(JSON)
    d_type = db.Column(db.String)
    tags = db.relationship('Tag', secondary=lambda: Myara_tags_relation_table)
    notes = db.Column(db.String)
    localfile = db.Column(db.String)
    localtxtfile = db.Column(db.String)
    localcsvfile = db.Column(db.String)
    created_date = db.Column(db.DateTime(), default=datetime.utcnow)
    created_by = db.Column(db.String, db.ForeignKey('users.name', ondelete='SET NULL'))
    in_review_by = db.Column(db.String, db.ForeignKey('users.name', ondelete='SET NULL'))
    vetted_by = db.Column(db.String, db.ForeignKey('users.name', ondelete='SET NULL'))
    stale_by = db.Column(db.String, db.ForeignKey('users.name', ondelete='SET NULL'))
    priority = db.Column(db.Integer, default=3)
    status = db.Column(db.String, default='open')

    def __init__(self,
        type_hash = None,
        source = None, 
        mem_yara_indicators = None,
        d_type = 'Memory - Yara',
        tags = None,
        notes = None,
        localcsvfile = None,
        localtxtfile = None,
        localfile = None,
        created_date = None,
        priority = None, 
        status = None,
        created_by = None, 
        in_review_by = None,
        vetted_by = None,
        stale_by = None,
        ):

        self.type_hash = type_hash
        self.source = source
        self.mem_yara_indicators = mem_yara_indicators
        self.d_type = d_type
        self.tags = tags
        self.notes = notes
        self.localfile = localfile
        self.localtxtfile = localtxtfile
        self.localcsvfile = localcsvfile
        self.created_date = created_date
        self.priority = priority
        self.status = status
        self.created_by = created_by
        self.in_review_by = in_review_by
        self.vetted_by = vetted_by
        self.stale_by = stale_by

    def __repr__(self):
        return '<id {}>'.format(self.id)

    #########################
    ### helper properties ###
    #########################

    memory_yara_tags = association_proxy('tags', 'tag_table')

    def _find_or_create_tag(self, tag):

        '''
        https://stackoverflow.com/questions/2310153/inserting-data-in-many-to-many-relationship-in-sqlalchemy
        '''

        q = Tag.query.filter_by(tag_string=tag)
        t = q.first()

        if not(t):
            t = Tag(tag)
        return t

    def _get_tags(self):
        return self.tags

    def _set_tags(self, value):

        while self.tags:
            del self.tags[0]

        if type(value) == unicode:   
            lvalue = value.split(',')
        else:
            lvalue = value

        for tag in lvalue:
            lt = tag.lower()
            ctag = lt.strip()
            self.tags.append(self._find_or_create_tag(ctag))

    str_tags = property(_get_tags,
                        _set_tags,
                        "Property str_tags is a simple wrapper for tags relation")

    def _get_i(self):

        return self.mem_yara_indicators

    def _set_i(self, value):

        split_sigs = re.split(r'\r\n\}\r\n\r\n', value)
        addback = [x.strip() + '\r\n}\r\n\r\n' for x in split_sigs[:-1]]
        addbackagain = [x.strip() for x in split_sigs[-1:]]
        final = addback + addbackagain

        out = json.dumps(final)
        newout = json.loads(out)
        self.mem_yara_indicators = newout

    newline_indicators = property(_get_i, 
                                  _set_i, 
                                  "Property to clean form output")


##########
## Tags ##
##########

Nbro_intel_tags_relation_table = db.Table('N_bro_intel_tags', db.Model.metadata,
    db.Column('tag_id', db.Integer, db.ForeignKey('tag_table.id', onupdate="CASCADE", ondelete="SET NULL")),
    db.Column('n_bro_intel_id', db.Integer, db.ForeignKey('N_bro_intel.id', onupdate="CASCADE", ondelete="SET NULL"))
)

Nsnort_suricata_tags_relation_table = db.Table('N_snort_suricata_tags', db.Model.metadata,
    db.Column('tag_id', db.Integer, db.ForeignKey('tag_table.id', onupdate="CASCADE", ondelete="SET NULL")),
    db.Column('n_snort_suricata_id', db.Integer, db.ForeignKey('N_snort_suricata.id', onupdate="CASCADE", ondelete="SET NULL"))
)

Byara_tags_relation_table = db.Table('B_yara_tags', db.Model.metadata,
    db.Column('tag_id', db.Integer, db.ForeignKey('tag_table.id', onupdate="CASCADE", ondelete="SET NULL")),
    db.Column('b_yara_id', db.Integer, db.ForeignKey('B_yara.id', onupdate="CASCADE", ondelete="SET NULL"))
)

Myara_tags_relation_table = db.Table('M_yara_tags', db.Model.metadata,
    db.Column('tag_id', db.Integer, db.ForeignKey('tag_table.id', onupdate="CASCADE", ondelete="SET NULL")),
    db.Column('m_yara_id', db.Integer, db.ForeignKey('M_yara.id', onupdate="CASCADE", ondelete="SET NULL"))
)

class Tag(db.Model):

    __tablename__ = 'tag_table'

    id = db.Column(db.Integer, primary_key=True)
    tag_string = db.Column(db.String)

    def __init__(self, 
        tag_string = None
        ):

        self.tag_string = tag_string

    def __repr__(self):
        return '%s' % self.tag_string


###########
## Users ##
###########


class User(db.Model):

    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True,)
    name = db.Column(db.String, unique=True)
    email = db.Column(db.String, unique=True)
    password = db.Column(db.String)
    role = db.Column(db.String, default='user')
    api_key = db.Column(db.String, unique=True)

    def __init__(self, 
        name=None, 
        email=None, 
        password=None, 
        role=None,
        api_key=None
        ):

        self.name = name
        self.email = email
        self.password = password
        self.role = role
        self.api_key = api_key

    def __repr__(self):
        return '%s' % (self.name)


###########
## Feeds ##
###########


class Feed_source(db.Model):

    __tablename__ = 'feed_source'

    id = db.Column(db.Integer, primary_key=True)
    feed_update_time = db.Column(db.DateTime(), default=datetime.utcnow)
    feedsource = db.Column(db.String, unique=True)
    sourceconfidence = db.Column(db.Integer, default=2)
    feedsource_type = db.Column(db.String)

    def __init__(self, 
        feed_update_time=None,
        feedsource=None,
        sourceconfidence=None,
        feedsource_type=None,
        ):

        self.feed_update_time = feed_update_time
        self.feedsource = feedsource
        self.sourceconfidence = sourceconfidence
        self.feedsource_type = feedsource_type

    def __repr__(self):
        return '<id {}>'.format(self.id)


class Feeds(db.Model):

    __tablename__ = 'feeds'

    id = db.Column(db.Integer, primary_key=True)
    feed_title = db.Column(db.String)
    feed_link = db.Column(db.String, unique=True)
    feed_time = db.Column(db.DateTime(), default=datetime.utcnow)
    feed_status = db.Column(db.Boolean(), default=True)
    feed_feedsource = db.Column(db.String, db.ForeignKey('feed_source.feedsource', ondelete='SET NULL'))
    feed_confidence = db.Column(db.Integer)
    feed_type = db.Column(db.String)
    
    def __init__(self, 
        feed_title=None, 
        feed_link=None, 
        feed_time=None,
        feed_status=None,
        feed_feedsource=None,
        feed_confidence=None,
        feed_type=None,
        ):

        self.feed_title = feed_title
        self.feed_link = feed_link
        self.feed_time = feed_time
        self.feed_status = feed_status
        self.feed_feedsource = feed_feedsource
        self.feed_confidence = feed_confidence
        self.feed_type = feed_type

    def __repr__(self):
        return '<id {}>'.format(self.id)

##############
## Settings ##
##############