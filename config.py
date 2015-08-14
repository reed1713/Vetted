#config.py

### config imports ###
import os

class Config(object):
    DEBUG = False
    TESTING = False
    CSRF_ENABLED = True
    SECRET_KEY = os.environ['SECRET_KEY']
    SQLALCHEMY_DATABASE_URI = os.environ['DATABASE_URL']

class ProductionConfig(Config):
    DEBUG = False
    # debug toolbar config
    DEBUG_TB_INTERCEPT_REDIRECTS = False

class StagingConfig(Config):
    DEVELOPMENT = True
    DEBUG = True
    # debug toolbar config
    DEBUG_TB_INTERCEPT_REDIRECTS = False

class DevelopmentConfig(Config):
    DEVELOPMENT = True
    DEBUG = True
    # debug toolbar config
    DEBUG_TB_INTERCEPT_REDIRECTS = False

class TestingConfig(Config):
    TESTING = True
    # debug toolbar config
    DEBUG_TB_INTERCEPT_REDIRECTS = False

