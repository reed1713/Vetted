#app/__init__.py

import os

# import debug toolbar
from flask_debugtoolbar import DebugToolbarExtension

#import flask libs
from flask import Flask
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.bcrypt import Bcrypt
from flask.ext.migrate import Migrate

#make it pretty
from flask_bootstrap import Bootstrap

app = Flask(__name__)
Bootstrap(app)
bcrypt = Bcrypt(app)
app.config.from_object(os.environ['APP_SETTINGS'])
db = SQLAlchemy(app)
migrate = Migrate(app, db)
docs = app.config['UPLOAD_FOLDER'] = os.environ['UPLOAD_FOLDER']

# debug toolbar init
toolbar = DebugToolbarExtension(app)

# import blueprints
from app.users.views import users_blueprint
from app.scrape.views import scrape_blueprint
from app.status.views import status_blueprint
from app.welcome.views import welcome_blueprint
from app.lists.views import lists_blueprint
from app.research.views import research_blueprint

# register our blueprints
app.register_blueprint(users_blueprint)
app.register_blueprint(scrape_blueprint)
app.register_blueprint(status_blueprint)
app.register_blueprint(welcome_blueprint)
app.register_blueprint(lists_blueprint)
app.register_blueprint(research_blueprint)