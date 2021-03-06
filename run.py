#run.py
import os

from flask.ext.script import Manager
from flask.ext.migrate import Migrate, MigrateCommand
from app import initdb

from app import app, db

app.config.from_object(os.environ['APP_SETTINGS'])

manager = Manager(app)
manager.add_command('db', MigrateCommand)

#comment this out if you init the db
app.run(host='0.0.0.0', port=5000)

if __name__ == '__main__':
	initdb()
	manager.run()