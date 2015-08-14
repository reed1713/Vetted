#run.py
import os

from flask.ext.script import Manager
from flask.ext.migrate import Migrate, MigrateCommand

from app import app, db

app.config.from_object(os.environ['APP_SETTINGS'])
#app.run(host='0.0.0.0', port=5000)

manager = Manager(app)
manager.add_command('db', MigrateCommand)

if __name__ == '__main__':
	manager.run()