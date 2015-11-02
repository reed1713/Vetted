#/app/login/views.py


#################
#### imports ####
#################

from flask import flash, redirect, render_template, request, \
    session, url_for, Blueprint
from sqlalchemy.exc import IntegrityError, InvalidRequestError
from forms import LoginForm
from app import db, bcrypt
from app.views import login_required
from app.models import User

################
#### config ####
################

login_blueprint = Blueprint(
    'login', __name__,
    url_prefix='/login',
    template_folder='templates',
    static_folder='static'
    )

################
#### helper ####
################

################
#### routes ####
################


@login_blueprint.route('/logout/')
@login_required
def logout():
    session.pop('logged_in', None)
    session.pop('user_id', None)
    session.pop('role', None)
    session.pop('name', None)
    flash('You are logged out.')
    return redirect(url_for('login.login'))

@login_blueprint.route('/', methods=['GET', 'POST'])
def login():
    error = None
    form = LoginForm(request.form)
    if request.method == 'POST':
        if form.validate_on_submit():
            user = User.query.filter_by(name=request.form['name']).first()
            if user is None:
                error = 'Invalid username or password.'
                return render_template(
                    "login.html",
                    form=form,
                    error=error
                    )
            else:
                pw = bcrypt.check_password_hash(user.password, request.form['password'])
                if pw == True:
                    session['logged_in'] = True
                    session['user_id'] = user.id
                    session['role'] = user.role
                    session['name'] = user.name
                    flash('You are logged in.')

                    return redirect(url_for('welcome.welcome'))
                else:
                    error = 'Invalid username or password.'
                    return render_template(
                    "login.html",
                    form=form,
                    error=error
                    )
        else:
            return render_template(
                "login.html",
                form=form,
                error=error
                )
    if request.method == 'GET':
        return render_template('login.html', form=form)
