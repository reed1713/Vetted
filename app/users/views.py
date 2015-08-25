#/app/users/views.py


#################
#### imports ####
#################

from flask import flash, redirect, render_template, request, \
    session, url_for, Blueprint
from sqlalchemy.exc import IntegrityError, InvalidRequestError
from forms import RegisterForm, LoginForm
from app import db, bcrypt
from app.views import login_required, admin
from app.models import User


################
#### config ####
################

users_blueprint = Blueprint(
    'users', __name__,
    url_prefix='/users',
    template_folder='templates',
    static_folder='static'
    )

################
#### helper ####
################

def generate_apikey():

    import uuid
    apikey = str(uuid.uuid4()).replace("-", "")
    return apikey

################
#### routes ####
################


@users_blueprint.route('/logout/')
@login_required
def logout():
    session.pop('logged_in', None)
    session.pop('user_id', None)
    session.pop('role', None)
    session.pop('name', None)
    flash('You are logged out.')
    return redirect(url_for('users.login'))

@users_blueprint.route('/', methods=['GET', 'POST'])
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

@users_blueprint.route('/register/', methods=['GET', 'POST'])
@login_required
@admin
def register():
    error = None
    form = RegisterForm(request.form)
    if request.method == 'POST':
        if form.validate_on_submit():
            newapikey = generate_apikey()
            new_user = User(
                name = form.name.data,
                email = form.email.data,
                password = bcrypt.generate_password_hash(form.password.data),
                role = form.role.data,
                api_key = newapikey,
            )
            try:
                db.session.add(new_user)
                db.session.commit()
                flash('User created')
                return redirect(url_for('users.register'))
            except IntegrityError:
                db.session.rollback()
                error = 'Sorry that username and/or email already exists.'
                return render_template('register.html', 
                    form=form, 
                    error=error, 
                    username=session['name']
                    )
        else:
            return render_template('register.html', 
                form=form, 
                error=error, 
                username=session['name']
                )
    if request.method == 'GET':
        return render_template('register.html', 
            form=form, 
            username=session['name']
            )

@users_blueprint.route('/edit_accounts/', methods=['GET', 'POST'])
@login_required
@admin
def edit_accounts():
    error = None
    userslist = db.session.query(User)
    return render_template('edit_accounts.html',  
                error=error, 
                userslist=userslist, 
                username=session['name']
                )

@users_blueprint.route('/edit_user/<int:user_id>/', methods=['GET', 'POST'])
@login_required
@admin
def edit_user(user_id):
    error = None
    new_id = user_id
    edit = db.session.query(User).filter_by(id=new_id)
    form = RegisterForm(request.form)

    for e in edit:
        form = RegisterForm(obj=e,
            )

    if request.method == 'GET':
        return render_template('edit_user.html', 
            form=form, 
            error=error, 
            username=session['name'], 
            e=e,
            )

    if request.method == 'POST':
        if form.validate_on_submit():

            new_userobj = User.query.get(new_id)

            new_userobj.name = form.name.data
            new_userobj.email = form.email.data
            new_userobj.password = bcrypt.generate_password_hash(form.password.data)
            new_userobj.role = form.role.data      

            try:
                db.session.commit()
                flash('The user was successfully updated.')
                return redirect(url_for('users.edit_accounts'))

            except IntegrityError:
                db.session.rollback()
                error = 'Sorry that username and/or email error already exist.'
                return render_template('edit_user.html', 
                    form=form, 
                    error=error, 
                    username=session['name'],
                    e=e
                    )
        else:
             return render_template('edit_user.html',
                form=form,
                error=error,
                username=session['name'],
                e=e
                )

@users_blueprint.route('/user_info/<user_name>')
@login_required
def user_info(user_name):
    un = user_name
    error = None
    current_user = db.session.query(User).filter_by(name=un)
    return render_template('user_info.html',  
                error=error, 
                username=session['name'],
                current_user = current_user,
                )

@users_blueprint.route('/delete/<int:user_id>')
@login_required
@admin
def delete_user(user_id):
    new_id = user_id
    error = None
    todelete = db.session.query(User).filter_by(id=new_id)
    todelete.delete()
    try:
        db.session.commit()
        flash('The user was deleted')
        return redirect(url_for('users.edit_accounts'))
    except InvalidRequestError:
        error = ("something broke")
        return render_template('edit_accounts.html', 
            error=error, 
            username=session['name'], 
            userslist=userslist
            )

