from flask import render_template, flash, redirect, url_for, request
from flask_login import current_user, login_user, logout_user, login_required
from urllib.parse import urlsplit
from datetime import datetime, timezone
import sqlalchemy as sa
from app import app, db
from app.forms import LoginForm, RegistrationForm, EditProfileForm, EditUserAndRole
from app.models import User, UserRole

@app.route('/')
@app.route('/index', methods=['GET', 'POST'])
@login_required
def index():
    users = db.session.scalars(sa.select(User)).all()
    form = EditUserAndRole()
    if current_user.role in [UserRole.ADMIN, UserRole.HR_MANAGER, UserRole.EDITOR]:
        if form.validate_on_submit():
            user = db.first_or_404(sa.select(User).where(User.username == form.old_username.data))
            if form.username.data:
                user.username = form.username.data
            if form.about_me.data:
                user.about_me = form.about_me.data
            if current_user.role in [UserRole.ADMIN, UserRole.HR_MANAGER, UserRole.EDITOR]:
                user.role = form.role.data
            if form.delete.data and current_user.role == UserRole.ADMIN:
                db.session.delete(user)
            db.session.commit()
            flash('Your changes have been saved.')
            return redirect(url_for('index'))
    return render_template('index.html', title='Home', users=users, role=UserRole, form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if form.validate_on_submit():
        user = db.session.scalar(
            sa.select(User).where(User.username == form.username.data))
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or urlsplit(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)
    return render_template('login.html', title='Sign In', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/user/<username>')
@login_required
def user(username):
    user = db.first_or_404(sa.select(User).where(User.username == username))
    posts = [
        {'author': user, 'body': 'Test post #1'},
        {'author': user, 'body': 'Test post #2'}
    ]
    return render_template('user.html', user=user, posts=posts)

@app.before_request
def before_request():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.now(timezone.utc)
        db.session.commit()

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm()
    user = db.first_or_404(sa.select(User).where(User.username == current_user.username))
    if form.validate_on_submit():
        if user.role != UserRole.READER:
            current_user.username = form.username.data
        current_user.about_me = form.about_me.data
        db.session.commit()
        flash('Your changes have been saved.')
        return redirect(url_for('edit_profile'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.about_me.data = current_user.about_me
    return render_template('edit_profile.html', title='Edit Profile', form=form, role=UserRole)
