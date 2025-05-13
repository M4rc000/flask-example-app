from flask import Blueprint, render_template, redirect, url_for, flash, request
from app.forms import RegisterForm, LoginForm
from app.models import User
from app import db
from flask_login import login_user, logout_user, login_required, current_user
from . import login_manager

auth = Blueprint('auth', __name__)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@auth.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    form = RegisterForm()
    if form.validate_on_submit():
        user = User(
            name=form.name.data,
            username=form.username.data, 
            email=form.email.data
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Account created!', 'success')
        return redirect(url_for('auth.login'))
    return render_template('auth/register.html', form=form)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        passwordInput = form.password.data
        if user:
            if user.check_password(passwordInput):
                login_user(user)
                flash('Login successful', 'success')
                return redirect(url_for('main.dashboard'))
            flash('Invalid credentials', 'danger')
            return render_template('auth/login.html', form=form)
        flash('Invalid credentials', 'danger')
        return render_template('auth/login.html', form=form)
    return render_template('auth/login.html', form=form)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully', 'info')
    return redirect(url_for('auth.login'))
