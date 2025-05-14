from flask import Blueprint, render_template, redirect, url_for, redirect, url_for, request, flash
from flask_login import login_user, logout_user, login_required, current_user
from app.models import User
from app import db
from app.models import User
from app.forms import RegisterForm, LoginForm, UserForm, UpdateProfileForm
from . import login_manager


auth = Blueprint('auth', __name__)
main = Blueprint('main', __name__)

login_manager.login_view = 'auth.login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@auth.route('/', methods=['GET'])
def root():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return redirect(url_for('auth.login'))

@auth.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    form = RegisterForm()

    if form.validate_on_submit():
        existing_username = User.query.filter_by(username=form.username.data).first()
        if existing_username:
            form.username.errors.append("Username already exists.")

        existing_email = User.query.filter_by(email=form.email.data).first()
        if existing_email:
            form.email.errors.append("Email already exists.")

        if existing_email or existing_username:
            return render_template('auth/register.html', form=form, title="Register")

        user = User(
            name=form.name.data,
            username=form.username.data,
            email=form.email.data
        )
        user.hash_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Account created successfully! You can now log in.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('auth/register.html', form=form, title="Register")

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.confirm_password(form.password.data):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('main.dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('auth/login.html', form=form, title="Login")

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully', 'info')
    return redirect(url_for('auth.login'))

@main.route('/admin/dashboard')
@login_required
def dashboard():
    return render_template('admin/dashboard.html', user=current_user, title="Dashboard")

@main.route('/admin/manage-user', methods=['GET'])
@login_required
def manage_user():
    users = User.query.all()
    return render_template('admin/manage_user.html', users=users, user=current_user, title="Manage User")


# @main.route('/admin/user/delete/<int:user_id>', methods=['POST'])
# @login_required
# def delete_user(user_id):
#     user_to_delete = User.query.get_or_404(user_id)
#     db.session.delete(user_to_delete)
#     db.session.commit()
#     flash('User deleted successfully!', 'success')
#     return redirect(url_for('main.manage_user'))


@main.route('/admin/user/toggle-active/<int:user_id>', methods=['POST'])
@login_required
def toggle_active_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_active = not user.is_active
    db.session.commit()
    flash('User status updated!', 'success')
    return redirect(url_for('main.manage_user'))

@main.route('/user/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = UpdateProfileForm(obj=current_user)
    
    if form.validate_on_submit():
        # Validasi username, hanya jika user mengubah username-nya
        if form.username.data != current_user.username:
            existing_username = User.query.filter_by(username=form.username.data).first()
            if existing_username:
                form.username.errors.append("Username already exists.")
        
        # Validasi email, hanya jika user mengubah email-nya
        if form.email.data != current_user.email:
            existing_email = User.query.filter_by(email=form.email.data).first()
            if existing_email:
                form.email.errors.append("Email already exists.")
        
        if form.username.errors or form.email.errors:
            return render_template('user/profile.html', form=form, user=current_user, title="Profile")
        
        current_user.name = form.name.data
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()

        flash("Profile updated successfully!", "success")
        return redirect(url_for('main.profile'))
    
    return render_template('user/profile.html', form=form, user=current_user, title="Profile")


@main.route('/users')
@login_required
def list_users():
    users = User.query.all()
    return render_template('user_list.html', users=users)

@main.route('/user/add', methods=['GET', 'POST'])
@login_required
def add_user():
    form = UserForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        if form.password.data:
            user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('User created successfully', 'success')
        return redirect(url_for('main.list_users'))
    return render_template('user_form.html', form=form, action='Add')

@main.route('/user/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    form = UserForm(obj=user)
    form.original_username = user.username
    form.original_email = user.email

    if form.validate_on_submit():
        user.username = form.username.data
        user.email = form.email.data
        if form.password.data:
            user.set_password(form.password.data)
        db.session.commit()
        flash('User updated successfully', 'success')
        return redirect(url_for('main.list_users'))

    return render_template('user_form.html', form=form, action='Edit')

@main.route('/user/delete/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully', 'info')
    return redirect(url_for('main.list_users'))
