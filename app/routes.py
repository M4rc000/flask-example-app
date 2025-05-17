from app import db
from app.models import User
from app.models import User
from app.utils.helper import encode_id, decode_id
from app.forms import RegisterForm, LoginForm, UserForm, UpdateProfileForm, EditManageUserForm, ShowManageUserForm
from flask import Blueprint, render_template, redirect, url_for, redirect, url_for, request, flash, session, current_app
from flask_login import login_user, logout_user, login_required, current_user
from . import login_manager
import sys
import os
from flask_dance.contrib.google import google
from sqlalchemy.exc import IntegrityError
from datetime import datetime, timezone
from werkzeug.utils import secure_filename

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

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
            email=form.email.data,
            picture="profile/user.png",
            created_at=datetime.now(timezone.utc),
            created_by="System"
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

# GOOGLE AUTH
@auth.route("/google")
def google_login():
    if not google.authorized:
        return redirect(url_for("google.login"))
    account_info = google.get("/oauth2/v2/userinfo").json()
    email = account_info["email"]
    name = account_info["name"]

    user = User.query.filter_by(email=email).first()
    if user:
        flash("Email already exists", "register_error")
        return redirect(url_for("auth.register"))
    else:
        # Jika pengguna belum terdaftar, buat akun baru
        form = RegisterForm()
        form.name.data = name
        form.email.data = email
        flash("Sign up with google is successfully, please fill Username and Password", "success")
        return render_template('auth/register.html', title="Register", form=form)

@auth.route("/google/callback")
def google_callback():
    resp = google.authorized
    if not resp:
        flash("Gagal login dengan Google.", "danger")
        return redirect(url_for("auth.login"))
    # Setelah berhasil otorisasi, pengguna akan di-redirect ke sini.
    # Flask-Dance seharusnya sudah menyimpan token akses.
    # Sekarang, redirect ke route yang akan mengambil informasi pengguna dan melakukan login/registrasi.
    return redirect(url_for("auth.google_login")) # Redirect ke google_login setelah callback

@main.route('/admin/dashboard')
@login_required
def dashboard():
    return render_template('admin/dashboard.html', usersession=current_user, title="Dashboard")

@main.route('/admin/manage-user', methods=['GET'])
@login_required
def manage_user():
    users = User.query.all()

    for u in users:
        u.hashid = encode_id(u.id)

    return render_template('admin/manage_user.html', users=users, usersession=current_user, title="Manage User")

@main.route('/admin/manage-user/add', methods=['GET', 'POST'])
@login_required
def add_manage_user():
    form = RegisterForm()

    if form.validate_on_submit():
        existing_username = User.query.filter_by(username=form.username.data).first()
        if existing_username:
            form.username.errors.append("Username already exists.")

        existing_email = User.query.filter_by(email=form.email.data).first()
        if existing_email:
            form.email.errors.append("Email already exists.")

        if existing_email or existing_username:
            return redirect(url_for('main.manage_user'))

        user = User(
            name=form.name.data,
            username=form.username.data,
            email=form.email.data,
            picture="profile/user.png",
            created_at=datetime.now(timezone.utc),
            created_by="System"
        )

        user.hash_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Account created successfully! You can now log in.', 'success')
        return redirect(url_for('main.manage_user'))

    return render_template('admin/add_manage_user.html', form=form, title="New User", usersession=current_user)


@main.route('/admin/manage-user/show/<hashid>', methods=['GET'])
@login_required
def show_manage_user(hashid):
    user_id = decode_id(hashid)
    if user_id is None:
        abort(404)

    user_to_edit = User.query.get_or_404(user_id)
    form = ShowManageUserForm(obj=user_to_edit)

    return render_template('admin/show_manage_user.html', form=form, usersession=current_user, user=user_to_edit, title="Show User")

@main.route('/admin/manage-user/edit/<hashid>', methods=['GET', 'POST'])
@login_required
def edit_manage_user(hashid):
    user_id = decode_id(hashid)
    if user_id is None:
        abort(404)

    user_to_edit = User.query.get_or_404(user_id)
    form = EditManageUserForm(obj=user_to_edit)

    if form.validate_on_submit():
        # Validasi email/username jika perlu
        user_to_edit.name = form.name.data
        user_to_edit.username = form.username.data
        user_to_edit.email = form.email.data
        user_to_edit.is_active = int(form.is_active.data)
        db.session.commit()
        flash('User updated successfully.', 'success')
        return redirect(url_for('main.manage_user'))

    form.is_active.data = str(user_to_edit.is_active)
    return render_template('admin/edit_manage_user.html', usersession=current_user, form=form, user=user_to_edit, title="Edit User")

@main.route('/admin/manage-user/delete/<hashid>', methods=['POST'])
@login_required
def delete_manage_user(hashid):
    user_id = decode_id(hashid)
    if user_id is None:
        abort(404)
    db.session.delete(user_id)
    db.session.commit()
    flash('User deleted successfully!', 'success')
    return redirect(url_for('main.manage_user'))

@main.route('/user/profile', methods=['GET', 'POST'])
@login_required
def user_profile():
    UPLOAD_FOLDER = os.path.join(current_app.root_path, 'static', 'img', 'profile')
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp'}

    def allowed_file(filename):
        return '.' in filename and \
            filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

    form = UpdateProfileForm(obj=current_user)

    if form.validate_on_submit():
        # Validasi username (hanya jika diubah)
        if form.username.data != current_user.username:
            existing_username = User.query.filter_by(username=form.username.data).first()
            if existing_username:
                form.username.errors.append("Username already exists.")

        # Validasi email (hanya jika diubah)
        if form.email.data != current_user.email:
            existing_email = User.query.filter_by(email=form.email.data).first()
            if existing_email:
                form.email.errors.append("Email already exists.")

        if form.username.errors or form.email.errors:
            return render_template('user/profile.html', form=form, usersession=current_user, user=current_user, title="Profile")

        current_user.name = form.name.data
        current_user.username = form.username.data
        current_user.email = form.email.data

        # Handle profile picture upload
        if form.picture.data: # Periksa apakah ada data file yang diunggah
            file = form.picture.data
            if hasattr(file, 'filename') and file and allowed_file(file.filename): # Pastikan itu objek file dengan atribut filename
                filename = secure_filename(file.filename)
                file_ext = filename.rsplit('.', 1)[1].lower()
                new_filename = f"{current_user.id}.{file_ext}"
                filepath = os.path.join(UPLOAD_FOLDER, new_filename)
                try:
                    file.save(filepath)
                    # Hapus gambar profil lama jika ada (kecuali default)
                    if current_user.picture and current_user.picture != 'profile/user.png':
                        old_filepath = os.path.join(UPLOAD_FOLDER, current_user.picture.replace('profile/', ''))
                        if os.path.exists(old_filepath):
                            os.remove(old_filepath)
                    current_user.picture = f"profile/{new_filename}"
                except Exception as e:
                    flash(f"Error saving profile picture: {e}", "error")
            else:
                flash("Invalid file type or no file uploaded for profile picture.", "error")

            db.session.commit()
            flash("Profile updated successfully!", "success")
            return redirect(url_for('main.user_profile'))
    return render_template('user/profile.html', form=form, usersession=current_user, user=current_user, title="Profile")

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
