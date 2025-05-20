from app import db
from app.models import User, Movies, Booking, Movies_Now_Showing, Teater, Seats
from app.utils.helper import encode_id, decode_id, send_verification_email, confirm_token, generate_token, send_forgot_password_email
from app.forms import RegisterForm, LoginForm, UserForm, UpdateProfileForm, EditManageUserForm, ShowManageUserForm, AddManageUserForm, ForgotPasswordForm, ForgotPasswordInputForm, BookMovieForm
from flask import Blueprint, abort, render_template, redirect, url_for, redirect, url_for, request, flash, session, current_app, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from . import login_manager
import sys
import os
import pytz
from flask_dance.contrib.google import google
from sqlalchemy.exc import IntegrityError
from datetime import datetime, timedelta, timezone
from werkzeug.utils import secure_filename

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

auth = Blueprint('auth', __name__)
main = Blueprint('main', __name__)

login_manager.login_view = 'auth.login'
wib = pytz.timezone('Asia/Jakarta')

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

        token = generate_token(form.email.data)

        user = User(
            name=form.name.data,
            username=form.username.data,
            email=form.email.data,
            picture="profile/user.png",
            email_token=token,
            created_at=datetime.now(wib),
            created_by="System"
        )

        user.hash_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        send_verification_email(user)
        flash('Account created! Please verify your email to activate your account.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('auth/register.html', form=form, title="Register")

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if not user.email_verified_at:
            print("Not verified")
            flash("Please verify your email before logging in.", "login_error")
            return redirect(url_for('auth.login'))
        if user and user.confirm_password(form.password.data):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('main.dashboard'))
        else:
            flash('Invalid username or password', 'login_error')
    
    return render_template('auth/login.html', form=form, title="Login")

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully', 'info')
    return redirect(url_for('auth.login'))

@auth.route('/forgot-password', methods=['GET','POST'])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        email = form.email.data
        user = User.query.filter_by(email=email).first()
        form.email.data = user.email
        if user:
            token = user.get_reset_password_token()
            user.reset_password_token = token
            user.reset_password_expiration = datetime.utcnow() + timedelta(minutes=30) # Contoh masa berlaku 30 menit
            db.session.commit()
            send_forgot_password_email(user, token) # Modifikasi fungsi send_forgot_password_email untuk menerima token
            flash("Silakan periksa email Anda untuk mengubah kata sandi.", "success")
        else:
            flash("Email belum terdaftar.", "error")
        return render_template('auth/forgot_password.html', form=form, title="Lupa Kata Sandi")
    return render_template('auth/forgot_password.html', form=form, title="Lupa Kata Sandi")

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

# EMAIL VERIFICATION
@auth.route('/verify-email/<token>')
def verify_email(token):
    try:
        email = confirm_token(token)  # token should decode and return email
    except:
        flash('The verification link is invalid or has expired.', 'danger')
        return redirect(url_for('auth.login'))

    user = User.query.filter_by(email=email).first_or_404()

    # Optional token match (if saved in DB)
    if user.email_token != token:
        flash('Invalid or tampered verification token.', 'danger')
        return redirect(url_for('auth.login'))

    if not user.email_verified_at:
        user.email_verified_at = datetime.now(wib)
        user.is_active = 1
        db.session.commit()
        flash('You have verified your account. You can now login.', 'success')
    else:
        flash('Account already verified. Please login.', 'success')

    return redirect(url_for('auth.login'))

@auth.route('/verify-forgotpassword/<token>', methods=['GET','POST'])
def verify_forgot_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    user = User.verify_reset_password_token(token)
    if not user:
        flash('Tautan reset kata sandi tidak valid atau telah kedaluwarsa.', 'error')
        return redirect(url_for('auth.forgot_password'))

    form = ForgotPasswordInputForm()
    if form.validate_on_submit():
        password = form.password.data
        user.hash_password(password)
        db.session.commit()
        flash('Kata sandi Anda berhasil diperbarui. Silakan login.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('auth/forgot_password_input.html', title="Atur Ulang Kata Sandi", form=form)

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
    form = AddManageUserForm()

    if form.validate_on_submit():
        existing_username = User.query.filter_by(username=form.username.data).first()
        if existing_username:
            form.username.errors.append("Username already exists.")

        existing_email = User.query.filter_by(email=form.email.data).first()
        if existing_email:
            form.email.errors.append("Email already exists.")

        if existing_email or existing_username:
            return render_template('admin/add_manage_user.html', form=form, title="New User", usersession=current_user)

        user = User(
            name=form.name.data,
            username=form.username.data,
            email=form.email.data,
            picture="profile/user.png",
            created_at=datetime.now(wib),
            created_by="System"
        )

        user.hash_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('User '+ form.username.data +' created successfully!', 'success')
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
    user = User.query.get(user_id)
    if user is None:
        abort(404)
    try:
        db.session.delete(user)
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'User deleted successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': 'An error occurred while deleting the user'})
    
@main.route('/home/explore', methods=['GET','POST'])
@login_required
def explore_film():
    movies_data = db.session.query(Movies, Movies_Now_Showing).join(Movies_Now_Showing).all()
    
    # Encode ID film untuk digunakan dalam URL
    formatted_movies = []
    movie_schedules = {}
    for movie, showing in movies_data:
        movie_id = movie.id
        if movie_id not in movie_schedules:
            movie_schedules[movie_id] = []
        movie_schedules[movie_id].append({
            'id': encode_id(showing.id),
            'time': showing.schedule
        })

    for movie, schedule in movies_data: # change to movies_data
        movie_id = movie.id
        if movie_id not in movie_schedules:
            movie_schedules[movie_id] = []
        
        formatted_movies.append({
            'id': movie.id,
            'name': movie.name,
            'year': movie.year,
            'rating': movie.rating,
            'picture': movie.picture,
            'hashid': encode_id(movie.id),
            'schedules': movie_schedules.get(movie.id, [])
        })

    unique_movies = []
    seen_movie_ids = set()
    for movie in formatted_movies:
        if movie['id'] not in seen_movie_ids:
            unique_movies.append(movie)
            seen_movie_ids.add(movie['id'])
    return render_template('home/explore.html', title="Explore", usersession=current_user, movies=unique_movies, movie_schedules=movie_schedules)

@main.route('/home/book-movie/<hashid>', methods=['GET','POST'])
@login_required
def booking_film(hashid):
    movie_now_showing_id = decode_id(hashid)

    showing = db.session.query(
        Movies.id,
        Movies.name,
        Movies.year,
        Movies_Now_Showing.schedule,
        Movies_Now_Showing.teater_id
    ).join(
        Movies, Movies.id == Movies_Now_Showing.movie_id
    ).filter(
        Movies_Now_Showing.id == movie_now_showing_id
    ).first()  # gunakan .first() jika hanya 1 data yang diharapkan

    if not showing:
        flash("Movie not found.", "error")
        return redirect(url_for('main.explore'))


    # Ambil informasi teater berdasarkan teater_id dari penayangan
    teater = db.session.query(Teater).filter_by(id=showing.teater_id).first()

    # Ambil semua kursi untuk teater tersebut
    seats = db.session.query(Seats).filter_by(teater_id=showing.teater_id).all()

    return render_template(
        'home/booking_movie.html',
        title="Book Movie",
        moview_showing=showing,
        teater=teater,
        seats=seats,
        usersession=current_user
    )

@main.route('/home/booking/confirmation', methods=['GET', 'POST'])
@login_required
def confirm_booking():
    form = BookMovieForm()
    if form.validate_on_submit:
        booking = Booking(
            movie_showing_id = form.movie_showing_id.data,
            seat_id = form.seat_id.data,
            teater_no = form.teater_no.data,
            is_active = 1,
            user_id = current_user.id,
            status_payment = 0
        )
    # Ambil data kursi & ID penayangan dari form
    selected_seats = request.form.getlist('seat_ids[]')
    selected_seats_codes = request.form.getlist('seat_codes[]')
    showing_id = request.form.get('movie_now_showing_id')

    showing = db.session.query(Movies_Now_Showing).filter_by(id=showing_id).first()

    if not selected_seats or not showing_id:
        flash('Please select at least one seat and movie showing.', 'error')
        return redirect(url_for('main.explore_film'))  # Ganti sesuai route

    unavailable_seats = Seats.query.filter(
        Seats.baris + Seats.kolom.in_(selected_seats),
        Seats.status != 0,
        Seats.teater_id == showing.teater_id
    ).all()

    if unavailable_seats:
        flash('One or more selected seats are no longer available.', 'error')
        return redirect(url_for('main.explore_film'))  # Ganti sesuai route

    # Ambil info film dan harga
    movie_showing = db.session.query(Movies.name, Movies.price).join(
        Movies_Now_Showing, Movies.id == Movies_Now_Showing.movie_id
    ).filter(
        Movies_Now_Showing.id == showing_id
    ).first()

    if not movie_showing:
        flash('Movie not found.', 'error')
        return redirect(url_for('main.explore_film'))

    total_price = len(selected_seats) * movie_showing.price

    return render_template(
        'home/confirm_booking_movie.html',
        title="Confirmation Booking Movie",
        usersession=current_user,
        selected_seats=selected_seats,
        movie_name=movie_showing.name,
        price_per_seat=movie_showing.price,
        total_price=total_price
    )

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