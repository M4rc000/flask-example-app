from flask_login import UserMixin
from app.extension import db, bcrypt
from datetime import datetime, timezone
from itsdangerous import URLSafeTimedSerializer
from flask import current_app

class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(30), nullable=False, unique=True)
    email = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(128), nullable=False)
    is_active = db.Column(db.Integer, default=1) # 1 untuk aktif, 0 untuk tidak aktif
    picture = db.Column(db.String(255))
    email_verified_at = db.Column(db.DateTime, nullable=True)
    email_token = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    created_by = db.Column(db.String(50))
    updated_at = db.Column(db.DateTime, default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))
    updated_by = db.Column(db.String(50))

    # Relasi dengan model Booking (one-to-many)
    bookings = db.relationship('Booking', backref='user', lazy=True)

    def get_reset_password_token(self, expires_in=1800): # 30 menit
        serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        return serializer.dumps(self.email, salt='reset-password-salt')

    @staticmethod
    def verify_reset_password_token(token):
        serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        try:
            email = serializer.loads(token, salt='reset-password-salt', max_age=1800)
        except:
            return None
        return User.query.filter_by(email=email).first()

    def hash_password(self, password):
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')

    def confirm_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

    def __repr__(self):
        return f'<User {self.username}>'
    
class Movies(db.Model): # Tidak perlu UserMixin
    __tablename__ = 'movies'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    type = db.Column(db.String(30), nullable=False)
    year = db.Column(db.String(10), nullable=False)
    rating = db.Column(db.String(10), nullable=False)
    duration = db.Column(db.String(30), nullable=False)
    price = db.Column(db.String(30), nullable=False)
    is_active = db.Column(db.Integer, default=1) # 1 untuk aktif, 0 untuk tidak aktif
    picture = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    created_by = db.Column(db.String(50))
    updated_at = db.Column(db.DateTime, default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))
    updated_by = db.Column(db.String(50))

    # Relasi dengan model Movies_Now_Showing (one-to-many)
    now_showing = db.relationship('Movies_Now_Showing', backref='movie', lazy=True)

    def __repr__(self):
        return f'<Movie {self.name}>'

class Movies_Now_Showing(db.Model): # Tidak perlu UserMixin
    __tablename__ = 'movies_now_showing'
    id = db.Column(db.Integer, primary_key=True)
    movie_id = db.Column(db.Integer, db.ForeignKey('movies.id'), nullable=False)
    teater_id = db.Column(db.Integer, db.ForeignKey('teater.id'), nullable=False)
    schedule = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    created_by = db.Column(db.String(50))
    updated_at = db.Column(db.DateTime, default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))
    updated_by = db.Column(db.String(50))

    # Relasi dengan model Booking (one-to-many)
    bookings = db.relationship('Booking', backref='movies_now_showing', lazy=True)

    # Relasi dengan Teater
    teater_id = db.Column(db.Integer, db.ForeignKey('teater.id'), nullable=False)
    
    def __repr__(self):
        return f'<MovieNowShowing {self.name}>'

class Teater(db.Model):
    __tablename__ = 'teater'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    total_row = db.Column(db.Integer, nullable=False)
    total_column = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    created_by = db.Column(db.String(50))
    updated_at = db.Column(db.DateTime, default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))
    updated_by = db.Column(db.String(50))
    
    seats = db.relationship('Seats', backref='teater', lazy=True)
    movies_now_showing = db.relationship('Movies_Now_Showing', backref='teater', lazy=True) #Relasi dengan Movies_Now_Showing

    def __repr__(self):
        return f'<Teater {self.name}>'

class Seats(db.Model):
    __tablename__ = 'seats'
    id = db.Column(db.Integer, primary_key=True)
    teater_id = db.Column(db.Integer, db.ForeignKey('teater.id'), nullable=False)
    baris = db.Column(db.String(1), nullable=False)
    kolom = db.Column(db.Integer, nullable=False)
    status = db.Column(db.Integer, nullable=False, default=0) # 0: tersedia, 1: terisi, 2: tidak tersedia
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    created_by = db.Column(db.String(50))
    updated_at = db.Column(db.DateTime, default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))
    updated_by = db.Column(db.String(50))
    
    def __repr__(self):
        return f'<Seats {self.seat_code}>'

class Booking(db.Model):
    __tablename__ = 'booking'
    id = db.Column(db.Integer, primary_key=True)
    book_id = db.Column(db.String(10), nullable=False)
    movie_showing_id = db.Column(db.Integer, db.ForeignKey('movies_now_showing.id'), nullable=False) # Foreign Key ke Movies_Now_Showing
    seat_id = db.Column(db.Integer, db.ForeignKey('seats.id'), nullable=False)
    teater_no = db.Column(db.String(1), nullable=False)  # Tambahkan teater_no
    is_active = db.Column(db.Integer, default=1) # 1 untuk aktif, 0 untuk tidak aktif
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status_payment = db.Column(db.Integer, default=0) # 1: Completed, 0: Pending, 2: Cancel
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    created_by = db.Column(db.String(50))
    updated_at = db.Column(db.DateTime, default=datetime.now(timezone.utc), onupdate=datetime.now(timezone.utc))
    updated_by = db.Column(db.String(50))

    def __repr__(self):
        return f'<Booking {self.book_id}>'