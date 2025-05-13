from app import db
from flask_login import UserMixin
from sqlalchemy import Column, Integer, String, text
from werkzeug.security import generate_password_hash, check_password_hash

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(30), nullable=False, unique=True)
    email = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    is_active = db.Column(db.Integer, server_default=text("1"))

    def set_password(self, password):
        self.password = generate_password_hash(password)
        

    def check_password(self, password):
        return check_password_hash(self.password, password)
