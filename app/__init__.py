from flask import Flask
from dotenv import load_dotenv
import os
from .extension import db, migrate, login_manager, csrf, bcrypt, oauth
from .routes import main, auth
from flask_dance.contrib.google import make_google_blueprint, google

load_dotenv()

def create_app():
    app = Flask(__name__, instance_relative_config=True)
    app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "supersekrit")
    app.config["GOOGLE_OAUTH_CLIENT_ID"] = os.environ.get("GOOGLE_CLIENT_ID")
    app.config["GOOGLE_OAUTH_CLIENT_SECRET"] = os.environ.get("GOOGLE_CLIENT_SECRET")
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQLALCHEMY_DATABASE_URI')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = os.environ.get('SQLALCHEMY_TRACK_MODIFICATIONS')

    csrf.init_app(app)
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    bcrypt.init_app(app)
    oauth.init_app(app)

    login_manager.login_view = 'auth.login'

    # BLUEPRINT GOOGLE
    google_bp = make_google_blueprint(
        client_id=app.config["GOOGLE_OAUTH_CLIENT_ID"],
        client_secret=app.config["GOOGLE_OAUTH_CLIENT_SECRET"],
        redirect_to="auth.google_callback",
        # scope=["openid", "email"]
        scope=["openid", "https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"]
    )
    app.register_blueprint(google_bp, url_prefix="/login")

    app.register_blueprint(main)
    app.register_blueprint(auth)

    return app