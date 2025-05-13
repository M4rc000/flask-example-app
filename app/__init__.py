from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect

db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
csrf = CSRFProtect()  # ✅ INI YANG DIBENERIN

def create_app():
    app = Flask(__name__, instance_relative_config=True)
    # BASE_DIR = os.path.abspath(os.path.dirname(__file__))
# app = Flask(__name__, template_folder=os.path.join(BASE_DIR, 'templates'))
    app.config.from_pyfile('config.py')

    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    csrf.init_app(app)

    login_manager.login_view = 'login'

    from .routes import main 
    from .auth_routes import auth
    app.register_blueprint(main)
    app.register_blueprint(auth)

    return app