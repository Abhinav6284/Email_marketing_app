from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from . import config

# 1. Initialize extensions here, but don't link them to the app yet.
db = SQLAlchemy()
login_manager = LoginManager()


def create_app():
    """Create and configure an instance of the Flask application."""
    app = Flask(__name__)
    app.config["SECRET_KEY"] = config.SECRET_KEY
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///markdb.db"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # 2. Link extensions to the app instance
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "main.login"

    # --- THIS IS THE CRUCIAL CHANGE ---
    # 3. Import Blueprints and Models *inside* the function
    #    This avoids circular imports because the 'db' object already exists
    #    before these files are loaded.
    from .app import main_bp
    from .whatsapp_routes import whatsapp_bp
    from .models import User

    # 4. Register the blueprints
    app.register_blueprint(main_bp)
    app.register_blueprint(whatsapp_bp)

    # 5. Define the user loader
    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    return app
