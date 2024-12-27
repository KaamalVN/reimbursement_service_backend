# app/__init__.py

from flask import Flask
from flask_cors import CORS
from .extensions import db, mail  # Import from the new extensions module
from .db_functions import configure_mail  # Import the configure_mail function

def create_app():
    app = Flask(__name__)
    app.config.from_object('app.config.Config')  # Load configuration
    CORS(app)  # Enable CORS for all routes

    db.init_app(app)
    configure_mail(app)  # Configure mail here

    # Register blueprints
    from .routes import main as main_blueprint
    app.register_blueprint(main_blueprint)

    return app