import os  # Import os to access environment variables
from flask import Flask
from flask_cors import CORS
from .extensions import db, mail  # Import from the new extensions module
from .db_functions import configure_mail  # Import the configure_mail function

def create_app():
    app = Flask(__name__)
    app.config.from_object('app.config.Config')  # Load configuration

    # Load frontend URL from environment variable
    frontend_url = os.getenv('FRONTEND_URL')  # Fetch the frontend URL

    # Specify allowed origins
    allowed_origins = [frontend_url] if frontend_url else []  # Use the env var, or empty list if not set

    # Enable CORS for specified origins
    CORS(app, origins=allowed_origins)

    db.init_app(app)
    configure_mail(app)  # Configure mail here

    # Register blueprints
    from .routes import main as main_blueprint
    app.register_blueprint(main_blueprint)

    return app
