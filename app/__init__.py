import os
from flask import Flask
from flask_cors import CORS
from .extensions import db, mail
from .db_functions import configure_mail

def create_app():
    app = Flask(__name__)
    app.config.from_object('app.config.Config')

    # Load frontend URL from environment variable
    frontend_url = os.getenv('FRONTEND_URL')  # Fetch the frontend URL
    local_url = "http://localhost:3000"  # Local development URL

    # Specify allowed origins: include both production and local URLs
    allowed_origins = [frontend_url, local_url] if frontend_url else [local_url]

    # Enable CORS for specified origins
    CORS(app, origins=allowed_origins)

    db.init_app(app)
    configure_mail(app)

    # Register blueprints
    from .routes import main as main_blueprint
    app.register_blueprint(main_blueprint)

    return app
