import os
from dotenv import load_dotenv

# Load environment variables from the .env file
load_dotenv()

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'default-secret-key')  # Fallback value if .env is missing
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///default.db')  # Fallback value
    
    # Mail configuration
    MAIL_SERVER = os.getenv('MAIL_SERVER', 'smtp.example.com')  # Fallback value
    MAIL_PORT = os.getenv('MAIL_PORT', 587)  # Fallback value
    MAIL_USE_TLS = os.getenv('MAIL_USE_TLS', 'True') == 'True'  # Convert to boolean
    MAIL_USERNAME = os.getenv('MAIL_USERNAME', 'default@example.com')  # Fallback value
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD', 'default-password')  # Fallback value
    MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER', 'default@example.com')  # Fallback value
