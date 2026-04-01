import os
from pathlib import Path
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[2] / '.env')

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-for-sandbug-project'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'postgresql://sandbug_user:sandbug_password@localhost/sandbug_db'
    SQLALCHEMY_ECHO = True

    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'jwt-secret-key-for-sandbug'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)

    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'uploads')
    MAX_CONTENT_LENGTH = 200 * 1024 * 1024  # 200MB max file size
    ALLOWED_EXTENSIONS = {'exe', 'dll', 'pdf', 'doc', 'docx'}

    REDIS_URL = os.environ.get('REDIS_URL') or 'redis://localhost:6379/0'

    HYBRID_ANALYSIS_API_KEY = os.environ.get('HYBRID_ANALYSIS_API_KEY', '')

    DEBUG = True
