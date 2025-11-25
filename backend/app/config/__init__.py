import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()

class Config:
    #Application configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-for-sandbug-project'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'postgresql://sandbug_user:sandbug_password@localhost/sandbug_db'
    #shows SQL queries in console
    SQLALCHEMY_ECHO = True  
    
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'jwt-secret-key-for-sandbug'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'uploads')
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50MB max file size
    ALLOWED_EXTENSIONS = {'exe', 'dll', 'pdf', 'doc', 'docx'}
    
    DEBUG = True