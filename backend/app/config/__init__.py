import os
from pathlib import Path
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[2] / '.env')

_PROD = os.environ.get('FLASK_ENV') == 'production'


def _require(var: str) -> str:
    val = os.environ.get(var)
    if not val and _PROD:
        raise RuntimeError(f'{var} must be set in production')
    return val


class Config:
    SECRET_KEY     = _require('SECRET_KEY')     or 'dev-secret-key-change-in-production'
    JWT_SECRET_KEY = _require('JWT_SECRET_KEY') or 'jwt-secret-key-change-in-production'

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'postgresql://sandbug_user:sandbug_password@localhost/sandbug_db'
    SQLALCHEMY_ECHO = not _PROD

    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)

    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER') or \
        os.path.join(os.path.dirname(os.path.dirname(__file__)), 'uploads')
    MAX_CONTENT_LENGTH = 200 * 1024 * 1024
    ALLOWED_EXTENSIONS = {
        # PE / Windows
        'exe', 'dll', 'sys', 'scr', 'com', 'drv', 'ocx', 'cpl',
        # Scripts
        'js', 'vbs', 'vbe', 'ps1', 'psm1', 'bat', 'cmd', 'hta', 'wsf', 'wsh',
        # Documents
        'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'pdf', 'rtf',
        # Linux / other
        'elf', 'so', 'apk', 'jar', 'lnk', 'iso', 'msi', 'cab',
        # Archives (extracted server-side)
        'zip',
    }

    REDIS_URL = os.environ.get('REDIS_URL') or 'redis://localhost:6379/0'

    CORS_ORIGINS = [o.strip() for o in os.environ.get('CORS_ORIGINS', 'http://localhost:3000').split(',')]

    HYBRID_ANALYSIS_API_KEY = os.environ.get('HYBRID_ANALYSIS_API_KEY', '')

    DEBUG = not _PROD

    S3_BUCKET             = os.environ.get('S3_BUCKET', '')
    S3_REGION             = os.environ.get('S3_REGION', 'us-east-1')
    AWS_ACCESS_KEY_ID     = os.environ.get('AWS_ACCESS_KEY_ID', '')
    AWS_SECRET_ACCESS_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY', '')
    USE_S3 = bool(
        os.environ.get('S3_BUCKET') and
        os.environ.get('AWS_ACCESS_KEY_ID') and
        os.environ.get('AWS_SECRET_ACCESS_KEY')
    )
