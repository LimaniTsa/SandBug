from flask import Blueprint

auth_bp = Blueprint('auth', __name__)
analysis_bp = Blueprint('analysis', __name__)
info_bp = Blueprint('info', __name__)

from app.api import auth, analysis, info