from flask import request, jsonify
from app.api import auth_bp
from app.models import db, User
from app import bcrypt
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from datetime import datetime, timezone, timedelta
from threading import Lock
import re

MAX_ATTEMPTS      = 5
LOCKOUT_SECONDS   = 900   # 15 minutes
WARNING_AT        = 3     # warn when this many attempts remain

_attempts: dict  = {}    # { ip: {"count": int, "locked_until": datetime|None} }
_attempts_lock   = Lock()

def _client_ip() -> str:
    return (request.headers.get('X-Forwarded-For', request.remote_addr) or '').split(',')[0].strip()

def _check_locked(ip: str):
    """Return (locked, seconds_remaining). Resets expired locks."""
    with _attempts_lock:
        rec = _attempts.get(ip)
        if not rec:
            return False, 0
        lu = rec.get('locked_until')
        if lu:
            now = datetime.now(timezone.utc)
            if now < lu:
                return True, int((lu - now).total_seconds())
            # lock expired — reset
            _attempts[ip] = {'count': 0, 'locked_until': None}
        return False, 0

def _record_failure(ip: str):
    """Increment failure counter. Returns (now_locked, attempts_remaining)."""
    with _attempts_lock:
        rec = _attempts.get(ip, {'count': 0, 'locked_until': None})
        if rec.get('locked_until') and datetime.now(timezone.utc) >= rec['locked_until']:
            rec = {'count': 0, 'locked_until': None}
        rec['count'] += 1
        if rec['count'] >= MAX_ATTEMPTS:
            rec['locked_until'] = datetime.now(timezone.utc) + timedelta(seconds=LOCKOUT_SECONDS)
            _attempts[ip] = rec
            return True, 0
        _attempts[ip] = rec
        return False, MAX_ATTEMPTS - rec['count']

def _clear_attempts(ip: str):
    with _attempts_lock:
        _attempts.pop(ip, None)

def is_valid_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def is_valid_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    if not re.search(r'[!@#$%^&*(),.?":{}|<>\[\]\\\/_+=`~;\'–-]', password):
        return False, "Password must contain at least one special character"
    return True, "Password is valid"

@auth_bp.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()

        if not data or not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Email and password are required'}), 400

        email = data['email'].strip().lower()
        password = data['password']

        if not is_valid_email(email):
            return jsonify({'error': 'Invalid email format'}), 400

        is_valid, message = is_valid_password(password)
        if not is_valid:
            return jsonify({'error': message}), 400

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return jsonify({'error': 'Email already registered'}), 409

        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

        new_user = User(
            email=email,
            password_hash=password_hash
        )

        db.session.add(new_user)
        db.session.commit()

        access_token = create_access_token(identity=str(new_user.id))

        return jsonify({
            'message': 'User registered successfully',
            'access_token': access_token,
            'user': new_user.to_dict()
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Registration failed: {str(e)}'}), 500

@auth_bp.route('/login', methods=['POST'])
def login():
    try:
        ip = _client_ip()

        locked, secs_left = _check_locked(ip)
        if locked:
            mins = (secs_left + 59) // 60
            return jsonify({
                'error': f'Account temporarily locked. Try again in {mins} minute{"s" if mins != 1 else ""}.',
                'locked': True,
                'retry_after': secs_left,
            }), 429

        data = request.get_json()

        if not data or not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Email and password are required'}), 400

        email    = data['email'].strip().lower()
        password = data['password']

        user = User.query.filter_by(email=email).first()

        if not user or not bcrypt.check_password_hash(user.password_hash, password):
            now_locked, remaining = _record_failure(ip)
            if now_locked:
                mins = LOCKOUT_SECONDS // 60
                return jsonify({
                    'error': f'Too many failed attempts. Account locked for {mins} minutes.',
                    'locked': True,
                    'retry_after': LOCKOUT_SECONDS,
                }), 429

            resp = {'error': 'Invalid email or password'}
            if remaining <= WARNING_AT:
                resp['attempts_remaining'] = remaining
                resp['warning'] = (
                    f'{remaining} attempt{"s" if remaining != 1 else ""} remaining '
                    f'before your account is locked.'
                )
            return jsonify(resp), 401

        if not user.is_active:
            return jsonify({'error': 'Account is deactivated'}), 403

        _clear_attempts(ip)
        user.last_login = datetime.now(timezone.utc)
        db.session.commit()

        access_token = create_access_token(identity=str(user.id))
        return jsonify({
            'message': 'Login successful',
            'access_token': access_token,
            'user': user.to_dict()
        }), 200

    except Exception as e:
        return jsonify({'error': f'Login failed: {str(e)}'}), 500

@auth_bp.route('/me', methods=['GET'])
@jwt_required()
def get_current_user():
    try:
        user_id = int(get_jwt_identity())
        user = User.query.get(user_id)

        if not user:
            return jsonify({'error': 'User not found'}), 404

        return jsonify({'user': user.to_dict()}), 200

    except Exception as e:
        return jsonify({'error': f'Failed to get user: {str(e)}'}), 500

@auth_bp.route('/verify', methods=['GET'])
@jwt_required()
def verify_token():
    try:
        user_id = int(get_jwt_identity())
        user = User.query.get(user_id)

        if not user or not user.is_active:
            return jsonify({'valid': False}), 401

        return jsonify({
            'valid': True,
            'user': user.to_dict()
        }), 200

    except Exception as e:
        return jsonify({'valid': False}), 401
