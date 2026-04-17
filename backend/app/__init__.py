from flask import Flask
from flask_cors import CORS
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from flask_bcrypt import Bcrypt
from redis import Redis
from rq import Queue

from app.config import Config
from app.models import db

# extensions are initialised here and bound to the app inside create_app
migrate = Migrate()
jwt = JWTManager()
bcrypt = Bcrypt()
rq_queue: Queue = None


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)
    bcrypt.init_app(app)

    # restrict cross-origin requests to the configured frontend origins
    CORS(app, resources={
        r"/api/*": {
            "origins": app.config['CORS_ORIGINS'],
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization"],
        }
    })

    from app.api import auth_bp, analysis_bp, info_bp
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(analysis_bp, url_prefix='/api/analysis')
    app.register_blueprint(info_bp, url_prefix='/api/info')

    import os
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    # connect to redis and create the rq job queue for background analysis tasks
    global rq_queue
    redis_conn = Redis.from_url(app.config['REDIS_URL'])
    rq_queue = Queue(connection=redis_conn)
    app.rq_queue = rq_queue

    return app
