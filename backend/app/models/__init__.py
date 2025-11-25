from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    #user model for authentication
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    
    #relationships
    analyses = db.relationship('Analysis', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<User {self.email}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'created_at': self.created_at.isoformat(),
            'last_login': self.last_login.isoformat() if self.last_login else None
        }

class Analysis(db.Model):
    #analysis model for storing malware analysis results
    __tablename__ = 'analyses'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)  # Nullable for guest analyses
    filename = db.Column(db.String(255), nullable=False)
    file_hash = db.Column(db.String(64), nullable=False, index=True)
    file_size = db.Column(db.Integer, nullable=False)
    file_type = db.Column(db.String(50))
    
    #analysis status
    status = db.Column(db.String(20), default='pending', nullable=False)  # pending, processing, completed, failed
    risk_level = db.Column(db.String(20))  # safe, low, medium, high, critical
    
    #timestamps
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    completed_at = db.Column(db.DateTime)
    
    #analysis results (stored as JSON)
    static_analysis = db.Column(db.JSON)
    dynamic_analysis = db.Column(db.JSON)
    ai_summary = db.Column(db.Text)
    
    def __repr__(self):
        return f'<Analysis {self.id}: {self.filename}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'filename': self.filename,
            'file_hash': self.file_hash,
            'file_size': self.file_size,
            'file_type': self.file_type,
            'status': self.status,
            'risk_level': self.risk_level,
            'submitted_at': self.submitted_at.isoformat(),
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'ai_summary': self.ai_summary
        }