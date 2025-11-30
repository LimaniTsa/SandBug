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
    
    # File information
    filename = db.Column(db.String(255), nullable=False)
    file_hash = db.Column(db.String(64), nullable=False, index=True)
    file_size = db.Column(db.Integer, nullable=False)
    file_type = db.Column(db.String(50))
    file_path = db.Column(db.String(500), nullable=True)  # ADDED for Sprint 4 - nullable for existing records
    
    # Analysis status and risk
    status = db.Column(db.String(20), default='pending', nullable=False)  # pending, static_complete, processing, completed, failed
    risk_level = db.Column(db.String(20))  # safe, low, medium, high, critical
    risk_score = db.Column(db.Integer, default=0)  # ADDED for Sprint 4 (0-100)
    
    # Timestamps
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    completed_at = db.Column(db.DateTime)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)  # ADDED for Sprint 4
    
    # Analysis results (stored as JSON)
    static_analysis = db.Column(db.JSON)  # UPDATED for Sprint 4 - stores full static analysis results
    dynamic_analysis = db.Column(db.JSON)  # For Sprint 6-7
    ai_summary = db.Column(db.Text)  # For Sprint 9
    
    def __repr__(self):
        return f'<Analysis {self.id}: {self.filename}>'
    
    def calculate_risk_level(self):
        """Calculate risk level based on risk score"""
        if self.risk_score < 25:
            self.risk_level = 'low'
        elif self.risk_score < 50:
            self.risk_level = 'medium'
        elif self.risk_score < 75:
            self.risk_level = 'high'
        else:
            self.risk_level = 'critical'
    
    def to_dict(self, include_results=False):
        """Convert to dictionary with optional full results"""
        data = {
            'id': self.id,
            'user_id': self.user_id,
            'filename': self.filename,
            'file_hash': self.file_hash,
            'file_size': self.file_size,
            'file_type': self.file_type,
            'status': self.status,
            'risk_score': self.risk_score,
            'risk_level': self.risk_level,
            'submitted_at': self.submitted_at.isoformat() if self.submitted_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None
        }
        
        if include_results:
            data['static_analysis'] = self.static_analysis
            data['dynamic_analysis'] = self.dynamic_analysis
            data['ai_summary'] = self.ai_summary
        
        return data