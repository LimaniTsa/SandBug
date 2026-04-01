from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = 'users'
    id            = db.Column(db.Integer, primary_key=True)
    email         = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)
    last_login    = db.Column(db.DateTime)
    is_active     = db.Column(db.Boolean, default=True)
    analyses      = db.relationship('Analysis', backref='user', lazy=True,
                                    foreign_keys='Analysis.user_id')
    url_analyses  = db.relationship('UrlAnalysis', backref='user', lazy=True)

    def to_dict(self):
        return {
            'id':         self.id,
            'email':      self.email,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None,
        }


class Analysis(db.Model):
    __tablename__     = 'analyses'
    id                = db.Column(db.Integer, primary_key=True)
    user_id           = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    filename          = db.Column(db.String(255), nullable=False)
    file_hash         = db.Column(db.String(64), nullable=False, index=True)
    file_size         = db.Column(db.Integer)
    file_type         = db.Column(db.String(50))
    status            = db.Column(db.String(30), default='pending')
    risk_score        = db.Column(db.Float)
    risk_level        = db.Column(db.String(20), index=True)
    submitted_at      = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at      = db.Column(db.DateTime)
    triage_sample_id  = db.Column(db.String(100))
    error_message     = db.Column(db.Text)

    # Internal — not in the public schema but needed for file storage and deletion
    file_path         = db.Column(db.String(500), nullable=True)
    # For URL analyses: links to the UrlAnalysis record that holds the full result
    url_analysis_id   = db.Column(db.Integer, db.ForeignKey('url_analyses.id'), nullable=True)

    # Relationships
    static_result  = db.relationship('StaticResult',  backref='analysis', uselist=False,
                                      cascade='all, delete-orphan')
    yara_matches   = db.relationship('YaraMatch',     backref='analysis', lazy=True,
                                      cascade='all, delete-orphan')
    dynamic_result = db.relationship('DynamicResult', backref='analysis', uselist=False,
                                      cascade='all, delete-orphan')
    iocs           = db.relationship('IOC',           backref='analysis', lazy=True,
                                      cascade='all, delete-orphan')
    ai_report      = db.relationship('AIReport',      backref='analysis', uselist=False,
                                      cascade='all, delete-orphan')
    url_analysis   = db.relationship('UrlAnalysis',   foreign_keys=[url_analysis_id])

    def calculate_risk_level(self):
        score = float(self.risk_score or 0)
        if score < 25:
            self.risk_level = 'low'
        elif score < 50:
            self.risk_level = 'medium'
        elif score < 75:
            self.risk_level = 'high'
        else:
            self.risk_level = 'critical'

    def to_dict(self, include_results=False):
        data = {
            'id':           self.id,
            'user_id':      self.user_id,
            'filename':     self.filename,
            'file_hash':    self.file_hash,
            'file_size':    self.file_size,
            'file_type':    self.file_type,
            'status':       self.status,
            'risk_score':   self.risk_score,
            'risk_level':   self.risk_level,
            'submitted_at': self.submitted_at.isoformat() if self.submitted_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
        }

        if not include_results:
            return data

    
        if self.file_type == 'URL' and self.url_analysis_id:
            ua = self.url_analysis
            if ua:
                data['static_analysis']  = ua.raw_result or {}
                data['dynamic_analysis'] = None
                data['ai_summary']       = ua.ai_summary
            return data


        sr = self.static_result
        if sr:
            yara_rules = [
                {
                    'rule': ym.rule_name,
                    'meta': {'severity': ym.severity or 'low', 'description': ''},
                    'tags': [ym.category] if ym.category else [],
                    'strings': ym.matched_strings or [],
                }
                for ym in (self.yara_matches or [])
            ]
            static_indicators = [
                ioc.value
                for ioc in (self.iocs or [])
                if ioc.source == 'static'
            ]
            sig_valid = bool(sr.is_signed)
            data['static_analysis'] = {
                'risk_score':            float(self.risk_score or 0),
                'entropy':               {
                    'overall':        sr.entropy or 0,
                    'interpretation': _interpret_entropy(sr.entropy or 0),
                },
                'sections':              sr.sections or [],
                'imports':               sr.imports or [],
                'yara':                  {'matched': bool(yara_rules), 'rules': yara_rules},
                'suspicious_indicators': static_indicators,
                'signature': {
                    'valid':     sig_valid,
                    'status':    'Valid' if sig_valid else 'NotSigned',
                    'publisher': sr.publisher,
                },
                'file_info': {
                    'filename': self.filename,
                    'size':     self.file_size,
                    'sha256':   self.file_hash,
                },
                'strings': sr.strings_extracted or {},
            }
        else:
            data['static_analysis'] = None

        dr = self.dynamic_result
        if dr:
            fo = dr.file_operations or {}
            data['dynamic_analysis'] = {
                'triage': {
                    'sandbox':       'hatching_triage',
                    'sample_id':     dr.sandbox_sample_id,
                    'report_url':    fo.get('report_url'),
                    'triage_score':  fo.get('triage_score', 0),
                    'signatures':    fo.get('signatures', []),
                    'network':       dr.network_activity or {},
                    'processes':     dr.processes or [],
                    'dropped_files': dr.dropped_files or [],
                    'registry':      dr.registry_changes or [],
                    'mutexes':       fo.get('mutexes', []),
                    'tags':          fo.get('tags', []),
                    'errors':        fo.get('errors', []),
                },
                'hybrid_analysis': None,
            }
        else:
            data['dynamic_analysis'] = None

        ar = self.ai_report
        data['ai_summary'] = ar.summary if ar else None

        return data


class StaticResult(db.Model):
    __tablename__     = 'static_results'
    id                = db.Column(db.Integer, primary_key=True)
    analysis_id       = db.Column(db.Integer, db.ForeignKey('analyses.id'), nullable=False)
    pe_type           = db.Column(db.String(50))
    entropy           = db.Column(db.Float)
    is_packed         = db.Column(db.Boolean)
    is_signed         = db.Column(db.Boolean)
    publisher         = db.Column(db.String(255))   # Authenticode CN= value
    imports           = db.Column(db.JSON)
    sections          = db.Column(db.JSON)
    strings_extracted = db.Column(db.JSON)
    created_at        = db.Column(db.DateTime, default=datetime.utcnow)


class YaraMatch(db.Model):
    __tablename__   = 'yara_matches'
    id              = db.Column(db.Integer, primary_key=True)
    analysis_id     = db.Column(db.Integer, db.ForeignKey('analyses.id'), nullable=False)
    rule_name       = db.Column(db.String(255), nullable=False)
    category        = db.Column(db.String(100))
    severity        = db.Column(db.String(20))
    matched_strings = db.Column(db.JSON)
    matched_at      = db.Column(db.DateTime, default=datetime.utcnow)


class DynamicResult(db.Model):
    __tablename__         = 'dynamic_results'
    id                    = db.Column(db.Integer, primary_key=True)
    analysis_id           = db.Column(db.Integer, db.ForeignKey('analyses.id'), nullable=False)
    sandbox_provider      = db.Column(db.String(50))   # 'triage'
    sandbox_sample_id     = db.Column(db.String(100))
    execution_time        = db.Column(db.Integer)
    executed_successfully = db.Column(db.Boolean)
    exit_code             = db.Column(db.Integer)
    processes             = db.Column(db.JSON)
    network_activity      = db.Column(db.JSON)
    file_operations       = db.Column(db.JSON)
    registry_changes      = db.Column(db.JSON)
    dropped_files         = db.Column(db.JSON)
    created_at            = db.Column(db.DateTime, default=datetime.utcnow)


class IOC(db.Model):
    __tablename__ = 'iocs'
    id          = db.Column(db.Integer, primary_key=True)
    analysis_id = db.Column(db.Integer, db.ForeignKey('analyses.id'), nullable=False)
    ioc_type    = db.Column(db.String(30))   # ip, domain, hash, registry_key, url, indicator
    value       = db.Column(db.String(500), index=True)
    source      = db.Column(db.String(50))   # 'static', 'dynamic', 'yara'
    severity    = db.Column(db.String(20))
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)


class UrlAnalysis(db.Model):
    __tablename__   = 'url_analyses'
    id              = db.Column(db.Integer, primary_key=True)
    user_id         = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    url_submitted   = db.Column(db.Text, nullable=False)
    final_url       = db.Column(db.Text)
    redirect_chain  = db.Column(db.JSON)
    resolved_ip     = db.Column(db.String(45))
    abuseipdb_score = db.Column(db.Integer)
    gsb_threat_type = db.Column(db.String(100))
    risk_score      = db.Column(db.Float)
    risk_level      = db.Column(db.String(20))
    ai_summary      = db.Column(db.Text)
    raw_result      = db.Column(db.JSON)
    submitted_at    = db.Column(db.DateTime, default=datetime.utcnow)


class AIReport(db.Model):
    __tablename__  = 'ai_reports'
    id             = db.Column(db.Integer, primary_key=True)
    analysis_id    = db.Column(db.Integer, db.ForeignKey('analyses.id'), nullable=False)
    model_used     = db.Column(db.String(100))
    threat_level   = db.Column(db.String(20))
    summary        = db.Column(db.Text)
    key_behaviours = db.Column(db.Text)
    remediation    = db.Column(db.Text)
    tokens_used    = db.Column(db.Integer)
    generated_at   = db.Column(db.DateTime, default=datetime.utcnow)


def _interpret_entropy(e: float) -> str:
    if e < 4.0: return "Low (likely not packed)"
    if e < 6.0: return "Medium (normal executable)"
    if e < 7.5: return "High (possibly compressed)"
    return "Very High (likely packed/encrypted)"
