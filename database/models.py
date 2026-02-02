"""
VIP SQLi Scanner v3.0 - Enhanced Database Models
Upgraded from v2.2 with backward compatibility
Integrates existing ML training data with new authentication & analytics features
"""

from sqlalchemy import Column, Integer, String, DateTime, Float, Text, Boolean, JSON, ForeignKey, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, backref
from sqlalchemy.sql import func
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from typing import Dict, List, Optional
import uuid

Base = declarative_base()

# ============================================================================
# USER MANAGEMENT MODELS
# ============================================================================

class User(Base):
    """User model for authentication and authorization"""
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False, index=True)
    email = Column(String(120), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    api_key = Column(String(255), unique=True, index=True)
    
    # Profile
    full_name = Column(String(255))
    organization = Column(String(255))
    
    # Status
    is_active = Column(Boolean, default=True, index=True)
    is_verified = Column(Boolean, default=False)
    role = Column(String(20), default='user', index=True)  # user, analyst, admin
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    last_login = Column(DateTime)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Preferences
    preferences = Column(JSON, default={})
    notification_settings = Column(JSON, default={})
    
    # Relationships
    scans = relationship('ScanHistory', backref='owner', lazy='dynamic', cascade='all, delete-orphan')
    api_usage = relationship('APIUsage', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    training_contributions = relationship('MLTrainingData', backref='contributor', lazy='dynamic')
    
    def set_password(self, password: str):
        """Hash and set password"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password: str) -> bool:
        """Verify password"""
        return check_password_hash(self.password_hash, password)
    
    def generate_api_key(self) -> str:
        """Generate new API key"""
        self.api_key = str(uuid.uuid4())
        return self.api_key
    
    def to_dict(self, include_sensitive=False) -> Dict:
        """Convert to dictionary"""
        data = {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'full_name': self.full_name,
            'organization': self.organization,
            'role': self.role,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None
        }
        
        if include_sensitive:
            data['api_key'] = self.api_key
            data['preferences'] = self.preferences
            data['notification_settings'] = self.notification_settings
        
        return data

# ============================================================================
# SCAN HISTORY MODELS (Enhanced from v2.2)
# ============================================================================

class ScanHistory(Base):
    """
    Enhanced scan history model
    Backward compatible with v2.2 while adding v3.0 features
    """
    __tablename__ = 'scan_history'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(String(36), unique=True, nullable=False, index=True)
    
    # User association (new in v3.0)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True, index=True)
    
    # Scan metadata
    name = Column(String(255))
    description = Column(Text)
    tags = Column(JSON, default=[])  # For categorization
    
    # Status tracking (enhanced)
    status = Column(String(20), default='idle', index=True)  # idle, running, paused, completed, stopped, error
    
    # Timestamps
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    started_at = Column(DateTime, index=True)
    completed_at = Column(DateTime)
    
    # Statistics (preserved from v2.2)
    total_urls = Column(Integer, default=0)
    scanned_urls = Column(Integer, default=0)  # New: track progress
    vulnerable = Column(Integer, default=0)
    safe = Column(Integer, default=0)
    errors = Column(Integer, default=0)  # New: error tracking
    suspicious = Column(Integer, default=0)  # New: suspicious findings
    
    # Performance metrics (new)
    avg_response_time = Column(Float)
    total_scan_time = Column(Float)
    
    # Configuration (preserved from v2.2)
    config = Column(JSON, default={})
    
    # Advanced features (new)
    waf_detected = Column(Boolean, default=False)
    target_info = Column(JSON, default={})  # Domain info, tech stack, etc.
    
    # Export tracking
    last_exported = Column(DateTime)
    export_count = Column(Integer, default=0)
    
    # Relationships
    results = relationship('URLResult', backref='scan', lazy='dynamic', cascade='all, delete-orphan')
    
    # Indexes for common queries
    __table_args__ = (
        Index('idx_scan_user_timestamp', 'user_id', 'timestamp'),
        Index('idx_scan_status_timestamp', 'status', 'timestamp'),
    )
    
    def calculate_duration(self) -> Optional[float]:
        """Calculate scan duration in seconds"""
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        elif self.started_at:
            return (datetime.utcnow() - self.started_at).total_seconds()
        return None
    
    def get_risk_distribution(self) -> Dict[str, int]:
        """Get count of findings by risk level"""
        from sqlalchemy import func
        from sqlalchemy.orm import Session
        
        # This would need session context
        return {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }
    
    def to_dict(self, include_results=False) -> Dict:
        """Convert to dictionary"""
        data = {
            'id': self.id,
            'scan_id': self.scan_id,
            'user_id': self.user_id,
            'name': self.name,
            'description': self.description,
            'tags': self.tags,
            'status': self.status,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'total_urls': self.total_urls,
            'scanned_urls': self.scanned_urls,
            'vulnerable': self.vulnerable,
            'safe': self.safe,
            'errors': self.errors,
            'suspicious': self.suspicious,
            'avg_response_time': self.avg_response_time,
            'duration': self.calculate_duration(),
            'config': self.config,
            'waf_detected': self.waf_detected,
            'target_info': self.target_info
        }
        
        if include_results:
            data['results'] = [r.to_dict() for r in self.results.all()]
        
        return data

# ============================================================================
# URL RESULT MODELS (Enhanced from v2.2)
# ============================================================================

class URLResult(Base):
    """
    Enhanced URL result model
    Backward compatible with v2.2 while adding v3.0 features
    """
    __tablename__ = 'url_results'
    
    id = Column(Integer, primary_key=True)
    
    # Scan association (preserved)
    scan_id = Column(String(36), ForeignKey('scan_history.scan_id'), nullable=False, index=True)
    
    # URL and verdict (preserved from v2.2)
    url = Column(Text, nullable=False)
    verdict = Column(String(20), index=True)  # SAFE, VULNERABLE, ERROR, SUSPICIOUS
    risk = Column(String(20), index=True)  # critical, high, medium, low, info
    
    # Details (enhanced)
    details = Column(Text)
    payload_used = Column(Text)
    injection_point = Column(String(50))  # GET, POST, COOKIE, HEADER
    
    # Response information (new)
    response_code = Column(Integer)
    response_time = Column(Float)
    response_size = Column(Integer)
    response_headers = Column(JSON)
    
    # ML scoring (preserved from v2.2)
    ml_score = Column(Float)
    ml_confidence = Column(Float)  # New: separate confidence metric
    ml_prediction = Column(String(50))
    features = Column(JSON)
    
    # Validation (new)
    verified = Column(Boolean, default=False)
    false_positive = Column(Boolean, default=False)
    verified_by = Column(Integer, ForeignKey('users.id'), nullable=True)
    verification_notes = Column(Text)
    
    # Evidence (new)
    evidence = Column(JSON)  # Screenshots, diff, etc.
    remediation = Column(Text)
    
    # Metadata
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    errors = Column(JSON)  # Error details if verdict is ERROR
    
    # WAF detection (new)
    waf_triggered = Column(Boolean, default=False)
    waf_signature = Column(String(255))
    
    # Severity scoring (new)
    cvss_score = Column(Float)
    severity_justification = Column(Text)
    
    # Indexes
    __table_args__ = (
        Index('idx_result_scan_verdict', 'scan_id', 'verdict'),
        Index('idx_result_scan_risk', 'scan_id', 'risk'),
        Index('idx_result_timestamp', 'timestamp'),
    )
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'url': self.url,
            'verdict': self.verdict,
            'risk': self.risk,
            'details': self.details,
            'payload_used': self.payload_used,
            'injection_point': self.injection_point,
            'response_code': self.response_code,
            'response_time': self.response_time,
            'response_size': self.response_size,
            'ml_score': self.ml_score,
            'ml_confidence': self.ml_confidence,
            'ml_prediction': self.ml_prediction,
            'features': self.features,
            'verified': self.verified,
            'false_positive': self.false_positive,
            'verification_notes': self.verification_notes,
            'evidence': self.evidence,
            'remediation': self.remediation,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'errors': self.errors,
            'waf_triggered': self.waf_triggered,
            'cvss_score': self.cvss_score
        }

# ============================================================================
# ML TRAINING DATA MODELS (Enhanced from v2.2)
# ============================================================================

class MLTrainingData(Base):
    """
    Enhanced ML training data model
    Backward compatible with v2.2 while adding v3.0 features
    """
    __tablename__ = 'ml_training_data'
    
    id = Column(Integer, primary_key=True)
    
    # URL and features (preserved from v2.2)
    url = Column(Text, nullable=False)
    features = Column(JSON, nullable=False)
    
    # Labels (preserved from v2.2)
    label = Column(Integer, nullable=False)  # 0=safe, 1=vulnerable
    confidence = Column(Float)
    
    # Verification (preserved from v2.2)
    verified = Column(Boolean, default=False, index=True)
    
    # Contributor tracking (new in v3.0)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True, index=True)
    
    # Source information (new)
    source = Column(String(50))  # manual, automated, imported
    source_scan_id = Column(String(36))  # If from a scan
    
    # Quality metrics (new)
    quality_score = Column(Float)  # 0-1, based on verification, source, etc.
    times_used = Column(Integer, default=0)  # How many times used in training
    
    # Version control (new)
    version = Column(Integer, default=1)
    superseded_by = Column(Integer, ForeignKey('ml_training_data.id'), nullable=True)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Additional context (new)
    attack_type = Column(String(50))  # error-based, boolean, time-based, etc.
    payload_category = Column(String(50))
    notes = Column(Text)
    
    # Indexes
    __table_args__ = (
        Index('idx_training_label_verified', 'label', 'verified'),
        Index('idx_training_quality', 'quality_score'),
    )
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'id': self.id,
            'url': self.url,
            'features': self.features,
            'label': self.label,
            'confidence': self.confidence,
            'verified': self.verified,
            'user_id': self.user_id,
            'source': self.source,
            'quality_score': self.quality_score,
            'times_used': self.times_used,
            'version': self.version,
            'attack_type': self.attack_type,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'notes': self.notes
        }

# ============================================================================
# NEW MODELS IN v3.0
# ============================================================================

class ScheduledScan(Base):
    """Scheduled/recurring scan configuration"""
    __tablename__ = 'scheduled_scans'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    
    # Schedule details
    name = Column(String(255), nullable=False)
    description = Column(Text)
    urls = Column(JSON, nullable=False)  # List of URLs to scan
    config = Column(JSON)  # Scan configuration
    
    # Schedule configuration
    schedule_type = Column(String(20))  # daily, weekly, monthly, cron
    cron_expression = Column(String(100))
    timezone = Column(String(50), default='UTC')
    
    # Execution tracking
    next_run = Column(DateTime, index=True)
    last_run = Column(DateTime)
    last_scan_id = Column(String(36))
    run_count = Column(Integer, default=0)
    
    # Status
    is_active = Column(Boolean, default=True, index=True)
    
    # Notifications
    notify_on_completion = Column(Boolean, default=True)
    notify_on_vulnerabilities = Column(Boolean, default=True)
    notification_channels = Column(JSON)  # email, slack, etc.
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'user_id': self.user_id,
            'name': self.name,
            'description': self.description,
            'schedule_type': self.schedule_type,
            'cron_expression': self.cron_expression,
            'next_run': self.next_run.isoformat() if self.next_run else None,
            'last_run': self.last_run.isoformat() if self.last_run else None,
            'is_active': self.is_active,
            'run_count': self.run_count
        }

class Setting(Base):
    """Application settings"""
    __tablename__ = 'settings'
    
    id = Column(Integer, primary_key=True)
    key = Column(String(100), unique=True, nullable=False, index=True)
    value = Column(JSON)
    data_type = Column(String(20))  # string, integer, boolean, json
    category = Column(String(50), index=True)  # scanner, ml, notifications, etc.
    
    description = Column(Text)
    is_public = Column(Boolean, default=False)  # Can non-admins see it?
    is_editable = Column(Boolean, default=True)  # Can it be changed via UI?
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = Column(Integer, ForeignKey('users.id'))
    
    def to_dict(self) -> Dict:
        return {
            'key': self.key,
            'value': self.value,
            'data_type': self.data_type,
            'category': self.category,
            'description': self.description,
            'is_public': self.is_public,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class APIUsage(Base):
    """Track API usage for rate limiting and analytics"""
    __tablename__ = 'api_usage'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True, index=True)
    
    # Request details
    endpoint = Column(String(255), index=True)
    method = Column(String(10))
    ip_address = Column(String(45))  # IPv6 compatible
    user_agent = Column(Text)
    
    # Response
    status_code = Column(Integer)
    response_time = Column(Float)
    
    # Metadata
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    request_id = Column(String(36))
    
    # Indexes
    __table_args__ = (
        Index('idx_api_user_timestamp', 'user_id', 'timestamp'),
        Index('idx_api_endpoint_timestamp', 'endpoint', 'timestamp'),
    )

class Notification(Base):
    """Notification history"""
    __tablename__ = 'notifications'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    
    # Notification details
    type = Column(String(50))  # scan_complete, vulnerability_found, error, etc.
    title = Column(String(255))
    message = Column(Text)
    data = Column(JSON)  # Additional context
    
    # Delivery
    channel = Column(String(50))  # email, web, slack, etc.
    delivered = Column(Boolean, default=False)
    delivered_at = Column(DateTime)
    
    # Status
    read = Column(Boolean, default=False, index=True)
    read_at = Column(DateTime)
    
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

class AuditLog(Base):
    """Audit trail for security and compliance"""
    __tablename__ = 'audit_logs'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True, index=True)
    
    # Action details
    action = Column(String(100), index=True)  # login, scan_start, export, etc.
    resource_type = Column(String(50))  # user, scan, setting, etc.
    resource_id = Column(String(100))
    
    # Context
    ip_address = Column(String(45))
    user_agent = Column(Text)
    details = Column(JSON)
    
    # Result
    success = Column(Boolean, index=True)
    error_message = Column(Text)
    
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    
    __table_args__ = (
        Index('idx_audit_user_timestamp', 'user_id', 'timestamp'),
        Index('idx_audit_action_timestamp', 'action', 'timestamp'),
    )

# ============================================================================
# STATISTICS & ANALYTICS MODELS
# ============================================================================

class ScanStatistics(Base):
    """Aggregated scan statistics for faster analytics queries"""
    __tablename__ = 'scan_statistics'
    
    id = Column(Integer, primary_key=True)
    
    # Time period
    date = Column(DateTime, nullable=False, unique=True, index=True)
    period = Column(String(20))  # daily, weekly, monthly
    
    # Scan metrics
    total_scans = Column(Integer, default=0)
    completed_scans = Column(Integer, default=0)
    failed_scans = Column(Integer, default=0)
    
    # URL metrics
    total_urls_scanned = Column(Integer, default=0)
    unique_domains = Column(Integer, default=0)
    
    # Finding metrics
    total_vulnerabilities = Column(Integer, default=0)
    critical_findings = Column(Integer, default=0)
    high_findings = Column(Integer, default=0)
    medium_findings = Column(Integer, default=0)
    low_findings = Column(Integer, default=0)
    
    # Performance metrics
    avg_scan_duration = Column(Float)
    avg_urls_per_scan = Column(Float)
    
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# ============================================================================
# MIGRATION HELPER FUNCTIONS
# ============================================================================

def upgrade_v2_to_v3(session):
    """
    Helper function to migrate v2.2 data to v3.0 schema
    Run this after creating v3.0 tables
    """
    # This would handle data migration if needed
    # For example, adding default user_id to existing scans
    pass

def get_model_by_name(model_name: str):
    """Get model class by name"""
    models = {
        'User': User,
        'ScanHistory': ScanHistory,
        'URLResult': URLResult,
        'MLTrainingData': MLTrainingData,
        'ScheduledScan': ScheduledScan,
        'Setting': Setting,
        'APIUsage': APIUsage,
        'Notification': Notification,
        'AuditLog': AuditLog,
        'ScanStatistics': ScanStatistics
    }
    return models.get(model_name)

# ============================================================================
# METADATA
# ============================================================================

__version__ = '3.0'
__models__ = [
    'User',
    'ScanHistory', 
    'URLResult',
    'MLTrainingData',
    'ScheduledScan',
    'Setting',
    'APIUsage',
    'Notification',
    'AuditLog',
    'ScanStatistics'
]