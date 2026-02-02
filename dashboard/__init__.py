"""
VIP SQLi Scanner v4.0 - Package Initialization
Enhanced module with better organization and exports
"""

from .app import (
    # Main functions
    start_dashboard,
    broadcast_update,
    
    # Flask app instance
    app,
    socketio,
    db,
    
    # Database models
    User,
    Scan,
    ScanResult,
    Setting,
    AuditLog,
    Notification,
    
    # Enumerations
    ScanStatus,
    VerdictType,
    RiskLevel,
    ExportFormat,
    AttackType,
    NotificationType,
    
    # Utilities
    VulnerabilityScanner,
    PayloadLibrary,
    ScanState,
    
    # Version info
)

__version__ = '4.0.0'
__author__ = 'VIP SQLi Scanner Team'
__description__ = 'Advanced SQL Injection Vulnerability Scanner'

# Public API
__all__ = [
    # Main functions
    'start_dashboard',
    'broadcast_update',
    
    # Core components
    'app',
    'socketio',
    'db',
    
    # Models
    'User',
    'Scan',
    'ScanResult',
    'Setting',
    'AuditLog',
    'Notification',
    
    # Enums
    'ScanStatus',
    'VerdictType',
    'RiskLevel',
    'ExportFormat',
    'AttackType',
    'NotificationType',
    
    # Scanner
    'VulnerabilityScanner',
    'PayloadLibrary',
    'ScanState',
    
    # Metadata
    '__version__',
    '__author__',
    '__description__',
]

def get_version():
    """Get package version"""
    return __version__

def get_info():
    """Get package information"""
    return {
        'version': __version__,
        'author': __author__,
        'description': __description__,
        'features': [
            'Multi-threaded scanning',
            'WAF detection and bypass',
            'Advanced SQL injection payloads',
            'ML-based vulnerability scoring',
            'Real-time WebSocket updates',
            'Multiple export formats (JSON, CSV, HTML, PDF, MD, SARIF)',
            'Audit logging and compliance',
            'Rate limiting and security',
            'Database persistence',
            'RESTful API',
        ]
    }