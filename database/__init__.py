"""
VIP SQLi Scanner v3.0 - Database Initialization Module
Enhanced from v2.2 with migration support and advanced features
"""

from sqlalchemy import create_engine, event, pool
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.engine import Engine
from contextlib import contextmanager
import os
import logging
from pathlib import Path

# Import all models
from .models import (
    Base,
    User,
    ScanHistory,
    URLResult,
    MLTrainingData,
    ScheduledScan,
    Setting,
    APIUsage,
    Notification,
    AuditLog,
    ScanStatistics
)

logger = logging.getLogger(__name__)

# ============================================================================
# DATABASE CONFIGURATION
# ============================================================================

class DatabaseConfig:
    """Database configuration with environment variable support"""
    
    @staticmethod
    def get_database_url():
        """Get database URL from environment or use default"""
        # Priority:
        # 1. Environment variable DATABASE_URL
        # 2. User's home directory (backward compatible with v2.2)
        # 3. Current directory
        
        # Check environment variable first
        db_url = os.getenv('DATABASE_URL')
        if db_url:
            return db_url
        
        # Default to SQLite in user's home directory (v2.2 compatible)
        db_path = os.getenv('VIPSQLI_DB_PATH')
        if not db_path:
            db_path = os.path.expanduser('~/.vipsqli/scanner.db')
        
        # Ensure directory exists
        db_dir = os.path.dirname(db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)
        
        return f'sqlite:///{db_path}'
    
    @staticmethod
    def get_engine_config():
        """Get engine configuration based on database type"""
        db_url = DatabaseConfig.get_database_url()
        
        config = {
            'echo': os.getenv('SQL_ECHO', 'false').lower() == 'true',
            'pool_pre_ping': True,  # Verify connections before using
        }
        
        if db_url.startswith('sqlite'):
            # SQLite specific configuration
            config.update({
                'connect_args': {'check_same_thread': False},
                'poolclass': pool.StaticPool,
            })
        elif db_url.startswith('postgresql'):
            # PostgreSQL specific configuration
            config.update({
                'pool_size': int(os.getenv('DB_POOL_SIZE', '20')),
                'max_overflow': int(os.getenv('DB_MAX_OVERFLOW', '40')),
                'pool_timeout': int(os.getenv('DB_POOL_TIMEOUT', '30')),
                'pool_recycle': int(os.getenv('DB_POOL_RECYCLE', '3600')),
            })
        
        return config

# ============================================================================
# ENGINE AND SESSION CREATION
# ============================================================================

# Get database URL
DATABASE_URL = DatabaseConfig.get_database_url()
DB_PATH = DATABASE_URL.replace('sqlite:///', '') if DATABASE_URL.startswith('sqlite') else None

logger.info(f"Database URL: {DATABASE_URL}")

# Create engine with configuration
engine_config = DatabaseConfig.get_engine_config()
engine = create_engine(DATABASE_URL, **engine_config)

# Create session factory
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)

# Create thread-safe scoped session
Session = scoped_session(SessionLocal)

# ============================================================================
# SQLITE OPTIMIZATIONS
# ============================================================================

@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_conn, connection_record):
    """Set SQLite pragmas for better performance"""
    if DATABASE_URL.startswith('sqlite'):
        cursor = dbapi_conn.cursor()
        # Enable foreign keys
        cursor.execute("PRAGMA foreign_keys=ON")
        # Use Write-Ahead Logging for better concurrency
        cursor.execute("PRAGMA journal_mode=WAL")
        # Synchronous mode for better performance
        cursor.execute("PRAGMA synchronous=NORMAL")
        # Increase cache size (in KB)
        cursor.execute("PRAGMA cache_size=-64000")  # 64MB
        # Temporary storage in memory
        cursor.execute("PRAGMA temp_store=MEMORY")
        cursor.close()

# ============================================================================
# DATABASE INITIALIZATION
# ============================================================================

def init_db(drop_all=False):
    """
    Initialize database and create all tables
    
    Args:
        drop_all: If True, drop all existing tables (DANGEROUS!)
    """
    try:
        if drop_all:
            logger.warning("Dropping all existing tables!")
            Base.metadata.drop_all(engine)
        
        # Create all tables
        Base.metadata.create_all(engine)
        logger.info("Database tables created successfully")
        
        # Initialize default data
        _create_default_settings()
        
        return True
    except Exception as e:
        logger.error(f"Error initializing database: {str(e)}")
        raise

def _create_default_settings():
    """Create default application settings"""
    session = get_session()
    try:
        default_settings = [
            # Scanner settings
            {'key': 'max_concurrent', 'value': 100, 'category': 'scanner', 
             'description': 'Maximum concurrent scan threads', 'is_public': True},
            {'key': 'timeout', 'value': 20, 'category': 'scanner',
             'description': 'Request timeout in seconds', 'is_public': True},
            {'key': 'retry_attempts', 'value': 3, 'category': 'scanner',
             'description': 'Number of retry attempts for failed requests', 'is_public': True},
            
            # Detection settings
            {'key': 'waf_detection', 'value': True, 'category': 'detection',
             'description': 'Enable WAF detection', 'is_public': True},
            {'key': 'error_based', 'value': True, 'category': 'detection',
             'description': 'Enable error-based SQL injection detection', 'is_public': True},
            {'key': 'boolean_based', 'value': True, 'category': 'detection',
             'description': 'Enable boolean-based SQL injection detection', 'is_public': True},
            {'key': 'time_based', 'value': True, 'category': 'detection',
             'description': 'Enable time-based SQL injection detection', 'is_public': True},
            
            # ML settings
            {'key': 'ml_enabled', 'value': True, 'category': 'ml',
             'description': 'Enable machine learning detection', 'is_public': True},
            {'key': 'ml_confidence_threshold', 'value': 0.7, 'category': 'ml',
             'description': 'ML confidence threshold for positive detection', 'is_public': True},
            {'key': 'ml_model_version', 'value': '1.0', 'category': 'ml',
             'description': 'Current ML model version', 'is_public': False},
            
            # Notification settings
            {'key': 'notifications_enabled', 'value': True, 'category': 'notifications',
             'description': 'Enable notifications', 'is_public': False},
            {'key': 'email_notifications', 'value': False, 'category': 'notifications',
             'description': 'Enable email notifications', 'is_public': False},
            {'key': 'slack_notifications', 'value': False, 'category': 'notifications',
             'description': 'Enable Slack notifications', 'is_public': False},
            
            # Export settings
            {'key': 'default_export_format', 'value': 'json', 'category': 'export',
             'description': 'Default export format', 'is_public': True},
            {'key': 'include_safe_in_exports', 'value': False, 'category': 'export',
             'description': 'Include safe URLs in exports by default', 'is_public': True},
            
            # Security settings
            {'key': 'rate_limit_enabled', 'value': True, 'category': 'security',
             'description': 'Enable rate limiting', 'is_public': False},
            {'key': 'require_authentication', 'value': False, 'category': 'security',
             'description': 'Require authentication for all scans', 'is_public': False},
            {'key': 'max_urls_per_scan', 'value': 10000, 'category': 'security',
             'description': 'Maximum URLs allowed per scan', 'is_public': True},
        ]
        
        for setting_data in default_settings:
            existing = session.query(Setting).filter_by(key=setting_data['key']).first()
            if not existing:
                setting = Setting(**setting_data)
                session.add(setting)
        
        session.commit()
        logger.info("Default settings created")
        
    except Exception as e:
        session.rollback()
        logger.error(f"Error creating default settings: {str(e)}")
    finally:
        session.close()

# ============================================================================
# SESSION MANAGEMENT
# ============================================================================

def get_session():
    """Get a new database session"""
    return SessionLocal()

@contextmanager
def get_db_session():
    """
    Context manager for database sessions
    Automatically handles commit/rollback and cleanup
    
    Usage:
        with get_db_session() as session:
            user = session.query(User).first()
    """
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception as e:
        session.rollback()
        logger.error(f"Database error: {str(e)}")
        raise
    finally:
        session.close()

def get_scoped_session():
    """Get a thread-safe scoped session"""
    return Session()

# ============================================================================
# MIGRATION UTILITIES
# ============================================================================

def migrate_from_v2():
    """
    Migrate data from v2.2 to v3.0
    This preserves existing scan history and ML training data
    """
    session = get_session()
    try:
        # Check if migration is needed
        # v2.2 scans won't have user_id, so we can detect them
        v2_scans = session.query(ScanHistory).filter(
            ScanHistory.user_id == None
        ).count()
        
        if v2_scans > 0:
            logger.info(f"Found {v2_scans} v2.2 scans to migrate")
            
            # Create a default "legacy" user for v2.2 scans
            legacy_user = session.query(User).filter_by(username='legacy').first()
            if not legacy_user:
                legacy_user = User(
                    username='legacy',
                    email='legacy@vipsqli.local',
                    role='user',
                    is_active=False
                )
                legacy_user.set_password('disabled')
                session.add(legacy_user)
                session.commit()
            
            # Update v2.2 scans to have the legacy user
            session.query(ScanHistory).filter(
                ScanHistory.user_id == None
            ).update({'user_id': legacy_user.id})
            
            session.commit()
            logger.info("v2.2 data migration completed")
        
    except Exception as e:
        session.rollback()
        logger.error(f"Migration error: {str(e)}")
        raise
    finally:
        session.close()

def check_database_version():
    """Check database schema version and migration status"""
    session = get_session()
    try:
        # Try to query a v3.0 specific column
        result = session.query(ScanHistory).limit(1).all()
        
        # Check if User table exists (v3.0 feature)
        from sqlalchemy import inspect
        inspector = inspect(engine)
        tables = inspector.get_table_names()
        
        has_users = 'users' in tables
        has_scheduled = 'scheduled_scans' in tables
        
        version = '3.0' if has_users and has_scheduled else '2.2'
        
        logger.info(f"Database version: {version}")
        return version
        
    except Exception as e:
        logger.warning(f"Could not determine database version: {str(e)}")
        return 'unknown'
    finally:
        session.close()

# ============================================================================
# DATABASE UTILITIES
# ============================================================================

def get_or_create(session, model, **kwargs):
    """Get existing record or create new one"""
    instance = session.query(model).filter_by(**kwargs).first()
    if instance:
        return instance, False
    else:
        instance = model(**kwargs)
        session.add(instance)
        return instance, True

def bulk_create(session, model, records):
    """Bulk create records for better performance"""
    try:
        session.bulk_insert_mappings(model, records)
        session.commit()
        return True
    except Exception as e:
        session.rollback()
        logger.error(f"Bulk create error: {str(e)}")
        return False

def vacuum_database():
    """Optimize database (SQLite only)"""
    if DATABASE_URL.startswith('sqlite'):
        try:
            engine.execute("VACUUM")
            logger.info("Database vacuumed successfully")
            return True
        except Exception as e:
            logger.error(f"Vacuum error: {str(e)}")
            return False
    return False

def get_database_stats():
    """Get database statistics"""
    session = get_session()
    try:
        stats = {
            'users': session.query(User).count(),
            'scans': session.query(ScanHistory).count(),
            'results': session.query(URLResult).count(),
            'training_data': session.query(MLTrainingData).count(),
            'scheduled_scans': session.query(ScheduledScan).count(),
            'settings': session.query(Setting).count(),
        }
        
        if DATABASE_URL.startswith('sqlite') and DB_PATH:
            stats['database_size_mb'] = os.path.getsize(DB_PATH) / (1024 * 1024)
        
        return stats
        
    except Exception as e:
        logger.error(f"Error getting database stats: {str(e)}")
        return {}
    finally:
        session.close()

# ============================================================================
# CLEANUP AND MAINTENANCE
# ============================================================================

def cleanup_old_data(days=90):
    """
    Clean up old data to keep database size manageable
    
    Args:
        days: Keep data newer than this many days
    """
    from datetime import datetime, timedelta
    
    session = get_session()
    try:
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        # Delete old scan history and results
        deleted_scans = session.query(ScanHistory).filter(
            ScanHistory.timestamp < cutoff_date
        ).delete()
        
        # Delete old API usage logs
        deleted_api = session.query(APIUsage).filter(
            APIUsage.timestamp < cutoff_date
        ).delete()
        
        # Delete old audit logs
        deleted_audit = session.query(AuditLog).filter(
            AuditLog.timestamp < cutoff_date
        ).delete()
        
        session.commit()
        
        logger.info(f"Cleaned up {deleted_scans} scans, {deleted_api} API logs, {deleted_audit} audit logs")
        
        return {
            'scans_deleted': deleted_scans,
            'api_logs_deleted': deleted_api,
            'audit_logs_deleted': deleted_audit
        }
        
    except Exception as e:
        session.rollback()
        logger.error(f"Cleanup error: {str(e)}")
        return None
    finally:
        session.close()

# ============================================================================
# EXPORT ALL UTILITIES
# ============================================================================

__all__ = [
    # Models
    'Base',
    'User',
    'ScanHistory',
    'URLResult',
    'MLTrainingData',
    'ScheduledScan',
    'Setting',
    'APIUsage',
    'Notification',
    'AuditLog',
    'ScanStatistics',
    
    # Engine and sessions
    'engine',
    'Session',
    'SessionLocal',
    'get_session',
    'get_db_session',
    'get_scoped_session',
    
    # Initialization
    'init_db',
    'DATABASE_URL',
    'DB_PATH',
    
    # Migration
    'migrate_from_v2',
    'check_database_version',
    
    # Utilities
    'get_or_create',
    'bulk_create',
    'vacuum_database',
    'get_database_stats',
    'cleanup_old_data',
]

# ============================================================================
# AUTO-INITIALIZATION
# ============================================================================

# Check and migrate on import if needed
try:
    version = check_database_version()
    if version == '2.2':
        logger.info("Detected v2.2 database, running migration...")
        init_db()  # Create new tables
        migrate_from_v2()  # Migrate old data
except Exception as e:
    logger.warning(f"Could not auto-initialize database: {str(e)}")
    logger.info("Run init_db() manually to initialize the database")