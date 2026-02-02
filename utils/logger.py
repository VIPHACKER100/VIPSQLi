import logging
import sys
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
from pathlib import Path
from typing import Optional
import json
from datetime import datetime

try:
    from rich.logging import RichHandler
    from rich.console import Console
    from rich.theme import Theme
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


class StructuredFormatter(logging.Formatter):
    """JSON formatter for structured logging"""
    
    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        
        # Add exception info if present
        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)
        
        # Add extra fields
        if hasattr(record, 'extra_fields'):
            log_data.update(record.extra_fields)
        
        return json.dumps(log_data)


class ColoredFormatter(logging.Formatter):
    """Colored formatter for terminal output"""
    
    # ANSI color codes
    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[35m',   # Magenta
        'RESET': '\033[0m'        # Reset
    }
    
    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        reset = self.COLORS['RESET']
        
        # Format the message
        formatted = super().format(record)
        
        # Add color
        return f"{color}{formatted}{reset}"


class EnhancedLogger:
    """Enhanced logger with multiple handlers and formatting options"""
    
    def __init__(self, name: str = "vipsqli", config: Optional[dict] = None):
        self.name = name
        self.config = config or {}
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)
        self.logger.handlers.clear()
        self.logger.propagate = False
        
        # Setup handlers
        self._setup_console_handler()
        self._setup_file_handler()
        self._setup_structured_handler()
    
    def _setup_console_handler(self):
        """Setup console handler with appropriate formatting"""
        console_level = self.config.get('console_level', 'INFO')
        
        if RICH_AVAILABLE and self.config.get('use_rich', True):
            # Use Rich handler for beautiful console output
            custom_theme = Theme({
                "logging.level.debug": "cyan",
                "logging.level.info": "green",
                "logging.level.warning": "yellow",
                "logging.level.error": "red bold",
                "logging.level.critical": "red bold reverse",
            })
            
            console = Console(theme=custom_theme)
            handler = RichHandler(
                console=console,
                show_time=self.config.get('show_time', True),
                show_path=self.config.get('show_path', False),
                markup=True,
                rich_tracebacks=True,
                tracebacks_show_locals=True
            )
            handler.setLevel(getattr(logging, console_level.upper()))
            self.logger.addHandler(handler)
        else:
            # Fallback to standard console handler with colors
            handler = logging.StreamHandler(sys.stdout)
            handler.setLevel(getattr(logging, console_level.upper()))
            
            formatter = ColoredFormatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
    
    def _setup_file_handler(self):
        """Setup rotating file handler"""
        log_file = self.config.get('log_file')
        if not log_file:
            return
        
        # Create log directory
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Determine rotation type
        rotation_type = self.config.get('rotation_type', 'size')
        
        if rotation_type == 'time':
            # Time-based rotation (e.g., daily)
            handler = TimedRotatingFileHandler(
                log_file,
                when=self.config.get('rotation_when', 'midnight'),
                interval=self.config.get('rotation_interval', 1),
                backupCount=self.config.get('backup_count', 7),
                encoding='utf-8'
            )
        else:
            # Size-based rotation
            max_bytes = self.config.get('max_bytes', 10 * 1024 * 1024)  # 10 MB
            backup_count = self.config.get('backup_count', 5)
            
            handler = RotatingFileHandler(
                log_file,
                maxBytes=max_bytes,
                backupCount=backup_count,
                encoding='utf-8'
            )
        
        handler.setLevel(logging.DEBUG)
        
        # Use detailed formatter for file logs
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
    
    def _setup_structured_handler(self):
        """Setup structured (JSON) logging handler"""
        structured_file = self.config.get('structured_log_file')
        if not structured_file:
            return
        
        # Create directory
        log_path = Path(structured_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Create handler
        handler = RotatingFileHandler(
            structured_file,
            maxBytes=self.config.get('structured_max_bytes', 50 * 1024 * 1024),  # 50 MB
            backupCount=self.config.get('structured_backup_count', 3),
            encoding='utf-8'
        )
        
        handler.setLevel(logging.DEBUG)
        handler.setFormatter(StructuredFormatter())
        self.logger.addHandler(handler)
    
    def get_logger(self) -> logging.Logger:
        """Get the configured logger instance"""
        return self.logger


def get_logger(name: str = "vipsqli", config: Optional[dict] = None) -> logging.Logger:
    """
    Get or create a logger with enhanced configuration
    
    Args:
        name: Logger name
        config: Optional configuration dict with the following keys:
            - console_level: Console log level (default: INFO)
            - log_file: Path to log file
            - structured_log_file: Path to structured JSON log file
            - use_rich: Use Rich for console output (default: True)
            - show_time: Show timestamp in console (default: True)
            - show_path: Show file path in console (default: False)
            - rotation_type: 'size' or 'time' (default: size)
            - max_bytes: Max log file size in bytes (default: 10MB)
            - backup_count: Number of backup files to keep (default: 5)
            
    Returns:
        Configured logger instance
    """
    # Default configuration
    default_config = {
        'console_level': 'INFO',
        'use_rich': True,
        'show_time': True,
        'show_path': False,
        'rotation_type': 'size',
        'max_bytes': 10 * 1024 * 1024,
        'backup_count': 5
    }
    
    # Merge with provided config
    if config:
        default_config.update(config)
    
    enhanced_logger = EnhancedLogger(name, default_config)
    return enhanced_logger.get_logger()


class ScanLogger:
    """Specialized logger for scan operations with context management"""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.scan_context = {}
    
    def set_scan_id(self, scan_id: str):
        """Set current scan ID for context"""
        self.scan_context['scan_id'] = scan_id
    
    def set_target(self, target: str):
        """Set current target for context"""
        self.scan_context['target'] = target
    
    def log_with_context(self, level: int, message: str, **kwargs):
        """Log message with scan context"""
        extra_fields = {**self.scan_context, **kwargs}
        extra = {'extra_fields': extra_fields}
        self.logger.log(level, message, extra=extra)
    
    def debug(self, message: str, **kwargs):
        self.log_with_context(logging.DEBUG, message, **kwargs)
    
    def info(self, message: str, **kwargs):
        self.log_with_context(logging.INFO, message, **kwargs)
    
    def warning(self, message: str, **kwargs):
        self.log_with_context(logging.WARNING, message, **kwargs)
    
    def error(self, message: str, **kwargs):
        self.log_with_context(logging.ERROR, message, **kwargs)
    
    def critical(self, message: str, **kwargs):
        self.log_with_context(logging.CRITICAL, message, **kwargs)
    
    def log_request(self, url: str, method: str, status_code: int, response_time: float):
        """Log HTTP request with metrics"""
        self.info(
            f"Request: {method} {url} -> {status_code}",
            method=method,
            url=url,
            status_code=status_code,
            response_time=response_time
        )
    
    def log_vulnerability(self, url: str, verdict: str, payload: str):
        """Log vulnerability finding"""
        self.warning(
            f"Vulnerability found: {url}",
            verdict=verdict,
            payload=payload,
            vulnerability_type='sql_injection'
        )
    
    def log_scan_start(self, total_targets: int):
        """Log scan start"""
        self.info(
            f"Starting scan of {total_targets} targets",
            total_targets=total_targets,
            event='scan_start'
        )
    
    def log_scan_complete(self, stats: dict):
        """Log scan completion with stats"""
        self.info(
            f"Scan complete: {stats.get('vulnerable', 0)} vulnerabilities found",
            **stats,
            event='scan_complete'
        )


# Example usage
if __name__ == '__main__':
    # Create logger with custom config
    config = {
        'console_level': 'DEBUG',
        'log_file': '/tmp/sqli_scanner.log',
        'structured_log_file': '/tmp/sqli_scanner.json',
        'use_rich': True,
        'show_time': True,
        'show_path': True
    }
    
    logger = get_logger('test', config)
    scan_logger = ScanLogger(logger)
    
    # Test logging
    scan_logger.set_scan_id('test-001')
    scan_logger.log_scan_start(100)
    scan_logger.log_request('http://example.com', 'GET', 200, 0.5)
    scan_logger.log_vulnerability('http://example.com/page?id=1', 'VULNERABLE', "1' OR '1'='1")
    scan_logger.log_scan_complete({'total': 100, 'vulnerable': 5, 'safe': 95})