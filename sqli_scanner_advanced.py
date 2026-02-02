#!/usr/bin/env python3
"""
VIP SQLi Scanner - Advanced Edition v2.1
Professional SQL Injection Triage Tool with Modern UI
Enhanced with Async Scanning, WAF Detection, HTML Reports, Resume, and Proxy Support
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
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Set
import logging

# Rich library imports
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

# Template engine
try:
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    JINJA_AVAILABLE = True
except ImportError:
    JINJA_AVAILABLE = False

console = Console()

# -------------------------------------------------------------------------
# CONSTANTS & CONFIGURATION
# -------------------------------------------------------------------------

VERSION = "2.1"
GITHUB_URL = "https://GitHub.com/viphacker100/"
WEBSITE_URL = "https://viphacker100.com"

# ... (Previous constants remain unchanged)
STATIC_EXTENSIONS = (
    # Stylesheets & Scripts
    '.css', '.js', '.min.js', '.map', '.scss', '.sass', '.less',
    # Images
    '.png', '.jpg', '.jpeg', '.gif', '.ico', '.webp', '.avif', 
    '.bmp', '.tiff', '.svg', '.heic', '.heif',
    # Fonts
    '.woff', '.woff2', '.ttf', '.eot', '.otf',
    # Documents
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    # Media
    '.mp4', '.mp3', '.avi', '.mov', '.wmv', '.flv', '.webm', '.mkv',
    '.wav', '.ogg', '.m4a', '.aac',
    # Archives
    '.zip', '.rar', '.tar', '.gz', '.7z',
    # Other
    '.xml', '.json', '.txt', '.csv', '.md', '.yaml', '.yml'
)

POSSIBLE_SQLI_EXTENSIONS = (
    '.php', '.php3', '.php4', '.php5', '.phtml',
    '.asp', '.aspx', '.ashx', '.asmx', '.axd',
    '.jsp', '.jspx', '.jsf', '.do', '.action',
    '.cfm', '.cfml', '.cfc',
    '.pl', '.cgi',
    '.dll', '.py', '.rb', '.lua'
)

IMPOSSIBLE_PATHS = (
    '/wp-content/', '/wp-includes/', '/wp-admin/css/', '/wp-admin/js/',
    '/assets/', '/static/', '/public/', '/resources/',
    '/fonts/', '/css/', '/js/', '/javascript/', '/styles/',
    '/images/', '/img/', '/pics/', '/pictures/', '/media/',
    '/lib/', '/libs/', '/vendor/', '/node_modules/', '/bower_components/',
    '/dist/', '/build/', '/cache/', '/temp/', '/tmp/',
    '/uploads/', '/files/', '/downloads/',
    '/theme/', '/themes/', '/templates/', '/skins/',
    '/docs/', '/documentation/', '/manual/'
)

HIGH_RISK_PARAMS = {
    'id', 'uid', 'user_id', 'userid', 'pid', 'product_id', 'productid',
    'cat', 'catid', 'category', 'category_id', 'cid', 'course_id',
    'volume_id', 'order_id', 'orderid', 'item_id', 'itemid',
    'user', 'username', 'uname', 'login', 'email', 'password', 'pass',
    'role', 'admin', 'auth', 'account',
    'page', 'p', 'view', 'detail', 'show', 'display', 'content',
    'article', 'post', 'news', 'blog',
    'query', 'q', 'search', 's', 'keyword', 'keywords', 'find',
    'action', 'act', 'do', 'cmd', 'command', 'method', 'function',
    'file', 'filename', 'path', 'dir', 'directory', 'folder',
    'doc', 'document', 'download',
    'sort', 'order', 'orderby', 'sortby', 'filter', 'group', 'groupby',
    'ref', 'reference', 'refid', 'type', 'mode', 'status'
}

LOW_RISK_PARAMS = {
    'ver', 'v', 'version', 'cache', 'nocache', 'random',
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

ERROR_SIGNATURES = [
    "SQL syntax", "mysql_fetch", "mysql_query", "mysql_num_rows",
    "Warning: mysql_", "mysqli_", "You have an error in your SQL syntax",
    "supplied argument is not a valid MySQL",
    "Call to a member function fetch_assoc() on boolean",
    "Syntax error or access violation",
    "PostgreSQL query failed", "pg_query", "pg_exec", "pg_fetch",
    "unterminated quoted string", "ERROR: syntax error at or near",
    "ORA-", "Oracle error", "Oracle ODBC", "Oracle Driver",
    "quoted string not properly terminated",
    "Microsoft OLE DB Provider for SQL Server",
    "SQLServer JDBC Driver", "System.Data.SqlClient.SqlException",
    "Unclosed quotation mark after the character string",
    "Incorrect syntax near", "[Microsoft][ODBC SQL Server Driver]",
    "[SQL Server]", "ADODB.Field error",
    "SQLite/JDBCDriver", "SQLite.Exception", "System.Data.SQLite.SQLiteException",
    "sqlite3.OperationalError", 'near ":": syntax error',
    "DB2 SQL error", "SQLCODE", "DB2 ODBC", "CLI Driver",
    "ODBC", "ODBC Driver", "ODBC Error",
    "PDOException", "SQLSTATE",
    "Unclosed quotation", "syntax error", "invalid query",
    "unexpected end of SQL command", "unterminated string",
    "SQL command not properly ended",
    "Microsoft JET Database Engine", "ADODB.Command",
    "ASP.NET_SessionId", "System.Data.OleDb.OleDbException"
]

WAF_SIGNATURES = {
    'Cloudflare': ['cf-ray', 'cloudflare', '__cfduid', 'cf-cache-status'],
    'AWS WAF': ['x-amzn-requestid', 'x-amz-cf-id', 'awselb'],
    'Akamai': ['akamai', 'ak-bmsc', 'x-akamai'],
    'Imperva': ['incap_ses', 'visid_incap', 'imperva'],
    'ModSecurity': ['mod_security', 'NOYB'],
    'Sucuri': ['x-sucuri-id', 'sucuri'],
    'Wordfence': ['wordfence'],
    'F5 BIG-IP': ['bigipserver', 'f5'],
}

DB_FINGERPRINTS = {
    'MySQL': ['mysql', 'mariadb', 'you have an error in your sql syntax'],
    'PostgreSQL': ['postgresql', 'pg_query', 'unterminated quoted string'],
    'MSSQL': ['microsoft sql', 'sql server', 'system.data.sqlclient'],
    'Oracle': ['ora-', 'oracle', 'pl/sql'],
    'SQLite': ['sqlite', 'sqlite3.operationalerror'],
}

# CVSS & Remediation Constants
CVSS_SCORES = {
    'CRITICAL': 9.8,  # AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    'HIGH': 7.5,      # AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L (Example)
    'MEDIUM': 5.3,
    'LOW': 0.0
}

REMEDIATION_GUIDE = {
    'error-based': """
    1. **Disable Verbose Errors**: Configure your web server and database to suppress detailed error messages to the client.
    2. **Use Prepared Statements**: Replace dynamic SQL queries with parameterized queries (e.g., PDO in PHP, PreparedStatement in Java).
    3. **Input Validation**: Strictly validate and sanitize all user inputs against a whitelist of allowed characters.
    """,
    'time-based': """
    1. **Parameterization**: Ensure all database interactions use bound parameters to prevent command injection.
    2. **WAF Configuration**: specific WAF rules to block sleep/benchmark SQL keywords.
    3. **Code Review**: Audit code for string concatenation in SQL queries.
    """,
    'general': """
    1. **Least Privilege**: Ensure the database user has only the minimum necessary permissions.
    2. **Regular Patching**: Keep database management systems updated to the latest stable versions.
    3. **Web Application Firewall**: Deploy a WAF to filter malicious SQL patterns.
    """
}

PAYLOAD_CATEGORIES = {
    'time_based': [],
    'error_based': [],
    'union_based': [],
    'boolean_based': [],
    'stacked_queries': [],
}

class ScanStats:
    def __init__(self):
        self.total = 0
        self.scanned = 0
        self.vulnerable = 0
        self.safe = 0
        self.excluded = 0
        self.errors = 0
        self.waf_detected = 0
        self.start_time = time.time()
        self.db_types_detected = {}
        self.concurrency = 0
        
    def elapsed(self):
        return time.time() - self.start_time
    
    def requests_per_second(self):
        elapsed = self.elapsed()
        return self.scanned / elapsed if elapsed > 0 else 0
        
    def to_dict(self):
        return {
            'total': self.total,
            'scanned': self.scanned,
            'vulnerable': self.vulnerable,
            'safe': self.safe,
            'excluded': self.excluded,
            'errors': self.errors,
            'waf_detected': self.waf_detected,
            'db_types_detected': self.db_types_detected,
            'elapsed': self.elapsed()
        }
        
    def from_dict(self, data):
        self.total = data.get('total', 0)
        self.scanned = data.get('scanned', 0)
        self.vulnerable = data.get('vulnerable', 0)
        self.safe = data.get('safe', 0)
        self.excluded = data.get('excluded', 0)
        self.errors = data.get('errors', 0)
        self.waf_detected = data.get('waf_detected', 0)
        self.db_types_detected = data.get('db_types_detected', {})
        # Note: start_time isn't fully restorable to continue elapsed count perfectly,
        # but we can adjust it based on previous elapsed time
        previous_elapsed = data.get('elapsed', 0)
        self.start_time = time.time() - previous_elapsed

stats = ScanStats()

# -------------------------------------------------------------------------
# STATE MANAGEMENT (RESUME)
# -------------------------------------------------------------------------

STATE_FILE = ".scan_state.json"

def save_state(processed_urls: Set[str], results: List[Dict]):
    """Save current scan state"""
    state = {
        'timestamp': datetime.now().isoformat(),
        'processed_urls': list(processed_urls),
        'results': results,
        'stats': stats.to_dict()
    }
    try:
        with open(STATE_FILE, 'w') as f:
            json.dump(state, f)
    except Exception as e:
        console.print(f"[red]Error saving state: {e}[/red]")

def load_state() -> Tuple[Set[str], List[Dict]]:
    """Load previous scan state"""
    if not os.path.exists(STATE_FILE):
        return set(), []
    
    try:
        with open(STATE_FILE, 'r') as f:
            state = json.load(f)
            
        console.print(f"[cyan]ℹ[/cyan] Resuming scan from {state['timestamp']}")
        console.print(f"  • Previously scanned: {len(state['processed_urls'])} URLs")
        console.print(f"  • Previous findings: {len(state['results'])} entries")
        
        stats.from_dict(state.get('stats', {}))
        return set(state['processed_urls']), state['results']
    except Exception as e:
        console.print(f"[red]Error loading state: {e}[/red]")
        return set(), []

# -------------------------------------------------------------------------
# PROXY & HEADERS
# -------------------------------------------------------------------------

class RequestManager:
    """Manage proxies and custom headers"""
    def __init__(self, proxy_list: List[str] = None, headers: Dict = None):
        self.proxies = proxy_list or []
        self.headers = headers or {}
        
    def get_proxy(self) -> Optional[str]:
        if not self.proxies:
            return None
        return random.choice(self.proxies)
        
    def get_headers(self) -> Dict:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        headers.update(self.headers)
        return headers

# -------------------------------------------------------------------------
# PAYLOAD LOADING
# -------------------------------------------------------------------------

def load_payloads_from_file(filepath: str = "payloads.txt") -> Dict[str, List[str]]:
    """Load and categorize payloads from payloads.txt"""
    payloads = {
        'time_based': [],
        'error_based': [],
        'union_based': [],
        'boolean_based': [],
        'stacked_queries': [],
        'other': []
    }
    
    if not Path(filepath).exists():
        console.print(f"[yellow]⚠[/yellow] Payload file not found: {filepath}, using defaults")
        # Fallback to default payloads
        payloads['time_based'] = [
            "' AND SLEEP(5)--",
            "' OR SLEEP(5)--",
            "1' AND SLEEP(5)--",
            "; WAITFOR DELAY '0:0:5'--",
            "'; WAITFOR DELAY '0:0:5'--",
            "' AND pg_sleep(5)--"
        ]
        payloads['error_based'] = [
            "' OR 1=1--",
            "' AND 1=1--",
            "' UNION SELECT NULL--",
            "' AND extractvalue(1,concat(0x7e,version()))--"
        ]
        return payloads
    
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            current_category = 'other'
            
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    if 'TIME-BASED' in line.upper():
                        current_category = 'time_based'
                    elif 'ERROR-BASED' in line.upper():
                        current_category = 'error_based'
                    elif 'UNION' in line.upper():
                        current_category = 'union_based'
                    elif 'BOOLEAN' in line.upper():
                        current_category = 'boolean_based'
                    elif 'STACKED' in line.upper():
                        current_category = 'stacked_queries'
                    continue
                
                if line not in payloads[current_category]:
                    payloads[current_category].append(line)
        
        total = sum(len(v) for v in payloads.values())
        console.print(f"[green]✓[/green] Loaded {total} payloads from {filepath}")
        return payloads
        
    except Exception as e:
        console.print(f"[red]✗[/red] Error loading payloads: {str(e)}")
        return payloads

# -------------------------------------------------------------------------
# MODERN UI FUNCTIONS
# -------------------------------------------------------------------------

def print_banner():
    """Display modern banner with Rich"""
    banner_content = Text()
    banner_content.append("VIP SQLi Scanner", style="bold cyan")
    banner_content.append(" - ", style="white")
    banner_content.append(f"Advanced Edition v{VERSION}", style="bold magenta")
    banner_content.append("\n")
    banner_content.append("Professional SQL Injection Triage Tool", style="italic yellow")
    banner_content.append("\n\n")
    banner_content.append("✨ New Features: ", style="bold green")
    banner_content.append("HTML Reports | Resume Capability | Proxy Support | Custom Headers", style="dim")
    banner_content.append("\n\n")
    banner_content.append("GitHub: ", style="dim")
    banner_content.append(GITHUB_URL, style="bold blue underline")
    banner_content.append("\n")
    banner_content.append("Website: ", style="dim")
    banner_content.append(WEBSITE_URL, style="bold blue underline")
    
    panel = Panel(
        banner_content,
        box=box.DOUBLE,
        border_style="cyan",
        padding=(1, 2)
    )
    console.print(panel)
    console.print()

def create_stats_panel():
    """Create live stats panel"""
    elapsed = int(stats.elapsed())
    rps = stats.requests_per_second()
    
    stats_table = Table(show_header=False, box=None, padding=(0, 2))
    stats_table.add_column(style="cyan")
    stats_table.add_column(style="bold white")
    
    stats_table.add_row("Total URLs:", str(stats.total))
    stats_table.add_row("Scanned:", f"[green]{stats.scanned}[/green]")
    stats_table.add_row("Vulnerable:", f"[red]{stats.vulnerable}[/red]")
    stats_table.add_row("Safe:", f"[green]{stats.safe}[/green]")
    stats_table.add_row("Excluded:", f"[yellow]{stats.excluded}[/yellow]")
    stats_table.add_row("Errors:", f"[red]{stats.errors}[/red]")
    stats_table.add_row("WAF Detected:", f"[yellow]{stats.waf_detected}[/yellow]")
    stats_table.add_row("Elapsed:", f"{elapsed}s")
    stats_table.add_row("Speed:", f"{rps:.2f} req/s")
    
    return Panel(stats_table, title="[bold cyan]Scan Statistics[/bold cyan]", border_style="cyan")

def display_result_table(results):
    """Display results in a beautiful table"""
    table = Table(title="Scan Results", box=box.ROUNDED, show_lines=True)
    
    table.add_column("URL", style="cyan", no_wrap=False)
    table.add_column("Status", justify="center")
    table.add_column("Risk", justify="center")
    table.add_column("Details", style="dim")
    
    for result in results:
        url = result['url']
        verdict = result['verdict']
        risk = result.get('risk', 'N/A')
        details = result.get('details', '')
        
        if verdict == "CRITICAL":
            status_style = "[bold red]VULNERABLE[/bold red]"
            risk_style = f"[bold red]{risk}[/bold red]"
        elif verdict == "WARN":
            status_style = "[yellow]INVESTIGATE[/yellow]"
            risk_style = f"[yellow]{risk}[/yellow]"
        else:
            status_style = "[green]SAFE[/green]"
            risk_style = f"[green]{risk}[/green]"
        
        table.add_row(url, status_style, risk_style, details)
    
    console.print(table)

# -------------------------------------------------------------------------
# DETECTION LOGIC
# -------------------------------------------------------------------------

def detect_waf(url: str, headers: dict, content: str) -> Optional[str]:
    """Detect Web Application Firewall"""
    detected_waf = None
    for waf_name, signatures in WAF_SIGNATURES.items():
        for sig in signatures:
            for header_name, header_value in headers.items():
                if sig.lower() in header_name.lower() or sig.lower() in str(header_value).lower():
                    detected_waf = waf_name
                    break
            if sig.lower() in content.lower():
                detected_waf = waf_name
                break
        if detected_waf: break
    return detected_waf

def fingerprint_database(content: str, errors: List[str]) -> Optional[str]:
    """Fingerprint database type from error messages"""
    content_lower = content.lower()
    errors_lower = ' '.join(errors).lower()
    combined = content_lower + ' ' + errors_lower
    for db_type, signatures in DB_FINGERPRINTS.items():
        for sig in signatures:
            if sig.lower() in combined:
                return db_type
    return None

def rule_zero_static_check(url):
    """Rule #0: Static file != SQLi"""
    parsed = urlparse(url)
    path = parsed.path.lower()
    if path.endswith(STATIC_EXTENSIONS):
        return False, f"Static file extension detected ({path.split('.')[-1]})"
    return True, "Passed"

def step_one_file_type(url):
    """Step 1: File type check"""
    parsed = urlparse(url)
    path = parsed.path.lower()
    for imp_path in IMPOSSIBLE_PATHS:
        if imp_path in path:
            return False, f"Path is in safe directory: {imp_path}"
    if path.endswith(POSSIBLE_SQLI_EXTENSIONS):
        return True, f"High risk extension detected ({path.split('.')[-1]})"
    return True, "Standard endpoint (proceeding)"

def step_two_param_check(url):
    """Step 2: Parameter name check"""
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    if not query_params:
        return False, "No parameters found in URL"
        
    high_risk_found = []
    low_risk_found = []
    
    for param in query_params.keys():
        param_lower = param.lower()
        if param_lower in HIGH_RISK_PARAMS:
            high_risk_found.append(param)
        elif param_lower in LOW_RISK_PARAMS or param_lower.startswith('utm_'):
            low_risk_found.append(param)
            
    if low_risk_found and not high_risk_found:
        return "LOW", f"Mostly low risk params: {low_risk_found}"
    if high_risk_found:
        return "HIGH", f"High risk parameters found: {high_risk_found}"
    return "NEUTRAL", f"Parameters found: {list(query_params.keys())}"

def check_error_signatures(content):
    """Check for SQL error signatures"""
    found = []
    for sig in ERROR_SIGNATURES:
        if sig.lower() in content.lower():
            found.append(sig)
    return found

def test_time_based_sqli(url, session, timeout=10, payloads=None, req_manager=None):
    """Test for time-based blind SQLi"""
    if payloads is None:
        payloads = PAYLOAD_CATEGORIES.get('time_based', [])[:3]
    
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    if not query_params:
        return False, []
    
    vulnerable_params = []
    for param in query_params.keys():
        if param.lower() not in HIGH_RISK_PARAMS:
            continue
            
        for payload in payloads:
            fuzzed_params = query_params.copy()
            fuzzed_params[param] = [payload]
            new_query = urlencode(fuzzed_params, doseq=True)
            fuzzed_url = urlunparse(parsed._replace(query=new_query))
            
            try:
                proxies = {'http': req_manager.get_proxy(), 'https': req_manager.get_proxy()} if req_manager else None
                start = time.time()
                resp = session.get(fuzzed_url, timeout=timeout, proxies=proxies)
                elapsed = time.time() - start
                
                if elapsed >= 4:
                    vulnerable_params.append({
                        'param': param,
                        'payload': payload,
                        'delay': f"{elapsed:.2f}s"
                    })
                    return True, vulnerable_params
            except:
                pass
    return False, vulnerable_params

def step_three_four_behavior_error(url, enable_time_based=False, payloads=None, req_manager=None):
    """Step 3 & 4: Behavior test & Error signature"""
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    if not query_params:
        return "SKIP", "No params to fuzz", {}
    
    target_params = [p for p in query_params.keys() if p.lower() in HIGH_RISK_PARAMS]
    if not target_params:
        target_params = list(query_params.keys())
        
    session = requests.Session()
    # Apply custom headers
    if req_manager:
        session.headers.update(req_manager.get_headers())
    else:
        session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})

    try:
        proxies = {'http': req_manager.get_proxy(), 'https': req_manager.get_proxy()} if req_manager else None
        baseline = session.get(url, timeout=10, proxies=proxies)
    except Exception as e:
        return "ERROR", f"Failed to connect: {str(e)}", {}

    # WAF & Error Detection in Baseline
    waf_detected = detect_waf(url, baseline.headers, baseline.text)
    if waf_detected:
        stats.waf_detected += 1

    baseline_errors = check_error_signatures(baseline.text)
    if baseline_errors:
        db_type = fingerprint_database(baseline.text, baseline_errors)
        result_details = {'type': 'error-based', 'errors': baseline_errors}
        if db_type:
            result_details['database'] = db_type
            stats.db_types_detected[db_type] = stats.db_types_detected.get(db_type, 0) + 1
        if waf_detected:
            result_details['waf'] = waf_detected
        return "CRITICAL", "SQL Error present in baseline request!", result_details

    # Time-based blind SQLi test
    if enable_time_based:
        is_vuln, time_results = test_time_based_sqli(url, session, payloads=payloads, req_manager=req_manager)
        if is_vuln:
            result_details = {'type': 'time-based', 'results': time_results}
            if waf_detected:
                result_details['waf'] = waf_detected
            return "CRITICAL", f"Time-based blind SQLi detected", result_details

    # Standard fuzzing
    real_sqli_candidate = False
    error_details = {}
    
    for param in target_params:
        fuzzed_params = query_params.copy()
        fuzzed_params[param] = ['99999999']
        new_query = urlencode(fuzzed_params, doseq=True)
        fuzzed_url = urlunparse(parsed._replace(query=new_query))
        
        try:
            proxies = {'http': req_manager.get_proxy(), 'https': req_manager.get_proxy()} if req_manager else None
            resp = session.get(fuzzed_url, timeout=10, proxies=proxies)
            errors = check_error_signatures(resp.text)
            if errors:
                real_sqli_candidate = True
                db_type = fingerprint_database(resp.text, errors)
                error_details = {'type': 'error-based', 'param': param, 'errors': errors}
                if db_type:
                    error_details['database'] = db_type
                    stats.db_types_detected[db_type] = stats.db_types_detected.get(db_type, 0) + 1
                if waf_detected:
                    error_details['waf'] = waf_detected
                break
        except:
            pass

    if real_sqli_candidate:
        return "CRITICAL", "SQL Injection Candidate Found (error signatures)", error_details
    
    return "SAFE", "No obvious SQLi behavior detected", {}

# -------------------------------------------------------------------------
# ASYNC SCANNING
# -------------------------------------------------------------------------

async def async_scan_single_url(session: aiohttp.ClientSession, url: str, 
                                enable_time_based: bool = False, 
                                payloads: Dict = None,
                                semaphore: asyncio.Semaphore = None,
                                req_manager: RequestManager = None) -> Dict:
    if semaphore:
        async with semaphore:
            return await _async_scan_url_impl(session, url, enable_time_based, payloads, req_manager)
    else:
        return await _async_scan_url_impl(session, url, enable_time_based, payloads, req_manager)

async def _async_scan_url_impl(session: aiohttp.ClientSession, url: str,
                                enable_time_based: bool, payloads: Dict, 
                                req_manager: RequestManager = None) -> Dict:
    # Use thread pool to run synchronous detection logic (reusing implementation)
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, scan_single_url, url, enable_time_based, False, payloads, req_manager)
    return result

async def scan_urls_async(urls, exclusions=[], max_concurrent=20, enable_time_based=False,
                          payloads=None, verbose=False, req_manager=None, resume_state=None):
    results = resume_state[1] if resume_state else []
    processed_urls = resume_state[0] if resume_state else set()
    
    urls_to_scan = []
    for url in urls:
        if url in processed_urls: continue
        excluded = False
        for pattern in exclusions:
            if pattern in url:
                stats.excluded += 1
                excluded = True
                break
        if not excluded:
            urls_to_scan.append(url)
    
    semaphore = asyncio.Semaphore(max_concurrent)
    connector = aiohttp.TCPConnector(limit=max_concurrent)
    timeout = aiohttp.ClientTimeout(total=30)
    
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        tasks = []
        for url in urls_to_scan:
            tasks.append(async_scan_single_url(session, url, enable_time_based, payloads, semaphore, req_manager))
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Scanning URLs (Async)...", total=len(tasks))
            
            # Process in chunks to save state periodically
            chunk_size = 50
            completed_count = 0
            
            for i in range(0, len(tasks), chunk_size):
                chunk = tasks[i:i + chunk_size]
                if not chunk: break
                
                for coro in asyncio.as_completed(chunk):
                    try:
                        result = await coro
                        results.append(result)
                        processed_urls.add(result['url'])
                        stats.scanned += 1
                    except Exception as e:
                        stats.errors += 1
                        console.print(f"[red]Error:[/red] {str(e)}")
                    progress.advance(task)
                    completed_count += 1
                
                # Auto-save state
                save_state(processed_urls, results)
    
    return results

# -------------------------------------------------------------------------
# THREADED SCANNING
# -------------------------------------------------------------------------

def scan_single_url(url, enable_time_based=False, verbose=False, payloads=None, req_manager=None):
    result = {
        'url': url,
        'verdict': 'SAFE',
        'risk': 'Low',
        'details': '',
        'timestamp': datetime.now().isoformat()
    }
    
    should_proceed, msg = rule_zero_static_check(url)
    if not should_proceed:
        result['details'] = msg
        stats.safe += 1
        return result
    
    should_proceed, msg = step_one_file_type(url)
    if not should_proceed:
        result['details'] = msg
        stats.safe += 1
        return result
    
    risk_level, msg = step_two_param_check(url)
    if risk_level == False:
        result['details'] = "No parameters"
        stats.safe += 1
        return result
    
    verdict, msg, details = step_three_four_behavior_error(url, enable_time_based, payloads, req_manager)
    
    result['verdict'] = verdict
    result['details'] = msg
    
    # Calculate Risk & CVSS
    if verdict == "CRITICAL":
        result['risk'] = 'Critical'
        result['cvss_score'] = CVSS_SCORES['CRITICAL']
        result['cvss_vector'] = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        stats.vulnerable += 1
        
        # Determine specific remediation
        vuln_type = 'general'
        if details and 'type' in details:
            vuln_type = details['type']
        elif details and isinstance(details, dict) and 'errors' in details:
             vuln_type = 'error-based'
        
        result['remediation'] = REMEDIATION_GUIDE.get(vuln_type, REMEDIATION_GUIDE['general'])
        
        if details:
            result['vuln_details'] = details
            
    elif verdict == "WARN":
        result['risk'] = 'Medium'
        result['cvss_score'] = CVSS_SCORES['MEDIUM']
        result['cvss_vector'] = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
        result['remediation'] = REMEDIATION_GUIDE['general']
        stats.safe += 1
    elif verdict == "ERROR":
        result['risk'] = 'Error'
        result['cvss_score'] = 0.0
        stats.errors += 1
    else:
        result['risk'] = 'Low'
        result['cvss_score'] = CVSS_SCORES['LOW']
        stats.safe += 1
    
    return result

def scan_urls_threaded(urls, exclusions=[], max_workers=5, enable_time_based=False, 
                       verbose=False, payloads=None, req_manager=None, resume_state=None):
    results = resume_state[1] if resume_state else []
    processed_urls = resume_state[0] if resume_state else set()
    
    urls_to_scan = [u for u in urls if u not in processed_urls]
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Scanning URLs...", total=len(urls_to_scan))
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_url = {}
            for url in urls_to_scan:
                excluded = False
                for pattern in exclusions:
                    if pattern in url:
                        stats.excluded += 1
                        excluded = True
                        break
                
                if not excluded:
                    future = executor.submit(scan_single_url, url, enable_time_based, verbose, payloads, req_manager)
                    future_to_url[future] = url
                else:
                    processed_urls.add(url) # Excluded counts as processed
                    progress.advance(task)
            
            completed_count = 0
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    result = future.result()
                    results.append(result)
                    processed_urls.add(url)
                    stats.scanned += 1
                except Exception as e:
                    results.append({'url': url, 'verdict': 'ERROR', 'risk': 'Error', 'details': str(e)})
                    stats.errors += 1
                    processed_urls.add(url)
                
                progress.advance(task)
                completed_count += 1
                
                if completed_count % 50 == 0:
                    save_state(processed_urls, results)
        
        save_state(processed_urls, results)
    
    return results

# -------------------------------------------------------------------------
# EXPORT
# -------------------------------------------------------------------------

def export_json(results, filename):
    output = {
        'scan_info': {
            'version': VERSION,
            'timestamp': datetime.now().isoformat(),
            'total_urls': stats.total,
            'scanned': stats.scanned,
            'vulnerable': stats.vulnerable,
            'safe': stats.safe,
            'excluded': stats.excluded,
            'errors': stats.errors,
            'waf_detected': stats.waf_detected,
            'elapsed_seconds': int(stats.elapsed()),
            'requests_per_second': round(stats.requests_per_second(), 2),
            'databases_detected': stats.db_types_detected,
            'concurrency': stats.concurrency
        },
        'results': results
    }
    with open(filename, 'w') as f:
        json.dump(output, f, indent=2)
    console.print(f"[green]✓[/green] JSON report saved: {filename}")

def export_csv(results, filename):
    import csv
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['url', 'verdict', 'risk', 'details'])
        writer.writeheader()
        for result in results:
            writer.writerow({
                'url': result['url'],
                'verdict': result['verdict'],
                'risk': result['risk'],
                'details': result['details']
            })
    console.print(f"[green]✓[/green] CSV report saved: {filename}")

def export_html(results, filename):
    if not JINJA_AVAILABLE:
        console.print("[yellow]⚠ Jinja2 not installed. Skipping HTML report.[/yellow]")
        console.print("Run: pip install jinja2")
        return

    try:
        env = Environment(
            loader=FileSystemLoader("templates"),
            autoescape=select_autoescape(['html', 'xml'])
        )
        template = env.get_template("report_template.html")
        
        scan_info = {
            'version': VERSION,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'total_urls': stats.total,
            'scanned': stats.scanned,
            'vulnerable': stats.vulnerable,
            'safe': stats.safe,
            'excluded': stats.excluded,
            'errors': stats.errors,
            'waf_detected': stats.waf_detected,
            'elapsed_seconds': int(stats.elapsed()),
            'requests_per_second': round(stats.requests_per_second(), 2),
            'databases_detected': stats.db_types_detected,
            'concurrency': stats.concurrency
        }
        
        html_content = template.render(results=results, scan_info=scan_info)
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
            
        console.print(f"[green]✓[/green] HTML report saved: {filename}")
        
    except Exception as e:
        console.print(f"[red]✗[/red] Error generating HTML report: {e}")

# -------------------------------------------------------------------------
# MAIN
# -------------------------------------------------------------------------

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(
        description=f"VIP SQLi Scanner - Advanced Edition v{VERSION}",
        epilog="Created by VIPHacker100"
    )
    parser.add_argument("url_pos", nargs='?', help="Target URL to scan")
    parser.add_argument("-u", "--url", help="Target URL (alternative to positional)")
    parser.add_argument("-l", "--list", help="File containing list of URLs")
    parser.add_argument("-e", "--exclude", help="File containing exclusion patterns")
    parser.add_argument("-p", "--payloads", default="payloads.txt", help="Payload file")
    
    # Export options
    parser.add_argument("-o", "--output", help="Output JSON file")
    parser.add_argument("--csv", help="Export to CSV file")
    parser.add_argument("--html", help="Export to HTML report")
    
    # Performance & Config
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of threads")
    parser.add_argument("--async", dest="use_async", action="store_true", help="Use async scanning")
    parser.add_argument("--max-concurrent", type=int, default=20, help="Max requests (async)")
    parser.add_argument("--time-based", action="store_true", help="Enable time-based SQLi")
    
    # Advanced Options
    parser.add_argument("--resume", action="store_true", help="Resume previous scan")
    parser.add_argument("--proxy", help="Single proxy (http://ip:port)")
    parser.add_argument("--proxy-list", help="File containing list of proxies")
    parser.add_argument("--headers", help="JSON file with custom headers")
    parser.add_argument("--filter", action="store_true", help="Organize results into domain folders")
    
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-i", "--interactive", action="store_true", help="Interactive mode")
    
    args = parser.parse_args()
    
    # Interactive mode
    if args.interactive:
        console.print("[cyan]Interactive Mode[/cyan]\n")
        args.list = Prompt.ask("URL list file (or press Enter to skip)")
        if not args.list:
            args.url = Prompt.ask("Enter single URL")
        args.threads = int(Prompt.ask("Number of threads", default="5"))
        args.use_async = Confirm.ask("Use async scanning?", default=False)
        args.html = Prompt.ask("HTML Report Filename (optional)")
    
    # Resolve URL from positional or flag
    target_url = args.url or args.url_pos
    
    if not target_url and not args.list:
        parser.error("Either provide a URL (positional or -u) or use --list to specify a file")
    
    # --- Load Configuration ---
    
    # Payloads
    payloads = load_payloads_from_file(args.payloads)
    global PAYLOAD_CATEGORIES
    PAYLOAD_CATEGORIES = payloads
    
    # Exclusions
    exclusions = []
    if args.exclude:
        try:
            with open(args.exclude, 'r', encoding='utf-8', errors='ignore') as f:
                exclusions = [line.strip() for line in f if line.strip() and not '/#' in line]
            console.print(f"[cyan]ℹ[/cyan] Loaded {len(exclusions)} exclusion patterns")
        except FileNotFoundError:
            console.print(f"[red]✗[/red] Exclusion file not found: {args.exclude}")
            sys.exit(1)
            
    # URLs
    urls_to_scan = []
    if args.list:
        try:
            with open(args.list, 'r', encoding='utf-8', errors='ignore') as f:
                urls_to_scan = [line.strip() for line in f if line.strip()]
            console.print(f"[cyan]ℹ[/cyan] Loaded {len(urls_to_scan)} URLs from list")
        except FileNotFoundError:
            console.print(f"[red]✗[/red] URL list file not found: {args.list}")
            sys.exit(1)
    else:
        urls_to_scan = [target_url]
        
    stats.total = len(urls_to_scan)
    stats.concurrency = args.max_concurrent if args.use_async else args.threads
    
    # Proxies
    proxy_list = []
    if args.proxy_list:
        try:
            with open(args.proxy_list, 'r', encoding='utf-8', errors='ignore') as f:
                proxy_list = [line.strip() for line in f if line.strip()]
            console.print(f"[cyan]ℹ[/cyan] Loaded {len(proxy_list)} proxies")
        except:
            console.print(f"[red]✗[/red] Proxy list not found")
            sys.exit(1)
    elif args.proxy:
        proxy_list = [args.proxy]
        
    # Custom Headers
    custom_headers = {}
    if args.headers:
        try:
            with open(args.headers, 'r', encoding='utf-8', errors='ignore') as f:
                custom_headers = json.load(f)
            console.print(f"[cyan]ℹ[/cyan] Loaded custom headers")
        except:
            console.print(f"[red]✗[/red] Failed to load headers file")
            sys.exit(1)

    req_manager = RequestManager(proxy_list, custom_headers)

    # Resume State
    resume_state = None
    if args.resume:
        resume_state = load_state()
        
    # --- Execute Scan ---
    
    console.print(f"\n[bold cyan]Starting scan...[/bold cyan]\n")
    
    try:
        if args.use_async:
            results = asyncio.run(scan_urls_async(
                urls_to_scan, exclusions, args.max_concurrent, 
                args.time_based, payloads, args.verbose, req_manager, resume_state
            ))
        else:
            results = scan_urls_threaded(
                urls_to_scan, exclusions, args.threads, 
                args.time_based, args.verbose, payloads, req_manager, resume_state
            )
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠ Scan interrupted by user. State saved.[/yellow]")
        sys.exit(0)
        
    # --- Output ---
    
    console.print()
    console.print(create_stats_panel())
    console.print()
    
    if stats.db_types_detected:
        console.print("[bold cyan]Database Types Detected:[/bold cyan]")
        for db_type, count in stats.db_types_detected.items():
            console.print(f"  • {db_type}: {count}")
    
    # Auto-export filtered results
    if args.filter:
        save_filtered_results(results)
        
    # Standard Exports
    if args.output:
        export_json(results, args.output)
    if args.csv:
        export_csv(results, args.csv)
    if args.html:
        export_html(results, args.html)

    # Auto-export separate file (VIP formatting)
    if results and len(urls_to_scan) > 0:
        try:
            target = urls_to_scan[0]
            parsed = urlparse(target)
            sitename = parsed.netloc or "target"
            sitename = sitename.replace(":", "_")
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Determine overall status for filename
            scan_verdict = "VULNERABLE" if stats.vulnerable > 0 else "SAFE"
            vip_filename = f"{scan_verdict}_{sitename}_{timestamp}_vip.csv"
            
            export_csv(results, vip_filename)
        except Exception as e:
            console.print(f"[red]Error saving auto-report: {e}[/red]")
        
    console.print()
    if stats.vulnerable > 0:
        console.print(f"[bold red]⚠ Found {stats.vulnerable} potential SQLi vulnerabilities![/bold red]")
    else:
        console.print(f"[bold green]✓ No SQLi vulnerabilities detected[/bold green]")
        
    # Clean up state file on successful completion
    if os.path.exists(STATE_FILE) and not args.resume:
        try:
            os.remove(STATE_FILE)
        except:
            pass

if __name__ == "__main__":
    main()
