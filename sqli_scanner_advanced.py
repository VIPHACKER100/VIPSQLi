#!/usr/bin/env python3
"""
VIP SQLi Scanner - Advanced Edition v2.0
Professional SQL Injection Triage Tool with Modern UI
Enhanced with Async Scanning, WAF Detection, and Advanced Features
"""

import requests
import sys
import re
import os
import argparse
import time
import json
import asyncio
import aiohttp
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

console = Console()

# -------------------------------------------------------------------------
# CONSTANTS & CONFIGURATION
# -------------------------------------------------------------------------

VERSION = "2.0"
GITHUB_URL = "https://GitHub.com/viphacker100/"
WEBSITE_URL = "https://viphacker100.com"

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

# WAF signatures
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

# Database fingerprints
DB_FINGERPRINTS = {
    'MySQL': ['mysql', 'mariadb', 'you have an error in your sql syntax'],
    'PostgreSQL': ['postgresql', 'pg_query', 'unterminated quoted string'],
    'MSSQL': ['microsoft sql', 'sql server', 'system.data.sqlclient'],
    'Oracle': ['ora-', 'oracle', 'pl/sql'],
    'SQLite': ['sqlite', 'sqlite3.operationalerror'],
}

# Payload categories
PAYLOAD_CATEGORIES = {
    'time_based': [],
    'error_based': [],
    'union_based': [],
    'boolean_based': [],
    'stacked_queries': [],
}

# Stats tracker
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
        
    def elapsed(self):
        return time.time() - self.start_time
    
    def requests_per_second(self):
        elapsed = self.elapsed()
        return self.scanned / elapsed if elapsed > 0 else 0

stats = ScanStats()

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
        with open(filepath, 'r', encoding='utf-8') as f:
            current_category = 'other'
            
            for line in f:
                line = line.strip()
                
                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    # Check for category headers
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
                
                # Add payload to current category
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
    banner_content.append("Async Scanning | WAF Detection | DB Fingerprinting | HTML Reports", style="dim")
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
# WAF DETECTION
# -------------------------------------------------------------------------

def detect_waf(url: str, headers: dict, content: str) -> Optional[str]:
    """Detect Web Application Firewall"""
    detected_waf = None
    
    # Check headers
    for waf_name, signatures in WAF_SIGNATURES.items():
        for sig in signatures:
            # Check in headers
            for header_name, header_value in headers.items():
                if sig.lower() in header_name.lower() or sig.lower() in str(header_value).lower():
                    detected_waf = waf_name
                    break
            
            # Check in content
            if sig.lower() in content.lower():
                detected_waf = waf_name
                break
                
        if detected_waf:
            break
    
    return detected_waf

# -------------------------------------------------------------------------
# DATABASE FINGERPRINTING
# -------------------------------------------------------------------------

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

# -------------------------------------------------------------------------
# DETECTION FUNCTIONS
# -------------------------------------------------------------------------

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

def test_time_based_sqli(url, session, timeout=10, payloads=None):
    """Test for time-based blind SQLi"""
    if payloads is None:
        payloads = PAYLOAD_CATEGORIES.get('time_based', [])[:3]  # Use first 3
    
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
                start = time.time()
                resp = session.get(fuzzed_url, timeout=timeout)
                elapsed = time.time() - start
                
                # If response took >= 4 seconds, likely vulnerable
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

def step_three_four_behavior_error(url, enable_time_based=False, payloads=None):
    """Step 3 & 4: Behavior test & Error signature"""
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    
    if not query_params:
        return "SKIP", "No params to fuzz", {}
    
    target_params = [p for p in query_params.keys() if p.lower() in HIGH_RISK_PARAMS]
    if not target_params:
        target_params = list(query_params.keys())
        
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    })

    # Baseline Request
    try:
        baseline = session.get(url, timeout=10)
    except Exception as e:
        return "ERROR", f"Failed to connect: {str(e)}", {}

    # WAF Detection
    waf_detected = detect_waf(url, baseline.headers, baseline.text)
    if waf_detected:
        stats.waf_detected += 1

    # Check for existing errors in baseline
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
        is_vuln, time_results = test_time_based_sqli(url, session, payloads=payloads)
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
            resp = session.get(fuzzed_url, timeout=10)
            
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
# ASYNC SCANNING FUNCTIONS
# -------------------------------------------------------------------------

async def async_scan_single_url(session: aiohttp.ClientSession, url: str, 
                                enable_time_based: bool = False, 
                                payloads: Dict = None,
                                semaphore: asyncio.Semaphore = None) -> Dict:
    """Async scan a single URL"""
    if semaphore:
        async with semaphore:
            return await _async_scan_url_impl(session, url, enable_time_based, payloads)
    else:
        return await _async_scan_url_impl(session, url, enable_time_based, payloads)

async def _async_scan_url_impl(session: aiohttp.ClientSession, url: str,
                                enable_time_based: bool, payloads: Dict) -> Dict:
    """Implementation of async URL scanning"""
    result = {
        'url': url,
        'verdict': 'SAFE',
        'risk': 'Low',
        'details': '',
        'timestamp': datetime.now().isoformat()
    }
    
    # Rule #0
    should_proceed, msg = rule_zero_static_check(url)
    if not should_proceed:
        result['details'] = msg
        stats.safe += 1
        return result
    
    # Step 1
    should_proceed, msg = step_one_file_type(url)
    if not should_proceed:
        result['details'] = msg
        stats.safe += 1
        return result
    
    # Step 2
    risk_level, msg = step_two_param_check(url)
    if risk_level == False:
        result['details'] = "No parameters"
        stats.safe += 1
        return result
    
    # For async, we use synchronous requests for actual testing
    # (aiohttp doesn't support precise timing for time-based SQLi)
    verdict, msg, details = step_three_four_behavior_error(url, enable_time_based, payloads)
    
    result['verdict'] = verdict
    result['details'] = msg
    
    if verdict == "CRITICAL":
        result['risk'] = 'Critical'
        stats.vulnerable += 1
        if details:
            result['vuln_details'] = details
    elif verdict == "WARN":
        result['risk'] = 'Medium'
        stats.safe += 1
    elif verdict == "ERROR":
        result['risk'] = 'Error'
        stats.errors += 1
    else:
        result['risk'] = 'Low'
        stats.safe += 1
    
    stats.scanned += 1
    return result

async def scan_urls_async(urls: List[str], exclusions: List[str] = [], 
                          max_concurrent: int = 20, enable_time_based: bool = False,
                          payloads: Dict = None, verbose: bool = False) -> List[Dict]:
    """Scan multiple URLs asynchronously with live stats"""
    results = []
    semaphore = asyncio.Semaphore(max_concurrent)
    
    # Filter excluded URLs
    urls_to_scan = []
    for url in urls:
        excluded = False
        for pattern in exclusions:
            if pattern in url:
                stats.excluded += 1
                excluded = True
                break
        if not excluded:
            urls_to_scan.append(url)
    
    connector = aiohttp.TCPConnector(limit=max_concurrent, limit_per_host=10)
    timeout = aiohttp.ClientTimeout(total=30)
    
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        tasks = [
            async_scan_single_url(session, url, enable_time_based, payloads, semaphore)
            for url in urls_to_scan
        ]
        
        # Use progress bar with live stats in verbose mode
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Scanning URLs (Async)...", total=len(tasks))
            
            for coro in asyncio.as_completed(tasks):
                try:
                    result = await coro
                    results.append(result)
                    
                    # Show current URL being processed if verbose
                    if verbose:
                        status = "🔴 VULNERABLE" if result['verdict'] == 'CRITICAL' else "✅ SAFE"
                        console.print(f"{status} | {result['url'][:80]}")
                        
                except Exception as e:
                    stats.errors += 1
                    if verbose:
                        console.print(f"[red]Error:[/red] {str(e)}")
                
                progress.advance(task)
    
    return results

# -------------------------------------------------------------------------
# SCANNING LOGIC (THREADED - ORIGINAL)
# -------------------------------------------------------------------------

def scan_single_url(url, enable_time_based=False, verbose=False, payloads=None):
    """Scan a single URL and return result (synchronous)"""
    result = {
        'url': url,
        'verdict': 'SAFE',
        'risk': 'Low',
        'details': '',
        'timestamp': datetime.now().isoformat()
    }
    
    # Rule #0
    should_proceed, msg = rule_zero_static_check(url)
    if not should_proceed:
        result['details'] = msg
        stats.safe += 1
        return result
    
    # Step 1
    should_proceed, msg = step_one_file_type(url)
    if not should_proceed:
        result['details'] = msg
        stats.safe += 1
        return result
    
    # Step 2
    risk_level, msg = step_two_param_check(url)
    if risk_level == False:
        result['details'] = "No parameters"
        stats.safe += 1
        return result
    
    # Step 3 & 4
    verdict, msg, details = step_three_four_behavior_error(url, enable_time_based, payloads)
    
    result['verdict'] = verdict
    result['details'] = msg
    
    if verdict == "CRITICAL":
        result['risk'] = 'Critical'
        stats.vulnerable += 1
        if details:
            result['vuln_details'] = details
    elif verdict == "WARN":
        result['risk'] = 'Medium'
        stats.safe += 1
    elif verdict == "ERROR":
        result['risk'] = 'Error'
        stats.errors += 1
    else:
        result['risk'] = 'Low'
        stats.safe += 1
    
    stats.scanned += 1
    return result

def scan_urls_threaded(urls, exclusions=[], max_workers=5, enable_time_based=False, 
                       verbose=False, payloads=None):
    """Scan multiple URLs with threading and verbose output"""
    results = []
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console
    ) as progress:
        
        task = progress.add_task("[cyan]Scanning URLs...", total=len(urls))
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_url = {}
            
            for url in urls:
                # Check exclusions
                excluded = False
                for pattern in exclusions:
                    if pattern in url:
                        stats.excluded += 1
                        excluded = True
                        break
                
                if not excluded:
                    future = executor.submit(scan_single_url, url, enable_time_based, verbose, payloads)
                    future_to_url[future] = url
                else:
                    progress.advance(task)
            
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    result = future.result()
                    results.append(result)
                    
                    # Show current URL being processed if verbose
                    if verbose:
                        status = "🔴 VULNERABLE" if result['verdict'] == 'CRITICAL' else "✅ SAFE"
                        console.print(f"{status} | {result['url'][:80]}")
                        
                except Exception as e:
                    results.append({
                        'url': url,
                        'verdict': 'ERROR',
                        'risk': 'Error',
                        'details': str(e)
                    })
                    stats.errors += 1
                    if verbose:
                        console.print(f"[red]Error:[/red] {str(e)}")
                
                progress.advance(task)
    
    return results

# -------------------------------------------------------------------------
# EXPORT FUNCTIONS
# -------------------------------------------------------------------------

def export_json(results, filename):
    """Export results to JSON"""
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
            'databases_detected': stats.db_types_detected
        },
        'results': results
    }
    
    with open(filename, 'w') as f:
        json.dump(output, f, indent=2)
    
    console.print(f"[green]✓[/green] JSON report saved: {filename}")

def export_csv(results, filename):
    """Export results to CSV"""
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

def organize_by_domain(results, verbose=False):
    """Organize results into domain-specific folders"""
    console.print("\n[bold cyan]Organizing results by domain...[/bold cyan]")
    
    domain_stats = {}
    
    for result in results:
        url = result['url']
        verdict = result['verdict']
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.split(':')[0]  # Remove port if present
            
            # Sanitize domain for folder name
            safe_domain = "".join(x for x in domain if x.isalnum() or x in "._-")
            
            if not safe_domain:
                continue
                
            # Create directory
            if not os.path.exists(safe_domain):
                os.makedirs(safe_domain)
            
            # Determine filename based on verdict
            if verdict in ["CRITICAL", "WARN"]:
                filename = os.path.join(safe_domain, "vulnurl.txt")
                status_type = "vulnerable"
            else:
                filename = os.path.join(safe_domain, "safeurl.txt")
                status_type = "safe"
                
            # Append URL to file
            with open(filename, 'a') as f:
                f.write(url + '\n')
            
            # Track stats
            if safe_domain not in domain_stats:
                domain_stats[safe_domain] = {'safe': 0, 'vulnerable': 0}
            domain_stats[safe_domain][status_type] += 1
            
        except Exception as e:
            if verbose:
                console.print(f"[red]Error organizing URL {url}: {str(e)}[/red]")
    
    # Print summary
    for domain, counts in domain_stats.items():
        console.print(f"  • [bold]{domain}[/bold]: {counts['safe']} safe, {counts['vulnerable']} vulnerable")
    
    console.print(f"[green]✓[/green] Output organized into {len(domain_stats)} domain folders")

# -------------------------------------------------------------------------
# MAIN
# -------------------------------------------------------------------------

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(
        description=f"VIP SQLi Scanner - Advanced Edition v{VERSION}\n\nGitHub: {GITHUB_URL}\nWebsite: {WEBSITE_URL}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Created by VIPHacker100 | For educational and authorized testing only"
    )
    parser.add_argument("url", nargs='?', help="Target URL to scan")
    parser.add_argument("-l", "--list", help="File containing list of URLs")
    parser.add_argument("-e", "--exclude", help="File containing exclusion patterns")
    parser.add_argument("-p", "--payloads", default="payloads.txt", help="Payload file (default: payloads.txt)")
    parser.add_argument("-o", "--output", help="Output file (JSON format)")
    parser.add_argument("--csv", help="Export to CSV file")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of threads (default: 5)")
    parser.add_argument("--async", dest="use_async", action="store_true", help="Use async scanning (faster)")
    parser.add_argument("--max-concurrent", type=int, default=20, help="Max concurrent requests for async mode (default: 20)")
    parser.add_argument("--time-based", action="store_true", help="Enable time-based blind SQLi detection")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-i", "--interactive", action="store_true", help="Interactive mode")

    parser.add_argument("--filter", action="store_true", help="Organize results into domain folders (safeurl.txt/vulnurl.txt)")
    
    args = parser.parse_args()
    
    # Interactive mode
    if args.interactive:
        console.print("[cyan]Interactive Mode[/cyan]\n")
        args.list = Prompt.ask("URL list file (or press Enter to skip)")
        if not args.list:
            args.url = Prompt.ask("Enter single URL")
        args.threads = int(Prompt.ask("Number of threads", default="5"))
        args.use_async = Confirm.ask("Use async scanning?", default=False)
        args.time_based = Confirm.ask("Enable time-based detection?", default=False)
        args.filter = Confirm.ask("Organize results by domain?", default=False)
    
    # Validate arguments
    if not args.url and not args.list:
        parser.error("Either provide a URL or use --list to specify a file")
    
    # Load payloads
    payloads = load_payloads_from_file(args.payloads)
    global PAYLOAD_CATEGORIES
    PAYLOAD_CATEGORIES = payloads
    
    # Load exclusions
    exclusions = []
    if args.exclude:
        try:
            with open(args.exclude, 'r') as f:
                exclusions = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            console.print(f"[cyan]ℹ[/cyan] Loaded {len(exclusions)} exclusion patterns\n")
        except FileNotFoundError:
            console.print(f"[red]✗[/red] Exclusion file not found: {args.exclude}")
            sys.exit(1)
    
    # Load URLs
    urls_to_scan = []
    if args.list:
        try:
            with open(args.list, 'r') as f:
                urls_to_scan = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            console.print(f"[cyan]ℹ[/cyan] Loaded {len(urls_to_scan)} URLs from list\n")
        except FileNotFoundError:
            console.print(f"[red]✗[/red] URL list file not found: {args.list}")
            sys.exit(1)
    else:
        urls_to_scan = [args.url]
    
    stats.total = len(urls_to_scan)
    
    # Scan URLs
    if args.use_async:
        console.print(f"[bold cyan]Starting async scan with {args.max_concurrent} concurrent requests...[/bold cyan]\n")
        results = asyncio.run(scan_urls_async(
            urls_to_scan,
            exclusions=exclusions,
            max_concurrent=args.max_concurrent,
            enable_time_based=args.time_based,
            payloads=payloads,
            verbose=args.verbose
        ))
    else:
        console.print(f"[bold cyan]Starting scan with {args.threads} threads...[/bold cyan]\n")
        results = scan_urls_threaded(
            urls_to_scan,
            exclusions=exclusions,
            max_workers=args.threads,
            enable_time_based=args.time_based,
            verbose=args.verbose,
            payloads=payloads
        )
    
    # Display stats
    console.print()
    console.print(create_stats_panel())
    console.print()
    
    # Display database types detected
    if stats.db_types_detected:
        console.print("[bold cyan]Database Types Detected:[/bold cyan]")
        for db_type, count in stats.db_types_detected.items():
            console.print(f"  • {db_type}: {count}")
        console.print()
    
    # Display results
    if results:
        display_result_table(results)
    
    # Export results
    if args.output:
        export_json(results, args.output)
    
    if args.csv:
        export_csv(results, args.csv)

    # Organize by domain if requested
    if args.filter:
        organize_by_domain(results, args.verbose)
    
    # Summary
    console.print()
    if stats.vulnerable > 0:
        console.print(f"[bold red]⚠ Found {stats.vulnerable} potential SQLi vulnerabilities![/bold red]")
    else:
        console.print(f"[bold green]✓ No SQLi vulnerabilities detected[/bold green]")

if __name__ == "__main__":
    main()
