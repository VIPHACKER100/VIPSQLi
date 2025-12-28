import requests
import sys
import re
import argparse
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# -------------------------------------------------------------------------
# CONSTANTS & CONFIGURATION
# -------------------------------------------------------------------------

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

# -------------------------------------------------------------------------
# UTILITY FUNCTIONS
# -------------------------------------------------------------------------

def print_banner():
    print(Fore.CYAN + Style.BRIGHT + """
    =======================================================
          REAL SQLi PEHCHANNE KA 30-SECOND FRAMEWORK
    =======================================================
    """)
    print(Fore.BLUE + "    GitHub: https://GitHub.com/viphacker100/")
    print(Fore.BLUE + "    Website: https://viphacker100.com")
    print()

def log(step, message, status="INFO"):
    if status == "SAFE":
        print(f"{Fore.GREEN}[SAFE] {step}: {message}")
    elif status == "WARN":
        print(f"{Fore.YELLOW}[WARN] {step}: {message}")
    elif status == "CRITICAL":
        print(f"{Fore.RED}[CRITICAL] {step}: {message}")
    else:
        print(f"{Fore.WHITE}[INFO] {step}: {message}")

# -------------------------------------------------------------------------
# CHECK LOGIC
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
    
    # Check impossible paths
    for imp_path in IMPOSSIBLE_PATHS:
        if imp_path in path:
            return False, f"Path is in safe directory: {imp_path}"
            
    # Check possible extensions
    # Note: If no extension or unknown extension, we proceed with caution
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
        # If ONLY low risk params are present, it's likely safe (90% rule)
        # But we don't return False immediately, we just flag it as low risk
        return "LOW", f"Mostly low risk params: {low_risk_found}"
        
    if high_risk_found:
        return "HIGH", f"High risk parameters found: {high_risk_found}"
        
    return "NEUTRAL", f"Parameters found: {list(query_params.keys())}"

def step_three_four_behavior_error(url):
    """Step 3 & 4: Behavior test & Error signature"""
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    
    if not query_params:
        return "SKIP", "No params to fuzz"

    # We need to test each parameter? Or just the high risk ones?
    # For a triage tool, testing high risk ones first involves less noise.
    # But let's test the first available parameter to keep it simple/30-sec style
    # or better, verify the 'id' or similar if exists.
    
    target_params = [p for p in query_params.keys() if p.lower() in HIGH_RISK_PARAMS]
    if not target_params:
        target_params = list(query_params.keys())
        
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'SQLi-Triage-Tool/1.0 (Education Purpose)'
    })

    # Baseline Request
    try:
        baseline = session.get(url, timeout=10)
        log("STEP-3", f"Baseline status: {baseline.status_code}, Len: {len(baseline.text)}")
    except Exception as e:
        return "ERROR", f"Failed to connect: {str(e)}"

    # Check for existing errors in baseline (highly unlikely but possible)
    if check_error_signatures(baseline.text):
        return "CRITICAL", "SQL Error present in baseline request!"

    # Fuzzing Logic
    # We will try to modify one parameter at a time with a large number
    
    real_sqli_candidate = False
    
    for param in target_params:
        original_value = query_params[param][0] # take first value
        
        # Test Case: Large Integer
        fuzzed_params = query_params.copy()
        fuzzed_params[param] = ['99999999'] # Large number
        
        # Reconstruct URL
        new_query = urlencode(fuzzed_params, doseq=True)
        fuzzed_url = urlunparse(parsed._replace(query=new_query))
        
        try:
            resp = session.get(fuzzed_url, timeout=10)
            
            # Step 4 Check: Error Signatures
            errors = check_error_signatures(resp.text)
            if errors:
                log("STEP-4", f"Error signature detected in param '{param}': {errors}", "CRITICAL")
                real_sqli_candidate = True
                continue # Found one, but let's see others? actually returning True is enough
                
            # Step 3 Check: Behavior
            # If same response -> No SQLi
            if resp.status_code == baseline.status_code and abs(len(resp.text) - len(baseline.text)) < 50:
                 log("STEP-3", f"Param '{param}': Same response (Safe)", "SAFE")
            elif resp.history: # Redirect
                log("STEP-3", f"Param '{param}': Redirects (Usually Safe)", "SAFE")
            elif resp.status_code >= 400:
                log("STEP-3", f"Param '{param}': HTTP Error {resp.status_code} (Investigate)", "WARN")
            else:
                 log("STEP-3", f"Param '{param}': Content changed significantly (Check Manually)", "WARN")

        except Exception as e:
             log("STEP-3", f"Error fuzzing param '{param}': {str(e)}", "WARN")

    if real_sqli_candidate:
        return "CRITICAL", "SQL Injection Candidate Found (based on error signatures)"
    
    return "SAFE", "No obvious SQLi behavior detected"

def check_error_signatures(content):
    found = []
    for sig in ERROR_SIGNATURES:
        if sig.lower() in content.lower():
            found.append(sig)
    return found

# -------------------------------------------------------------------------
# MAIN
# -------------------------------------------------------------------------

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(
        description="SQLi Triage Tool based on 30-Second Framework\n\nGitHub: https://GitHub.com/viphacker100/\nWebsite: https://viphacker100.com",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Created by VIPHacker100 | For educational and authorized testing only"
    )
    parser.add_argument("url", nargs='?', help="Target URL to scan")
    parser.add_argument("-l", "--list", help="File containing list of URLs to scan (one per line)")
    parser.add_argument("-e", "--exclude", help="File containing exclusion patterns (one per line)")
    parser.add_argument("-o", "--output", help="Output file for results (default: stdout)")
    args = parser.parse_args()
    
    # Validate arguments
    if not args.url and not args.list:
        parser.error("Either provide a URL or use --list to specify a file")
    
    # Load exclusion patterns
    exclusions = []
    if args.exclude:
        try:
            with open(args.exclude, 'r') as f:
                exclusions = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            print(f"{Fore.CYAN}[INFO] Loaded {len(exclusions)} exclusion patterns\n")
        except FileNotFoundError:
            print(f"{Fore.RED}[ERROR] Exclusion file not found: {args.exclude}")
            sys.exit(1)
    
    # Prepare output file
    output_file = None
    if args.output:
        try:
            output_file = open(args.output, 'w', encoding='utf-8')
            print(f"{Fore.CYAN}[INFO] Results will be saved to: {args.output}\n")
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Cannot open output file: {str(e)}")
            sys.exit(1)
    
    # Process URLs
    urls_to_scan = []
    if args.list:
        try:
            with open(args.list, 'r') as f:
                urls_to_scan = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            print(f"{Fore.CYAN}[INFO] Loaded {len(urls_to_scan)} URLs from list\n")
        except FileNotFoundError:
            print(f"{Fore.RED}[ERROR] URL list file not found: {args.list}")
            sys.exit(1)
    else:
        urls_to_scan = [args.url]
    
    # Scan each URL
    total_urls = len(urls_to_scan)
    sqli_candidates = []
    
    for idx, url in enumerate(urls_to_scan, 1):
        # Check exclusions
        excluded = False
        for pattern in exclusions:
            if pattern in url:
                if args.list:
                    print(f"{Fore.YELLOW}[{idx}/{total_urls}] EXCLUDED: {url}")
                    if output_file:
                        output_file.write(f"EXCLUDED: {url}\n")
                excluded = True
                break
        
        if excluded:
            continue
        
        if args.list:
            print(f"\n{Fore.CYAN}{'='*60}")
            print(f"{Fore.CYAN}[{idx}/{total_urls}] Scanning: {url}")
            print(f"{Fore.CYAN}{'='*60}\n")
        
        verdict = scan_single_url(url, output_file)
        
        if verdict == "CRITICAL":
            sqli_candidates.append(url)
    
    # Summary for batch mode
    if args.list:
        print(f"\n\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}SCAN SUMMARY")
        print(f"{Fore.CYAN}{'='*60}")
        print(f"{Fore.WHITE}Total URLs scanned: {total_urls}")
        print(f"{Fore.RED}SQLi Candidates found: {len(sqli_candidates)}")
        if sqli_candidates:
            print(f"\n{Fore.RED}[!] CRITICAL - SQLi Candidates:")
            for candidate in sqli_candidates:
                print(f"{Fore.RED}  - {candidate}")
        print(f"{Fore.CYAN}{'='*60}\n")
        
        if output_file:
            output_file.write(f"\n\nSUMMARY:\n")
            output_file.write(f"Total URLs: {total_urls}\n")
            output_file.write(f"SQLi Candidates: {len(sqli_candidates)}\n")
            if sqli_candidates:
                output_file.write(f"\nCRITICAL URLs:\n")
                for candidate in sqli_candidates:
                    output_file.write(f"  {candidate}\n")
    
    if output_file:
        output_file.close()
        print(f"{Fore.GREEN}[INFO] Results saved to: {args.output}")

def scan_single_url(url, output_file=None):
    """Scan a single URL and return verdict"""
    def write_output(msg):
        if output_file:
            # Strip color codes for file output
            clean_msg = re.sub(r'\x1b\[[0-9;]*m', '', msg)
            output_file.write(clean_msg + '\n')
    
    
    print(f"Target: {url}\n")
    write_output(f"Target: {url}")
    
    # Rule #0
    should_proceed, msg = rule_zero_static_check(url)
    if not should_proceed:
        log("RULE-0", msg, "SAFE")
        verdict_msg = f"\n{Fore.GREEN}Verdict: SAFE (Static Asset)"
        print(verdict_msg)
        write_output("Verdict: SAFE (Static Asset)")
        return "SAFE"
    else:
        log("RULE-0", msg)

    # Step 1
    should_proceed, msg = step_one_file_type(url)
    if not should_proceed:
        log("STEP-1", msg, "SAFE")
        verdict_msg = f"\n{Fore.GREEN}Verdict: SAFE (Safe Directory/Type)"
        print(verdict_msg)
        write_output("Verdict: SAFE (Safe Directory/Type)")
        return "SAFE"
    else:
        log("STEP-1", msg)

    # Step 2
    risk_level, msg = step_two_param_check(url)
    if risk_level == "LOW":
        log("STEP-2", msg, "SAFE")
    elif risk_level == "HIGH":
        log("STEP-2", msg, "CRITICAL")
    else:
        log("STEP-2", msg)
        
    if risk_level == False: # No params
         verdict_msg = f"\n{Fore.GREEN}Verdict: SAFE (No Parameters)"
         print(verdict_msg)
         write_output("Verdict: SAFE (No Parameters)")
         return "SAFE"

    # Step 3 & 4
    print(f"\n{Fore.CYAN}--- running active tests ---")
    verdict, msg = step_three_four_behavior_error(url)
    
    print("-" * 30)
    
    if verdict == "CRITICAL":
        print(f"\n{Fore.RED}[!] FINAL VERDICT: REAL SQLi CANDIDATE")
        print(f"{Fore.RED}Reason: {msg}")
        write_output(f"FINAL VERDICT: REAL SQLi CANDIDATE - {msg}")
        return "CRITICAL"
    elif verdict == "WARN":
        print(f"\n{Fore.YELLOW}[WARN] FINAL VERDICT: INVESTIGATE")
        print(f"{Fore.YELLOW}Reason: {msg}")
        write_output(f"FINAL VERDICT: INVESTIGATE - {msg}")
        return "WARN"
    else:
        print(f"\n{Fore.GREEN}[OK] FINAL VERDICT: SAFE / FALSE POSITIVE")
        print(f"{Fore.GREEN}Reason: {msg}")
        write_output(f"FINAL VERDICT: SAFE - {msg}")
        return "SAFE"

if __name__ == "__main__":
    main()
