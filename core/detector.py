import re
from typing import Tuple, List, Dict

SQL_ERROR_PATTERNS = [
    r"SQL syntax", r"mysql_fetch", r"mysql_query", r"mysql_num_rows",
    r"Warning: mysql_", r"mysqli_", r"You have an error in your SQL syntax",
    r"supplied argument is not a valid MySQL",
    r"Call to a member function fetch_assoc\(\) on boolean",
    r"Syntax error or access violation",
    r"PostgreSQL query failed", r"pg_query", r"pg_exec", r"pg_fetch",
    r"unterminated quoted string", r"ERROR: syntax error at or near",
    r"ORA-\d*", r"Oracle error", r"Oracle ODBC", r"Oracle Driver",
    r"quoted string not properly terminated",
    r"Microsoft OLE DB Provider for SQL Server",
    r"SQLServer JDBC Driver", r"System\.Data\.SqlClient\.SqlException",
    r"Unclosed quotation mark after the character string",
    r"Incorrect syntax near", r"\[Microsoft\]\[ODBC SQL Server Driver\]",
    r"\[SQL Server\]", r"ADODB\.Field error",
    r"SQLite/JDBCDriver", r"SQLite\.Exception", r"System\.Data\.SQLite\.SQLiteException",
    r"sqlite3\.OperationalError", r'near ":": syntax error',
    r"DB2 SQL error", r"SQLCODE", r"DB2 ODBC", r"CLI Driver",
    r"ODBC", r"ODBC Driver", r"ODBC Error",
    r"PDOException", r"SQLSTATE",
    r"Unclosed quotation", r"syntax error", r"invalid query",
    r"unexpected end of SQL command", r"unterminated string",
    r"SQL command not properly ended",
    r"Microsoft JET Database Engine", r"ADODB\.Command",
    r"ASP\.NET_SessionId", r"System\.Data\.OleDb\.OleDbException"
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

class SQLiDetector:
    def __init__(self, config=None):
        self.config = config or {}
        # Pre-compile patterns for performance
        self.patterns = [re.compile(p, re.I) for p in SQL_ERROR_PATTERNS]
    
    def detect_error_based(self, text: str) -> Tuple[bool, List[str]]:
        """Check for SQL error messages in text"""
        found_errors = []
        for pattern in self.patterns:
            if pattern.search(text):
                found_errors.append(pattern.pattern)
        return len(found_errors) > 0, list(set(found_errors))
    
    def detect_waf(self, headers: Dict, text: str) -> Tuple[bool, str]:
        """Identify WAF presence"""
        # Check headers first
        for waf_name, signatures in WAF_SIGNATURES.items():
            for sig in signatures:
                # Check keys and values in headers
                for k, v in headers.items():
                    if sig.lower() in k.lower() or sig.lower() in str(v).lower():
                        return True, waf_name
        
        # Check body
        for waf_name, signatures in WAF_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in text.lower():
                    return True, waf_name
                    
        return False, None

    def detect_time_based(self, elapsed: float, expected_delay: float = 5.0) -> bool:
        """Simple threshold-based check for time-based SQLi"""
        return elapsed >= expected_delay
