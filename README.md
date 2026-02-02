<p align="center">
  <img src="assets/logo.svg" width="200" alt="VIP SQLi Scanner Logo">
</p>

# 🔥 VIP SQLi Scanner - Advanced Edition v2.2

<p align="center">
  <img src="assets/logo.svg" width="150" alt="VIP Logo">
</p>

**REAL SQLi PEHCHANNE KA 30-SECOND FRAMEWORK**

A professional, fast, and safe SQL Injection triage tool that identifies real SQLi vulnerabilities in 30 seconds without exploits or illegal payloads.

---

**🔗 Links:**
- **GitHub**: [https://GitHub.com/viphacker100/](https://GitHub.com/viphacker100/)
- **Website**: [https://viphacker100.com](https://viphacker100.com)

## 🎯 Features

### Rule #0: Static File Detection
Instantly skips static assets with **60+ file extensions**:
- **Stylesheets & Scripts**: `.css`, `.js`, `.min.js`, `.scss`, `.sass`, `.less`
- **Images**: `.png`, `.jpg`, `.gif`, `.webp`, `.svg`, `.heic`
- **Fonts**: `.woff`, `.woff2`, `.ttf`, `.eot`, `.otf`
- **Documents**: `.pdf`, `.doc`, `.docx`, `.xls`, `.xlsx`, `.ppt`
- **Media**: `.mp4`, `.mp3`, `.avi`, `.mov`, `.webm`, `.mkv`
- **Archives**: `.zip`, `.rar`, `.tar`, `.gz`, `.7z`

### Step 1: File Type Analysis
Detects **15+ dangerous extensions** and **25+ safe paths**:
- **High-Risk**: `.php`, `.aspx`, `.jsp`, `.cfm`, `.ashx`, `.asmx`
- **Safe Paths**: `/wp-content/`, `/static/`, `/assets/`, `/node_modules/`

### Step 2: Parameter Risk Assessment
Analyzes **60+ high-risk** and **40+ low-risk** parameters:
- **High-Risk**: `id`, `product_id`, `user_id`, `query`, `search`, `email`, `password`
- **Low-Risk**: `ver`, `utm_*`, `fbclid`, `csrf_token`, `lang`, `width`

### Step 3: Behavior Testing
Safe fuzzing logic:
- Compares baseline vs modified parameter responses
- Detects redirects, errors, and content changes
- No destructive payloads

### Step 4: Error Signature Detection
Scans for **50+ SQL error patterns** across:
- **MySQL/MariaDB**: `mysql_fetch`, `You have an error in your SQL syntax`
- **PostgreSQL**: `pg_query`, `ERROR: syntax error at or near`
- **Oracle**: `ORA-`, `quoted string not properly terminated`
- **MSSQL**: `SQLServer JDBC Driver`, `Incorrect syntax near`
- **SQLite**: `sqlite3.OperationalError`, `System.Data.SQLite`
- **DB2**: `SQLCODE`, `DB2 SQL error`

### Step 5: Premium Branding & Dashboard
Visual excellence for professional delivery:
- **Custom SVG Logo**: Integrated into Dashboard and PDF reports.
- **Real-time Web UI**: Live visualization of scan progress.
- **Graded PDF Reports**: Clean, executive-level documentation.

## 📦 Installation

```bash
# Clone or download the tool
cd VIPSQLi

# Install dependencies (v2.2)
pip install -r requirements-v2.2.txt
```

## 🚀 Usage

### Single URL Scan
```bash
python sqli_scanner_advanced.py -u "http://example.com/product.php?id=1"
```

### Batch Scanning (URL List)
```bash
# Scan multiple URLs from a file
python sqli_scanner_advanced.py -l urls.txt --threads 10

# Scan with exclusion patterns
python sqli_scanner_advanced.py -l urls.txt -e exclusions.txt

# Save results to file
python sqli_scanner_advanced.py -l urls.txt -o results.json
```

### Command-Line Options
- `-l, --list`: File containing URLs to scan (one per line)
- `-e, --exclude`: File containing exclusion patterns (one per line)
- `-o, --output`: Output file for results (default: stdout)
- `-h, --help`: Show help message

---

## ⚡ Advanced Scanner Commands

For high-performance scanning with modern UI, use the **Advanced Edition** (`sqli_scanner_advanced.py`):

### Quick Start (Advanced)
```bash
# Single URL with modern UI
python sqli_scanner_advanced.py "http://example.com/product.php?id=1"

# Fast async scan (5-10x faster)
python sqli_scanner_advanced.py -l urls.txt --async --max-concurrent 20

# Full detection with time-based SQLi
python sqli_scanner_advanced.py -l urls.txt --async --time-based -v
```

### High-Performance Scanning
```bash
# Ultra-fast async (30 concurrent requests)
python sqli_scanner_advanced.py -l urls.txt --async --max-concurrent 30

# Multi-threaded scan
python sqli_scanner_advanced.py -l urls.txt --threads 10

# Maximum speed (50 concurrent)
python sqli_scanner_advanced.py -l urls.txt --async --max-concurrent 50
```

### Professional Pentesting
```bash
# Complete scan with all features
python sqli_scanner_advanced.py \
  -l urls.txt \
  -e exclusions.txt \
  -p payloads.txt \
  --async \
  --max-concurrent 25 \
  --time-based \
  -o results.json \
  --csv results.csv \
  -v

# Quick triage scan
python sqli_scanner_advanced.py -l urls.txt -e exclusions.txt --async --max-concurrent 30

# Stealth scan (low thread count)
python sqli_scanner_advanced.py -l urls.txt --threads 3 --time-based -o results.json
```

### Export & Reporting
```bash
# JSON export
python sqli_scanner_advanced.py -l urls.txt -o scan_results.json

# CSV export
python sqli_scanner_advanced.py -l urls.txt --csv scan_results.csv

# Both JSON & CSV & HTML
python sqli_scanner_advanced.py -l urls.txt -o results.json --csv results.csv --html report.html
```

### Resume & Authenticated Scanning (v2.1)
```bash
# Resume interrupted scan
python sqli_scanner_advanced.py --resume

# Scan with custom headers and proxy
python sqli_scanner_advanced.py -u "http://target.com" --headers headers.json --proxy http://127.0.0.1:8080

# Organize results by domain (Safe/Vuln lists)
python sqli_scanner_advanced.py -l urls.txt --filter
```

### Real-Time Monitoring
```bash
# Verbose mode (see each URL status in real-time)
python sqli_scanner_advanced.py -l urls.txt --async --time-based -v
```
*Shows: ✅ SAFE / 🔴 VULNERABLE for each URL as it's scanned*

### Interactive Mode
```bash
# Guided setup (beginner-friendly)
python sqli_scanner_advanced.py -i
```

**See [README_ADVANCED.md](README_ADVANCED.md) for complete documentation**

---

### Examples

**1. Static File (Instant Skip)**
```bash
python sqli_scanner.py "http://example.com/video.mp4"
```
Output: `Verdict: SAFE (Static Asset)`

**2. Safe Directory**
```bash
python sqli_scanner.py "http://example.com/wp-content/themes/style.css"
```
Output: `Verdict: SAFE (Safe Directory/Type)`

**3. High-Risk Endpoint**
```bash
python sqli_scanner.py "http://example.com/product.php?product_id=123"
```
Output:
- Detects `.php` (High Risk Extension)
- Detects `product_id` (High Risk Parameter)
- Runs active tests
- **Verdict**: SAFE or REAL SQLi CANDIDATE

## 🧠 How It Works

### The 30-Second Framework

1. **Rule #0 (Instant)**: Skip if static file → 0% SQLi chance
2. **Step 1 (5 sec)**: Check file type and path
3. **Step 2 (10 sec)**: Analyze parameter names
4. **Step 3 (10 sec)**: Safe behavior testing
5. **Step 4 (5 sec)**: Error signature scan

### Decision Logic

| Check | Result | Action |
|-------|--------|--------|
| Static file | ✅ | Skip (0% SQLi) |
| Safe path | ✅ | Skip |
| Low-risk params only | ✅ | Skip |
| Same response | ✅ | Safe |
| SQL error detected | 🚨 | **REAL SQLi** |
| Content changed | ⚠️ | Investigate |

## 🎓 Pentester's Golden Line

> "If the application safely redirects or ignores malformed input without error disclosure, SQL Injection is not present."

## ⚠️ Legal Notice

This tool is for **educational and authorized security testing only**. Always obtain proper authorization before testing any system you don't own.

## 📊 Detection Coverage

- **60+** static file extensions
- **15+** dangerous file extensions
- **25+** safe directory paths
- **60+** high-risk parameters
- **40+** low-risk parameters
- **50+** SQL error signatures

## 🛠️ Requirements

- Python 3.6+
- `requests`
- `colorama`

## 📝 License

Educational use only. Use responsibly.

---

**Version**: 2.2 (Advanced Edition)  
**Status**: Production Ready  
**Quality**: Enterprise Grade (Cyberpunk Edition)  

---

**EST 2026 . viphacker100**
