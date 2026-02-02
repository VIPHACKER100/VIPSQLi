# 🔥 VIP SQLi Scanner - Advanced Edition v2.2

<p align="center">
  <img src="assets/logo.svg" width="200" alt="VIP SQLi Scanner Logo">
</p>

**Professional SQL Injection Triage Tool with Modern UI**

A next-generation SQLi detection tool featuring beautiful terminal UI, multi-threading, advanced detection methods, and enterprise-grade reporting.

---

**🔗 Links:**
- **GitHub**: [https://GitHub.com/viphacker100/](https://GitHub.com/viphacker100/)
- **Website**: [https://viphacker100.com](https://viphacker100.com)

---

## ✨ What's New in Advanced Edition

### 🎨 Modern UI with Rich Library
- **Beautiful Bordered Panels** - Professional banner and stats display
- **Progress Bars** - Real-time scanning progress with spinners
- **Color-Coded Tables** - Easy-to-read results with risk indicators
- **Live Statistics** - Real-time scan metrics that update during scanning
- **Verbose Mode** - See each URL status as it's scanned (✅ SAFE / 🔴 VULNERABLE)

### ⚡ Performance & Scalability
- **Async Scanning** - Ultra-fast async mode with configurable concurrency
- **Multi-Threading** - Scan multiple URLs in parallel (configurable workers)
- **Smart Rate Limiting** - Avoid detection with controlled request rates
- **Connection Pooling** - Efficient HTTP session management

### 🔍 Advanced Detection
- **Time-Based Blind SQLi** - Detects blind SQL injection via response delays
- **Enhanced Error Detection** - 50+ SQL error signatures across all major databases
- **Response Analysis** - Content diff and behavior comparison
- **WAF Detection** - Identifies Web Application Firewalls
- **Database Fingerprinting** - Detects MySQL, PostgreSQL, Oracle, MSSQL, SQLite

### 📊 Professional Reporting
- **JSON Export** - Detailed machine-readable results
- **CSV Export** - Spreadsheet-compatible format
- **Risk Scoring** - Critical/Medium/Low/Error classification
- **CVSS 3.1 Scoring** - Automated vulnerability scoring (e.g., 9.8 Critical)
- **Remediation Advice** - Context-aware fixes for developers
- **Stats Dashboard** - Comprehensive scan metrics with live updates

### 🎯 User Experience
- **Interactive Mode** - Guided setup with prompts
- **Verbose Mode** - Detailed logging for debugging with real-time URL status
- **Exclusion Patterns** - Skip unwanted URLs automatically
- **Dynamic Payload Loading** - Load custom payloads from file

## 🚀 New in Version 2.1

### 📄 Professional HTML Reporting
- **Bootstrap 5 Dashboard** - Beautiful, responsive reports
- **Executive Summary** - Charts and key metrics
- **Detailed Findings** - Code blocks with vulnerability details

### 💾 Scan Resilience
- **Resume Capability** - Auto-save state and resume interrupted scans
- **State Management** - Never lose progress on large scans

### 🛡️ Operational Security
- **Proxy Support** - Rotate proxies or use a single upstream proxy (Burp/Zap)
- **Custom Headers** - Inject Authentication tokens/cookies for authenticated scanning

## 🚀 New in Version 2.2

### 🧠 ML-Powered Detection
- **Random Forest Engine** - Reduces false positives by analyzing 20+ features.
- **Hybrid Scanning** - Combines traditional signatures with ML predictions.
- **Training Mode** - Train custom models on your own scan data.

### 🔌 Plugin Architecture
- **Extensible System** - Easily add new detection logic via Python plugins.
- **Built-in Plugins**:
  - **GraphQL**: Introspection and Injection checks.
  - **NoSQL**: MongoDB operator injection detection.

### 📈 Real-Time Web Dashboard
- **Live Visualization** - Flask + Socket.IO dashboard.
- **Interactive Charts** - Visual breakdown of vulnerabilities.
- **Live Logs** - Watch scan progress in real-time from your browser.

---

## 📦 Installation

```bash
cd VIPSQLi
pip install -r requirements.txt
```

**Dependencies:**
- `requests` - HTTP client
- `colorama` - Color support
- `rich` - Modern terminal UI
- `jinja2` - HTML reporting engine

---

## 🚀 Usage

### Quick Start

**Single URL Scan:**
```bash
python sqli_scanner_advanced.py "http://example.com/product.php?id=1"
```

**Batch Scan with Modern UI:**
```bash
python sqli_scanner_advanced.py -l urls.txt --threads 5
```

**Fast Async Scan (Recommended):**
```bash
python sqli_scanner_advanced.py -l urls.txt --async --max-concurrent 20
```

---

### ⚡ High-Performance Commands

**Ultra-Fast Async Scan:**
```bash
python sqli_scanner_advanced.py -l urls.txt --async --max-concurrent 30
```

**Multi-Threaded Scan:**
```bash
python sqli_scanner_advanced.py -l urls.txt --threads 10
```

**Maximum Speed (50 concurrent):**
```bash
python sqli_scanner_advanced.py -l urls.txt --async --max-concurrent 50
```

**Custom Payloads + Async:**
```bash
python sqli_scanner_advanced.py -l urls.txt --async -p custom_payloads.txt
```

python sqli_scanner_advanced.py -l urls.txt --async -p custom_payloads.txt
```

**Authenticated Scan (Custom Headers):**
```bash
python sqli_scanner_advanced.py -l urls.txt --headers headers.json
```

**Proxy Scan (Burp Suite/Zap):**
```bash
python sqli_scanner_advanced.py -l urls.txt --proxy http://127.0.0.1:8080
```

**Resume Interrupted Scan:**
```bash
python sqli_scanner_advanced.py --resume --html final_report.html
```

---

### 🔍 Advanced Detection Commands

**Time-Based Blind SQLi Detection:**
```bash
python sqli_scanner_advanced.py -l urls.txt --time-based
```

**Full Detection Suite:**
```bash
python sqli_scanner_advanced.py -l urls.txt --async --time-based --max-concurrent 20
```

**Verbose Mode (Real-Time URL Status):**
```bash
python sqli_scanner_advanced.py -l urls.txt --async --time-based -v
```
*Shows: ✅ SAFE / 🔴 VULNERABLE for each URL in real-time*

**Deep Analysis with Verbose:**
```bash
python sqli_scanner_advanced.py -l urls.txt --threads 10 --time-based -v
```

---

### 📊 Export & Reporting Commands

**JSON Export:**
```bash
python sqli_scanner_advanced.py -l urls.txt -o scan_results.json
```

**HTML Report (New):**
```bash
python sqli_scanner_advanced.py -l urls.txt --html scan_report.html
```

**CSV Export:**
```bash
python sqli_scanner_advanced.py -l urls.txt --csv scan_results.csv
```

**Both JSON & CSV:**
```bash
python sqli_scanner_advanced.py -l urls.txt -o results.json --csv results.csv
```

**Complete Scan with All Reports:**
```bash
python sqli_scanner_advanced.py -l urls.txt --async --time-based -o results.json --csv results.csv -v
```

---

### 📂 Domain Organization (Filter System)

**Organize Results by Domain:**
```bash
python sqli_scanner_advanced.py -l urls.txt --async --filter
```

**Full Scan with Filtering:**
```bash
python sqli_scanner_advanced.py -l urls.txt --async --time-based --filter -v
```
python sqli_scanner_advanced.py -l urls.txt --async --time-based --filter -v
```
*Creates `domains/` folder with subfolders for each site containing `safeurl.txt`, `vulnurl.txt`, and `report.json`*

---

### 🎯 Professional Pentesting Commands

**Full-Featured Professional Scan:**
```bash
python sqli_scanner_advanced.py \
  -l urls.txt \
  -e exclusions.txt \
  -p payloads.txt \
  --async \
  --max-concurrent 25 \
  --time-based \
  -o scan_results.json \
  --csv scan_results.csv \
  -v
```

**Quick Triage Scan:**
```bash
python sqli_scanner_advanced.py -l urls.txt -e exclusions.txt --async --max-concurrent 30
```

**Stealth Scan (Low Thread Count):**
```bash
python sqli_scanner_advanced.py -l urls.txt --threads 3 --time-based -o results.json
```

**WAF-Aware Deep Scan:**
```bash
python sqli_scanner_advanced.py -l urls.txt --async --time-based -v -o waf_scan.json
```

---

### 🎨 Interactive Mode

**Guided Setup (Beginner-Friendly):**
```bash
python sqli_scanner_advanced.py -i
```

The tool will prompt you for:
- URL list file or single URL
- Number of threads
- Enable async scanning (yes/no)
- Enable time-based detection (yes/no)
- Enable ML detection (yes/no) (v2.2)
- Launch Dashboard (yes/no) (v2.2)

### 🧠 ML & Dashboard Commands (v2.2)

**Enable ML Detection:**
```bash
python sqli_scanner_advanced.py -l urls.txt --ml
```

**Launch Web Dashboard:**
```bash
python sqli_scanner_advanced.py --dashboard
```

**Train ML Model:**
```bash
python sqli_scanner_advanced.py --train
```

**Scan Profiles:**
```bash
# Aggressive (Fast, Noisy)
python sqli_scanner_advanced.py -l urls.txt --profile aggressive

# Stealth (Slow, Quiet)
python sqli_scanner_advanced.py -l urls.txt --profile stealth
```

---

### Command-Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `url` | Single URL to scan | - |
| `-l, --list` | File containing URLs (one per line) | - |
| `-e, --exclude` | File containing exclusion patterns | - |
| `-p, --payloads` | Payload file | `payloads.txt` |
| `-o, --output` | JSON output file | - |
| `--csv` | CSV output file | - |
| `-t, --threads` | Number of threads | `5` |
| `--async` | Enable async scanning (faster) | `False` |
| `--max-concurrent` | Max concurrent requests for async | `20` |
| `--time-based` | Enable time-based blind SQLi detection | `False` |
| `-v, --verbose` | Verbose output with real-time URL status | `False` |
| `-i, --interactive` | Interactive mode with prompts | `False` |
| `--html` | HTML report filename | - |
| `--resume` | Resume previous scan | `False` |
| `--proxy` | Single proxy URL | - |
| `--headers` | Custom headers JSON file | - |
| `--filter` | Organize results into domain folders (safeurl.txt/vulnurl.txt) | `False` |
| `--ml` | Enable ML-based detection (v2.2) | `False` |
| `--dashboard` | Launch Web Dashboard (v2.2) | `False` |
| `--train` | Train ML Model (v2.2) | `False` |
| `--profile` | Scan Profile (aggressive, balanced, stealth) | `balanced` |

---

### 💡 Pro Tips

1. **For Speed**: Use `--async` with `--max-concurrent 20-30`
2. **For Accuracy**: Add `--time-based` flag
3. **For Stealth**: Use lower thread count (`--threads 3`)
4. **For Reports**: Always use `-o` and `--csv` for documentation
5. **For Debugging**: Add `-v` for verbose output with live URL status
6. **For WAF Detection**: Verbose mode shows WAF detection in real-time
7. **For Custom Payloads**: Use `-p custom_payloads.txt` to load your own payloads

---

## 📊 Output Examples

### Terminal Output

```
╔══════════════════════════════════════════════════╗
║  VIP SQLi Scanner - Advanced Edition             ║
║  Professional SQL Injection Triage Tool          ║
║  30-Second Framework | Enterprise Features      ║
╚══════════════════════════════════════════════════╝

ℹ Loaded 13 exclusion patterns
ℹ Loaded 50 URLs from list

Starting scan with 10 threads...

  Scanning URLs... ━━━━━━━━━━━━━━━━━━━━ 100% 0:00:15

╭──────────────── Scan Statistics ─────────────────╮
│   Total URLs:    50                              │
│   Scanned:       45                              │
│   Vulnerable:    2                               │
│   Safe:          43                              │
│   Excluded:      5                               │
│   Errors:        0                               │
│   Elapsed:       15s                             │
╰──────────────────────────────────────────────────╯

                    Scan Results
╭────────────────┬────────────┬──────────┬──────────╮
│ URL            │ Status     │ Risk     │ Details  │
├────────────────┼────────────┼──────────┼──────────┤
│ example.com/.. │ VULNERABLE │ Critical │ SQL Inj..│
│ shop.com/...   │ VULNERABLE │ Critical │ Time-ba..│
│ test.com/...   │ SAFE       │ Low      │ No obvi..│
╰────────────────┴────────────┴──────────┴──────────╯

⚠ Found 2 potential SQLi vulnerabilities!
```

### JSON Export

```json
{
  "scan_info": {
    "timestamp": "2026-02-02T01:00:00",
    "total_urls": 50,
    "scanned": 45,
    "vulnerable": 2,
    "safe": 43,
    "excluded": 5,
    "errors": 0,
    "elapsed_seconds": 15
  },
  "results": [
    {
      "url": "http://example.com/product.php?id=1",
      "verdict": "CRITICAL",
      "risk": "Critical",
      "details": "SQL Injection Candidate Found",
      "vuln_details": {
        "type": "error-based",
        "param": "id",
        "errors": ["You have an error in your SQL syntax"]
      }
    }
  ]
}
```

---

## 🎯 Features Comparison

| Feature | Basic Version | Advanced Version |
|---------|--------------|------------------|
| Modern UI | ❌ | ✅ Rich library |
| Progress Bars | ❌ | ✅ Real-time |
| Multi-Threading | ❌ | ✅ Configurable |
| Time-Based SQLi | ❌ | ✅ Included |
| JSON Export | ❌ | ✅ Detailed |
| CSV Export | ❌ | ✅ Included |
| Interactive Mode | ❌ | ✅ Guided setup |
| Risk Scoring | ❌ | ✅ 4-level system |
| Stats Dashboard | ❌ | ✅ Live updates |

---

## 🔍 Detection Capabilities

### Static Analysis
- **60+** static file extensions
- **15+** dangerous file extensions
- **60+** static file extensions
- **15+** dangerous file extensions
- **25+** safe directory paths
- **New in v2.1**: Kubernetes, Docker, MFA, and modern framework exclusions

### Parameter Analysis
- **60+** high-risk parameters
- **40+** low-risk parameters

### SQL Error Detection
- **50+** error signatures
- MySQL/MariaDB, PostgreSQL, Oracle
- MSSQL, SQLite, DB2
- ODBC, PDO, ASP/IIS

### Advanced Techniques
- Time-based blind SQLi (SLEEP/WAITFOR)
- Boolean-based detection
- Response content analysis
- Error-based injection

---

## 📝 Example Files

### urls.txt
```
# Production endpoints
http://example.com/product.php?id=1
http://example.com/search.php?query=test
http://shop.example.com/item.aspx?product_id=123
```

### exclusions.txt
```
# Skip static assets
.css
.js
.png
/wp-content/
/assets/
```

---

## ⚠️ Legal Notice

This tool is for **educational and authorized security testing only**. Always obtain proper authorization before testing any system you don't own.

---

## 🛠️ Requirements

- Python 3.6+
- `requests`
- `colorama`
- `rich`

---

## 📈 Performance Tips

1. **Adjust Threads**: Use `--threads 10` for faster scans
2. **Use Exclusions**: Skip known-safe URLs with `-e exclusions.txt`
3. **Disable Time-Based**: Skip `--time-based` for faster scans (less accurate)
4. **Export Results**: Use `-o` and `--csv` for post-processing

---

## 🎓 Pentester's Workflow

1. **Reconnaissance**: Gather URLs from crawling/spidering
2. **Filter**: Create exclusion list for static assets
3. **Scan**: Run advanced scanner with threading
4. **Review**: Check JSON/CSV reports for vulnerabilities
5. **Verify**: Manually test flagged endpoints
6. **Report**: Use results for client reporting

---

**Version**: 2.2 (Advanced Edition)  
**Status**: Production Ready  
**Quality**: Enterprise Grade (Cyberpunk Edition)  

---

**EST 2026 . viphacker100**
