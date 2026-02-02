# 🔥 VIP SQLi Scanner - Advanced Edition v3.0

<p align="center">
  <img src="assets/logo.svg" width="150" alt="VIP Logo">
</p>

**PROFESSIONAL SQLi DETECTION & EXPLOITATION TRIAGE FRAMEWORK**

A next-generation, high-performance security tool for automated SQLi discovery. v3.0 introduces machine learning scoring, boolean-based blind detection, and an enterprise dashboard with distributed scanning support.

<img width="745" height="393" alt="image" src="https://github.com/user-attachments/assets/6c8878c5-6da8-4d9a-8a16-38237cce48c2" />
---

**🔗 Links:**
- **GitHub**: [https://GitHub.com/viphacker100/](https://GitHub.com/viphacker100/)
- **Website**: [https://viphacker100.com](https://viphacker100.com)

## 🎯 Features

### 🔍 Advanced Detection (v3.0)
- **Boolean-Based Blind Detection**: Precision testing using logic pairs (TRUE/FALSE) with response diff analysis.
- **ML Scoring Engine**: Integrated machine learning model to categorize and score vulnerability confidence.
- **Error-Based Injections**: Support for **100+ SQL error signatures** across MySQL, PG, Oracle, MSSQL, SQLite, and DB2.
- **Time-Based Triage**: High-accuracy blind SQLi detection with automated WAF bypass logic.

### 📈 Modern UI & Dashboard (v4.0 Backend)
- **Cyberpunk Aesthetics**: Real-time visualization using a premium glassmorphism dashboard.
- **Enterprise SSO**: GitHub OAuth integration for team-based security operations.
- **Distributed Infrastructure**: Register and monitor external scan nodes for massive scalability.
- **Real-time Reporting**: Live WebSocket updates as findings are discovered.

### 📊 Professional Export formats
- **SARIF v2.1.0**: Standard format for integration with GitHub Advanced Security.
- **Executive PDF/HTML**: Beautiful reports with CVSS scoring and remediation advice.
- **Bulk CSV/JSON**: Structured data for post-processing and SIEM integration.

### 🛡️ Smart Triage System
- **Rule #0 Skip**: Automatically excludes **60+ static asset types** to maximize speed.
- **Risk Assessment**: Analyzes **15+ high-risk extensions** and **60+ sensitive parameters**.
- **WAF Bypass**: Sophisticated payload encoding to identify hidden vulnerabilities behind firewalls.

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
python sqli_scanner_advanced.py -u "http://example.com/product.php?id=1" --boolean --ml
```

### Batch Scanning (URL List)
```bash
# Scan multiple URLs with all detection types enabled
python sqli_scanner_advanced.py -l urls.txt --threads 20 --boolean --ml --sarif report.sarif
```

### Primary Command-Line Options
| Flag | Description |
|------|-------------|
| `-u, --url` | Single target URL |
| `-l, --list` | File containing URLs to scan |
| `--boolean` | Enable boolean-based blind detection (v3.0) |
| `--ml` | Enable ML-based vulnerability scoring (v3.0) |
| `--sarif` | Save results in SARIF v2.1.0 format |
| `-k, --insecure` | Ignore SSL verification errors |
| `--dashboard` | Launch the Enterprise Web Dashboard (v4.0) |

---


## 🖥️ Enterprise Web Dashboard (v4.0+)

The scanner now features a high-performance Cyberpunk-themed backend for managing complex operations.

**Launch Dashboard:**
```powershell
python dashboard/app.py
```

**Interactive Controls:**
- **Distributed Nodes**: Manage remote scanning infrastructure.
- **SSO Integration**: Secure team access via GitHub.
- **Live Feed**: Watch real-time vulnerabilities with ML scoring.

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

### 🖥️ Real-time Dashboard (v2.2+)
Launch the interactive web dashboard to monitor and control scans:
```powershell
python sqli_scanner_advanced.py --dashboard
```
**New Interactive Features:**
- **Command Center**: Sidebar control for running scans.
- **Dynamic Targeting**: Add URLs and domains to the scan queue in real-time.
- **Payload Injection**: Inject custom SQLi payloads directly into the engine from the web UI.
- **Process Management**: Start and terminate scan threads remotely.

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
