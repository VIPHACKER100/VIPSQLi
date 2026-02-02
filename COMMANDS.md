# 🚀 VIP SQLi Scanner - Command Reference

Quick reference guide for all scanner commands with real-time statistics.

---

## 📋 Table of Contents
- [Quick Start](#quick-start)
- [High-Performance Scanning](#high-performance-scanning)
- [Advanced Detection (v3.0)](#advanced-detection-v30)
- [ML-Powered Detection](#ml-powered-detection)
- [Enterprise Web Dashboard (v4.0)](#enterprise-web-dashboard-v40)
- [Export & Reporting](#export--reporting)
- [Professional Pentesting](#professional-pentesting)
- [Interactive Mode](#interactive-mode)
- [Command Options](#command-options)

---

## Quick Start

### Single URL Scan
```bash
python sqli_scanner_advanced.py "http://example.com/product.php?id=1"
```

### Batch Scan (Basic)
```bash
python sqli_scanner_advanced.py -l urls.txt
```

### Batch Scan with Exclusions
```bash
python sqli_scanner_advanced.py -l urls.txt -e exclusions.txt
```

---

## High-Performance Scanning

### Fast Async Scan (Recommended) ⚡
```bash
python sqli_scanner_advanced.py -l urls.txt --async --max-concurrent 20
```

### Ultra-Fast Async
```bash
python sqli_scanner_advanced.py -l urls.txt --async --max-concurrent 30
```

### Multi-threaded Scan
```bash
python sqli_scanner_advanced.py -l urls.txt --threads 10
```

### Custom Payloads + Async
```bash
python sqli_scanner_advanced.py -l urls.txt --async --max-concurrent 30 -p payloads.txt
```

---

## Advanced Detection (v3.0)

### Boolean-Based Blind SQLi Detection ⭐
High-precision detection using logical conditions.
```bash
python sqli_scanner_advanced.py -l urls.txt --boolean
```

### Time-Based Blind SQLi Detection
```bash
python sqli_scanner_advanced.py -l urls.txt --time-based
```

### Full Detection Suite
```bash
python sqli_scanner_advanced.py -l urls.txt --boolean --time-based -t 20
```

### Verbose Mode (Real-Time URL Status) 📊
```bash
python sqli_scanner_advanced.py -l urls.txt --boolean -v
```
*Shows live updates: ✅ SAFE / 🔴 VULNERABLE for each URL*

---

## ML-Powered Detection (v2.2)

### Enable ML Engine
Uses Random Forest to reduce false positives.
```bash
python sqli_scanner_advanced.py -l urls.txt --ml
```

### Train Custom Model
Train on your own scan data for localized accuracy.
```bash
python sqli_scanner_advanced.py --train
```

### Scan Profiles
```bash
# Aggressive (Fast, more requests)
python sqli_scanner_advanced.py -l urls.txt --profile aggressive

# Stealth (Slow, randomized delays)
python sqli_scanner_advanced.py -l urls.txt --profile stealth
```

---

## Enterprise Web Dashboard (v4.0)

### Launch Dashboard Engine
Access high-performance controls at `http://localhost:5000`.
```bash
python dashboard/app.py
```

---

## Export & Reporting

### SARIF Export (v3.0) ⭐
Industry standard format for GitHub Advanced Security.
```bash
python sqli_scanner_advanced.py -l urls.txt --sarif scan_results.sarif
```

### Professional HTML & PDF
```bash
python sqli_scanner_advanced.py -l urls.txt --html report.html --pdf report.pdf
```

### 📂 Domain Filter System
Automatically organize results into domain-specific folders with `safeurl.txt` and `vulnurl.txt`.

```bash
# Basic filter scan
python sqli_scanner_advanced.py -l urls.txt --async --filter

# Full scan with filter
python sqli_scanner_advanced.py -l urls.txt --async --time-based --filter -v
```

### Complete Scan with All Reports
```bash
python sqli_scanner_advanced.py -l urls.txt --async --time-based -o results.json --csv results.csv --filter -v
```

---

## Cloud & PDF (Phase 5)

### Generate PDF Report
Professional graded reports using `reportlab`.
```bash
python sqli_scanner_advanced.py -l urls.txt --pdf
```

### Slack Integration
Send notification blocks to your SOC/Pentest channel.
```bash
python sqli_scanner_advanced.py -l urls.txt --slack
```

### S3 & Jira Sync
```bash
# Upload to S3
python sqli_scanner_advanced.py -l urls.txt --s3

# Create Jira issues for Criticals
python sqli_scanner_advanced.py -l urls.txt --jira
```

---

## Professional Pentesting

### Full-Featured Professional Scan 🎯
```bash
python sqli_scanner_advanced.py -l urls.txt -e exclusions.txt -p payloads.txt --async --max-concurrent 25 --time-based -o scan_results.json --csv scan_results.csv -v
```

### Quick Triage Scan
```bash
python sqli_scanner_advanced.py -l urls.txt -e exclusions.txt --async --max-concurrent 30
```

### Stealth Scan (Low Thread Count)
```bash
python sqli_scanner_advanced.py -l urls.txt --threads 3 --time-based -o results.json
```

### Maximum Speed Scan
```bash
python sqli_scanner_advanced.py -l urls.txt --async --max-concurrent 50 -v
```

---

## Interactive Mode

### Guided Setup (Beginner-Friendly) 🎨
```bash
python sqli_scanner_advanced.py -i
```

The tool will prompt you for:
- URL list file or single URL
- Number of threads
- Enable async scanning (yes/no)
- Enable time-based detection (yes/no)

---

## Command Options

| Option | Description | Default |
|--------|-------------|---------|
| `url` | Single URL to scan | - |
| `-l, --list` | File containing URLs (one per line) | - |
| `-e, --exclude` | File containing exclusion patterns | - |
| `-p, --payloads` | Payload file | `payloads.txt` |
| `-o, --output` | JSON output file | - |
| `--csv` | CSV output file | - |
| `-t, --threads` | Number of threads | `5` |
| `--boolean` | Enable boolean-based blind detection (v3.0) | `False` |
| `--ml` | Enable ML-based scoring (v3.0) | `False` |
| `--sarif` | Save results in SARIF v2.1.0 format (v3.0) | - |
| `-k, --insecure` | Ignore SSL verification errors (v3.0) | `False` |
| `--time-based` | Enable time-based blind SQLi detection | `False` |
| `-v, --verbose` | Verbose output with real-time URL status | `False` |
| `-i, --interactive` | Interactive mode with prompts | `False` |
| `--html` | HTML report filename | - |
| `--pdf` | PDF report filename | - |
| `--proxy` | Single proxy URL | - |
| `--headers` | Custom headers JSON file | - |

---

## 💡 Pro Tips

1. **For Speed**: Use `--async` with `--max-concurrent 20-30`
2. **For Accuracy**: Add `--time-based` flag
3. **For Stealth**: Use lower thread count (`--threads 3`)
4. **For Reports**: Always use `-o` and `--csv` for documentation
5. **For Debugging**: Add `-v` for verbose output with live URL status
6. **For Live Stats**: Verbose mode shows real-time statistics panel during scanning
7. **For Custom Payloads**: Use `-p custom_payloads.txt` to load your own payloads

---

## 📝 Example Workflow

```bash
# 1. Quick scan to identify targets
python sqli_scanner_advanced.py -l urls.txt --async -v

# 2. Deep scan on interesting targets with live stats
python sqli_scanner_advanced.py -l interesting_urls.txt --async --time-based -o results.json --csv results.csv -v

# 3. Review results
cat scan_results.json
```

---

## 🎯 Real-Time Features

### Live Statistics Panel 📊
When scanning, you'll see:
- **Progress Bar** - Visual progress with percentage and time elapsed
- **Live Stats** - Updates every 0.25 seconds showing:
  - Total URLs
  - Scanned count
  - Vulnerable count
  - Safe count
  - Excluded count
  - Errors
  - WAF detected
  - Elapsed time
  - Requests per second

### Verbose Mode Output
With `-v` flag, see each URL as it's scanned:
```
✅ SAFE | http://example.com/page.php?id=1
✅ SAFE | http://example.com/product.php?cat=2
🔴 VULNERABLE | http://example.com/search.php?q=test
```

---

**EST 2026 . viphacker100**
