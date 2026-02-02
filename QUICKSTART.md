# 🚀 Quick Start Guide - VIP SQLi Scanner v3.0

## Installation

```bash
cd VIPSQLi
python -m pip install -r requirements.txt
```

## Basic Usage

### 1. Single URL Scan (v3.0 Advanced)
```bash
python sqli_scanner_advanced.py -u "http://target.com/page.php?id=1" --boolean --ml
```

### 2. Batch Scan (Recommended)
```bash
# High-speed scan with all the bells and whistles
python sqli_scanner_advanced.py -l urls.txt -t 20 --boolean --ml --sarif report.sarif
```

### 3. Launch the Cyberpunk Dashboard (v4.0 Backend)
```powershell
python dashboard/app.py
```
*Access via browser: `http://localhost:5000`*

## Common Scenarios

### Enterprise CI/CD Scan
```bash
python sqli_scanner_advanced.py -l targets.txt --sarif scan_results.sarif --no-color
```

### Thorough Blind SQLi Scan
```bash
python sqli_scanner_advanced.py -l urls.txt --boolean --time-based -v
```

### Ignore SSL Security Errors
```bash
python sqli_scanner_advanced.py -u "https://internal-dev.local" -k
```

## Tips

- **Use threads**: Default is 5, but you can go up to 50 for large lists: `-t 50`
- **Enable ML Scoring**: Add `--ml` to filter out low-confidence "false positive" noise.
- **Boolean vs Time-Based**: Boolean (`--boolean`) is faster and very reliable; Time-based (`--time-based`) is a great fallback for truly silent endpoints.

## Version Comparison

| | v2.2 | v3.0 (Latest) |
|---|---|---|
| **Boolean Detection** | ❌ | ✅ High Precision |
| **ML Scoring** | ⚠️ Partial | ✅ Fully Integrated |
| **Reporting** | JSON/HTML | ✅ SARIF + PDF + HTML |
| **Dashboard** | ❌ Basic | ✅ Cyberpunk v4.0 (Enterprise) |
| **Authentication** | ❌ | ✅ GitHub SSO support |
| **Distributed** | ❌ | ✅ Node Management System |

---

**EST 2026 . viphacker100**
