# 🚀 Quick Start Guide - VIP SQLi Scanner Advanced

## Installation

```bash
cd VIPSQLi
pip install -r requirements.txt
```

## Basic Usage

### 1. Single URL Scan
```bash
python sqli_scanner_advanced.py "http://example.com/product.php?id=1"
```

### 2. Batch Scan (Recommended)
```bash
python sqli_scanner_advanced.py -l urls.txt
```

### 3. Full-Featured Scan
```bash
python sqli_scanner_advanced.py \
  -l urls.txt \
  -e exclusions.txt \
  --threads 10 \
  --time-based \
  -o results.json \
  --csv results.csv
```

### 4. Interactive Mode (Beginner-Friendly)
```bash
python sqli_scanner_advanced.py -i
```

## Common Scenarios

### Fast Scan (Skip Time-Based Detection)
```bash
python sqli_scanner_advanced.py -l urls.txt --threads 10
```

### Thorough Scan (Enable All Detection)
```bash
python sqli_scanner_advanced.py -l urls.txt --time-based -v
```

### Export Results for Reporting
```bash
python sqli_scanner_advanced.py -l urls.txt -o report.json --csv report.csv
```

## Tips

- **Start with 5 threads**: `--threads 5` (default)
- **Use exclusions**: Skip static files with `-e exclusions.txt`
- **Enable time-based for blind SQLi**: Add `--time-based` flag
- **Export for analysis**: Use `-o` for JSON and `--csv` for spreadsheets

## Comparison: Basic vs Advanced

| Command | Basic Version | Advanced Version |
|---------|--------------|------------------|
| Single URL | `python sqli_scanner.py URL` | `python sqli_scanner_advanced.py URL` |
| Batch | `python sqli_scanner.py -l urls.txt` | `python sqli_scanner_advanced.py -l urls.txt --threads 10` |
| Export | `python sqli_scanner.py -l urls.txt -o out.txt` | `python sqli_scanner_advanced.py -l urls.txt -o out.json --csv out.csv` |

## What You Get

✅ Beautiful modern UI with progress bars  
✅ 5-10x faster with multi-threading  
✅ Time-based blind SQLi detection  
✅ Professional JSON/CSV reports  
✅ Live statistics dashboard  
✅ Color-coded results  

---

**Need Help?** Run `python sqli_scanner_advanced.py --help`
