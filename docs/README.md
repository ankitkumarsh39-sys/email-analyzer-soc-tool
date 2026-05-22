# Email Analysis with IOC Validation

A comprehensive email security analysis system that extracts and validates Indicators of Compromise (IOCs) from email content.

## Project Overview

This project integrates email analysis with IOC (Indicators of Compromise) validation to automatically detect malware, phishing, and other threats in email messages.

**Key Features:**
- 📧 Parse and analyze email messages
- 🔍 Extract IOCs (IPs, domains, URLs, hashes, CVEs)
- 🎯 Defang detection and normalization
- 📊 Generate multiple report formats (JSON, text, blocklist)
- ⚪ Whitelist filtering for known-safe indicators
- 🔄 Reusable IOC validation library for any project

---

## Project Structure

```
Email Analysis/
├── ioc_lib/                          # IOC validation library (reusable)
│   ├── __init__.py                   # IOCValidator, IOCResult classes
│   └── ioc_validator.py              # IOC extraction helper functions
│
├── email_analyzer/                   # Email analysis module
│   ├── __init__.py                   # Package initialization
│   ├── analyzer.py                   # Email parsing and analysis
│   ├── mail_reporter.py              # Report generation
│   └── main.py                       # Entry point
│
├── tests/                            # Unit tests
│   ├── test_ioc_lib.py               # IOC library tests (50+ test cases)
│   └── test_run.py                   # Email analyzer tests
│
├── examples/                         # Usage examples
│   └── examples.py                   # 9 complete usage examples
│
├── docs/                             # Documentation
│   ├── README_IOC_LIB.md             # IOC library documentation
│   └── README.md                     # This file
│
├── config/                           # Configuration files
│   ├── whitelist.txt                 # Known-safe IOCs
│   └── blocklist.txt                 # Known-malicious IOCs
│
├── data/                             # Sample data
│   └── Sample Email/                 # Sample email files
│       └── sample_phishing.eml       # Example phishing email
│
├── reports/                          # Generated reports (auto-created)
│
├── requirements.txt                  # Python dependencies
└── README.md                         # This file
```

---

## Quick Start

### 1. Installation

```bash
pip install -r requirements.txt
```

### 2. Basic Usage

```python
from email_analyzer import analyze_email

# Analyze an email file
email_data = analyze_email("data/Sample Email/sample_phishing.eml")

# Access results
print(f"IOCs found: {email_data['iocs']}")
print(f"Malicious indicators: {email_data['malicious_indicators']}")
```

### 3. Generate Reports

```python
from email_analyzer.mail_reporter import MailReporter

reporter = MailReporter()

# Generate different report formats
json_report = reporter.generate_json_report(email_data)
text_report = reporter.generate_text_report(email_data)
blocklist = reporter.generate_blocklist(email_data)
```

---

## Usage Examples

### Example 1: Extract IOCs from Email

```python
from ioc_lib import IOCValidator

validator = IOCValidator()

email_body = """
Subject: Security Alert

Detected threat from 192.168.1.100
Malicious domain: phishing[.]example[.]com
Download link: hxxps://malware[.]site/payload.exe
Hash: d41d8cd98f00b204e9800998ecf8427e
CVE-2021-1234 exploited
"""

result = validator.extract(email_body)
print(f"Found {result.total_count()} IOCs")
print(f"IPs: {result.ips}")
print(f"Domains: {result.domains}")
```

### Example 2: Whitelist Filtering

```python
from ioc_lib import IOCValidator

validator = IOCValidator()
result = validator.extract(email_body)

whitelist = ["8.8.8.8", "google.com"]
filtered = validator.filter_whitelist(result, whitelist)

print(f"After filtering: {filtered.total_count()} IOCs")
```

### Example 3: Normalize Defanged IOCs

```python
from ioc_lib import IOCValidator

defanged = "192[.]168[.]1[.]1"
normalized = IOCValidator.normalize(defanged)
print(f"{defanged} → {normalized}")
```

---

## IOC Validator API

### Core Methods

| Method | Description |
|--------|------------|
| `extract(text)` | Extract all IOCs from text |
| `normalize(ioc, type)` | Normalize defanged IOCs |
| `is_defanged(ioc)` | Check if IOC is defanged |
| `generate_report(result, detailed)` | Generate structured report |
| `filter_whitelist(result, whitelist)` | Filter whitelisted IOCs |

### Supported IOC Types

- **IP Addresses**: `192.168.1.1`, `10[.]0[.]0[.]1`
- **Domains**: `example.com`, `malware[.]com`
- **URLs**: `https://example.com`, `hxxps://evil[.]com`
- **Hashes**: MD5, SHA1, SHA256
- **CVEs**: `CVE-2021-0001`, `CVE 2022-12345`

---

## Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_ioc_lib.py -v

# Run with coverage
pytest tests/ --cov=ioc_lib
```

---

## Configuration

### Whitelist (config/whitelist.txt)

List of known-safe IOCs (one per line):
```
8.8.8.8
1.1.1.1
google.com
microsoft.com
```

### Blocklist (config/blocklist.txt)

List of known-malicious IOCs (one per line):
```
192.168.1.100
malware.com
evil.net
```

---

## Report Formats

### 1. JSON Report

```json
{
  "timestamp": "2026-05-15T12:34:56",
  "summary": {
    "total_iocs": 5,
    "ips": 1,
    "domains": 1,
    "urls": 1,
    "hashes": 1,
    "cves": 1
  },
  "iocs": {
    "ips": ["192.168.1.100"],
    "domains": ["malware.com"],
    "urls": ["https://evil.com/payload"],
    "hashes": ["d41d8cd98f00b204e9800998ecf8427e"],
    "cves": ["CVE-2021-1234"]
  }
}
```

### 2. Text Report

```
Email Analysis Report
====================
Timestamp: 2026-05-15 12:34:56

Summary:
--------
Total IOCs: 5
- IPs: 1
- Domains: 1
- URLs: 1
- Hashes: 1
- CVEs: 1

Details:
--------
IPs: 192.168.1.100
Domains: malware.com
URLs: https://evil.com/payload
Hashes: d41d8cd98f00b204e9800998ecf8427e
CVEs: CVE-2021-1234
```

### 3. Blocklist Format

```
192.168.1.100
malware.com
evil.com
d41d8cd98f00b204e9800998ecf8427e
```

---

## Use Cases

✅ Email Security Analysis  
✅ Phishing Detection  
✅ Malware Detection  
✅ Threat Intelligence Processing  
✅ SIEM Integration  
✅ Incident Response  
✅ Compliance Reporting  
✅ Automated Alerting  

---

## Performance Tips

1. **Reuse validator instances** for better performance
2. **Use whitelist filtering** to reduce false positives
3. **Process in batches** for large email volumes
4. **Cache results** for frequently analyzed content
5. **Enable logging** only in debug mode

---

## Troubleshooting

### ImportError: No module named 'ioc_lib'

```bash
pip install -r requirements.txt
```

### No IOCs Found

- Verify email contains actual IOCs
- Check defanging patterns (e.g., `192[.]168[.]1[.]1`)
- Enable logging for debugging

### Performance Issues

- Use whitelist to filter known-safe IOCs
- Process large files in chunks
- Consider caching results

---

## Dependencies

- **iocextract** - IOC extraction engine
- **requests** - HTTP client for web scraping
- **beautifulsoup4** - HTML parsing
- **mailparser** - Email parsing
- **pytest** - Unit testing framework

---

## License

This project is provided for security analysis and threat intelligence purposes.

---

## Support & Examples

See `examples/examples.py` for 9 complete usage examples:
1. Basic IOC extraction
2. Web scraping threat intel
3. IOC normalization
4. Whitelist filtering
5. Batch processing
6. Custom logging
7. JSON output for APIs
8. Email analysis integration
9. Defanging detection

For complete IOC library documentation, see `docs/README_IOC_LIB.md`
