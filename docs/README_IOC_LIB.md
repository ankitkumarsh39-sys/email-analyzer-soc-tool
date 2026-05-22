# IOC Validator Library - Complete Documentation

## Overview

The **IOC Validator Library** is a standalone, reusable Python module for extracting and validating Indicators of Compromise (IOCs) from any text source. It's designed to be framework-agnostic and can be integrated into any project.

**Supported IOC Types:**
- IP Addresses (including defanged patterns like `192[.]168[.]1[.]1`)
- Domains (including defanged patterns like `example[.]com`)
- URLs (including `hxxp://` and `hxxps://` variants)
- File Hashes (MD5, SHA1, SHA256)
- CVE Identifiers

---

## Installation

### 1. Copy Files to Your Project

Copy these files to your project:
```
ioc_lib/                   # IOC validation library package
requirements.txt           # Dependencies
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

Or install individually:
```bash
pip install iocextract requests beautifulsoup4
```

---

## Quick Start

### Basic Usage (3 lines of code)

```python
from ioc_lib import IOCValidator

validator = IOCValidator()
result = validator.extract("Your text with IOCs here")
print(f"Found {result.total_count()} IOCs: {result.to_dict()}")
```

### Complete Example

```python
from ioc_lib import IOCValidator

# Initialize
validator = IOCValidator()

# Extract IOCs
text = """
Threat detected from 192.168.1.100 and malware[.]com.
Download: hxxps://evil[.]site/payload.exe
Hash: d41d8cd98f00b204e9800998ecf8427e
CVE-2021-0001 vulnerability exploited.
"""

result = validator.extract(text)

# Access results
print(f"IPs: {result.ips}")                           # ['192.168.1.100']
print(f"Domains: {result.domains}")                   # ['malware.com']
print(f"URLs: {result.urls}")                         # ['hxxps://evil.site/payload.exe']
print(f"Hashes: {result.hashes}")                     # ['d41d8cd98f00b204e9800998ecf8427e']
print(f"CVEs: {result.cves}")                         # ['CVE-2021-0001']
print(f"Total: {result.total_count()}")               # 5
```

---

## Core API Reference

### IOCValidator Class

#### Methods

##### `extract(text: str) -> IOCResult`
Extract all IOCs from text.

```python
validator = IOCValidator()
result = validator.extract("192.168.1.1 and example.com")
# Returns: IOCResult(ips=['192.168.1.1'], domains=['example.com'], ...)
```

##### `normalize(ioc: str, ioc_type: str = None) -> str`
Normalize defanged IOCs to standard format.

```python
IOCValidator.normalize("192[.]168[.]1[.]1")        # '192.168.1.1'
IOCValidator.normalize("hxxps://example[.]com")    # 'https://example.com'
IOCValidator.normalize("malware[.]com")            # 'malware.com'
```

##### `is_defanged(ioc: str) -> bool`
Check if an IOC is defanged.

```python
IOCValidator.is_defanged("192[.]168[.]1[.]1")      # True
IOCValidator.is_defanged("192.168.1.1")            # False
```

##### `generate_report(ioc_result: IOCResult, detailed: bool = False) -> Dict`
Generate a structured report.

```python
result = validator.extract(text)
report = validator.generate_report(result, detailed=True)
# Returns structured report with timestamp and counts
```

##### `filter_whitelist(ioc_result: IOCResult, whitelist: List[str]) -> IOCResult`
Filter out whitelisted IOCs.

```python
result = validator.extract(text)
whitelist = ["8.8.8.8", "google.com"]
filtered = validator.filter_whitelist(result, whitelist)
```

### IOCResult Class (Data Container)

```python
@dataclass
class IOCResult:
    ips: List[str]          # List of IP addresses
    domains: List[str]      # List of domains
    urls: List[str]         # List of URLs
    hashes: List[str]       # List of file hashes
    cves: List[str]         # List of CVE IDs
    
    # Methods:
    .total_count() -> int   # Total number of IOCs
    .to_dict() -> Dict      # Convert to dictionary
```

---

## Real-World Integration Examples

### Example 1: Email Analysis

```python
from ioc_lib import IOCValidator
import mailparser

validator = IOCValidator()

# Parse email
mail = mailparser.parse_from_file("email.eml")

# Extract IOCs from body
body_text = " ".join(mail.text_plain)
result = validator.extract(body_text)

print(f"Suspicious indicators in email: {result.to_dict()}")
```

### Example 2: Web Scraping Threat Intel

```python
from ioc_lib import IOCValidator
import requests
from bs4 import BeautifulSoup

validator = IOCValidator()

# Fetch threat intel page
response = requests.get("https://threat-intel.com/report")
soup = BeautifulSoup(response.content, 'html.parser')
text = soup.get_text()

# Extract and report
result = validator.extract(text)
report = validator.generate_report(result, detailed=True)
```

### Example 3: Log Analysis

```python
from ioc_lib import IOCValidator

validator = IOCValidator()

# Read log file
with open("access.log", "r") as f:
    log_content = f.read()

# Extract IOCs from logs
result = validator.extract(log_content)

if result.total_count() > 0:
    print(f"Alert: Found {result.total_count()} suspicious indicators in logs!")
    print(f"IPs: {result.ips}")
```

### Example 4: API Integration

```python
from ioc_lib import IOCValidator
import json
import requests

validator = IOCValidator()
result = validator.extract("Threat from 192.168.1.1 and example.com")

# Send to external API
report = validator.generate_report(result, detailed=True)
response = requests.post(
    "https://api.example.com/iocs",
    json=report,
    headers={"Content-Type": "application/json"}
)
```

### Example 5: Database Storage

```python
from ioc_lib import IOCValidator
import json
import sqlite3

validator = IOCValidator()
result = validator.extract(text)
report = validator.generate_report(result, detailed=True)

# Store in database
conn = sqlite3.connect("iocs.db")
cursor = conn.cursor()
cursor.execute(
    "INSERT INTO reports (data, timestamp) VALUES (?, ?)",
    (json.dumps(report), report['timestamp'])
)
conn.commit()
```

---

## Configuration

### Custom Logging

```python
import logging
from ioc_lib import IOCValidator

# Create custom logger
logger = logging.getLogger("my_app")
logger.setLevel(logging.DEBUG)

# Use with validator
validator = IOCValidator(logger=logger)
```

### Extending the Library

```python
from ioc_lib import IOCValidator

class CustomIOCValidator(IOCValidator):
    def __init__(self, custom_extensions=None):
        super().__init__()
        if custom_extensions:
            self.ignored_extensions.extend(custom_extensions)
    
    def extract_custom_ioc(self, text: str):
        """Add custom IOC extraction logic"""
        pass

# Use custom validator
validator = CustomIOCValidator()
```

---

## Defanging Support

The library automatically handles common defanging patterns:

| Defanged | Normalized |
|----------|------------|
| `192[.]168[.]1[.]1` | `192.168.1.1` |
| `example[.]com` | `example.com` |
| `[.]` | `.` |
| `hxxp://` | `http://` |
| `hxxps://` | `https://` |
| `[://]` | `://` |

---

## Error Handling

```python
from ioc_lib import IOCValidator

validator = IOCValidator()

try:
    result = validator.extract(None)  # Will log warning and return empty IOCResult
except Exception as e:
    print(f"Error: {e}")
```

---

## Performance Tips

1. **Reuse validator instance** for multiple extractions
2. **Use whitelist filtering** to reduce noise
3. **Process large texts in chunks** if needed
4. **Enable logging only in debug mode**

```python
validator = IOCValidator()  # Create once

# Use multiple times
for text in large_dataset:
    result = validator.extract(text)
```

---

## Troubleshooting

### ImportError for iocextract

```python
# Install missing library
pip install iocextract
```

### No IOCs Found

- Check if input text contains actual IOCs
- Verify defanging patterns match expected format
- Enable logging: `logger.setLevel(logging.DEBUG)`

### Performance Issues

- Use whitelist to filter known safe IPs/domains
- Process files in smaller chunks
- Consider caching results for frequently analyzed text

---

## Use Cases

✅ Email Security Analysis  
✅ Malware Report Processing  
✅ SIEM Integration  
✅ Threat Intelligence Feeds  
✅ Log Analysis  
✅ Web Scraping  
✅ API Integration  
✅ Automated Alerting  
✅ Compliance Reporting  
✅ Incident Response  

---

## License

This library is provided as-is for security analysis and threat intelligence purposes.

---

## Support

For issues, examples, or enhancements, refer to the `examples/examples.py` file included in this package.
