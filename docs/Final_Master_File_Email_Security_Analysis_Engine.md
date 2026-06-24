# FINAL MASTER FILE — EMAIL SECURITY ANALYSIS ENGINE

FINAL MASTER FILE — EMAIL SECURITY ANALYSIS ENGINE

1. PROJECT OBJECTIVE
Build a SOC-grade Email Threat Analysis Engine that:
- Parses .eml files
- Extracts Indicators of Compromise (IOCs)
- Performs multi-source OSINT enrichment
- Executes sandbox analysis (URLs + files)
- Produces structured reports (TXT + JSON)
- Supports automation + SIEM integration

2. ARCHITECTURE OVERVIEW
End-to-End Flow:
INPUT (.eml)
  -> Email Parser (mailparser)
  -> HTML + Link Extraction (BeautifulSoup)
  -> IOC Extraction Layer
  -> IOC Analyzer (Multi-source enrichment)
  -> Scoring Engine (Final verdict)
  -> Reporter (TXT / JSON)
  -> Automation / SIEM / SOC

3. PROJECT STRUCTURE
Email_Analysis/
├── email_analyzer/
│   ├── analyzer.py
│   ├── mail_reporter.py
│   ├── main.py
├── ioc_lib/
│   ├── ioc_analyzer.py
├── config/
│   ├── whitelist.txt
│   ├── blocklist.txt
├── reports/
│   ├── *.txt
│   ├── *.json
│   ├── vt_cache.json
├── .env
├── requirements.txt

4. CORE FEATURES
- Email parsing (.eml)
- Header spoofing detection (SPF / DKIM / DMARC)
- Hidden HTML detection
- URL extraction (text + HTML)
- Attachment hashing (SHA256)
- IOC extraction: IPs, Domains, URLs, Hashes
- Multi-source enrichment
- Scoring engine
- SOC reporting

5. MULTI-SOURCE INTELLIGENCE MODEL (FINAL)
URLs
Tools Used:
- VirusTotal -> reputation
- urlscan.io -> behavior + DOM analysis
- Cisco Talos -> categorization
- ANY.RUN -> sandbox execution
- Hybrid Analysis -> detonation
Purpose:
- Detect phishing pages
- Detect credential harvesting
- Observe network behavior & redirects

FILE HASHES / ATTACHMENTS
Tools Used:
- VirusTotal -> AV detection
- Cisco Talos -> file reputation
- ANY.RUN -> sandbox detonation
- Hybrid Analysis -> deep malware analysis
Purpose:
- Malware behavior detection
- Trojan / ransomware
- Execution chains

IPs
Tools Used:
- VirusTotal
- AbuseIPDB -> abuse score
- Cisco Talos -> reputation
Purpose:
- Malicious infrastructure
- Botnet activity
- Hosting risk

DOMAINS
Tools Used:
- VirusTotal
- Cisco Talos
- RDAP / ICANN -> domain age
Purpose:
- Detect newly registered domains
- Suspicious hosting patterns

6. TWO-LAYER INTELLIGENCE MODEL
Layer 1 — Reputation (FAST)
- VirusTotal
- AbuseIPDB
- Talos
- RDAP
Used for initial classification

Layer 2 — Behavior (DEEP)
- urlscan
- ANY.RUN
- Hybrid Analysis
Used for high-risk IOCs

7. SANDBOX TRIGGER LOGIC (SMART EXECUTION)
if vt_score == 0 and suspicious_pattern:
    trigger sandbox
elif vt_score <= 2:
    trigger sandbox
elif ioc_type == "hash" and unknown:
    trigger sandbox

Decision Table
- Known malicious (VT > 5) -> No sandbox
- Suspicious URL -> urlscan + ANY.RUN
- Unknown file -> ANY.RUN + Hybrid Analysis
- Clean domain -> No sandbox

8. IOC DATA MODEL (FINAL)
{
  "ioc_type": "url",
  "normalized": "...",
  "vt_malicious": 2,
  "category": "Malicious",
  "final_score": 6,
  "reasons": [
      "VT detections",
      "urlscan malicious",
      "ANY.RUN suspicious behavior"
  ],
  "provider_context": {
      "virustotal": {...},
      "urlscan": {...},
      "anyrun": {...},
      "hybrid_analysis": {...},
      "talos": {...},
      "abuseipdb": {...},
      "rdap": {...}
  }
}

9. SCORING LOGIC (FINAL)
Source -> Score
- VT detection -> +3
- urlscan malicious -> +3
- AbuseIPDB (>70) -> +2
- Blocklist -> override = 10
Verdict Rule:
- final_score >= 3 -> Malicious
- otherwise -> Clean

10. OSINT SUMMARY ENGINE
Aggregates results across all IOCs
Example:
{
  "osint_summary": {
    "total_iocs_scored": 6,
    "malicious_iocs": 2,
    "providers_seen": ["urlscan", "talos", "abuseipdb"],
    "urlscan_hits": 1,
    "anyrun_submissions": 1
  }
}

11. REPORTING MODEL
TXT REPORT
IOC SCORING
URL | example.com | VT=0 | FS=3 | WL=False | BL=False | Malicious
     OSINT: urlscan(malicious=True)
            ANY.RUN(submitted)
            Talos(link)
     Reason: urlscan malicious behavior

JSON REPORT
Contains:
- Full IOC list
- Full provider evidence
- OSINT summary
- Email metadata

12. EMAIL SEVERITY LOGIC
Indicator -> Score
- Malicious IOC -> +3
- Hidden HTML -> +2
- SPF/DKIM fail -> +2
- DMARC fail -> +3
- Header mismatch -> +1 per mismatch
Severity Levels:
- Score >= 7 -> HIGH
- Score >= 4 -> MEDIUM
- Score < 4 -> LOW

13. SECURITY & PERFORMANCE FEATURES
- VT caching (vt_cache.json)
- Whitelist tagging (non-blocking)
- Blocklist override
- Safe execution (try/except)
- API quota protection
- Modular design

14. SOC BENEFITS
- Multi-source validation
- Behavioral detection
- Reduced false positives
- Explainable results (WHY)
- Automation-ready
- SIEM-ready

15. FUTURE ROADMAP
- SIEM Integration (Sentinel / Splunk)
- Power Automate integration
- Threat classification (Phishing / Malware / Infra)
- MITRE ATT&CK mapping
- AI summarization (LLM-based)

FINAL STATUS
Your project is now:
- Email Analysis Engine
- IOC Extraction Engine
- Multi-source OSINT Platform
- Sandbox Execution System
- SOC Reporting Tool
- Automation-ready Framework
