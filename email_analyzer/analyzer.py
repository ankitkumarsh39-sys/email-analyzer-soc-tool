"""
analyzer.py (FINAL + VT IOC SCORING)

Purpose:
- Parse .eml file OR newest .eml from a folder
- Extract:
  - Full headers + focus headers
  - Header mismatch flags (From/Reply-To/Return-Path/Sender)
  - Received hops + Authentication-Results
  - Body stats
  - URLs
  - Hidden HTML indicators
  - Attachments + SHA256
- Run advanced IOC analysis (NO CVE) using IOCAnalyzer:
  - extraction
  - normalization
  - whitelist/blocklist tagging
  - VirusTotal scoring
- Return structured data used by mail_reporter.py
"""

from __future__ import annotations

import os
import re
import base64
import hashlib
import logging
from typing import Optional, Dict, Any, List, Set
from urllib.parse import urlparse

import mailparser
from bs4 import BeautifulSoup

from collections import Counter
from email.header import decode_header

# Advanced IOC scoring engine (with VT / whitelist / blocklist)
from ioc_lib.ioc_analyzer import IOCAnalyzer, AnalysisCancelled

logger = logging.getLogger(__name__)

# Project root helps build stable paths to config / reports
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Simple URL regex for extracting plain URLs from text/html
URL_REGEX = re.compile(r"\bhttps?://[^\s<>\"')]+", re.IGNORECASE)

#-----------------------------------------------------------------------


def decode_mime_header(value: str) -> str:
    if not value:
        return ""

    # Handle list/tuple cases (mailparser sometimes returns this)
    if isinstance(value, (list, tuple)):
        value = value[0] if value else ""
        if isinstance(value, tuple):
            value = value[1]

    decoded_parts = decode_header(str(value))
    result = ""

    for part, encoding in decoded_parts:
        if isinstance(part, bytes):
            result += part.decode(encoding or "utf-8", errors="ignore")
        else:
            result += str(part)

    return result

# -----------------------------------------------------------------------------
# Small Utility Helpers
# -----------------------------------------------------------------------------
def sha256_bytes(data: bytes) -> str:
    """Return SHA256 hash of given bytes."""
    return hashlib.sha256(data).hexdigest()

def safe_str(value: Any, limit: int = 200) -> str:
    """
    Convert value to string safely and shorten if too long.
    This keeps logs/reports readable.
    """
    if value is None:
        return ""
    s = str(value)
    return s[:limit] + ("..." if len(s) > limit else "")

#--------------------------------------------------------------------

def normalize_url(url: str) -> str:
    """
    Trim trailing punctuation often seen in plain-text emails.
    Example:
      https://example.com/login).  -> https://example.com/login
    """
    if not url:
        return url
    return url.strip().strip(').,;\"\'')  # safe cleanup

#---------------------------------------------------------------------
    """
    convert IOC into safe analyst-readable form.
    used ONLY for text reporting / human-readable output.
    """

#--------------------------------------------------------------------

def defang_ioc(value: str) -> str:
    if not value:
        return value
    
    # Defang Protocols first
    values = value.replace("https://", "hxxps://")
    values = value.replace("http://", "hxxp://")
    #Then defang separators
    value = value.replace(".", "[.]")

    return value

#-----------------------------------------------------------------
"""
Build one clean text block of defanged IOCs for TXT reporting.
This is intentionally human-readable, not JSON-structured.
"""
#-----------------------------------------------------------------

def build_defanged_ioc_text(iocs: Dict[str, Any]) -> str:

    lines =[]
    lines.append("IOC List")
    lines.append("=" * 80)

    #IPs
    lines.append("\nIPs:")
    for ip in iocs.get("ips", []) or []:
        lines.append(f" - {defang_ioc(ip)}")
    if not (iocs.get("ips",[]) or []):
        lines.append("  - None")
    
    # Domain
    lines.append("\nDomains:")
    for d in iocs.get("domains", []) or []:
        lines.append(f" - {defang_ioc(d)}")
    if not (iocs.get("domains", []) or []):
        lines.append("  - None")

    # URLs
    lines.append("\nURLs:")
    for u in iocs.get("urls", []) or []:
        lines.append(f"  - {defang_ioc(u)}")
    if not (iocs.get("urls", []) or []):
        lines.append("  - None")

    # Hashs (hashes are not Defanged)
    lines.append("\nHashes:")
    for h in iocs.get("hashes", []) or []:
        lines.append(f"  - {h}")
    if not (iocs.get("hashes", []) or []):
        lines.append("  - None")

    return "\n".join(lines)

def extract_urls_from_text(text: str) -> List[str]:
    """Extract unique URLs from plain text."""
    if not text:
        return []

    urls = {normalize_url(u) for u in URL_REGEX.findall(text)}
    return sorted(u for u in urls if u)

def extract_urls_from_html(html: str) -> List[str]:
    """
    Extract unique URLs from HTML using:
    - href in <a>
    - src in <img>
    - raw URLs present in HTML text
    """
    if not html:
        return []

    urls: Set[str] = set()
    soup = BeautifulSoup(html, "html.parser")

    # Extract href links
    for a in soup.find_all("a", href=True):
        urls.add(normalize_url(a["href"]))

    # Extract img src links (useful for tracking pixels)
    for img in soup.find_all("img", src=True):
        urls.add(normalize_url(img["src"]))

    # Extract raw URLs from HTML content itself
    for u in URL_REGEX.findall(html):
        urls.add(normalize_url(u))

    return sorted(u for u in urls if u)

def find_hidden_elements(html: str) -> int:
    """
    Count HTML elements that appear hidden using common phishing tricks:
    - display:none
    - visibility:hidden
    - font-size:0
    """
    if not html:
        return 0

    soup = BeautifulSoup(html, "html.parser")

    def is_hidden_style(style_value: str) -> bool:
        v = style_value.replace(" ", "").lower()
        return ("display:none" in v) or ("visibility:hidden" in v) or ("font-size:0" in v)

    hidden = soup.find_all(style=lambda value: value and is_hidden_style(value))
    return len(hidden)

def decode_attachment_payload(payload: Any) -> Optional[bytes]:
    """
    Decode attachment payload into raw bytes for hashing.

    Payload can be:
    - bytes
    - base64 string
    - plain string
    """
    if payload is None:
        return None

    if isinstance(payload, (bytes, bytearray)):
        return bytes(payload)

    if isinstance(payload, str):
        try:
            return base64.b64decode(payload, validate=True)
        except Exception:
            # If not base64, keep raw bytes from string
            return payload.encode(errors="ignore")

    return str(payload).encode(errors="ignore")

def resolve_eml_path(input_path: str) -> Optional[str]:
    """
    Accept either:
    - direct .eml file path
    - folder path containing .eml files (returns newest .eml)
    """
    if not input_path:
        return None

    if os.path.isfile(input_path) and input_path.lower().endswith(".eml"):
        return input_path

    if os.path.isdir(input_path):
        eml_files = [
            os.path.join(input_path, f)
            for f in os.listdir(input_path)
            if f.lower().endswith(".eml")
        ]
        if not eml_files:
            return None
        return max(eml_files, key=os.path.getmtime)

    return None

# -----------------------------------------------------------------------------
# Header Helper Functions
# -----------------------------------------------------------------------------
def _headers_as_dict(mail) -> Dict[str, Any]:
    """Return mail.headers as dict if available."""
    h = getattr(mail, "headers", None)
    return h if isinstance(h, dict) else {}

def _get_header(headers: Dict[str, Any], name: str):
    """Case-insensitive header lookup."""
    for k, v in (headers or {}).items():
        if str(k).lower() == name.lower():
            return v
    return None

#---------------------------------------------------------------------
"""
    Extract Received hops.
    Uses parser output if present, otherwise falls back to raw Received headers.
"""
#---------------------------------------------------------------------

def _extract_received_hops(mail) -> List[Dict[str, Any]]:
    hops = []

    headers = getattr(mail, "headers", {}) or {}

    # 1. Try mailparser native first
    if hasattr(mail, "received") and mail.received:
        for r in mail.received:
            hops.append({"raw": str(r)})

    # 2. Try headers dict
    for k, v in headers.items():
        if str(k).lower() == "received":
            if isinstance(v, list):
                for item in v:
                    hops.append({"raw": item})
            elif isinstance(v, str):
                hops.append({"raw": v})

    # 3. Raw parse
    if not hops:
        try:
            raw_email = getattr(mail, "raw", "")
            matches = re.findall(
                r"(Received:.*?(?:\r?\n\s+.*)*)",
                raw_email,
                re.IGNORECASE
            )
            for m in matches:
                cleaned = " ".join(m.split())
                hops.append({"raw": cleaned})
        except Exception:
            pass

    if not hops:
        logger.warning("No Received headers found -> Possible malformed email or evasion technique")

    return hops

#---------------------------------------------------------------------

def _domain_from_addr(text: str) -> str:
    """
    Extract domain from any email-like string.
    Example:
      "John <john@example.com>" -> example.com
    """
    if not text:
        return ""

    m = re.search(r'[\w\.\-+%]+@([\w\.\-]+\.[A-Za-z]{2,})', str(text))
    return m.group(1).lower() if m else ""

#---------------------------------------------------------------------

def _header_mismatch_flags(headers: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build spoofing-related mismatch flags:
    - From vs Reply-To
    - From vs Return-Path
    - From vs Sender
    """
    from_h = str(_get_header(headers, "From") or "")
    reply_to = str(_get_header(headers, "Reply-To") or "")
    return_path = str(_get_header(headers, "Return-Path") or "")
    sender = str(_get_header(headers, "Sender") or "")

    from_dom = _domain_from_addr(from_h)
    reply_dom = _domain_from_addr(reply_to)
    return_dom = _domain_from_addr(return_path)
    sender_dom = _domain_from_addr(sender)

    return {
        "from_domain": from_dom,
        "reply_to_domain": reply_dom,
        "return_path_domain": return_dom,
        "sender_domain": sender_dom,
        "reply_to_mismatch": bool(reply_dom and from_dom and reply_dom != from_dom),
        "return_path_mismatch": bool(return_dom and from_dom and return_dom != from_dom),
        "sender_mismatch": bool(sender_dom and from_dom and sender_dom != from_dom),
    }


#-----------------------------------------------------------------
    """
    Keep only the most important headers for human-readable reporting.
    Full headers are still returned separately.
    """

#---------------------------------------------------------------------

def _extract_header_focus(headers: Dict[str, Any]) -> Dict[str, Any]:

    focus_keys = [
        "From", "To", "Cc", "Bcc", "Subject", "Date", "Message-ID",
        "Return-Path", "Reply-To", "Sender",
        "Authentication-Results", "Received-SPF",
        "DKIM-Signature", "ARC-Authentication-Results", "ARC-Seal", "ARC-Message-Signature",
        "MIME-Version", "Content-Type", "Content-Transfer-Encoding",
        "User-Agent", "X-Mailer", "X-Originating-IP",
        "X-Forefront-Antispam-Report", "X-Microsoft-Antispam",
    ]

    out = {}
    for k in focus_keys:
        v = _get_header(headers, k)
        if v is not None:
            out[k] = v

    return out

#---------------------------------------------------------------------------------------
    """
    Lightweight phishing-oriented subject inspection.
    Returns structured flags for scoring/reporting.
    """
#----------------------------------------------------------------------------------------

def analyze_subject_threat(subject: str) -> Dict[str, Any]:
 
    s = (subject or "").strip()
    s_lower = s.lower()

    flags: List[str] = []
    score = 0

    # Urgency / fear tactics
    urgent_terms = [
        "urgent", "action required", "immediate action", "suspended",
        "verify", "security alert", "account locked", "password expires"
    ]
    for term in urgent_terms:
        if term in s_lower:
            flags.append(f"Urgency keyword: {term}")
            score += 1

    # Brand impersonation markers
    brands = ["microsoft", "office365", "office 365", "outlook", "paypal", "bank"]
    for brand in brands:
        if brand in s_lower:
            flags.append(f"Brand mention: {brand}")
            score += 1
            break

    # Excessive punctuation style
    if "!!" in s or "⚠" in s:
        flags.append("Attention-grabbing punctuation/symbols")
        score += 1

    # MIME-encoded subject indicator (useful if raw header still contains it)
    if "=?" in s and "?=" in s:
        flags.append("Encoded subject detected")
        score += 1

    return {
        "subject_text": s,
        "subject_score": score,
        "subject_flags": flags,
        "subject_severity": (
            "High" if score >= 4 else
            "Medium" if score >= 2 else
            "Low"
        )
    }

#--------------------------------------------------------------------------------------------
    """Calculate a simple severity score based on various indicators.
    This intended for phishing  / Suspicious email scoring in final reports.
    It uses:
    - IOC verdicts (more IOCs = higher score)
    - Header mismatch flags (each mismatch adds to score)
    - hidden HTML count (more hidden elements = higher score)
    - authentication results (fail results add to score)

    output is added back into email_data so reporter / SIEM can use it for sorting/prioritization.
    """
#---------------------------------------------------------------------------------------------

def calculate_email_severity_score(email_data: Dict[str, Any]) -> Dict[str, Any]:
    score = 0
    reason: List[str] = []

    #------------------------------------------------------------------------------------
    #IOC-based scoring: Each IOC adds to score, with more weight for certain types (e.g. URLs > domains > IPs)
    #------------------------------------------------------------------------------------

    for item in email_data.get("ioc_scoring", []):
        if item.get("category") == "Malicious":
            ioc_type = item.get("ioc_type", "ioc")

            if ioc_type == "url":
                score += 3
                reason.append("Malicious URL IOC\n")

            elif ioc_type == "domain":
                score += 3
                reason.append("Malicious Domain IOC\n")

            elif ioc_type == "ip":
                score += 2
                reason.append("Malicious IP IOC\n")

            elif ioc_type == "hash":
                score += 4
                reason.append("Malicious Hash IOC\n")

            else:
                score += 1
                reason.append(f"Malicious {ioc_type} IOC")

    #------------------------------------------------------------------------------------
    # Hidden HTML is a common phishing technique, so we add to score based on couFnt
    #------------------------------------------------------------------------------------

    hidden_count = email_data.get("body_stats", {}).get("hidden_html_count", 0)
    if hidden_count >= 1:
        score += 2
        reason.append(f"{hidden_count} hidden HTML elements detected:\n")
    
    # --------------------------------------------------------------------
    # Subject threat scoring
    # --------------------------------------------------------------------
    subject_score = email_data.get("subject_analysis", {}).get("subject_score", 0)
    subject_flags = email_data.get("subject_analysis", {}).get("subject_flags", []) or []

    if subject_score > 0:
        score += min(subject_score, 3)  # cap contribution
        for flag in subject_flags:
            reason.append(f"Subject indicator: {flag}")

    #------------------------------------------------------------------------------------
    # Authentication results: SPF/DKIM/DMARC failures are strong indicators of spoofing/phishing
    #------------------------------------------------------------------------------------
    auth_text = (email_data.get("auth_results") or "").lower()

    if "spf=fail" in auth_text:
        score += 2
        reason.append("SPF fail in Authentication-Results\n")

    if "dkim=fail" in auth_text:
        score += 2
        reason.append("DKIM fail in Authentication-Results\n")
    
    if "dmarc=fail" in auth_text:
        score += 3
        reason.append("DMARC fail in Authentication-Results\n")

    #------------------------------------------------------------------------------------
    # Header mismatch flags: Each mismatch adds to score as it can indicate spoofing
    #------------------------------------------------------------------------------------

    mismatch_flags = email_data.get("header_analysis", {}).get("mismatch_flags", {})
    if isinstance(mismatch_flags, dict):
        mismatch_count = sum(
            1 for k, v in mismatch_flags.items()
            if k.endswith("_mismatch") and bool(v)
        )

        if mismatch_count:
            score += mismatch_count  # each mismatch adds 1 to score
            reason.append(f"{mismatch_count} header domain mismatches detected\n\n")

    #------------------------------------------------------------------------------------
    # Finalize score and reason
    #------------------------------------------------------------------------------------

    severity = ("High" if score >= 7
                else "Medium" if score >= 4
                else "Low")

    # ✅ Remove duplicates + add count
    reason_counts = Counter(reason)

    formatted_reasons = []

    for r, count in reason_counts.items():
        if count > 1:
            formatted_reasons.append(f"{r.strip()} (x{count})")
        else:
            formatted_reasons.append(r.strip())

    return {
        "email_score": score,
        "email_severity": severity,
        "email_score_reason": formatted_reasons if formatted_reasons else ["No significant indicators detected"]
    }

#------------------------------------------------------------------------------
# OSINT SUMMARY
#------------------------------------------------------------------------------

def summarize_osint(ioc_scoring: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Build OSINT summary from IOC scoring results
    """
    summary ={
        "total_iocs_scored": len(ioc_scoring),
        "malicious_iocs": 0,
        "providers_seen": set(),
        "urlscan_hits": 0,
        "abuseipdb_hits": 0,
        "anyrun_submissions": 0,
    }

    for row in ioc_scoring:
        if row.get("category") == "Malicious":summary["malicious_iocs"] +=1
        provider_context = row.get("provider_context",{}) or {}
        
        #----------------------
        #urlscan
        #----------------------

        urlscan = provider_context.get("urlscan",{}) or {}
        
        if urlscan:
            summary["providers_seen"].add("urlscan")
            if urlscan.get("urlscan_malicious"): summary["urlscan_hits"] += 1
        
        #---------------------
        # AbuseIPDB
        #---------------------

        abuse = provider_context.get("abuseipdb", {}) or {}
        if abuse:
            summary["providers_seen"].add("abuseipdb")

            if abuse.get("abuse_score", 0) >= 70:
                summary["abuseipdb_hits"] += 1

        #---------------------
        # ANY.RUN
        #---------------------
        anyrun = provider_context.get("anyrun",{}) or {}
        if anyrun:
            summary["providers_seen"].add("anyrun")

            if anyrun.get("status") == "submitted":
                summary["anyrun_submissions"] += 1

        #---------------------
        # Talos/RDAP
        #---------------------
        if provider_context.get("talos"):
            summary["providers_seen"].add("talos")
        
        if provider_context.get("rdap"):
            summary["providers_seen"].add("rdap")
    
    # Convert set -> list for JSON
    summary["providers_seen"]= sorted(summary["providers_seen"])
    return summary

# -----------------------------------------------------------------------------
# Main Analysis Function
# -----------------------------------------------------------------------------

def analyze_email(input_path: str) -> Optional[Dict[str, Any]]:
    """
    Main entry for email analysis.
    Returns a structured dict or None on failure.
    """
    logger.info("========== Analyze request started ==========\n")

    # Resolve file path this code is use to accept either a direct .eml file or a folder containing .eml files (it will pick the newest one).
    eml_path = resolve_eml_path(input_path)
    if not eml_path:
        logger.error("No .eml found for input: %s", input_path)
        return None

    logger.info("searching for Files in path '%s'", input_path) # this code is use to log the input path being analyzed, whether it's a direct .eml file or a folder containing .eml files.
    logger.info("Parsing email from file '%s'\n", eml_path)

    # We parse .eml files using the mailparser Python library. 
    # It converts the raw email file into a structured object from which we can directly read headers, plain body, HTML body, attachments, and other email components. 
    #For HTML-specific analysis, we then use BeautifulSoup.

    try:
        mail = mailparser.parse_from_file(eml_path)
    except Exception:
        logger.critical("Failed to parse EML: %s", eml_path, exc_info=True)
        return None
    
    if not mail or (
        not getattr(mail, "subject", None)
        and not getattr(mail, "headers", None)
        and not getattr(mail, "text_plain", None)
        and not getattr(mail, "text_html", None)
        and not getattr(mail, "attachments", None)
    ):
        logger.error("Parsed email appears empty or malformed: %s", eml_path)
        return None

    # -------------------------------------------------------------------------
    # Headers
    # -------------------------------------------------------------------------
    headers_raw = _headers_as_dict(mail)
    headers_focus = _extract_header_focus(headers_raw)
    mismatch_flags = _header_mismatch_flags(headers_raw)

    #-------------------------------------------------------------------------
    # Extract sender-related domains
    #-------------------------------------------------------------------------

    sender_domains= set()

    if mismatch_flags.get("from_domain"):
        sender_domains.add(mismatch_flags["from_domain"])
    
    if mismatch_flags.get("reply_to_domain"):
        sender_domains.add(mismatch_flags["reply_to_domain"])

    if mismatch_flags.get("return_path_domain"):
        sender_domains.add(mismatch_flags["return_path_domain"])

    if mismatch_flags.get("sender_domain"):
        sender_domains.add(mismatch_flags["sender_domain"])
                          
    received = _extract_received_hops(mail)
    auth_results = _get_header(headers_raw, "Authentication-Results")
    
    decoded_subject = decode_mime_header(getattr(mail, "subject", ""))
    subject_analysis = analyze_subject_threat(decoded_subject)


    # -------------------------------------------------------------------------
    # Body
    # -------------------------------------------------------------------------
    text_plain = "\n".join(mail.text_plain) if getattr(mail, "text_plain", None) else ""
    text_html = "\n".join(mail.text_html) if getattr(mail, "text_html", None) else ""

    # -------------------------------------------------------------------------
    # URLs
    # -------------------------------------------------------------------------
    urls: Set[str] = set()
    urls.update(extract_urls_from_text(text_plain))
    urls.update(extract_urls_from_html(text_html))
    urls_sorted = sorted(urls)

    # Full URL details go to file logs only
    logger.debug("URLs extracted: %d", len(urls_sorted))
    for u in urls_sorted[:200]:
        logger.debug("URL: %s", u)

    # -------------------------------------------------------------------------
    # Hidden HTML
    # -------------------------------------------------------------------------
    hidden_count = find_hidden_elements(text_html)
    if hidden_count > 0:
        logger.warning("Hidden HTML elements detected: %d", hidden_count)

    # -------------------------------------------------------------------------
    # Advanced IOC analysis (VT / whitelist / blocklist)
    # -------------------------------------------------------------------------
    html_text_for_iocs = BeautifulSoup(text_html, "html.parser").get_text(" ", strip=True) if text_html else ""

    #----------------------------------------------------------
    # Build full IOC input text by combining:
    #----------------------------------------------------------

    combined_text = ""

    # - plain text body
    combined_text += (text_plain or "") + "\n"

    # - visible text extracted from HTML body
    combined_text += (html_text_for_iocs or "") + "\n"

    #Critical fix -> inject extracted URLs back into the text for IOC analysis, as many IOCs are URL-based and may not be fully captured in the plain/HTML text alone.
    combined_text += "\n".join(urls_sorted) + "\n"
    
    #  ADD Header : Optional but HIGH VALUE: We could also consider adding header values to the combined text for IOC analysis, as sometimes IOCs can be found in headers (e.g. X-Originating-IP, User-Agent, etc.).
    combined_text += str(headers_raw) + "\n"
    osint_summary: Dict[str, Any] = {}
    defanged_ioc_text = ""
    scored = {}

    try:
        ioc_engine = IOCAnalyzer(
            vt_api_key="",  # uses .env VT_API_KEY automatically if present
            whitelist_path=os.path.join(PROJECT_ROOT, "config", "whitelist.xlsx"),
            blocklist_path=os.path.join(PROJECT_ROOT, "config", "blocklist.xlsx"),
            logger=logger,
        )

        scored = ioc_engine.analyze_text_iocs(combined_text)

        if not scored or "results" not in scored:
            raise Exception("Invalid IOC analyzer output")


        # Keep simple IOC structure for reporter compatibility
        iocs = scored["simple_iocs"]

        # Detailed VT scoring rows for final report
        ioc_scoring = scored["results"]
        defanged_ioc_text = build_defanged_ioc_text(iocs)

        try:
            osint_summary = summarize_osint(ioc_scoring)
        except Exception:
            logger.error("OSINT summary generation failed", exc_info=True)
            osint_summary ={}
        

        logger.info("============================ IOC_REPORT: [!] IOC Extraction Report =========================\n")
        
        logger.warning(
            "IOC counts: ips=%d domains=%d urls=%d hashes=%d",
            iocs["counts"]["ips"],
            iocs["counts"]["domains"],
            iocs["counts"]["urls"],
            iocs["counts"]["hashes"],
        )

        # Full IOC rows in file logs only
        for row in ioc_scoring:
            logger.debug("IOC_SCORE_ROW: %s", row)

    except AnalysisCancelled:
        logger.warning("IOC analysis cancelled by user.")
        iocs = {
            "ips": [], "domains": [], "urls": [], "hashes": [],
            "counts": {"ips": 0, "domains": 0, "urls": 0, "hashes": 0},
            "error": "IOC analysis cancelled"
        }
        ioc_scoring = []

    except Exception:
        logger.error("Advanced IOC analysis failed.", exc_info=True)
        scored = {}
        iocs = {
            "ips": [], "domains": [], "urls": [], "hashes": [],
            "counts": {"ips": 0, "domains": 0, "urls": 0, "hashes": 0},
            "error": "IOC analysis failed"
        }
        ioc_scoring = []

    # -------------------------------------------------------------------------
    # Attachments
    # -------------------------------------------------------------------------

    attachments_info: List[Dict[str, Any]] = []
    attachments = getattr(mail, "attachments", None) or []

    for att in attachments:
        try:
            filename = att.get("filename", "unknown")
            payload = decode_attachment_payload(att.get("payload"))
            if not payload:
                continue

            h = sha256_bytes(payload)
           
            # ==============================
            # ✅ ADD THIS BLOCK HERE
            # ==============================

            vt_hash_result = {
                "vt_malicious": 0,
                "vt_status": "VT unavailable"
            }
            vt_upload_result = None

            if ioc_engine:
                vt_malicious, vt_status = ioc_engine.vt.lookup("hash", h)

                vt_hash_result = {
                    "vt_malicious": vt_malicious,
                    "vt_status": vt_status
                }

                if vt_malicious == 0:
                    vt_upload_result = ioc_engine.vt.submit_file_bytes(filename, payload)

            # ==============================
            # ✅ STORE RESULT
            # ==============================

            attachments_info.append({
                "filename": filename,
                "size": len(payload),
                "sha256": h,
                "vt_hash": vt_hash_result,
                "vt_upload": vt_upload_result
            })

        except Exception:
            logger.error("Attachment processing failed.", exc_info=True)


    logger.info("\n========== Analyze request completed successfully ==========\n")

    #-----------------------------------------------------------------------
    # Email-level Severity scoring based on combined indicators (IOCs, header mismatches, hidden HTML, auth results)
    #-----------------------------------------------------------------------
    
    severity_data = calculate_email_severity_score({
    **{"ioc_scoring": ioc_scoring},
    **{"body_stats": {"hidden_html_count": hidden_count}},
    **{"auth_results": auth_results},
    **{"header_analysis": {"mismatch_flags": mismatch_flags}},
    **{"subject_analysis": subject_analysis},
    })


    # Final output used by mail_reporter.py
    return {
        "input_path": input_path,
        "eml_used": eml_path,
        "subject": safe_str(decoded_subject, 300),

        "from": safe_str(getattr(mail, "from_", ""), 500),
        "to": safe_str(getattr(mail, "to", ""), 500),

        "headers_focus": headers_focus,
        "headers_raw": headers_raw,
        "header_analysis": {
            "received_hop_count": len(received),
            "mismatch_flags": mismatch_flags,
        },
        "received_hops": received,
        "auth_results": safe_str(auth_results, 1000),

        "body_stats": {
            "plain_length": len(text_plain),
            "html_length": len(text_html),
            "hidden_html_count": hidden_count,
        },

        "urls_extracted": urls_sorted,
        "iocs": iocs,
        "attachments": attachments_info,
        "sender_domains": list(sender_domains),

        # IOC scoring section for final reports
        "ioc_scoring": ioc_scoring,
        "osint_summary": osint_summary,

        "campaign": scored.get("campaign", {}),
        "alert": scored.get("alert", {}), 
        
        # Human-readable defanged IOC block for TXT report only
        "defanged_iocs_text": defanged_ioc_text,
        "subject_analysis": subject_analysis,

        # Email-level severity data based on combined indicators
        "email_score": severity_data.get("email_score", 0),
        "email_severity": severity_data.get("email_severity", "Unknown"),
        "email_score_reasons": severity_data.get("email_score_reason"),
    }