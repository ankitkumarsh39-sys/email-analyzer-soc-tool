"""
# analyzer.py

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
import ipaddress
import base64
import gzip
import hashlib
import logging
import zlib
import mailparser
import html as html_lib
import requests

from typing import Optional, Dict, Any, List, Set

# For URL parsing and query extraction
from urllib.parse import (
    urlparse,
    parse_qs,
    unquote
)

from bs4 import BeautifulSoup

from collections import Counter
from email.header import decode_header



# Advanced IOC scoring engine (with VT / whitelist / blocklist)
from ioc_lib.ioc_analyzer import (
    IOCAnalyzer,
    AnalysisCancelled,
    abuseipdb_lookup,
    rdap_lookup_reference,
    talos_lookup_reference,
    urlscan_search_lookup,
)
from email_analyzer.utils.whois_utils import whois_lookup

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

#------------------------------------------------------------------------

#==========================================================================
# Function: clean_html_url

# Purpose:
# Somtimes URLS are extracted with full HTML tags.

# Example:

# INPUT : <a href="https://evil.com/login">Click Here</a>

# Output: https://evil.com/login

# WHY:
# We only want the URL.

# Many threat intelligence providers cannont process HTML tags.

#===========================================================================

def clean_html_url(value):

    # Nothing provided
    if not value:
        return ""
    
    value = str(value).strip()

    try:

        # Parse HTML safely
        soup = BeautifulSoup(value, "html.parser")

        # Look for href link
        tag = soup.find("a", href=True)

        if tag: 

            # Return actual URL
            return tag["href"]

    except Exception:
        pass

    # Return original value if not HTML
    return value

#--------------------------------------------------------------------

# ============================================================
# FUNCTION: normalize_url
#
# Purpose:
# Clean one URL before it goes to wrapper detection,
# IOC extraction, VirusTotal, Talos, URLScan, or reports.
#
# Input:
# Raw URL string. It may contain:
# - HTML anchor tag
# - HTML entities
# - defanged dots like [.]
# - trailing punctuation
#
# Output:
# Clean URL string.
#
# Layman explanation:
# This function turns messy email URLs into a clean URL
# that security tools can understand.
# ============================================================

def normalize_url(url: str) -> str:
    """
    Normalize URL before IOC processing.

    Why:
    - Remove HTML anchor tags
    - Decode HTML entities
    - Remove trailing junk
    """

    if not url:
        return ""

    text = str(url).strip()

    # -------------------------------------------------
    # Extract href directly if a full HTML anchor
    # extract only the href value.
    # -------------------------------------------------
    href_match = re.search(
        r'href="([^"]+)"',
        text,
        re.IGNORECASE
    )

    if href_match:
        text = href_match.group(1)

    # -------------------------------------------------
    # Remove HTML entities
    # -------------------------------------------------
    try:
        import html
        text = html.unescape(text)
    except Exception:
        pass

    # -------------------------------------------------
    # Cleanup common trailing junk
    # -------------------------------------------------
    text = text.strip().strip(').,;"\'')

    return text

# ============================================================
# W3C_SKIP_URLS
#
# Purpose:
# Ignore HTML namespace/schema URLs.
#
# Why:
# Emails often contain technical HTML references like:
# - w3.org XHTML namespace
# - XHTML DTD reference
#
# These are NOT links clicked by users.
# These are NOT useful IOCs.
# ============================================================

W3C_SKIP_URLS = (
    "www.w3.org",
    "w3.org/1999/xhtml",
    "xhtml1-transitional.dtd",
)


# ============================================================
# FUNCTION: should_skip_url
#
# Purpose:
# Decide whether a URL is noise and should not be analyzed.
#
# Input:
# Clean URL string
#
# Output:
# True  = skip this URL
# False = keep this URL
# ============================================================

def should_skip_url(url: str) -> bool:

    if not url:
        return True

    lower_url = str(url).lower()

    return any(
        noise in lower_url
        for noise in W3C_SKIP_URLS
    )


# ============================================================
# FUNCTION: is_http_url
#
# Purpose:
# Check whether a value is a normal http/https URL.
#
# Input:
# Any string
#
# Output:
# True if it starts with http:// or https://
# ============================================================

def is_http_url(value: str) -> bool:

    if not value:
        return False

    value = normalize_url(value)

    return value.lower().startswith(
        (
            "http://",
            "https://"
        )
    )

# ============================================================
# Known URL wrapper / tracking providers
#
# Purpose:
# Identify security or marketing systems that rewrite URLs.
#
# Why:
# We want to know whether a URL is the real destination
# or only a wrapper/tracking URL.
# ============================================================

KNOWN_WRAPPERS = {
    "safelinks.protection.outlook.com": "Microsoft Safe Links",
    "urldefense.proofpoint.com": "Proofpoint",
    "protect-us.mimecast.com": "Mimecast",
    "linkprotect.cudasvc.com": "Barracuda",
    "webdefence.global.blackspider.com": "MailControl / WebDefence",
    "mailcontrol.com": "MailControl",
    "click.momence.com": "Momence Tracking",
    "unsubscribe.momence.com": "Momence Unsubscribe",
}

WRAPPER_PARAMS = [
    "url",
    "u",
    "q",
    "target",
    "redirect",
    "destination",
    "dest",
    "link",
    "next",
    "return",
    "to",
]


# ============================================================
# FUNCTION: _decode_wrapper_value
#
# Purpose:
# Try to recover a real destination URL from a wrapper value.
#
# Input:
# A wrapper parameter value such as:
# - url=https://example.com
# - u=https-3A__example.com
# - q=AXic... compressed payload
#
# Output:
# Recovered URL or None.
#
# Layman explanation:
# Some wrappers hide the real URL directly.
# Some encode it.
# Some compress it.
# This function tries each method safely.
# ============================================================

def _decode_wrapper_value(value: Any) -> Optional[str]:

    if value is None:
        return None

    if isinstance(value, (list, tuple)):
        for item in value:
            decoded = _decode_wrapper_value(item)
            if decoded:
                return decoded
        return None

    candidate = normalize_url(str(value))

    if not candidate:
        return None

    # Try repeated URL decoding.
    # Example:
    # https%3A%2F%2Fexample.com
    # becomes:
    # https://example.com
    for _ in range(5):
        decoded_candidate = unquote(candidate)

        if decoded_candidate == candidate:
            break

        candidate = normalize_url(decoded_candidate)

    # Proofpoint sometimes represents ":" and "/" differently.
    # Example:
    # https-3A__example.com_login
    # becomes:
    # https://example.com/login
    proofpoint_candidate = (
        candidate
        .replace("-3A__", "://")
        .replace("-3a__", "://")
        .replace("_", "/")
    )

    if is_http_url(proofpoint_candidate):
        return normalize_url(proofpoint_candidate)

    if is_http_url(candidate):
        return normalize_url(candidate)

    # Try Base64 / URL-safe Base64 decoding.
    # Some wrappers store the destination in encoded form.
    decoded_bytes = None

    try:
        padded = candidate + "=" * (-len(candidate) % 4)

        decoded_bytes = base64.urlsafe_b64decode(
            padded.encode("utf-8")
        )

    except Exception:
        decoded_bytes = None

    if decoded_bytes:

        # Try plain text first
        try:
            decoded_text = decoded_bytes.decode(
                "utf-8",
                errors="ignore"
            )

            decoded_text = normalize_url(decoded_text)

            if is_http_url(decoded_text):
                return decoded_text

            match = URL_REGEX.search(decoded_text)

            if match:
                return normalize_url(match.group(0))

        except Exception:
            pass

        # Try zlib decompression.
        # MailControl URLWrap often needs this.
        zlib_candidates = [
            decoded_bytes,
            decoded_bytes[1:],
            decoded_bytes[2:],
            decoded_bytes[3:],
        ]

        for blob in zlib_candidates:

            if not blob:
                continue

            try:
                decompressed = zlib.decompress(blob)

                decompressed_text = decompressed.decode(
                    "utf-8",
                    errors="ignore"
                )

                match = URL_REGEX.search(decompressed_text)

                if match:
                    return normalize_url(match.group(0))

            except Exception:
                continue

        # Try gzip decompression.
        try:
            decompressed = gzip.decompress(decoded_bytes)

            decompressed_text = decompressed.decode(
                "utf-8",
                errors="ignore"
            )

            match = URL_REGEX.search(decompressed_text)

            if match:
                return normalize_url(match.group(0))

        except Exception:
            pass

    return None


def detect_wrapped_url(url: str) -> Dict[str, Any]:
    """
    Purpose: Detect whether the provided URL appears to be rewritten by a known
             email security wrapper service.
    Input: url (str)
    Output: dict with keys: wrapped (bool), provider (str|None), wrapper_domain (str|None)
    """

    try:
        parsed = urlparse(url)
        host = (parsed.netloc or "").lower()

        # Match known exact mappings first
        for wrapper_domain, provider in KNOWN_WRAPPERS.items():
            if wrapper_domain in host:
                return {"wrapped": True, "provider": provider, "wrapper_domain": host}

        # Heuristic tokens
        heuristic_tokens = ("safelink", "proofpoint", "mimecast", "mailcontrol", "urldefense", "cudasvc", "protect", "linkprotect", "wrap")
        if any(token in host for token in heuristic_tokens):
            return {"wrapped": True, "provider": host or "Unknown Wrapper", "wrapper_domain": host}

        # If query contains common wrapper params, consider it wrapped
        params = parse_qs(parsed.query, keep_blank_values=True)
        if any(param in params for param in WRAPPER_PARAMS):
            return {"wrapped": True, "provider": host or "Unknown Wrapper", "wrapper_domain": host}

    except Exception:
        logger.debug("detect_wrapped_url failed for %s", url, exc_info=True)

    return {"wrapped": False, "provider": None, "wrapper_domain": None}


"""
    Recover original URL from wrapper parameters.

    Example:
        https://safelinks...?url=https://evil.com

    Returns:
        https://evil.com
"""

def extract_embedded_url(url: str) -> Optional[str]:
    """
    Purpose: Recover original destination URL from known wrapper encodings.
    Input: url (str) - possibly rewritten by a wrapper
    Output: decoded destination URL (str) or None
    """
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        # 1) Query-parameter based wrappers (e.g. ?url=..., ?u=...)
        for parameter in WRAPPER_PARAMS:
            if parameter not in params:
                continue
            for value in params[parameter]:
                decoded = _decode_wrapper_value(value)
                if decoded:
                    return decoded

        # 2) Path-style wrappers: Mimecast often uses /s/<dest>, Barracuda/others may use /l/ or /web/redirect
        path = (parsed.path or "").lstrip("/")
        path_candidates = []
        if path.startswith("s/"):
            path_candidates.append(path[2:])
        if path.startswith("l/"):
            path_candidates.append(path[2:])
            
        # capture patterns like /web/Redirect?u=<url>
        if "/web/Redirect" in path or "/web/rewrite" in path:
            # fallback to checking query params for known keys
            for parameter in WRAPPER_PARAMS:
                if parameter in params:
                    for value in params[parameter]:
                        decoded = _decode_wrapper_value(value)
                        if decoded:
                            return decoded

        for candidate in path_candidates:
            candidate = candidate.strip().strip('"\'<>')
            # If candidate itself contains an encoded URL (e.g. percent-encoded), unquote and test
            candidate_unq = unquote(candidate)
            if candidate_unq.startswith(("http://", "https://")):
                return candidate_unq

        # 3) Sometimes the full destination is present in entire query string
        entire_q = parsed.query or ""
        decoded_entire = _decode_wrapper_value(entire_q)
        if decoded_entire and decoded_entire.startswith(("http://", "https://")):
            return decoded_entire

    except Exception:
        logger.debug("extract_embedded_url failed for %s", url, exc_info=True)

    return None


def unwrap_url(url: str) -> Dict[str, Any]:
    """
    Purpose: Produce a standardized wrapper investigation result for one URL.
    Input: url (str)
    Output: dict with keys: wrapped, provider, wrapped_url, decoded_url, decode_success, wrapper_domain, final_ioc_url
    Rules: final_ioc_url = decoded_url if present, else wrapped_url
    """

    wrapper_info = detect_wrapped_url(url)

    decoded = extract_embedded_url(url) if wrapper_info.get("wrapped") else None

    final_ioc = decoded if decoded else url

    return {
        "wrapped": bool(wrapper_info.get("wrapped")),
        "provider": wrapper_info.get("provider"),
        "wrapped_url": url,
        "decoded_url": decoded,
        "decode_success": bool(decoded),
        "wrapper_domain": wrapper_info.get("wrapper_domain"),
        "final_ioc_url": final_ioc,
    }


# -------------------------------------------------------------------------
# Maintenance: Placeholder intelligence engine stubs
# The project requires multiple passive/active intelligence modules.
# These stubs provide stable return shapes so the UI/reporting code can
# render consistent fields until proper integrations are implemented.
# Add real provider lookups (whois, ssl, urlscan, passive DNS, MX lookups)
# when integrating external services.
# -------------------------------------------------------------------------
def whois_lookup(domain: str) -> Dict[str, Any]:
    """Return minimal WHOIS-like data for reporting; stub for integration."""
    if not domain:
        return {}
    return {
        "registrar": "",
        "creation_date": None,
        "updated_date": None,
        "expiry_date": None,
        "age_days": None,
        "country": "",
        "organization": "",
        "dnssec": None,
        "status": "",
        "nameservers": [],
        "ips": [],
    }


def ssl_intelligence(host: str) -> Dict[str, Any]:
    """Stub for SSL certificate intelligence (issuer, valid_from, valid_to)."""
    return {}


def redirect_chain(url: str) -> Dict[str, Any]:
    """Stub to return redirect chain information for a URL."""
    return {}


def brand_impersonation_check(url: str, text: str = "") -> Dict[str, Any]:
    """Stub for brand impersonation heuristics (logos, domains, similarity)."""
    return {}


def qr_phishing_check(image_bytes: bytes) -> Dict[str, Any]:
    """Stub for QR code detection & analysis."""
    return {}


def homograph_detection(domain: str) -> Dict[str, Any]:
    """Stub for homograph (IDN) detection and similarity scoring."""
    return {}


def mx_intelligence(domain: str) -> Dict[str, Any]:
    """Stub for MX-host analysis (mx hosts, ASNs, hosting provider)."""
    return {}


def infrastructure_reuse_check(value: str) -> Dict[str, Any]:
    """Stub to detect reuse of hosting/infrastructure across IOCs."""
    return {}


def passive_dns_lookup(domain: str) -> Dict[str, Any]:
    """Stub for passive DNS aggregation results."""
    return {}

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

    # Extract href links but only keep http(s) targets. Avoid javascript:, mailto:, anchors, or malformed hrefs.
    for a in soup.find_all("a", href=True):
        href = a.get("href") or ""
        if not href:
            continue
        candidate = normalize_url(href)
        if candidate and candidate.lower().startswith(("http://", "https://")):
            urls.add(candidate)

    # Extract img src links (useful for tracking pixels)
    for img in soup.find_all("img", src=True):
        src = img.get("src") or ""
        candidate = normalize_url(src)
        if candidate and candidate.lower().startswith(("http://", "https://")):
            urls.add(candidate)

    # Extract raw URLs from HTML content itself
    for u in URL_REGEX.findall(html):
        candidate = normalize_url(u)
        if candidate and candidate.lower().startswith(("http://", "https://")):
            urls.add(candidate)

    return sorted(u for u in urls if u)

#----------------------------------------------------------------
def extract_urls_from_headers(headers: Dict[str, Any]) -> List:
    """
    Extract http/https URLs from email headers safely.
    Why:
    - mailparser exposes headers, but does not create a dedicated header URL List.
    - This avoids feeding full raw header dict strings into IOC extraction, which caused false-positive domains like "header.from" and "smtp.mailfrom".
    """

    if not headers:
        return []

    urls: Set[str] = set()

    for key, value in headers.items():
        if value is None:
            continue

        # Convert list/tuple/dict/header values into searchable text safely.
        if isinstance(value, (list, tuple, dict)):
            text = str(value)
        else:
            text = str(value)

        for u in URL_REGEX.findall(text):
            clean_url = normalize_url(u)
            if clean_url and clean_url.lower().startswith(("http://", "https://")):
                urls.add(clean_url)

    return sorted(urls)

#------------------------------------------------------------------------------------

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


def _dns_record_lookup(name: str, record_type: str) -> Dict[str, Any]:
    """Fetch one DNS record set through Google's JSON DNS endpoint."""
    try:
        response = requests.get(
            "https://dns.google/resolve",
            params={"name": name, "type": record_type},
            headers={"Accept": "application/dns-json"},
            timeout=5,
        )
        if response.status_code != 200:
            status = f"failed_{response.status_code}"
            logger.warning("Sender DNS lookup failed for %s %s: %s", name, record_type, status)
            return {"status": status, "records": []}

        payload = response.json()
        if not isinstance(payload, dict):
            logger.warning("Sender DNS lookup returned invalid data for %s %s", name, record_type)
            return {"status": "invalid_response", "records": []}
        answers = payload.get("Answer", []) or []
        records = [
            str(answer.get("data", "")).strip('"')
            for answer in answers
            if isinstance(answer, dict) and answer.get("data")
        ]
        if records:
            return {"status": "ok", "records": records}
        if payload.get("Status") == 3:
            return {"status": "nxdomain", "records": []}
        return {"status": "no_records", "records": []}
    except requests.RequestException as exc:
        logger.warning("Sender DNS lookup failed for %s %s: %s", name, record_type, exc)
        return {"status": "error", "error": str(exc), "records": []}
    except ValueError as exc:
        logger.warning("Sender DNS response was invalid for %s %s: %s", name, record_type, exc)
        return {"status": "error", "error": f"Invalid DNS response: {exc}", "records": []}


def analyze_sender_intelligence(
    headers: Dict[str, Any],
    mismatch_flags: Dict[str, Any],
    received_hops: List[Dict[str, Any]],
    auth_results: Any,
    ioc_engine: Optional[IOCAnalyzer],
    ioc_scoring: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Collect sender domains and IP evidence, reusing IOC analysis results."""
    domain_roles: Dict[str, List[str]] = {}
    sender_addresses: Dict[str, List[str]] = {}
    for header_name, role in (
        ("From", "From"),
        ("Reply-To", "Reply-To"),
        ("Return-Path", "Return-Path"),
        ("Sender", "Sender"),
    ):
        raw_value = _get_header(headers, header_name)
        values = raw_value if isinstance(raw_value, (list, tuple)) else [raw_value]
        values = [str(value) for value in values if value]
        sender_addresses[role] = values
        domains = re.findall(
            r"(?i)[A-Z0-9._%+\-]+@((?:[A-Z0-9-]+\.)+[A-Z]{2,63})",
            "\n".join(values),
        )
        if not domains:
            fallback = mismatch_flags.get({
                "From": "from_domain",
                "Reply-To": "reply_to_domain",
                "Return-Path": "return_path_domain",
                "Sender": "sender_domain",
            }[header_name])
            domains = [fallback] if fallback else []
        for domain in domains:
            normalized = str(domain).lower().rstrip(".")
            domain_roles.setdefault(normalized, [])
            if role not in domain_roles[normalized]:
                domain_roles[normalized].append(role)

    sender_ip_sources: Dict[str, List[str]] = {}
    for header_name in (
        "Received",
        "X-Originating-IP",
        "X-Sender-IP",
        "X-Client-IP",
        "Authentication-Results",
        "Received-SPF",
    ):
        value = _get_header(headers, header_name)
        if isinstance(value, (list, tuple)):
            values = [str(part) for part in value if part]
        elif value:
            values = [str(value)]
        else:
            values = []
        if values:
            sender_ip_sources[header_name] = values
    for index, hop in enumerate(received_hops or []):
        if isinstance(hop, dict) and hop.get("raw"):
            sender_ip_sources.setdefault("Received", []).append(str(hop["raw"]))

    sender_ips = set()
    ip_pattern = re.compile(
        r"(?<![\w])(?:\d{1,3}(?:\.\d{1,3}){3}|(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f:.]*)(?![\w])"
    )
    ip_sources: Dict[str, List[str]] = {}
    for source, values in sender_ip_sources.items():
        for candidate in ip_pattern.findall("\n".join(values)):
            try:
                sender_ip = str(ipaddress.ip_address(candidate.strip("[]")))
                sender_ips.add(sender_ip)
                ip_sources.setdefault(sender_ip, [])
                if source not in ip_sources[sender_ip]:
                    ip_sources[sender_ip].append(source)
            except ValueError:
                continue

    received_spf = _get_header(headers, "Received-SPF")
    authentication_text = f"{auth_results or ''} {received_spf or ''}".lower()
    spf_auth = (
        "pass" if (
            re.search(r"\bspf\s*=\s*pass\b", authentication_text)
            or re.match(r"\s*pass\b", str(received_spf or ""), re.IGNORECASE)
        )
        else "fail" if (
            re.search(r"\bspf\s*=\s*(?:fail|softfail|permerror)\b", authentication_text)
            or re.match(r"\s*(?:fail|softfail|permerror)\b", str(received_spf or ""), re.IGNORECASE)
        )
        else "unknown"
    )
    dmarc_auth = (
        "pass" if re.search(r"\bdmarc\s*=\s*pass\b", authentication_text)
        else "fail" if re.search(r"\bdmarc\s*=\s*(?:fail|permerror)\b", authentication_text)
        else "unknown"
    )

    existing_iocs = {
        (str(item.get("ioc_type", "")).lower(), str(item.get("normalized", "")).lower()): item
        for item in (ioc_scoring or [])
    }
    lookup_cache: Dict[tuple[str, str], Dict[str, Any]] = {}
    abuseipdb_cache: Dict[str, Dict[str, Any]] = {}

    def lookup_ioc(value: str, ioc_type: str) -> Dict[str, Any]:
        key = (ioc_type, value.lower())
        if key in lookup_cache:
            return lookup_cache[key]

        existing = existing_iocs.get(key)
        if existing:
            result = {
                "virustotal": {
                    "status": existing.get("vt_status", "unavailable"),
                    "malicious": existing.get("vt_malicious", 0),
                },
                "provider_context": existing.get("provider_context", {}) or {},
                "whitelisted": existing.get("is_whitelisted"),
                "blocklisted": existing.get("is_blocklisted"),
            }
            lookup_cache[key] = result
            return result

        if ioc_engine is None:
            result = {
                "virustotal": {"status": "IOC analysis unavailable", "malicious": 0},
                "provider_context": {},
                "whitelisted": None,
                "blocklisted": None,
            }
            lookup_cache[key] = result
            return result
        try:
            record = ioc_engine.enrich_ioc(value, ioc_type)
            result = {
                "virustotal": {
                    "status": record.vt_status,
                    "malicious": record.vt_malicious,
                },
                "provider_context": record.provider_context or {},
                "whitelisted": record.is_whitelisted,
                "blocklisted": record.is_blocklisted,
            }
        except Exception as exc:
            logger.warning("Sender IOC lookup failed for %s %s: %s", ioc_type, value, exc)
            result = {
                "virustotal": {"status": "lookup_error", "malicious": 0},
                "provider_context": {},
                "whitelisted": None,
                "blocklisted": None,
            }
        lookup_cache[key] = result
        return result

    def lookup_abuseipdb(ip: str, providers: Dict[str, Any]) -> Dict[str, Any]:
        normalized_ip = ip.lower()
        if normalized_ip not in abuseipdb_cache:
            result = providers.get("abuseipdb") or {}
            if not result:
                try:
                    result = abuseipdb_lookup(ip)
                except Exception as exc:
                    logger.warning("AbuseIPDB lookup failed for sender IP %s: %s", ip, exc)
                    result = {"status": "error", "error": str(exc)}
            if result.get("status") != "ok":
                logger.warning(
                    "AbuseIPDB lookup unavailable for sender IP %s: %s",
                    ip,
                    result.get("status", "no_status"),
                )
            abuseipdb_cache[normalized_ip] = result
        return abuseipdb_cache[normalized_ip]

    urlscan_cache: Dict[tuple[str, str], Dict[str, Any]] = {}

    def search_urlscan(value: str, search_type: str) -> Dict[str, Any]:
        key = (search_type, value.lower())
        if key not in urlscan_cache:
            urlscan_cache[key] = urlscan_search_lookup(value, search_type)
        return urlscan_cache[key]

    domains_out = []
    reasons = []
    indicator_scores: Dict[str, int] = {}
    low_risk_domains = []
    mismatch_detected = any(
        mismatch_flags.get(flag)
        for flag in ("reply_to_mismatch", "return_path_mismatch", "sender_mismatch")
    )

    for domain, roles in sorted(domain_roles.items()):
        indicator = lookup_ioc(domain, "domain")
        providers = indicator["provider_context"]
        whois = providers.get("whois") or {}
        if not whois:
            try:
                whois = whois_lookup(domain)
            except Exception:
                logger.exception("WHOIS lookup failed for sender domain %s", domain)
                whois = {"status": "error"}
        if whois.get("status") != "ok":
            logger.warning("WHOIS lookup unavailable for sender domain %s: %s", domain, whois.get("status", "no_status"))
        dns = {
            "a": _dns_record_lookup(domain, "A"),
            "aaaa": _dns_record_lookup(domain, "AAAA"),
            "mx": _dns_record_lookup(domain, "MX"),
            "txt": _dns_record_lookup(domain, "TXT"),
            "dmarc": _dns_record_lookup(f"_dmarc.{domain}", "TXT"),
        }
        spf_records = [
            record for record in dns["txt"]["records"]
            if record.lower().startswith("v=spf1")
        ]
        dmarc_records = [
            record for record in dns["dmarc"]["records"]
            if record.lower().startswith("v=dmarc1")
        ]
        spf_status = (
            "found" if spf_records else
            "not_found" if dns["txt"]["status"] in {"ok", "no_records"} else
            dns["txt"]["status"]
        )
        dmarc_status = (
            "found" if dmarc_records else
            "not_found" if dns["dmarc"]["status"] in {"ok", "no_records"} else
            dns["dmarc"]["status"]
        )
        resolved_ips = sorted(set(
            ip
            for record_type in ("a", "aaaa")
            for ip in dns[record_type]["records"]
        ))
        resolved_ip_intelligence = []
        resolved_ips_low_risk = True
        for resolved_ip in resolved_ips:
            ip_indicator = lookup_ioc(resolved_ip, "ip")
            ip_providers = ip_indicator["provider_context"]
            ip_abuse = lookup_abuseipdb(resolved_ip, ip_providers)
            ip_risk_score = 0
            ip_reasons = []
            if ip_indicator["blocklisted"]:
                ip_risk_score += 100
                ip_reasons.append("Resolved IP address matches the blocklist.")
            if int(ip_indicator["virustotal"].get("malicious", 0) or 0) > 0:
                ip_risk_score += 30
                ip_reasons.append("VirusTotal reports malicious activity for the resolved IP.")
            try:
                ip_abuse_score = int(ip_abuse.get("abuse_score", 0) or 0)
            except (TypeError, ValueError):
                ip_abuse_score = 0
            if ip_abuse_score >= 70:
                ip_risk_score += 25
                ip_reasons.append(f"AbuseIPDB confidence score is {ip_abuse_score}.")
            if ip_indicator["whitelisted"]:
                ip_reasons.append("Resolved IP address matches the whitelist.")
            reasons.extend(f"{resolved_ip}: {reason}" for reason in ip_reasons)
            indicator_scores[resolved_ip] = max(
                indicator_scores.get(resolved_ip, 0), min(100, ip_risk_score)
            )
            resolved_ips_low_risk = (
                resolved_ips_low_risk
                and ip_indicator["virustotal"].get("status") == "0 hits"
                and ip_abuse.get("status") == "ok"
                and ip_abuse_score < 70
                and not ip_indicator["blocklisted"]
            )
            resolved_ip_intelligence.append({
                "ip": resolved_ip,
                "virustotal": ip_indicator["virustotal"],
                "abuseipdb": ip_abuse,
                "talos": ip_providers.get("talos", {}) or {},
                "urlscan_search": search_urlscan(resolved_ip, "ip"),
                "whitelisted": ip_indicator["whitelisted"],
                "blocklisted": ip_indicator["blocklisted"],
                "risk_score": min(100, ip_risk_score),
                "reasons": ip_reasons,
            })

        urlscan_search = search_urlscan(domain, "domain")
        age_days = whois.get("age_days")
        score = 0
        domain_reasons = []
        if indicator["blocklisted"]:
            score += 100
            domain_reasons.append("Domain matches the blocklist.")
        if int(indicator["virustotal"].get("malicious", 0) or 0) > 0:
            score += 30
            domain_reasons.append(
                f"VirusTotal reports {indicator['virustotal']['malicious']} malicious detection(s)."
            )
        if mismatch_detected:
            score += 15
            domain_reasons.append("Sender header domains do not align.")
        try:
            age_days = int(age_days) if age_days is not None else None
        except (TypeError, ValueError):
            age_days = None
        if age_days is not None and age_days < 30:
            score += 20
            domain_reasons.append(f"Domain is newly registered ({age_days} days old).")
        elif age_days is not None and age_days < 90:
            score += 10
            domain_reasons.append(f"Domain is recently registered ({age_days} days old).")
        if dns["txt"]["status"] in {"ok", "no_records"} and not spf_records:
            score += 8
            domain_reasons.append("No SPF record was found.")
        if dns["dmarc"]["status"] in {"ok", "no_records"} and not dmarc_records:
            score += 8
            domain_reasons.append("No DMARC record was found.")
        if spf_auth == "fail":
            score += 10
            domain_reasons.append("SPF authentication failed.")
        if dmarc_auth == "fail":
            score += 15
            domain_reasons.append("DMARC authentication failed.")
        if indicator["whitelisted"]:
            domain_reasons.append("Domain matches the whitelist.")
        if not domain_reasons:
            domain_reasons.append("No domain risk indicators were confirmed.")

        indicator_scores[domain] = min(100, score)
        low_risk_domains.append(
            age_days is not None
            and age_days >= 90
            and bool(spf_records)
            and bool(dmarc_records)
            and spf_auth == "pass"
            and dmarc_auth == "pass"
            and indicator["virustotal"].get("status") == "0 hits"
            and not indicator["blocklisted"]
            and resolved_ips_low_risk
        )
        reasons.extend(f"{domain}: {reason}" for reason in domain_reasons)
        domains_out.append({
            "domain": domain,
            "headers": roles,
            "addresses": {
                role: sender_addresses.get(role, [])
                for role in roles
            },
            "whois": whois,
            "domain_age_days": age_days,
            "rdap": providers.get("rdap", {}) or rdap_lookup_reference(domain),
            "dns": dns,
            "spf_records": spf_records,
            "spf_status": spf_status,
            "dmarc_records": dmarc_records,
            "dmarc_status": dmarc_status,
            "resolved_ips": resolved_ips,
            "resolved_ip_intelligence": resolved_ip_intelligence,
            "virustotal": indicator["virustotal"],
            "talos": providers.get("talos", {}) or talos_lookup_reference(domain),
            "urlscan_search": urlscan_search,
            "whitelisted": indicator["whitelisted"],
            "blocklisted": indicator["blocklisted"],
            "risk_score": min(100, score + sum(
                item["risk_score"] for item in resolved_ip_intelligence
            )),
            "reasons": domain_reasons,
        })

    ips_out = []
    ip_scores = []
    low_risk_ips = []
    for ip in sorted(sender_ips):
        indicator = lookup_ioc(ip, "ip")
        providers = indicator["provider_context"]
        abuseipdb = lookup_abuseipdb(ip, providers)
        score = 0
        ip_reasons = []
        if indicator["blocklisted"]:
            score += 100
            ip_reasons.append("IP address matches the blocklist.")
        if int(indicator["virustotal"].get("malicious", 0) or 0) > 0:
            score += 30
            ip_reasons.append(
                f"VirusTotal reports {indicator['virustotal']['malicious']} malicious detection(s)."
            )
        try:
            abuse_score = int(abuseipdb.get("abuse_score", 0) or 0)
        except (TypeError, ValueError):
            abuse_score = 0
        if abuse_score >= 70:
            score += 25
            ip_reasons.append(f"AbuseIPDB confidence score is {abuse_score}.")
        if indicator["whitelisted"]:
            ip_reasons.append("IP address matches the whitelist.")
        if not ip_reasons:
            ip_reasons.append("No IP risk indicators were confirmed.")
        indicator_scores[ip] = max(indicator_scores.get(ip, 0), min(100, score))
        low_risk_ips.append(
            indicator["virustotal"].get("status") == "0 hits"
            and abuseipdb.get("status") == "ok"
            and abuse_score < 70
            and not indicator["blocklisted"]
        )
        reasons.extend(f"{ip}: {reason}" for reason in ip_reasons)
        ips_out.append({
            "ip": ip,
            "sources": ip_sources.get(ip, []),
            "virustotal": indicator["virustotal"],
            "abuseipdb": abuseipdb,
            "talos": providers.get("talos", {}) or talos_lookup_reference(ip),
            "urlscan_search": search_urlscan(ip, "ip"),
            "whitelisted": indicator["whitelisted"],
            "blocklisted": indicator["blocklisted"],
            "risk_score": min(100, score),
            "reasons": ip_reasons,
        })

    risk_score = min(100, sum(indicator_scores.values()))
    if risk_score >= 60:
        verdict = "High Risk"
    elif risk_score >= 30:
        verdict = "Medium Risk"
    elif risk_score > 0:
        verdict = "Low Risk"
    elif (
        domains_out
        and all(low_risk_domains)
        and all(low_risk_ips)
        and not mismatch_detected
    ):
        verdict = "Low Risk"
    else:
        verdict = "Needs Review"
        reasons.append("Insufficient independent evidence to confirm a low-risk sender.")

    return {
        "risk_score": risk_score,
        "verdict": verdict,
        "reasons": reasons,
        "authentication": {"spf": spf_auth, "dmarc": dmarc_auth},
        "sender_addresses": sender_addresses,
        "domains": domains_out,
        "ips": ips_out,
    }


#---------------------------------------------------------------------

def _extract_header_focus(headers: Dict[str, Any]) -> Dict[str, Any]:
    """Keep the most important headers for human-readable reporting."""

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

#----------------------------------------------------------------------------------------

def analyze_subject_threat(subject: str) -> Dict[str, Any]:
    """Inspect the subject for lightweight phishing indicators."""

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

def calculate_email_severity_score(email_data: Dict[str, Any]) -> Dict[str, Any]:
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
        # Talos/RDAP
        #---------------------
        if provider_context.get("talos"):
            summary["providers_seen"].add("talos")
        
        if provider_context.get("rdap"):
            summary["providers_seen"].add("rdap")
    
    # Convert set -> list for JSON
    summary["providers_seen"]= sorted(summary["providers_seen"])
    return summary


def reanalyze_ioc_in_email_data(email_data: Dict[str, Any], normalized_value: str) -> Dict[str, Any]:
    """
    Reanalyze a single IOC entry from already-loaded email_data.
    """
    if not email_data or not normalized_value:
        return email_data

    ioc_rows = email_data.get("ioc_scoring", []) or []
    selected_index = None
    selected_item = None

    for idx, item in enumerate(ioc_rows):
        if item.get("normalized") == normalized_value:
            selected_index = idx
            selected_item = item
            break

    if selected_index is None or selected_item is None:
        return email_data

    try:
        ioc_engine = IOCAnalyzer(
            vt_api_key="",
            whitelist_path=os.path.join(PROJECT_ROOT, "config", "whitelist.xlsx"),
            blocklist_path=os.path.join(PROJECT_ROOT, "config", "blocklist.xlsx"),
            logger=logger,
        )

        updated_record = ioc_engine.reanalyze_ioc(selected_item)
        if hasattr(updated_record, "__dict__"):
            updated_item = updated_record.__dict__
        else:
            updated_item = dict(updated_record)

        email_data["ioc_scoring"][selected_index] = updated_item
        email_data["osint_summary"] = summarize_osint(email_data["ioc_scoring"])

        severity_data = calculate_email_severity_score({
            **{"ioc_scoring": email_data.get("ioc_scoring", [])},
            **{"body_stats": email_data.get("body_stats", {})},
            **{"auth_results": email_data.get("auth_results", "")},
            **{"header_analysis": email_data.get("header_analysis", {})},
            **{"subject_analysis": email_data.get("subject_analysis", {})},
        })

        email_data["email_score"] = severity_data.get("email_score", 0)
        email_data["email_severity"] = severity_data.get("email_severity", "Unknown")
        email_data["email_score_reasons"] = severity_data.get("email_score_reason")

    except Exception:
        logger.error("Failed to reanalyze IOC: %s", normalized_value, exc_info=True)

    return email_data

# -----------------------------------------------------------------------------
# Main Analysis Function
# -----------------------------------------------------------------------------
def build_targeted_header_ioc_text(
    headers_raw: Dict[str, Any],
    mismatch_flags: Dict[str, Any],
    auth_results: Any,
    received_hops: List[Dict[str, Any]],
) -> str:
    """
    Build a clean IOC-only text block from header data.

    Why this exists:
    - avoid feeding raw Python dict/list string representations into IOC extraction
    - keep real header-derived IOCs (domains, IPs, auth text)
    - avoid false positives like:
        header.from
        smtp.mailfrom
        soc.alert
        ankit.gp.kumar
    """
    parts: List[str] = []

    # Sender/auth mismatch domains
    for key in ("from_domain", "reply_to_domain", "return_path_domain", "sender_domain"):
        value = (mismatch_flags or {}).get(key)
        if value:
            parts.append(str(value))

    # Authentication-Results text can still contain useful evidence
    if auth_results:
        parts.append(str(auth_results))

    # Selected header values only (not all raw headers)
    selected_headers = [
        "From", "Reply-To", "Return-Path", "Sender",
        "Received-SPF", "Authentication-Results", "X-Originating-IP"
    ]

    for header_name in selected_headers:
        header_value = _get_header(headers_raw, header_name)
        if header_value:
            parts.append(str(header_value))

    # Received hops - extract only raw hop strings if available
    for hop in received_hops or []:
        if isinstance(hop, dict):
            raw = hop.get("raw")
            if raw:
                parts.append(str(raw))

    return "\n".join(parts)


#----------------------------------------------------------------------------------------

# this function defines the main entry point for analyzing an email.
# It takes an input path (which can be a direct .eml file or a folder containing .eml files) and an optional flag to force reanalysis of IOCs.
#  The function returns a structured dictionary containing the analysis results or None if the analysis fails.

def analyze_email(input_path: str, force_reanalyze_iocs: bool = False) -> Optional[Dict[str, Any]]:
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
    # Pre-collect attachment hashes BEFORE IOC analysis
    #
    # Why this is needed:
    # - The IOC analyzer currently extracts/scorers hashes from text input
    # - If attachment SHA256 stays only in attachments_info later,
    #   it will not appear in email_data["ioc_scoring"]
    # -------------------------------------------------------------------------
    attachments = getattr(mail, "attachments", None) or []
    attachment_hashes: List[str] = []

    for att in attachments:
        try:
            payload = decode_attachment_payload(att.get("payload"))
            if not payload:
                continue

            h = sha256_bytes(payload)
            if h:
                attachment_hashes.append(h)

        except Exception:
            logger.error("Pre-attachment hash collection failed.", exc_info=True)

# -------------------------------------------------------------------------
# URL Extraction + Wrapper Recovery
#
# Collect URLs from:
# - plain text
# - HTML
# - headers
#
# Then:
# - detect wrapper services
# - recover original destination URLs
# - preserve investigation evidence
# -------------------------------------------------------------------------

    urls: Set[str] = set()
    url_evidence: List[Dict[str, Any]] = []

    # ----------------------------------------------------
    # Plain Text URLs
    # ----------------------------------------------------
    for url in extract_urls_from_text(text_plain):

        unwrap_data = unwrap_url(url)

        final_url = (
            unwrap_data["decoded_url"]
            if unwrap_data["decode_success"]
            else unwrap_data["wrapped_url"]
        )

        urls.add(final_url)

        # Maintenance: include `final_ioc_url` so downstream reporters and
        # IOC engines can clearly consume the decoded/final URL.
        url_evidence.append({
            **unwrap_data,
            "source": "plain_text",
            "final_ioc_url": final_url,
        })

    # ----------------------------------------------------
    # HTML URLs
    # ----------------------------------------------------
    for url in extract_urls_from_html(text_html):

        unwrap_data = unwrap_url(url)

        final_url = (
            unwrap_data["decoded_url"]
            if unwrap_data["decode_success"]
            else unwrap_data["wrapped_url"]
        )

        urls.add(final_url)

        # Maintenance: include `final_ioc_url` for HTML-sourced URLs.
        url_evidence.append({
            **unwrap_data,
            "source": "html",
            "final_ioc_url": final_url,
        })

    # ----------------------------------------------------
    # Header URLs
    # ----------------------------------------------------
    for url in extract_urls_from_headers(headers_raw):

        unwrap_data = unwrap_url(url)

        final_url = (
            unwrap_data["decoded_url"]
            if unwrap_data["decode_success"]
            else unwrap_data["wrapped_url"]
        )

        urls.add(final_url)

        # Maintenance: include `final_ioc_url` for header-sourced URLs.
        url_evidence.append({
            **unwrap_data,
            "source": "header",
            "final_ioc_url": final_url,
        })

    urls_sorted = sorted(urls)

    # -------------------------------------------------------------------------
    # Hidden HTML extraction section
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
    combined_text += build_targeted_header_ioc_text(
        headers_raw=headers_raw,
        mismatch_flags=mismatch_flags,
        auth_results=auth_results,
        received_hops=received,
    ) + "\n"

    # Add attachment SHA256 values so they are scored as normal hash IOCs
    
    if attachment_hashes:
        unique_attachment_hashes = sorted(set(attachment_hashes))
        combined_text += "\n".join(unique_attachment_hashes) + "\n"

    osint_summary: Dict[str, Any] = {}
    defanged_ioc_text = ""
    scored = {}

    # Initialize engine reference early so later attachment code can safely check it
    ioc_engine: Optional[IOCAnalyzer] = None

    try:
        ioc_engine = IOCAnalyzer(
            vt_api_key="",  # uses .env VT_API_KEY automatically if present
            whitelist_path=os.path.join(PROJECT_ROOT, "config", "whitelist.xlsx"),
            blocklist_path=os.path.join(PROJECT_ROOT, "config", "blocklist.xlsx"),
            logger=logger,
        )

        scored = ioc_engine.analyze_text_iocs(
            combined_text,
            force_refresh=force_reanalyze_iocs,
        )

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

    # Reuse the IOC results so sender checks do not repeat provider calls.
    try:
        sender_intelligence = analyze_sender_intelligence(
            headers=headers_raw,
            mismatch_flags=mismatch_flags,
            received_hops=received,
            auth_results=auth_results,
            ioc_engine=ioc_engine,
            ioc_scoring=ioc_scoring,
        )
    except Exception as exc:
        logger.error("Sender intelligence analysis failed.", exc_info=True)
        sender_intelligence = {
            "risk_score": 0,
            "verdict": "Needs Review",
            "reasons": ["Sender intelligence analysis failed."],
            "domains": [],
            "ips": [],
            "error": str(exc),
        }

    # -------------------------------------------------------------------------
    # Attachments
    # -------------------------------------------------------------------------

    attachments_info: List[Dict[str, Any]] = []

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

            if ioc_engine is not None:
                vt_malicious, vt_status = ioc_engine.vt.lookup("hash", h)
 
                vt_hash_result = {
                    "vt_malicious": vt_malicious,
                    "vt_status": vt_status
                }
 
                # Do not submit attachments when the lookup failed or no API key is configured.
                if vt_status == "0 hits" and ioc_engine.vt.vt_api_key:
                    vt_upload_result = ioc_engine.vt.submit_file_bytes(filename, payload)
 
                talos_result = talos_lookup_reference(h)
            else:
                talos_result = {}

            # ==============================
            # ✅ STORE RESULT
            # ==============================

            attachments_info.append({
                "filename": filename,
                "size": len(payload),
                "sha256": h,
                "vt_hash": vt_hash_result,
                "vt_upload": vt_upload_result,
                "talos": talos_result,
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
    return{
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

        # URLs that went to IOC analysis
        "urls_extracted": urls_sorted,

        # Investigation evidence
        # Shows wrapper provider and recovered URLs
        "urls_extracted_detail": url_evidence,

        "iocs": iocs,
        "attachments": attachments_info,
        "sender_domains": list(sender_domains),
        "sender_intelligence": sender_intelligence,

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