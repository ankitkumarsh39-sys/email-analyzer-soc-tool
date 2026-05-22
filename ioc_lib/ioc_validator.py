"""
ioc_validator.py (FINAL + COMMENTED)

 Extract Indicators of Compromise (IOCs) from text (NO CVE):Purpose:
  1) IPs
  2) Domains (hostnames only)
  3) URLs (including defanged forms)
  4) File Hashes (MD5/SHA1/SHA256)

Important design rules:
- Do NOT call logging.basicConfig() here.
  Logging handlers/levels are configured in email_analyzer/main.py.
  This module only uses logger = logging.getLogger(__name__).

Why this module exists:
- analyzer.py does email parsing (headers/body/attachments)
- ioc_validator.py focuses only on pulling IOCs from text
  (clean separation = easy maintenance and testing)
"""

from __future__ import annotations

import re
import logging
from typing import List, Tuple, Dict, Any, Set
from urllib.parse import urlparse

# Module-level logger (inherits handlers & levels from main.py)
logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
# 1) IOC NORMALIZATION (Refanging / De-obfuscation)
# -----------------------------------------------------------------------------
def normalize_ioc(ioc: str, ioc_type: str | None = None) -> str:
    """
    Normalize IOC by removing common defanging/obfuscation patterns.

    Why this is needed:
    - SOC emails and tools often "defang" IOCs to prevent accidental clicking.
      Examples:
        hxxp://evil[.]com
        http[:]//evil(.)com
        example[.]com

    What this function does:
    - Converts common defang patterns back to normal form:
        [.]   -> .
        (.)   -> .
        [:]   -> :
        hxxp  -> http
        hxxps -> https

    ioc_type:
    - If ioc_type == "url", we keep the case as-is (rarely case-sensitive URLs exist)
    - Otherwise we lower-case to normalize domains/emails/etc.
    """
    if not ioc:
        return ""

    cleaned = (
        ioc.replace("[.]", ".")          # defanged dot
           .replace("(.)", ".")          # defanged dot alt
           .replace("[://]", "://")      # defanged scheme separator
           .replace("[:]", ":")          # defanged colon
           .replace("hxxps://", "https://")  # defanged https scheme
           .replace("hxxp://", "http://")    # defanged http scheme
           .replace("hxxps", "https")        # defanged https without ://
           .replace("hxxp", "http")          # defanged http without ://
           .strip()
    )

    # Keep URL case if requested; otherwise normalize case
    if ioc_type == "url":
        return cleaned
    return cleaned.lower()


# -----------------------------------------------------------------------------
# 2) REGEX PATTERNS
# -----------------------------------------------------------------------------
# Practical IPv4 regex:
# - This does not enforce 0-255 strictly (that requires heavier logic),
#   but works well for IOC extraction in SOC triage.
IP_REGEX = re.compile(r"\b(?:(?:\d{1,3})(?:\.\d{1,3}){3})\b")

# Domain/hostname only (NO paths):
# - Ensures we capture only hostnames like: example.com, sub.example.co.in
# - Avoids junk like: example.com/path or example.com</p>
DOMAIN_REGEX = re.compile(r"\b(?:[a-z0-9-]{1,63}\.)+(?:[a-z]{2,63})\b", re.IGNORECASE)

# URL regex:
# - Supports normal URLs: http://, https://
# - Supports defanged: hxxp, hxxps
# - Supports weird formatting: http[:]// or hxxp[:]//
# - Stops before common delimiters that appear in HTML/text
URL_REGEX = re.compile(
    r"\b(?:https?|hxxps?)\s*[:]\s*//[^\s<>\")']+|\b(?:https?|hxxps?)://[^\s<>\")']+",
    re.IGNORECASE
)

# Hash patterns:
MD5_REGEX = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_REGEX = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_REGEX = re.compile(r"\b[a-fA-F0-9]{64}\b")


# -----------------------------------------------------------------------------
# 3) SMALL INTERNAL HELPERS
# -----------------------------------------------------------------------------
def _unique_sorted(items: List[str]) -> List[str]:
    """Remove empty values, dedupe, and return sorted list for stable output."""
    return sorted(set(i for i in items if i))


def _extract_hashes(text: str) -> List[str]:
    """
    Extract all supported hashes from text using regex:
    - MD5 (32 hex)
    - SHA1 (40 hex)
    - SHA256 (64 hex)
    """
    hashes: Set[str] = set()
    hashes.update(MD5_REGEX.findall(text))
    hashes.update(SHA1_REGEX.findall(text))
    hashes.update(SHA256_REGEX.findall(text))
    return sorted(hashes)


def _domains_from_urls(urls: List[str]) -> List[str]:
    """
    Extract hostnames from URLs using urlparse, which is more accurate than regex.
    Example:
      https://sub.example.com/path -> sub.example.com
    """
    out = set()
    for u in urls or []:
        try:
            host = urlparse(u).netloc.lower()
            if host:
                out.add(host)
        except Exception:
            continue
    return sorted(out)


# -----------------------------------------------------------------------------
# 4) MAIN IOC EXTRACTION FUNCTION
# -----------------------------------------------------------------------------
def extract_iocs_from_text(text: str) -> Tuple[List[str], List[str], List[str], List[str]]:
    """
    Extract IOCs from a text blob.

    Returns exactly 4 values (NO CVE):
      (ips, domains, urls, hashes)

    Why order matters:
    - analyzer.py expects this exact order for unpacking:
      ips, domains, urls, hashes = extract_iocs_from_text(...)
    """
    text = text or ""

    # -------------------------
    # Step 1: Extract URLs first (because domains can come from URLs too)
    # -------------------------
    raw_urls = URL_REGEX.findall(text)

    urls = []
    for u in raw_urls:
        # Normalize defanged URLs (hxxp -> http, [:] -> :)
        u2 = normalize_ioc(u, "url")
        # Remove whitespace around scheme (e.g., "http : //" -> "http://")
        u2 = re.sub(r"\s+", "", u2)
        urls.append(u2)

    urls = _unique_sorted(urls)

    # -------------------------
    # Step 2: Refang the whole text for IP/domain/hash extraction
    # -------------------------
    text_refanged = normalize_ioc(text)

    # -------------------------
    # Step 3: Extract IPs + Domains + Hashes
    # -------------------------
    ips = _unique_sorted(IP_REGEX.findall(text_refanged))

    domains = _unique_sorted(DOMAIN_REGEX.findall(text_refanged))

    # Add domains derived from URLs (more reliable)
    domains = _unique_sorted(domains + _domains_from_urls(urls))

    hashes = _extract_hashes(text_refanged)

    # Summary log (counts only)
    logger.info(
        "IOC Extraction Complete - IPs: %d, Domains: %d, URLs: %d, Hashes: %d",
        len(ips), len(domains), len(urls), len(hashes)
    )

    return ips, domains, urls, hashes


# -----------------------------------------------------------------------------
# 5) CLASSIFICATION STRUCTURE (used by analyzer + reporter)
# -----------------------------------------------------------------------------
def classify_iocs(ips: List[str], domains: List[str], urls: List[str], hashes: List[str]) -> Dict[str, Any]:
    """
    Build a unified IOC structure used across the project.

    Output format:
      {
        "ips": [...],
        "domains": [...],
        "urls": [...],
        "hashes": [...],
        "counts": {"ips": n, "domains": n, "urls": n, "hashes": n}
      }
    """
    classification = {
        "ips": ips,
        "domains": domains,
        "urls": urls,
        "hashes": hashes,
        "counts": {
            "ips": len(ips),
            "domains": len(domains),
            "urls": len(urls),
            "hashes": len(hashes),
        }
    }

    total = sum(classification["counts"].values())
    logger.info("Total IOCs classified: %d", total)

    return classification


# -----------------------------------------------------------------------------
# 6) HUMAN READABLE IOC REPORT (used by analyzer logs + TXT report)
# -----------------------------------------------------------------------------
def format_ioc_report(classification: Dict[str, Any]) -> str:
    """
    Convert the IOC structure into a readable multi-line report.

    Note:
    - analyzer.py logs this as DEBUG (full detail in files)
    - console shows only counts (summary)
    """
    counts = classification.get("counts", {})
    ips = classification.get("ips", [])
    domains = classification.get("domains", [])
    urls = classification.get("urls", [])
    hashes = classification.get("hashes", [])

    lines = []
    lines.append("[!] IOC Extraction Report:")
    lines.append("=" * 60)

    def section(title: str, items: List[str], n: int = 10):
        lines.append(f"{title} ({len(items)} found):")
        if not items:
            lines.append("  - None")
        else:
            for x in items[:n]:
                lines.append(f"  - {x}")
            if len(items) > n:
                lines.append(f"  ... and {len(items) - n} more")
        lines.append("")

    section("IPs", ips)
    section("Domains", domains)
    section("URLs", urls)
    section("File Hashes", hashes)

    lines.append("=" * 60)
    return "\n".join(lines)