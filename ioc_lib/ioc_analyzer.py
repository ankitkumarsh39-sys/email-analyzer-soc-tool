"""
ioc_analyzer.py
====================================================================================
IOC Analyzer for Email Analysis Project

This module adds scoring + tagging on top of IOC extraction.

What it does:
1) Extract IOCs from text:
   - IPs (supports defanged [.] and (.))
   - Domains (supports defanged)
   - URLs (supports hxxp/hxxps and [://])
   - Hashes (MD5/SHA1/SHA256 via iocextract)
   - NOTE: CVE extraction is intentionally REMOVED (as per requirement)

2) Normalize / Refang IOCs:
   - example[.]com -> example.com
   - hxxp[:]// -> http://
   - keeps URL path case (VT can be case-sensitive in URL path/query)

3) Whitelist + Blocklist:
   - IMPORTANT:
     Whitelist does NOT skip IOCs anymore.
     Whitelist only tags IOC as "is_whitelisted": True/False
     VT scoring is still performed.

   - Blocklist still forces IOC to be treated as malicious.

4) VirusTotal v3 lookups with caching (vt_cache.json)
5) Classification:
   - Malicious if (blocklisted OR VT malicious score > 0)
   - Clean otherwise

6) Cancellation support:
   - Press 'q' on Windows during long VT lookups
====================================================================================
"""

from __future__ import annotations

import os
import re
import json
import time
import base64
import logging
import pandas as pd
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Optional, Any
from urllib.parse import quote

import requests
import iocextract
from dotenv import load_dotenv

from email_analyzer.utils.whois_utils import whois_lookup
from ioc_lib.ioc_cache import get_cached, set_cache

# Windows-only keypress detection for cancel support
try:
    import msvcrt  # type: ignore
except ImportError:
    msvcrt = None

logger = logging.getLogger(__name__)



class AnalysisCancelled(Exception):
    """Raised when user cancels analysis during IOC processing."""
    pass

@dataclass
class IOCRecord:
    """
    A single IOC row, easy to convert to JSON / report sections.
    """
    raw: str
    normalized: str
    ioc_type: str             # ip | domain | url | hash
    vt_malicious: int         # VT malicious hits count
    vt_status: str            # "2 hits", "Lookup Error", etc.
    is_whitelisted: bool      # Tag only (NOT skipping)
    is_blocklisted: bool      # Forces malicious
    category: str             # "Malicious" or "Clean"

    # NEW: Multi-Source scoring fields
    final_score: int = 0             # Combined score from all sources
    reason: Optional[List[str]] = None  # Explanation of final score
    provider_context: Optional[Dict[str, Any]] = None  # Raw data from providers for evidence

# Load .env so VT_API_KEY can be read automatically
load_dotenv()
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
ANYRUN_API_KEY = os.getenv("ANYRUN_API_KEY")
WHOISJSON_API_KEY = os.getenv("WHOISJSON_API_KEY")

class IocsClient:
    """
    Small VirusTotal client with JSON cache.
    Handles:
    - environment key load
    - reusable requests session
    - local cache file
    - VT lookups for ip/domain/url/hash
    """

    def __init__(
        self,
        api_key: str = "",
        cache_path: str = "",
        cache_max_age_seconds: int = 7 * 24 * 60 * 60,
        logger: Optional[logging.Logger] = None,
    ):
        self.logger = logger or logging.getLogger(__name__)

        # Load API key (.env first, fallback to argument)
        # Prefer .env key if present, otherwise fallback to provided api_key
        self.vt_api_key = os.getenv("VT_API_KEY") or api_key

        if not self.vt_api_key:
            raise ValueError(
                "VT API key missing. Ensure VT_API_KEY is set in .env or provided explicitly."
            )

        # Reusable session for connection pooling
        
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/json",
            "x-apikey": self.vt_api_key
        })

        # Optional: request timeout control
        self.request_timeout = 20 # seconds 

    # -------------------------------------------------------------------------
    # VT helpers
    # -------------------------------------------------------------------------
    def _get_url_id(self, url: str) -> str:
        """
        VirusTotal v3 URL lookup requires a base64 URL-safe encoded ID without '=' padding.
        """
        return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    def lookup(self, ioc_type: str, normalized: str) -> Tuple[int, str]:
        """
        Lookup VT malicious score for a single IOC.

        Returns:
          (malicious_score, status_text)

        Examples:
          (0, "0 hits")
          (5, "5 hits")
          (0, "VT Lookup Failed (404)")
          (0, "Lookup Error")
        """

        endpoints = {
            "ip": "ip_addresses",
            "domain": "domains",
            "hash": "files",
            "url": "urls",
        }

        if ioc_type not in endpoints:
            return 0, "Unsupported IOC Type"

        resource_id = self._get_url_id(normalized) if ioc_type == "url" else normalized
        api_url = f"https://www.virustotal.com/api/v3/{endpoints[ioc_type]}/{resource_id}"

        try:
            # Be friendly with API rate limit
            time.sleep(1)

            response = self.session.get(api_url, timeout=20)

            if response.status_code == 429:
                # One retry after delay
                time.sleep(5)
                response = self.session.get(api_url, timeout=20)

            if response.status_code == 200:
                data = response.json()
                malicious = int(
                    data["data"]["attributes"]["last_analysis_stats"].get("malicious", 0)
                )
                status = f"{malicious} hits"
            else:
                malicious = 0
                status = f"VT Lookup Failed ({response.status_code})"

            return malicious, status

        except Exception as e:
            self.logger.error("VT lookup error for %s '%s': %s", ioc_type, normalized, str(e))
            return 0, "Lookup Error"

    def submit_file_bytes(self, filename: str, file_bytes: bytes) -> Dict[str, Any]:
        """
        Submit a file to VirusTotal.
        - <= 32 MB: direct POST to /api/v3/files
        - > 32 MB: get one-time upload URL first
        """
        try:
            size_bytes = len(file_bytes)

            # Small files: direct upload
            if size_bytes <= 32 * 1024 * 1024:
                upload_url = "https://www.virustotal.com/api/v3/files"
            else:
                # Large files: get upload URL first
                r = self.session.get(
                    "https://www.virustotal.com/api/v3/files/upload_url",
                    timeout=30
                )
                if r.status_code != 200:
                    return {"status": f"failed_upload_url_{r.status_code}"}

                upload_url = r.json().get("data")
                if not upload_url:
                    return {"status": "failed_upload_url_missing"}

            files = {
                "file": (filename, file_bytes)
            }

            r = requests.post(
                upload_url,
                headers={"x-apikey": self.vt_api_key},
                files=files,
                timeout=60
            )

            if r.status_code not in (200, 201):
                return {
                    "status": f"failed_{r.status_code}",
                    "body": r.text[:500]
                }

            data = r.json()
            return {
                "status": "submitted",
                "analysis_id": data.get("data", {}).get("id"),
                "raw": data
            }

        except Exception as e:
            self.logger.error("VT file submission error for %s: %s", filename, str(e))
            return {
                "status": "error",
                "error": str(e)
            }
        
# =============================================================================
# OSINT / SANDBOX HELPERS
# =============================================================================


def abuseipdb_lookup(ip: str) -> dict:
    """
    Check AbuseIPDB reputation for an IP address.

    Why this helper exists:
    - Good for IP abuse confidence and complaint volume.
    - Useful for IOC enrichment of sender / hosting IPs.

    Safe behavior:
    - Returns {} if key missing
    - Returns lightweight dict if lookup works
    - Never breaks pipeline if API fails
    """
    if not ABUSEIPDB_API_KEY:
        return {}

    try:
        headers = {
            "Key": ABUSEIPDB_API_KEY,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90
        }

        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers,
            params=params,
            timeout=15
        )

        if r.status_code != 200:
            return {
                "source": "AbuseIPDB",
                "status": f"failed_{r.status_code}"
            }

        data = r.json().get("data", {})

        return {
            "source": "AbuseIPDB",
            "abuse_score": data.get("abuseConfidenceScore", 0),
            "abuse_reports": data.get("totalReports", 0),
            "status": "ok"
        }

    except Exception as e:
        return {
            "source": "AbuseIPDB",
            "status": "error",
            "error": str(e)
        }

def anyrun_url_lookup(url: str) -> dict:
    """
    Submit URL to ANY.RUN sandbox.

    Important note:
    - ANY.RUN docs confirm analysis endpoints under /v1/analysis/.
    - Task payloads can vary by workflow/account/product.
    - So this helper is intentionally defensive and lightweight.

    Safe behavior:
    - Returns {} if key missing
    - Returns basic submission info if request succeeds
    - Never breaks pipeline if ANY.RUN API fails
    """
    if not ANYRUN_API_KEY:
        return {}

    try:
        headers = {
            "Authorization": f"API-Key {ANYRUN_API_KEY}",
            "Content-Type": "application/json"
        }

        payload = {
            "url": url
        }

        r = requests.post(
            "https://api.any.run/v1/analysis/",
            headers=headers,
            json=payload,
            timeout=20
        )

        if r.status_code not in (200, 201):
            return {
                "source": "ANY.RUN",
                "status": f"failed_{r.status_code}"
            }

        data = r.json()

        return {
            "source": "ANY.RUN",
            "status": "submitted",
            "raw": data
        }

    except Exception as e:
        return {
            "source": "ANY.RUN",
            "status": "error",
            "error": str(e)
        }


# Module-level convenience wrapper for urlscan to be used elsewhere in this module.
def urlscan_lookup(url: str) -> dict:
    """
    Submit URL to urlscan.io for analysis (module-level wrapper).
    Returns {} if no API key or on error. Keeps behavior lightweight so it
    never breaks the IOC pipeline.
    """
    if not URLSCAN_API_KEY:
        return {}

    try:
        headers = {
            "API-Key": URLSCAN_API_KEY,
            "Content-Type": "application/json"
        }

        payload = {
            "url": url,
            "visibility": "unlisted"
        }

        r = requests.post(
            "https://urlscan.io/api/v1/scan/",
            headers=headers,
            json=payload,
            timeout=20
        )

        if r.status_code not in (200, 201):
            return {
                "source": "urlscan",
                "status": f"failed_{r.status_code}"
            }

        data = r.json()

        return {
            "scan_id": data.get("uuid"),
            "source": "urlscan",
            "status": "submitted",
            "raw": data
        }

    except Exception as e:
        return {
            "source": "urlscan",
            "status": "error",
            "error": str(e)
        }


def talos_lookup_reference(value: str) -> dict:
    """
    Talos public site reference helper.

    Why this is just a reference link:
    - Talos reputation portal is useful for analyst lookup
    - But public Talos web reputation site does NOT have a published public API

    This helper gives you a direct analyst lookup URL you can store in output.
    """
    return {
        "source": "Talos",
        "portal_lookup": f"https://talosintelligence.com/reputation_center/lookup?search={quote(value)}"
    }


def rdap_lookup_reference(domain: str) -> dict:
    """
    ICANN RDAP reference helper.

    Why this is useful:
    - Domain age / registrar / registration context can help phishing analysis
    - ICANN lookup is RDAP-based and useful as analyst context

    This returns a portal lookup URL instead of forcing a fragile scrape.
    """
    return {
        "source": "RDAP",
        "portal_lookup": f"https://lookup.icann.org/en/lookup?name={quote(domain)}"
    }

class IOCAnalyzer:
    """
    IOCAnalyzer = extraction + normalization + VT scoring + classification.
    Designed to integrate into email_analyzer/analyzer.py.
    """

    def __init__(
        self,
        vt_api_key: str = "",
        whitelist_path: str = "config/whitelist.xlsx",
        blocklist_path: str = "config/blocklist.xlsx",
        #cache_path: str = "",
        cache_max_age_seconds: int = 7 * 24 * 60 * 60,
        logger: Optional[logging.Logger] = None,
    ):
        self.logger = logger or logging.getLogger(__name__)

        # VirusTotal client
        self.vt = IocsClient(
            api_key=vt_api_key,
            cache_max_age_seconds=cache_max_age_seconds,
            logger=self.logger,
        )

        # Load whitelist from Excel
        wl_records = self._load_excel_records(whitelist_path)
        self.whitelist_records = wl_records
        self.ip_whitelist = [r["value"] for r in wl_records if r["type"] == "ip"]
        self.domain_whitelist = [r["value"] for r in wl_records if r["type"] == "domain"]

        # Load blocklist from Excel
        bl_records = self._load_excel_records(blocklist_path)
        self.blocklist_records = bl_records
        self.manual_blocklist = [r["value"] for r in bl_records]

        # Cancel state
        self.cancel_requested = False

    # -------------------------------------------------------------------------
    # Cancel support
    # -------------------------------------------------------------------------
    def reset_cancel_state(self) -> None:
        """Reset cancel flag before a new scoring run."""
        self.cancel_requested = False

    def check_for_exit(self) -> None:
        """
        Allow Windows user to press 'q' during long VT scoring.
        Safe no-op on non-Windows.
        """
        if self.cancel_requested:
            raise AnalysisCancelled()

        if msvcrt is None:
            return

        try:
            while msvcrt.kbhit():
                key = msvcrt.getwch()
                if key.lower() == "q":
                    self.cancel_requested = True
                    self.logger.warning("User requested cancellation during IOC scoring.")
                    raise AnalysisCancelled()
        except Exception:
            raise AnalysisCancelled()

    # -------------------------------------------------------------------------
    # File / list helpers
    # -------------------------------------------------------------------------
    def _ensure_dir(self, path: str) -> None:
        folder = os.path.dirname(path)
        if folder and not os.path.exists(folder):
            os.makedirs(folder, exist_ok=True)

    def _load_list(self, path: str) -> List[str]:
        """
        Load list file (whitelist/blocklist):
        - lowercase
        - ignore blank lines
        - ignore comment lines starting with '#'
        """
        if not os.path.exists(path):
            self.logger.warning(f"{path} not found → creating new Excel")

            os.makedirs(os.path.dirname(path), exist_ok=True)

            df = pd.DataFrame(columns=[
                "type", "value", "description"
            ])

            df.to_excel(path, index=False, engine="openpyxl")

            return []

        out: List[str] = []
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                out.append(line.lower())
        return out

    import pandas as pd

    def _load_excel_records(self, path: str) -> List[Dict[str, Any]]:
        """
        Load IOC records from Excel config.
        Required columns:
        type, value
        Optional columns:
        description, score, confidence, severity, source, category,
        status, first_seen, last_analyzed, tags, campaign, action, whois_age, reputation
        """
        if not os.path.exists(path):
            return []

        try:
            df = pd.read_excel(path, engine="openpyxl")

            if "value" not in df.columns or "type" not in df.columns:
                self.logger.warning("Excel config missing required columns 'type' and 'value': %s", path)
                return []

            records = []
            for _, row in df.fillna("").iterrows():
                value = str(row.get("value", "")).strip().lower()
                ioc_type = str(row.get("type", "")).strip().lower()

                if not value or not ioc_type:
                    continue

                records.append({
                    "type": ioc_type,
                    "value": value,
                    "description": str(row.get("description", "")).strip(),
                    "score": int(row.get("score", 0) or 0),
                    "confidence": str(row.get("confidence", "")).strip(),
                    "severity": str(row.get("severity", "")).strip(),
                    "source": str(row.get("source", "")).strip(),
                    "category": str(row.get("category", "")).strip(),
                    "status": str(row.get("status", "")).strip(),
                    "first_seen": str(row.get("first_seen", "")).strip(),
                    "last_analyzed": str(row.get("last_analyzed", "")).strip(),
                    "tags": str(row.get("tags", "")).strip(),
                    "campaign": str(row.get("campaign", "")).strip(),
                    "action": str(row.get("action", "")).strip(),
                    "whois_age": str(row.get("whois_age", "")).strip(),
                    "reputation": str(row.get("reputation", "")).strip(),
                })
            return records

        except Exception as e:
            self.logger.error("Failed to load Excel config %s: %s", path, e)
            return []
        
    def _load_whitelist(self, path: str) -> Tuple[List[str], List[str]]:
        """
        Split whitelist into:
        - IP whitelist
        - Domain whitelist
        """
        raw = self._load_list(path)
        ip_pat = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

        ips: List[str] = []
        domains: List[str] = []

        for item in raw:
            if ip_pat.match(item):
                ips.append(item)
            else:
                domains.append(item)

        return ips, domains

    # -------------------------------------------------------------------------
    # IOC normalize / refang
    # -------------------------------------------------------------------------
    def normalize_ip(self, ip: str) -> str:
        return str(ip).replace("[.]", ".").replace("(.)", ".")

    def normalize_ioc(self, ioc: str, ioc_type: str) -> str:
        """
        Refang IOC and normalize.

        Important:
        - URLs keep case because URL path/query can be case-sensitive
        - other IOC types are lowercased
        """
        cleaned = (
            str(ioc)
            .replace("[.]", ".")
            .replace("(.)", ".")
            .replace("{.}", ".")
            .replace("[://]", "://")
            .replace("hxxps://", "https://")
            .replace("hxxp://", "http://")
            .replace("hxxps", "https://")
            .replace("hxxp", "http")
            .replace("[:]", ":")
            .strip()
        )
        return cleaned if ioc_type == "url" else cleaned.lower()

    # -------------------------------------------------------------------------
    # IOC extraction
    # -------------------------------------------------------------------------
    def extract_iocs(self, text: str) -> Dict[str, List[str]]:
        """
        Extract IPs, domains, URLs, hashes from text.
        CVE extraction is intentionally NOT included.
        """
        if not text:
            return {"ips": [], "domains": [], "urls": [], "hashes": []}

        # IPs (supports defanged)
        ip_candidates = re.findall(
            r"\b(?:\d{1,3}(?:(?:\[\.]|\(\.\)|\.)\d{1,3}){3})\b",
            text
        )
        ips = sorted(set(self.normalize_ip(x) for x in ip_candidates))

        # Hashes via iocextract
        hashes = sorted(set(iocextract.extract_hashes(text)))

        # Whois Domains
        """
        That matters because WhoisXML’s WHOIS API is for domains, not paths or file names. 
        WhoisXML’s public API description explicitly positions it as domain registration / WHOIS retrieval.

        """

        domain_candidates = re.findall(
            r"\b[a-zA-Z0-9.-]+\.[a-z]{2,}\b",
            text,
            re.IGNORECASE
        )

        domains = []
        for d in domain_candidates:
            norm = self.normalize_ioc(d, "domain")

            # skip obvious file names
            if norm.endswith((".pdf", ".docx", ".zip", ".exe", ".png", ".jpg", ".js", ".json", ".txt")):
                continue

            # skip malformed things that still contain paths
            if "/" in norm:
                continue

            domains.append(norm)

        domains = sorted(set(domains))

        # URLs (supports hxxp and [://])
        url_candidates = re.findall(
            r"(?:http|hxxp)s?(?:\[\:\/\/]|\:\/*)[^\s<>\")']+",
            text,
            re.IGNORECASE
        )
        urls = sorted(set(self.normalize_ioc(u, "url") for u in url_candidates))

        return {
            "ips": ips,
            "domains": domains,
            "urls": urls,
            "hashes": hashes
        }

    # -------------------------------------------------------------------------
    # Whitelist / Blocklist
    # -------------------------------------------------------------------------
    def is_whitelisted(self, normalized: str, ioc_type: str) -> bool:
        """
        Whitelist = tag only.
        It does NOT skip scoring.
        """
        val = (normalized or "").strip().lower()
        if not val:
            return False

        if ioc_type == "ip":
            return val in self.ip_whitelist

        if ioc_type == "domain":
            return any(val == d or val.endswith("." + d) for d in self.domain_whitelist)
        

        if ioc_type == "url":
            host = re.sub(r"^https?://", "", val).split("/")[0]
            return any(host == d or host.endswith("." + d) for d in self.domain_whitelist)

        return False

    def is_blocklisted(self, normalized: str) -> bool:
        """Blocklist forces IOC to be malicious."""
        return (normalized or "").strip().lower() in self.manual_blocklist
    
    def _get_whitelist_record(self, normalized: str, ioc_type: str) -> Optional[Dict[str, Any]]:
        """
        Return matching whitelist Excel row if present.
        """
        val = (normalized or "").strip().lower()
        if not val:
            return None

        for r in getattr(self, "whitelist_records", []):
            r_type = str(r.get("type", "")).strip().lower()
            r_value = str(r.get("value", "")).strip().lower()

            if r_type == ioc_type and r_value == val:
                return r

            # Domain-style matching for subdomains and URL hosts
            if ioc_type == "domain" and r_type == "domain":
                if val == r_value or val.endswith("." + r_value):
                    return r

            if ioc_type == "url" and r_type == "domain":
                host = re.sub(r"^https?://", "", val).split("/")[0]
                if host == r_value or host.endswith("." + r_value):
                    return r
        return None

    def _get_blocklist_record(self, normalized: str, ioc_type: str) -> Optional[Dict[str, Any]]:
        """
        Return matching blocklist Excel row if present.
        """
        val = (normalized or "").strip().lower()
        if not val:
            return None

        for r in getattr(self, "blocklist_records", []):
            r_type = str(r.get("type", "")).strip().lower()
            r_value = str(r.get("value", "")).strip().lower()

            if r_type == ioc_type and r_value == val:
                return r

            if ioc_type == "domain" and r_type == "domain":
                if val == r_value or val.endswith("." + r_value):
                    return r

            if ioc_type == "url" and r_type == "domain":
                host = re.sub(r"^https?://", "", val).split("/")[0]
                if host == r_value or host.endswith("." + r_value):
                    return r
        
        return None

    # -------------------------------------------------------------------------
    # Main scoring entry
    # -------------------------------------------------------------------------
    def analyze_text_iocs(self, text: str) -> Dict[str, Any]:
        """
        Analyze a text blob:
        1) extract IOCs
        2) normalize each IOC
        3) VT score each IOC
        4) tag whitelist / blocklist
        5) classify as Malicious/Clean

        Returns JSON-friendly structure:
        {
          "extracted": {...},
          "results": [...],
          "containers": {"malicious":[...], "clean":[...]},
          "counts": {...},
          "simple_iocs": {...}   <-- useful for existing reporter
        }
        """
        self.reset_cancel_state()
        extracted = self.extract_iocs(text)

        results: List[IOCRecord] = []
        malicious: List[IOCRecord] = []
        clean: List[IOCRecord] = []

        self.logger.debug(f"======================Extracted IOCs:====================== {extracted}")
        def process(items: List[str], ioc_type: str) -> None:
            for raw in items:
                self.check_for_exit()

                normalized = self.normalize_ioc(raw, ioc_type)

                wl_record = self._get_whitelist_record(normalized, ioc_type)
                bl_record = self._get_blocklist_record(normalized, ioc_type)

                is_wl = wl_record is not None
                is_bl = bl_record is not None

                # IMPORTANT: VT is always checked even if whitelisted
                # IMPORTANT:
                # VT is always checked even if IOC is whitelisted
           
                # ------------------------------------------------------------
                # CACHE CHECK + ENRICHMENT
                # ------------------------------------------------------------
                cached = get_cached(ioc_type, normalized)

                if cached:
                    score = int(cached.get("vt_malicious", 0))
                    status = str(cached.get("vt_status", "Cached"))
                    final_score = int(cached.get("final_score", 0))
                    reasons = cached.get("reason", []) or []

                    provider_context = cached.get("provider_context", {}) or {}
                    urlscan_data = provider_context.get("urlscan", {}) or {}
                    abuse_data = provider_context.get("abuseipdb", {}) or {}
                    anyrun_data = provider_context.get("anyrun", {}) or {}
                    talos_ref = provider_context.get("talos", {}) or {}
                    rdap_ref = provider_context.get("rdap", {}) or {}
                    whois_data = provider_context.get("whois", {}) or {}

                else:
                    score, status = self.vt.lookup(ioc_type, normalized)

                    urlscan_data = {}
                    abuse_data = {}
                    anyrun_data = {}
                    talos_ref = {}
                    rdap_ref = {}
                    whois_data = {}

                    # URL-specific enrichment
                    if ioc_type == "url":
                        urlscan_data = urlscan_lookup(normalized)
                        anyrun_data = anyrun_url_lookup(normalized)
                        talos_ref = talos_lookup_reference(normalized)

                    # IP-specific enrichment
                    elif ioc_type == "ip":
                        abuse_data = abuseipdb_lookup(normalized)
                        talos_ref = talos_lookup_reference(normalized)

                    # Domain-specific enrichment
                    elif ioc_type == "domain":
                        talos_ref = talos_lookup_reference(normalized)
                        rdap_ref = rdap_lookup_reference(normalized)

                        try:
                            whois_data = whois_lookup(normalized)
                        except Exception as e:
                            self.logger.error("WHOIS lookup crashed for domain '%s': %s", normalized, str(e))
                            whois_data = {
                                "status": "error",
                                "error": str(e)
                            }
                
                # Pull out lightweight values for scoring
                urlscan_score = int(urlscan_data.get("urlscan_score", 0) or 0)
                urlscan_malicious = bool(urlscan_data.get("urlscan_malicious", False))
                abuse_score = int(abuse_data.get("abuse_score", 0) or 0)

                # ------------------------------------------------------------
                # Final weighted score
                #
                # Design:
                # - VT gives base malicious signal
                # - urlscan strengthens URL confidence
                # - AbuseIPDB strengthens IP confidence
                # - blocklist overrides everything
                # ------------------------------------------------------------

                if not cached:
                    final_score = 0
                    reasons = []

                # VirusTotal contribution
                if score > 0:
                    final_score += 3
                    reason_text = f"VirusTotal detections: {score}"

                    if reason_text not in reasons:
                        reasons.append(reason_text)

                # urlscan contribution
                if urlscan_malicious:
                    final_score += 3
                    reason_text = f"urlscan malicious verdict (score={urlscan_score})"
                    if reason_text not in reasons:
                        reasons.append(reason_text)

                # AbuseIPDB contribution
                if abuse_score >= 70:
                    final_score += 2
                    reason_text = f"AbuseIPDB high confidence ({abuse_score})"
                    if reason_text not in reasons:
                        reasons.append(reason_text)

                # Manual blocklist override

                if is_bl:
                    final_score = 10

                    if bl_record:
                        bl_desc = str(bl_record.get("description", "")).strip()
                        bl_score = bl_record.get("score", 10)
                        try:
                            bl_score = int(bl_score or 10)
                        except Exception:
                            bl_score = 10

                        final_score = max(final_score, bl_score)
                       
                    """ if "Blocklisted IOC" not in reasons:
                        reasons.append("Blocklisted IOC")
                    """

                    if bl_desc:
                        desc_text = bl_desc.strip()
                        if desc_text and desc_text not in reasons:
                            reasons.append(desc_text)

                if is_wl and wl_record:
                    wl_desc = str(wl_record.get("description", "")).strip()
                   
                    reason_text = "Whitelisted IOC"

                    if wl_desc:
                        reason_text += f" - {wl_desc}"

                    if reason_text not in reasons:
                        reasons.append(reason_text)
       
                
                structured_verdict = None
                if ioc_type == "url":
                    structured_verdict = self.analyze_url_ioc(normalized, score, status)

                if ioc_type == "hash":
                    structured_verdict = self.analyze_attachment_ioc(
                        filename= "unknown",
                        sha256=normalized,
                        vt_score=score,
                        vt_status=status
                    )
                
                reasons = list(dict.fromkeys(reasons))  # ✅ keeps order + removes duplicates

                # -------------------------
                # Domain Risk Intelligence
                # -------------------------
                if ioc_type == "domain":

                    # WHOIS-age scoring
                    age = whois_data.get("age_days")
                    if age is not None:
                        if age < 30:
                            final_score += 3
                            reasons.append(f"New domain ({age} days old)")
                        elif age < 90:
                            final_score += 2
                            reasons.append(f"Recent domain ({age} days old)")

                    # Phishing keyword detection
                    if "login" in normalized or "verify" in normalized or "secure" in normalized:
                        final_score += 2
                        reasons.append("Phishing keyword in domain")

                    if "microsoft" in normalized and "fake" in normalized:
                        final_score += 3
                        reasons.append("Brand impersonation detected (Microsoft)")
                
                # Final category decision
                category = "Malicious" if final_score >= 3 else "Clean"

                if cached:
                        logger.debug(f"CACHE HIT: {normalized}")
                else:
                        logger.debug(f"API CALL: {normalized}")

                if not cached:
                    set_cache(ioc_type, normalized, {
                        "vt_malicious": score,
                        "vt_status": status,
                        "final_score": final_score,
                        "category": category,
                        "reason": reasons,
                        "provider_context": {
                            "urlscan": urlscan_data,
                            "abuseipdb": abuse_data,
                            "anyrun": anyrun_data,
                            "talos": talos_ref,
                            "rdap": rdap_ref,
                            "whois": whois_data
                        }
                    })

                record = IOCRecord(
                    raw=str(raw),
                    normalized=str(normalized),
                    ioc_type=ioc_type,
                    vt_malicious=int(score),
                    vt_status=str(status),
                    is_whitelisted=bool(is_wl),
                    is_blocklisted=bool(is_bl),
                    category=category,
                    final_score=final_score,
                    reason=reasons,
                    provider_context={
                        "urlscan": urlscan_data,
                        "abuseipdb": abuse_data,
                        "anyrun": anyrun_data,
                        "talos": talos_ref,
                        "rdap": rdap_ref,
                        "whois": whois_data
                    }
                )

                results.append(record)
                (malicious if category == "Malicious" else clean).append(record)

        process(extracted["ips"], "ip")
        process(extracted["domains"], "domain")
        process(extracted["urls"], "url")
        process(extracted["hashes"], "hash")

               
        
        # "simple_iocs" = existing structure your current reporter can still use
        simple_iocs = {
            "ips": extracted["ips"],
            "domains": extracted["domains"],
            "urls": extracted["urls"],
            "hashes": extracted["hashes"],
            "counts": {
                "ips": len(extracted["ips"]),
                "domains": len(extracted["domains"]),
                "urls": len(extracted["urls"]),
                "hashes": len(extracted["hashes"]),
            }
        }

        

        campaign = self.detect_campaign([r.__dict__ for r in results])
        alert = self.calculate_final_alert([r.__dict__ for r in results], campaign)

        return {
            "extracted": extracted,
            "results": [r.__dict__ for r in results],
            "campaign": campaign,
            "alert": alert,
            "containers": {
                "malicious": [r.__dict__ for r in malicious],
                "clean": [r.__dict__ for r in clean],
            },
            "counts": {
                "total": len(results),
                "malicious": len(malicious),
                "clean": len(clean),
                "ips": len(extracted["ips"]),
                "domains": len(extracted["domains"]),
                "urls": len(extracted["urls"]),
                "hashes": len(extracted["hashes"]),
            },
            "simple_iocs": simple_iocs
        }
    
        
#=========================================================================
# Structure Verdict builder (schema-aligned with existing report sections)
# =========================================================================
    def build_base_verdict(
        self,
        classification: str,
        score: int,
        reason: str,
        ) ->Dict[str, Any]:
        """ Build a normalized verdict object for one IOC."""
        severity = (
            "High" if classification == "Malicious" and score >= 6 
            else "Medium" if classification == "Malicious"
            else "Low" if classification == "suspicious"
            else "Informational"
        )

        """
        Build a base verdict structure for an IOC.
        This can be extended with additional fields as needed.
        """
        return {
            "classification": classification,  # "Malicious" or "Clean"
            "Severity": severity,              # "High", "Medium", "Low", "Informational"
            "score": score,                    # VT malicious hits count
            "reason": reason,                  # Explanation of classification
            "timestamp": datetime.now().isoformat()
        }
    
#=======================================================================
# This code is use to build a structured verdict for URL IOCs, with potential for extension to other types.
# ========================================================================
    def analyze_url_ioc(
        self,
        normalized_url: str,
        vt_score: int,
        vt_status: str,
        ) -> Dict[str, Any]:
        
        """
        Build a structured URL verdict.

        Right now:
        - VT is included as direct evidence
        - Other sources can later be added to evidence block
        """

        evidence = []
        reason =[]
        score = 0

        #VirusTotal score analysis
        evidence.append({
            "source": "VirusTotal",
            "summary": f"VirusTotal score: {vt_score} hits",
            "details": {
                "malicious_hits": vt_score,
                "lookup_status": vt_status
            }
        })


# this code is use to 
        if vt_score > 0:
            score += 3
            reason.append("High VirusTotal detection")
        
        #Placeholder hooks (safe, no API calls yet)
        # URLScan
        # Whois
        # AbuseIPDB
        # AlienVault OTX

        classification = "Malicious" if score >= 3 else "Clean"

        return {
            "ioc_type": "url",
            "value": normalized_url,
            "verdict": self.build_base_verdict(classification, score, reason),
            "evidence": evidence,
            "policy_tags": {
                "whitelisted": False,
                "blacklisted": False
            }
        }

#=====================================================================
# This code is use to build a structured verdict for attachment/hash IOCs, with potential for extension to other types.
#=====================================================================

    def analyze_attachment_ioc(
        self,
        filename: str,
        sha256: str,
        vt_score: int,
        vt_status: str
    ) -> Dict[str, Any]:
        """
        Build a structured attachment/hash verdict.
        This can be extended with additional enrichment sources as needed."""

        evidence = []
        reason = []
        score = 0

        evidence.append({
            "source": "VirusTotal",
            "details": {
                "sha256": sha256,
                "malicious" : vt_score,
                "status" : vt_status
            }
        })

        if vt_score > 0:
            score += 4
            reason.append("Known malicious file hash")

        classification = "Malicious" if score >= 1 else "Clean"

        return {
            "ioc_type" : "attachment",
            "value": filename,
            "verdict": self.build_base_verdict(classification, score, reason),
            "evidence": evidence,
            "policy_tags": {
                "whitelisted": False,
                "blocklisted": False,
            }
        }

# ============================================================
# STEP 3 — CAMPAIGN DETECTION ENGINE
# ============================================================

    def detect_campaign(self, results: list) -> dict:

        """
        Detect common patterns across IOCs.
        """

        campaign = {
            "malicious_ips" : [],
            "malicious_domains": [],
            "phishing_domains": [],
            "ransomware_domains" : [],
            "reused_iocs" : [],
            "confidence": "LOW"
        }

        ip_count = {}
        
        for r in results:
            if r["category"] != "Malicious":
                continue

            val = r["normalized"]
            ioc_type = r["ioc_type"]

            # -------------------------
            # Track malicious IPs
            # -------------------------
            if ioc_type == "ip":
                campaign["malicious_ips"].append(val) 
                ip_count[val] = ip_count.get(val, 0) + 1

            # -------------------------
            # Track malicious domains
            # -------------------------
            if ioc_type == "domain":
                campaign["malicious_domains"].append(val)

                if any(x in val for x in ["login", "verify", "secure"]):
                    
                    campaign["phishing_domains"].append(val)
                
                if any(x in  val for x in ["lockbit"]):
                    campaign["ransomware_domains"].append(val)

        # Detect reused infrastructure
        for ip, count in ip_count.items():
            if count > 1:
                campaign["reused_iocs"].append(ip)

        # confidence logic
        if campaign["ransomware_domains"]:
            campaign["confidence"] = "HIGH"
        elif campaign["phishing_domains"]:
            campaign["confidence"] = "MEDIUM"

        return campaign
        
    # ============================================================
    # STEP 4 — FINAL ALERT ENGINE
    # ============================================================
    def calculate_final_alert(self, results: list, campaign: dict) -> dict:

        """
        Determine final alert severity for the email.
        """

        alert = {
            "level": "LOW",
            "reasons": [],
            "recommended_actions": []
        }

        malicious_count = 0

        for r in results:
            if r["category"] == "Malicious":
                malicious_count += 1

        # -------------------------
        # HIGH RISK CONDITIONS
        # -------------------------
        if campaign.get("ransomware_domains"):
            alert["level"] = "HIGH"
            alert["reasons"].append("Ransomware infrastructure detected")

        if malicious_count >= 5:
            alert["level"] = "HIGH"
            alert["reasons"].append("Multiple malicious IOCs detected")

        if campaign.get("reused_iocs"):
            alert["level"] = "HIGH"
            alert["reasons"].append("Reused attacker infrastructure")

        # -------------------------
        # MEDIUM RISK CONDITIONS
        # -------------------------
        elif campaign.get("phishing_domains"):
            alert["level"] = "MEDIUM"
            alert["reasons"].append("Phishing indicators detected")

        # -------------------------
        # LOW RISK
        # -------------------------
        else:
            alert["level"] = "LOW"
            alert["reasons"].append("No strong threat indicators")

        # -------------------------
        # RECOMMENDED ACTIONS
        # -------------------------
        if alert["level"] == "HIGH":
            alert["recommended_actions"] = [
                "Block sender and domain",
                "Add IOC to blocklist",
                "Initiate incident response",
                "Search for similar emails"
            ]

        elif alert["level"] == "MEDIUM":
            alert["recommended_actions"] = [
                "Flag email as suspicious",
                "Monitor domain activity",
                "User awareness notification"
            ]

        else:
            alert["recommended_actions"] = [
                "No immediate action required",
                "Log for monitoring"
            ]

        return alert