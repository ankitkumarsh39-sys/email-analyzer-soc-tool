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

#-----------------------------------------------------------------------------

# -------------------------------------------------------------------------
# Valid TLD support (no external dependency)
#
# Why this exists:
# - avoids runtime dependency on tldextract
# - uses a local list of valid TLDs for better precision
# - aligns with internal guidance to use a valid TLD list from IANA
# -------------------------------------------------------------------------

DEFAULT_VALID_TLDS = {
    # Common baseline / fallback only.
    # Load a full list from config/tlds-alpha-by-domain.txt if available.
    "com", "net", "org", "io", "co", "uk", "ie",
    "onion", "test", "example", "invalid", "localhost",
    "zip", "mov"
}

def load_valid_tlds(path: str = "config/tlds-alpha-by-domain.txt") -> set:
    """
    Load valid TLDs from a local IANA-style TLD file.

    Expected format:
    - one TLD per line
    - uppercase or lowercase accepted
    - lines beginning with # are comments

    If the file is missing or invalid, fall back to a minimal built-in set.
    """
    tlds = set(DEFAULT_VALID_TLDS)

    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    tlds.add(line.lower())
    except Exception as e:
        logger.warning("Failed to load TLD file %s: %s", path, e)

    return tlds

VALID_TLDS = load_valid_tlds()

def has_valid_tld(candidate: str) -> bool:
    """
    Basic domain-suffix validation using local valid TLDs.
    """
    if not candidate or "." not in candidate:
        return False

    candidate = candidate.strip().strip(".").lower()
    if not candidate:
        return False

    tld = candidate.rsplit(".", 1)[-1]
    return tld in VALID_TLDS

def is_header_token_false_positive(candidate: str) -> bool:
    """
    Reject header/auth metadata tokens that look like domains but are not.
    """
    candidate = (candidate or "").strip().lower()

    false_positive_exact = {
        "header.from",
        "header.d",
        "header.s",
        "smtp.mailfrom",
        "compauth.none",
    }

    false_positive_prefixes = (
        "header.",
        "smtp.",
        "dkim.",
        "spf.",
        "dmarc.",
        "mime.",
        "content.",
        "message.",
        "auth.",
    )

    if candidate in false_positive_exact:
        return True

    if candidate.startswith(false_positive_prefixes):
        return True

    return False

#---------------------------------------------------------------------------

def dedup_reason_list(reasons: list) -> list:
    """
    Remove duplicate reason strings while preserving original order.

    Why this exists:
    - IOC scoring can add the same reason more than once
    - cache + live scoring + blocklist logic can create duplicates
    - reports should stay clean and readable
    """
    if not reasons:
        return []

    cleaned = []
    seen = set()

    for r in reasons:
        if r is None:
            continue

        text = str(r).strip()
        if not text:
            continue

        if text not in seen:
            seen.add(text)
            cleaned.append(text)

    return cleaned

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

    Returns explicit fields from AbuseIPDB CHECK response only.
    If city or ASN are not present in the response, they remain None.
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
            "country_code": data.get("countryCode"),
            "country_name": data.get("countryName"),
            "usage_type": data.get("usageType"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "hostnames": data.get("hostnames", []),
            "city": data.get("city"),
            "asn": data.get("asn"),
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
    Submit a URL to the ANY.RUN sandbox endpoint.
    """
    if not ANYRUN_API_KEY:
        return {}

    try:
        headers = {
            "API-Key": ANYRUN_API_KEY,
            "Authorization": f"API-Key {ANYRUN_API_KEY}",
            "Accept": "application/json"
        }

        payload = {
            "url": url,
            "env_os": "windows",
            "visibility": "unlisted"
        }

        r = requests.post(
            "https://api.any.run/v1/analysis",
            headers=headers,
            json=payload,
            timeout=20
        )

        if r.status_code not in (200, 201, 202):
            return {
                "source": "ANY.RUN",
                "status": f"failed_{r.status_code}",
                "raw_status": r.text[:500]
            }

        data = r.json()
        analysis_id = data.get("data", {}).get("id") or data.get("id")
        result_url = (
            data.get("url") or
            data.get("result") or
            data.get("data", {}).get("attributes", {}).get("url") or
            data.get("data", {}).get("attributes", {}).get("result")
        )

        output = {
            "source": "ANY.RUN",
            "status": "submitted",
            "analysis_id": analysis_id,
            "raw": data
        }

        if result_url:
            output["url"] = result_url

        return output

    except Exception as e:
        return {
            "source": "ANY.RUN",
            "status": "error",
            "error": str(e)
        }


def anyrun_file_lookup(filename: str, file_bytes: bytes) -> dict:
    """
    Submit a file attachment to ANY.RUN sandbox for analysis.
    """
    if not ANYRUN_API_KEY:
        return {}

    try:
        headers = {
            "API-Key": ANYRUN_API_KEY,
            "Authorization": f"API-Key {ANYRUN_API_KEY}",
            "Accept": "application/json"
        }
        files = {
            "file": (filename, file_bytes)
        }

        r = requests.post(
            "https://api.any.run/v1/analysis",
            headers=headers,
            files=files,
            data={"env_os": "windows", "visibility": "unlisted"},
            timeout=60
        )

        if r.status_code not in (200, 201, 202):
            return {
                "source": "ANY.RUN",
                "status": f"failed_{r.status_code}",
                "raw_status": r.text[:1000]
            }

        data = r.json()
        analysis_id = data.get("data", {}).get("id") or data.get("id")
        analysis_url = (
            data.get("url") or
            data.get("result") or
            data.get("data", {}).get("attributes", {}).get("url") or
            data.get("data", {}).get("attributes", {}).get("result")
        )

        output = {
            "source": "ANY.RUN",
            "status": "submitted",
            "analysis_id": analysis_id,
            "raw": data
        }

        if analysis_url:
            output["url"] = analysis_url

        return output

    except Exception as e:
        return {
            "source": "ANY.RUN",
            "status": "error",
            "error": str(e)
        }


def anyrun_get_analysis(analysis_id: str) -> dict:
    """
    Retrieve ANY.RUN analysis status or report metadata.
    """
    if not ANYRUN_API_KEY or not analysis_id:
        return {}

    headers = {
        "API-Key": ANYRUN_API_KEY,
        "Authorization": f"API-Key {ANYRUN_API_KEY}",
        "Accept": "application/json"
    }

    endpoints = [
        f"https://api.any.run/v1/analysis/{analysis_id}",
        f"https://api.any.run/v1/analysis/{analysis_id}/report",
        f"https://api.any.run/report/{analysis_id}/ioc/json",
    ]

    for endpoint in endpoints:
        try:
            for attempt in range(3):
                r = requests.get(endpoint, headers=headers, timeout=20)
                if r.status_code == 200:
                    data = r.json()
                    response = {
                        "source": "ANY.RUN",
                        "status": "ok",
                        "analysis_id": analysis_id,
                        "raw": data
                    }
                    if isinstance(data, dict):
                        state = (
                            data.get("data", {})
                            .get("attributes", {})
                            .get("state")
                        )
                        if state:
                            response["analysis_state"] = state
                    return response

                if r.status_code in (202, 102):
                    time.sleep(3)
                    continue

                if r.status_code == 404:
                    break

                return {
                    "source": "ANY.RUN",
                    "status": f"failed_{r.status_code}",
                    "analysis_id": analysis_id,
                    "raw_status": r.text[:1000]
                }

        except Exception as e:
            return {
                "source": "ANY.RUN",
                "status": "error",
                "error": str(e),
                "analysis_id": analysis_id
            }

    return {
        "source": "ANY.RUN",
        "status": "not_found",
        "analysis_id": analysis_id
    }


def anyrun_list_analyses(limit: int = 20) -> dict:
    """
    Retrieve recent ANY.RUN analysis history using the official endpoint.
    """
    if not ANYRUN_API_KEY:
        return {}

    headers = {
        "API-Key": ANYRUN_API_KEY,
        "Authorization": f"API-Key {ANYRUN_API_KEY}",
        "Accept": "application/json"
    }
    params = {"limit": limit}

    try:
        r = requests.get("https://api.any.run/v1/analysis", headers=headers, params=params, timeout=20)
        if r.status_code != 200:
            return {
                "source": "ANY.RUN",
                "status": f"failed_{r.status_code}",
                "raw_status": r.text[:1000]
            }

        data = r.json()
        tasks = []
        if isinstance(data, dict):
            tasks = (data.get("data", {}) or {}).get("tasks", []) or []

        return {
            "source": "ANY.RUN",
            "status": "ok",
            "items": tasks,
            "raw": data
        }

    except Exception as e:
        return {
            "source": "ANY.RUN",
            "status": "error",
            "error": str(e)
        }


# -------------------------------------------------------------------------
# URLScan helper
#
# What this function does:
# 1. Submit the URL to urlscan.io
# 2. Wait briefly for the scan result
# 3. Retrieve the finished result
# 4. Return fields that our scoring code already expects:
#    - urlscan_score
#    - urlscan_malicious
#    - scan_id
#    - result_url
#
# Why this is needed:
# The old version only submitted the scan, but never fetched the final result.
# Because of that, scoring always saw urlscan_score = 0 and
# urlscan_malicious = False.
# -------------------------------------------------------------------------

# Module-level convenience wrapper for urlscan to be used elsewhere in this module.
def urlscan_lookup(url: str) -> dict:
    """
    Submit a URL to urlscan.io, then try to retrieve the finished result.

    Why this function exists:
    - The scan API starts the scan and returns a UUID
    - The result API is where the real verdict data lives
    - Our scoring code expects fields like:
        - urlscan_score
        - urlscan_malicious
    """

    # If no API key is configured, return empty data safely
    if not URLSCAN_API_KEY:
        return {}

    try:
        # Use the documented header name from urlscan docs
        headers = {
            "api-key": URLSCAN_API_KEY,
            "Content-Type": "application/json"
        }

        payload = {
            "url": url,
            "visibility": "unlisted"
        }

        # ------------------------------------------------------------
        # STEP 1: Submit the URL for scanning
        # ------------------------------------------------------------
        submit_resp = requests.post(
            "https://urlscan.io/api/v1/scan/",
            headers=headers,
            json=payload,
            timeout=20
        )

        if submit_resp.status_code not in (200, 201):
            return {
                "source": "urlscan",
                "status": f"failed_{submit_resp.status_code}",
                "raw_status": submit_resp.text[:1000],
                "urlscan_score": 0,
                "urlscan_malicious": False,
                "result_url": "",
            }

        submit_data = submit_resp.json()

        # urlscan returns a UUID for the scan
        scan_id = submit_data.get("uuid")

        # These links may be returned by the submission response
        result_api = submit_data.get("api")
        result_page = submit_data.get("result")

        # Base output in case the result is not ready yet
        output = {
            "source": "urlscan",
            "status": "submitted",
            "scan_id": scan_id,
            "result_url": result_page,
            "raw_submit": submit_data
        }

        # If we somehow do not get a UUID, just return the submission response
        if not scan_id:
            return output

        # ------------------------------------------------------------
        # STEP 2: Poll the result API
        #
        # Why polling is needed:
        # - urlscan scans are asynchronous
        # - the result may not exist immediately after submission
        # ------------------------------------------------------------
        result_headers = {
            "api-key": URLSCAN_API_KEY,
            "Accept": "application/json"
        }

        # Try a few times before giving up
        for _ in range(5):
            time.sleep(3)

            # Use the API URL returned by submit response if present,
            # otherwise build the standard result endpoint
            result_endpoint = result_api or f"https://urlscan.io/api/v1/result/{scan_id}/"

            result_resp = requests.get(
                result_endpoint,
                headers=result_headers,
                timeout=20
            )

            # If result is ready
            if result_resp.status_code == 200:
                result_json = result_resp.json()

                # Safely read the result fields documented by urlscan
                overall = (result_json.get("verdicts", {}) or {}).get("overall", {}) or {}
                page = result_json.get("page", {}) or {}

                score = overall.get("score", 0)
                malicious = score > 0

                output.update({
                    "status": "ok",
                    "urlscan_score": score,
                    "urlscan_malicious": malicious,
                    "page_domain": page.get("domain"),
                    "page_title": page.get("title"),
                    "raw_result": result_json
                })

                return output

            # If the result is not ready yet, keep retrying
            if result_resp.status_code in (404, 429):
                continue

            # Other non-success result errors
            output["status"] = f"result_failed_{result_resp.status_code}"
            output["raw_result_status"] = result_resp.text[:500]
            return output

        # If we never got a result in time
        output["status"] = "result_not_ready"
        return output

    except Exception as e:
            return {
            "source": "urlscan",
            "status": "error",
            "error": str(e),
            "urlscan_score": 0,
            "urlscan_malicious": False,
            "result_url": "",
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

def is_valid_domain_candidate(candidate: str) -> bool:
    """
    Validate domain candidates using tldextract / Public Suffix logic.

    Why this is needed:
    - avoids false positives like header.from / smtp.mailfrom
    - avoids email local-part fragments like ankit.gp.kumar
    - preserves real domains that use valid TLDs, including newer TLDs
    """
    if not candidate or "." not in candidate:
        return False

    candidate = candidate.strip().lower().strip(".")
    if not candidate:
        return False

    ext = tldextract.extract(candidate)

    # Must have both a domain and suffix to be considered a real domain
    if not ext.domain or not ext.suffix:
        return False

    return True


def is_header_token_false_positive(candidate: str) -> bool:
    """
    Reject header/auth metadata tokens that look like domains but are not.
    """
    candidate = (candidate or "").strip().lower()

    false_positive_exact = {
        "header.from",
        "header.d",
        "header.s",
        "smtp.mailfrom",
        "compauth.none",
    }

    false_positive_prefixes = (
        "header.",
        "smtp.",
        "dkim.",
        "spf.",
        "dmarc.",
        "mime.",
        "content.",
        "message.",
        "auth.",
    )

    if candidate in false_positive_exact:
        return True

    if candidate.startswith(false_positive_prefixes):
        return True

    return False

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

        # -----------------------------------------------------------------
        # Domain extraction (final, dependency-free version)
        #
        # Strategy:
        # 1) Extract email domains explicitly
        # 2) Extract generic domain-like values
        # 3) Filter header/auth false positives
        # 4) Skip email local-part fragments (e.g. ankit.gp.kumar@accent.com)
        # 5) Validate final suffix using the local valid-TLD set
        # -----------------------------------------------------------------

        # 1) Extract email domains explicitly
        email_domain_pat = re.compile(
            r"(?i)(?:[a-z0-9._%+\-=?]+)@((?:[a-z0-9\-]+\.)+[a-z]{2,63})"
        )

        email_domains = set()
        for m in email_domain_pat.finditer(text):
            domain_value = self.normalize_ioc(m.group(1), "domain")
            if domain_value and has_valid_tld(domain_value):
                email_domains.add(domain_value)

        # 2) Extract generic domain candidates
        domain_pat = re.compile(
            r"(?i)\b((?:[a-z0-9\-]{1,63}\.)+[a-z]{2,63})\b"
        )

        domains = set(email_domains)

        for m in domain_pat.finditer(text):
            raw_candidate = m.group(1)
            norm = self.normalize_ioc(raw_candidate, "domain")

            if not norm:
                continue

            # Skip obvious metadata/header false positives
            if is_header_token_false_positive(norm):
                continue

            # Skip path/file-like tokens only when they appear in file/path context
            left_context = text[max(0, m.start() - 80):m.start()]
            right_context = text[m.end():m.end() + 80]

            file_context_tokens = (
                "filename", "name=", "attachment", "content-type",
                "content-disposition", "multipart", "boundary=",
                "/", "\\"
            )

            in_file_context = any(
                tok in left_context.lower() or tok in right_context.lower()
                for tok in file_context_tokens
            )

            if in_file_context:
                continue

            # Skip if this “domain” is really the local part of an email-like token
            # Example: ankit.gp.kumar@accent.com -> skip ankit.gp.kumar
            if right_context.startswith("@"):
                continue

            next_token = right_context.split()[0] if right_context.split() else ""
            if "@" in next_token:
                continue

            if right_context.startswith("=") and "@" in right_context:
                continue

            # Final suffix validation
            if not has_valid_tld(norm):
                continue

            domains.add(norm)

        domains = sorted(domains)

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

    def _build_provider_context(self, provider_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize provider context storage shape.
        """
        return {
            "urlscan": provider_context.get("urlscan", {}) or {},
            "abuseipdb": provider_context.get("abuseipdb", {}) or {},
            "anyrun": provider_context.get("anyrun", {}) or {},
            "talos": provider_context.get("talos", {}) or {},
            "rdap": provider_context.get("rdap", {}) or {},
            "whois": provider_context.get("whois", {}) or {},
        }

    def enrich_ioc(self, raw: str, ioc_type: str, force_refresh: bool = False) -> IOCRecord:
        """
        Enrich and score a single IOC entity.
        """
        normalized = self.normalize_ioc(raw, ioc_type)
        wl_record = self._get_whitelist_record(normalized, ioc_type)
        bl_record = self._get_blocklist_record(normalized, ioc_type)

        is_wl = wl_record is not None
        is_bl = bl_record is not None
        cached = None if force_refresh else get_cached(ioc_type, normalized)

        if cached:
            score = int(cached.get("vt_malicious", 0))
            status = str(cached.get("vt_status", "Cached"))
            final_score = int(cached.get("final_score", 0))

            reasons = cached.get("reason", []) or []
            reasons = dedup_reason_list(reasons)

            category = str(cached.get("category", "Clean"))
            provider_context = self._build_provider_context(cached.get("provider_context", {}) or {})

        else:
            score, status = self.vt.lookup(ioc_type, normalized)
            provider_context = {
                "urlscan": {},
                "abuseipdb": {},
                "anyrun": {},
                "talos": {},
                "rdap": {},
                "whois": {},
            }

            if ioc_type == "url":
                provider_context["urlscan"] = urlscan_lookup(normalized)
                provider_context["anyrun"] = anyrun_url_lookup(normalized)
                provider_context["talos"] = talos_lookup_reference(normalized)

            elif ioc_type == "ip":
                provider_context["abuseipdb"] = abuseipdb_lookup(normalized)
                provider_context["talos"] = talos_lookup_reference(normalized)

            elif ioc_type == "domain":
                provider_context["talos"] = talos_lookup_reference(normalized)
                provider_context["rdap"] = rdap_lookup_reference(normalized)
                try:
                    provider_context["whois"] = whois_lookup(normalized)
                except Exception as e:
                    self.logger.error("WHOIS lookup crashed for domain '%s': %s", normalized, str(e))
                    provider_context["whois"] = {"status": "error", "error": str(e)}

            urlscan_data = provider_context.get("urlscan", {}) or {}
            abuse_data = provider_context.get("abuseipdb", {}) or {}

            final_score = 0
            reasons = []

            if score > 0:
                final_score += 3
                reasons.append(f"VirusTotal detections: {score}")

            if bool(urlscan_data.get("urlscan_malicious", False)):
                final_score += 3
                reasons.append(f"urlscan malicious verdict (score={int(urlscan_data.get('urlscan_score', 0) or 0)})")

            if int(abuse_data.get("abuse_score", 0) or 0) >= 70:
                final_score += 2
                reasons.append(f"AbuseIPDB high confidence ({abuse_data.get('abuse_score')})")

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
                    if bl_desc and bl_desc not in reasons:
                        reasons.append(bl_desc)

            if is_wl and wl_record:
                wl_desc = str(wl_record.get("description", "")).strip()
                reason_text = "Whitelisted IOC"
                if wl_desc:
                    reason_text += f" - {wl_desc}"
                if reason_text not in reasons:
                    reasons.append(reason_text)

            if ioc_type == "url":
                _ = self.analyze_url_ioc(normalized, score, status)

            if ioc_type == "hash":
                _ = self.analyze_attachment_ioc(
                    filename="unknown",
                    sha256=normalized,
                    vt_score=score,
                    vt_status=status,
                )

            if ioc_type == "domain":
                whois_data = provider_context.get("whois", {}) or {}
                age = whois_data.get("age_days")
                if age is not None:
                    try:
                        age_val = int(age)
                    except Exception:
                        age_val = None
                    if age_val is not None:
                        if age_val < 30:
                            final_score += 3
                            reasons.append(f"New domain ({age_val} days old)")
                        elif age_val < 90:
                            final_score += 2
                            reasons.append(f"Recent domain ({age_val} days old)")

                if "login" in normalized or "verify" in normalized or "secure" in normalized:
                    final_score += 2
                    reasons.append("Phishing keyword in domain")
                if "microsoft" in normalized and "fake" in normalized:
                    final_score += 3
                    reasons.append("Brand impersonation detected (Microsoft)")

            reasons = dedup_reason_list(reasons)
            category = "Malicious" if final_score >= 3 else "Clean"

            if force_refresh or not cached:
                set_cache(ioc_type, normalized, {
                    "vt_malicious": score,
                    "vt_status": status,
                    "final_score": final_score,
                    "category": category,
                    "reason": reasons,
                    "provider_context": provider_context,
                })

        return IOCRecord(
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
            provider_context=self._build_provider_context(provider_context),
        )

    def reanalyze_ioc(self, item: Dict[str, Any]) -> IOCRecord:
        """
        Re-analyze a single IOC entry and return an updated IOCRecord.
        """
        raw = item.get("raw", "") or item.get("normalized", "")
        ioc_type = item.get("ioc_type", "")
        return self.enrich_ioc(raw, ioc_type, force_refresh=True)

    # -------------------------------------------------------------------------
    # Main scoring entry
    # -------------------------------------------------------------------------
    def analyze_text_iocs(self, text: str, force_refresh: bool = False) -> Dict[str, Any]:
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

        force_refresh:
        If True, bypasses IOC cache and performs fresh enrichment.
        """
        self.reset_cancel_state()
        extracted = self.extract_iocs(text)

        results: List[IOCRecord] = []
        malicious: List[IOCRecord] = []
        clean: List[IOCRecord] = []

        self.logger.debug(f"======================Extracted IOCs:======================")
        def process(items: List[str], ioc_type: str) -> None:
            """
            Process IOCs using enrich_ioc() as the single source of truth.

            Why this version is correct:
            - avoids duplicate scoring logic
            - avoids duplicate reason strings
            - keeps provider_context, cache, and category consistent
            """
            for raw in items:
                self.check_for_exit()

                # Enrich and score only once
                record = self.enrich_ioc(raw, ioc_type, force_refresh=force_refresh)

                # Final cleanup before storing
                record.reason = dedup_reason_list(record.reason or [])

                results.append(record)
                (malicious if record.category == "Malicious" else clean).append(record)

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

        Rule:
        - HIGH if ransomware infrastructure exists
        - HIGH if many malicious IOCs are present
        - HIGH if attacker infrastructure is reused
        - MEDIUM if phishing indicators exist without stronger HIGH evidence
        - LOW otherwise
        """

        alert = {
            "level": "LOW",
            "reasons": [],
            "recommended_actions": []
        }

        malicious_count = sum(1 for r in results if r.get("category") == "Malicious")

        # HIGH risk
        if campaign.get("ransomware_domains") or malicious_count >= 5 or campaign.get("reused_iocs"):
            alert["level"] = "HIGH"

            if campaign.get("ransomware_domains"):
                alert["reasons"].append("Ransomware infrastructure detected")

            if malicious_count >= 5:
                alert["reasons"].append("Multiple malicious IOCs detected")

            if campaign.get("reused_iocs"):
                alert["reasons"].append("Reused attacker infrastructure")

        # MEDIUM risk
        elif campaign.get("phishing_domains"):
            alert["level"] = "MEDIUM"
            alert["reasons"].append("Phishing indicators detected")

        # LOW risk
        else:
            alert["level"] = "LOW"
            alert["reasons"].append("No strong threat indicators")

        # Keep reasons clean
        alert["reasons"] = dedup_reason_list(alert["reasons"])

        # Recommended actions
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