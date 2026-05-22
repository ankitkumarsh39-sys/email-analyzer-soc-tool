"""
analyzer.py - Email Analysis Core

- Accepts: .eml file path OR folder path (uses newest .eml)
- Parses email using mailparser
- Extracts: full headers, focus headers, mismatch flags, received hops, auth results
- Extracts: URLs, hidden HTML, attachments SHA256
- Extracts IOCs (IPs, domains, URLs, hashes) from body (NO CVE)
- Returns a dict for MailReporter (JSON/TXT/Blocklist)

Logging:
- Does NOT configure handlers.
- main.py config controls console + reports/email_analysis_<timestamp>.log + logging/email.log
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

from ioc_lib.ioc_validator import extract_iocs_from_text, classify_iocs, format_ioc_report

logger = logging.getLogger(__name__)

URL_REGEX = re.compile(r"\bhttps?://[^\s<>\"')]+", re.IGNORECASE)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_str(value: Any, limit: int = 200) -> str:
    if value is None:
        return ""
    s = str(value)
    return s[:limit] + ("..." if len(s) > limit else "")


def normalize_url(url: str) -> str:
    if not url:
        return url
    return url.strip().strip(').,;\"\'')  # safe cleanup


def extract_urls_from_text(text: str) -> List[str]:
    if not text:
        return []
    urls = {normalize_url(u) for u in URL_REGEX.findall(text)}
    return sorted(u for u in urls if u)


def extract_urls_from_html(html: str) -> List[str]:
    if not html:
        return []
    urls: Set[str] = set()
    soup = BeautifulSoup(html, "html.parser")

    for a in soup.find_all("a", href=True):
        urls.add(normalize_url(a["href"]))

    for img in soup.find_all("img", src=True):
        urls.add(normalize_url(img["src"]))

    for u in URL_REGEX.findall(html):
        urls.add(normalize_url(u))

    return sorted(u for u in urls if u)


def find_hidden_elements(html: str) -> int:
    if not html:
        return 0
    soup = BeautifulSoup(html, "html.parser")

    def is_hidden_style(style_value: str) -> bool:
        v = style_value.replace(" ", "").lower()
        return ("display:none" in v) or ("visibility:hidden" in v) or ("font-size:0" in v)

    hidden = soup.find_all(style=lambda value: value and is_hidden_style(value))
    return len(hidden)


def decode_attachment_payload(payload: Any) -> Optional[bytes]:
    if payload is None:
        return None
    if isinstance(payload, (bytes, bytearray)):
        return bytes(payload)
    if isinstance(payload, str):
        try:
            return base64.b64decode(payload, validate=True)
        except Exception:
            return payload.encode(errors="ignore")
    return str(payload).encode(errors="ignore")


def resolve_eml_path(input_path: str) -> Optional[str]:
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


def _get_header_case_insensitive(headers: Dict[str, Any], key: str) -> Any:
    if not isinstance(headers, dict):
        return None
    for k, v in headers.items():
        if str(k).lower() == key.lower():
            return v
    return None


def _headers_as_dict(mail) -> Dict[str, Any]:
    h = getattr(mail, "headers", None)
    return h if isinstance(h, dict) else {}


def _extract_received_hops(mail) -> List[Dict[str, Any]]:
    received = getattr(mail, "received", None) or []
    headers = _headers_as_dict(mail)

    if not received:
        received_raw = _get_header_case_insensitive(headers, "Received")
        if isinstance(received_raw, str):
            received_raw = [received_raw]
        elif received_raw is None:
            received_raw = []
        received = [{"raw": hop} for hop in received_raw]

    return received


def _domain_from_addr(text: str) -> str:
    if not text:
        return ""
    m = re.search(r'[\w\.\-+%]+@([\w\.\-]+\.[A-Za-z]{2,})', str(text))
    return (m.group(1).lower() if m else "")


def _header_mismatch_flags(headers: Dict[str, Any]) -> Dict[str, Any]:
    from_h = str(_get_header_case_insensitive(headers, "From") or "")
    reply_to = str(_get_header_case_insensitive(headers, "Reply-To") or "")
    return_path = str(_get_header_case_insensitive(headers, "Return-Path") or "")
    sender = str(_get_header_case_insensitive(headers, "Sender") or "")

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
        v = _get_header_case_insensitive(headers, k)
        if v is not None:
            out[k] = v
    return out


def _domains_from_urls(urls: List[str]) -> List[str]:
    out = set()
    for u in urls or []:
        try:
            host = urlparse(u).netloc.lower()
            if host:
                out.add(host)
        except Exception:
            pass
    return sorted(out)


def analyze_email(input_path: str) -> Optional[Dict[str, Any]]:
    logger.info("========== Analyze request started ==========")
    logger.info("Input path: %s", input_path)

    eml_path = resolve_eml_path(input_path)
    if not eml_path:
        logger.error("No .eml found for input: %s", input_path)
        return None

    if os.path.isdir(input_path):
        logger.info("Folder provided. Newest .eml selected: %s", eml_path)
    else:
        logger.info("EML file provided: %s", eml_path)

    try:
        mail = mailparser.parse_from_file(eml_path)
        logger.info("Email parsed successfully.")
    except Exception:
        logger.critical("Failed to parse EML: %s", eml_path, exc_info=True)
        return None

    # Headers (full + focus + mismatch)
    headers_raw = _headers_as_dict(mail)
    headers_focus = _extract_header_focus(headers_raw)
    mismatch_flags = _header_mismatch_flags(headers_raw)

    # Metadata
    subject = safe_str(getattr(mail, "subject", ""), 300)
    from_addr = safe_str(getattr(mail, "from_", ""), 500)
    to_addr = safe_str(getattr(mail, "to", ""), 500)

    logger.info("Metadata: Subject=%s", subject)
    logger.info("Metadata: From=%s", from_addr)
    logger.info("Metadata: To=%s", to_addr)

    # Received hops
    received = _extract_received_hops(mail)
    logger.info("Received hops detected: %d", len(received))

    # Auth results (also in focus headers)
    auth_results = _get_header_case_insensitive(headers_raw, "Authentication-Results")
    if auth_results:
        logger.info("Authentication-Results found: %s", safe_str(auth_results, 500))
    else:
        logger.warning("Authentication-Results not found.")

    # Body extraction
    text_plain = "\n".join(mail.text_plain) if getattr(mail, "text_plain", None) else ""
    text_html = "\n".join(mail.text_html) if getattr(mail, "text_html", None) else ""
    logger.info("Body lengths: plain=%d html=%d", len(text_plain), len(text_html))

    # URL extraction
    urls: Set[str] = set()
    urls.update(extract_urls_from_text(text_plain))
    urls.update(extract_urls_from_html(text_html))
    urls_sorted = sorted(urls)

    logger.info("URLs extracted: %d", len(urls_sorted))
    for u in urls_sorted[:30]:
        logger.info("URL: %s", u)

    # Hidden HTML elements
    hidden_count = find_hidden_elements(text_html)
    if hidden_count > 0:
        logger.warning("Hidden HTML elements detected: %d", hidden_count)

    # IOC extraction - use HTML->text to avoid HTML fragments
    html_text_for_iocs = BeautifulSoup(text_html, "html.parser").get_text("\n") if text_html else ""
    combined_text = f"{text_plain}\n{html_text_for_iocs}"

    try:
        ips, domains, ioc_urls, hashes = extract_iocs_from_text(combined_text)

        # Improve domains list by adding domains from URLs we extracted
        domains = sorted(set(domains).union(_domains_from_urls(urls_sorted)))

        iocs = classify_iocs(ips, domains, ioc_urls, hashes)
        logger.info("IOC extraction complete.")
        logger.warning(
            "IOC counts: ips=%d domains=%d urls=%d hashes=%d",
            len(ips), len(domains), len(ioc_urls), len(hashes)
        )

        """ Log formatted IOC report"""
        try:
            report_text = format_ioc_report(iocs)
            for line in report_text.splitlines():
                logger.info("IOC_REPORT: %s", line)
        except Exception:
            logger.error("IOC report formatting failed.", exc_info=True)

    except Exception:
        logger.error("IOC extraction failed.", exc_info=True)
        iocs = {
            "ips": [], "domains": [], "urls": [], "hashes": [],
            "counts": {"ips": 0, "domains": 0, "urls": 0, "hashes": 0},
            "error": "IOC extraction failed"
        }

    # Attachments
    attachments_info: List[Dict[str, Any]] = []
    attachments = getattr(mail, "attachments", None) or []
    logger.info("Attachments found: %d", len(attachments))

    for att in attachments:
        try:
            filename = att.get("filename", "unknown")
            payload = decode_attachment_payload(att.get("payload"))
            if not payload:
                logger.warning("Attachment payload missing/undecodable: %s", filename)
                continue
            h = sha256_bytes(payload)
            attachments_info.append({"filename": filename, "size": len(payload), "sha256": h})
            logger.info("Attachment hashed: filename=%s size=%d sha256=%s", filename, len(payload), h)
        except Exception:
            logger.error("Attachment processing failed.", exc_info=True)

    # Final result dict (includes FULL header analysis)
    result = {
        "input_path": input_path,
        "eml_used": eml_path,
        "subject": subject,
        "from": from_addr,
        "to": to_addr,

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
    }

    logger.info("========== Analyze request completed successfully ==========")
    return result   