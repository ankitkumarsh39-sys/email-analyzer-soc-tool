# mail_reporter
import os
import json
import logging
import pandas as pd
import re
import datetime as dt

from typing import Dict, Any
from urllib.parse import quote_plus, urlparse

from docx import Document
from docx.enum.table import WD_CELL_VERTICAL_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor

logger = logging.getLogger(__name__)


def is_ip(value):
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value)


class MailReporter:
    """
    Generates:
      - JSON report (machine-readable)
      - TXT report (human-readable)
      - Blocklist
    Includes:
      - full headers
      - header analysis
      - IOC section
      - VT IOC scoring
    """

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)
        logger.info("Initializing MailReporter with output directory: %s", self.output_dir)

    def _timestamp(self):
        return dt.datetime.now().strftime("%Y%m%d_%H%M%S")

    def _normalize_iocs(self, iocs: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        """
        Convert IOC structure into stable report format.
        """

        if not iocs:
            return {
                "IPs": {"count": 0, "items": []},
                "Domains": {"count": 0, "items": []},
                "URLs": {"count": 0, "items": []},
                "File_Hashes": {"count": 0, "items": []},
            }

        if isinstance(iocs, dict) and "counts" in iocs:
            ips = iocs.get("ips", []) or []
            domains = iocs.get("domains", []) or []
            urls = iocs.get("urls", []) or []
            hashes = iocs.get("hashes", []) or []
            counts = iocs.get("counts", {}) or {}

            return {
                "IPs": {"count": counts.get("ips", len(ips)), "items": ips},
                "Domains": {"count": counts.get("domains", len(domains)), "items": domains},
                "URLs": {"count": counts.get("urls", len(urls)), "items": urls},
                "File_Hashes": {"count": counts.get("hashes", len(hashes)), "items": hashes},
            }

        out = {}
        for k, v in iocs.items():
            if isinstance(v, dict) and "count" in v and "items" in v:
                out[k] = v

        for key in ("IPs", "Domains", "URLs", "File_Hashes"):
            out.setdefault(key, {"count": 0, "items": []})

        return out

    def _dedup_reasons(self, reasons: list) -> list:
        """
        Return ordered deduplicated reason strings.
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

    def _pick_urlscan_result_url(self, urlscan: Dict[str, Any]) -> str:
        """
        Return the best available URLScan result link.
        """
        if not urlscan:
            return ""

        return (
            urlscan.get("result_url", "")
            or urlscan.get("result", "")
            or urlscan.get("url", "")
        )

    def _normalize_provider_context(self, provider_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize provider context before writing reports.
        """
        provider_context = {
            key: value
            for key, value in dict(provider_context or {}).items()
            if key in {"urlscan", "abuseipdb", "talos", "rdap", "whois", "hosting", "hosting_provider"}
        }

        urlscan = dict(provider_context.get("urlscan", {}) or {})
        if urlscan:
            urlscan.setdefault("result_url", self._pick_urlscan_result_url(urlscan))
            provider_context["urlscan"] = urlscan

        return provider_context

    def generate_json_report(self, email_data: Dict[str, Any]) -> str:
        """
        Create JSON report with all available data.
        """
        ts = self._timestamp()
        report_path = os.path.join(self.output_dir, f"email_analysis_{ts}.json")

        safe_ioc_scoring = []
        for item in email_data.get("ioc_scoring", []) or []:
            safe_item = dict(item)
            safe_item["reason"] = self._dedup_reasons(safe_item.get("reason", []) or [])
            safe_item["provider_context"] = self._normalize_provider_context(
                safe_item.get("provider_context", {}) or {}
            )
            safe_ioc_scoring.append(safe_item)

        report = {
            "timestamp": dt.datetime.now().isoformat(),
            "input_path": email_data.get("input_path"),
            "email_metadata": {
                "subject": email_data.get("subject"),
                "from": email_data.get("from"),
                "to": email_data.get("to"),
                "eml_used": email_data.get("eml_used"),
            },
            "header_analysis": email_data.get("header_analysis", {}),
            "headers_focus": email_data.get("headers_focus", {}),
            "headers_raw": email_data.get("headers_raw", {}),
            "received_hops": email_data.get("received_hops", []),
            "auth_results": email_data.get("auth_results"),
            "subject_analysis": email_data.get("subject_analysis", {}),
            "sender_intelligence": email_data.get("sender_intelligence", {}),
            "sender_domains": email_data.get("sender_domains", []),
            "body_stats": email_data.get("body_stats", {}),
            "urls_extracted": email_data.get("urls_extracted", []),
            "urls_extracted_detail": email_data.get("urls_extracted_detail", []),
            "iocs": email_data.get("iocs", {}),
            "attachments": email_data.get("attachments", []),
            "ioc_scoring": safe_ioc_scoring,
            "osint_summary": email_data.get("osint_summary", {}),
            "campaign": email_data.get("campaign", {}),
            "alert": email_data.get("alert", {}),
            "email_score": email_data.get("email_score"),
            "email_severity": email_data.get("email_severity"),
            "email_score_reasons": email_data.get("email_score_reasons", []),
            "defanged_iocs_text": email_data.get("defanged_iocs_text", ""),
            "analyst_comment": email_data.get("analyst_comment", ""), # Analyst-written investigation notes from UI
            "response_actions": email_data.get("response_actions", {}),
            "investigation_submitted": email_data.get("investigation_submitted", False),
            "submitted_time": email_data.get("submitted_time")
            or (email_data.get("response_actions", {}) or {}).get("submitted_time"),
        }

        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        logger.info("JSON report generated: %s", report_path)
        return report_path

    def generate_text_report(self, email_data: Dict[str, Any]) -> str:
        """
        Create a detailed plain-text analyst report with the requested sections.
        If data is missing, prints 'N/A' for that field.
        """
        print(
            "TXT REPORT COMMENT =",
            repr(email_data.get("analyst_comment"))
        )
        ts = self._timestamp()
        report_path = os.path.join(self.output_dir, f"email_analysis_{ts}.txt")

        iocs_norm = self._normalize_iocs(email_data.get("iocs", {}))
        urls = email_data.get("urls_extracted", []) or []
        attachments = email_data.get("attachments", []) or []
        body_stats = email_data.get("body_stats", {}) or {}

        headers_focus = email_data.get("headers_focus", {}) or {}
        headers_raw = email_data.get("headers_raw", {}) or {}
        received_hops = email_data.get("received_hops", []) or []
        header_analysis = email_data.get("header_analysis", {}) or {}
        mismatch = header_analysis.get("mismatch_flags", {}) or {}
        vt_results = email_data.get("ioc_scoring", []) or []
        wrapper_evidence = email_data.get('urls_extracted_detail', []) or []

        def _safe(v, default='N/A'):
            return default if v is None or v == '' else v

        # helper to match wrapper evidence to an IOC normalized value
        def _find_final_url_for_ioc(normalized_value: str) -> str:
            if not normalized_value:
                return 'N/A'
            for w in wrapper_evidence:
                for key in ('final_ioc_url', 'decoded_url', 'wrapped_url'):
                    v = (w.get(key) or '')
                    if not v:
                        continue
                    if v == normalized_value or normalized_value in v or v in normalized_value:
                        return v
            return normalized_value

        with open(report_path, "w", encoding="utf-8") as f:
            # Executive Summary
            f.write("=" * 80 + "\n")
            f.write("EXECUTIVE SUMMARY\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"Subject           : { _safe(email_data.get('subject')) }\n")
            f.write(f"From              : { _safe(email_data.get('from')) }\n")
            f.write(f"To                : { _safe(email_data.get('to')) }\n")
            f.write(f"EML file          : { _safe(email_data.get('eml_used')) }\n")
            f.write(f"Severity          : { _safe(email_data.get('email_severity','Unknown')) }\n")
            f.write(f"Score             : { _safe(email_data.get('email_score',0)) }\n")
            f.write("\n")

            # Email Overview
            f.write("=" * 80 + "\n")
            f.write("EMAIL OVERVIEW\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"Plain text length : { body_stats.get('plain_length', 0) } chars\n")
            f.write(f"HTML length       : { body_stats.get('html_length', 0) } chars\n")
            f.write(f"Hidden HTML count : { body_stats.get('hidden_html_count', 0) }\n")
            f.write(f"Attachments found  : { len(attachments) }\n")
            f.write(f"Extracted URLs     : { len(urls) }\n")
            f.write("\n")

            # Authentication
            f.write("=" * 80 + "\n")
            f.write("AUTHENTICATION\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"Authentication-Results: { _safe(email_data.get('auth_results','N/A')) }\n")
            f.write("Header mismatch flags:\n")
            if mismatch:
                for k, v in mismatch.items():
                    f.write(f"  {k:20s}: {v}\n")
            else:
                f.write("  N/A\n")
            f.write("\n")

            # Sender Intelligence
            sender_intelligence = email_data.get('sender_intelligence', {}) or {}
            f.write("=" * 80 + "\n")
            f.write("SENDER INTELLIGENCE\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"Risk Score        : { _safe(sender_intelligence.get('risk_score', 0)) }\n")
            f.write(f"Verdict           : { _safe(sender_intelligence.get('verdict', 'Needs Review')) }\n")
            authentication = sender_intelligence.get('authentication', {}) or {}
            f.write(f"SPF Authentication: { _safe(authentication.get('spf', 'unknown')) }\n")
            f.write(f"DMARC Authentication: { _safe(authentication.get('dmarc', 'unknown')) }\n")

            def _provider_value(value, status, label):
                if value not in (None, "", [], {}):
                    return value
                if status in {"not_found", "nxdomain", "no_records"}:
                    return "Not found"
                if status and status not in {"ok", "found"}:
                    return f"Unavailable ({status})"
                return f"Unavailable ({label} did not provide this field)"

            for reason in sender_intelligence.get('reasons', []) or []:
                f.write(f"Reason            : { _safe(reason) }\n")

            for domain in sender_intelligence.get('domains', []) or []:
                dns = domain.get('dns', {}) or {}
                whois = domain.get('whois', {}) or {}
                talos = domain.get('talos', {}) or {}
                rdap = domain.get('rdap', {}) or {}
                urlscan = domain.get('urlscan_search', {}) or {}
                resolved_ips = domain.get('resolved_ips', []) or []
                resolved_statuses = [
                    (dns.get(record_type, {}) or {}).get('status')
                    for record_type in ('a', 'aaaa')
                ]
                resolved_status = (
                    'found' if resolved_ips else
                    'no_records' if all(
                        status in {'ok', 'no_records', 'nxdomain'}
                        for status in resolved_statuses
                    ) else
                    next((status for status in resolved_statuses if status not in {'ok', 'no_records', 'nxdomain'}), 'no_records')
                )
                f.write(f"\nDomain            : { _safe(domain.get('domain')) }\n")
                f.write(f"Header roles      : { ', '.join(domain.get('headers', []) or []) or 'N/A' }\n")
                f.write(f"WHOIS status      : { _safe(whois.get('status'), 'Unavailable (no result)') }\n")
                f.write(f"Domain age (days) : { _provider_value(domain.get('domain_age_days'), whois.get('status'), 'WHOIS') }\n")
                f.write(f"WHOIS Registrar   : { _provider_value(whois.get('registrar'), whois.get('status'), 'WHOIS') }\n")
                f.write(f"WHOIS Created     : { _provider_value(whois.get('created'), whois.get('status'), 'WHOIS') }\n")
                f.write(f"WHOIS Expires     : { _provider_value(whois.get('expires'), whois.get('status'), 'WHOIS') }\n")
                f.write(f"WHOIS Nameservers : { ', '.join(whois.get('nameservers', []) or []) or _provider_value(None, whois.get('status'), 'WHOIS') }\n")
                f.write(f"RDAP Lookup       : { _provider_value(rdap.get('portal_lookup'), rdap.get('status', 'ok'), 'RDAP') }\n")
                f.write(f"SPF ({domain.get('spf_status', 'unknown')}): { ', '.join(domain.get('spf_records', []) or []) or _provider_value(None, domain.get('spf_status'), 'DNS') }\n")
                f.write(f"DMARC ({domain.get('dmarc_status', 'unknown')}): { ', '.join(domain.get('dmarc_records', []) or []) or _provider_value(None, domain.get('dmarc_status'), 'DNS') }\n")
                f.write(f"DNS A records     : { ', '.join((dns.get('a', {}) or {}).get('records', []) or []) or _provider_value(None, (dns.get('a', {}) or {}).get('status'), 'DNS') }\n")
                f.write(f"DNS AAAA records  : { ', '.join((dns.get('aaaa', {}) or {}).get('records', []) or []) or _provider_value(None, (dns.get('aaaa', {}) or {}).get('status'), 'DNS') }\n")
                f.write(f"DNS TXT           : { ', '.join((dns.get('txt', {}) or {}).get('records', []) or []) or _provider_value(None, (dns.get('txt', {}) or {}).get('status'), 'DNS') }\n")
                f.write(f"Resolved IPs      : { ', '.join(resolved_ips) or _provider_value(None, resolved_status, 'DNS') }\n")
                f.write(f"MX records        : { ', '.join((dns.get('mx', {}) or {}).get('records', []) or []) or _provider_value(None, (dns.get('mx', {}) or {}).get('status'), 'DNS') }\n")
                f.write(f"VirusTotal        : { _safe((domain.get('virustotal', {}) or {}).get('status')) }\n")
                f.write(f"VT malicious count: { _safe((domain.get('virustotal', {}) or {}).get('malicious', 0)) }\n")
                f.write(f"Talos Lookup      : { _safe(talos.get('portal_lookup')) }\n")
                f.write(f"URLScan status    : { _safe(urlscan.get('status'), 'Unavailable (no result)') }\n")
                f.write(f"URLScan search    : { _safe(urlscan.get('search_url')) } ({_safe(urlscan.get('result_count', 0))} matches)\n")
                f.write(f"Whitelisted       : { _safe(domain.get('whitelisted', False)) }\n")
                f.write(f"Blocklisted       : { _safe(domain.get('blocklisted', False)) }\n")
                f.write(f"Risk Score        : { _safe(domain.get('risk_score', 0)) }\n")
                for reason in domain.get('reasons', []) or []:
                    f.write(f"  Reason          : { _safe(reason) }\n")

                for resolved_ip in domain.get('resolved_ip_intelligence', []) or []:
                    abuse = resolved_ip.get('abuseipdb', {}) or {}
                    resolved_urlscan = resolved_ip.get('urlscan_search', {}) or {}
                    f.write(f"  Resolved IP     : { _safe(resolved_ip.get('ip')) }\n")
                    f.write(f"  IP risk score   : { _safe(resolved_ip.get('risk_score', 0)) }\n")
                    f.write(f"  IP risk reasons : { '; '.join(resolved_ip.get('reasons', []) or []) or 'No confirmed risk indicators' }\n")
                    f.write(f"  IP VT Status    : { _safe((resolved_ip.get('virustotal', {}) or {}).get('status')) }\n")
                    f.write(f"  AbuseIPDB status: { _safe(abuse.get('status'), 'Unavailable (no result)') }\n")
                    f.write(f"  ASN / Hosting   : { _safe(abuse.get('asn'))} / { _safe(abuse.get('isp')) }\n")
                    f.write(f"  AbuseIPDB Score : { _safe(abuse.get('abuse_score')) }\n")
                    f.write(f"  IP Talos        : { _safe((resolved_ip.get('talos', {}) or {}).get('portal_lookup')) }\n")
                    f.write(f"  IP URLScan state: { _safe(resolved_urlscan.get('status'), 'Unavailable (no result)') }\n")
                    f.write(f"  IP URLScan      : { _safe(resolved_urlscan.get('search_url'))} ({_safe(resolved_urlscan.get('result_count', 0))} matches)\n")

            for sender_ip in sender_intelligence.get('ips', []) or []:
                abuse = sender_ip.get('abuseipdb', {}) or {}
                talos = sender_ip.get('talos', {}) or {}
                urlscan = sender_ip.get('urlscan_search', {}) or {}
                f.write(f"\nSender IP         : { _safe(sender_ip.get('ip')) }\n")
                f.write(f"Source headers    : { ', '.join(sender_ip.get('sources', []) or []) or 'N/A' }\n")
                f.write(f"VirusTotal        : { _safe((sender_ip.get('virustotal', {}) or {}).get('status')) }\n")
                f.write(f"VT malicious count: { _safe((sender_ip.get('virustotal', {}) or {}).get('malicious', 0)) }\n")
                f.write(f"AbuseIPDB status  : { _safe(abuse.get('status'), 'Unavailable (no result)') }\n")
                f.write(f"AbuseIPDB Score   : { _safe(abuse.get('abuse_score')) }\n")
                f.write(f"ASN / Hosting     : { _safe(abuse.get('asn'))} / { _safe(abuse.get('isp')) }\n")
                f.write(f"Talos Lookup      : { _safe(talos.get('portal_lookup')) }\n")
                f.write(f"URLScan status    : { _safe(urlscan.get('status'), 'Unavailable (no result)') }\n")
                f.write(f"URLScan search    : { _safe(urlscan.get('search_url'))} ({_safe(urlscan.get('result_count', 0))} matches)\n")
                f.write(f"Whitelisted       : { _safe(sender_ip.get('whitelisted', False)) }\n")
                f.write(f"Blocklisted       : { _safe(sender_ip.get('blocklisted', False)) }\n")
                f.write(f"Risk Score        : { _safe(sender_ip.get('risk_score', 0)) }\n")
            f.write("\n")

            # IOC Summary
            f.write("=" * 80 + "\n")
            f.write("IOC SUMMARY\n")
            f.write("=" * 80 + "\n\n")
            counts = (email_data.get('iocs') or {}).get('counts', {}) or {}
            f.write(f"  IPs    : { counts.get('ips', 0) }\n")
            f.write(f"  Domains: { counts.get('domains', 0) }\n")
            f.write(f"  URLs   : { counts.get('urls', 0) }\n")
            f.write(f"  Hashes : { counts.get('hashes', 0) }\n\n")

            # URL Wrapper Investigation
            f.write("=" * 80 + "\n")
            f.write("URL WRAPPER INVESTIGATION\n")
            f.write("=" * 80 + "\n\n")
            if wrapper_evidence:
                for w in wrapper_evidence:
                    provider = w.get('provider') or ('Direct URL' if not w.get('wrapped') else 'Unknown')
                    status = ('Recovered' if w.get('decode_success') else ('Decode Failed' if w.get('wrapped') else 'Direct'))
                    f.write(f"Provider          : { provider }\n")
                    f.write(f"Status            : { status }\n")
                    f.write(f"Source            : { _safe(w.get('source','N/A')) }\n")
                    f.write(f"Wrapped URL       : { _safe(w.get('wrapped_url','N/A')) }\n")
                    f.write(f"Decoded URL       : { _safe(w.get('decoded_url','N/A')) }\n")
                    f.write(f"Final IOC URL     : { _safe(w.get('final_ioc_url', w.get('decoded_url') or w.get('wrapped_url') or 'N/A')) }\n")
                    f.write('-' * 40 + '\n')
            else:
                f.write('No wrapper evidence present.\n')
            f.write('\n')

            # IOC Details
            f.write("=" * 80 + "\n")
            f.write("IOC DETAILS\n")
            f.write("=" * 80 + "\n\n")

            if not vt_results:
                f.write('No IOC scoring results available.\n\n')
            else:
                for item in vt_results:
                    provider_context = self._normalize_provider_context(item.get('provider_context', {}) or {})
                    whois = provider_context.get('whois', {}) or {}
                    abuse = provider_context.get('abuseipdb', {}) or {}
                    talos = provider_context.get('talos', {}) or {}

                    ioc_type = _safe(item.get('ioc_type','N/A'))
                    value = _safe(item.get('normalized','N/A'))
                    final_ioc = _safe(_find_final_url_for_ioc(value) if ioc_type=='url' else value)
                    verdict = _safe(item.get('category','N/A'))
                    risk = _safe(item.get('final_score','N/A'))
                    vt_score = _safe(item.get('vt_malicious', 'N/A'))
                    vt_status = _safe(item.get('vt_status', 'N/A'))
                    urlscan_link = _safe(self._pick_urlscan_result_url(provider_context.get('urlscan', {})))
                    talos_txt = _safe(talos.get('portal_lookup') if isinstance(talos, dict) else talos)
                    abuse_txt = f"Score={ _safe(abuse.get('abuse_score','N/A')) } Reports={ _safe(abuse.get('abuse_reports','N/A')) }"
                    whois_age = _safe(whois.get('age_days','N/A'))
                    registrar = _safe(whois.get('registrar','N/A'))
                    hosting = provider_context.get('hosting', {}) or {}
                    hosting_provider = _safe(hosting.get('provider') or provider_context.get('hosting_provider') or 'N/A')
                    reasons = self._dedup_reasons(item.get('reason', []) or [])

                    f.write(f"Type              : { ioc_type }\n")
                    f.write(f"Value             : { value }\n")
                    f.write(f"Final IOC URL     : { final_ioc }\n")
                    f.write(f"Verdict           : { verdict }\n")
                    f.write(f"Risk Score        : { risk }\n")
                    f.write(f"VT Score          : { vt_score }\n")
                    f.write(f"VT Status         : { vt_status }\n")
                    f.write(f"URLScan           : { urlscan_link }\n")
                    f.write(f"Talos             : { talos_txt }\n")
                    f.write(f"AbuseIPDB         : { abuse_txt }\n")
                    f.write(f"WHOIS Age (days)  : { whois_age }\n")
                    f.write(f"Registrar         : { registrar }\n")
                    f.write(f"Hosting Provider  : { hosting_provider }\n")
                    f.write(f"Reasons           : {', '.join(reasons) if reasons else 'N/A'}\n")
                    f.write('-' * 60 + '\n')
                f.write('\n')

            # Domain WHOIS Details
            f.write('=' * 80 + '\n')
            f.write('DOMAIN WHOIS DETAILS\n')
            f.write('=' * 80 + '\n\n')
            domain_written = False
            for item in vt_results:
                if item.get('ioc_type') not in ('domain','url'):
                    continue
                prov = self._normalize_provider_context(item.get('provider_context', {}) or {})
                who = prov.get('whois', {}) or {}
                if not who:
                    continue
                domain_written = True
                f.write(f"Domain: { _safe(item.get('normalized','N/A')) }\n")
                f.write(f"  Registrar     : { _safe(who.get('registrar','N/A')) }\n")
                f.write(f"  Creation Date : { _safe(who.get('creation_date', who.get('created','N/A'))) }\n")
                f.write(f"  Updated Date  : { _safe(who.get('updated_date', who.get('updated','N/A'))) }\n")
                f.write(f"  Expiry Date   : { _safe(who.get('expiry_date', who.get('expires','N/A'))) }\n")
                f.write(f"  Domain Age    : { _safe(who.get('age_days','N/A')) } days\n")
                f.write(f"  Country       : { _safe(who.get('country','N/A')) }\n")
                f.write(f"  Organization  : { _safe(who.get('organization','N/A')) }\n")
                f.write(f"  DNSSEC        : { _safe(who.get('dnssec','N/A')) }\n")
                status_field = who.get('status')
                if isinstance(status_field, list):
                    status_txt = ', '.join(status_field) if status_field else 'N/A'
                else:
                    status_txt = _safe(status_field, 'N/A')
                f.write(f"  Status        : { status_txt }\n")
                nameservers_txt = ', '.join(who.get('nameservers',[]) or []) or 'N/A'
                resolved_ips_txt = ', '.join(map(str, who.get('ips',[]) or [])) or 'N/A'
                mx_txt = ', '.join(who.get('mx',[]) or []) or 'N/A'
                f.write(f"  Nameservers   : { _safe(nameservers_txt) }\n")
                f.write(f"  Resolved IPs  : { _safe(resolved_ips_txt) }\n")
                f.write(f"  MX Records    : { _safe(mx_txt) }\n")
                f.write(f"  ASN           : { _safe(who.get('asn','N/A')) }\n")
                f.write(f"  Hosting       : { _safe(prov.get('hosting',{}).get('provider') or prov.get('hosting_provider') or 'N/A') }\n")
                f.write('-' * 40 + '\n')

            if not domain_written:
                f.write('No domain WHOIS details available.\n')
            f.write('\n')

            # Attachment Intelligence
            f.write("=" * 80 + "\n")
            f.write("ATTACHMENT INTELLIGENCE\n")
            f.write("=" * 80 + "\n\n")
            if attachments:
                for att in attachments:
                    f.write(f"Filename         : { _safe(att.get('filename','N/A')) }\n")
                    f.write(f"Size (bytes)     : { _safe(att.get('size', att.get('length', 'N/A'))) }\n")
                    f.write(f"SHA256           : { _safe(att.get('sha256','N/A')) }\n")
                    vt_hash = att.get('vt_hash', {}) or {}
                    f.write(f"  VT Score       : { _safe(vt_hash.get('vt_malicious', 'N/A')) }\n")
                    f.write(f"  VT Status      : { _safe(vt_hash.get('vt_status','N/A')) }\n")
                    f.write('-' * 40 + '\n')
            else:
                f.write('No attachments present.\n')
            f.write('\n')

            # Threat Verdict
            f.write("=" * 80 + "\n")
            f.write("THREAT VERDICT\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"Email Severity : { _safe(email_data.get('email_severity','Unknown')) }\n")
            f.write(f"Email Score    : { _safe(email_data.get('email_score',0)) }\n")
            reasons = email_data.get('email_score_reasons') or []
            if reasons:
                f.write('Key reasons:\n')
                for r in reasons:
                    f.write(f" - { r }\n")
            else:
                f.write('No specific scoring reasons available.\n')
            f.write('\n')

            # Analyst Comment
#=========================================================================================
# Purpose:
# Add SOC analyst notes into the final TXT report.
# 
# Input:
# email_data["analyst_comment"]
#
# Output:
# Human-readable analyst comment section in TXT report.
#=========================================================================================


            f.write("=" * 80 + "\n")
            f.write("ANALYST COMMENTS\n")
            f.write("=" * 80 + "\n\n")

            analyst_comment = email_data.get("analyst_comment", "")

            if analyst_comment and str(analyst_comment).strip():
                f.write(str(analyst_comment).strip() + "\n\n")
            else:
                f.write("No analyst comment provided.\n\n")
#--------------------------------------------------------------------------------------------

            # Include final response details when the investigation is submitted.
            response_actions = email_data.get("response_actions", {}) or {}
            f.write("=" * 80 + "\n")
            f.write("FINAL INVESTIGATION / RESPONSE ACTIONS\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"Finding           : { _safe(response_actions.get('finding')) }\n")
            f.write(f"Action Taken      : { _safe(response_actions.get('action_taken')) }\n")
            f.write(f"Recommendation    : { _safe(response_actions.get('recommendation')) }\n")
            f.write(f"Final Verdict     : { _safe(response_actions.get('final_verdict')) }\n")
            f.write(f"Block Domain      : { _safe(response_actions.get('block_domain')) }\n")
            f.write(f"Block URL         : { _safe(response_actions.get('block_url')) }\n")
            f.write(f"Block Sender      : { _safe(response_actions.get('block_sender')) }\n")
            f.write(f"Escalate Tier 2   : { _safe(response_actions.get('escalate_tier2')) }\n")
            f.write(f"Search Similar    : { _safe(response_actions.get('search_similar')) }\n")
            selected_actions = [
                label for key, label in (
                    ('block_domain', 'Block Domain'),
                    ('block_url', 'Block URL'),
                    ('block_sender', 'Block Sender'),
                    ('escalate_tier2', 'Escalate to Tier 2'),
                    ('search_similar', 'Search Similar Emails'),
                )
                if response_actions.get(key)
            ]
            f.write(f"Selected Actions  : { ', '.join(selected_actions) or 'None' }\n")
            f.write(f"Response Notes    : { _safe(response_actions.get('response_notes')) }\n")
            f.write(f"Submitted Time    : { _safe(response_actions.get('submitted_time')) }\n\n")

            # Recommended Actions
            f.write("=" * 80 + "\n")
            f.write("RECOMMENDED ACTIONS\n")
            f.write("=" * 80 + "\n\n")
            sev = (email_data.get('email_severity') or 'Unknown').lower()
            if 'high' in sev or 'malicious' in sev:
                f.write("- Quarantine the email and block the sender/source immediately.\n")
                f.write("- Review attachment hashes and VirusTotal/Talos results before opening.\n")
                f.write("- Block and investigate Final IOC URLs; consult URLScan/Talos/VT records.\n")
                f.write("- Review related accounts and infrastructure for reuse.\n")
            else:
                f.write("- Monitor the IOCs and consider blocking identified malicious infrastructure.\n")
                f.write("- Notify recipients and provide phishing awareness guidance.\n")
                f.write("- If uncertain, submit key IOCs to OSINT providers for enrichment.\n")

        logger.info("TXT report generated: %s", report_path)
        return report_path

    def generate_word_report(self, email_data: Dict[str, Any]) -> str:
        """Create a professional DOCX report from the saved analysis only."""
        timestamp = dt.datetime.now().astimezone()
        report_path = os.path.join(
            self.output_dir,
            f"email_analysis_{timestamp.strftime('%Y%m%d_%H%M%S')}.docx",
        )
        document = Document()
        section = document.sections[0]
        section.top_margin = Inches(0.65)
        section.bottom_margin = Inches(0.65)
        section.left_margin = Inches(0.7)
        section.right_margin = Inches(0.7)

        styles = document.styles
        styles["Normal"].font.name = "Aptos"
        styles["Normal"].font.size = Pt(9)
        styles["Title"].font.name = "Aptos Display"
        styles["Title"].font.size = Pt(23)
        styles["Heading 1"].font.name = "Aptos Display"
        styles["Heading 1"].font.size = Pt(16)
        styles["Heading 1"].font.color.rgb = RGBColor(31, 78, 121)
        styles["Heading 2"].font.name = "Aptos"
        styles["Heading 2"].font.size = Pt(12)
        styles["Heading 2"].font.color.rgb = RGBColor(47, 84, 150)

        header = section.header.paragraphs[0]
        header.text = "SOC EMAIL INVESTIGATION REPORT"
        header.alignment = WD_ALIGN_PARAGRAPH.RIGHT
        for run in header.runs:
            run.font.size = Pt(8)
            run.font.color.rgb = RGBColor(100, 100, 100)

        footer = section.footer.paragraphs[0]
        footer.alignment = WD_ALIGN_PARAGRAPH.CENTER
        footer.add_run(f"Generated {timestamp.strftime('%Y-%m-%d %H:%M:%S %Z')}  |  ")
        page_field = OxmlElement("w:fldSimple")
        page_field.set(qn("w:instr"), "PAGE")
        footer._p.append(page_field)
        for run in footer.runs:
            run.font.size = Pt(8)
            run.font.color.rgb = RGBColor(100, 100, 100)

        def display(value: Any) -> str:
            if value is None or value == "":
                return "N/A"
            if isinstance(value, bool):
                return "Yes" if value else "No"
            if isinstance(value, (dict, list, tuple)):
                return json.dumps(value, ensure_ascii=False, default=str)
            return str(value)

        def wrap_long_text(value: Any) -> str:
            # Zero-width spaces let Word wrap long URLs without changing their visible text.
            text = display(value)
            return re.sub(r"(?<=[/?.&=_-])", "\u200b", text)

        def add_hyperlink(paragraph, label: str, url: str) -> None:
            try:
                parsed = urlparse(str(url))
            except ValueError:
                paragraph.add_run(label)
                return
            if parsed.scheme != "https" or not parsed.hostname:
                paragraph.add_run(label)
                return
            relationship_id = paragraph.part.relate_to(
                url,
                "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink",
                is_external=True,
            )
            hyperlink = OxmlElement("w:hyperlink")
            hyperlink.set(qn("r:id"), relationship_id)
            run = OxmlElement("w:r")
            properties = OxmlElement("w:rPr")
            color = OxmlElement("w:color")
            color.set(qn("w:val"), "0563C1")
            properties.append(color)
            underline = OxmlElement("w:u")
            underline.set(qn("w:val"), "single")
            properties.append(underline)
            run.append(properties)
            text = OxmlElement("w:t")
            text.text = label
            run.append(text)
            hyperlink.append(run)
            paragraph._p.append(hyperlink)

        def shade_cell(cell, fill: str) -> None:
            properties = cell._tc.get_or_add_tcPr()
            shading = OxmlElement("w:shd")
            shading.set(qn("w:fill"), fill)
            properties.append(shading)

        def add_table(title: str, columns: list, rows: list) -> None:
            if title:
                document.add_heading(title, level=2)
            table = document.add_table(rows=1, cols=len(columns))
            table.style = "Table Grid"
            table.autofit = True
            for index, name in enumerate(columns):
                cell = table.rows[0].cells[index]
                cell.text = str(name)
                shade_cell(cell, "1F4E79")
                for run in cell.paragraphs[0].runs:
                    run.font.bold = True
                    run.font.color.rgb = RGBColor(255, 255, 255)
                    run.font.size = Pt(8)
            for row_data in rows or [["N/A"] + [""] * (len(columns) - 1)]:
                row = table.add_row()
                for index, value in enumerate(row_data):
                    cell = row.cells[index]
                    cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.TOP
                    cell.text = ""
                    paragraph = cell.paragraphs[0]
                    if isinstance(value, dict) and value.get("url"):
                        add_hyperlink(paragraph, str(value.get("label") or "Open provider"), value["url"])
                    else:
                        paragraph.add_run(wrap_long_text(value))
                    for run in paragraph.runs:
                        run.font.size = Pt(8)
                    column_name = str(columns[index]).lower()
                    if columns and str(columns[0]).lower() in {"field", "metric"} and row_data:
                        column_name += " " + str(row_data[0]).lower()
                    lower_value = display(value).lower()
                    if "severity" in column_name or "verdict" in column_name:
                        if any(term in lower_value for term in ("critical", "high", "malicious", "phishing")):
                            for run in paragraph.runs:
                                run.font.color.rgb = RGBColor(192, 0, 0)
                                run.font.bold = True
                        elif any(term in lower_value for term in ("medium", "suspicious")):
                            for run in paragraph.runs:
                                run.font.color.rgb = RGBColor(191, 110, 0)
                                run.font.bold = True
                        elif any(term in lower_value for term in ("low", "benign", "clean", "no threat")):
                            for run in paragraph.runs:
                                run.font.color.rgb = RGBColor(0, 128, 0)
                                run.font.bold = True
            document.add_paragraph()

        def add_key_values(title: str, values: Dict[str, Any]) -> None:
            rows = [[key, display(value)] for key, value in values.items()]
            add_table(title, ["Field", "Details"], rows)

        def flatten_values(value: Any, prefix: str = "") -> list:
            result = []
            if isinstance(value, dict):
                for key, child in value.items():
                    result.extend(flatten_values(child, f"{prefix}.{key}" if prefix else str(key)))
            elif isinstance(value, list):
                if value:
                    for index, child in enumerate(value, start=1):
                        result.extend(flatten_values(child, f"{prefix}[{index}]"))
                else:
                    result.append([prefix or "Details", "N/A"])
            else:
                result.append([prefix or "Details", display(value)])
            return result

        def provider_link_rows(entity_type: str, value: str, intelligence: Dict[str, Any]) -> list:
            if not value:
                return []
            if entity_type == "domain":
                encoded = quote_plus(value)
                candidates = [
                    ("VirusTotal", (intelligence.get("virustotal") or {}).get("url"),
                     f"https://www.virustotal.com/gui/domain/{encoded}"),
                    ("Talos", (intelligence.get("talos") or {}).get("portal_lookup"),
                     f"https://talosintelligence.com/reputation_center/lookup?search={encoded}"),
                    ("URLScan", (intelligence.get("urlscan_search") or {}).get("search_url"),
                     f"https://urlscan.io/search/#domain:{encoded}"),
                    ("RDAP / ICANN", (intelligence.get("rdap") or {}).get("portal_lookup"),
                     f"https://lookup.icann.org/en/lookup?name={encoded}"),
                    ("WHOIS", (intelligence.get("whois") or {}).get("url"),
                     f"https://www.whois.com/whois/{encoded}"),
                ]
            elif entity_type == "ip":
                encoded = quote_plus(value)
                candidates = [
                    ("VirusTotal", (intelligence.get("virustotal") or {}).get("url"),
                     f"https://www.virustotal.com/gui/ip-address/{encoded}"),
                    ("Talos", (intelligence.get("talos") or {}).get("portal_lookup"),
                     f"https://talosintelligence.com/reputation_center/lookup?search={encoded}"),
                    ("URLScan", (intelligence.get("urlscan_search") or {}).get("search_url"),
                     f"https://urlscan.io/search/#ip:{encoded}"),
                    ("AbuseIPDB", (intelligence.get("abuseipdb") or {}).get("url"),
                     f"https://www.abuseipdb.com/check/{encoded}"),
                ]
            else:
                encoded = quote_plus(value)
                candidates = [
                    ("VirusTotal", (intelligence.get("virustotal") or {}).get("url"),
                     f"https://www.virustotal.com/gui/search/{encoded}"),
                    ("URLScan", (intelligence.get("urlscan") or {}).get("result_url")
                     or (intelligence.get("urlscan") or {}).get("url"), ""),
                    ("Talos", (intelligence.get("talos") or {}).get("portal_lookup"), ""),
                ]
            rows = []
            for label, available_url, fallback_url in candidates:
                url = available_url or fallback_url
                try:
                    parsed = urlparse(str(url))
                except ValueError:
                    continue
                if parsed.scheme == "https" and parsed.hostname:
                    rows.append([value, {"label": f"Open {label}", "url": url}])
            return rows

        document.add_heading("Email Threat Investigation", level=0)
        title_paragraph = document.add_paragraph(
            f"Final SOC report | {timestamp.strftime('%Y-%m-%d %H:%M:%S %Z')}"
        )
        title_paragraph.alignment = WD_ALIGN_PARAGRAPH.LEFT

        subject_analysis = email_data.get("subject_analysis", {}) or {}
        body_stats = email_data.get("body_stats", {}) or {}
        sender_intelligence = email_data.get("sender_intelligence", {}) or {}
        response_actions = email_data.get("response_actions", {}) or {}
        mismatch = (email_data.get("header_analysis", {}) or {}).get("mismatch_flags", {}) or {}
        auth_results = email_data.get("auth_results", "")
        severity = str(email_data.get("email_severity", "Unknown"))
        verdict = str(response_actions.get("final_verdict") or sender_intelligence.get("verdict") or "N/A")

        add_key_values("Executive Summary", {
            "Subject": email_data.get("subject"),
            "From": email_data.get("from"),
            "To": email_data.get("to"),
            "Severity": severity,
            "Email score": email_data.get("email_score"),
            "Final analyst verdict": verdict,
            "Investigation submitted": email_data.get("investigation_submitted", False),
        })
        add_key_values("Email Overview", {
            "Source EML": email_data.get("eml_used"),
            "Input path": email_data.get("input_path"),
            "Plain text length": body_stats.get("plain_length"),
            "HTML length": body_stats.get("html_length"),
            "Hidden HTML elements": body_stats.get("hidden_html_count"),
            "Extracted URL count": len(email_data.get("urls_extracted", []) or []),
            "Attachment count": len(email_data.get("attachments", []) or []),
        })

        sender_domain_rows = []
        sender_domain_provider_rows = []
        sender_ip_rows = []
        sender_link_rows = []
        for domain in sender_intelligence.get("domains", []) or []:
            whois = domain.get("whois", {}) or {}
            dns = domain.get("dns", {}) or {}
            vt = domain.get("virustotal", {}) or {}
            talos = domain.get("talos", {}) or {}
            urlscan = domain.get("urlscan_search", {}) or {}
            rdap = domain.get("rdap", {}) or {}
            sender_domain_rows.append([
                domain.get("domain"),
                ", ".join(domain.get("headers", []) or []),
                domain.get("domain_age_days"),
                whois.get("status"),
                whois.get("registrar"),
                domain.get("spf_status"),
                ", ".join(domain.get("spf_records", []) or []),
                domain.get("dmarc_status"),
                ", ".join(domain.get("dmarc_records", []) or []),
                ", ".join((dns.get("mx", {}) or {}).get("records", []) or []),
                ", ".join(domain.get("resolved_ips", []) or []),
                domain.get("risk_score"),
            ])
            sender_domain_provider_rows.append([
                domain.get("domain"),
                vt.get("status"),
                vt.get("malicious"),
                talos.get("portal_lookup"),
                urlscan.get("status"),
                urlscan.get("result_count"),
                rdap.get("portal_lookup"),
            ])
            sender_link_rows.extend(provider_link_rows("domain", str(domain.get("domain") or ""), domain))
            for ip_intelligence in domain.get("resolved_ip_intelligence", []) or []:
                ip_abuse = ip_intelligence.get("abuseipdb", {}) or {}
                ip_vt = ip_intelligence.get("virustotal", {}) or {}
                ip_talos = ip_intelligence.get("talos", {}) or {}
                ip_urlscan = ip_intelligence.get("urlscan_search", {}) or {}
                sender_ip_rows.append([
                    ip_intelligence.get("ip"),
                    f"Resolved from {domain.get('domain', 'N/A')}",
                    ip_vt.get("status"),
                    ip_abuse.get("abuse_score"),
                    ip_abuse.get("asn"),
                    ip_abuse.get("isp"),
                    ip_intelligence.get("risk_score"),
                    "; ".join(ip_intelligence.get("reasons", []) or []),
                    ip_talos.get("portal_lookup"),
                    ip_urlscan.get("status"),
                    ip_urlscan.get("result_count"),
                ])
                sender_link_rows.extend(provider_link_rows("ip", str(ip_intelligence.get("ip") or ""), ip_intelligence))
        add_table(
            "Sender Intelligence",
            ["Domain", "Header role", "Age days", "WHOIS status", "Registrar", "SPF status",
             "SPF record", "DMARC status", "DMARC record", "MX", "Resolved IPs", "Risk score",
             ],
            sender_domain_rows,
        )
        add_table(
            "Sender Provider Results",
            ["Domain", "VT status", "VT malicious", "Talos lookup", "URLScan status", "URLScan matches", "RDAP lookup"],
            sender_domain_provider_rows,
        )
        for ip in sender_intelligence.get("ips", []) or []:
            abuse = ip.get("abuseipdb", {}) or {}
            ip_talos = ip.get("talos", {}) or {}
            ip_urlscan = ip.get("urlscan_search", {}) or {}
            sender_ip_rows.append([
                ip.get("ip"), ", ".join(ip.get("sources", []) or []),
                (ip.get("virustotal", {}) or {}).get("status"), abuse.get("abuse_score"),
                abuse.get("asn"), abuse.get("isp"), ip.get("risk_score"),
                "; ".join(ip.get("reasons", []) or []),
                ip_talos.get("portal_lookup"), ip_urlscan.get("status"), ip_urlscan.get("result_count"),
            ])
            sender_link_rows.extend(provider_link_rows("ip", str(ip.get("ip") or ""), ip))
        if sender_ip_rows:
            add_table(
                "Sender IP Intelligence",
                ["IP", "Source header", "VT", "AbuseIPDB", "ASN", "Hosting / ISP", "Risk score", "Reasons",
                 "Talos lookup", "URLScan status", "URLScan matches"],
                sender_ip_rows,
            )
        for reason in sender_intelligence.get("reasons", []) or []:
            document.add_paragraph(f"Sender finding: {display(reason)}")
        if sender_link_rows:
            add_table("Sender Intelligence Links", ["Indicator", "Provider"], sender_link_rows)

        subject_flags = subject_analysis.get("subject_flags", []) or []
        add_key_values("Subject / Body Analysis", {
            "Subject": email_data.get("subject"),
            "Subject severity": subject_analysis.get("subject_severity"),
            "Subject score": subject_analysis.get("subject_score"),
            "Subject findings": "; ".join(map(str, subject_flags)) if subject_flags else "N/A",
            "Plain text length": body_stats.get("plain_length"),
            "HTML length": body_stats.get("html_length"),
            "Hidden HTML count": body_stats.get("hidden_html_count"),
        })
        add_key_values("Authentication", {
            "Authentication-Results": auth_results,
            "SPF result": (sender_intelligence.get("authentication", {}) or {}).get("spf"),
            "DKIM result": re.search(r"\bdkim\s*=\s*([a-z]+)", str(auth_results), re.IGNORECASE).group(1)
            if re.search(r"\bdkim\s*=\s*([a-z]+)", str(auth_results), re.IGNORECASE) else None,
            "DMARC result": (sender_intelligence.get("authentication", {}) or {}).get("dmarc"),
        })

        headers_focus = email_data.get("headers_focus", {}) or {}
        header_rows = [[key, display(value)] for key, value in headers_focus.items()]
        add_table("Headers / Mismatches", ["Header", "Value"], header_rows)
        add_table("Header Mismatch Findings", ["Check", "Result"], [[key, value] for key, value in mismatch.items()])
        headers_raw = email_data.get("headers_raw", {}) or {}
        if headers_raw:
            add_table("Full Raw Headers", ["Header", "Value"], [[key, display(value)] for key, value in headers_raw.items()])

        hop_rows = []
        for index, hop in enumerate(email_data.get("received_hops", []) or [], start=1):
            hop_rows.append([
                index,
                hop.get("from", ""),
                hop.get("by", ""),
                hop.get("with", ""),
                hop.get("date", ""),
                hop.get("delay", ""),
                hop.get("raw", ""),
            ])
        add_table("Received Hops", ["#", "From", "By", "With", "Date", "Delay", "Raw"], hop_rows)

        normalized_iocs = self._normalize_iocs(email_data.get("iocs", {}) or {})
        add_table("IOC Summary", ["Type", "Count", "Indicators"], [
            [key, value.get("count", len(value.get("items", []) or [])),
             "; ".join(map(str, value.get("items", []) or []))]
            for key, value in normalized_iocs.items()
        ])
        add_table(
            "OSINT Summary",
            ["Metric", "Value"],
            [[key, display(value)] for key, value in (email_data.get("osint_summary", {}) or {}).items()],
        )
        ioc_rows = []
        ioc_link_rows = []
        whitelist_rows = []
        for item in email_data.get("ioc_scoring", []) or []:
            provider_context = self._normalize_provider_context(item.get("provider_context", {}) or {})
            value = str(item.get("normalized") or "")
            ioc_type = str(item.get("ioc_type") or "")
            ioc_rows.append([
                ioc_type, value, item.get("category"), item.get("vt_status"), item.get("vt_malicious"),
                item.get("final_score"), "; ".join(self._dedup_reasons(item.get("reason", []) or [])),
                item.get("is_whitelisted"), item.get("is_blocklisted"),
            ])
            if ioc_type in {"domain", "ip", "url", "hash"}:
                ioc_link_rows.extend(provider_link_rows(ioc_type, value, {
                    "virustotal": {"url": ""},
                    "talos": provider_context.get("talos", {}),
                    "urlscan_search": provider_context.get("urlscan", {}),
                    "urlscan": provider_context.get("urlscan", {}),
                    "rdap": provider_context.get("rdap", {}),
                    "whois": provider_context.get("whois", {}),
                    "abuseipdb": provider_context.get("abuseipdb", {}),
                }))
            whitelist_rows.append([
                ioc_type, value, item.get("is_whitelisted"), item.get("is_blocklisted"),
                item.get("category"),
            ])
        add_table(
            "IOC Details",
            ["Type", "Indicator", "Verdict", "VT status", "VT malicious", "Score", "Reasons", "Whitelisted", "Blocklisted"],
            ioc_rows,
        )

        wrapper_rows = []
        for wrapper in email_data.get("urls_extracted_detail", []) or []:
            wrapper_rows.append([
                wrapper.get("provider"), wrapper.get("status"),
                wrapper.get("source"), wrapper.get("wrapped_url"),
                wrapper.get("decoded_url"), wrapper.get("final_ioc_url"),
            ])
        add_table(
            "URL Wrapper Investigation",
            ["Provider", "Status", "Source", "Wrapped URL", "Decoded URL", "Final IOC URL"],
            wrapper_rows,
        )
        add_table(
            "Extracted URLs",
            ["URL"],
            [[url] for url in email_data.get("urls_extracted", []) or []],
        )

        whois_dns_rows = []
        intelligence_rows = list(sender_intelligence.get("domains", []) or [])
        for domain in intelligence_rows:
            dns = domain.get("dns", {}) or {}
            whois = domain.get("whois", {}) or {}
            rdap = domain.get("rdap", {}) or {}
            whois_dns_rows.append([
                domain.get("domain"), whois.get("registrar"), whois.get("created"),
                whois.get("expires"), whois.get("age_days", domain.get("domain_age_days")),
                ", ".join(whois.get("nameservers", []) or []),
                rdap.get("portal_lookup"), ", ".join(domain.get("resolved_ips", []) or []),
                "; ".join((dns.get("mx", {}) or {}).get("records", []) or []),
                "; ".join((dns.get("txt", {}) or {}).get("records", []) or []),
            ])
        for item in email_data.get("ioc_scoring", []) or []:
            if item.get("ioc_type") not in {"domain", "url"}:
                continue
            providers = self._normalize_provider_context(item.get("provider_context", {}) or {})
            whois = providers.get("whois", {}) or {}
            rdap = providers.get("rdap", {}) or {}
            if whois or rdap:
                whois_dns_rows.append([
                    item.get("normalized"), whois.get("registrar"), whois.get("created"),
                    whois.get("expires"), whois.get("age_days"),
                    ", ".join(whois.get("nameservers", []) or []),
                    rdap.get("portal_lookup"), ", ".join(map(str, whois.get("ips", []) or [])),
                    ", ".join(whois.get("mx", []) or []), "N/A",
                ])
        add_table(
            "WHOIS / RDAP / DNS", ["Domain", "Registrar", "Created", "Expires", "Age days",
             "Nameservers", "RDAP", "Resolved IPs", "MX", "TXT"], whois_dns_rows,
        )

        provider_rows = []
        for item in email_data.get("ioc_scoring", []) or []:
            providers = self._normalize_provider_context(item.get("provider_context", {}) or {})
            provider_rows.append([
                item.get("ioc_type"), item.get("normalized"), item.get("vt_status"),
                (providers.get("abuseipdb", {}) or {}).get("abuse_score"),
                (providers.get("urlscan", {}) or {}).get("status"),
                (providers.get("talos", {}) or {}).get("portal_lookup"),
            ])
        add_table(
            "VT / AbuseIPDB / URLScan / Talos Results",
            ["Type", "Indicator", "VT", "AbuseIPDB", "URLScan", "Talos"],
            provider_rows,
        )
        if ioc_link_rows:
            add_table("IOC Intelligence Links", ["Indicator", "Provider"], ioc_link_rows)

        attachment_rows = []
        for attachment in email_data.get("attachments", []) or []:
            vt_hash = attachment.get("vt_hash", {}) or {}
            attachment_rows.append([
                attachment.get("filename"), attachment.get("size", attachment.get("length")),
                attachment.get("sha256"), vt_hash.get("vt_status"),
                vt_hash.get("vt_malicious"), attachment.get("talos"),
            ])
        add_table(
            "Attachments", ["Filename", "Size bytes", "SHA256", "VT status", "VT malicious", "Talos"],
            attachment_rows,
        )
        sender_rows = [
            ["Domain", domain.get("domain"), domain.get("whitelisted"), domain.get("blocklisted")]
            for domain in sender_intelligence.get("domains", []) or []
        ]
        sender_rows.extend([
            ["IP", ip.get("ip"), ip.get("whitelisted"), ip.get("blocklisted")]
            for ip in sender_intelligence.get("ips", []) or []
        ])
        add_table(
            "Whitelist / Blocklist Findings",
            ["Type", "Indicator", "Whitelisted", "Blocklisted", "Verdict"],
            whitelist_rows + sender_rows,
        )

        campaign_alert_rows = flatten_values(email_data.get("campaign", {}) or {}, "Campaign")
        campaign_alert_rows.extend(flatten_values(email_data.get("alert", {}) or {}, "Alert"))
        add_table("Campaign / Alert Findings", ["Finding", "Details"], campaign_alert_rows)

        add_key_values("Threat Verdict / Score / Reasons", {
            "Email severity": severity,
            "Email score": email_data.get("email_score"),
            "Email reasons": "; ".join(map(str, email_data.get("email_score_reasons", []) or [])),
            "Sender verdict": sender_intelligence.get("verdict"),
            "Sender risk score": sender_intelligence.get("risk_score"),
            "Sender reasons": "; ".join(map(str, sender_intelligence.get("reasons", []) or [])),
        })
        add_key_values("Analyst Comments", {
            "Analyst comment": email_data.get("analyst_comment"),
        })
        selected_actions = [
            label for key, label in (
                ("block_domain", "Block Domain"),
                ("block_url", "Block URL"),
                ("block_sender", "Block Sender"),
                ("escalate_tier2", "Escalate to Tier 2"),
                ("search_similar", "Search Similar Emails"),
            )
            if response_actions.get(key)
        ]
        add_key_values("Final Investigation / Response Actions", {
            "Finding": response_actions.get("finding"),
            "Action Taken": response_actions.get("action_taken"),
            "Recommendation": response_actions.get("recommendation"),
            "Final Analyst Verdict": response_actions.get("final_verdict"),
            "Selected Response Actions": ", ".join(selected_actions) if selected_actions else "None",
            "Response Notes": response_actions.get("response_notes"),
            "Submitted Time": response_actions.get("submitted_time") or email_data.get("submitted_time"),
        })

        recommended_actions = (email_data.get("alert", {}) or {}).get("recommended_actions", []) or []
        if not recommended_actions:
            if "high" in severity.lower() or "malicious" in severity.lower():
                recommended_actions = [
                    "Quarantine the email and block the sender/source immediately.",
                    "Review attachment hashes and provider results before opening.",
                    "Block and investigate final IOC URLs and related infrastructure.",
                ]
            else:
                recommended_actions = [
                    "Monitor the IOCs and consider blocking identified malicious infrastructure.",
                    "Notify recipients and provide phishing awareness guidance.",
                    "Submit key IOCs to OSINT providers for enrichment if uncertainty remains.",
                ]
        add_table("Recommended Actions", ["#", "Action"], [
            [index, action] for index, action in enumerate(recommended_actions, start=1)
        ])

        document.save(report_path)
        logger.info("Word report generated: %s", report_path)
        return report_path
    
    # ============================================================
    # Blocklist Excel Export
    #
    # What does this function do?
    # --------------------------------
    # This function creates an Excel file that contains
    # all malicious or suspicious IOCs detected in the email.
    #
    # Why do we need this?
    # --------------------------------
    # SOC analysts often want a quick list of:
    # - malicious URLs
    # - malicious domains
    # - malicious IPs
    #
    # so they can:
    # - block them
    # - hunt for them in SIEM
    # - share them with other analysts
    #
    # Input:
    # --------------------------------
    # email_data
    #
    # The same email analysis dictionary that is used
    # throughout the project.
    #
    # Output:
    # --------------------------------
    # reports/ioc_blocklist.xlsx
    #
    # Example:
    #
    # IOC Type | IOC Value | Verdict | Risk Score
    # ------------------------------------------------
    # URL      | evil.com  | malicious | 95
    # IP       | 1.2.3.4   | suspicious | 72
    #
    # Notes:
    # --------------------------------
    # Only malicious or suspicious IOCs are exported.
    # Clean IOCs are ignored.
    #
    # ============================================================
    def update_config_blocklist_excel(self, email_data):

            try:

                logger.info(
                    "Starting blocklist Excel generation..."
                )

                blocklist_rows = []

                # =======================================
                # Read IOC scoring results
                # =======================================
                for item in email_data.get(
                    "ioc_scoring",
                    []
                ):

                    verdict = str(
                        item.get(
                            "category",
                            ""
                        )
                    ).lower()

                    # Only export bad indicators
                    if verdict not in (
                        "malicious",
                        "suspicious"
                    ):
                        continue

                    blocklist_rows.append({
                        "IOC Type":
                            item.get(
                                "ioc_type",
                                "Unknown"
                            ),

                        "IOC Value":
                            item.get(
                                "normalized",
                                "Unknown"
                            ),

                        "Verdict":
                            item.get(
                                "category",
                                "Unknown"
                            ),

                        "Risk Score":
                            item.get(
                                "final_score",
                                ""
                            )
                    })

                # =======================================
                # Nothing found
                # =======================================
                if not blocklist_rows:

                    logger.info(
                        "No malicious IOC found for blocklist export."
                    )

                    return

                # =======================================
                # Create dataframe
                # =======================================
                df = pd.DataFrame(
                    blocklist_rows
                )

                # =======================================
                # Create output path
                # =======================================
                excel_path = os.path.join(
                    self.output_dir,
                    "ioc_blocklist.xlsx"
                )

                # =======================================
                # Save Excel
                # =======================================
                df.to_excel(
                    excel_path,
                    index=False
                )

                logger.info(
                    "Blocklist Excel generated: %s",
                    excel_path
                )

            except Exception as exc:

                logger.exception(
                    "Failed to create blocklist Excel: %s",
                    exc
                )

        
