# mail_reporter
import os
import json
import logging
import pandas as pd
import re
import datetime as dt

from typing import Dict, Any

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
        provider_context = dict(provider_context or {})

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
            safe_item.pop("final_score", None)
            safe_ioc_scoring.append(safe_item)

        report = {
            "timestamp": dt.datetime.now().isoformat(),
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
            "body_stats": email_data.get("body_stats", {}),
            "urls_extracted": email_data.get("urls_extracted", []),
            "urls_extracted_detail": email_data.get("urls_extracted_detail", []),
            "iocs": email_data.get("iocs", {}),
            "attachments": email_data.get("attachments", []),
            "ioc_scoring": safe_ioc_scoring,
            "osint_summary": email_data.get("osint_summary", {}),
            "analyst_comment": email_data.get("analyst_comment", ""), # Analyst-written investigation notes from UI
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
                    anyrun = att.get('anyrun',{}) or {}
                    if anyrun:
                        f.write(f"  ANY.RUN Status : { _safe(anyrun.get('status','N/A')) }\n")
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
            f.write("ANALYST COMMNET \n")
            f.write("=" * 80 + "\n\n")

            analyst_comment = email_data.get("analyst_comment", "")

            if analyst_comment and str(analyst_comment).strip():
                f.write(str(analyst_comment).strip() + "\n\n")
            else:
                f.write("No analyst comment provided.\n\n")
#--------------------------------------------------------------------------------------------

            # Recommended Actions
            f.write("=" * 80 + "\n")
            f.write("RECOMMENDED ACTIONS\n")
            f.write("=" * 80 + "\n\n")
            sev = (email_data.get('email_severity') or 'Unknown').lower()
            if 'high' in sev or 'malicious' in sev:
                f.write("- Quarantine the email and block the sender/source immediately.\n")
                f.write("- Isolate and submit attachments to a sandbox for behavior analysis.\n")
                f.write("- Block and investigate Final IOC URLs; consult URLScan/Talos/VT records.\n")
                f.write("- Review related accounts and infrastructure for reuse.\n")
            else:
                f.write("- Monitor the IOCs and consider blocking identified malicious infrastructure.\n")
                f.write("- Notify recipients and provide phishing awareness guidance.\n")
                f.write("- If uncertain, submit key IOCs to OSINT providers for enrichment.\n")

        logger.info("TXT report generated: %s", report_path)
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

        
