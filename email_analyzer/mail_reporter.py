import os
import json
import logging
from datetime import datetime
from typing import Dict, Any

logger = logging.getLogger(__name__)


class MailReporter:
    """
    Generates reports:
      - JSON report (includes full headers)
      - TXT report (includes full header analysis + full raw headers)
      - Blocklist
    """

    def __init__(self, output_dir="reports"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)
        logger.info("Initializing MailReporter with output directory: %s", self.output_dir)

    def _timestamp(self) -> str:
        return datetime.now().strftime("%Y%m%d_%H%M%S")

    def _normalize_iocs(self, iocs: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        """
        Normalizes IOC structure to a stable display format:
          {
            "IPs": {"count": int, "items": [...]},
            "Domains": {"count": int, "items": [...]},
            "URLs": {"count": int, "items": [...]},
            "File_Hashes": {"count": int, "items": [...]},
          }
        Accepts your new structure:
          {"ips":[], "domains":[], "urls":[], "hashes":[], "counts":{...}}
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

        # Fallback if someone uses old structure
        out = {}
        for k, v in iocs.items():
            if isinstance(v, dict) and "count" in v and "items" in v:
                out[k] = v
        for key in ("IPs", "Domains", "URLs", "File_Hashes"):
            out.setdefault(key, {"count": 0, "items": []})
        return out

    def generate_json_report(self, email_data: Dict[str, Any]) -> str:
        ts = self._timestamp()
        report_path = os.path.join(self.output_dir, f"email_analysis_{ts}.json")

        report = {
            "timestamp": datetime.now().isoformat(),
            "email_metadata": {
                "subject": email_data.get("subject"),
                "from": email_data.get("from"),
                "to": email_data.get("to"),
                "eml_used": email_data.get("eml_used"),
            },
            "header_analysis": email_data.get("header_analysis", {}),
            "headers_focus": email_data.get("headers_focus", {}),
            "headers_raw": email_data.get("headers_raw", {}),      # FULL HEADERS
            "received_hops": email_data.get("received_hops", []),
            "auth_results": email_data.get("auth_results"),
            "body_stats": email_data.get("body_stats", {}),
            "urls_extracted": email_data.get("urls_extracted", []),
            "iocs": email_data.get("iocs", {}),
            "attachments": email_data.get("attachments", []),
        }

        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        logger.info("JSON report generated: %s", report_path)
        return report_path

    def generate_text_report(self, email_data: Dict[str, Any]) -> str:
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

        with open(report_path, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("EMAIL THREAT ANALYSIS REPORT (FULL)\n")
            f.write("=" * 80 + "\n\n")

            # METADATA
            f.write("METADATA:\n")
            f.write(f"  Subject: {email_data.get('subject', 'N/A')}\n")
            f.write(f"  From:    {email_data.get('from', 'N/A')}\n")
            f.write(f"  To:      {email_data.get('to', 'N/A')}\n")
            f.write(f"  EML:     {email_data.get('eml_used', 'N/A')}\n")
            f.write(f"  Report:  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            # HEADER ANALYSIS
            f.write("=" * 80 + "\n")
            f.write("HEADER ANALYSIS\n")
            f.write("=" * 80 + "\n\n")

            f.write("IMPORTANT HEADERS (FOCUS):\n")
            if headers_focus:
                for k, v in headers_focus.items():
                    f.write(f"  {k}: {str(v)}\n")
            else:
                f.write("  (No focus headers found)\n")
            f.write("\n")

            f.write("MISMATCH CHECKS:\n")
            f.write(f"  From domain        : {mismatch.get('from_domain','')}\n")
            f.write(f"  Reply-To domain     : {mismatch.get('reply_to_domain','')}\n")
            f.write(f"  Return-Path domain  : {mismatch.get('return_path_domain','')}\n")
            f.write(f"  Sender domain       : {mismatch.get('sender_domain','')}\n")
            f.write(f"  Reply-To mismatch   : {mismatch.get('reply_to_mismatch', False)}\n")
            f.write(f"  Return-Path mismatch: {mismatch.get('return_path_mismatch', False)}\n")
            f.write(f"  Sender mismatch     : {mismatch.get('sender_mismatch', False)}\n\n")

            f.write(f"RECEIVED HOPS (count={len(received_hops)}):\n")
            if received_hops:
                for idx, hop in enumerate(received_hops, start=1):
                    if isinstance(hop, dict) and "raw" in hop:
                        f.write(f"  Hop {idx} (raw): {hop.get('raw')}\n")
                    else:
                        f.write(f"  Hop {idx}:\n")
                        f.write(f"    From: {hop.get('from')}\n")
                        f.write(f"    By  : {hop.get('by')}\n")
                        f.write(f"    Date: {hop.get('date')}\n")
            else:
                f.write("  - No Received headers found.\n")
            f.write("\n")

            f.write("AUTHENTICATION-RESULTS:\n")
            f.write(f"  {email_data.get('auth_results', 'Not Found')}\n\n")

            # FULL HEADERS RAW (as requested: all details)
            f.write("=" * 80 + "\n")
            f.write("FULL HEADERS (RAW)\n")
            f.write("=" * 80 + "\n\n")
            if headers_raw:
                for k, v in headers_raw.items():
                    f.write(f"{k}: {str(v)}\n")
            else:
                f.write("(No raw headers found)\n")
            f.write("\n")

            # BODY SUMMARY
            f.write("=" * 80 + "\n")
            f.write("BODY SUMMARY\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"Plain length : {body_stats.get('plain_length', 0)}\n")
            f.write(f"HTML length  : {body_stats.get('html_length', 0)}\n")
            f.write(f"Hidden HTML  : {body_stats.get('hidden_html_count', 0)}\n\n")

            # IOC SECTION
            f.write("=" * 80 + "\n")
            f.write("INDICATORS OF COMPROMISE (IOCs)\n")
            f.write("=" * 80 + "\n\n")
            for category, data in iocs_norm.items():
                f.write(f"{category} ({data.get('count', 0)} found):\n")
                items = data.get("items", []) or []
                if items:
                    for item in items:
                        f.write(f"  - {item}\n")
                else:
                    f.write("  - None\n")
                f.write("\n")

            # URLS
            f.write("=" * 80 + "\n")
            f.write("EXTRACTED URLs\n")
            f.write("=" * 80 + "\n\n")
            if urls:
                for u in urls:
                    f.write(f"  - {u}\n")
            else:
                f.write("  - None\n")
            f.write("\n")

            # ATTACHMENTS
            f.write("=" * 80 + "\n")
            f.write("ATTACHMENTS\n")
            f.write("=" * 80 + "\n\n")
            if attachments:
                for att in attachments:
                    f.write(f"  Filename: {att.get('filename', 'N/A')}\n")
                    f.write(f"  Size:     {att.get('size', 0)} bytes\n")
                    f.write(f"  SHA256:   {att.get('sha256', 'N/A')}\n\n")
            else:
                f.write("  - No attachments found.\n\n")

            # SUMMARY
            f.write("=" * 80 + "\n")
            f.write("THREAT SUMMARY\n")
            f.write("=" * 80 + "\n\n")
            total_iocs = sum(v.get("count", 0) for v in iocs_norm.values())
            f.write(f"Total IOCs detected: {total_iocs}\n")
            f.write(f"Total attachments:   {len(attachments)}\n")
            f.write(f"Total URLs found:    {len(urls)}\n\n")

            if total_iocs > 0 or body_stats.get("hidden_html_count", 0) > 0:
                f.write("[!] ALERT: Suspicious indicators detected in this email!\n")
            else:
                f.write("[✓] No obvious malicious indicators detected.\n")

        logger.info("Text report generated: %s", report_path)
        return report_path

    def generate_blocklist(self, email_data: Dict[str, Any]) -> str:
        ts = self._timestamp()
        report_path = os.path.join(self.output_dir, f"blocklist_{ts}.txt")

        iocs_norm = self._normalize_iocs(email_data.get("iocs", {}))
        attachments = email_data.get("attachments", []) or []

        with open(report_path, "w", encoding="utf-8") as f:
            f.write("# BLOCKLIST - Generated from Email Analysis\n")
            f.write(f"# Generated: {datetime.now().isoformat()}\n")
            f.write(f"# Subject: {email_data.get('subject', 'N/A')}\n\n")

            for category, data in iocs_norm.items():
                items = data.get("items", []) or []
                if items:
                    f.write(f"[{category}]\n")
                    for item in items:
                        f.write(f"{item}\n")
                    f.write("\n")

            if attachments:
                f.write("[ATTACHMENT_HASHES]\n")
                for att in attachments:
                    sha = att.get("sha256")
                    fn = att.get("filename", "unknown")
                    if sha:
                        f.write(f"{sha}  # {fn}\n")

        logger.info("Blocklist generated: %s", report_path)
        return report_path