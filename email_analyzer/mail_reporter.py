
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

        Input style:
          {"ips":[], "domains":[], "urls":[], "hashes":[], "counts":{...}}

        Output style:
          {
            "IPs": {"count": int, "items": [...]},
            "Domains": {"count": int, "items": [...]},
            "URLs": {"count": int, "items": [...]},
            "File_Hashes": {"count": int, "items": [...]},
          }
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

        # Fallback old-style handling
        out = {}
        for k, v in iocs.items():
            if isinstance(v, dict) and "count" in v and "items" in v:
                out[k] = v

        for key in ("IPs", "Domains", "URLs", "File_Hashes"):
            out.setdefault(key, {"count": 0, "items": []})

        return out

    def generate_json_report(self, email_data: Dict[str, Any]) -> str:
        """
        Create JSON report with all available data.
        """
        ts = self._timestamp()
        report_path = os.path.join(self.output_dir, f"email_analysis_{ts}.json")

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
            "iocs": email_data.get("iocs", {}),
            "attachments": email_data.get("attachments", []),

            # IOC scoring section Existing IOC details (now including OSINT if ioc_analyzer returns them)
            "ioc_scoring": email_data.get("ioc_scoring", []),
            "osint_summary": email_data.get("osint_summary", {}),

        }

        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        logger.info("JSON report generated: %s", report_path)
        return report_path

    def generate_text_report(self, email_data: Dict[str, Any]) -> str:
        """
        Create TXT report with:
        - metadata
        - header analysis
        - full raw headers
        - body summary
        - IOC list
        - extracted URLs
        - attachments
        - VT IOC scoring
        - threat summary
        """

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

        with open(report_path, "w", encoding="utf-8") as f:
            # -----------------------------------------------------------------
            # Report Header
            # -----------------------------------------------------------------
            f.write("=" * 80 + "\n")
            f.write("EMAIL THREAT ANALYSIS REPORT (FULL)\n")
            f.write("=" * 80 + "\n\n")

            # -----------------------------------------------------------------
            # Metadata
            # -----------------------------------------------------------------
            f.write("METADATA:\n")
            f.write(f"  Subject: {email_data.get('subject', 'N/A')}\n")
            f.write(f"  From:    {email_data.get('from', 'N/A')}\n")
            f.write(f"  To:      {email_data.get('to', 'N/A')}\n")
            f.write(f"  EML:     {email_data.get('eml_used', 'N/A')}\n")
            f.write(f"  Report:  {dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            subject_analysis = email_data.get("subject_analysis", {}) or {}

            if subject_analysis:
                f.write("SUBJECT ANALYSIS:\n")
                f.write(f"  Subject Severity: {subject_analysis.get('subject_severity', 'Low')}\n")
                flags = subject_analysis.get("subject_flags", []) or []
                if flags:
                    for flag in flags:
                        f.write(f"  - {flag}\n")
                else:
                    f.write("  - No suspicious subject indicators\n")
                f.write("\n")

            # -----------------------------------------------------------------
            # Header Analysis
            # -----------------------------------------------------------------
            
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
            f.write(f"  From domain         : {mismatch.get('from_domain','')}\n")
            f.write(f"  Reply-To domain      : {mismatch.get('reply_to_domain','')}\n")
            f.write(f"  Return-Path domain   : {mismatch.get('return_path_domain','')}\n")
            f.write(f"  Sender domain        : {mismatch.get('sender_domain','')}\n")
            f.write(f"  Reply-To mismatch    : {mismatch.get('reply_to_mismatch', False)}\n")
            f.write(f"  Return-Path mismatch : {mismatch.get('return_path_mismatch', False)}\n")
            f.write(f"  Sender mismatch      : {mismatch.get('sender_mismatch', False)}\n\n")

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

            # -----------------------------------------------------------------
            # Full Raw Headers
            # -----------------------------------------------------------------
            f.write("=" * 80 + "\n")
            f.write("FULL HEADERS (RAW)\n")
            f.write("=" * 80 + "\n\n")
            if headers_raw:
                for k, v in headers_raw.items():
                    f.write(f"{k}: {str(v)}\n")
            else:
                f.write("(No raw headers found)\n")
            f.write("\n")

            # -----------------------------------------------------------------
            # Body Summary
            # -----------------------------------------------------------------
            f.write("=" * 80 + "\n")
            f.write("BODY SUMMARY\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"Plain length : {body_stats.get('plain_length', 0)}\n")
            f.write(f"HTML length  : {body_stats.get('html_length', 0)}\n")
            f.write(f"Hidden HTML  : {body_stats.get('hidden_html_count', 0)}\n\n")


            # -----------------------------------------------------------------
            # Defanged IOC List
            # -----------------------------------------------------------------
            f.write("=" * 80 + "\n")
            """
            f.write("DEFANGED IOC LIST\n")
            f.write("=" * 80 + "\n\n")
            """

            f.write(email_data.get("defanged_iocs_text", "No defanged IOC text available.\n"))
            f.write("\n\n")

            """
            No need fo this code for now 
            # -----------------------------------------------------------------
            # Extracted URLs
            # -----------------------------------------------------------------
            f.write("=" * 80 + "\n")
            f.write("EXTRACTED URLs\n")
            f.write("=" * 80 + "\n\n")
            if urls:
                for u in urls:
                    f.write(f"  - {u}\n")
            else:
                f.write("  - None\n")
            f.write("\n")
            """

            # -----------------------------------------------------------------
            # Attachments
            # -----------------------------------------------------------------

            f.write("=" * 80 + "\n")
            f.write("ATTACHMENTS\n")
            f.write("=" * 80 + "\n\n")
            if attachments:
                for att in attachments:
                    f.write(f"  Filename: {att.get('filename', 'N/A')}\n")
                    f.write(f"  Size:     {att.get('size', 0)} bytes\n")
                    f.write(f"  SHA256:   {att.get('sha256', 'N/A')}\n")

                    # ✅ VT HASH RESULT
                    vt_hash = att.get("vt_hash", {}) or {}

                    if vt_hash:
                        f.write(f"  VT Hash Score : {vt_hash.get('vt_malicious', 0)}\n")
                        f.write(f"  VT Status     : {vt_hash.get('vt_status', 'N/A')}\n")

                    # ✅ VT UPLOAD RESULT
                    vt_upload = att.get("vt_upload", {}) or {}
                    if vt_upload:
                        if vt_upload.get("status") == "submitted":
                            f.write("  VT Upload     : Submitted\n")
                            f.write(f"  Analysis ID   : {vt_upload.get('analysis_id', 'N/A')}\n")
                        else:
                            f.write(f"  VT Upload     : {vt_upload.get('status')}\n")

                    f.write("\n")
            else:
                f.write("  - No attachments found.\n\n")

            # -----------------------------------------------------------------
            # IOC Scoring (--OSINT--)
            # -----------------------------------------------------------------

            f.write("=" * 50 + "\n")
            f.write("IOC SCORING (--OSINT--)\n")
            f.write("=" * 50 + "\n\n")

            if vt_results:
                for item in vt_results:

                    ioc_type = item.get("ioc_type", "IOC").lower()
                    value = item.get("normalized", "")
                    vt_score = item.get("vt_malicious", 0)
                    status = item.get("category", "Unknown")

                    wl = item.get("is_whitelisted", False)
                    bl = item.get("is_blocklisted", False)

                    final_score = item.get("final_score", vt_score)

                    provider_context = item.get("provider_context", {}) or {}
                    reason = item.get("reason", []) or []

                    urlscan_info = provider_context.get("urlscan", {}) or {}
                    abuse_info = provider_context.get("abuseipdb", {}) or {}
                    anyrun_info = provider_context.get("anyrun", {}) or {}
                    talos_info = provider_context.get("talos", {}) or {}
                    rdap_info = provider_context.get("rdap", {}) or {}
                    whois_info = provider_context.get("whois", {}) or {}

                    # ---------------- HASH SPECIAL BLOCK ----------------
                    if ioc_type == "hash":

                        f.write(f"[HASH] {value}\n")
                        f.write("-" * 40 + "\n")

                        f.write(f"→ Verdict     : {status}\n")
                        f.write(f"→ VT Score    : {vt_score}\n\n")

                        matched = False

                        for att in attachments:
                            if att.get("sha256") == value:
                                matched = True
                                
                                f.write("→ File Info:\n")
                                f.write(f"     • Name : {att.get('filename')}\n")
                                f.write(f"     • Size : {att.get('size')} bytes\n")
                                
                        # ADD VT DATA IF AVAILABLE
                                vt_hash = att.get("vt_hash", {}) or {}

                                if vt_hash:
                                    f.write(f"     • VT Score : {vt_hash.get('vt_malicious', 0)}\n")

                                if vt_upload:
                                    f.write(f"     • VT Upload : {vt_upload.get('status')}\n")

                        if not matched:
                            f.write("→ File Info: Not linked to extracted attachments\n")

                        f.write("\n→ Threat Intelligence:\n")
                        f.write(f"     • VT detections: {vt_score}\n")

                        if vt_score >= 20:
                            f.write("     • Known Malware\n")

                        if reason:
                            f.write("\n→ Reason:\n")
                            for r in reason:
                                f.write(f"     • {r}\n")

                        f.write("\n\n")

                        continue   # VERY IMPORTANT

                    # ---------------- NORMAL IOC BLOCK ----------------

                    f.write(f"[{ioc_type.upper()}] {value}\n")
                    f.write("-" * 40 + "\n")

                    f.write(f"→ Verdict     : {status}\n")
                    f.write(f"→ VT Score    : {vt_score}\n")
                    f.write(f"→ Final Score : {final_score}\n")

                    # WHOIS BLOCK
              
                    whois_info = provider_context.get("whois", {}) or {}

                    if ioc_type == "ip":
                        f.write("→ WHOIS: Not applicable (IP address)\n")

                    elif whois_info and whois_info.get("status") == "ok":

                        f.write("→ WHOIS:\n")

                        age = whois_info.get("age_days")
                        created = whois_info.get("created")
                        expires = whois_info.get("expires")
                        registrar = whois_info.get("registrar")

                        if age is not None:
                            flag = " [NEW]" if age < 30 else ""
                            f.write(f"     • Age       : {age} days{flag}\n")

                            if age < 7:
                                f.write("     • Risk      : Newly registered domain ⚠️\n")

                        if created:
                            f.write(f"     • Created   : {created[:10]}\n")

                        if expires:
                            f.write(f"     • Expires   : {expires[:10]}\n")

                        if registrar:
                            f.write(f"     • Registrar : {registrar}\n")

                    elif whois_info and whois_info.get("status") in ("error", "failed_401", "failed_403", "failed_404", "no_data", "not_applicable", "no_api_key", "invalid_domain"):
                        error_text = whois_info.get("error") or whois_info.get("reason") or whois_info.get("status")
                        f.write(f"→ WHOIS: Lookup failed ({error_text})\n")

                    else:
                        f.write("→ WHOIS: No data available\n")

                    # OSINT BLOCK (CLEAN)
                    f.write("\n→ OSINT:\n")

                    if urlscan_info:
                        f.write(f"     • URLScan : {urlscan_info.get('status')}\n")

                    if abuse_info:
                        f.write(f"     • AbuseIPDB : score={abuse_info.get('abuse_score')}\n")

                    if anyrun_info:
                        f.write(f"     • Any.Run : {anyrun_info.get('status')}\n")

                    if talos_info:
                        f.write(f"     • Talos : {talos_info.get('portal_lookup')}\n")

                    if rdap_info:
                        f.write(f"     • RDAP  : {rdap_info.get('portal_lookup')}\n")

                    """                    
                    # REASON BLOCK
                    if reason:
                        f.write("\n→ Reason:\n")
                        for r in reason:
                            f.write(f"     • {r}\n")
                    """

                    f.write("\n\n")

            else:
                f.write("No VirusTotal scoring results available.\n\n")
            f.write("\n")
            
            # ==================================================
            # CAMPAIGN ANALYSIS
            # ==================================================

            f.write("=" *80 + "\n")
            f.write("CAMPAIGN ANALYSIS\n")
            f.write("=" *80 + "\n")

            campaign = email_data.get("campaign", {}) or {}

            # If your structure is different, use:
            # Campaign = email_data.get("campaign", {})

            f.write(f"\nConfidence: {campaign.get('confidence', 'UNKNOWN')}\n")

            # Malicious IPs
            if campaign.get("malicious_ips"):
                f.write("\nMalicious IPs:\n")
                for ip in campaign["malicious_ips"]:
                    f.write(f"  - {ip}\n")
            
            # Malicious Domains
            if campaign.get("malicious_domains"):
                f.write("\nMalicious Domains:\n")
                for d in campaign["malicious_domains"]:
                    f.write(f"   - {d}\n")
            
            # Phishing Domains
            if campaign.get("phishing_domains"):
                f.write("\nPhishing Domains:\n")
                for d in campaign["phishing_domains"]:
                    f.write(f"  - {d}\n")

            # Ransomware Domains
            if campaign.get("ransomware_domains"):
                f.write("\nRansomware Domains:\n")
                for d in campaign["ransomware_domains"]:
                    f.write(f"    -{d}\n")

            # Reused Infrastructure
            if campaign.get("reused_iocs"):
                f.write("\nReused Infrastructure:\n")
                for i in campaign["reused_iocs"]:
                    f.wrtire(f"  - {i}\n")

            if not campaign:
                f.write("\nNo campaign patterns detected\n")

            # ==================================================
            # FINAL ALERT DECISION ✅
            # ==================================================
            f.write("=" * 80 + "\n")
            f.write("FINAL ALERT DECISION\n")
            f.write("=" * 80 + "\n")

            alert = email_data.get("alert", {}) or {}
            # OR:
            # alert = email_data.get("alert", {})

            level = alert.get("level", "UNKNOWN")

            if level == "HIGH":
                f.write("\n🚨 FINAL ALERT LEVEL: HIGH (IMMEDIATE ACTION REQUIRED)\n")
            elif level == "MEDIUM":
                f.write("\n⚠ FINAL ALERT LEVEL: MEDIUM (INVESTIGATION REQUIRED)\n")
            else:
                f.write("\n✅ FINAL ALERT LEVEL: LOW\n")

            # Reasons
            if alert.get("reasons"):
                f.write("\nReason:\n")
                for r in alert["reasons"]:
                    f.write(f" - {r}\n")

            # Actions
            if alert.get("recommended_actions"):
                f.write("\nRecommended Actions:\n")
                for a in alert["recommended_actions"]:
                    f.write(f" - {a}\n")
            
            if alert.get("level") == "HIGH":
                f.write("\n⚠ HIGH RISK EMAIL DETECTED\n")

            # -----------------------------------------------------------------
            # Threat Summary
            # -----------------------------------------------------------------
            f.write("=" * 80 + "\n")
            f.write("THREAT SUMMARY\n")
            f.write("=" * 80 + "\n\n")
            total_iocs = sum(v.get("count", 0) for v in iocs_norm.values())
            f.write(f"Total IOCs detected: {total_iocs} (IPs + Domains + URLs + Hashes)\n")
            f.write(f"Total attachments:   {len(attachments)}\n")
            f.write(f"Total URLs found:    {len(urls)}\n\n")

            # OSINT SUMMARY
            osint_summary = email_data.get("osint_summary", {}) or {}

            """
                f.write("→ OSINT:\n")

            providers = osint_summary.get("providers_seen", []) or []

            if "urlscan" in providers:
                f.write(f"     • URLScan : hits={osint_summary.get('urlscan_hits', 0)}\n")

            if "abuseipdb" in providers:
                f.write(f"     • AbuseIPDB : hits={osint_summary.get('abuseipdb_hits', 0)}\n")

            if "anyrun" in providers:
                f.write(f"     • Any.Run : submissions={osint_summary.get('anyrun_submissions', 0)}\n")
            """

            f.write(f"Email Severity:{email_data.get('email_severity', 'Unknown')}\n")
            f.write(f"Email Score: {email_data.get('email_score', 0)}\n")
            f.write("Reasons:\n")
            for reason in email_data.get("email_score_reasons", []):
                f.write(f"  • {reason}\n")

            if email_data.get("email_score", 0) > 0:
                f.write("[!] ALERT: Suspicious indicators detected in this email!\n")
            else:
                f.write("[✓] No obvious malicious indicators detected.\n")

        logger.info("Text report generated: %s", report_path)
        return report_path


    def update_config_blocklist_excel(self, email_data: Dict[str, Any], path: str = "config/blocklist.xlsx") -> str:
        """
        Auto update config/blocklist.xlsx (no duplicates)
        """

        ioc_scoring = email_data.get("ioc_scoring", []) or []
        new_rows = []

        for item in ioc_scoring:

            if item.get("category") != "Malicious":
                continue

            value = item.get("normalized")
            ioc_type = item.get("ioc_type")

            if not value:
                continue

            provider_context = item.get("provider_context", {}) or {}
            whois_info = provider_context.get("whois", {}) or {}
            abuse_info = provider_context.get("abuseipdb", {}) or {}

            vt_hits = item.get("vt_malicious", 0)
            score = item.get("final_score", 0)

            # ✅ basic intelligence mapping
            confidence = "HIGH" if vt_hits > 5 else "MEDIUM"

            if score >= 8:
                severity = "CRITICAL"
            elif score >= 5:
                severity = "HIGH"
            else:
                severity = "MEDIUM"

            if provider_context.get("urlscan"):
                source = "URLSCAN"
            elif provider_context.get("abuseipdb"):
                source = "ABUSEIPDB"
            else:
                source = "VT"

            if "login" in value:
                category = "phishing"
            elif "lockbit" in value:
                category = "ransomware"
            elif ioc_type == "hash":
                category = "malware"
            else:
                category = "infra"

            reputation = "malicious" if vt_hits > 5 else "suspicious" if abuse_info.get("abuse_score", 0) >= 70 else "clean"

            new_rows.append({
                "type": ioc_type,
                "value": value,
                "description": ", ".join(item.get("reason", [])[:2]),
                "score": score,
                "confidence": confidence,
                "severity": severity,
                "source": source,
                "category": category,
                "status": "active",
                "first_seen": dt.datetime.now().strftime("%Y-%m-%d"),
                "last_analyzed": dt.datetime.now().strftime("%Y-%m-%d"),
                "frequency": 1,
                "tags": ",".join(item.get("reason", [])[:2]),
                "campaign": "",
                "action": "block",
                "whois_age": str(whois_info.get("age_days", "")),
                
                "reputation": reputation,
            })

        if not new_rows:
            logger.info("No new blocklist entries to update.")
            return path

        # ✅ LOAD EXISTING FILE
        if os.path.exists(path):
            try:
                df_existing = pd.read_excel(path, engine="openpyxl").fillna("")
            except Exception as e:
                logger.warning(f"⚠ Invalid Excel detected, recreating: {path} → {e}")
                df_existing = pd.DataFrame()
        else:
            df_existing = pd.DataFrame()

        df_new = pd.DataFrame(new_rows)

        required_cols = list(df_new.columns)

        for col in required_cols:
            if col not in df_existing.columns:
                df_existing[col] = ""

        # ✅ Make sure numeric columns are really numeric
        if "score" in df_existing.columns:
            df_existing["score"] = pd.to_numeric(df_existing["score"], errors="coerce").fillna(0).astype(int)

        if "frequency" in df_existing.columns:
            df_existing["frequency"] = pd.to_numeric(df_existing["frequency"], errors="coerce").fillna(0).astype(int)
        else:
            df_existing["frequency"] = 0

        if "whois_age" in df_existing.columns:
            # keep whois_age flexible because some rows may contain "-"
            df_existing["whois_age"] = df_existing["whois_age"].astype(str)
        
# ✅ CREATE UNIQUE KEY (type + value)
        if not df_existing.empty:
            df_existing["key"] = df_existing["type"].str.lower() + "|" + df_existing["value"].str.lower()
        else:
            df_existing = pd.DataFrame(columns=list(df_new.columns) + ["key"])

        df_new["key"] = df_new["type"].str.lower() + "|" + df_new["value"].str.lower()

        df_existing_map = {row["key"]: idx for idx, row in df_existing.iterrows()}

        for _, row in df_new.iterrows():
            key = row["key"]

            if key in df_existing_map:
                idx = df_existing_map[key]

                # Update existing IOC intelligence
                old_score = df_existing.at[idx, "score"]
                try:
                    old_score = int(old_score) if old_score != "" else 0
                except Exception:
                    old_score = 0

                old_freq = int(df_existing.at[idx, "frequency"]) if "frequency" in df_existing.columns else 0
                try:
                    old_freq = int(old_freq) if old_freq != "" else 0
                except Exception:
                    old_freq = 0

                df_existing.at[idx, "score"] = max(old_score, int(row["score"]))
                df_existing.at[idx, "last_analyzed"] = row["last_analyzed"]
                df_existing.at[idx, "description"] = row["description"] or df_existing.at[idx, "description"]
                df_existing.at[idx, "confidence"] = row["confidence"] or df_existing.at[idx, "confidence"]
                df_existing.at[idx, "severity"] = row["severity"] or df_existing.at[idx, "severity"]
                df_existing.at[idx, "source"] = row["source"] or df_existing.at[idx, "source"]
                df_existing.at[idx, "category"] = row["category"] or df_existing.at[idx, "category"]
                df_existing.at[idx, "status"] = "active"
                df_existing.at[idx, "tags"] = row["tags"] or df_existing.at[idx, "tags"]
                df_existing.at[idx, "campaign"] = row["campaign"] or df_existing.at[idx, "campaign"]
                df_existing.at[idx, "action"] = row["action"] or df_existing.at[idx, "action"]
                whois_age_value = str(row["whois_age"]) if row["whois_age"] not in (None, "", "nan") else ""
                df_existing.at[idx, "whois_age"] = (
                    whois_age_value or df_existing.at[idx, "whois_age"]
                )

                df_existing.at[idx, "reputation"] = row["reputation"] or df_existing.at[idx, "reputation"]
                df_existing.at[idx, "frequency"] = old_freq + 1

            else:
                df_existing = pd.concat([df_existing, pd.DataFrame([row])], ignore_index=True)

            df_final = df_existing.drop(columns=["key"], errors="ignore")

        # ✅ SAVE BACK
        df_final.to_excel(path, index=False, engine="openpyxl")

        logger.info(f"✅ Updated config blocklist: {path}")

        return path

    def generate_blocklist_report(self, email_data: Dict[str, Any]) -> str:
        """
        Create blocklist report Excel file in reports folder
        """

        ts = self._timestamp()
        output_path = os.path.join(self.output_dir, f"blocklist_{ts}.xlsx")

        ioc_scoring = email_data.get("ioc_scoring", [])

        rows = []

        for item in ioc_scoring:
            if item.get("category") != "Malicious":
                continue

            rows.append({
                "type": item.get("ioc_type"),
                "value": item.get("normalized"),
                "vt_score": item.get("vt_malicious"),
                "final_score": item.get("final_score"),
                "reason": ", ".join(item.get("reason", [])[:2])
            })

        if not rows:
            logger.info("No malicious IOCs for blocklist report")
            return output_path

        df = pd.DataFrame(rows)

        df.to_excel(output_path, index=False, engine="openpyxl")

        logger.info("Blocklist report generated: %s", output_path)


        return output_path