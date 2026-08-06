# app.py
import os
import json
import re
# import requests
# import ipaddress
import ast
import html
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime

from pathlib import Path

import pandas as pd
import streamlit as st
from email_analyzer.analyzer import analyze_email, reanalyze_ioc_in_email_data
from email.utils import parsedate_to_datetime
from ioc_lib.ioc_analyzer import anyrun_list_analyses
from email_analyzer.mail_reporter import MailReporter
from email_analyzer.watcher import run_cycle

# -------------------------------------------------------------------
# Page Config
# -------------------------------------------------------------------
st.set_page_config(page_title="Email Threat Analysis Dashboard", layout="wide")

st.title("📧 Email Threat Analysis Dashboard")

# -------------------------------------------------------------------
# Session State Defaults
# -------------------------------------------------------------------
DEFAULT_SESSION_VALUES = {
    "email_data": None,
    "analysis_done": False,
    "last_uploaded_name": None,
    "json_report_path": None,
    "txt_report_path": None,
    "uploaded_eml_path": None,
    "show_only_malicious": False,
}
for k, v in DEFAULT_SESSION_VALUES.items():
    if k not in st.session_state:
        st.session_state[k] = v


# -------------------------------------------------------------------
# Utility / Setup Helpers
# -------------------------------------------------------------------
def safe_report_time() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def read_file_bytes(path: str) -> bytes:
    return Path(path).read_bytes()


def run_analysis_on_path(eml_path: str, force_reanalyze: bool = False) -> dict:
    ensure_config_excels()
    ensure_reports_dir()

    email_data = analyze_email(eml_path, force_reanalyze_iocs=force_reanalyze)
    if not email_data:
        return {}

    reporter = MailReporter(output_dir="reports")
    txt_report_path = reporter.generate_text_report(email_data)
    json_report_path = reporter.generate_json_report(email_data)

    st.session_state.email_data = email_data
    st.session_state.analysis_done = True
    st.session_state.txt_report_path = txt_report_path
    st.session_state.json_report_path = json_report_path

    # Preserve the original source EML file. Do not move uploaded or input files into processed history.
    # Uploaded files are already stored in a temp path for analysis, and source files remain unchanged.
    return email_data


CONFIG_DIR = "config"
WHITELIST_FILE = os.path.join(CONFIG_DIR, "whitelist.xlsx")
BLOCKLIST_FILE = os.path.join(CONFIG_DIR, "blocklist.xlsx")


def ensure_reports_dir() -> None:
    os.makedirs("reports", exist_ok=True)


def ensure_processed_dir() -> str:
    path = os.path.join("data", "processed")
    os.makedirs(path, exist_ok=True)
    return path


def load_excel_file(path: str):
    if not os.path.exists(path):
        return None, f"File not found: {path}"

    try:
        df = pd.read_excel(path, engine="openpyxl")
        return df, None
    except Exception as e:
        return None, str(e)


def ensure_config_excels() -> None:
    """
    Create whitelist.xlsx and blocklist.xlsx if missing.
    """
    os.makedirs("config", exist_ok=True)

    columns = [
        "type", "value", "description", "score", "confidence", "severity",
        "source", "category", "status", "first_seen", "last_analyzed",
        "frequency", "tags", "campaign", "action", "whois_age", "reputation"
    ]

    whitelist_path = os.path.join("config", "whitelist.xlsx")
    blocklist_path = os.path.join("config", "blocklist.xlsx")

    if not os.path.exists(whitelist_path):
        pd.DataFrame(columns=columns).to_excel(whitelist_path, index=False, engine="openpyxl")

    if not os.path.exists(blocklist_path):
        pd.DataFrame(columns=columns).to_excel(blocklist_path, index=False, engine="openpyxl")


def save_json_report(email_data: dict) -> str:
    ensure_reports_dir()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_path = f"reports/email_analysis_{timestamp}.json"

    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(email_data, f, indent=4, ensure_ascii=False)

    return file_path


def save_text_report(email_data: dict) -> str:
    """
    Simple UI-side TXT summary export.
    """
    ensure_reports_dir()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_path = f"reports/email_analysis_{timestamp}.txt"

    subject = email_data.get("subject", "")
    sender = email_data.get("from", "")
    to = email_data.get("to", "")
    severity = email_data.get("email_severity", "Unknown")
    score = email_data.get("email_score", 0)

    iocs = email_data.get("iocs", {}) or {}
    counts = iocs.get("counts", {}) or {}

    with open(file_path, "w", encoding="utf-8") as f:
        f.write("EMAIL THREAT ANALYSIS SUMMARY\n")
        f.write("=" * 70 + "\n")
        f.write(f"Subject : {subject}\n")
        f.write(f"From    : {sender}\n")
        f.write(f"To      : {to}\n")
        f.write(f"Severity: {severity}\n")
        f.write(f"Score   : {score}\n")
        f.write(f"Report  : {safe_report_time()}\n\n")

        f.write("IOC COUNTS\n")
        f.write("-" * 70 + "\n")
        f.write(f"IPs    : {counts.get('ips', 0)}\n")
        f.write(f"Domains: {counts.get('domains', 0)}\n")
        f.write(f"URLs   : {counts.get('urls', 0)}\n")
        f.write(f"Hashes : {counts.get('hashes', 0)}\n\n")

        f.write("ALERT\n")
        f.write("-" * 70 + "\n")
        alert = email_data.get("alert", {}) or {}
        f.write(f"Level: {alert.get('level', 'Unknown')}\n")
        for reason in alert.get("reasons", []) or []:
            f.write(f"- {reason}\n")

    return file_path


def get_latest_report_path() -> str:
    ensure_reports_dir()
    reports = [
        os.path.join("reports", f)
        for f in os.listdir("reports")
        if f.lower().endswith((".json", ".txt"))
    ]
    if not reports:
        return ""
    return max(reports, key=os.path.getmtime)


def find_report_before(target_dt: datetime) -> str:
    """Find the latest report file whose embedded timestamp is <= target_dt.

    Returns the file path or empty string if none found.
    """
    ensure_reports_dir()
    pattern = re.compile(r"email_analysis_(\d{8}_\d{6})\.(json|txt)$")
    candidates = []
    for f in os.listdir("reports"):
        m = pattern.search(f)
        if not m:
            continue
        ts_str = m.group(1)
        try:
            ts = datetime.strptime(ts_str, "%Y%m%d_%H%M%S")
        except Exception:
            continue
        if ts <= target_dt:
            candidates.append((ts, os.path.join("reports", f)))

    if not candidates:
        return ""
    candidates.sort(key=lambda x: x[0], reverse=True)
    return candidates[0][1]


def list_reports_in_range(from_dt: datetime, to_dt: datetime) -> list:
    """Return list of report file paths with embedded timestamps (or mtime fallback) within [from_dt, to_dt]."""
    ensure_reports_dir()
    pattern = re.compile(r"email_analysis_(\d{8}_\d{6})\.(json|txt)$")
    matches = []

    for f in os.listdir("reports"):
        full = os.path.join("reports", f)
        m = pattern.search(f)
        if m:
            try:
                ts = datetime.strptime(m.group(1), "%Y%m%d_%H%M%S")
            except Exception:
                continue
            if from_dt <= ts <= to_dt:
                matches.append((ts, full))
        else:
            # fallback to mtime-based check
            try:
                mtime = datetime.fromtimestamp(os.path.getmtime(full))
            except Exception:
                continue
            if from_dt <= mtime <= to_dt:
                matches.append((mtime, full))

    # sort newest first
    matches.sort(key=lambda x: x[0], reverse=True)
    return [p for _, p in matches]


def list_processed_eml_files() -> list:
    """Return processed EML files from possible processed folders, sorted by mtime desc."""
    candidates = []
    project_root = os.path.dirname(os.path.abspath(__file__))
    dirs = [os.path.join(project_root, "data", "processed"), os.path.join(project_root, "data", "Processed")]
    for d in dirs:
        if not os.path.isdir(d):
            continue
        for f in os.listdir(d):
            if not f.lower().endswith(".eml"):
                continue
            if f.lower() == "temp_uploaded.eml":
                continue
            full = os.path.join(d, f)
            try:
                mtime = os.path.getmtime(full)
            except Exception:
                continue
            candidates.append((mtime, full))

    candidates.sort(key=lambda x: x[0], reverse=True)
    return [p for _, p in candidates]


def load_report_at_path(path: str) -> dict:
    """Load a JSON report at path into session state (if JSON) and return dict.

    Will set `st.session_state.email_data`, `st.session_state.json_report_path`,
    and `st.session_state.txt_report_path` when appropriate.
    """
    if not path or not os.path.exists(path):
        return {}

    email_data = {}
    try:
        if path.lower().endswith(".json"):
            with open(path, "r", encoding="utf-8") as f:
                email_data = json.load(f)
            st.session_state.json_report_path = path
            # derive txt path if exists
            txt_candidate = path[:-5] + ".txt"
            if os.path.exists(txt_candidate):
                st.session_state.txt_report_path = txt_candidate
            else:
                st.session_state.txt_report_path = None
        elif path.lower().endswith(".txt"):
            # can't load structured JSON, but set txt path for download
            st.session_state.txt_report_path = path
            st.session_state.json_report_path = None
            email_data = {}

        st.session_state.email_data = email_data
        st.session_state.last_uploaded_name = os.path.basename(path)
        return email_data
    except Exception:
        return {}


def load_latest_report() -> dict:
    latest_path = get_latest_report_path()
    if not latest_path or not os.path.exists(latest_path):
        return {}

    try:
        with open(latest_path, "r", encoding="utf-8") as f:
            report = json.load(f)
        st.session_state.email_data = report
        st.session_state.analysis_done = True
        st.session_state.json_report_path = latest_path
        st.session_state.txt_report_path = None
        st.session_state.last_uploaded_name = os.path.basename(latest_path)
        return report
    except Exception as e:
        st.error(f"Failed to load latest report: {e}")
        return {}


def analyze_inbox_for_date(target_date: datetime) -> int:
    """Analyze all .eml files in the inbox whose modification time falls on target_date.

    Returns the number of files analyzed.
    """
    project_root = os.path.dirname(os.path.abspath(__file__))
    inbox_dir = os.path.join(project_root, "data", "Sample Email")
    if not os.path.exists(inbox_dir):
        return 0

    # compute day's range
    from_dt = datetime.combine(target_date.date(), datetime.min.time())
    to_dt = datetime.combine(target_date.date(), datetime.max.time())

    eml_files = [f for f in os.listdir(inbox_dir) if f.lower().endswith(".eml")]
    analyzed = 0

    for fn in eml_files:
        full_path = os.path.join(inbox_dir, fn)
        try:
            mtime = datetime.fromtimestamp(os.path.getmtime(full_path))
        except Exception:
            continue

        if from_dt <= mtime <= to_dt:
            # run analysis for this file (uses existing reporter flow)
            run_analysis_on_path(full_path, force_reanalyze=False)
            analyzed += 1

    return analyzed


# -------------------------------------------------------------------
# Data Builders
# -------------------------------------------------------------------
def format_ioc_link(url: str, label: str = "Open") -> str:
    if not url:
        return ""
    safe_url = html.escape(url, quote=True)
    safe_label = html.escape(label)
    return (
        f'<a href="{safe_url}" target="_blank" rel="noopener noreferrer">'
        f'<button style="padding:6px 10px; border:none; background-color:#0078d4; color:#ffffff; '
        f'border-radius:4px; cursor:pointer;">{safe_label}</button></a>'
    )


def render_ioc_html_table(df: pd.DataFrame) -> str:
    if df.empty:
        return ""
    header_cells = "".join(
        f'<th style="padding:8px 10px; text-align:left; background:#f3f4f6; position:sticky; top:0; z-index:2; border-bottom:1px solid #d1d5db;">{html.escape(str(col))}</th>'
        for col in df.columns
    )
    rows_html = []
    for _, row in df.iterrows():
        cells = []
        for col in df.columns:
            value = row[col]
            if col in {"ANY.RUN URL", "URLScan Result", "Talos Lookup", "RDAP Lookup"} and value:
                button_label = {
                    "ANY.RUN URL": "ANY.RUN",
                    "URLScan Result": "URLScan",
                    "Talos Lookup": "Talos",
                    "RDAP Lookup": "RDAP",
                }.get(col, "Open")
                cells.append(f'<td style="padding:6px 10px;">{format_ioc_link(str(value), button_label)}</td>')
            else:
                cells.append(f'<td style="padding:6px 10px; vertical-align:top;">{html.escape(str(value))}</td>')
        rows_html.append(f"<tr>{''.join(cells)}</tr>")
    table_html = (
        '<div style="overflow:auto; margin-top:16px; max-height:480px;">'
        '<table style="border-collapse:collapse; width:100%; min-width:900px; font-family:Arial, sans-serif; font-size:13px;">'
        f'<thead><tr>{header_cells}</tr></thead>'
        f'<tbody>{"".join(rows_html)}</tbody>'
        '</table></div>'
    )
    return table_html


def build_ioc_df(email_data: dict) -> pd.DataFrame:
    """
    Main IOC Results table with integrated OSINT summary fields.
    """
    rows = []
    for item in email_data.get("ioc_scoring", []) or []:
        provider = item.get("provider_context", {}) or {}
        whois = provider.get("whois", {}) or {}
        abuseipdb = provider.get("abuseipdb", {}) or {}
        anyrun = provider.get("anyrun", {}) or {}
        talos = provider.get("talos", {}) or {}
        rdap = provider.get("rdap", {}) or {}
        urlscan = provider.get("urlscan", {}) or {}

        talos_lookup = talos.get("portal_lookup") if isinstance(talos, dict) else str(talos)
        rdap_lookup = rdap.get("portal_lookup") if isinstance(rdap, dict) else str(rdap)
        urlscan_result = urlscan.get("result_url", "") or urlscan.get("result", "") or urlscan.get("url", "")
        anyrun_url = anyrun.get("url", "") or anyrun.get("result", "")

        rows.append({
            "Type": item.get("ioc_type", "").upper(),
            "Value": item.get("normalized", ""),
            "VT Score": item.get("vt_malicious", 0),
            "Verdict": item.get("category", ""),
            "AbuseIPDB Score": abuseipdb.get("abuse_score", ""),
            "ANY.RUN Status": anyrun.get("status", ""),
            "ANY.RUN URL": anyrun_url,
            "URLScan Result": urlscan_result,
            "WHOIS Age (days)": whois.get("age_days", ""),
            "Registrar": whois.get("registrar", ""),
            "Talos Lookup": talos_lookup,
            "RDAP Lookup": rdap_lookup,
            "Whitelisted": item.get("is_whitelisted", False),
            "Blocklisted": item.get("is_blocklisted", False),
        })
    return pd.DataFrame(rows)


def build_url_wrapper_df(email_data: dict) -> pd.DataFrame:
    rows = []
    for item in email_data.get("urls_extracted_detail", []) or []:
        rows.append({
            "Provider": item.get("provider", "Direct URL") or "Direct URL",
            "Source": item.get("source", ""),
            "Wrapped URL": item.get("wrapped_url", ""),
            "Decoded URL": item.get("decoded_url", ""),
            "Final IOC URL": item.get("final_ioc_url", ""),
            "Decode Success": item.get("decode_success", False),
            "Wrapped": item.get("wrapped", False),
        })
    return pd.DataFrame(rows)

# This code is used to build the attachment DataFrame for the email analysis dashboard.

def build_attachment_df(email_data: dict) -> pd.DataFrame:
    rows = []
    for att in email_data.get("attachments", []) or []:
        vt_hash = att.get("vt_hash", {}) or {}
        vt_upload = att.get("vt_upload", {}) or {}
        anyrun = att.get("anyrun", {}) or {}
        talos = att.get("talos", {}) or {}
        rows.append({
            "Filename": att.get("filename", ""),
            "Size": att.get("size", 0),
            "SHA256": att.get("sha256", ""),
            "VT Hash Score": vt_hash.get("vt_malicious", 0),
            "VT Status": vt_hash.get("vt_status", ""),
            "VT Upload": vt_upload.get("status", ""),
            "ANY.RUN Status": anyrun.get("status", ""),
            #"ANY.RUN Analysis ID": anyrun.get("analysis_id", ""),
            "Talos Lookup": talos.get("portal_lookup", "") if isinstance(talos, dict) else "",
        })
    return pd.DataFrame(rows)


def build_ioc_observed_df(email_data: dict) -> pd.DataFrame:
    """
    Cleaner IOC Observed table:
    """
    iocs = email_data.get("iocs", {}) or {}

    ip_items = iocs.get("ips", []) or []
    domain_items = iocs.get("domains", []) or []
    url_items = iocs.get("urls", []) or []
    hash_items = iocs.get("hashes", []) or []

    rows = [
        {"IOC Type": "IPs", "Count": len(ip_items) },
        {"IOC Type": "Domains", "Count": len(domain_items) },
        {"IOC Type": "URLs", "Count": len(url_items)},
        {"IOC Type": "Hashes", "Count": len(hash_items)},
    ]
    return pd.DataFrame(rows)


def build_ioc_osint_df(email_data: dict) -> pd.DataFrame:
    rows = []
    for item in email_data.get("ioc_scoring", []) or []:
        provider = item.get("provider_context", {}) or {}
        value = item.get("normalized", "")
        ioc_type = (item.get("ioc_type", "") or "").upper()

        if provider.get("whois"):
            whois = provider.get("whois", {}) or {}
            rows.append({
                "IOC": value,
                "Type": ioc_type,
                "Source": "WHOIS",
                "Key Info": f"Registrar: {whois.get('registrar', 'N/A')}",
                "Details": f"Age: {whois.get('age_days', 'N/A')} | Created: {whois.get('created', 'N/A')} | Expires: {whois.get('expires', 'N/A')}"
            })

        if provider.get("abuseipdb"):
            abuse = provider.get("abuseipdb", {}) or {}
            rows.append({
                "IOC": value,
                "Type": ioc_type,
                "Source": "AbuseIPDB",
                "Key Info": f"Score: {abuse.get('abuse_score', 'N/A')}",
                "Details": f"Reports: {abuse.get('abuse_reports', 'N/A')} | Country: {abuse.get('country_name', 'N/A')}"
            })

        if provider.get("urlscan"):
            urlscan = provider.get("urlscan", {}) or {}
            rows.append({
                "IOC": value,
                "Type": ioc_type,
                "Source": "URLScan",
                "Key Info": f"Status: {urlscan.get('status', 'N/A')}",
                "Details": f"Result: {urlscan.get('result', '') or urlscan.get('url', '')}"
            })

        if provider.get("anyrun"):
            anyrun = provider.get("anyrun", {}) or {}
            rows.append({
                "IOC": value,
                "Type": ioc_type,
                "Source": "ANY.RUN",
                "Key Info": f"Status: {anyrun.get('status', 'N/A')}",
                "Details": f"Analysis ID: {anyrun.get('analysis_id', 'N/A')} | URL: {anyrun.get('url', '')}"
            })

        if provider.get("talos"):
            talos = provider.get("talos", {}) or {}
            talos_link = talos.get("portal_lookup") if isinstance(talos, dict) else str(talos)
            rows.append({
                "IOC": value,
                "Type": ioc_type,
                "Source": "Talos",
                "Key Info": "Reputation Lookup",
                "Details": talos_link,
            })

        if provider.get("rdap"):
            rdap = provider.get("rdap", {}) or {}
            rdap_link = rdap.get("portal_lookup") if isinstance(rdap, dict) else str(rdap)
            rows.append({
                "IOC": value,
                "Type": ioc_type,
                "Source": "RDAP",
                "Key Info": "Domain Lookup",
                "Details": rdap_link,
            })

    return pd.DataFrame(rows)


def build_domain_whois_summary_df(email_data: dict) -> pd.DataFrame:
    """
    WHOIS summary table for domain IOCs used in Threat Summary.
    """
    rows = []
    for item in email_data.get("ioc_scoring", []) or []:
        if item.get("ioc_type") != "domain":
            continue

        provider = item.get("provider_context", {}) or {}
        whois = provider.get("whois", {}) or {}

        if whois:
            rows.append({
                "Domain": item.get("normalized", ""),
                "Verdict": item.get("category", ""),
                "WHOIS Age (days)": whois.get("age_days", ""),
                "Registrar": whois.get("registrar", ""),
                "Expires": whois.get("expires", ""),
            })

    return pd.DataFrame(rows)


def format_hop_date(date_str: str):
    if not date_str:
        return {"utc": "", "ist": ""}

    try:
        dt = parsedate_to_datetime(date_str)

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        dt_utc = dt.astimezone(timezone.utc)
        dt_ist = dt_utc.astimezone(
            timezone(timedelta(hours=5, minutes=30))
        )

        return {
            "utc": dt_utc.strftime("%Y-%m-%d %H:%M:%S"),
            "ist": dt_ist.strftime("%Y-%m-%d %H:%M:%S"),
        }

    except Exception as e:
        print(f"Date parse error: {date_str} | {e}")
        return {"utc": "", "ist": ""}


def normalize_received_hops(email_data: dict):
    normalized = []
    hops = email_data.get("received_hops", []) or []

    for hop in hops:
        if not isinstance(hop, dict):
            continue

        raw = hop.get("raw")

        # Case 0: already normalized hop dict
        if raw is None and any(k in hop for k in ("from", "by", "with", "date")):
            normalized.append(hop)
            continue

        # Case 1: dict stored as string
        if isinstance(raw, str) and raw.strip().startswith("{"):
            try:
                parsed = ast.literal_eval(raw)
                normalized.append(parsed)
                continue
            except Exception:
                pass

        # Case 2: raw Received header line
        if isinstance(raw, str):
            from_match = re.search(r"from\s+(.*?)\s+by", raw, re.IGNORECASE)
            by_match = re.search(r"by\s+(.*?)\s+(with|;)", raw, re.IGNORECASE)
            with_match = re.search(r"with\s+(\S+)", raw, re.IGNORECASE)
            date_match = re.search(r";\s*(.+)", raw)

            parsed = {
                "from": from_match.group(1).strip() if from_match else "",
                "by": by_match.group(1).strip() if by_match else "",
                "with": with_match.group(1).strip() if with_match else "",
                "date": date_match.group(1).strip() if date_match else "",
                "delay": hop.get("delay"),
            }
            normalized.append(parsed)

    return normalized

def build_received_hops_df(email_data: dict) -> pd.DataFrame:
    hops = email_data.get("received_hops", []) or []
    rows = []

    for idx, hop in enumerate(hops, start=1):
        if not isinstance(hop, dict):
            continue

        date_info = format_hop_date(hop.get("date", ""))
        delay = hop.get("delay")

        if isinstance(delay, (int, float)):
            delay_display = f"{delay:.1f} sec" if delay >= 0 else f"⚠️ {delay:.1f} sec"
        else:
            delay_display = ""

        risk = detect_hop_risk(hop)

        rows.append({
            "Hop": idx,
            "From": hop.get("from", ""),
            "By": hop.get("by", ""),
            "With": hop.get("with", ""),
            "Date UTC": date_info["utc"],
            "Date IST": date_info["ist"],
            "Delay": delay_display,
            "Risk": risk,
        })

    return pd.DataFrame(rows)


def detect_hop_risk(hop: dict):
    risks = []

    # High-risk indicators
    if "unknown" in (hop.get("from") or "").lower():
        risks.append("🚨 Unknown Sender")

    if not hop.get("by"):
        risks.append("🚨 Missing Receiving Server")

    # Medium-risk indicators
    delay = hop.get("delay")
    if isinstance(delay, (int, float)):
        if delay < 0:
            risks.append("⚠️ Negative Delay")
        elif delay > 10:
            risks.append("⚠️ High Delay")

    if not hop.get("with"):
        risks.append("⚠️ Missing Protocol")

    return ", ".join(risks)


def highlight_risk(row):
    if "🚨" in str(row.get("Risk", "")):
        return ["background-color: #ffcccc"] * len(row)  # RED
    elif "⚠️" in str(row.get("Risk", "")):
        return ["background-color: #fff3cd"] * len(row)  # YELLOW
    else:
        return [""] * len(row)
    

def render_received_hop_details(email_data: dict):
    """
    Readable per-hop details below the table.
    """
    hops = email_data.get("received_hops", []) or []

    if not hops:
        st.info("No received hops found.")
        return

    #st.markdown("### Received Hop Details")
    #for idx, hop in enumerate(hops, start=1):
     #   with st.expander(f"Hop {idx}", expanded=False):
    #        if isinstance(hop, dict):
    #           st.write(f"**From:** {hop.get('from', '')}")
     #           st.write(f"**By:** {hop.get('by', '')}")
      #          st.write(f"**With:** {hop.get('with', '')}")
       #         st.write(f"**Date:** {hop.get('date', '')}")
                
       #         date_info = format_hop_date(hop.get("date", ""))
        #        st.write(f"**Date UTC:** {date_info['utc']}")
         #       st.write(f"**Date IST:** {date_info['ist']}")

          #      if hop.get("delay") is not None:
           #         st.write(f"**Delay:** {hop.get('delay', '')}")
            #else:
             #   st.code(str(hop), language="text")

def build_subject_analysis_df(email_data: dict) -> pd.DataFrame:
    subj = email_data.get("subject_analysis", {}) or {}
    rows = [{"Field": "Subject Severity", "Value": subj.get("subject_severity", "Unknown")}]
    for flag in subj.get("subject_flags", []) or []:
        rows.append({"Field": "Indicator", "Value": flag})
    return pd.DataFrame(rows)


def build_body_summary_df(email_data: dict) -> pd.DataFrame:
    body = email_data.get("body_stats", {}) or {}
    rows = [
        {"Metric": "Plain Length", "Value": body.get("plain_length", 0)},
        {"Metric": "HTML Length", "Value": body.get("html_length", 0)},
        {"Metric": "Hidden HTML Elements", "Value": body.get("hidden_html_count", 0)},
    ]
    return pd.DataFrame(rows)


def build_mismatch_df(email_data: dict) -> pd.DataFrame:
    mismatch = (email_data.get("header_analysis", {}) or {}).get("mismatch_flags", {}) or {}
    rows = [
        {"Field": "From Domain", "Value": mismatch.get("from_domain", "")},
        {"Field": "Reply-To Domain", "Value": mismatch.get("reply_to_domain", "")},
        {"Field": "Return-Path Domain", "Value": mismatch.get("return_path_domain", "")},
        {"Field": "Sender Domain", "Value": mismatch.get("sender_domain", "")},
        {"Field": "Reply-To Mismatch", "Value": mismatch.get("reply_to_mismatch", False)},
        {"Field": "Return-Path Mismatch", "Value": mismatch.get("return_path_mismatch", False)},
        {"Field": "Sender Mismatch", "Value": mismatch.get("sender_mismatch", False)},
    ]
    return pd.DataFrame(rows)


def build_campaign_summary_df(email_data: dict) -> pd.DataFrame:
    campaign = email_data.get("campaign", {}) or {}
    rows = [
        {"Field": "Confidence", "Value": campaign.get("confidence", "Unknown")},
        {"Field": "Malicious IPs", "Value": ", ".join(campaign.get("malicious_ips", [])[:5])},
        {"Field": "Malicious Domains", "Value": ", ".join(campaign.get("malicious_domains", [])[:5])},
        {"Field": "Phishing Domains", "Value": ", ".join(campaign.get("phishing_domains", [])[:5])},
        {"Field": "Ransomware Domains", "Value": ", ".join(campaign.get("ransomware_domains", [])[:5])},
        {"Field": "Reused Infrastructure", "Value": ", ".join(campaign.get("reused_iocs", [])[:5])},
    ]
    return pd.DataFrame(rows)


def build_alert_summary_df(email_data: dict) -> pd.DataFrame:
    alert = email_data.get("alert", {}) or {}
    rows = [{"Field": "Level", "Value": alert.get("level", "Unknown")}]

    for reason in alert.get("reasons", []) or []:
        rows.append({"Field": "Reason", "Value": reason})

    for action in alert.get("recommended_actions", []) or []:
        rows.append({"Field": "Action", "Value": action})

    return pd.DataFrame(rows)


def build_osint_df(provider: dict) -> pd.DataFrame:
    rows = []

    # WHOIS
    if provider.get("whois"):
        whois = provider["whois"] or {}
        rows.append({
            "Source": "WHOIS",
            "Key Info": f"Registrar: {whois.get('registrar', 'N/A')}",
            "Details": f"Age: {whois.get('age_days', 'N/A')} days | Created: {whois.get('created', 'N/A')} | Expires: {whois.get('expires', 'N/A')}"
        })

    # AbuseIPDB
    if provider.get("abuseipdb"):
        abuse = provider["abuseipdb"] or {}
        rows.append({
            "Source": "AbuseIPDB",
            "Key Info": f"Score: {abuse.get('abuse_score', 'N/A')}",
            "Details": f"Reports: {abuse.get('abuse_reports', 'N/A')} | Status: {abuse.get('status', 'N/A')}"
        })

    # URLScan
    if provider.get("urlscan"):
        urlscan = provider["urlscan"] or {}
        rows.append({
            "Source": "URLScan",
            "Key Info": f"Status: {urlscan.get('status', 'N/A')}",
            "Details": str(urlscan)
        })

    # ANY.RUN
    if provider.get("anyrun"):
        anyrun = provider["anyrun"] or {}
        rows.append({
            "Source": "ANY.RUN",
            "Key Info": f"Status: {anyrun.get('status', 'N/A')}",
            "Details": str(anyrun)
        })

    # Talos
    if provider.get("talos"):
        talos_data = provider["talos"]
        if isinstance(talos_data, dict):
            rows.append({
                "Source": "Talos",
                "Key Info": "Reputation Lookup",
                "Details": talos_data.get("portal_lookup", "")
            })
        else:
            rows.append({
                "Source": "Talos",
                "Key Info": "Reputation Lookup",
                "Details": str(talos_data)
            })

    # RDAP
    if provider.get("rdap"):
        rdap_data = provider["rdap"]
        if isinstance(rdap_data, dict):
            rows.append({
                "Source": "RDAP",
                "Key Info": "Domain Lookup",
                "Details": rdap_data.get("portal_lookup", "")
            })
        else:
            rows.append({
                "Source": "RDAP",
                "Key Info": "Domain Lookup",
                "Details": str(rdap_data)
            })

    return pd.DataFrame(rows)


def show_ioc_detail(email_data: dict, selected_value: str):
    selected = None
    for item in email_data.get("ioc_scoring", []) or []:
        if item.get("normalized") == selected_value:
            selected = item
            break

    if not selected:
        st.warning("No IOC details found.")
        return

    provider = selected.get("provider_context", {}) or {}
    whois = provider.get("whois", {}) or {}

    st.subheader("🔍 IOC Detail")

    c1, c2 = st.columns(2)
    with c1:
        st.write(f"**Type:** {selected.get('ioc_type', '').upper()}")
        st.write(f"**Value:** {selected.get('normalized', '')}")
        st.write(f"**Verdict:** {selected.get('category', '')}")

    with c2:
        st.write(f"**VT Score:** {selected.get('vt_malicious', 0)}")
        st.write(f"**Whitelisted:** {selected.get('is_whitelisted', False)}")
        st.write(f"**Blocklisted:** {selected.get('is_blocklisted', False)}")

    # WHOIS quick view
    if whois:
        st.markdown("### WHOIS Quick View")
        whois_df = pd.DataFrame([
            {"Field": "Registrar", "Value": whois.get("registrar", "")},
            {"Field": "Age (days)", "Value": whois.get("age_days", "")},
            {"Field": "Created", "Value": whois.get("created", "")},
            {"Field": "Expires", "Value": whois.get("expires", "")},
        ])
        st.dataframe(whois_df, use_container_width=True, hide_index=True)

    abuseipdb = provider.get("abuseipdb", {}) or {}
    if abuseipdb:
        st.markdown("### AbuseIPDB Details")
        abuse_rows = [
            {"Field": "Confidence / Abuse Score", "Value": abuseipdb.get("abuse_score", "N/A")},
            {"Field": "ISP", "Value": abuseipdb.get("isp", "N/A")},
            {"Field": "Usage Type", "Value": abuseipdb.get("usage_type", "N/A")},
            {"Field": "Hostname(s)", "Value": ", ".join(abuseipdb.get("hostnames", []) or [])},
            {"Field": "Domain", "Value": abuseipdb.get("domain", "N/A")},
            {"Field": "Country", "Value": abuseipdb.get("country_name", "N/A")},
            {"Field": "City", "Value": abuseipdb.get("city", "N/A")},
            {"Field": "ASN", "Value": abuseipdb.get("asn", "N/A")},
            {"Field": "Status", "Value": abuseipdb.get("status", "N/A")},
        ]
        st.dataframe(pd.DataFrame(abuse_rows), use_container_width=True, hide_index=True)

    reasons = selected.get("reason", []) or []
    if reasons:
        st.markdown("### 📊 Reasons")
        for reason in reasons:
            st.write(f"- {reason}")

    with st.expander("🌐 WHOIS / RDAP / Talos / Sandbox / Reputation", expanded=True):
        osint_df = build_osint_df(provider)
        if not osint_df.empty:
            st.dataframe(osint_df, use_container_width=True, hide_index=True)
        else:
            st.info("No OSINT data available for this IOC.")

        # External links
        st.markdown("### 🔗 External Links")
        cols = st.columns(4)

        talos_url = ""
        rdap_url = ""
        urlscan_url = ""
        anyrun_url = ""

        if provider.get("talos"):
            talos_data = provider["talos"]
            talos_url = talos_data.get("portal_lookup", "") if isinstance(talos_data, dict) else str(talos_data)

        if provider.get("rdap"):
            rdap_data = provider["rdap"]
            rdap_url = rdap_data.get("portal_lookup", "") if isinstance(rdap_data, dict) else str(rdap_data)

        if provider.get("urlscan"):
            urlscan_data = provider["urlscan"] or {}
            urlscan_url = urlscan_data.get("result_url", "") or urlscan_data.get("result", "") or urlscan_data.get("url", "")

        if provider.get("anyrun"):
            anyrun_data = provider["anyrun"] or {}
            anyrun_url = anyrun_data.get("url", "") or anyrun_data.get("result", "")

        with cols[0]:
            if talos_url:
                st.link_button("Open Talos", talos_url, type="primary")
        with cols[1]:
            if rdap_url:
                st.link_button("Open RDAP", rdap_url)
        with cols[2]:
            if urlscan_url:
                st.link_button("Open URLScan", urlscan_url)
        with cols[3]:
            if anyrun_url:
                st.link_button("Open ANY.RUN", anyrun_url)


# -------------------------------------------------------------------
# Sidebar Controls
# -------------------------------------------------------------------
with st.sidebar:
    st.header("Controls")
    uploaded = st.file_uploader("Upload .eml file", type=["eml"])
    st.checkbox("Show only Malicious IOC", key="show_only_malicious", value=False)
    run_analysis = st.button("▶ Run Analysis", type="primary")
    load_latest = st.button("📂 Load latest report from reports")

    st.markdown("---")
    st.markdown("### Find reports by Date/Time Range")
    # Date/time inputs default to now
    now_time = datetime.now().time().replace(microsecond=0)
    from_date = st.date_input("From Date", value=datetime.now().date(), key="from_date")
    from_time = st.time_input("From Time", value=now_time, key="from_time")
    to_date = st.date_input("To Date", value=datetime.now().date(), key="to_date")
    to_time = st.time_input("To Time", value=now_time, key="to_time")
    find_range = st.button("🔎 Find reports in range")

    st.markdown("---")
    st.markdown("### Analyze inbox by date")
    analyze_date = st.date_input("Analyze Date", value=datetime.now().date(), key="analyze_date")
    analyze_by_date = st.button("▶ Analyze inbox for date")

# -------------------------------------------------------------------
# Run Analysis
# -------------------------------------------------------------------
if uploaded is not None and run_analysis:
    os.makedirs("data", exist_ok=True)
    temp_path = "data/temp_uploaded.eml"
    with open(temp_path, "wb") as f:
        f.write(uploaded.getbuffer())

    st.session_state.uploaded_eml_path = temp_path
    st.session_state.last_uploaded_name = uploaded.name

    progress_bar = st.progress(0)
    with st.spinner("Analyzing email..."):
        progress_bar.progress(10)
        email_data = run_analysis_on_path(temp_path, force_reanalyze=False)
        progress_bar.progress(100)

    if not email_data:
        st.error("Analysis failed or email could not be parsed.")
        st.stop()

    st.success("Analysis complete.")
    progress_bar.empty()

if load_latest:
    path = get_latest_report_path()
    if not path:
        st.warning("No JSON report files found in the reports folder.")
    else:
        loaded = load_report_at_path(path)
        if not loaded and st.session_state.get("txt_report_path"):
            st.info("Latest report is a TXT file and has been selected for download.")
        elif loaded:
            st.success(f"Loaded latest JSON report: {os.path.basename(path)}")
        else:
            st.error("Failed to load the latest report.")

if 'find_range' in locals() and find_range:
    try:
        from_dt = datetime.combine(st.session_state.get("from_date"), st.session_state.get("from_time"))
        to_dt = datetime.combine(st.session_state.get("to_date"), st.session_state.get("to_time"))
    except Exception:
        st.error("Invalid date/time selection")
        from_dt = datetime.now()
        to_dt = datetime.now()

    if from_dt > to_dt:
        st.error("From datetime must be earlier than or equal to To datetime.")
    else:
        # Find all reports whose report timestamp falls in the selected range.
        reports_in_range = list_reports_in_range(from_dt, to_dt)
        if reports_in_range:
            st.success(f"Found {len(reports_in_range)} report(s) in the selected range.")
            report_rows = [
                {
                    "#": idx + 1,
                    "Filename": os.path.basename(path),
                    "Type": path.split('.')[-1].upper(),
                }
                for idx, path in enumerate(reports_in_range)
            ]
            st.table(pd.DataFrame(report_rows))

            # The user can choose among all matching reports.
            json_reports = [p for p in reports_in_range if p.lower().endswith(".json")]
            txt_reports = [p for p in reports_in_range if p.lower().endswith(".txt")]

            if json_reports:
                options = [os.path.basename(p) for p in json_reports]
                st.selectbox("Choose a JSON report to load", options=options, key="range_report_select")
                if st.button("Load selected report", key="load_range_report"):
                    chosen = json_reports[options.index(st.session_state.get("range_report_select"))]
                    loaded = load_report_at_path(chosen)
                    if loaded:
                        st.success(f"Loaded report: {os.path.basename(chosen)}")
                    else:
                        st.error("Failed to load selected report.")
            elif txt_reports:
                options = [os.path.basename(p) for p in txt_reports]
                st.selectbox("Choose a TXT report to reference", options=options, key="range_report_txt_select")
                if st.button("Select TXT report", key="load_range_txt_report"):
                    chosen = txt_reports[options.index(st.session_state.get("range_report_txt_select"))]
                    load_report_at_path(chosen)
                    st.info("TXT report selected for download; structured JSON is not available.")
        else:
            st.warning("No reports found in the selected range.")
            st.info("Searching processed EML files as a fallback...")

            processed = list_processed_eml_files()
            processed_in_range = []
            for p in processed:
                try:
                    mtime = datetime.fromtimestamp(os.path.getmtime(p))
                except Exception:
                    continue
                if from_dt <= mtime <= to_dt:
                    processed_in_range.append(p)

            if processed_in_range:
                st.info(f"Found {len(processed_in_range)} processed EML(s) in range.")
                opts = [os.path.basename(p) for p in processed_in_range]
                sel_eml = st.selectbox("Choose a processed EML", options=opts, key="processed_select")

                if st.button("Find reports for selected EML", key="find_reports_for_eml_btn"):
                    chosen_eml = processed_in_range[opts.index(st.session_state.get("processed_select"))]
                    eml_base = os.path.basename(chosen_eml)
                    # Search reports for matching eml_used metadata
                    matched_reports = []
                    ensure_reports_dir()
                    for f in os.listdir("reports"):
                        full = os.path.join("reports", f)
                        if not f.lower().endswith(".json"):
                            continue
                        try:
                            with open(full, "r", encoding="utf-8") as fh:
                                data = json.load(fh)
                        except Exception:
                            continue
                        eml_used = (data.get("email_metadata") or {}).get("eml_used", "") or ""
                        if eml_base in os.path.basename(eml_used):
                            matched_reports.append(full)

                    if matched_reports:
                        st.success(f"Found {len(matched_reports)} report(s) referencing {eml_base}.")
                        opts2 = [os.path.basename(p) for p in matched_reports]
                        sel2 = st.selectbox("Choose a report to load", options=opts2, key="found_report_select")
                        if st.button("Load chosen report", key="load_found_report_btn"):
                            chosen = matched_reports[opts2.index(st.session_state.get("found_report_select"))]
                            if load_report_at_path(chosen):
                                st.success("Loaded report from processed EML.")
                            else:
                                st.error("Failed to load the selected report.")
                    else:
                        st.info("No existing reports found for this processed EML. You can reanalyze it to regenerate reports.")
                        if st.button("Reanalyze selected EML", key="reanalyze_eml_btn"):
                            chosen_eml = processed_in_range[opts.index(st.session_state.get("processed_select"))]
                            with st.spinner("Reanalyzing selected processed EML..."):
                                new_data = run_analysis_on_path(chosen_eml, force_reanalyze=False)
                            if new_data:
                                st.success("Reanalysis complete and new report generated.")
                            else:
                                st.error("Reanalysis failed.")
            else:
                st.warning("No processed EML files found in the selected range. Processed history may be missing.")

if 'analyze_by_date' in locals() and analyze_by_date:
    try:
        target = st.session_state.get("analyze_date")
        with st.spinner(f"Analyzing inbox for {target}..."):
            count = analyze_inbox_for_date(datetime.combine(target, datetime.min.time()))

        if count == 0:
            st.info("No emails found for the selected date in the inbox.")
        else:
            st.success(f"Analyzed {count} email(s) for {target}.")
    except Exception as e:
        st.error(f"Failed to analyze inbox for date: {e}")


# -------------------------------------------------------------------
# Dashboard
# -------------------------------------------------------------------
if st.session_state.analysis_done and st.session_state.email_data:
    email_data = st.session_state.email_data

    # Top Summary
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Severity", email_data.get("email_severity", "Unknown"))
    c2.metric("Score", email_data.get("email_score", 0))
    c3.metric("Alert", (email_data.get("alert", {}) or {}).get("level", "Unknown"))
    c4.metric("Campaign Confidence", (email_data.get("campaign", {}) or {}).get("confidence", "Unknown"))

    # Email Overview
    st.markdown("## 📌 Email Overview")
    ov1, ov2 = st.columns(2)

    with ov1:
        st.write(f"**Subject:** {email_data.get('subject', '')}")
        st.write(f"**From:** {email_data.get('from', '')}")
        st.write(f"**To:** {email_data.get('to', '')}")

    with ov2:
        st.write(f"**File:** {st.session_state.last_uploaded_name or ''}")
        st.write(f"**Report:** {safe_report_time()}")
        
    tab_ioc, tab_att, tab_summary, tab_header, tab_raw, tab_lists = st.tabs(
        ["IOC Results", "Attachments", "Summary", "Header Details", "Raw / JSON", "Whitelist / Blocklist"]
    )

    # IOC Results
    with tab_ioc:
        st.subheader("IOC Results")

        ioc_df = build_ioc_df(email_data)
        if st.session_state.get("show_only_malicious", False) and not ioc_df.empty:
            ioc_df = ioc_df[ioc_df["Verdict"] == "Malicious"]

        display_columns = [
            "Type", "Value", "VT Score", "Verdict",
            "AbuseIPDB Score",
            "ANY.RUN Status", "ANY.RUN URL", "URLScan Result",
            "WHOIS Age (days)", "Registrar", "Talos Lookup", "RDAP Lookup",
            "Whitelisted", "Blocklisted"
        ]
        #
        display_df = ioc_df[display_columns] if not ioc_df.empty else ioc_df
        if not display_df.empty:
            st.markdown(render_ioc_html_table(display_df), unsafe_allow_html=True)
        else:
            st.info("No IOC results available.")

        st.markdown("### URL Wrapper Evidence")
        wrapper_df = build_url_wrapper_df(email_data)
        if not wrapper_df.empty:
            st.dataframe(wrapper_df, use_container_width=True, hide_index=True)
        else:
            st.info("No URL wrapper evidence found.")

        st.markdown("### IOC Detail Viewer")
        if not ioc_df.empty:
            selected_ioc_value = st.selectbox(
                "Choose an IOC for detailed OSINT view",
                options=ioc_df["Value"].tolist(),
                key="ioc_detail_select"
            )

            if st.button("🔎 Run IOC Details", key="run_ioc_detail"):
                show_ioc_detail(email_data, selected_ioc_value)

            if st.button("🔄 Force Reanalyze IOC", key="force_reanalyze_selected_ioc"):
                progress_bar = st.progress(0)
                with st.spinner("Reanalyzing selected IOC..."):
                    progress_bar.progress(20)
                    email_data = reanalyze_ioc_in_email_data(email_data, selected_ioc_value)
                    progress_bar.progress(100)

                st.session_state.email_data = email_data
                st.success("Selected IOC has been reanalyzed.")
                progress_bar.empty()
                show_ioc_detail(email_data, selected_ioc_value)
        else:
            st.info("No IOC results available.")

    # Attachments
    with tab_att:
        st.subheader("Attachments")
        att_df = build_attachment_df(email_data)
        st.dataframe(att_df, use_container_width=True, hide_index=True)

        if email_data.get("attachments"):
            st.markdown("### Attachment Sandbox Details")
            for att in email_data.get("attachments", []) or []:
                with st.expander(f"{att.get('filename', 'unknown')} ({att.get('sha256', '')})", expanded=False):
                    st.write(f"**Size:** {att.get('size', 0)} bytes")
                    vt_hash = att.get("vt_hash", {}) or {}
                    vt_upload = att.get("vt_upload", {}) or {}
                    anyrun = att.get("anyrun", {}) or {}
                    anyrun_report = att.get("anyrun_report", {}) or {}
                    talos = att.get("talos", {}) or {}

                    st.write(f"**SHA256:** {att.get('sha256', '')}")
                    st.write(f"**VT Hash Score:** {vt_hash.get('vt_malicious', 0)}")
                    st.write(f"**VT Status:** {vt_hash.get('vt_status', 'N/A')}")
                    st.write(f"**VT Upload Status:** {vt_upload.get('status', 'N/A')}")

                    st.write(f"**ANY.RUN Status:** {anyrun.get('status', 'N/A')}")
                    #if anyrun.get("analysis_id"):
                        #st.write(f"**ANY.RUN Analysis ID:** {anyrun.get('analysis_id')}")
                    if anyrun.get("url"):
                        st.markdown(f"**ANY.RUN URL:** [{anyrun.get('url')}]({anyrun.get('url')})")

                    if talos.get("portal_lookup"):
                        talos_link = talos.get("portal_lookup")
                        st.markdown(
                            f"<a href=\"{talos_link}\" target=\"_blank\"><button style=\"padding:8px 14px; border:none; background-color:#0078d4; color:white; border-radius:4px; cursor:pointer;\">Open Talos</button></a>",
                            unsafe_allow_html=True,
                        )

                    if anyrun_report:
                        st.markdown("#### ANY.RUN Retrieved Report")
                        st.json(anyrun_report)

    # Whitelist / Blocklist
    with tab_lists:
        st.subheader("Config: Whitelist and Blocklist")
        st.write("Review the configured whitelist and blocklist spreadsheets used by the analysis pipeline.")

        whitelist_df, whitelist_error = load_excel_file(WHITELIST_FILE)
        blocklist_df, blocklist_error = load_excel_file(BLOCKLIST_FILE)

        col1, col2 = st.columns(2)
        with col1:
            st.markdown("### Whitelist")
            if whitelist_error:
                st.error(f"Unable to load whitelist.xlsx: {whitelist_error}")
            elif whitelist_df is None or whitelist_df.empty:
                st.info("Whitelist file is empty or missing.")
            else:
                st.dataframe(whitelist_df, use_container_width=True)
                with st.expander("Download whitelist.xlsx"):
                    st.download_button(
                        label="Download whitelist.xlsx",
                        data=open(WHITELIST_FILE, "rb").read() if os.path.exists(WHITELIST_FILE) else b"",
                        file_name="whitelist.xlsx",
                        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    )
        with col2:
            st.markdown("### Blocklist")
            if blocklist_error:
                st.error(f"Unable to load blocklist.xlsx: {blocklist_error}")
            elif blocklist_df is None or blocklist_df.empty:
                st.info("Blocklist file is empty or missing.")
            else:
                st.dataframe(blocklist_df, use_container_width=True)
                with st.expander("Download blocklist.xlsx"):
                    st.download_button(
                        label="Download blocklist.xlsx",
                        data=open(BLOCKLIST_FILE, "rb").read() if os.path.exists(BLOCKLIST_FILE) else b"",
                        file_name="blocklist.xlsx",
                        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    )

    # Summary
    with tab_summary:
        st.subheader("🧠 Threat Summary")

        st.markdown("### IOC Observed")
        observed_df = build_ioc_observed_df(email_data)
        st.dataframe(observed_df, use_container_width=True, hide_index=True)

        st.markdown("### Domain WHOIS Summary")
        whois_summary_df = build_domain_whois_summary_df(email_data)
        if not whois_summary_df.empty:
            st.dataframe(whois_summary_df, use_container_width=True, hide_index=True)
        else:
            st.info("No WHOIS details available for domain IOCs in this analysis.")

        st.markdown("### 📌 Subject Analysis")
        st.dataframe(build_subject_analysis_df(email_data), use_container_width=True, hide_index=True)

        st.markdown("### 📄 Body Summary")
        st.dataframe(build_body_summary_df(email_data), use_container_width=True, hide_index=True)

        st.markdown("### 🧪 Campaign Summary")
        st.dataframe(build_campaign_summary_df(email_data), use_container_width=True, hide_index=True)

        st.markdown("### 🔎 OSINT Summary")
        osint_summary = email_data.get("osint_summary", {}) or {}
        st.write(f"Providers Seen: {', '.join(osint_summary.get('providers_seen', []) or []) or 'None'}")
        st.write(f"AbuseIPDB Hits: {osint_summary.get('abuseipdb_hits', 0)}")
        st.write(f"ANY.RUN Submissions: {osint_summary.get('anyrun_submissions', 0)}")
        st.write(f"URLScan Hits: {osint_summary.get('urlscan_hits', 0)}")

        st.markdown("### 🚨 Alert Summary")
        st.dataframe(build_alert_summary_df(email_data), use_container_width=True, hide_index=True)

    # Header Details
    with tab_header:
        st.subheader("Header Details")

        st.markdown("### 📨 Mismatch Checks")
        st.dataframe(build_mismatch_df(email_data), use_container_width=True, hide_index=True)

        st.markdown("### 🔐 Authentication Results")
        st.code(str(email_data.get("auth_results", "Not Found")), language="text")

        st.markdown("### 🌐 Received Hops")
        with st.expander("🌐 Received Header Analysis", expanded=True):
            normalized_hops = normalize_received_hops(email_data)

            hop_view_data = dict(email_data)
            email_data["received_hops"] = normalized_hops

            df = build_received_hops_df(email_data)

            if not df.empty:
                styled_df = df.style.apply(highlight_risk, axis=1)
                st.dataframe(styled_df, use_container_width=True)
            else:
                st.warning("No hop data available")

            render_received_hop_details(hop_view_data)
            #render_received_hop_details(email_data)

        st.markdown("### 🏷 Headers (Focus)")
        st.json(email_data.get("headers_focus", {}))

    # Raw / JSON + Downloads
    with tab_raw:
        
        file_col1, file_col2, file_col3 = st.columns(3)

        with file_col1:
            uploaded_path = st.session_state.get("uploaded_eml_path")
            if uploaded_path and os.path.exists(uploaded_path):
                st.download_button(
                    label="⬇ Download Uploaded EML",
                    data=read_file_bytes(uploaded_path),
                    file_name=os.path.basename(st.session_state.last_uploaded_name or "uploaded_email.eml"),
                    mime="message/rfc822",
                    key="download_uploaded_eml"
                )

        with file_col2:
            json_report_path = st.session_state.get("json_report_path")
            if json_report_path and os.path.exists(json_report_path):
                st.download_button(
                    label="⬇ Download JSON Report",
                    data=read_file_bytes(json_report_path),
                    file_name=os.path.basename(json_report_path),
                    mime="application/json",
                    key="download_json_report"
                )

        with file_col3:
            txt_report_path = st.session_state.get("txt_report_path")
            if txt_report_path and os.path.exists(txt_report_path):
                st.download_button(
                    label="⬇ Download TXT Report",
                    data=read_file_bytes(txt_report_path),
                    file_name=os.path.basename(txt_report_path),
                    mime="text/plain",
                    key="download_txt_report"
                )

        st.subheader("Full JSON Output")
        st.json(email_data)

elif uploaded is not None and not run_analysis:
    st.info("Upload complete. Click **Run Analysis** in the sidebar to start.")
else:
    st.info("Upload an .eml file from the sidebar and click **Run Analysis**.")