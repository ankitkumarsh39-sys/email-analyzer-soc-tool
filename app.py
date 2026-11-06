# app.py

import os
import json
import re
import importlib
# import requests
import html
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime
from urllib.parse import urlparse

from pathlib import Path

import pandas as pd
import streamlit as st
mail_reporter_module = importlib.import_module("email_analyzer.mail_reporter")
REPORTER_EXPORTS = (
    "MailReporter",
    "build_report_model",
    "format_resolved_ips",
    "format_vt_malicious",
    "response_consistency_warnings",
)
if not all(hasattr(mail_reporter_module, name) for name in REPORTER_EXPORTS):
    mail_reporter_module = importlib.reload(mail_reporter_module)

MailReporter = mail_reporter_module.MailReporter
build_report_model = mail_reporter_module.build_report_model
format_resolved_ips = mail_reporter_module.format_resolved_ips
format_vt_malicious = mail_reporter_module.format_vt_malicious
response_consistency_warnings = mail_reporter_module.response_consistency_warnings

from email_analyzer.analyzer import analyze_email, reanalyze_ioc_in_email_data
from email.utils import parsedate_to_datetime
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
    "word_report_path": None,
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

    # ============================================================
    # Ensure latest analyst comment goes into downloaded report
    #
    # Purpose:
    # Streamlit text areas update interactively. Before report
    # download, we copy the latest comment into email_data.
    #
    # Input:
    # st.session_state["analyst_comment"]
    #
    # Output:
    # email_data["analyst_comment"]
    # ============================================================

    if email_data is not None:

        email_data["analyst_comment"] = st.session_state.get(
            "analyst_comment",
            ""
        )

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
def render_ioc_html_table(df: pd.DataFrame) -> str:
    if df.empty:
        return ""
    header_cells = "".join(
        f'<th style="padding:8px 10px; text-align:left; background:black; position:sticky; top:0; z-index:2; border-bottom:1px solid #d1d5db;">{html.escape(str(col))}</th>'
        for col in df.columns
    )
    rows_html = []
    for _, row in df.iterrows():
        cells = []
        for col in df.columns:
            value = row[col]
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

#---------------------------------------------------------------------------------------
def build_ioc_df(email_data: dict) -> pd.DataFrame:
    """
    Main IOC Results table with integrated OSINT summary fields.
    """
    rows = []
    report_model = build_report_model(email_data)
    for item in report_model.get("ioc_scoring", []) or []:
        provider = item.get("provider_context", {}) or {}
        whois = provider.get("whois", {}) or {}
        abuseipdb = provider.get("abuseipdb", {}) or {}
        talos = provider.get("talos", {}) or {}
        rdap = provider.get("rdap", {}) or {}
        urlscan = provider.get("urlscan", {}) or {}

        rows.append({
            "Type": item.get("ioc_type", "").upper(),
            "Value": item.get("normalized", ""),
            "VT Score": format_vt_malicious(item.get("vt_malicious"), item.get("vt_status")),
            "Verdict": item.get("category", ""),
            "AbuseIPDB Score": abuseipdb.get("abuse_score", ""),
            "URLScan Status": urlscan.get("status", "Unknown"),
            "WHOIS Age (days)": whois.get("age_days", ""),
            "Registrar": whois.get("registrar", ""),
            "Talos Status": talos.get("status", "Unknown"),
            "RDAP Status": rdap.get("status", "Unknown"),
            "Whitelisted": item.get("is_whitelisted", False),
            "Blocklisted": item.get("is_blocklisted", False),
        })
    
    return pd.DataFrame(rows)


def build_intelligence_links_df(email_data: dict) -> pd.DataFrame:
    report_model = build_report_model(email_data)
    rows = []
    for item in report_model.get("intelligence_links", []) or []:
        rows.append({
            "Type": item["type"].upper(),
            "Indicator": item["indicator"],
            **(item.get("links", {}) or {}),
        })
    return pd.DataFrame(
        rows,
        columns=["Type", "Indicator", "VirusTotal", "Talos", "RDAP", "WHOIS", "URLScan", "AbuseIPDB"],
    )

#------------------------------------------------------------------------------------------------------

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

#---------------------------------------------------------------------------------------------------------

# This code is used to build the attachment DataFrame for the email analysis dashboard.

def build_attachment_df(email_data: dict) -> pd.DataFrame:
    rows = []
    for att in email_data.get("attachments", []) or []:
        vt_hash = att.get("vt_hash", {}) or {}
        vt_upload = att.get("vt_upload", {}) or {}
        talos = att.get("talos", {}) or {}
        rows.append({
            "Filename": att.get("filename", ""),
            "Size": att.get("size", 0),
            "SHA256": att.get("sha256", ""),
            "VT Hash Score": format_vt_malicious(vt_hash.get("vt_malicious"), vt_hash.get("vt_status")),
            "VT Status": vt_hash.get("vt_status", ""),
            "VT Upload": vt_upload.get("status", ""),
            "Talos Status": talos.get("status", "Unknown") if isinstance(talos, dict) else "Unknown",
        })
    return pd.DataFrame(rows)

#----------------------------------------------------------------------------------------------------------------

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

#-------------------------------------------------------------------------------------------------------------------

#-------------------------------------------------------------------------------------------------------------------

def build_domain_whois_summary_df(email_data: dict) -> pd.DataFrame:
    """
    Merged WHOIS summary for sender and IOC indicators.
    """
    rows = [
        {
            "Type": item["type"].upper(),
            "Indicator": item["indicator"],
            "WHOIS status": item.get("status", "Unknown"),
            "WHOIS Age (days)": item.get("age_days", ""),
            "Registrar": item.get("registrar", ""),
            "Expires": item.get("expires", ""),
            "Resolved IPs": format_resolved_ips(item.get("resolved_ips")),
        }
        for item in build_report_model(email_data).get("whois_rows", [])
    ]
    return pd.DataFrame(rows)

#-------------------------------------------------------------------------------------------------------------------
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

#-------------------------------------------------------------------------------------------------------------------

def normalize_received_hops(email_data: dict):
    return build_report_model(email_data).get("received_hops", [])

#-------------------------------------------------------------------------------------------------------------------

def build_received_hops_df(email_data: dict) -> pd.DataFrame:
    hops = normalize_received_hops(email_data)
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

#-------------------------------------------------------------------------------------------------------------------

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

#-------------------------------------------------------------------------------------------------------------------

def highlight_risk(row):
    if "🚨" in str(row.get("Risk", "")):
        return ["background-color: #ffcccc"] * len(row)  # RED
    elif "⚠️" in str(row.get("Risk", "")):
        return ["background-color: #fff3cd"] * len(row)  # YELLOW
    else:
        return [""] * len(row)
    
#-------------------------------------------------------------------------------------------------------------------

def render_received_hop_details(email_data: dict):
    """
    Readable per-hop details below the table.
    """
    hops = normalize_received_hops(email_data)

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

#----------------------------------------------------------------------------------------------------------

def build_subject_analysis_df(email_data: dict) -> pd.DataFrame:
    subj = email_data.get("subject_analysis", {}) or {}
    rows = [{"Field": "Subject Severity", "Value": subj.get("subject_severity", "Unknown")}]
    for flag in subj.get("subject_flags", []) or []:
        rows.append({"Field": "Indicator", "Value": flag})
    return pd.DataFrame(rows)

#----------------------------------------------------------------------------------------------------------

def build_body_summary_df(email_data: dict) -> pd.DataFrame:
    body = email_data.get("body_stats", {}) or {}
    rows = [
        {"Metric": "Plain Length", "Value": body.get("plain_length", 0)},
        {"Metric": "HTML Length", "Value": body.get("html_length", 0)},
        {"Metric": "Hidden HTML Elements", "Value": body.get("hidden_html_count", 0)},
    ]
    return pd.DataFrame(rows)

#----------------------------------------------------------------------------------------------------------

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
    df = pd.DataFrame(rows)
    if not df.empty:
        df["Value"] = df["Value"].map(str)
    return df

#----------------------------------------------------------------------------------------------------------

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

#----------------------------------------------------------------------------------------------------------

def build_alert_summary_df(email_data: dict) -> pd.DataFrame:
    alert = email_data.get("alert", {}) or {}
    rows = [{"Field": "Level", "Value": alert.get("level", "Unknown")}]

    for reason in alert.get("reasons", []) or []:
        rows.append({"Field": "Reason", "Value": reason})

    for action in alert.get("recommended_actions", []) or []:
        rows.append({"Field": "Action", "Value": action})

    return pd.DataFrame(rows)

#--------------------------------------------------------------------------------------------------------------

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
            "Details": f"{urlscan.get('result_count', 0)} matches"
        })

    # Talos
    if provider.get("talos"):
        talos_data = provider["talos"]
        if isinstance(talos_data, dict):
            rows.append({
                "Source": "Talos",
                "Key Info": "Status",
                "Details": talos_data.get("status", "Unknown")
            })
        else:
            rows.append({
                "Source": "Talos",
                "Key Info": "Status",
                "Details": "Unknown"
            })

    # RDAP
    if provider.get("rdap"):
        rdap_data = provider["rdap"]
        if isinstance(rdap_data, dict):
            rows.append({
                "Source": "RDAP",
                "Key Info": "Status",
                "Details": rdap_data.get("status", "Unknown")
            })
        else:
            rows.append({
                "Source": "RDAP",
                "Key Info": "Status",
                "Details": "Unknown"
            })

    return pd.DataFrame(rows)

#-------------------------------------------------------------------------------------------------------------

def show_ioc_detail(email_data: dict, selected_value: str):
    selected = None
    for item in build_report_model(email_data).get("ioc_scoring", []) or []:
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
        st.write(f"**VT Score:** {format_vt_malicious(selected.get('vt_malicious'), selected.get('vt_status'))}")
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
        whois_df["Value"] = whois_df["Value"].map(str)
        st.dataframe(whois_df, width="stretch", hide_index=True)

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
        abuse_df = pd.DataFrame(abuse_rows)
        abuse_df["Value"] = abuse_df["Value"].map(str)
        st.dataframe(abuse_df, width="stretch", hide_index=True)

    reasons = selected.get("reason", []) or []
    if reasons:
        st.markdown("### 📊 Reasons")
        for reason in reasons:
            st.write(f"- {reason}")

    with st.expander("🌐 WHOIS / RDAP / Talos / Reputation", expanded=True):
        osint_df = build_osint_df(provider)
        if not osint_df.empty:
            st.dataframe(osint_df, width="stretch", hide_index=True)
        else:
            st.info("No OSINT data available for this IOC.")

        st.caption("Use the shared Intelligence Links table in the Summary tab for lookups.")
# -------------------------------------------------------------------
# Sidebar Controls
# -------------------------------------------------------------------
with st.sidebar:
    st.header("Controls")
    uploaded = st.file_uploader("Upload .eml file", type=["eml"])
    st.checkbox("Show only Malicious IOC", key="show_only_malicious", value=False)
    run_analysis = st.button("▶ Run Analysis", type="primary")
    # Reanalysis is available only after an EML file has been saved for analysis.
    uploaded_eml_path = st.session_state.get("uploaded_eml_path")
    reanalyze_whole_email = st.button(
        "🔄 Reanalyze Whole Email",
        key="reanalyze_whole_email",
        disabled=not uploaded_eml_path or not os.path.isfile(uploaded_eml_path),
    )
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

if reanalyze_whole_email:
    # Reuse the saved EML and existing analysis flow to refresh all results and reports.
    eml_path = st.session_state.get("uploaded_eml_path")
    if not eml_path or not os.path.isfile(eml_path):
        st.error("The uploaded EML file is no longer available. Upload it again to reanalyze.")
    else:
        progress_bar = st.progress(0)
        try:
            with st.spinner("Reanalyzing the whole email..."):
                progress_bar.progress(10)
                email_data = run_analysis_on_path(eml_path, force_reanalyze=True)
                progress_bar.progress(100)

            if email_data:
                st.success("Whole-email reanalysis complete. Analysis data and TXT/JSON reports were refreshed.")
            else:
                st.error("Whole-email reanalysis failed or the EML could not be parsed.")
        except Exception as exc:
            st.error(f"Whole-email reanalysis failed: {exc}")
        finally:
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
    report_model = build_report_model(email_data)

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
        
    tab_summary, tab_ioc, tab_att, tab_header, tab_raw, tab_comment, tab_response, tab_lists = st.tabs(
        ["📊 Summary", "🔍 IOC Results", "📎 Attachments", "📨 Header Details", "📄 Raw / JSON", "📝 Analyst Comments", "🚨 Response Actions", "✅ Whitelist / Blocklist"]
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
            "URLScan Status",
            "WHOIS Age (days)", "Registrar", "Talos Status", "RDAP Status",
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
            st.dataframe(wrapper_df, width="stretch", hide_index=True)
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
        st.dataframe(att_df, width="stretch", hide_index=True)

        if email_data.get("attachments"):
            st.markdown("### Attachment Details")
            for att in email_data.get("attachments", []) or []:
                with st.expander(f"{att.get('filename', 'unknown')} ({att.get('sha256', '')})", expanded=False):
                    st.write(f"**Size:** {att.get('size', 0)} bytes")
                    vt_hash = att.get("vt_hash", {}) or {}
                    vt_upload = att.get("vt_upload", {}) or {}
                    talos = att.get("talos", {}) or {}

                    st.write(f"**SHA256:** {att.get('sha256', '')}")
                    st.write(f"**VT Hash Score:** {format_vt_malicious(vt_hash.get('vt_malicious'), vt_hash.get('vt_status'))}")
                    st.write(f"**VT Status:** {vt_hash.get('vt_status', 'N/A')}")
                    st.write(f"**VT Upload Status:** {vt_upload.get('status', 'N/A')}")
                    st.write(f"**Talos Status:** {talos.get('status', 'Unknown') if isinstance(talos, dict) else 'Unknown'}")

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
                st.dataframe(whitelist_df, width="stretch")
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
                st.dataframe(blocklist_df, width="stretch")
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

        sender_intelligence = report_model.get("sender_intelligence", {}) or {}
        st.markdown("### Sender Intelligence")
        risk_col, verdict_col = st.columns(2)
        risk_col.metric("Sender Risk Score", sender_intelligence.get("risk_score", 0))
        verdict_col.metric("Sender Verdict", sender_intelligence.get("verdict", "Needs Review"))
        authentication = sender_intelligence.get("authentication", {}) or {}
        auth_text = str(email_data.get("auth_results", "") or "")
        dkim_match = re.search(r"\bdkim\s*=\s*([a-z]+)", auth_text, re.IGNORECASE)
        dkim_status = dkim_match.group(1).lower() if dkim_match else "unknown"
        st.write(
            f"SPF authentication: {authentication.get('spf', 'unknown')} | "
            f"DKIM authentication: {dkim_status} | "
            f"DMARC authentication: {authentication.get('dmarc', 'unknown')}"
        )
        for reason in sender_intelligence.get("reasons", []) or []:
            st.write(f"- {reason}")

        domain_rows = []
        for domain in sender_intelligence.get("domains", []) or []:
            dns = domain.get("dns", {}) or {}
            talos = domain.get("talos", {}) or {}
            urlscan = domain.get("urlscan_search", {}) or {}
            resolved_intel = domain.get("resolved_ip_intelligence", []) or []
            domain_rows.append({
                "Header(s)": ", ".join(domain.get("headers", []) or []),
                "Domain": domain.get("domain", ""),
                "SPF": ", ".join(domain.get("spf_records", []) or []),
                "SPF status": domain.get("spf_status", "not checked"),
                "DMARC": ", ".join(domain.get("dmarc_records", []) or []),
                "DMARC status": domain.get("dmarc_status", "not checked"),
                "DNS TXT": ", ".join((dns.get("txt", {}) or {}).get("records", []) or []),
                "DNS TXT status": (dns.get("txt", {}) or {}).get("status", "not checked"),
                "Resolved IPs": format_resolved_ips(domain.get("resolved_ips")),
                "Resolved ASN / Hosting": "; ".join(
                    f"{(item.get('abuseipdb', {}) or {}).get('asn', '')} / "
                    f"{(item.get('abuseipdb', {}) or {}).get('isp', '')}"
                    for item in resolved_intel
                ),
                "Resolved IP URLScan matches": ", ".join(
                    str((item.get("urlscan_search", {}) or {}).get("result_count", 0))
                    for item in resolved_intel
                ),
                "MX": ", ".join((dns.get("mx", {}) or {}).get("records", []) or []),
                "VT": (domain.get("virustotal", {}) or {}).get("status", ""),
                "Risk score": domain.get("risk_score", 0),
                "Talos status": talos.get("status", "Unknown"),
                "URLScan matches": urlscan.get("result_count", 0),
                "URLScan status": urlscan.get("status", "Unknown"),
                "Whitelisted": domain.get("whitelisted", False),
                "Blocklisted": domain.get("blocklisted", False),
            })
        if domain_rows:
            st.dataframe(pd.DataFrame(domain_rows), width="stretch", hide_index=True)

        for domain in sender_intelligence.get("domains", []) or []:
            domain_name = domain.get("domain", "")
            dns = domain.get("dns", {}) or {}
            talos = domain.get("talos", {}) or {}
            urlscan = domain.get("urlscan_search", {}) or {}
            with st.expander(f"Domain details: {domain_name or 'unknown'}"):
                st.write(f"Header role(s): {', '.join(domain.get('headers', []) or []) or 'N/A'}")
                st.write(f"Address(es): {domain.get('addresses', {}) or 'N/A'}")
                st.write(f"SPF ({domain.get('spf_status', 'unknown')}): {', '.join(domain.get('spf_records', []) or []) or 'N/A'}")
                st.write(f"DMARC DNS ({domain.get('dmarc_status', 'unknown')}): {', '.join(domain.get('dmarc_records', []) or []) or 'N/A'}")
                st.write(
                    "DNS: "
                    f"A={', '.join((dns.get('a', {}) or {}).get('records', []) or []) or 'N/A'}; "
                    f"AAAA={', '.join((dns.get('aaaa', {}) or {}).get('records', []) or []) or 'N/A'}; "
                    f"MX={', '.join((dns.get('mx', {}) or {}).get('records', []) or []) or 'N/A'}; "
                    f"TXT={', '.join((dns.get('txt', {}) or {}).get('records', []) or []) or 'N/A'}"
                )
                st.write(
                    f"VirusTotal: {(domain.get('virustotal', {}) or {}).get('status', 'N/A')} "
                    f"({format_vt_malicious((domain.get('virustotal', {}) or {}).get('malicious'), (domain.get('virustotal', {}) or {}).get('status'))} malicious)"
                )
                st.write(
                    f"Talos: {talos.get('status', 'Unknown')} | "
                    f"URLScan: {urlscan.get('status', 'Unknown')} "
                    f"({urlscan.get('result_count', 0)} matches)"
                )
                st.write(f"Risk score: {domain.get('risk_score', 0)}")

                for resolved_ip in domain.get("resolved_ip_intelligence", []) or []:
                    abuse = resolved_ip.get("abuseipdb", {}) or {}
                    with st.container(border=True):
                        st.write(f"Resolved IP: {format_resolved_ips(resolved_ip.get('ip'))}")
                        st.write(
                            f"VirusTotal: {(resolved_ip.get('virustotal', {}) or {}).get('status', 'N/A')} | "
                            f"AbuseIPDB: {abuse.get('status', 'N/A')} "
                            f"(score {abuse.get('abuse_score', 'N/A')}) | "
                            f"ASN: {abuse.get('asn', 'N/A')} | Hosting / ISP: {abuse.get('isp', 'N/A')}"
                        )
                        resolved_urlscan = resolved_ip.get("urlscan_search", {}) or {}
                        resolved_talos = resolved_ip.get("talos", {}) or {}
                        st.write(
                            f"Talos: {resolved_talos.get('status', 'Lookup available' if resolved_talos.get('portal_lookup') else 'N/A')} | "
                            f"URLScan: {resolved_urlscan.get('status', 'N/A')} "
                            f"({resolved_urlscan.get('result_count', 0)} matches)"
                        )
                        st.write(f"Risk score: {resolved_ip.get('risk_score', 0)}")
                        for reason in resolved_ip.get("reasons", []) or []:
                            st.write(f"- {reason}")

        ip_rows = []
        for sender_ip in sender_intelligence.get("ips", []) or []:
            abuse = sender_ip.get("abuseipdb", {}) or {}
            talos = sender_ip.get("talos", {}) or {}
            urlscan = sender_ip.get("urlscan_search", {}) or {}
            ip_rows.append({
                "Sender IP": sender_ip.get("ip", ""),
                "Source header(s)": ", ".join(sender_ip.get("sources", []) or []),
                "VT": (sender_ip.get("virustotal", {}) or {}).get("status", ""),
                "AbuseIPDB": abuse.get("abuse_score", ""),
                "AbuseIPDB status": abuse.get("status", "No result"),
                "ASN": abuse.get("asn", ""),
                "Hosting / ISP": abuse.get("isp", ""),
                "Risk score": sender_ip.get("risk_score", 0),
                "Talos status": talos.get("status", "Unknown"),
                "URLScan matches": urlscan.get("result_count", 0),
                "URLScan status": urlscan.get("status", "Unknown"),
                "Whitelisted": sender_ip.get("whitelisted", False),
                "Blocklisted": sender_ip.get("blocklisted", False),
            })
        if ip_rows:
            st.dataframe(pd.DataFrame(ip_rows), width="stretch", hide_index=True)
            for sender_ip in sender_intelligence.get("ips", []) or []:
                with st.expander(f"IP details: {sender_ip.get('ip', 'unknown')}"):
                    abuse = sender_ip.get("abuseipdb", {}) or {}
                    talos = sender_ip.get("talos", {}) or {}
                    urlscan = sender_ip.get("urlscan_search", {}) or {}
                    st.write(f"Source header(s): {', '.join(sender_ip.get('sources', []) or []) or 'N/A'}")
                    st.write(
                        f"VirusTotal: {(sender_ip.get('virustotal', {}) or {}).get('status', 'N/A')} "
                        f"({format_vt_malicious((sender_ip.get('virustotal', {}) or {}).get('malicious'), (sender_ip.get('virustotal', {}) or {}).get('status'))} malicious)"
                    )
                    st.write(
                        f"AbuseIPDB: {abuse.get('status', 'N/A')} "
                        f"(score {abuse.get('abuse_score', 'N/A')}) | "
                        f"ASN: {abuse.get('asn', 'N/A')} | Hosting / ISP: {abuse.get('isp', 'N/A')}"
                    )
                    st.write(
                        f"Talos: {talos.get('status', 'Unknown')} | "
                        f"URLScan: {urlscan.get('status', 'Unknown')} "
                        f"({urlscan.get('result_count', 0)} matches)"
                    )
                    st.write(f"Risk score: {sender_ip.get('risk_score', 0)}")
        if not domain_rows and not ip_rows:
            st.info("No sender domains or IP addresses were available for enrichment.")

        st.markdown("### Intelligence Links")
        intelligence_links_df = build_intelligence_links_df(report_model)
        if not intelligence_links_df.empty:
            st.dataframe(
                intelligence_links_df,
                width="stretch",
                hide_index=True,
                column_config={
                    name: st.column_config.LinkColumn(name, display_text="Open")
                    for name in ("VirusTotal", "Talos", "RDAP", "WHOIS", "URLScan", "AbuseIPDB")
                },
            )
        else:
            st.info("No intelligence lookup links are available.")

        st.markdown("### IOC Observed")
        observed_df = build_ioc_observed_df(email_data)
        st.dataframe(observed_df, width="stretch", hide_index=True)

        st.markdown("### Domain WHOIS Summary")
        whois_summary_df = build_domain_whois_summary_df(report_model)
        if not whois_summary_df.empty:
            st.dataframe(whois_summary_df, width="stretch", hide_index=True)
        else:
            st.info("No WHOIS details available for domain IOCs in this analysis.")

        st.markdown("### 📌 Subject Analysis")
        st.dataframe(build_subject_analysis_df(email_data), width="stretch", hide_index=True)

        st.markdown("### 📄 Body Summary")
        st.dataframe(build_body_summary_df(email_data), width="stretch", hide_index=True)

        st.markdown("### 🧪 Campaign Summary")
        st.dataframe(build_campaign_summary_df(email_data), width="stretch", hide_index=True)

        st.markdown("### 🔎 OSINT Summary")
        osint_summary = email_data.get("osint_summary", {}) or {}
        st.write(f"Providers Seen: {', '.join(osint_summary.get('providers_seen', []) or []) or 'None'}")
        st.write(f"AbuseIPDB Hits: {osint_summary.get('abuseipdb_hits', 0)}")
        st.write(f"URLScan Hits: {osint_summary.get('urlscan_hits', 0)}")

        st.markdown("### 🚨 Alert Summary")
        st.dataframe(build_alert_summary_df(email_data), width="stretch", hide_index=True)

# Header Details
    with tab_header:
        st.subheader("Header Details")

        st.markdown("### 📨 Mismatch Checks")
        st.dataframe(build_mismatch_df(email_data), width="stretch", hide_index=True)

        st.markdown("### 🔐 Authentication Results")
        st.code(str(email_data.get("auth_results", "Not Found")), language="text")

        st.markdown("### 🌐 Received Hops")
        with st.expander("🌐 Received Header Analysis", expanded=True):
            hop_view_data = dict(email_data)
            hop_view_data["received_hops"] = report_model["received_hops"]
            df = build_received_hops_df(hop_view_data)

            if not df.empty:
                styled_df = df.style.apply(highlight_risk, axis=1)
                st.dataframe(styled_df, width="stretch")
            else:
                st.warning("No hop data available")

            render_received_hop_details(hop_view_data)
            #render_received_hop_details(email_data)

        st.markdown("### 🏷 Headers (Focus)")
        st.json(email_data.get("headers_focus", {}))

    # COMMENTs

    #---------------------------------------------------------------------------
    # Allow the SOC Analyst to Write investigation notes.
    # 
    # Input:
    # Analyst types a free-text comment in the UI.
    # 
    # Output:
    # The comment is stored inside email_data so it can appear in:
    # - UI
    # - TXT report
    # - JSON report
    # 
    # Layman explanation:
    # This gives the analyst a place to write their conclusion, extra notes, escalation details, or response actions.

        
    with tab_comment:

        st.markdown("## 📝 Analyst Comment")
        analyst_comment = st.text_area(
            "Analyst Comment", 
            value=st.session_state.get("analyst_comment", ""),
            height=180,
            placeholder=(
                "Example: Email appears suspicious due to URL wrapper, "
                "Brand impersonation, and recovered login URL. "
                "Recommend blocking final IOC URL and searching for similar messages. "
            )
        )

        # Store comment in Sreamlit session so it survives UI refreshes
        st.session_state["analyst_comment"] = analyst_comment

        # Store comment in eamil_data so reporter can use it 
        if email_data is not None:
            email_data["analyst_comment"] = analyst_comment

        if analyst_comment.strip():

            with st.container(border=True):
                st.markdown("### 🧾 Comment Preview")

                st.info(
                    analyst_comment
                )
        else:
            st.warning(
                "No analyst comment added yet."
            )
    #-----------------------------------------------------------------------------

    # Final Comments

    with tab_response:

            st.markdown("## 📝 Analyst Investigation")

            finding = st.text_area(
                "Finding",
                value=st.session_state.get(
                    "finding",
                    ""
                ),
                height=100
            )

            action_taken = st.text_area(
                "Action Taken",
                value=st.session_state.get(
                    "action_taken",
                    ""
                ),
                height=100
            )

            recommendation = st.text_area(
                "Recommendation",
                value=st.session_state.get(
                    "recommendation",
                    ""
                ),
                height=100
            )

            final_verdict = st.selectbox(
                "Final Analyst Verdict",
                [
                    "Benign",
                    "Suspicious",
                    "Phishing",
                    "Malicious",
                    "Needs Further Investigation",
                    "No Threat Observed"
                ]
            )

            # Save all fields
            st.session_state["finding"] = finding
            st.session_state["action_taken"] = action_taken
            st.session_state["recommendation"] = recommendation
            st.session_state["final_verdict"] = final_verdict

            if st.session_state.get("email_data"):

                st.session_state.email_data[
                    "analyst_comments"
                ] = {
                    "finding": finding,
                    "action_taken": action_taken,
                    "recommendation": recommendation,
                    "final_verdict": final_verdict
                }

    #----------------------------------------------------------------------------------
            st.markdown("---")

            block_domain = st.checkbox("Block Domain", key="block_domain")
            block_url = st.checkbox("Block URL", key="block_url")
            block_sender = st.checkbox("Block Sender", key="block_sender")
            escalate_tier2 = st.checkbox("Escalate to Tire 2", key="escalate_tier2")
            search_similar = st.checkbox("Search Similar Emails", key="search_similar")

            response_notes = st.text_area("Response Notes", height=150)

            proposed_response_actions = {
                "finding": finding,
                "action_taken": action_taken,
                "recommendation": recommendation,
                "final_verdict": final_verdict,
                "block_domain": block_domain,
                "block_url": block_url,
                "block_sender": block_sender,
                "escalate_tier2": escalate_tier2,
                "search_similar": search_similar,
                "response_notes": response_notes,
            }
            proposed_email_data = dict(st.session_state.get("email_data") or {})
            proposed_email_data["response_actions"] = proposed_response_actions
            consistency_warnings = response_consistency_warnings(proposed_email_data)
            for warning in consistency_warnings:
                st.warning(warning)
            consistency_confirmed = False
            if consistency_warnings:
                consistency_confirmed = st.checkbox(
                    "I reviewed the consistency warning and want to keep this verdict.",
                    key="confirm_verdict_consistency",
                )

            if st.button("✅ Submit Final Investigation", key="submit_final_investigation"):
                final_email_data = st.session_state.get("email_data")
                if not final_email_data:
                    st.error("No email analysis is loaded to submit.")
                elif consistency_warnings and not consistency_confirmed:
                    st.error("Review and confirm the consistency warning before submitting.")
                else:
                    final_email_data["analyst_comment"] = st.session_state.get("analyst_comment", "")
                    final_email_data["response_actions"] = {
                        "finding": finding,
                        "action_taken": action_taken,
                        "recommendation": recommendation,
                        "final_verdict": final_verdict,
                        "block_domain": block_domain,
                        "block_url": block_url,
                        "block_sender": block_sender,
                        "escalate_tier2": escalate_tier2,
                        "search_similar": search_similar,
                        "response_notes": response_notes,
                        "submitted_time": datetime.now().astimezone().isoformat(timespec="seconds"),
                    }
                    final_email_data["investigation_submitted"] = True
                    final_email_data["submitted_time"] = final_email_data["response_actions"]["submitted_time"]
                    st.session_state.email_data = final_email_data

                    # Create final reports from saved data without running analysis again.
                    ensure_reports_dir()
                    final_reporter = MailReporter(output_dir="reports")
                    st.session_state.txt_report_path = final_reporter.generate_text_report(final_email_data)
                    st.session_state.json_report_path = final_reporter.generate_json_report(final_email_data)
                    word_reporter = final_reporter
                    if not callable(getattr(word_reporter, "generate_word_report", None)):
                        # Refresh an older reporter class kept in memory by Streamlit.
                        mail_reporter_module = importlib.reload(mail_reporter_module)
                        word_reporter = mail_reporter_module.MailReporter(output_dir="reports")
                    st.session_state.word_report_path = word_reporter.generate_word_report(final_email_data)
                    st.success("Investigation submitted and final reports generated successfully.")

            current_email_data = st.session_state.get("email_data") or {}
            if current_email_data.get("investigation_submitted"):
                final_txt_path = st.session_state.get("txt_report_path")
                final_json_path = st.session_state.get("json_report_path")
                final_word_path = st.session_state.get("word_report_path")
                if final_txt_path and os.path.exists(final_txt_path):
                    st.download_button(
                        label="📄 Download Final TXT",
                        data=read_file_bytes(final_txt_path),
                        file_name=os.path.basename(final_txt_path),
                        mime="text/plain",
                        key="download_final_txt",
                    )
                if final_json_path and os.path.exists(final_json_path):
                    st.download_button(
                        label="📊 Download Final JSON",
                        data=read_file_bytes(final_json_path),
                        file_name=os.path.basename(final_json_path),
                        mime="application/json",
                        key="download_final_json",
                    )
                if final_word_path and os.path.exists(final_word_path):
                    st.download_button(
                        label="📘 Download Final Word Report",
                        data=read_file_bytes(final_word_path),
                        file_name=os.path.basename(final_word_path),
                        mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                        key="download_final_word",
                    )


#---------------------------------------------------------------------------
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
                    label="📄 Downloadable Report",
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
