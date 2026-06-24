# app.py
import os
import json
import re
# import requests
# import ipaddress
import ast
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime

from pathlib import Path

import pandas as pd
import streamlit as st
from email_analyzer.analyzer import analyze_email
from email.utils import parsedate_to_datetime

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


def ensure_reports_dir() -> None:
    os.makedirs("reports", exist_ok=True)


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


# -------------------------------------------------------------------
# Data Builders
# -------------------------------------------------------------------
def build_ioc_df(email_data: dict) -> pd.DataFrame:
    """
    Main IOC Results table.
    """
    rows = []
    for item in email_data.get("ioc_scoring", []) or []:
        provider = item.get("provider_context", {}) or {}
        whois = provider.get("whois", {}) or {}

        rows.append({
            "Type": item.get("ioc_type", "").upper(),
            "Value": item.get("normalized", ""),
            "VT Score": item.get("vt_malicious", 0),
            "Final Score": item.get("final_score", 0),
            "Verdict": item.get("category", ""),
            "WHOIS Age (days)": whois.get("age_days", ""),
            "Registrar": whois.get("registrar", ""),
            "Whitelisted": item.get("is_whitelisted", False),
            "Blocklisted": item.get("is_blocklisted", False),
        })
    return pd.DataFrame(rows)


def build_attachment_df(email_data: dict) -> pd.DataFrame:
    rows = []
    for att in email_data.get("attachments", []) or []:
        vt_hash = att.get("vt_hash", {}) or {}
        vt_upload = att.get("vt_upload", {}) or {}
        rows.append({
            "Filename": att.get("filename", ""),
            "Size": att.get("size", 0),
            "SHA256": att.get("sha256", ""),
            "VT Hash Score": vt_hash.get("vt_malicious", 0),
            "VT Status": vt_hash.get("vt_status", ""),
            "VT Upload": vt_upload.get("status", ""),
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

    st.markdown("### Received Hop Details")
    for idx, hop in enumerate(hops, start=1):
        with st.expander(f"Hop {idx}", expanded=False):
            if isinstance(hop, dict):
                st.write(f"**From:** {hop.get('from', '')}")
                st.write(f"**By:** {hop.get('by', '')}")
                st.write(f"**With:** {hop.get('with', '')}")
                st.write(f"**Date:** {hop.get('date', '')}")

                date_info = format_hop_date(hop.get("date", ""))
                st.write(f"**Date UTC:** {date_info['utc']}")
                st.write(f"**Date IST:** {date_info['ist']}")

                if hop.get("delay") is not None:
                    st.write(f"**Delay:** {hop.get('delay', '')}")
            else:
                st.code(str(hop), language="text")


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
        st.write(f"**Final Score:** {selected.get('final_score', 0)}")
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
            urlscan_url = urlscan_data.get("result", "") or urlscan_data.get("url", "")

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


# -------------------------------------------------------------------
# Run Analysis
# -------------------------------------------------------------------
if uploaded is not None and run_analysis:
    ensure_config_excels()
    ensure_reports_dir()

    progress_bar = st.progress(0, text="Starting analysis...")

    # Stage 1: Save uploaded EML
    temp_path = "data/processed/temp_uploaded.eml"
    with open(temp_path, "wb") as f:
        f.write(uploaded.getbuffer())
    st.session_state.uploaded_eml_path = temp_path
    st.session_state.last_uploaded_name = uploaded.name
    progress_bar.progress(20, text="Upload saved (20%)")

    # Stage 2: Analyze
    with st.spinner("Analyzing email..."):
        progress_bar.progress(45, text="Parsing email and extracting evidence (45%)")
        email_data = analyze_email(temp_path)

    progress_bar.progress(80, text="Analysis complete, preparing dashboard (80%)")

    if not email_data:
        progress_bar.empty()
        st.error("Analysis failed or email could not be parsed.")
        st.stop()

    # Save reports
    json_report_path = save_json_report(email_data)
    txt_report_path = save_text_report(email_data)

    st.session_state.email_data = email_data
    st.session_state.analysis_done = True
    st.session_state.json_report_path = json_report_path
    st.session_state.txt_report_path = txt_report_path

    progress_bar.progress(100, text="Dashboard ready (100%)")
    st.success("Analysis complete.")


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
        
    tab_ioc, tab_att, tab_summary, tab_header, tab_raw = st.tabs(
        ["IOC Results", "Attachments", "Summary", "Header Details", "Raw / JSON"]
    )

    # IOC Results
    with tab_ioc:
        st.subheader("IOC Results")

        ioc_df = build_ioc_df(email_data)
        if st.session_state.get("show_only_malicious", False) and not ioc_df.empty:
            ioc_df = ioc_df[ioc_df["Verdict"] == "Malicious"]

        st.dataframe(ioc_df, use_container_width=True, hide_index=True)

        st.markdown("### IOC Detail Viewer")
        if not ioc_df.empty:
            selected_ioc_value = st.selectbox(
                "Choose an IOC for detailed OSINT view",
                options=ioc_df["Value"].tolist(),
                key="ioc_detail_select"
            )

            if st.button("🔎 Run IOC Details", key="run_ioc_detail"):
                show_ioc_detail(email_data, selected_ioc_value)
        else:
            st.info("No IOC results available.")

    # Attachments
    with tab_att:
        st.subheader("Attachments")
        att_df = build_attachment_df(email_data)
        st.dataframe(att_df, use_container_width=True, hide_index=True)

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