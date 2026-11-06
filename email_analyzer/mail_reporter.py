# mail_reporter
import os
import json
import logging
import pandas as pd
import re
import datetime as dt
import copy
import ipaddress
import ast

from typing import Dict, Any
from urllib.parse import quote_plus, urlparse, urlsplit, urlunsplit
from ioc_lib.ioc_validator import normalize_ioc as normalize_ioc_value

from docx import Document
from docx.enum.table import WD_CELL_VERTICAL_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor

logger = logging.getLogger(__name__)


def is_ip(value):
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value)


def format_resolved_ips(value: Any) -> str:
    """Keep resolved-IP display consistent across reports and the UI."""
    if isinstance(value, str):
        return value if value else "N/A"
    if isinstance(value, (list, tuple, set)):
        values = [str(item).strip() for item in value if item not in (None, "") and str(item).strip()]
        return ", ".join(values) if values else "N/A"
    return "N/A"


def _normalized_indicator(ioc_type: Any, value: Any) -> tuple:
    indicator_type = str(ioc_type or "unknown").strip().lower()
    text = normalize_ioc_value(str(value or ""), indicator_type)
    if indicator_type == "domain":
        text = text.rstrip(".").lower()
    elif indicator_type in {"ip", "hash", "file_hash", "file_hashes"}:
        text = text.lower()
        if indicator_type in {"file_hash", "file_hashes"}:
            indicator_type = "hash"
        if indicator_type == "ip":
            try:
                text = str(ipaddress.ip_address(text))
            except ValueError:
                pass
    elif indicator_type == "url":
        try:
            parsed = urlsplit(text)
            if parsed.hostname:
                host = parsed.hostname.lower()
                if parsed.port:
                    host = f"{host}:{parsed.port}"
                text = urlunsplit((parsed.scheme.lower(), host, parsed.path, parsed.query, parsed.fragment))
        except ValueError:
            pass
    return indicator_type, text


def _merge_values(left: Any, right: Any) -> Any:
    if isinstance(left, dict) and isinstance(right, dict):
        merged = dict(left)
        for key, value in right.items():
            merged[key] = _merge_values(merged[key], value) if key in merged else copy.deepcopy(value)
        return merged
    if isinstance(left, list) or isinstance(right, list):
        values = list(left) if isinstance(left, list) else [left]
        values += right if isinstance(right, list) else [right]
        result = []
        seen = set()
        for value in values:
            if value in (None, ""):
                continue
            marker = str(value).strip().casefold()
            if marker not in seen:
                seen.add(marker)
                result.append(value)
        return result
    return right if left in (None, "", {}, []) else left


def _flatten_registrars(value: Any) -> list:
    values = []
    if isinstance(value, (list, tuple, set)):
        for item in value:
            values.extend(_flatten_registrars(item))
    elif value not in (None, ""):
        values.extend(part.strip() for part in re.split(r"[,;]", str(value)) if part.strip())
    unique = []
    seen = set()
    for item in values:
        marker = item.casefold()
        if marker not in seen:
            seen.add(marker)
            unique.append(item)
    return unique


def _report_provider(provider: Any) -> dict:
    result = copy.deepcopy(provider) if isinstance(provider, dict) else {}
    status = str(result.get("status") or "").strip()
    if not status:
        result["status"] = "Unknown"
    elif status.lower().startswith(
        (
            "error", "failed", "unavailable", "vt unavailable", "vt lookup failed",
            "lookup error", "lookup_", "vt api key missing", "ioc analysis unavailable",
            "unsupported ioc type", "404", "pending",
        )
    ):
        result["status"] = f"Lookup failed ({status})"
    elif status.lower() in {"not_found", "not found", "no result", "no results", "n/a"}:
        result["status"] = "Unknown"
    return result


def format_vt_malicious(value: Any, status: Any) -> Any:
    """Do not show a zero score when the VirusTotal lookup did not return results."""
    status_text = str(status or "").strip()
    if not re.fullmatch(r"\d+\s+hits", status_text, re.IGNORECASE):
        return "N/A"
    return value if value is not None else "N/A"


def _has_independent_clean_evidence(item: dict) -> bool:
    if item.get("is_whitelisted") is True:
        return True
    status = str(item.get("vt_status") or "").strip().lower()
    if not re.fullmatch(r"\d+\s+hits", status):
        return False
    try:
        if int(status.split()[0]) != 0:
            return False
    except (ValueError, IndexError):
        return False
    providers = item.get("provider_context", {}) or {}
    indicator_type = str(item.get("ioc_type") or "").lower()
    if indicator_type == "ip":
        abuse = providers.get("abuseipdb", {}) or {}
        try:
            return abuse.get("status") == "ok" and int(abuse.get("abuse_score", 100)) < 70
        except (TypeError, ValueError):
            return False
    if indicator_type == "url":
        urlscan = providers.get("urlscan", providers.get("urlscan_search", {})) or {}
        return urlscan.get("status") == "ok" and urlscan.get("urlscan_malicious") is False
    return False


def _merge_provider_context(left: Any, right: Any) -> dict:
    merged = _merge_values(left or {}, right or {})
    if not isinstance(merged, dict):
        return {}
    old_whois = (left or {}).get("whois", {}) if isinstance(left, dict) else {}
    new_whois = (right or {}).get("whois", {}) if isinstance(right, dict) else {}
    registrars = _flatten_registrars([
        (old_whois or {}).get("registrar"),
        (new_whois or {}).get("registrar"),
    ])
    if registrars:
        merged.setdefault("whois", {})["registrar"] = registrars
    return merged


def _provider_url(provider: Any, *keys: str) -> str:
    if not isinstance(provider, dict):
        return ""
    for key in keys:
        value = provider.get(key)
        if not isinstance(value, str) or not value.strip():
            continue
        try:
            parsed = urlparse(value.strip())
        except ValueError:
            continue
        if parsed.scheme == "https" and parsed.hostname:
            return value.strip()
    return ""


def response_consistency_warnings(email_data: Dict[str, Any]) -> list:
    """Flag benign analyst verdicts that conflict with findings or response actions."""
    data = email_data or {}
    response = data.get("response_actions", {}) or {}
    verdict = str(response.get("final_verdict") or "").strip().casefold()
    if verdict not in {"benign", "no threat observed"}:
        return []

    warnings = []
    if any(response.get(key) for key in ("block_domain", "block_url", "block_sender", "escalate_tier2")):
        warnings.append("The benign verdict conflicts with selected blocking or escalation actions.")

    malicious_indicators = any(
        str(item.get("category") or "").strip().casefold() in {"malicious", "phishing"}
        for item in data.get("ioc_scoring", []) or []
        if isinstance(item, dict)
    )
    sender_verdict = str(
        (data.get("sender_intelligence", {}) or {}).get("verdict") or ""
    ).casefold()
    analyst_text = " ".join(
        str(response.get(key) or "")
        for key in ("finding", "action_taken", "recommendation", "response_notes")
    ).casefold()
    text_indicates_threat = bool(
        re.search(r"\b(?:malicious|phishing|credential theft|compromised)\b", analyst_text)
    )
    if malicious_indicators or sender_verdict in {"malicious", "phishing"} or text_indicates_threat:
        warnings.append("The benign verdict conflicts with malicious findings or investigation notes.")
    return warnings


def build_report_model(email_data: Dict[str, Any]) -> Dict[str, Any]:
    """Build one deduplicated, display-ready view of the existing analysis."""
    model = copy.deepcopy(email_data or {})
    sender = model.get("sender_intelligence", {}) or {}

    # Merge repeated sender values before building WHOIS and link rows.
    def merge_sender_records(records: Any, key_name: str, list_fields: tuple = ()) -> list:
        merged_records = {}
        for record in records or []:
            if not isinstance(record, dict):
                continue
            key = _normalized_indicator(key_name, record.get(key_name))[1]
            if not key:
                continue
            merged = _merge_values(merged_records.get(key, {}), record)
            for field in list_fields:
                values = merged.get(field, []) or []
                if not isinstance(values, (list, tuple, set)):
                    values = [values]
                unique = []
                seen = set()
                for value in values:
                    marker = str(value).strip().casefold()
                    if marker and marker not in seen:
                        seen.add(marker)
                        unique.append(value)
                merged[field] = unique
            if key_name == "domain":
                nested = {}
                for resolved_ip in merged.get("resolved_ip_intelligence", []) or []:
                    if not isinstance(resolved_ip, dict):
                        continue
                    ip_key = _normalized_indicator("ip", resolved_ip.get("ip"))[1]
                    if ip_key:
                        nested[ip_key] = _merge_values(nested.get(ip_key, {}), resolved_ip)
                merged["resolved_ip_intelligence"] = list(nested.values())
            merged_records[key] = merged
        return list(merged_records.values())

    sender["domains"] = merge_sender_records(
        sender.get("domains", []), "domain", ("headers", "spf_records", "dmarc_records")
    )
    sender["ips"] = merge_sender_records(sender.get("ips", []), "ip", ("sources",))

    # Keep one attachment row per content hash while retaining every filename.
    attachments = []
    attachment_indexes = {}
    for attachment_index, attachment in enumerate(model.get("attachments", []) or []):
        if not isinstance(attachment, dict):
            continue
        digest = _normalized_indicator("hash", attachment.get("sha256"))[1]
        filename = str(attachment.get("filename") or "").strip()
        key = ("hash", digest) if digest else ("unhashed", attachment_index)
        if key not in attachment_indexes:
            copied = copy.deepcopy(attachment)
            copied["filenames"] = [filename] if filename else []
            attachment_indexes[key] = len(attachments)
            attachments.append(copied)
            continue
        existing = attachments[attachment_indexes[key]]
        filenames = list(existing.get("filenames", []) or [])
        if filename and filename.casefold() not in {value.casefold() for value in filenames}:
            filenames.append(filename)
        merged = _merge_values(existing, attachment)
        merged["filenames"] = filenames
        attachments[attachment_indexes[key]] = merged
    model["attachments"] = attachments

    hops = []
    hop_indexes = {}
    for hop in model.get("received_hops", []) or []:
        if not isinstance(hop, dict):
            continue
        raw = str(hop.get("raw") or "").strip()
        fields = {
            key: str(hop.get(key) or "").strip()
            for key in ("from", "by", "with", "date")
        }
        if raw.startswith("{"):
            try:
                parsed_hop = ast.literal_eval(raw)
            except (SyntaxError, ValueError):
                parsed_hop = {}
            if isinstance(parsed_hop, dict):
                fields = {
                    key: fields[key] or str(parsed_hop.get(key) or "").strip()
                    for key in fields
                }
                raw = str(parsed_hop.get("raw") or "")
        if raw:
            normalized = re.sub(r"\s+", " ", raw).strip()
            parsed = {
                "from": re.search(r"\bfrom\s+(.*?)\s+\bby\s+", normalized, re.IGNORECASE),
                "by": re.search(r"\bby\s+(.*?)\s+(?:with\b|;)", normalized, re.IGNORECASE),
                "with": re.search(r"\bwith\s+(\S+)", normalized, re.IGNORECASE),
                "date": re.search(r";\s*(.+)$", normalized),
            }
            if not fields["from"] and parsed["from"]:
                fields["from"] = parsed["from"].group(1).strip()
            if not fields["by"] and parsed["by"]:
                fields["by"] = parsed["by"].group(1).strip()
            if not fields["with"] and parsed["with"]:
                fields["with"] = parsed["with"].group(1).strip()
            if not fields["date"] and parsed["date"]:
                fields["date"] = parsed["date"].group(1).strip()
            key = re.sub(r"^received:\s*", "", normalized, flags=re.IGNORECASE).casefold()
        else:
            if not fields["from"] or not fields["by"]:
                continue
            normalized = " ".join(
                f"{name} {fields[name]}" for name in ("from", "by", "with", "date") if fields[name]
            )
            key = re.sub(r"\s+", " ", normalized).strip().casefold()
        if not fields["from"] or not fields["by"]:
            continue
        normalized_hop = {
            **fields,
            "raw": raw or normalized,
            "delay": hop.get("delay"),
        }
        if key in hop_indexes:
            existing = hops[hop_indexes[key]]
            for field, value in fields.items():
                if not existing.get(field) and value:
                    existing[field] = value
            continue
        hop_indexes[key] = len(hops)
        hops.append(normalized_hop)
    model["received_hops"] = hops

    urls = model.get("urls_extracted", []) or []
    unique_urls = []
    seen_urls = set()
    for url in urls:
        normalized_url = _normalized_indicator("url", url)[1]
        if normalized_url and normalized_url not in seen_urls:
            seen_urls.add(normalized_url)
            unique_urls.append(normalized_url)
    model["urls_extracted"] = unique_urls
    wrappers = []
    seen_wrappers = set()
    for wrapper in model.get("urls_extracted_detail", []) or []:
        if not isinstance(wrapper, dict):
            continue
        wrapper_key = tuple(
            re.sub(r"\s+", " ", str(wrapper.get(key) or "")).strip().casefold()
            for key in ("wrapped_url", "decoded_url", "final_ioc_url")
        )
        if not any(wrapper_key) or wrapper_key in seen_wrappers:
            continue
        seen_wrappers.add(wrapper_key)
        wrappers.append(wrapper)
    model["urls_extracted_detail"] = wrappers
    auth_text = str(model.get("auth_results") or "")
    body_domains = set()
    for url in urls:
        try:
            host = urlsplit(str(url)).hostname
            if host:
                body_domains.add(host.lower().rstrip("."))
        except ValueError:
            continue
    auth_domains = {
        match.lower().rstrip(".")
        for match in re.findall(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,63}\b", auth_text, re.IGNORECASE)
    }
    hop_domains = set()
    for hop in hops:
        for field in ("from", "by"):
            hop_domains.update(
                match.lower().rstrip(".")
                for match in re.findall(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,63}\b", hop.get(field, ""), re.IGNORECASE)
            )

    def keep_ioc(ioc_type: Any, value: Any) -> bool:
        normalized_type, normalized_value = _normalized_indicator(ioc_type, value)
        return not (
            normalized_type == "domain"
            and normalized_value in hop_domains
            and normalized_value not in body_domains
            and normalized_value not in auth_domains
        )

    hash_sources = {}
    for digest, sources in (model.get("hash_sources", {}) or {}).items():
        normalized_digest = _normalized_indicator("hash", digest)[1]
        if normalized_digest:
            if isinstance(sources, str):
                sources = [sources]
            hash_sources[normalized_digest] = list(dict.fromkeys(
                str(source).strip().lower() for source in (sources or []) if str(source).strip()
            ))

    normalized_iocs = {}
    source_types = {"ips": "ip", "domains": "domain", "urls": "url", "hashes": "hash"}
    for source_key, output_key in (("ips", "ips"), ("domains", "domains"), ("urls", "urls"), ("hashes", "hashes")):
        source_type = source_types[source_key]
        values = (model.get("iocs", {}) or {}).get(source_key, []) or []
        if not isinstance(values, (list, tuple, set)):
            values = [values]
        if source_key == "hashes":
            values = list(values) + [
                attachment.get("sha256")
                for attachment in model.get("attachments", []) or []
                if attachment.get("sha256")
            ]
        unique = []
        seen = set()
        attachment_hashes = {
            _normalized_indicator("hash", attachment.get("sha256"))[1]
            for attachment in model.get("attachments", []) or []
            if attachment.get("sha256")
        }
        for value in values:
            if not keep_ioc(source_type, value):
                continue
            key = _normalized_indicator(source_type, value)
            if key not in seen:
                seen.add(key)
                unique.append(key[1])
                if source_key == "hashes":
                    hash_sources.setdefault(key[1], [])
                    if key[1] in attachment_hashes and "attachment" not in hash_sources[key[1]]:
                        hash_sources[key[1]].append("attachment")
        normalized_iocs[output_key] = unique
    normalized_iocs["counts"] = {key: len(normalized_iocs[key]) for key in ("ips", "domains", "urls", "hashes")}
    model["iocs"] = normalized_iocs
    model["hash_sources"] = hash_sources

    scored = {}
    for item in model.get("ioc_scoring", []) or []:
        if not isinstance(item, dict):
            continue
        ioc_type, value = _normalized_indicator(item.get("ioc_type"), item.get("normalized"))
        if ioc_type not in source_types.values() or not value or not keep_ioc(ioc_type, value):
            continue
        key = (ioc_type, value)
        normalized_item = copy.deepcopy(item)
        normalized_item["ioc_type"] = ioc_type
        normalized_item["normalized"] = value
        normalized_item["provider_context"] = {
            name: _report_provider(provider)
            for name, provider in (normalized_item.get("provider_context", {}) or {}).items()
            if isinstance(provider, dict)
        }
        normalized_item["vt_status"] = _report_provider(
            {"status": normalized_item.get("vt_status")}
        )["status"]
        normalized_item["vt_malicious_display"] = format_vt_malicious(
            normalized_item.get("vt_malicious"), normalized_item["vt_status"]
        )
        if ioc_type == "hash":
            item_sources = normalized_item.get("hash_sources", []) or []
            if isinstance(item_sources, str):
                item_sources = [item_sources]
            merged_sources = list(dict.fromkeys(
                hash_sources.get(value, []) + [str(source).lower() for source in item_sources]
            ))
            hash_sources[value] = merged_sources
            normalized_item["hash_sources"] = merged_sources
        else:
            normalized_item["hash_sources"] = []
        if str(normalized_item.get("category") or "").lower() == "clean" and not _has_independent_clean_evidence(normalized_item):
            normalized_item["category"] = "Unknown"
        if key in scored:
            existing = scored[key]
            existing["reason"] = list(dict.fromkeys(
                list(existing.get("reason", []) or []) + list(normalized_item.get("reason", []) or [])
            ))
            existing["provider_context"] = _merge_provider_context(
                existing.get("provider_context", {}), normalized_item.get("provider_context", {})
            )
            category_order = {"malicious": 3, "phishing": 3, "suspicious": 2, "unknown": 1, "clean": 0}
            existing_category = str(existing.get("category") or "Unknown").lower()
            next_category = str(normalized_item.get("category") or "Unknown").lower()
            if category_order.get(next_category, 1) > category_order.get(existing_category, 1):
                existing["category"] = normalized_item.get("category")
            for field in ("final_score", "vt_malicious"):
                try:
                    old_value = existing.get(field)
                    new_value = normalized_item.get(field)
                    if new_value is not None and (old_value is None or float(new_value) > float(old_value)):
                        existing[field] = new_value
                except (TypeError, ValueError):
                    continue
            existing["hash_sources"] = list(dict.fromkeys(
                existing.get("hash_sources", []) + normalized_item.get("hash_sources", [])
            ))
            continue
        scored[key] = normalized_item
    type_to_list = {"ip": "ips", "domain": "domains", "url": "urls", "hash": "hashes"}
    for ioc_type, value in scored:
        list_name = type_to_list.get(ioc_type)
        if list_name and value not in normalized_iocs[list_name]:
            normalized_iocs[list_name].append(value)
    normalized_iocs["counts"] = {
        key: len(normalized_iocs[key]) for key in ("ips", "domains", "urls", "hashes")
    }
    model["iocs"] = normalized_iocs
    model["hash_sources"] = hash_sources
    for source_key, ioc_type in source_types.items():
        for value in normalized_iocs[source_key]:
            key = _normalized_indicator(ioc_type, value)
            if key not in scored:
                scored[key] = {
                    "ioc_type": key[0],
                    "normalized": key[1],
                    "category": "Unknown",
                    "vt_status": "Unknown",
                    "vt_malicious": None,
                    "vt_malicious_display": "N/A",
                    "final_score": None,
                    "reason": [],
                    "provider_context": {},
                    "hash_sources": hash_sources.get(key[1], []) if key[0] == "hash" else [],
                }
    model["ioc_scoring"] = list(scored.values())
    for item in model["ioc_scoring"]:
        whois = (item.get("provider_context", {}) or {}).get("whois", {}) or {}
        for field in ("registrar", "nameservers", "mx", "ips"):
            flattened = _flatten_registrars(whois.get(field))
            if flattened:
                whois[field] = ", ".join(flattened)

    indicators = {}

    def add_indicator(ioc_type: Any, value: Any, source: str, data: dict) -> None:
        normalized_type, normalized_value = _normalized_indicator(ioc_type, value)
        if not normalized_value:
            return
        key = (normalized_type, normalized_value)
        entry = indicators.setdefault(key, {
            "type": normalized_type,
            "value": normalized_value,
            "sender": {},
            "ioc": {},
            "provider_context": {},
            "whois": {},
            "resolved_ip_text": "N/A",
        })
        if source == "sender":
            entry["sender"] = _merge_values(entry["sender"], data)
            provider_context = {
                "virustotal": data.get("virustotal", {}),
                "talos": data.get("talos", {}),
                "urlscan": data.get("urlscan_search", data.get("urlscan", {})),
                "rdap": data.get("rdap", {}),
                "whois": data.get("whois", {}),
                "abuseipdb": data.get("abuseipdb", {}),
            }
            entry["provider_context"] = _merge_provider_context(entry["provider_context"], provider_context)
            entry["whois"] = _merge_provider_context(
                {"whois": entry["whois"]},
                {"whois": data.get("whois", {}) or {}},
            ).get("whois", {})
            entry["resolved_ip_text"] = format_resolved_ips(
                data.get("resolved_ips", data.get("ips"))
            )
        else:
            entry["ioc"] = _merge_values(entry["ioc"], data)
            context = data.get("provider_context", {}) or {}
            entry["provider_context"] = _merge_provider_context(entry["provider_context"], context)
            entry["whois"] = _merge_provider_context(
                {"whois": entry["whois"]},
                {"whois": context.get("whois", {}) or {}},
            ).get("whois", {})
            if entry["resolved_ip_text"] == "N/A":
                entry["resolved_ip_text"] = format_resolved_ips(
                    (context.get("whois", {}) or {}).get("ips")
                )

    sender_domains = sender.get("domains", []) or []
    sender_ips = sender.get("ips", []) or []
    for domain in sender_domains:
        add_indicator("domain", domain.get("domain"), "sender", domain)
        for resolved_ip in domain.get("resolved_ip_intelligence", []) or []:
            add_indicator("ip", resolved_ip.get("ip"), "sender", resolved_ip)
    for ip in sender_ips:
        add_indicator("ip", ip.get("ip"), "sender", ip)
    for item in model["ioc_scoring"]:
        add_indicator(item.get("ioc_type"), item.get("normalized"), "ioc", item)
    for attachment in model.get("attachments", []) or []:
        sha256 = attachment.get("sha256")
        if sha256:
            talos = attachment.get("talos", {})
            add_indicator(
                "hash",
                sha256,
                "ioc",
                {"provider_context": {"talos": talos if isinstance(talos, dict) else {}}},
            )

    model["report_indicators"] = list(indicators.values())
    whois_rows = []
    ip_intelligence_rows = {}
    intelligence_links = []
    for indicator in model["report_indicators"]:
        whois = indicator.get("whois", {}) or {}
        has_whois_data = bool(whois)
        registrars = _flatten_registrars(whois.get("registrar"))
        if registrars:
            whois["registrar"] = ", ".join(registrars)
        whois["nameservers"] = _flatten_registrars(whois.get("nameservers"))
        whois["mx"] = _flatten_registrars(whois.get("mx"))
        whois["ips"] = _flatten_registrars(whois.get("ips"))
        indicator["whois"] = whois
        indicator["resolved_ip_text"] = format_resolved_ips(
            indicator["sender"].get("resolved_ips")
            or whois.get("ips")
            or indicator.get("resolved_ip_text")
        )
        rdap = indicator["provider_context"].get("rdap", {}) or {}
        if indicator["type"] == "domain" and (has_whois_data or rdap):
            age_days = whois.get("age_days")
            if age_days is None:
                age_days = indicator["sender"].get("domain_age_days")
            whois_rows.append({
                "type": "domain",
                "indicator": indicator["value"],
                "registrar": whois.get("registrar") or "N/A",
                "created": whois.get("created") or whois.get("creation_date") or "N/A",
                "updated": whois.get("updated") or whois.get("updated_date") or "N/A",
                "expires": whois.get("expires") or whois.get("expiry_date") or "N/A",
                "age_days": age_days if age_days is not None else "N/A",
                "nameservers": ", ".join(whois["nameservers"]) or "N/A",
                "resolved_ips": format_resolved_ips(indicator["resolved_ip_text"]),
                "mx": ", ".join(whois["mx"]) or ", ".join(
                    ((indicator["sender"].get("dns", {}) or {}).get("mx", {}) or {}).get("records", []) or []
                ) or "N/A",
                "rdap_status": _report_provider(rdap).get("status", "Unknown"),
                "status": _report_provider(whois).get("status", "Unknown"),
            })
        if indicator["type"] == "ip":
            context = indicator["provider_context"]
            abuse = _report_provider(context.get("abuseipdb", {}))
            ip_intelligence_rows[indicator["value"]] = {
                "ip": indicator["value"],
                "sources": indicator["sender"].get("sources", []),
                "virustotal": _report_provider(context.get("virustotal", {})),
                "abuseipdb": abuse,
                "talos": _report_provider(context.get("talos", {})),
                "urlscan": _report_provider(context.get("urlscan", {})),
                "asn": abuse.get("asn"),
                "hosting": abuse.get("isp"),
                "risk_score": indicator["sender"].get("risk_score"),
            }

        context = indicator["provider_context"]
        encoded = quote_plus(indicator["value"])
        if indicator["type"] == "domain":
            fallbacks = {
                "VirusTotal": f"https://www.virustotal.com/gui/domain/{encoded}",
                "Talos": f"https://talosintelligence.com/reputation_center/lookup?search={encoded}",
                "RDAP": f"https://lookup.icann.org/en/lookup?name={encoded}",
                "WHOIS": f"https://www.whois.com/whois/{encoded}",
                "URLScan": f"https://urlscan.io/search/#domain:{encoded}",
            }
        elif indicator["type"] == "ip":
            fallbacks = {
                "VirusTotal": f"https://www.virustotal.com/gui/ip-address/{encoded}",
                "Talos": f"https://talosintelligence.com/reputation_center/lookup?search={encoded}",
                "URLScan": f"https://urlscan.io/search/#ip:{encoded}",
                "AbuseIPDB": f"https://www.abuseipdb.com/check/{encoded}",
            }
        elif indicator["type"] == "url":
            fallbacks = {
                "VirusTotal": f"https://www.virustotal.com/gui/search/{encoded}",
                "URLScan": f"https://urlscan.io/search/#page.url:{encoded}",
            }
        elif indicator["type"] == "hash":
            fallbacks = {"VirusTotal": f"https://www.virustotal.com/gui/search/{encoded}"}
        else:
            fallbacks = {}
        # Provider links are collected here so each indicator has one shared link row.
        source_links = {
            "VirusTotal": _provider_url(context.get("virustotal"), "url", "lookup_url", "portal_lookup", "result_url"),
            "Talos": _provider_url(context.get("talos"), "portal_lookup", "url", "lookup_url"),
            "RDAP": _provider_url(context.get("rdap"), "portal_lookup", "url", "lookup_url"),
            "URLScan": _provider_url(context.get("urlscan"), "search_url", "result_url", "result", "url"),
            "WHOIS": _provider_url(context.get("whois"), "url", "lookup_url", "whois_url"),
            "AbuseIPDB": _provider_url(context.get("abuseipdb"), "url", "lookup_url", "report_url"),
        }
        links = {
            provider: source_links.get(provider) or fallbacks.get(provider, "")
            for provider in ("VirusTotal", "Talos", "RDAP", "WHOIS", "URLScan", "AbuseIPDB")
        }
        intelligence_links.append({
            "type": indicator["type"],
            "indicator": indicator["value"],
            "links": links,
        })

    model["whois_rows"] = whois_rows
    model["ip_intelligence_rows"] = list(ip_intelligence_rows.values())
    model["intelligence_links"] = intelligence_links

    for domain in sender.get("domains", []) or []:
        domain["resolved_ip_text"] = format_resolved_ips(domain.get("resolved_ips"))
        whois = domain.get("whois", {}) or {}
        registrars = _flatten_registrars(whois.get("registrar"))
        if registrars:
            whois["registrar"] = ", ".join(registrars)
        whois["status"] = _report_provider(whois).get("status", "Unknown")
        for provider_key in ("virustotal", "talos", "urlscan_search", "rdap"):
            domain[provider_key] = _report_provider(domain.get(provider_key))
        domain["virustotal"]["malicious_display"] = format_vt_malicious(
            domain["virustotal"].get("malicious"), domain["virustotal"].get("status")
        )
        for resolved_ip in domain.get("resolved_ip_intelligence", []) or []:
            for provider_key in ("virustotal", "talos", "urlscan_search", "abuseipdb"):
                resolved_ip[provider_key] = _report_provider(resolved_ip.get(provider_key))
            resolved_ip["virustotal"]["malicious_display"] = format_vt_malicious(
                resolved_ip["virustotal"].get("malicious"), resolved_ip["virustotal"].get("status")
            )
    for ip in sender.get("ips", []) or []:
        ip["resolved_ip_text"] = format_resolved_ips(ip.get("ip"))
        for provider_key in ("virustotal", "talos", "urlscan_search", "abuseipdb"):
            ip[provider_key] = _report_provider(ip.get(provider_key))
        ip["virustotal"]["malicious_display"] = format_vt_malicious(
            ip["virustotal"].get("malicious"), ip["virustotal"].get("status")
        )
    for attachment in model.get("attachments", []) or []:
        vt_hash = attachment.get("vt_hash", {}) or {}
        attachment["vt_hash_display"] = dict(vt_hash)
        attachment["vt_hash_display"]["vt_malicious"] = format_vt_malicious(
            vt_hash.get("vt_malicious"), vt_hash.get("vt_status")
        )
    model["sender_intelligence"] = sender

    response = model.get("response_actions", {}) or {}
    selected_actions = [
        label for key, label in (
            ("block_domain", "Block Domain"),
            ("block_url", "Block URL"),
            ("block_sender", "Block Sender"),
            ("escalate_tier2", "Escalate to Tier 2"),
            ("search_similar", "Search Similar Emails"),
        )
        if response.get(key)
    ]
    model["selected_response_actions"] = selected_actions
    model["automated_verdict"] = model.get("email_severity") or "Unknown"
    model["final_analyst_verdict"] = response.get("final_verdict") or "N/A"
    model["consistency_warnings"] = response_consistency_warnings(model)
    automated_actions = (model.get("alert", {}) or {}).get("recommended_actions", []) or []
    if not automated_actions:
        severity = str(model.get("email_severity") or "Unknown").lower()
        if "high" in severity or "malicious" in severity:
            automated_actions = [
                "Quarantine the email and block the sender/source immediately.",
                "Review attachment hashes and provider results before opening.",
                "Block and investigate final IOC URLs and related infrastructure.",
            ]
        else:
            automated_actions = [
                "Monitor the IOCs and consider blocking identified malicious infrastructure.",
                "Notify recipients and provide phishing awareness guidance.",
                "Submit key IOCs to OSINT providers for enrichment if uncertainty remains.",
            ]
    model["recommended_actions"] = list(automated_actions)
    if model.get("investigation_submitted"):
        model["recommended_actions"].insert(
            0,
            f"Final analyst verdict: {response.get('final_verdict') or 'Unknown'}; selected actions: "
            f"{', '.join(selected_actions) or 'None'}.",
        )

    campaign_rows = []

    def add_campaign_rows(value: Any, prefix: str) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if prefix == "Alert" and str(key).casefold() == "recommended_actions":
                    continue
                add_campaign_rows(child, f"{prefix}.{key}" if prefix else str(key))
        elif isinstance(value, (list, tuple)):
            for index, child in enumerate(value, start=1):
                add_campaign_rows(child, f"{prefix}[{index}]")
        elif value not in (None, ""):
            campaign_rows.append([prefix or "Finding", str(value)])

    add_campaign_rows(model.get("campaign", {}) or {}, "Campaign")
    add_campaign_rows(model.get("alert", {}) or {}, "Alert")
    model["campaign_alert_findings"] = campaign_rows or [
        ["Correlation", "No campaign correlation found."]
    ]
    return model


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
        email_data = build_report_model(email_data)
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

        def remove_provider_links(provider: Any) -> None:
            if not isinstance(provider, dict):
                return
            for key in ("url", "portal_lookup", "lookup", "lookup_url", "result_url", "search_url", "whois_url", "report_url"):
                value = provider.get(key)
                if isinstance(value, str) and value.startswith("https://"):
                    provider.pop(key, None)

        report_sender_intelligence = copy.deepcopy(email_data.get("sender_intelligence", {}))
        sender_data = report_sender_intelligence if isinstance(report_sender_intelligence, dict) else {}
        for domain in sender_data.get("domains", []) or []:
            for key in ("virustotal", "talos", "urlscan_search", "rdap"):
                remove_provider_links(domain.get(key))
            for resolved_ip in domain.get("resolved_ip_intelligence", []) or []:
                for key in ("virustotal", "talos", "urlscan_search", "abuseipdb"):
                    remove_provider_links(resolved_ip.get(key))
        for ip in sender_data.get("ips", []) or []:
            for key in ("virustotal", "talos", "urlscan_search", "abuseipdb"):
                remove_provider_links(ip.get(key))
        for item in safe_ioc_scoring:
            for provider in (item.get("provider_context", {}) or {}).values():
                remove_provider_links(provider)
        report_attachments = copy.deepcopy(email_data.get("attachments", []))
        for attachment in report_attachments:
            remove_provider_links(attachment.get("talos"))

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
            "sender_intelligence": report_sender_intelligence,
            "sender_domains": email_data.get("sender_domains", []),
            "body_stats": email_data.get("body_stats", {}),
            "urls_extracted": email_data.get("urls_extracted", []),
            "urls_extracted_detail": email_data.get("urls_extracted_detail", []),
            "iocs": email_data.get("iocs", {}),
            "attachments": report_attachments,
            "ioc_scoring": safe_ioc_scoring,
            "whois_rows": email_data.get("whois_rows", []),
            "ip_intelligence_rows": email_data.get("ip_intelligence_rows", []),
            "intelligence_links": email_data.get("intelligence_links", []),
            "recommended_actions": email_data.get("recommended_actions", []),
            "automated_verdict": email_data.get("automated_verdict", "Unknown"),
            "final_analyst_verdict": email_data.get("final_analyst_verdict", "N/A"),
            "consistency_warnings": email_data.get("consistency_warnings", []),
            "campaign_alert_findings": email_data.get("campaign_alert_findings", []),
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
        email_data = build_report_model(email_data)
        ts = self._timestamp()
        report_path = os.path.join(self.output_dir, f"email_analysis_{ts}.txt")

        urls = email_data.get("urls_extracted", []) or []
        attachments = email_data.get("attachments", []) or []
        body_stats = email_data.get("body_stats", {}) or {}

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
            f.write(f"Automated verdict : { _safe(email_data.get('automated_verdict', 'Unknown')) }\n")
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

            f.write("=" * 80 + "\n")
            f.write("RECEIVED HOPS\n")
            f.write("=" * 80 + "\n\n")
            for index, hop in enumerate(received_hops, start=1):
                f.write(
                    f"{index}. From: {_safe(hop.get('from'))} | "
                    f"By: {_safe(hop.get('by'))} | "
                    f"With: {_safe(hop.get('with'))} | "
                    f"Date: {_safe(hop.get('date'))}\n"
                )
            if not received_hops:
                f.write("No valid Received hops found.\n")
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
                f.write(f"SPF ({domain.get('spf_status', 'unknown')}): { ', '.join(domain.get('spf_records', []) or []) or _provider_value(None, domain.get('spf_status'), 'DNS') }\n")
                f.write(f"DMARC ({domain.get('dmarc_status', 'unknown')}): { ', '.join(domain.get('dmarc_records', []) or []) or _provider_value(None, domain.get('dmarc_status'), 'DNS') }\n")
                f.write(f"DNS A records     : { ', '.join((dns.get('a', {}) or {}).get('records', []) or []) or _provider_value(None, (dns.get('a', {}) or {}).get('status'), 'DNS') }\n")
                f.write(f"DNS AAAA records  : { ', '.join((dns.get('aaaa', {}) or {}).get('records', []) or []) or _provider_value(None, (dns.get('aaaa', {}) or {}).get('status'), 'DNS') }\n")
                f.write(f"DNS TXT           : { ', '.join((dns.get('txt', {}) or {}).get('records', []) or []) or _provider_value(None, (dns.get('txt', {}) or {}).get('status'), 'DNS') }\n")
                f.write(f"MX records        : { ', '.join((dns.get('mx', {}) or {}).get('records', []) or []) or _provider_value(None, (dns.get('mx', {}) or {}).get('status'), 'DNS') }\n")
                f.write(f"VirusTotal        : { _safe((domain.get('virustotal', {}) or {}).get('status'), 'Unknown') }\n")
                vt = domain.get("virustotal", {}) or {}
                f.write(f"VT malicious count: { _safe(format_vt_malicious(vt.get('malicious'), vt.get('status'))) }\n")
                f.write(f"Talos status      : { _safe(talos.get('status'), 'Unknown') }\n")
                f.write(f"URLScan status    : { _safe(urlscan.get('status'), 'Unknown')} ({_safe(urlscan.get('result_count', 0))} matches)\n")
                f.write(f"Whitelisted       : { _safe(domain.get('whitelisted', False)) }\n")
                f.write(f"Blocklisted       : { _safe(domain.get('blocklisted', False)) }\n")
                f.write(f"Risk Score        : { _safe(domain.get('risk_score', 0)) }\n")
            ip_rows = email_data.get("ip_intelligence_rows", []) or []
            if ip_rows:
                f.write("=" * 80 + "\n")
                f.write("IP INTELLIGENCE\n")
                f.write("=" * 80 + "\n")
            for ip in ip_rows:
                abuse = ip.get("abuseipdb", {}) or {}
                talos = ip.get("talos", {}) or {}
                urlscan = ip.get("urlscan", {}) or {}
                vt = ip.get("virustotal", {}) or {}
                f.write(f"\nIP                : { format_resolved_ips(ip.get('ip')) }\n")
                f.write(f"Source headers    : { ', '.join(ip.get('sources', []) or []) or 'N/A' }\n")
                f.write(f"VirusTotal        : { _safe(vt.get('status'), 'Unknown') }\n")
                f.write(f"VT malicious count: { _safe(format_vt_malicious(vt.get('malicious'), vt.get('status'))) }\n")
                f.write(f"AbuseIPDB status  : { _safe(abuse.get('status'), 'Unknown') }\n")
                f.write(f"AbuseIPDB Score   : { _safe(abuse.get('abuse_score')) }\n")
                f.write(f"ASN / Hosting     : { _safe(ip.get('asn'))} / { _safe(ip.get('hosting')) }\n")
                f.write(f"Talos status      : { _safe(talos.get('status'), 'Unknown') }\n")
                f.write(f"URLScan status    : { _safe(urlscan.get('status'), 'Unknown')} ({_safe(urlscan.get('result_count', 0))} matches)\n")
                f.write(f"Risk Score        : { _safe(ip.get('risk_score', 0)) }\n")
            f.write("\n")

            f.write("=" * 80 + "\n")
            f.write("INTELLIGENCE LINKS\n")
            f.write("=" * 80 + "\n\n")
            for link_item in email_data.get("intelligence_links", []) or []:
                f.write(f"{link_item['type'].upper()} {link_item['indicator']}\n")
                for provider, url in (link_item.get("links", {}) or {}).items():
                    if url:
                        f.write(f"  {provider}: {url}\n")
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
                    vt_status = _safe(item.get('vt_status', 'N/A'))
                    vt_score = _safe(format_vt_malicious(item.get('vt_malicious'), vt_status))
                    urlscan = provider_context.get('urlscan', {}) or {}
                    abuse_txt = f"Score={ _safe(abuse.get('abuse_score','N/A')) } Reports={ _safe(abuse.get('abuse_reports','N/A')) }"
                    hosting = provider_context.get('hosting', {}) or {}
                    hosting_provider = _safe(hosting.get('provider') or provider_context.get('hosting_provider') or 'N/A')
                    reasons = self._dedup_reasons(item.get('reason', []) or [])

                    f.write(f"Type              : { ioc_type }\n")
                    f.write(f"Value             : { value }\n")
                    f.write(f"Final IOC URL     : { final_ioc }\n")
                    f.write(f"Verdict           : { verdict }\n")
                    f.write(f"Risk Score        : { risk }\n")
                    f.write(f"VT Score          : { vt_score }\n")
                    f.write(f"VT Status         : { _safe(vt_status, 'Unknown') }\n")
                    f.write(f"URLScan status    : { _safe(urlscan.get('status'), 'Unknown') }\n")
                    f.write(f"Talos status      : { _safe(talos.get('status'), 'Unknown') }\n")
                    f.write(f"AbuseIPDB         : { abuse_txt }\n")
                    f.write(f"Hosting Provider  : { hosting_provider }\n")
                    f.write(f"Reasons           : {', '.join(reasons) if reasons else 'N/A'}\n")
                    hash_sources = item.get("hash_sources", []) or []
                    if ioc_type == "hash":
                        f.write(f"Hash source       : {', '.join(hash_sources) or 'Unknown'}\n")
                    f.write('-' * 60 + '\n')
                f.write('\n')

            # Domain WHOIS Details
            f.write('=' * 80 + '\n')
            f.write('DOMAIN WHOIS DETAILS\n')
            f.write('=' * 80 + '\n\n')
            domain_written = False
            for who in email_data.get("whois_rows", []) or []:
                domain_written = True
                f.write(f"Type / Indicator: {who['type']} / {who['indicator']}\n")
                f.write(f"  Registrar     : { _safe(who.get('registrar')) }\n")
                f.write(f"  Creation Date : { _safe(who.get('created')) }\n")
                f.write(f"  Updated Date  : { _safe(who.get('updated')) }\n")
                f.write(f"  Expiry Date   : { _safe(who.get('expires')) }\n")
                f.write(f"  Domain Age    : { _safe(who.get('age_days')) } days\n")
                f.write(f"  Status        : { _safe(who.get('status'), 'Unknown') }\n")
                f.write(f"  Nameservers   : { _safe(who.get('nameservers')) }\n")
                f.write(f"  Resolved IPs  : { format_resolved_ips(who.get('resolved_ips')) }\n")
                f.write(f"  MX Records    : { _safe(who.get('mx')) }\n")
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
                    f.write(f"Filename         : { _safe(', '.join(att.get('filenames', []) or [att.get('filename', 'N/A')])) }\n")
                    f.write(f"Size (bytes)     : { _safe(att.get('size', att.get('length', 'N/A'))) }\n")
                    f.write(f"SHA256           : { _safe(att.get('sha256','N/A')) }\n")
                    vt_hash = att.get('vt_hash', {}) or {}
                    f.write(f"  VT Score       : { _safe(format_vt_malicious(vt_hash.get('vt_malicious'), vt_hash.get('vt_status'))) }\n")
                    f.write(f"  VT Status      : { _safe(vt_hash.get('vt_status','N/A')) }\n")
                    f.write('-' * 40 + '\n')
            else:
                f.write('No attachments present.\n')
            f.write('\n')

            # Threat Verdict
            f.write("=" * 80 + "\n")
            f.write("AUTOMATED THREAT VERDICT\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"Automated verdict: { _safe(email_data.get('email_severity'),'Unknown') }\n")
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

            if email_data.get("consistency_warnings"):
                f.write("CONSISTENCY WARNINGS\n")
                for warning in email_data["consistency_warnings"]:
                    f.write(f" - {warning}\n")
                f.write("\n")

            f.write("=" * 80 + "\n")
            f.write("CAMPAIGN / ALERT FINDINGS\n")
            f.write("=" * 80 + "\n\n")
            for label, details in email_data.get("campaign_alert_findings", []) or []:
                f.write(f"{label}: {details}\n")
            f.write("\n")

            # Recommended Actions
            f.write("=" * 80 + "\n")
            f.write("RECOMMENDED ACTIONS\n")
            f.write("=" * 80 + "\n\n")
            sev = (email_data.get('email_severity') or 'Unknown').lower()
            if email_data.get("investigation_submitted"):
                for action in email_data.get("recommended_actions", []):
                    f.write(f"- {action}\n")
            elif 'high' in sev or 'malicious' in sev:
                f.write("- Quarantine the email and block the sender/source immediately.\n")
                f.write("- Review attachment hashes and VirusTotal/Talos results before opening.\n")
                f.write("- Block and investigate Final IOC URLs; consult URLScan/Talos/VT records.\n")
                f.write("- Review related accounts and infrastructure for reuse.\n")
            else:
                f.write("- Monitor the IOCs and consider blocking identified malicious infrastructure.\n")
                f.write("- Notify recipients and provide phishing awareness guidance.\n")
                f.write("- If uncertain, submit key IOCs to OSINT providers for enrichment.\n")

            f.write("\n" + "=" * 80 + "\n")
            f.write("APPENDIX: FULL RAW HEADERS\n")
            f.write("=" * 80 + "\n\n")
            for key, value in headers_raw.items():
                f.write(f"{key}: {value}\n")

        logger.info("TXT report generated: %s", report_path)
        return report_path

    def generate_word_report(self, email_data: Dict[str, Any]) -> str:
        """Create a professional DOCX report from the saved analysis only."""
        email_data = build_report_model(email_data)
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
        add_key_values("Executive Summary", {
            "Subject": email_data.get("subject"),
            "From": email_data.get("from"),
            "To": email_data.get("to"),
            "Automated verdict": severity,
            "Email score": email_data.get("email_score"),
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
        sender_ip_rows = []
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
                domain.get("spf_status"),
                ", ".join(domain.get("spf_records", []) or []),
                domain.get("dmarc_status"),
                ", ".join(domain.get("dmarc_records", []) or []),
                ", ".join((dns.get("mx", {}) or {}).get("records", []) or []),
                format_resolved_ips(domain.get("resolved_ips")),
                domain.get("risk_score"),
                format_vt_malicious(vt.get("malicious"), vt.get("status")),
                vt.get("status", "Unknown"),
                talos.get("status", "Unknown"),
                urlscan.get("status", "Unknown"),
                rdap.get("status", "Unknown"),
            ])
        for ip in email_data.get("ip_intelligence_rows", []) or []:
            abuse = ip.get("abuseipdb", {}) or {}
            vt = ip.get("virustotal", {}) or {}
            talos = ip.get("talos", {}) or {}
            urlscan = ip.get("urlscan", {}) or {}
            sender_ip_rows.append([
                ip.get("ip"),
                ", ".join(ip.get("sources", []) or []),
                vt.get("status", "Unknown"),
                abuse.get("abuse_score"),
                ip.get("asn"),
                ip.get("hosting"),
                ip.get("risk_score"),
                talos.get("status", "Unknown"),
                urlscan.get("status", "Unknown"),
                urlscan.get("result_count"),
            ])
        add_table(
            "Sender Intelligence",
            ["Domain", "Header role", "SPF status",
             "SPF record", "DMARC status", "DMARC record", "MX", "Resolved IPs", "Risk score",
             "VT malicious", "VT status", "Talos", "URLScan", "RDAP",
             ],
            sender_domain_rows,
        )
        if sender_ip_rows:
            add_table(
                "Sender IP Intelligence",
                ["IP", "Source header", "VT", "AbuseIPDB", "ASN", "Hosting / ISP", "Risk score",
                 "Talos status", "URLScan status", "URLScan matches"],
                sender_ip_rows,
            )
        add_key_values("Sender Risk Summary", {
            "Verdict": sender_intelligence.get("verdict"),
            "Risk score": sender_intelligence.get("risk_score"),
            "Reasons": "; ".join(map(str, sender_intelligence.get("reasons", []) or [])),
        })
        link_rows = []
        for link_item in email_data.get("intelligence_links", []) or []:
            row = [link_item["type"], link_item["indicator"]]
            row.extend(
                {"label": f"Open {provider}", "url": url} if url else "N/A"
                for provider, url in (link_item.get("links", {}) or {}).items()
            )
            link_rows.append(row)
        add_table(
            "Intelligence Links",
            ["Type", "Indicator", "VirusTotal", "Talos", "RDAP", "WHOIS", "URLScan", "AbuseIPDB"],
            link_rows,
        )

        subject_flags = subject_analysis.get("subject_flags", []) or []
        add_key_values("Subject / Body Analysis", {
            "Subject": email_data.get("subject"),
            "Subject severity": subject_analysis.get("subject_severity"),
            "Subject score": subject_analysis.get("subject_score"),
            "Subject findings": "; ".join(map(str, subject_flags)) if subject_flags else "N/A",
        })
        add_key_values("Authentication", {
            "Authentication-Results": auth_results,
            "SPF result": (sender_intelligence.get("authentication", {}) or {}).get("spf"),
            "DKIM result": re.search(r"\bdkim\s*=\s*([a-z]+)", str(auth_results), re.IGNORECASE).group(1)
            if re.search(r"\bdkim\s*=\s*([a-z]+)", str(auth_results), re.IGNORECASE) else None,
            "DMARC result": (sender_intelligence.get("authentication", {}) or {}).get("dmarc"),
        })

        headers_focus = email_data.get("headers_focus", {}) or {}
        repeated_header_names = {"subject", "from", "to", "authentication-results", "received"}
        header_rows = [
            [key, display(value)] for key, value in headers_focus.items()
            if str(key).lower() not in repeated_header_names
        ]
        add_table("Headers / Mismatches", ["Header", "Value"], header_rows)
        add_table("Header Mismatch Findings", ["Check", "Result"], [[key, value] for key, value in mismatch.items()])

        hop_rows = []
        for index, hop in enumerate(email_data.get("received_hops", []) or [], start=1):
            hop_rows.append([
                index,
                hop.get("from", ""),
                hop.get("by", ""),
                hop.get("with", ""),
                hop.get("date", ""),
                hop.get("delay", ""),
            ])
        add_table("Received Hops", ["#", "From", "By", "With", "Date", "Delay"], hop_rows)

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
        whitelist_rows = []
        for item in email_data.get("ioc_scoring", []) or []:
            provider_context = self._normalize_provider_context(item.get("provider_context", {}) or {})
            value = str(item.get("normalized") or "")
            ioc_type = str(item.get("ioc_type") or "")
            abuse = provider_context.get("abuseipdb", {}) or {}
            urlscan = provider_context.get("urlscan", {}) or {}
            talos = provider_context.get("talos", {}) or {}
            ioc_rows.append([
                ioc_type, value, item.get("category"), item.get("vt_status", "Unknown"),
                format_vt_malicious(item.get("vt_malicious"), item.get("vt_status")),
                item.get("final_score"), "; ".join(self._dedup_reasons(item.get("reason", []) or [])),
                ", ".join(item.get("hash_sources", []) or []) if ioc_type == "hash" else "N/A",
                abuse.get("abuse_score", "N/A"), urlscan.get("status", "Unknown"),
                talos.get("status", "Unknown"),
                item.get("is_whitelisted"), item.get("is_blocklisted"),
            ])
            whitelist_rows.append([
                ioc_type, value, item.get("is_whitelisted"), item.get("is_blocklisted"),
                item.get("category"),
            ])
        add_table(
            "IOC Details",
            ["Type", "Indicator", "Verdict", "VT status", "VT malicious", "Score", "Reasons",
             "Hash source", "AbuseIPDB", "URLScan", "Talos", "Whitelisted", "Blocklisted"],
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

        whois_dns_rows = [
            [
                row["type"], row["indicator"], row.get("registrar"), row.get("created"),
                row.get("expires"), row.get("age_days"), row.get("nameservers"),
                row.get("status"), format_resolved_ips(row.get("resolved_ips")), row.get("mx"),
            ]
            for row in email_data.get("whois_rows", []) or []
        ]
        add_table(
            "WHOIS / RDAP / DNS", ["Type", "Indicator", "Registrar", "Created", "Expires", "Age days",
             "Nameservers", "WHOIS status", "Resolved IPs", "MX"], whois_dns_rows,
        )

        attachment_rows = []
        for attachment in email_data.get("attachments", []) or []:
            vt_hash = attachment.get("vt_hash", {}) or {}
            talos = attachment.get("talos", {}) or {}
            attachment_rows.append([
                ", ".join(attachment.get("filenames", []) or [attachment.get("filename", "N/A")]),
                attachment.get("size", attachment.get("length")),
                attachment.get("sha256"), vt_hash.get("vt_status"),
                format_vt_malicious(vt_hash.get("vt_malicious"), vt_hash.get("vt_status")),
                talos.get("status", "Unknown"),
            ])
        add_table(
            "Attachments", ["Filename", "Size bytes", "SHA256", "VT status", "VT malicious", "Talos status"],
            attachment_rows,
        )
        indicator_rows = []
        for indicator in email_data.get("report_indicators", []) or []:
            sender_data = indicator.get("sender", {}) or {}
            ioc_data = indicator.get("ioc", {}) or {}
            indicator_rows.append([
                indicator["type"], indicator["value"],
                sender_data.get("whitelisted", ioc_data.get("is_whitelisted", False)),
                sender_data.get("blocklisted", ioc_data.get("is_blocklisted", False)),
                ioc_data.get("category", sender_intelligence.get("verdict", "Unknown")),
            ])
        add_table(
            "Whitelist / Blocklist Findings",
            ["Type", "Indicator", "Whitelisted", "Blocklisted", "Verdict"],
            indicator_rows,
        )

        campaign_alert_rows = email_data.get("campaign_alert_findings", []) or []
        add_table("Campaign / Alert Findings", ["Finding", "Details"], campaign_alert_rows)

        add_key_values("Automated Threat Verdict / Score / Reasons", {
            "Automated verdict": severity,
            "Email score": email_data.get("email_score"),
            "Email reasons": "; ".join(map(str, email_data.get("email_score_reasons", []) or [])),
            "Sender verdict": sender_intelligence.get("verdict"),
            "Sender risk score": sender_intelligence.get("risk_score"),
        })
        add_key_values("Analyst Comments", {
            "Analyst comment": email_data.get("analyst_comment"),
        })
        selected_actions = email_data.get("selected_response_actions", [])
        add_key_values("Final Investigation / Response Actions", {
            "Finding": response_actions.get("finding"),
            "Action Taken": response_actions.get("action_taken"),
            "Recommendation": response_actions.get("recommendation"),
            "Final Analyst Verdict": response_actions.get("final_verdict"),
            "Selected Response Actions": ", ".join(selected_actions) if selected_actions else "None",
            "Response Notes": response_actions.get("response_notes"),
            "Submitted Time": response_actions.get("submitted_time") or email_data.get("submitted_time"),
        })
        if email_data.get("consistency_warnings"):
            add_table(
                "Verdict Consistency Warnings",
                ["Warning"],
                [[warning] for warning in email_data["consistency_warnings"]],
            )

        recommended_actions = list(email_data.get("recommended_actions", []) or [])
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
        if email_data.get("investigation_submitted") and not any(
            str(action).startswith("Final analyst verdict:") for action in recommended_actions
        ):
            recommended_actions.insert(
                0,
                f"Final analyst verdict: {response_actions.get('final_verdict') or 'Unknown'}; "
                f"selected actions: {', '.join(selected_actions) or 'None'}.",
            )
        add_table("Recommended Actions", ["#", "Action"], [
            [index, action] for index, action in enumerate(recommended_actions, start=1)
        ])

        headers_raw = email_data.get("headers_raw", {}) or {}
        if headers_raw:
            add_table("Appendix: Full Raw Headers", ["Header", "Value"], [
                [key, display(value)] for key, value in headers_raw.items()
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

        
