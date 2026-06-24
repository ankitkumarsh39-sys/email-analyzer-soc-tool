import os
import ipaddress
import requests
import datetime as dt

WHOIS_CACHE = {}

def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address((value or "").strip())
        return True
    except ValueError:
        return False

def whois_lookup(domain: str, force_refresh: bool = False) -> dict:
    """
    WHOISJSON lookup for domain intelligence
    """

    try:
        domain = (domain or "").strip().lower().rstrip(".")

        if not domain:
            return {"status": "invalid_domain"}

        if is_ip(domain):
            return {
                "status": "not_applicable",
                "reason": "ip_address"
            }

        cache_key = (domain, force_refresh)
        if cache_key in WHOIS_CACHE:
            return WHOIS_CACHE[cache_key]

        api_key = os.getenv("WHOISJSON_API_KEY")
        if not api_key:
            return {"status": "no_api_key"}

        url = "https://whoisjson.com/api/v1/whois"
        headers = {
            "Authorization": f"TOKEN={api_key}"
        }
        params = {
            "domain": domain
        }

        if force_refresh:
            params["_forceRefresh"] = 1

        r = requests.get(url, headers=headers, params=params, timeout=15)

        if r.status_code != 200:
            return {
                "status": f"failed_{r.status_code}",
                "body": r.text[:500]
            }

        payload = r.json()

        if not isinstance(payload, dict) or not payload:
            return {
                "status": "no_data",
                "reason": "whois_not_supported_or_empty",
                "raw": payload
            }

        registrar_obj = payload.get("registrar") or {}
        if not isinstance(registrar_obj, dict):
            registrar_obj = {}

        created = payload.get("created")
        expires = payload.get("expires")
        nameservers = payload.get("nameserver") or []
        if not isinstance(nameservers, list):
            nameservers = [nameservers]

        registrar = registrar_obj.get("name")

        age_days = None
        if created:
            try:
                created_dt = dt.datetime.fromisoformat(created.replace("Z", "+00:00"))
                if created_dt.tzinfo is None:
                    created_dt = created_dt.replace(tzinfo=dt.timezone.utc)

                now = dt.datetime.now(dt.timezone.utc)
                age_days = (now - created_dt).days

                if age_days < 0:
                    age_days = None

            except Exception as parse_err:
                return {
                    "status": "error",
                    "error": f"date_parse_failed: {str(parse_err)}",
                    "created_raw": created
                }

        result = {
            "status": "ok",
            "created": created,
            "age_days": age_days,
            "registrar": registrar,
            "expires": expires,
            "nameservers": nameservers,
            "remaining_requests": r.headers.get("Remaining-Requests")
        }

        WHOIS_CACHE[cache_key] = result
        return result

    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }
    