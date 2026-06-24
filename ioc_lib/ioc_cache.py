import json
import os
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

# ------------------------------------------------------------
# CONFIG
# ------------------------------------------------------------
CACHE_FILE = "reports/ioc_cache.json"   # unified cache file
EXPIRY_HOURS = 48                       # re-analyze after 48 hours


# ------------------------------------------------------------
# LOAD CACHE
# ------------------------------------------------------------
def load_cache() -> Dict[str, Any]:
    """
    Load cache safely.
    - Returns empty dict if file does not exist
    - Self-heals if JSON is corrupted
    """
    if not os.path.exists(CACHE_FILE):
        return {}

    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        # corrupted file → reset
        return {}


# ------------------------------------------------------------
# SAVE CACHE
# ------------------------------------------------------------
def save_cache(cache: Dict[str, Any]) -> None:
    """
    Save cache safely.
    """
    os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)

    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2)


# ------------------------------------------------------------
# GET CACHE ENTRY
# ------------------------------------------------------------
def get_cached(ioc_type: str, value: str) -> Optional[Dict[str, Any]]:
    """
    Get cached IOC result.

    Logic:
    IF IOC NOT in cache → analyze
    IF IOC in cache AND < 48 hrs → use cache
    IF IOC in cache BUT > 48 hrs → reanalyze
    """

    cache = load_cache()
    key = f"{ioc_type}:{value}"

    entry = cache.get(key)

    # Not in cache → reanalyz
    if not entry:
        print(f"[CACHE MISS] {value}")
        return None

    try:
        last_checked = datetime.fromisoformat(entry["timestamp"])
    except Exception:
        return None
    
    # if older than 48h -> reanalyze
    if datetime.now() - last_checked > timedelta(hours=EXPIRY_HOURS):
        print(f"[CACHE MISS] {value}")
        return None
    
    # Use Cache
    print(f"[CACHE Data used] {value}")
    return entry.get("data")

    # ------------------------------------------------------------
    # EXPIRY CHECK ✅
    # ------------------------------------------------------------
    if datetime.now() - last_checked > timedelta(hours=EXPIRY_HOURS):
        print(f"[CACHE EXPIRED ⏰] {value}")
        return None

    print(f"[CACHE HIT ✅] {value}")
    return entry.get("data")


# ------------------------------------------------------------
# SET CACHE ENTRY
# ------------------------------------------------------------
def set_cache(ioc_type: str, value: str, data: Dict[str, Any]) -> None:
    """
    Store FULL IOC result.

    Stored structure:
    {
      "timestamp": "...",
      "data": {
         vt_malicious,
         vt_status,
         final_score,
         category,
         reason,
         provider_context
      }
    }
    """

    cache = load_cache()
    key = f"{ioc_type}:{value}"

    cache[key] = {
        "timestamp": datetime.now().isoformat(),
        "data": data
    }

    save_cache(cache)

    print(f"[CACHE SAVED 💾] {value}")