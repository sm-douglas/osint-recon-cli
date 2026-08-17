"""
virustotal.py — URL/domain reputation check via the VirusTotal v3 API.

Requires a free API key from https://www.virustotal.com/gui/join-us
Set it as the VIRUSTOTAL_API_KEY environment variable — never hardcode it here.
"""

import base64

from ..config import settings, missing_key_warning
from ..utils import section, kv, warn, safe_get

API_BASE = "https://www.virustotal.com/api/v3"


def _url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def run(target: str, is_url: bool = False) -> None:
    label = target if not is_url else target
    section(f"VirusTotal — {label}")

    if not settings.has("virustotal_key"):
        print(missing_key_warning("VirusTotal", "VIRUSTOTAL_API_KEY"))
        return

    headers = {"x-apikey": settings.virustotal_key}

    if is_url:
        endpoint = f"{API_BASE}/urls/{_url_id(target)}"
    else:
        endpoint = f"{API_BASE}/domains/{target}"

    resp = safe_get(endpoint, headers=headers)
    if resp is None:
        return
    if resp.status_code == 401:
        warn("VirusTotal rejected the API key (401 Unauthorized). Check VIRUSTOTAL_API_KEY.")
        return
    if resp.status_code == 404:
        warn("Target not found in VirusTotal's database yet.")
        return
    if resp.status_code != 200:
        warn(f"VirusTotal returned HTTP {resp.status_code}.")
        return

    attrs = resp.json().get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})

    kv("Malicious", stats.get("malicious", 0))
    kv("Suspicious", stats.get("suspicious", 0))
    kv("Harmless", stats.get("harmless", 0))
    kv("Undetected", stats.get("undetected", 0))

    reputation = attrs.get("reputation")
    if reputation is not None:
        kv("Community reputation", reputation)

    categories = attrs.get("categories", {})
    if categories:
        kv("Categories", ", ".join(f"{k}: {v}" for k, v in categories.items()))
