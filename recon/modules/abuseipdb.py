"""
abuseipdb.py — Abuse report history for an IP via the AbuseIPDB API.

Requires a free API key from https://www.abuseipdb.com/account/api
Set it as the ABUSEIPDB_API_KEY environment variable — never hardcode it here.
"""

from ..config import settings, missing_key_warning
from ..utils import section, kv, warn, safe_get, is_valid_ip

API_URL = "https://api.abuseipdb.com/api/v2/check"


def run(ip: str) -> None:
    section(f"AbuseIPDB — {ip}")

    scope = is_valid_ip(ip)
    if scope is None:
        warn("Invalid IP address.")
        return
    if scope == "private":
        warn("Private/reserved IP address — skipping abuse database check.")
        return

    if not settings.has("abuseipdb_key"):
        print(missing_key_warning("AbuseIPDB", "ABUSEIPDB_API_KEY"))
        return

    headers = {"Key": settings.abuseipdb_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 365, "verbose": ""}

    resp = safe_get(API_URL, headers=headers, params=params)
    if resp is None:
        return
    if resp.status_code == 401:
        warn("AbuseIPDB rejected the API key (401 Unauthorized). Check ABUSEIPDB_API_KEY.")
        return
    if resp.status_code != 200:
        warn(f"AbuseIPDB returned HTTP {resp.status_code}.")
        return

    data = resp.json().get("data", {})
    kv("Abuse confidence score", f"{data.get('abuseConfidenceScore', 0)}%")
    kv("Total reports", data.get("totalReports", 0))
    kv("Distinct reporters", data.get("numDistinctUsers", 0))
    kv("ISP", data.get("isp", "-"))
    kv("Domain", data.get("domain", "-"))
    kv("Country", data.get("countryCode", "-"))
    kv("Last reported", data.get("lastReportedAt", "never"))

    reports = data.get("reports", [])
    if reports:
        print("\n  Recent reports:")
        for r in reports[:5]:
            categories = ", ".join(str(c) for c in r.get("categories", []))
            print(f"    - {r.get('reportedAt', '?')}  [{categories}]")
