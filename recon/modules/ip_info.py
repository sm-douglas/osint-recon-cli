"""
ip_info.py — IP geolocation and ASN/organization info via ipinfo.io.

Works without an API key (rate-limited free tier). If IPINFO_API_KEY is set,
it is used to raise the rate limit — never required for basic usage.
"""

from ..config import settings
from ..utils import section, kv, warn, safe_get, is_valid_ip


def run(ip: str) -> None:
    section(f"IP Info — {ip}")

    scope = is_valid_ip(ip)
    if scope is None:
        warn("Invalid IP address.")
        return
    if scope == "private":
        warn("This is a private/reserved IP address — public geolocation data does not apply.")
        return

    params = {}
    if settings.has("ipinfo_key"):
        params["token"] = settings.ipinfo_key

    resp = safe_get(f"https://ipinfo.io/{ip}/json", params=params)
    if resp is None:
        return
    if resp.status_code != 200:
        warn(f"ipinfo.io returned HTTP {resp.status_code}.")
        return

    data = resp.json()
    kv("IP", data.get("ip", ip))
    kv("Hostname", data.get("hostname", "-"))
    kv("Organization", data.get("org", "-"))
    location = ", ".join(
        filter(None, [data.get("city"), data.get("region"), data.get("country")])
    )
    kv("Location", location or "-")
    kv("Coordinates", data.get("loc", "-"))
    kv("Timezone", data.get("timezone", "-"))

    if not settings.has("ipinfo_key"):
        warn("Using ipinfo.io free tier (no API key set) — results may be rate-limited.")
