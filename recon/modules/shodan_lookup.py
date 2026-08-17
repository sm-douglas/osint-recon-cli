"""
shodan_lookup.py — Open ports and service banners for an IP via Shodan.

Requires a free API key from https://account.shodan.io/register
Set it as the SHODAN_API_KEY environment variable — never hardcode it here.
"""

from ..config import settings, missing_key_warning
from ..utils import section, kv, warn, safe_get, is_valid_ip

API_URL = "https://api.shodan.io/shodan/host/{ip}"


def run(ip: str) -> None:
    section(f"Shodan — {ip}")

    scope = is_valid_ip(ip)
    if scope is None:
        warn("Invalid IP address.")
        return
    if scope == "private":
        warn("Private/reserved IP address — skipping Shodan check.")
        return

    if not settings.has("shodan_key"):
        print(missing_key_warning("Shodan", "SHODAN_API_KEY"))
        return

    params = {"key": settings.shodan_key}
    resp = safe_get(API_URL.format(ip=ip), params=params)
    if resp is None:
        return
    if resp.status_code == 401:
        warn("Shodan rejected the API key (401 Unauthorized). Check SHODAN_API_KEY.")
        return
    if resp.status_code == 404:
        warn("No Shodan data available for this IP.")
        return
    if resp.status_code != 200:
        warn(f"Shodan returned HTTP {resp.status_code}.")
        return

    data = resp.json()
    kv("Organization", data.get("org", "-"))
    kv("Operating System", data.get("os") or "-")
    kv("Open ports", ", ".join(str(p) for p in sorted(data.get("ports", []))))

    for service in data.get("data", [])[:10]:
        port = service.get("port")
        product = service.get("product", "")
        banner_line = f"{product}".strip() or service.get("data", "").splitlines()[0][:80]
        print(f"    - port {port}: {banner_line}")
