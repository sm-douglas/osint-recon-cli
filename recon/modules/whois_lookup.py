"""
whois_lookup.py — Domain registration data via RDAP (the modern WHOIS successor).

Uses the public RDAP bootstrap service (rdap.org), which requires no API key
and redirects transparently to the correct registry (Verisign, GoDaddy's
RDAP endpoint, etc.) for the given TLD.
"""

from ..utils import section, kv, warn, safe_get


def run(domain: str) -> None:
    section(f"RDAP / WHOIS — {domain}")

    resp = safe_get(f"https://rdap.org/domain/{domain}")
    if resp is None:
        return

    if resp.status_code == 404:
        warn("Domain not found in RDAP registry (may not be registered).")
        return
    if resp.status_code != 200:
        warn(f"RDAP lookup returned HTTP {resp.status_code}.")
        return

    try:
        data = resp.json()
    except ValueError:
        warn("RDAP response was not valid JSON.")
        return

    kv("Domain", data.get("ldhName", domain))

    events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
    if events.get("registration"):
        kv("Registered", events["registration"])
    if events.get("last changed"):
        kv("Last changed", events["last changed"])
    if events.get("expiration"):
        kv("Expires", events["expiration"])

    for entity in data.get("entities", []):
        roles = ", ".join(entity.get("roles", []))
        name = None
        for vcard_item in entity.get("vcardArray", [None, []])[1]:
            if vcard_item and vcard_item[0] == "fn":
                name = vcard_item[3]
        if name:
            kv(f"Entity ({roles})", name)

    nameservers = [ns.get("ldhName") for ns in data.get("nameservers", [])]
    if nameservers:
        kv("Nameservers", ", ".join(nameservers))

    secure_dns = data.get("secureDNS", {})
    if "delegationSigned" in secure_dns:
        kv("DNSSEC", "Yes" if secure_dns["delegationSigned"] else "No")

    status = data.get("status", [])
    if status:
        kv("Status", ", ".join(status))
