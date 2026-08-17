"""
dns_lookup.py > A/AAAA/MX/NS/TXT/CNAME/SOA resolution via dnspython, with a
DNS-over-HTTPS (DoH) fallback for networks that block traditional DNS.

No third-party API or key required.

Resolution strategy, in order:
    1. System-configured resolver over UDP (port 53)
    2. System-configured resolver over TCP (port 53)
    3. Public resolvers (Cloudflare, Google) over UDP (port 53)
    4. Public resolvers (Cloudflare, Google) over TCP (port 53)
    5. DNS-over-HTTPS via Cloudflare's JSON API (port 443)

Step 5 exists because some corporate networks, VPNs, and antivirus products
block all outbound traffic on port 53 (both UDP and TCP) while still
allowing normal HTTPS traffic. Since DoH rides over HTTPS, it works even on
those restrictive networks.
"""

from ..utils import section, kv, warn, safe_get

try:
    import dns.resolver
    import dns.exception
except ImportError:
    dns = None

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
FALLBACK_NAMESERVERS = ["1.1.1.1", "8.8.8.8"]  # Cloudflare, Google

DOH_ENDPOINTS = [
    {"url": "https://cloudflare-dns.com/dns-query", "headers": {"accept": "application/dns-json"}},
    {"url": "https://dns.google/resolve", "headers": {}},
]


def _build_resolver(nameservers=None) -> "dns.resolver.Resolver":
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = 5
    resolver.lifetime = 5
    if nameservers:
        resolver.nameservers = nameservers
    return resolver


def _resolve_classic(domain: str, record_type: str):
    """Traditional DNS over UDP/TCP, trying system then public resolvers."""
    attempts = [
        {"nameservers": None, "tcp": False},
        {"nameservers": None, "tcp": True},
        {"nameservers": FALLBACK_NAMESERVERS, "tcp": False},
        {"nameservers": FALLBACK_NAMESERVERS, "tcp": True},
    ]
    last_exc = None
    for attempt in attempts:
        resolver = _build_resolver(nameservers=attempt["nameservers"])
        try:
            return resolver.resolve(domain, record_type, tcp=attempt["tcp"])
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            raise
        except Exception as exc:  # noqa: BLE001 — try the next strategy
            last_exc = exc
            continue
    raise last_exc


def _resolve_doh(domain: str, record_type: str):
    """
    DNS-over-HTTPS fallback. Tries Cloudflare's JSON API first, then
    Google's, since both expose a compatible response format. Returns a
    list of formatted strings (already human-readable), or None if nothing
    was found. Raises RuntimeError only if every provider fails.
    """
    last_error = None
    for provider in DOH_ENDPOINTS:
        resp = safe_get(
            provider["url"],
            headers=provider["headers"],
            params={"name": domain, "type": record_type},
        )
        if resp is None or resp.status_code != 200:
            last_error = f"{provider['url']} unreachable or non-200"
            continue

        try:
            data = resp.json()
        except ValueError:
            last_error = f"{provider['url']} returned invalid JSON"
            continue

        if data.get("Status") != 0:
            return None  # NXDOMAIN or no answer — a definitive answer, not a failure

        answers = data.get("Answer", [])
        if not answers:
            return None

        return [a.get("data", "").strip() for a in answers]

    raise RuntimeError(last_error or "all DoH providers failed")


def run(domain: str) -> None:
    section(f"DNS Records — {domain}")

    if dns is None:
        warn("dnspython is not installed. Run: pip install dnspython")
        return

    found_any = False
    classic_blocked_count = 0

    for record_type in RECORD_TYPES:
        # --- Tier 1: classic DNS (UDP/TCP, system + public resolvers) ---
        try:
            answers = _resolve_classic(domain, record_type)
            values = [str(rdata).strip() for rdata in answers]
            kv(record_type, "; ".join(values))
            found_any = True
            continue
        except dns.resolver.NoAnswer:
            continue
        except dns.resolver.NXDOMAIN:
            warn(f"{domain} does not exist (NXDOMAIN).")
            return
        except Exception:  # noqa: BLE001 — fall through to DoH
            classic_blocked_count += 1

        # --- Tier 2: DNS-over-HTTPS (works even if port 53 is blocked) ---
        try:
            values = _resolve_doh(domain, record_type)
            if values:
                kv(f"{record_type} (via DoH)", "; ".join(values))
                found_any = True
        except RuntimeError:
            warn(f"{record_type} query failed on both classic DNS and DoH.")

    if classic_blocked_count >= len(RECORD_TYPES) - 1:
        warn(
            "Classic DNS (port 53) appears to be blocked on this network "
            "(firewall/VPN/antivirus), results above were retrieved via "
            "DNS-over-HTTPS (port 443) instead."
        )

    if not found_any:
        warn("No DNS records could be retrieved for the queried types.")
