"""
full_scan.py > Runs every available check against a target in one go.

This is an example/utility script that chains all recon modules together
for a full investigation instead of calling the CLI multiple times by hand.
It resolves the domain's IP automatically so IP-based checks (AbuseIPDB,
Shodan, geolocation) run against the correct address without you having to
look it up separately.

Usage:
    python scripts/full_scan.py example.com
    python scripts/full_scan.py example.com --subdomains app,play

This will run, for the base domain and each subdomain given:
    - WHOIS/RDAP
    - DNS records
    - SSL certificate
    - VirusTotal domain reputation
    - VirusTotal URL reputation (https://<subdomain>.<domain>)
    - IP geolocation, AbuseIPDB, and Shodan for every resolved IP
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from recon.modules import (
    whois_lookup,
    dns_lookup,
    ssl_check,
    virustotal,
    ip_info,
    abuseipdb,
    shodan_lookup,
)
from recon.utils import is_valid_domain, clean_domain_input, error

try:
    import dns.resolver
except ImportError:
    print("dnspython is required. Run: pip install -r requirements.txt")
    sys.exit(1)


def resolve_ips(domain: str) -> list[str]:
    """Return the list of A-record IPs for a domain, or an empty list."""
    try:
        resolver = dns.resolver.Resolver(configure=True)
        resolver.timeout = 5
        resolver.lifetime = 5
        answers = resolver.resolve(domain, "A")
        return [str(rdata).strip() for rdata in answers]
    except Exception:
        return []


def scan_domain(domain: str) -> list[str]:
    """Run every domain-level check and return the resolved IPs."""
    print(f"\n{'#' * 70}\n#  TARGET: {domain}\n{'#' * 70}")

    whois_lookup.run(domain)
    dns_lookup.run(domain)
    ssl_check.run(domain)
    virustotal.run(domain, is_url=False)
    virustotal.run(f"https://{domain}", is_url=True)

    return resolve_ips(domain)


def scan_ip(ip: str) -> None:
    print(f"\n{'-' * 70}\n  IP-based checks for {ip}\n{'-' * 70}")
    ip_info.run(ip)
    abuseipdb.run(ip)
    shodan_lookup.run(ip)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run a full OSINT scan (all modules) against a domain and its subdomains."
    )
    parser.add_argument("domain", help="Base domain, e.g. santgreen.com")
    parser.add_argument(
        "--subdomains",
        default="",
        help="Comma-separated subdomain prefixes to also scan, e.g. app,play",
    )
    args = parser.parse_args()

    base_domain = clean_domain_input(args.domain)
    if not is_valid_domain(base_domain):
        error(f"'{base_domain}' is not a valid domain.")
        return 1

    targets = [base_domain]
    if args.subdomains:
        prefixes = [p.strip() for p in args.subdomains.split(",") if p.strip()]
        targets += [f"{prefix}.{base_domain}" for prefix in prefixes]

    all_ips: set[str] = set()

    for target in targets:
        if not is_valid_domain(target):
            error(f"Skipping invalid target: {target}")
            continue
        ips = scan_domain(target)
        all_ips.update(ips)

    if all_ips:
        print(f"\n{'#' * 70}\n#  RESOLVED IPs: {', '.join(sorted(all_ips))}\n{'#' * 70}")
        for ip in sorted(all_ips):
            scan_ip(ip)
    else:
        print("\n[!] No IPs were resolved for any target, skipping IP-based checks.")

    print(f"\n{'#' * 70}\n#  SCAN COMPLETE\n{'#' * 70}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
