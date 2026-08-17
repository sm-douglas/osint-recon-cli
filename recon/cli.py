"""
cli.py > Command-line entry point for OSINT Recon CLI.

Usage examples:
    python -m recon domain example.com
    python -m recon domain example.com --whois --dns --ssl
    python -m recon ip 8.8.8.8
    python -m recon ip 8.8.8.8 --abuseipdb --shodan
    python -m recon url https://example.com --virustotal
"""

import argparse
import sys

from . import __version__
from .modules import (
    whois_lookup,
    dns_lookup,
    ip_info,
    abuseipdb,
    virustotal,
    shodan_lookup,
    ssl_check,
)
from .utils import is_valid_domain, is_valid_ip, error

BANNER = r"""
  ___  ____ ___ _   _ _____   ____                         ____ _     ___
 / _ \/ ___|_ _| \ | |_   _| |  _ \ ___  ___ ___  _ __     / ___| |   |_ _|
| | | \___ \| ||  \| | | |   | |_) / _ \/ __/ _ \| '_ \   | |   | |    | |
| |_| |___) | || |\  | | |   |  _ <  __/ (_| (_) | | | |  | |___| |___ | |
 \___/|____/___|_| \_| |_|   |_| \_\___|\___\___/|_| |_|   \____|_____|___|
"""

DISCLAIMER = (
    "This tool queries only public, third-party OSINT sources and performs\n"
    "no intrusive scanning. Use it only against targets you own or are\n"
    "explicitly authorized to investigate, and in compliance with the\n"
    "terms of service of each underlying API and applicable law."
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="recon",
        description="Modular OSINT reconnaissance CLI — domains, IPs, and URLs.",
    )
    parser.add_argument(
        "--version", action="version", version=f"osint-recon-cli {__version__}"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- domain ---
    domain_parser = subparsers.add_parser("domain", help="Investigate a domain name")
    domain_parser.add_argument("target", help="Domain name, e.g. example.com")
    domain_parser.add_argument("--whois", action="store_true", help="RDAP/WHOIS lookup")
    domain_parser.add_argument("--dns", action="store_true", help="DNS record lookup")
    domain_parser.add_argument("--ssl", action="store_true", help="TLS certificate inspection")
    domain_parser.add_argument(
        "--virustotal", action="store_true", help="VirusTotal domain reputation"
    )
    domain_parser.add_argument(
        "--all", action="store_true", help="Run every available check for this domain"
    )

    # --- ip ---
    ip_parser = subparsers.add_parser("ip", help="Investigate an IP address")
    ip_parser.add_argument("target", help="IPv4 or IPv6 address")
    ip_parser.add_argument("--geo", action="store_true", help="Geolocation / ASN info")
    ip_parser.add_argument("--abuseipdb", action="store_true", help="AbuseIPDB report history")
    ip_parser.add_argument("--shodan", action="store_true", help="Shodan open ports/services")
    ip_parser.add_argument(
        "--all", action="store_true", help="Run every available check for this IP"
    )

    # --- url ---
    url_parser = subparsers.add_parser("url", help="Investigate a full URL")
    url_parser.add_argument("target", help="Full URL, e.g. https://example.com/path")
    url_parser.add_argument(
        "--virustotal", action="store_true", help="VirusTotal URL reputation"
    )
    url_parser.add_argument(
        "--all", action="store_true", help="Run every available check for this URL"
    )

    return parser


def run_domain(args: argparse.Namespace) -> int:
    domain = args.target.strip().lower().removeprefix("http://").removeprefix("https://").split("/")[0]
    if not is_valid_domain(domain):
        error(f"'{args.target}' does not look like a valid domain name.")
        return 1

    run_all = args.all or not any([args.whois, args.dns, args.ssl, args.virustotal])

    if args.whois or run_all:
        whois_lookup.run(domain)
    if args.dns or run_all:
        dns_lookup.run(domain)
    if args.ssl or run_all:
        ssl_check.run(domain)
    if args.virustotal or run_all:
        virustotal.run(domain, is_url=False)
    return 0


def run_ip(args: argparse.Namespace) -> int:
    ip = args.target.strip()
    if is_valid_ip(ip) is None:
        error(f"'{ip}' is not a valid IP address.")
        return 1

    run_all = args.all or not any([args.geo, args.abuseipdb, args.shodan])

    if args.geo or run_all:
        ip_info.run(ip)
    if args.abuseipdb or run_all:
        abuseipdb.run(ip)
    if args.shodan or run_all:
        shodan_lookup.run(ip)
    return 0


def run_url(args: argparse.Namespace) -> int:
    url = args.target.strip()
    if not (url.startswith("http://") or url.startswith("https://")):
        error("URL must start with http:// or https://")
        return 1

    run_all = args.all or not any([args.virustotal])

    if args.virustotal or run_all:
        virustotal.run(url, is_url=True)
    return 0


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    print(BANNER)
    print(DISCLAIMER)

    try:
        if args.command == "domain":
            return run_domain(args)
        if args.command == "ip":
            return run_ip(args)
        if args.command == "url":
            return run_url(args)
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        return 130

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
