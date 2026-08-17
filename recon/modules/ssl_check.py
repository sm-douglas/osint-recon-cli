"""
ssl_check.py — TLS certificate inspection using Python's standard library.

Connects directly to the target on port 443 and reads the certificate it
presents. No third-party API or key is used or required.
"""

import socket
import ssl
from datetime import datetime, timezone

from ..utils import section, kv, warn


def _parse_name(name_tuples) -> str:
    parts = []
    for rdn in name_tuples:
        for key, value in rdn:
            parts.append(f"{key}={value}")
    return ", ".join(parts)


def run(domain: str, port: int = 443, timeout: int = 10) -> None:
    section(f"SSL Certificate — {domain}:{port}")

    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
    except socket.timeout:
        warn(f"Connection to {domain}:{port} timed out.")
        return
    except socket.gaierror:
        warn(f"Could not resolve {domain}.")
        return
    except ssl.SSLCertVerificationError as exc:
        warn(f"Certificate verification failed: {exc.verify_message}")
        return
    except (ConnectionRefusedError, OSError) as exc:
        warn(f"Could not connect to {domain}:{port}: {exc}")
        return

    subject = _parse_name(cert.get("subject", []))
    issuer = _parse_name(cert.get("issuer", []))
    kv("Subject", subject or "-")
    kv("Issuer", issuer or "-")

    not_before = cert.get("notBefore")
    not_after = cert.get("notAfter")
    kv("Valid from", not_before or "-")
    kv("Valid until", not_after or "-")

    if not_after:
        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
            days_left = (expiry - datetime.now(timezone.utc)).days
            if days_left < 0:
                warn("Certificate has EXPIRED.")
            elif days_left < 15:
                warn(f"Certificate expires very soon ({days_left} days).")
            else:
                kv("Days until expiry", days_left)
        except ValueError:
            pass

    alt_names = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
    if alt_names:
        kv("Alternative names", ", ".join(alt_names))

    if cipher:
        kv("Cipher suite", f"{cipher[0]} ({cipher[1]}, {cipher[2]} bits)")
