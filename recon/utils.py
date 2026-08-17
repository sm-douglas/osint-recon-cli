"""
utils.py > Shared helpers: input validation, safe HTTP requests, and output formatting.

Input validation exists so the tool only ever queries third-party APIs with
well-formed domains/IPs, this avoids malformed requests, accidental
querying of internal/private addresses, and keeps the tool's behavior
predictable and auditable.
"""

import ipaddress
import re
import sys
from typing import Optional

import requests

from .config import settings

DOMAIN_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def is_valid_domain(value: str) -> bool:
    if not value or len(value) > 253:
        return False
    return bool(DOMAIN_RE.match(value.strip().lower()))

def clean_domain_input(value: str) -> str:
    """
    Normalize user input into a bare domain: strips scheme (http/https),
    any path/query/fragment, a trailing dot, and surrounding whitespace.
    Accepts both "example.com" and "https://example.com/some/path?x=1"
    and returns "example.com" in either case.
    """
    cleaned = value.strip().lower()
    cleaned = re.sub(r"^https?://", "", cleaned)
    cleaned = cleaned.split("/")[0]
    cleaned = cleaned.split("?")[0]
    cleaned = cleaned.split("#")[0]
    cleaned = cleaned.rstrip(".")
    return cleaned


def clean_domain_input(value: str) -> str:
    """
    Normalize user input into a bare domain: strips scheme (http/https),
    any path/query/fragment, a trailing dot, and surrounding whitespace.
    Accepts both "example.com" and "https://example.com/some/path?x=1"
    and returns "example.com" in either case.
    """
    cleaned = value.strip().lower()
    cleaned = re.sub(r"^https?://", "", cleaned)
    cleaned = cleaned.split("/")[0]
    cleaned = cleaned.split("?")[0]
    cleaned = cleaned.split("#")[0]
    cleaned = cleaned.rstrip(".")
    return cleaned


def is_valid_ip(value: str) -> Optional[str]:
    """Returns 'private' or 'public' if valid, None if invalid."""
    try:
        ip_obj = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
        return "private"
    return "public"


def safe_get(url: str, headers: Optional[dict] = None, params: Optional[dict] = None):
    """
    Wrapper around requests.get with a timeout, a fixed User-Agent, and
    consistent error handling so no module has to duplicate try/except
    boilerplate or risk a hanging connection.
    """
    final_headers = {"User-Agent": settings.user_agent}
    if headers:
        final_headers.update(headers)
    try:
        response = requests.get(
            url,
            headers=final_headers,
            params=params,
            timeout=settings.request_timeout,
        )
        return response
    except requests.exceptions.Timeout:
        print(f"[!] Request to {url} timed out after {settings.request_timeout}s.")
    except requests.exceptions.ConnectionError:
        print(f"[!] Could not connect to {url}. Check your network connection.")
    except requests.exceptions.RequestException as exc:
        print(f"[!] Request to {url} failed: {exc}")
    return None


def section(title: str) -> None:
    bar = "-" * min(len(title) + 4, 70)
    print(f"\n{bar}\n  {title}\n{bar}")


def kv(key: str, value) -> None:
    print(f"  {key:<28} {value}")


def warn(msg: str) -> None:
    print(f"  [!] {msg}", file=sys.stderr)


def error(msg: str) -> None:
    print(f"[x] {msg}", file=sys.stderr)
