"""
app.py — A simple browser-based interface for OSINT Recon CLI.

Runs entirely on your own machine (no data leaves your computer except the
requests each module already makes to its respective public API). Built for
people who prefer clicking buttons over typing terminal commands — it wraps
the exact same modules used by the command-line tool, so results are
identical either way.

Run with:
    streamlit run app.py
"""

import contextlib
import io
import sys
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent))

from recon.config import settings
from recon.modules import (
    whois_lookup,
    dns_lookup,
    ssl_check,
    virustotal,
    ip_info,
    abuseipdb,
    shodan_lookup,
)
from recon.utils import is_valid_domain, is_valid_ip

try:
    import dns.resolver
except ImportError:
    dns = None


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def run_captured(fn, *args, **kwargs) -> str:
    """Call a recon module's run() function and capture everything it
    printed, so it can be rendered inside the Streamlit page instead of a
    terminal."""
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(buffer):
        try:
            fn(*args, **kwargs)
        except Exception as exc:  # noqa: BLE001 — surface unexpected errors in the UI itself
            buffer.write(f"\n[x] Unexpected error: {exc}\n")
    return buffer.getvalue()


def resolve_ips(domain: str) -> list[str]:
    if dns is None:
        return []
    try:
        resolver = dns.resolver.Resolver(configure=True)
        resolver.timeout = 5
        resolver.lifetime = 5
        answers = resolver.resolve(domain, "A")
        return [str(rdata).strip() for rdata in answers]
    except Exception:
        return []


def render_output(title: str, text: str) -> None:
    with st.expander(title, expanded=True):
        st.code(text.strip() or "(no output)", language=None)


def key_badge(label: str, has_key: bool) -> str:
    icon = "🟢" if has_key else "⚪"
    status = "configured" if has_key else "not set — check will be skipped"
    return f"{icon} **{label}** — {status}"


# --------------------------------------------------------------------------
# Page setup
# --------------------------------------------------------------------------

st.set_page_config(page_title="OSINT Recon", page_icon="🔍", layout="wide")

st.title("🔍 OSINT Recon")
st.caption(
    "A friendly interface for the OSINT Recon CLI. Runs locally on your "
    "machine — nothing is sent anywhere except the requests each check "
    "already makes to its own public API."
)

with st.sidebar:
    st.header("API keys")
    st.caption("Configured via your `.env` file. No key is required to use this tool.")
    st.markdown(key_badge("AbuseIPDB", settings.has("abuseipdb_key")))
    st.markdown(key_badge("VirusTotal", settings.has("virustotal_key")))
    st.markdown(key_badge("Shodan", settings.has("shodan_key")))
    st.markdown(key_badge("ipinfo.io", settings.has("ipinfo_key")))
    st.divider()
    st.caption(
        "⚠️ Only investigate targets you own or are explicitly authorized "
        "to assess. Respect each API's Terms of Service and applicable law."
    )

tab_domain, tab_ip, tab_url, tab_full = st.tabs(
    ["🌐 Domain", "📡 IP Address", "🔗 URL", "🧩 Full scan"]
)

# --------------------------------------------------------------------------
# Domain tab
# --------------------------------------------------------------------------

with tab_domain:
    st.subheader("Investigate a domain")
    domain_input = st.text_input(
        "Domain", placeholder="example.com", key="domain_target"
    )

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        chk_whois = st.checkbox("WHOIS / RDAP", value=True, key="d_whois")
    with col2:
        chk_dns = st.checkbox("DNS records", value=True, key="d_dns")
    with col3:
        chk_ssl = st.checkbox("SSL certificate", value=True, key="d_ssl")
    with col4:
        chk_vt = st.checkbox("VirusTotal", value=True, key="d_vt")

    if st.button("Run checks", type="primary", key="run_domain"):
        clean_domain = domain_input.strip().lower()
        if not is_valid_domain(clean_domain):
            st.error(f"'{domain_input}' does not look like a valid domain.")
        else:
            with st.spinner(f"Investigating {clean_domain}..."):
                if chk_whois:
                    render_output("WHOIS / RDAP", run_captured(whois_lookup.run, clean_domain))
                if chk_dns:
                    render_output("DNS Records", run_captured(dns_lookup.run, clean_domain))
                if chk_ssl:
                    render_output("SSL Certificate", run_captured(ssl_check.run, clean_domain))
                if chk_vt:
                    render_output(
                        "VirusTotal",
                        run_captured(virustotal.run, clean_domain, is_url=False),
                    )
            st.success("Done.")

# --------------------------------------------------------------------------
# IP tab
# --------------------------------------------------------------------------

with tab_ip:
    st.subheader("Investigate an IP address")
    ip_input = st.text_input("IP address", placeholder="8.8.8.8", key="ip_target")

    col1, col2, col3 = st.columns(3)
    with col1:
        chk_geo = st.checkbox("Geolocation", value=True, key="i_geo")
    with col2:
        chk_abuse = st.checkbox("AbuseIPDB", value=True, key="i_abuse")
    with col3:
        chk_shodan = st.checkbox("Shodan", value=True, key="i_shodan")

    if st.button("Run checks", type="primary", key="run_ip"):
        clean_ip = ip_input.strip()
        if is_valid_ip(clean_ip) is None:
            st.error(f"'{ip_input}' is not a valid IP address.")
        else:
            with st.spinner(f"Investigating {clean_ip}..."):
                if chk_geo:
                    render_output("IP Info", run_captured(ip_info.run, clean_ip))
                if chk_abuse:
                    render_output("AbuseIPDB", run_captured(abuseipdb.run, clean_ip))
                if chk_shodan:
                    render_output("Shodan", run_captured(shodan_lookup.run, clean_ip))
            st.success("Done.")

# --------------------------------------------------------------------------
# URL tab
# --------------------------------------------------------------------------

with tab_url:
    st.subheader("Investigate a URL")
    url_input = st.text_input(
        "Full URL", placeholder="https://example.com/path", key="url_target"
    )

    if st.button("Run VirusTotal check", type="primary", key="run_url"):
        clean_url = url_input.strip()
        if not (clean_url.startswith("http://") or clean_url.startswith("https://")):
            st.error("URL must start with http:// or https://")
        else:
            with st.spinner(f"Checking {clean_url}..."):
                render_output(
                    "VirusTotal", run_captured(virustotal.run, clean_url, is_url=True)
                )
            st.success("Done.")

# --------------------------------------------------------------------------
# Full scan tab
# --------------------------------------------------------------------------

with tab_full:
    st.subheader("Full scan — domain, subdomains, and every resolved IP")
    st.caption(
        "Runs every domain-level check on the base domain and any subdomains "
        "you list, then automatically resolves and scans every IP found."
    )
    full_domain = st.text_input(
        "Base domain", placeholder="santgreen.com", key="full_domain"
    )
    full_subdomains = st.text_input(
        "Subdomain prefixes (comma-separated, optional)",
        placeholder="app,play",
        key="full_subdomains",
    )

    if st.button("Run full scan", type="primary", key="run_full"):
        base = full_domain.strip().lower()
        if not is_valid_domain(base):
            st.error(f"'{full_domain}' does not look like a valid domain.")
        else:
            prefixes = [p.strip() for p in full_subdomains.split(",") if p.strip()]
            targets = [base] + [f"{p}.{base}" for p in prefixes]

            all_ips: set[str] = set()

            for target in targets:
                if not is_valid_domain(target):
                    st.warning(f"Skipping invalid target: {target}")
                    continue

                st.markdown(f"### 🎯 {target}")
                with st.spinner(f"Scanning {target}..."):
                    render_output("WHOIS / RDAP", run_captured(whois_lookup.run, target))
                    render_output("DNS Records", run_captured(dns_lookup.run, target))
                    render_output("SSL Certificate", run_captured(ssl_check.run, target))
                    render_output(
                        "VirusTotal (domain)",
                        run_captured(virustotal.run, target, is_url=False),
                    )
                    render_output(
                        "VirusTotal (URL)",
                        run_captured(virustotal.run, f"https://{target}", is_url=True),
                    )
                all_ips.update(resolve_ips(target))

            if all_ips:
                st.markdown(f"### 📡 Resolved IPs: {', '.join(sorted(all_ips))}")
                for ip in sorted(all_ips):
                    st.markdown(f"#### {ip}")
                    with st.spinner(f"Scanning {ip}..."):
                        render_output("IP Info", run_captured(ip_info.run, ip))
                        render_output("AbuseIPDB", run_captured(abuseipdb.run, ip))
                        render_output("Shodan", run_captured(shodan_lookup.run, ip))
            else:
                st.info("No IPs were resolved — skipping IP-based checks.")

            st.success("Full scan complete.")
