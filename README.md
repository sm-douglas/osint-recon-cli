# OSINT Recon CLI

A modular, key-optional command-line tool for open-source intelligence (OSINT)
reconnaissance on domains, IP addresses, and URLs, built for security
analysts, IT professionals, and researchers who need a quick, scriptable way
to pull together public intelligence from multiple sources in one place.

```
  ___  ____ ___ _   _ _____   ____                         ____ _     ___
 / _ \/ ___|_ _| \ | |_   _| |  _ \ ___  ___ ___  _ __     / ___| |   |_ _|
| | | \___ \| ||  \| | | |   | |_) / _ \/ __/ _ \| '_ \   | |   | |    | |
| |_| |___) | || |\  | | |   |  _ <  __/ (_| (_) | | | |  | |___| |___ | |
 \___/|____/___|_| \_| |_|   |_| \_\___|\___\___/|_| |_|   \____|_____|___|
```

## What it does

| Command | Checks |
|---|---|
| `recon domain <domain>` | RDAP/WHOIS, DNS records, TLS certificate, VirusTotal domain reputation |
| `recon ip <ip>` | Geolocation/ASN, AbuseIPDB report history, Shodan open ports |
| `recon url <url>` | VirusTotal URL reputation |

Every check that requires a third-party API key **works without one** it
simply prints a notice and skips that specific check instead of failing.
This means the tool is useful the moment you clone it, and gets more
powerful as you add free API keys over time.

## Installation

```bash
git clone https://github.com/<your-username>/osint-recon-cli.git
cd osint-recon-cli
python3 -m venv venv
source venv/bin/activate    # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Setup (optional but recommended)

1. Copy the example environment file:
   ```bash
   cp .env.example .env
   ```
2. Get free API keys from the services you want to use and paste them into
   `.env`:
   - [AbuseIPDB](https://www.abuseipdb.com/account/api) — free tier
   - [VirusTotal](https://www.virustotal.com/gui/join-us) — free tier
   - [Shodan](https://account.shodan.io/register) — free tier (limited)
   - [ipinfo.io](https://ipinfo.io/signup) — optional, works without a key
     at low request volume

`.env` is listed in `.gitignore` and will never be committed. Only
`.env.example`, with empty placeholder values, is version-controlled.

## Usage

```bash
# Full domain recon (runs every check)
python -m recon domain example.com

# Only specific checks
python -m recon domain example.com --whois --dns

# Full IP recon
python -m recon ip 8.8.8.8

# Only AbuseIPDB
python -m recon ip 8.8.8.8 --abuseipdb

# URL reputation
python -m recon url https://example.com/some/path --virustotal
```

If installed via `pip install -e .`, the `recon` command is also available
directly:

```bash
recon domain example.com
```

### Full scan script

For investigating a domain together with its subdomains and every resolved
IP in a single run, instead of calling the CLI separately for each target
— use the bundled `full_scan.py` script:

```bash
# Base domain only
python scripts/full_scan.py example.com

# Base domain + subdomains (app.example.com, play.example.com)
python scripts/full_scan.py example.com --subdomains app,play
```

This runs, for the base domain and each subdomain given: WHOIS/RDAP, DNS
records, SSL certificate, and VirusTotal (domain + URL) then automatically
resolves every IP found and runs geolocation, AbuseIPDB, and Shodan against
each one. It's the same logic as running the CLI once per target and IP, just
chained together with one command.

## Web interface (optional)

Prefer clicking buttons over typing commands? A local browser-based
interface is included, built with [Streamlit](https://streamlit.io). It
wraps the exact same modules as the CLI, so results are identical it just
runs entirely on your own machine.

```bash
pip install -r requirements-app.txt
streamlit run app.py
```

This opens a page in your browser with tabs for Domain, IP, URL, and Full
scan (domain + subdomains + every resolved IP, all in one click). The
sidebar shows which API keys are currently configured. No data leaves your
machine except the requests each check already makes to its own public API.

### Example output

```
─────────────────────────
  RDAP / WHOIS — example.com
─────────────────────────
  Domain                       EXAMPLE.COM
  Registered                   1995-08-14T04:00:00Z
  Expires                      2026-08-13T04:00:00Z
  Nameservers                  A.IANA-SERVERS.NET, B.IANA-SERVERS.NET
  DNSSEC                       Yes
```

## Project structure

```
osint-recon-cli/
├── app.py                   # optional Streamlit web interface
├── recon/
│   ├── cli.py              # argparse-based command-line entry point
│   ├── config.py           # env-var-only settings, no hardcoded secrets
│   ├── utils.py            # input validation + shared HTTP helper
│   └── modules/
│       ├── whois_lookup.py     # RDAP (no key required)
│       ├── dns_lookup.py       # DNS records (no key required)
│       ├── ssl_check.py        # TLS certificate (no key required)
│       ├── ip_info.py          # geolocation (works without a key)
│       ├── abuseipdb.py        # requires ABUSEIPDB_API_KEY
│       ├── virustotal.py       # requires VIRUSTOTAL_API_KEY
│       └── shodan_lookup.py    # requires SHODAN_API_KEY
├── scripts/
│   └── full_scan.py        # chains every check for a domain + subdomains + IPs
├── tests/
│   └── test_utils.py       # validation unit tests (incl. injection attempts)
├── .github/workflows/ci.yml # tests + automated secret scanning
├── .env.example
├── .gitignore
├── requirements.txt
├── requirements-dev.txt
├── requirements-app.txt    # only needed for the Streamlit interface
├── SECURITY.md
├── LICENSE
└── README.md
```

## Design principles

This project was deliberately built to be **safe to publish publicly**:

- No API key, token, or personal data is hardcoded anywhere in the source.
- All secrets load from environment variables only.
- Every domain/IP is validated before being used in a network request.
- Private and reserved IP ranges are rejected before querying external APIs.
- Every HTTP request has a fixed timeout, no hanging connections.
- Every module fails gracefully with a clear message instead of crashing.
- CI runs the test suite and a secret scanner (gitleaks) on every push.

See [`SECURITY.md`](SECURITY.md) for the full breakdown.

## Running tests

```bash
pip install -r requirements-dev.txt
pytest tests/ -v
```

## Ethical & legal use

This tool only queries public, third-party OSINT sources and performs no
intrusive scanning, exploitation, or brute-forcing. Use it only against
infrastructure you own or are explicitly authorized to investigate, and
always respect the Terms of Service of each underlying API and the laws of
your jurisdiction.

## License

MIT — see [`LICENSE`](LICENSE).

## Author

**Douglas Santana Mendonça**
IT Analyst & Independent Contractor — Network Infrastructure, Digital
Forensics, LGPD Compliance
[LinkedIn](https://linkedin.com/in/douglas-santana-8b5263222)
