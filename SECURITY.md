# Security Policy

## How this project protects you

This tool was built with the explicit goal of being safe to publish and run
without exposing the maintainer or any user to unnecessary risk:

- **No hardcoded credentials.** Every API key is read exclusively from
  environment variables (optionally via a local `.env` file). Search the
  codebase — there is no key, token, or secret embedded anywhere.
- **`.env` is git-ignored.** Only `.env.example` (with empty placeholder
  values) is tracked in version control.
- **Input validation on every network call.** Domains and IPs are validated
  with strict regex/`ipaddress` checks before being sent to any API. This
  prevents command-injection-style payloads and accidental queries against
  malformed input.
- **Private/reserved IPs are rejected** before being sent to any external
  service, so the tool never leaks internal network topology to a third
  party by accident.
- **No intrusive scanning.** This tool only queries public, third-party
  OSINT APIs (RDAP, DNS, AbuseIPDB, VirusTotal, Shodan, ipinfo.io) and
  performs a standard TLS handshake to read certificate metadata. It does
  not port-scan, brute-force, exploit, or otherwise interact intrusively
  with any target.
- **Fixed request timeouts.** Every HTTP request has a timeout, so the tool
  can never hang indefinitely or be used to build a denial-of-service
  vector against itself or a target.
- **Graceful degradation.** Missing API keys produce a clear warning and
  skip that check — the tool never crashes or silently fails.

## Reporting a vulnerability

If you find a security issue in this project (e.g., an injection vector,
a way to leak credentials, or a way to abuse the tool against unintended
targets), please open a **private security advisory** on GitHub
(*Security → Advisories → Report a vulnerability*) rather than a public
issue, so it can be fixed before disclosure.

## Before you commit

Run a secrets scan before every push, especially if you forked this project
and experimented with real keys locally:

```bash
# Using gitleaks (recommended)
gitleaks detect --source . --verbose

# Or manually confirm .env is not tracked
git status --ignored
```

## Responsible use

This tool is intended for legitimate security research, due diligence, and
investigation of infrastructure you own or are explicitly authorized to
assess. Respect the Terms of Service of every third-party API it queries,
and applicable law in your jurisdiction.
