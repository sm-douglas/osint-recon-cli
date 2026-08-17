"""
config.py > Centralized configuration and secrets loading.

SECURITY NOTE:
No API key, token, or credential is ever hardcoded in this project.
All secrets are loaded exclusively from environment variables, optionally
via a local .env file that is explicitly excluded from version control
(see .gitignore). If a key is missing, the corresponding module degrades
gracefully and informs the user instead of failing silently or crashing.
"""

import os
from dataclasses import dataclass
from pathlib import Path

# Optional .env support. If python-dotenv isn't installed, the tool still
# works using real environment variables (this dependency is not required).
try:
    from dotenv import load_dotenv

    _env_path = Path(__file__).resolve().parent.parent / ".env"
    if _env_path.exists():
        load_dotenv(dotenv_path=_env_path)
except ImportError:
    pass


@dataclass(frozen=True)
class Settings:
    abuseipdb_key: str = os.getenv("ABUSEIPDB_API_KEY", "")
    virustotal_key: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    shodan_key: str = os.getenv("SHODAN_API_KEY", "")
    ipinfo_key: str = os.getenv("IPINFO_API_KEY", "")  # optional, works without a key too

    request_timeout: int = int(os.getenv("RECON_TIMEOUT", "15"))
    user_agent: str = os.getenv(
        "RECON_USER_AGENT", "osint-recon-cli/1.0 (+https://github.com/)"
    )

    def has(self, key_name: str) -> bool:
        return bool(getattr(self, key_name, ""))


settings = Settings()


def missing_key_warning(service: str, env_var: str) -> str:
    return (
        f"[!] {service}: no API key found (expected env var {env_var}).\n"
        f"    Skipping this check. See README.md for setup instructions."
    )
