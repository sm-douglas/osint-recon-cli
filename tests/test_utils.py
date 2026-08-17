"""
Unit tests for input validation, the most security-relevant part of the
codebase, since it gates every outbound request the tool makes.

Run with: pytest tests/
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from recon.utils import is_valid_domain, is_valid_ip, clean_domain_input


class TestIsValidDomain:
    def test_valid_domains(self):
        assert is_valid_domain("example.com")
        assert is_valid_domain("sub.example.com")
        assert is_valid_domain("a-b.example.co.uk")

    def test_invalid_domains(self):
        assert not is_valid_domain("")
        assert not is_valid_domain("not a domain")
        assert not is_valid_domain("-example.com")
        assert not is_valid_domain("example-.com")
        assert not is_valid_domain("example")  # no TLD
        assert not is_valid_domain("http://example.com")  # scheme not allowed here
        assert not is_valid_domain("a" * 300 + ".com")  # too long

    def test_injection_attempts_rejected(self):
        assert not is_valid_domain("example.com; rm -rf /")
        assert not is_valid_domain("example.com`whoami`")
        assert not is_valid_domain("example.com$(id)")
        assert not is_valid_domain("' OR '1'='1")


class TestIsValidIp:
    def test_valid_public_ip(self):
        assert is_valid_ip("8.8.8.8") == "public"
        assert is_valid_ip("1.1.1.1") == "public"

    def test_valid_private_ip(self):
        assert is_valid_ip("192.168.1.1") == "private"
        assert is_valid_ip("10.0.0.1") == "private"
        assert is_valid_ip("127.0.0.1") == "private"

    def test_invalid_ip(self):
        assert is_valid_ip("999.999.999.999") is None
        assert is_valid_ip("not-an-ip") is None
        assert is_valid_ip("") is None
        assert is_valid_ip("8.8.8.8; ls") is None


class TestCleanDomainInput:
    def test_strips_scheme_and_path(self):
        assert clean_domain_input("https://bwis.io/") == "bwis.io"
        assert clean_domain_input("https://bwis.io") == "bwis.io"
        assert clean_domain_input("http://bwis.io/some/path") == "bwis.io"
        assert clean_domain_input("https://bwis.io/?q=1") == "bwis.io"
        assert clean_domain_input("https://bwis.io/#section") == "bwis.io"

    def test_bare_domain_unchanged(self):
        assert clean_domain_input("bwis.io") == "bwis.io"

    def test_normalizes_case_and_whitespace(self):
        assert clean_domain_input("  BWIS.IO  ") == "bwis.io"

    def test_strips_trailing_dot(self):
        assert clean_domain_input("bwis.io.") == "bwis.io"

    def test_cleaned_output_is_valid_domain(self):
        for raw in ["https://bwis.io/", "BWIS.IO", "  bwis.io  ", "bwis.io."]:
            assert is_valid_domain(clean_domain_input(raw))
