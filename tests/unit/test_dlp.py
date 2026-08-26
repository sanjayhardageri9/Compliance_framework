from __future__ import annotations

from aimw.audit.dlp import DLPClassifier, SensitivityTier


def test_no_pii_is_none_tier():
    result = DLPClassifier().classify("What's the weather today?")
    assert result.tier == SensitivityTier.NONE
    assert result.categories == []


def test_ip_address_is_low_tier():
    result = DLPClassifier().classify("Server is at 192.168.1.1")
    assert result.tier == SensitivityTier.LOW
    assert "ip_address" in result.categories


def test_email_is_medium_tier():
    result = DLPClassifier().classify("Contact jane@example.com")
    assert result.tier == SensitivityTier.MEDIUM


def test_ssn_is_restricted_tier():
    result = DLPClassifier().classify("SSN: 123-45-6789")
    assert result.tier == SensitivityTier.RESTRICTED
    assert "ssn" in result.categories


def test_mixed_content_takes_highest_tier():
    result = DLPClassifier().classify(
        "IP 10.0.0.1, email jane@example.com, SSN 123-45-6789"
    )
    assert result.tier == SensitivityTier.RESTRICTED
    assert set(result.categories) == {"ip_address", "email", "ssn"}
