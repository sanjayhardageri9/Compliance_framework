"""Regex libraries used by the L1 guardrail.

This is a deliberately small, named, easy-to-extend stand-in for a real PII
classifier (e.g. Presidio at L2/L3). Isolating the patterns here means
swapping in a real classifier later is a one-file replacement of
regex_pii.py behind the unchanged BaseGuardrail contract.
"""

from __future__ import annotations

import re

PII_PATTERNS: dict[str, re.Pattern[str]] = {
    "email": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    "phone": re.compile(r"\b(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]?\d{3}[-. ]?\d{4}\b"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "credit_card": re.compile(r"\b(?:\d[ -]?){13,16}\b"),
    "ip_address": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"
    ),
}

# Heuristic markers of prompt-injection / control-token forgery attempts.
# Not exhaustive - this is an L1 stand-in, not a real classifier.
PROMPT_INJECTION_PATTERNS: dict[str, re.Pattern[str]] = {
    "ignore_instructions": re.compile(
        r"(?i)\bignore\s+(all\s+)?(previous|prior|above)\s+instructions\b"
    ),
    "forged_control_token": re.compile(r"<<\s*(SYS|SYSTEM|INST)\s*>>|\[\[\s*SYSTEM\s*\]\]"),
    "role_override": re.compile(r"(?i)\byou\s+are\s+now\s+(a|an)\b"),
}


def mask(text: str, patterns: dict[str, re.Pattern[str]] = PII_PATTERNS) -> str:
    """Replace every match of every pattern with a [REDACTED:<label>] marker."""
    masked = text
    for label, pattern in patterns.items():
        masked = pattern.sub(f"[REDACTED:{label.upper()}]", masked)
    return masked


def find_injection_markers(text: str) -> list[str]:
    """Return the labels of any prompt-injection heuristics that matched."""
    return [label for label, pattern in PROMPT_INJECTION_PATTERNS.items() if pattern.search(text)]
