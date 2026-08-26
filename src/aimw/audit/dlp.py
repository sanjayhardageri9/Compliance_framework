"""L2 audit enrichment: DLP sensitivity classification (Section 13's "PII protection" row).

L1's RegexPIIGuardrail masks PII but doesn't grade *how* sensitive what it
found was. L2 adds that grading - "Presidio + DLP classification" in the
document's terms - so an audit record can carry a sensitivity tier
alongside its redacted content, letting downstream review prioritize
RESTRICTED-tier findings over LOW-tier ones. Reuses the same pattern
library as RegexPIIGuardrail rather than introducing a second detector, so
the two never disagree about what counts as PII.
"""

from __future__ import annotations

from enum import IntEnum

from pydantic import BaseModel

from aimw.guardrails.patterns import PII_PATTERNS

_TIER_BY_CATEGORY: dict[str, SensitivityTier] = {}


class SensitivityTier(IntEnum):
    NONE = 0
    LOW = 1
    MEDIUM = 2
    RESTRICTED = 3

    @classmethod
    def max(cls, tiers: list[SensitivityTier]) -> SensitivityTier:
        return max(tiers) if tiers else cls.NONE


_TIER_BY_CATEGORY.update(
    {
        "ip_address": SensitivityTier.LOW,
        "email": SensitivityTier.MEDIUM,
        "phone": SensitivityTier.MEDIUM,
        "ssn": SensitivityTier.RESTRICTED,
        "credit_card": SensitivityTier.RESTRICTED,
    }
)


class DLPClassification(BaseModel):
    tier: SensitivityTier
    categories: list[str]


class DLPClassifier:
    """Grades text by the most sensitive category of PII it contains."""

    def classify(self, text: str) -> DLPClassification:
        categories: list[str] = []
        for label, pattern in PII_PATTERNS.items():
            if pattern.search(text):
                categories.append(label)
        tier = SensitivityTier.max(
            [_TIER_BY_CATEGORY.get(label, SensitivityTier.LOW) for label in categories]
        )
        return DLPClassification(tier=tier, categories=sorted(categories))
