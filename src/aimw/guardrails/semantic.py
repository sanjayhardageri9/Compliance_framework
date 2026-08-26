"""L2 guardrail: a lightweight local 'semantic' layer over the L1 regex guardrail.

The document's L2 gateway row calls for "semantic guardrails" (vs. L1's
plain regex) - in production that's an ML classifier or an embedding-based
similarity search (e.g. Presidio's NLP recognizers). This build stays
hermetic (no external model/API), so SemanticGuardrail instead measures
token-overlap similarity between the input and a small library of known
attack *intents*, catching paraphrases and word-order variations that slip
past exact regex matches - a real, if modest, step up from pure regex, not
a mocked one. It wraps an inner BaseGuardrail (composition, not
inheritance) so it can layer on top of RegexPIIGuardrail without
duplicating PII masking logic.
"""

from __future__ import annotations

import re

from aimw.guardrails.errors import GuardrailViolation
from aimw.interfaces.guardrail import BaseGuardrail
from aimw.models import ExecutionContext

_TOKEN_RE = re.compile(r"[a-z0-9]+")

# Short library of known prompt-injection *intents*, expressed as token
# sets. A candidate prompt is compared against each via Jaccard similarity
# over token sets - catches reordering/paraphrasing that a literal regex
# would miss, without needing an embedding model.
_INJECTION_INTENTS: dict[str, set[str]] = {
    "override_instructions": {"ignore", "prior", "previous", "instructions", "disregard"},
    "role_override": {"you", "are", "now", "unrestricted", "no", "longer", "assistant"},
    "exfiltrate_system_prompt": {"reveal", "print", "system", "prompt", "show", "instructions"},
    "disable_safety": {"disable", "bypass", "safety", "guardrails", "filters", "turn", "off"},
}


def _tokenize(text: str) -> set[str]:
    return set(_TOKEN_RE.findall(text.lower()))


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    intersection = len(a & b)
    union = len(a | b)
    return intersection / union if union else 0.0


def semantic_injection_score(text: str) -> tuple[float, str | None]:
    """Return (best_score, best_matching_intent_label_or_None)."""
    tokens = _tokenize(text)
    best_score = 0.0
    best_label: str | None = None
    for label, intent_tokens in _INJECTION_INTENTS.items():
        score = _jaccard(tokens, intent_tokens)
        if score > best_score:
            best_score = score
            best_label = label
    return best_score, best_label


class SemanticGuardrail(BaseGuardrail):
    """Layers a local similarity-based injection check on top of an inner guardrail."""

    def __init__(self, inner: BaseGuardrail, similarity_threshold: float = 0.35) -> None:
        self._inner = inner
        self._threshold = similarity_threshold

    async def inspect_input(self, prompt: str, context: ExecutionContext) -> str:
        score, label = semantic_injection_score(prompt)
        if score >= self._threshold:
            raise GuardrailViolation(
                f"input rejected: semantic similarity {score:.2f} to known "
                f"injection intent '{label}' (session={context.session_id})"
            )
        return await self._inner.inspect_input(prompt, context)

    async def inspect_output(self, response: str, context: ExecutionContext) -> str:
        return await self._inner.inspect_output(response, context)
