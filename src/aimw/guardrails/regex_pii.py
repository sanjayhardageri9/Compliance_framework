"""L1 guardrail: regex-based PII masking and prompt-injection heuristics.

Stands in for the framework document's "Presidio" PII masking (Section 13)
and the control-token / instruction-isolation checks (Section 8.1). Ingress
content that trips a prompt-injection heuristic is rejected outright
(instructions must never be derived from untrusted content); PII is masked
symmetrically on both ingress and egress.
"""

from __future__ import annotations

from aimw.guardrails.errors import GuardrailViolation
from aimw.guardrails.patterns import find_injection_markers, mask
from aimw.interfaces.guardrail import BaseGuardrail
from aimw.models import ExecutionContext


class RegexPIIGuardrail(BaseGuardrail):
    """Regex-based guardrail: prompt-injection heuristics + PII masking."""

    def __init__(self, block_on_injection: bool = True) -> None:
        self._block_on_injection = block_on_injection

    async def inspect_input(self, prompt: str, context: ExecutionContext) -> str:
        markers = find_injection_markers(prompt)
        if markers and self._block_on_injection:
            raise GuardrailViolation(
                f"input rejected: prompt-injection markers detected {markers} "
                f"(session={context.session_id})"
            )
        return mask(prompt)

    async def inspect_output(self, response: str, context: ExecutionContext) -> str:
        return mask(response)
