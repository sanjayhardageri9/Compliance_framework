"""Abstract ingress/egress content-evaluation contract.

Implementations inspect and (optionally) transform content flowing into or
out of the LLM reasoning loop: prompt-injection and control-token checks on
ingress, PII masking on both sides. At L1 this is regex-based (a stand-in
for Presidio); at L2/L3 it can be swapped for ML-based classifiers or a
managed DLP service without touching the pipeline.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from aimw.models import ExecutionContext


class BaseGuardrail(ABC):
    """Ingress/egress content evaluation."""

    @abstractmethod
    async def inspect_input(self, prompt: str, context: ExecutionContext) -> str: ...

    @abstractmethod
    async def inspect_output(self, response: str, context: ExecutionContext) -> str: ...
