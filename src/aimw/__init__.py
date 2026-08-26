"""AI Governance Middleware SDK — L1 "Pragmatic Lite" + L2 "Growth Tier".

Implements Part III of the AI Governance & Runtime Protection Framework: a
runtime governance pipeline that intercepts agent tool calls and enforces
policy, guardrails, sandboxing, and tamper-evident audit logging.
"""

from aimw.audit.dlp import DLPClassification, DLPClassifier, SensitivityTier
from aimw.audit.siem import BaseAuditSink, LocalSiemForwarder
from aimw.audit.worm_log import ChainVerificationResult, HashChainedJSONLLogger
from aimw.gateway.shim import FakeLLMClient, LiteLLMGatewayShim, ProposedToolCall
from aimw.guardrails.regex_pii import RegexPIIGuardrail
from aimw.guardrails.semantic import SemanticGuardrail
from aimw.hitl.approval import ApprovalCallback, InMemoryApprovalQueue
from aimw.identity.base import BaseIdentityVerifier
from aimw.identity.session_token import SessionTokenIssuer
from aimw.identity.static_bearer import StaticBearerTokenVerifier
from aimw.interceptor import InterceptorResult, ToolCallInterceptor
from aimw.interfaces import BaseGuardrail, BasePolicyEngine, BaseRegistry
from aimw.models import ExecutionContext, PolicyDecision, ToolRequest
from aimw.pipeline import GovernancePipeline, PipelineResult
from aimw.policy.db_engine import DbBackedPolicyEngine
from aimw.policy.db_rules import DbRuleStore
from aimw.policy.db_rules import connect as connect_policy_db
from aimw.policy.db_rules import seed_example as seed_example_policy_db
from aimw.policy.rules import PolicyRuleSet, load_ruleset
from aimw.policy.static_engine import StaticPolicyEngine
from aimw.registry.db_registry import DbBackedToolRegistry
from aimw.registry.static_registry import StaticToolRegistry
from aimw.reliability.circuit_breaker import (
    BaseCircuitBreakerBackend,
    CircuitBreaker,
    InMemoryCircuitBreakerBackend,
)
from aimw.sandbox.base import BaseSandbox, SandboxResult
from aimw.sandbox.docker_sandbox import DockerSandbox, RestrictedDockerSandbox
from aimw.sandbox.subprocess_sandbox import SubprocessSandbox

__version__ = "0.2.0"

__all__ = [
    "ApprovalCallback",
    "BaseAuditSink",
    "BaseCircuitBreakerBackend",
    "BaseGuardrail",
    "BaseIdentityVerifier",
    "BasePolicyEngine",
    "BaseRegistry",
    "BaseSandbox",
    "ChainVerificationResult",
    "CircuitBreaker",
    "DLPClassification",
    "DLPClassifier",
    "DbBackedPolicyEngine",
    "DbBackedToolRegistry",
    "DbRuleStore",
    "DockerSandbox",
    "ExecutionContext",
    "FakeLLMClient",
    "GovernancePipeline",
    "HashChainedJSONLLogger",
    "InMemoryApprovalQueue",
    "InMemoryCircuitBreakerBackend",
    "InterceptorResult",
    "LiteLLMGatewayShim",
    "LocalSiemForwarder",
    "PipelineResult",
    "PolicyDecision",
    "PolicyRuleSet",
    "ProposedToolCall",
    "RegexPIIGuardrail",
    "RestrictedDockerSandbox",
    "SandboxResult",
    "SemanticGuardrail",
    "SensitivityTier",
    "SessionTokenIssuer",
    "StaticBearerTokenVerifier",
    "StaticPolicyEngine",
    "StaticToolRegistry",
    "SubprocessSandbox",
    "ToolCallInterceptor",
    "ToolRequest",
    "__version__",
    "connect_policy_db",
    "load_ruleset",
    "seed_example_policy_db",
]
