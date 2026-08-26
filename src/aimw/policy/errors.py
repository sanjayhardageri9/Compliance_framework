class PolicyEvaluationError(Exception):
    """Raised when a policy engine cannot reach a decision.

    Callers (the ToolCallInterceptor) must treat this — and any other
    exception raised during evaluation — as an implicit deny, per the
    "fail safe, not open" principle.
    """
