class GuardrailViolation(Exception):
    """Raised when input content trips a hard guardrail (e.g. prompt injection).

    Distinct from PII masking, which silently transforms content rather than
    rejecting it: a GuardrailViolation means the content itself is
    disqualifying, per the "instruction isolation" principle - untrusted
    content must never be treated as instruction.
    """
