class AuditTamperError(Exception):
    """Raised by strict-mode chain verification when a break is detected."""

    def __init__(self, broken_index: int, message: str = "") -> None:
        self.broken_index = broken_index
        super().__init__(message or f"audit chain broken at record index {broken_index}")
