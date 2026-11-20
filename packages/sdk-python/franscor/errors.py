"""Error types. Every protocol error carries an FSP code (see FSP-0.1 §9)."""

from __future__ import annotations


class FSPError(Exception):
    """A protocol-level failure with a stable, language-independent code."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message

    def to_body(self) -> dict:
        return {"code": self.code, "message": self.message}


class TaskError(FSPError):
    """A delegated task did not complete. `status` is the FSP task status."""

    def __init__(self, status: str, code: str, message: str, task_id: str = ""):
        super().__init__(code, message)
        self.status = status
        self.task_id = task_id


MALFORMED = "FSP-1000"
UNSUPPORTED_VERSION = "FSP-1001"
TOO_LARGE = "FSP-1002"
BAD_SIGNATURE = "FSP-1100"
ID_MISMATCH = "FSP-1101"
STALE = "FSP-1102"
BAD_NONCE = "FSP-1103"
NOT_REGISTERED = "FSP-1104"
REVOKED = "FSP-1105"
PASSPORT_INVALID = "FSP-1106"
PASSPORT_EXPIRED = "FSP-1107"
PASSPORT_REVOKED = "FSP-1108"
PERMIT_INVALID = "FSP-1109"
PERMIT_EXPIRED = "FSP-1110"
PERMIT_REVOKED = "FSP-1111"
PERMIT_DENIED = "FSP-1112"
OFFLINE = "FSP-1200"
DENIED = "FSP-1201"
ENCRYPTION_REQUIRED = "FSP-1203"
UNKNOWN_CAPABILITY = "FSP-1202"
RATE_LIMITED = "FSP-1300"
HANDLER_FAILED = "FSP-1400"
TIMEOUT = "FSP-1401"
APPROVAL_REJECTED = "FSP-1402"
