"""Lifecycle states and status enumerations."""
from __future__ import annotations

from enum import Enum


class _StrEnum(str, Enum):
    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return self.value


class State(_StrEnum):
    FACTORY = "FACTORY"
    QUARANTINE = "QUARANTINE"
    SCANNING = "SCANNING"
    FAILED = "FAILED"
    CONDITIONAL = "CONDITIONAL"
    PASSED = "PASSED"
    PROVISIONING = "PROVISIONING"
    ACTIVE = "ACTIVE"
    MAINTENANCE = "MAINTENANCE"
    DISABLED = "DISABLED"


class SecurityStatus(_StrEnum):
    UNKNOWN = "UNKNOWN"
    PASS = "PASS"
    CONDITIONAL = "CONDITIONAL"
    CONDITIONAL_ACCEPTED = "CONDITIONAL_ACCEPTED"
    FAIL = "FAIL"


class BackupStatus(_StrEnum):
    NOT_CONFIGURED = "NOT_CONFIGURED"
    CONFIGURED = "CONFIGURED"
    OK = "OK"
    FAILED = "FAILED"


# States in which the device holds credentials / a tunnel (see policy.POLICIES).
CREDENTIALED_STATES = frozenset({State.PROVISIONING, State.ACTIVE, State.MAINTENANCE})
