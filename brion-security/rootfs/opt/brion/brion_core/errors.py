"""Exception hierarchy. Every error maps to a stable CLI exit code."""
from __future__ import annotations

from typing import Iterable


class BrionError(Exception):
    exit_code = 1


class ValidationError(BrionError):
    exit_code = 2


class NotInitializedError(BrionError):
    exit_code = 2


class InvalidTransitionError(BrionError):
    exit_code = 3


class GuardViolationError(BrionError):
    exit_code = 4

    def __init__(self, trigger: str, violations: Iterable[str]):
        self.trigger = trigger
        self.violations = tuple(violations)
        super().__init__(f"{trigger}: " + "; ".join(self.violations))


class IntegrityError(BrionError):
    exit_code = 5


class ConcurrencyError(BrionError):
    exit_code = 6
