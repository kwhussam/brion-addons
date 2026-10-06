"""Brion core: persistent lifecycle state machine shared by the Brion add-ons.

The canonical copy lives in ``lib/brion_core``. ``scripts/sync-core.sh`` vendors it
into each add-on build context, because a Home Assistant add-on image can only be
built from files inside its own directory.
"""
from .errors import (
    BrionError,
    ConcurrencyError,
    GuardViolationError,
    IntegrityError,
    InvalidTransitionError,
    NotInitializedError,
    ValidationError,
)
from .ids import format_installation_id, normalize_hardware_serial, normalize_serial, validate_installation_id
from .machine import InstallationRecord, StateMachine, default_db_path
from .policy import POLICIES, ReconcilePlan, SecurityFacts, StatePolicy, build_plan
from .states import BackupStatus, SecurityStatus, State
from .transitions import RULES, Rule

__version__ = "0.2.0"

__all__ = [
    "BackupStatus", "BrionError", "ConcurrencyError", "GuardViolationError",
    "InstallationRecord", "IntegrityError", "InvalidTransitionError",
    "NotInitializedError", "POLICIES", "RULES", "ReconcilePlan", "Rule",
    "SecurityFacts", "SecurityStatus", "State", "StateMachine", "StatePolicy",
    "ValidationError", "build_plan", "default_db_path", "format_installation_id",
    "normalize_hardware_serial", "normalize_serial", "validate_installation_id", "__version__",
]
