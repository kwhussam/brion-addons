"""Per-state security policy, observed security facts and reconciliation plans.

The *record* in SQLite says what the device is allowed to have. The *facts* are
what the agent actually observes on the device (key file present? wg interface up?
master switch on?). Reconciliation compares both and produces the actions needed
to make reality at least as restrictive as the record (fail closed).
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, fields
from typing import Any, Dict, List, Mapping, Protocol, Tuple

from .errors import ValidationError
from .states import State


@dataclass(frozen=True)
class SecurityFacts:
    """Observed, non-secret booleans. Never put key material in here."""

    wg_private_key_present: bool
    tunnel_active: bool
    backup_credentials_present: bool
    cloud_credentials_present: bool
    master_enable_on: bool

    @classmethod
    def locked(cls) -> "SecurityFacts":
        return cls(False, False, False, False, False)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "SecurityFacts":
        names = [f.name for f in fields(cls)]
        unknown = set(data) - set(names)
        missing = set(names) - set(data)
        if unknown or missing:
            raise ValidationError(f"facts: missing={sorted(missing)} unknown={sorted(unknown)}")
        for n in names:
            if not isinstance(data[n], bool):
                raise ValidationError(f"facts.{n} must be boolean")
        return cls(**{n: data[n] for n in names})

    def to_dict(self) -> Dict[str, bool]:
        return asdict(self)


class FactsProvider(Protocol):
    """Implemented by the Brion Agent (phase 7) to probe the real device."""

    def collect(self) -> SecurityFacts: ...


@dataclass(frozen=True)
class StatePolicy:
    """What may exist/be active on the device while in a given state."""

    wg_private_key: bool
    tunnel: bool
    backup_credentials: bool
    cloud_credentials: bool
    master_enable: bool

    def includes(self, other: "StatePolicy") -> bool:
        """True if everything ``other`` allows is also allowed by ``self``."""
        return all(getattr(self, f.name) or not getattr(other, f.name) for f in fields(self))


LOCKED = StatePolicy(False, False, False, False, False)
CREDENTIALED = StatePolicy(True, True, True, True, False)
OPERATIONAL = StatePolicy(True, True, True, True, True)

POLICIES: Mapping[State, StatePolicy] = {
    State.FACTORY: LOCKED,
    State.QUARANTINE: LOCKED,
    State.SCANNING: LOCKED,
    State.FAILED: LOCKED,
    State.CONDITIONAL: LOCKED,
    State.PASSED: LOCKED,
    State.PROVISIONING: CREDENTIALED,
    State.ACTIVE: OPERATIONAL,
    State.MAINTENANCE: CREDENTIALED,
    State.DISABLED: LOCKED,
}

# (policy flag, fact field, corrective action) - ordered: stop effects before wiping.
_CHECKS: Tuple[Tuple[str, str, str], ...] = (
    ("master_enable", "master_enable_on", "set_master_enable_off"),
    ("tunnel", "tunnel_active", "stop_tunnel"),
    ("wg_private_key", "wg_private_key_present", "wipe_wg_private_key"),
    ("backup_credentials", "backup_credentials_present", "wipe_backup_credentials"),
    ("cloud_credentials", "cloud_credentials_present", "wipe_cloud_credentials"),
)


def policy_violations(policy: StatePolicy, facts: SecurityFacts) -> List[str]:
    return [fact for flag, fact, _ in _CHECKS if getattr(facts, fact) and not getattr(policy, flag)]


@dataclass(frozen=True)
class ReconcilePlan:
    state: State
    master_enable_desired: bool
    actions: Tuple[str, ...]
    violations: Tuple[str, ...]

    @property
    def compliant(self) -> bool:
        return not self.violations

    def to_dict(self) -> Dict[str, Any]:
        return {
            "state": self.state.value,
            "master_enable_desired": self.master_enable_desired,
            "actions": list(self.actions),
            "violations": list(self.violations),
            "compliant": self.compliant,
        }


def build_plan(state: State, facts: SecurityFacts) -> ReconcilePlan:
    policy = POLICIES[state]
    violations = policy_violations(policy, facts)
    actions = [action for _, fact, action in _CHECKS if fact in violations]
    desired = state is State.ACTIVE
    if desired and not facts.master_enable_on:
        # Agent turns it on only after its own health checks succeed.
        actions.append("set_master_enable_on")
    return ReconcilePlan(state, desired, tuple(actions), tuple(violations))
