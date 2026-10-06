"""Declarative transition table and guards.

Rule of thumb enforced by the machine (not by individual rules):

* Escalating transitions (target policy allows more than source policy) require
  that the observed facts comply with the *source* policy - nothing may be
  smuggled into a more privileged state.
* De-escalating transitions (e.g. ``disabled``) are never blocked by facts. The
  record becomes restrictive immediately and reconciliation enforces it.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, Callable, Dict, Mapping, Optional, Tuple

from .errors import InvalidTransitionError
from .policy import LOCKED, SecurityFacts, policy_violations
from .states import BackupStatus, SecurityStatus, State

if TYPE_CHECKING:  # pragma: no cover
    from .machine import InstallationRecord


@dataclass(frozen=True)
class GuardInput:
    record: "InstallationRecord"
    facts: SecurityFacts
    context: Mapping[str, Any]
    actor: str
    reason: Optional[str]
    now: datetime
    scan_max_age: timedelta
    clock_skew: timedelta


Guard = Callable[[GuardInput], Optional[str]]


@dataclass(frozen=True)
class Rule:
    trigger: str
    sources: frozenset
    target: State
    guards: Tuple[Guard, ...] = ()
    requires_reason: bool = False
    human_only: bool = False
    effects: Tuple[Tuple[str, Any], ...] = ()
    description: str = ""


# --------------------------------------------------------------------------- guards

def identity_complete(gi: GuardInput) -> Optional[str]:
    if not gi.record.installation_id or not gi.record.serial_number:
        return "installation_id and serial_number must be assigned"
    return None


def configuration_versioned(gi: GuardInput) -> Optional[str]:
    if not gi.record.configuration_version:
        return "configuration_version must be set"
    return None


def facts_locked(gi: GuardInput) -> Optional[str]:
    v = policy_violations(LOCKED, gi.facts)
    return f"device not locked down: {', '.join(v)}" if v else None


def security_status_is(*allowed: SecurityStatus) -> Guard:
    def _guard(gi: GuardInput) -> Optional[str]:
        if gi.record.security_status not in allowed:
            return (f"security_status is {gi.record.security_status.value}, "
                    f"expected {'/'.join(a.value for a in allowed)}")
        return None
    _guard.__name__ = f"security_status_is_{'_'.join(a.value for a in allowed)}"
    return _guard


security_ok = security_status_is(SecurityStatus.PASS, SecurityStatus.CONDITIONAL_ACCEPTED)


def scan_fresh(gi: GuardInput) -> Optional[str]:
    ts = gi.record.last_security_check
    if ts is None:
        return "no security check recorded"
    if ts > gi.now + gi.clock_skew:
        return "last_security_check lies in the future (clock not trustworthy)"
    if gi.now - ts > gi.scan_max_age:
        return f"security check older than {gi.scan_max_age}"
    return None


def not_activated(gi: GuardInput) -> Optional[str]:
    return "device is already activated" if gi.record.activated else None


def activated(gi: GuardInput) -> Optional[str]:
    return None if gi.record.activated else "activation not confirmed by activation service"


def vpn_up(gi: GuardInput) -> Optional[str]:
    if not gi.record.vpn_provisioned:
        return "vpn not provisioned"
    if not (gi.facts.wg_private_key_present and gi.facts.tunnel_active):
        return "wireguard key/tunnel not observed on device"
    return None


def backup_configured(gi: GuardInput) -> Optional[str]:
    if gi.record.backup_status not in (BackupStatus.CONFIGURED, BackupStatus.OK):
        return f"backup_status is {gi.record.backup_status.value}"
    return None


def context_true(key: str) -> Guard:
    def _guard(gi: GuardInput) -> Optional[str]:
        return None if gi.context.get(key) is True else f"context.{key} must be true"
    _guard.__name__ = f"context_{key}"
    return _guard


# ---------------------------------------------------------------------------- rules

S = State
_RESET_SCAN = (("security_status", SecurityStatus.UNKNOWN), ("last_security_check", None))
_WIPE_CREDENTIALS = (("vpn_provisioned", False), ("backup_status", BackupStatus.NOT_CONFIGURED))
_OPERATIONAL_CHECKS = (security_ok, scan_fresh, activated, vpn_up, backup_configured,
                       context_true("integrations_validated"), context_true("automations_validated"))

RULES: Tuple[Rule, ...] = (
    Rule("workshop_finalized", frozenset({S.FACTORY}), S.QUARANTINE,
         guards=(identity_complete, configuration_versioned, facts_locked),
         description="Workshop finished; device ships in quarantine."),
    Rule("scan_started", frozenset({S.QUARANTINE}), S.SCANNING,
         guards=(identity_complete, facts_locked),
         effects=(("security_status", SecurityStatus.UNKNOWN),),
         description="Security add-on starts a scan."),
    Rule("scan_passed", frozenset({S.SCANNING}), S.PASSED,
         guards=(security_status_is(SecurityStatus.PASS), scan_fresh, facts_locked)),
    Rule("scan_conditional", frozenset({S.SCANNING}), S.CONDITIONAL,
         guards=(security_status_is(SecurityStatus.CONDITIONAL),)),
    Rule("scan_failed", frozenset({S.SCANNING}), S.FAILED,
         guards=(security_status_is(SecurityStatus.FAIL),)),
    Rule("scan_aborted", frozenset({S.SCANNING}), S.QUARANTINE,
         description="Scan interrupted (e.g. reboot); back to quarantine."),
    Rule("rescan_requested", frozenset({S.FAILED, S.CONDITIONAL}), S.QUARANTINE,
         guards=(facts_locked,), requires_reason=True, effects=_RESET_SCAN),
    Rule("conditional_accepted", frozenset({S.CONDITIONAL}), S.PASSED,
         guards=(security_status_is(SecurityStatus.CONDITIONAL), scan_fresh, facts_locked),
         requires_reason=True, human_only=True,
         effects=(("security_status", SecurityStatus.CONDITIONAL_ACCEPTED),),
         description="Technician accepts documented findings."),
    Rule("provisioning_started", frozenset({S.PASSED}), S.PROVISIONING,
         guards=(security_ok, scan_fresh, not_activated, facts_locked),
         description="Agent may now generate the WireGuard keypair locally."),
    Rule("activation_completed", frozenset({S.PROVISIONING}), S.ACTIVE,
         guards=_OPERATIONAL_CHECKS),
    Rule("provisioning_failed", frozenset({S.PROVISIONING}), S.FAILED,
         requires_reason=True, effects=(("activated", False),) + _WIPE_CREDENTIALS),
    Rule("maintenance_started", frozenset({S.ACTIVE}), S.MAINTENANCE, requires_reason=True),
    Rule("security_degraded", frozenset({S.ACTIVE}), S.MAINTENANCE, requires_reason=True,
         description="Periodic scan failed while active."),
    Rule("maintenance_finished", frozenset({S.MAINTENANCE}), S.ACTIVE, guards=_OPERATIONAL_CHECKS),
    Rule("disabled", frozenset(set(S) - {S.FACTORY, S.DISABLED}), S.DISABLED,
         requires_reason=True, effects=_WIPE_CREDENTIALS,
         description="Kill switch. Never blocked by facts."),
    Rule("reenabled", frozenset({S.DISABLED}), S.QUARANTINE,
         guards=(facts_locked,), requires_reason=True, human_only=True,
         effects=(("activated", False),) + _WIPE_CREDENTIALS + _RESET_SCAN,
         description="Full re-onboarding from quarantine."),
)

_INDEX: Dict[Tuple[State, str], Rule] = {}
for _r in RULES:
    for _s in _r.sources:
        if (_s, _r.trigger) in _INDEX:  # pragma: no cover - table sanity
            raise RuntimeError(f"duplicate rule {_s}/{_r.trigger}")
        _INDEX[(_s, _r.trigger)] = _r

TRIGGERS = frozenset(r.trigger for r in RULES)


def find_rule(state: State, trigger: str) -> Rule:
    if trigger not in TRIGGERS:
        raise InvalidTransitionError(f"unknown trigger {trigger!r}")
    try:
        return _INDEX[(state, trigger)]
    except KeyError:
        raise InvalidTransitionError(f"trigger {trigger!r} not allowed in state {state.value}") from None


def rules_from(state: State) -> Tuple[Rule, ...]:
    return tuple(r for (s, _), r in sorted(_INDEX.items(), key=lambda kv: kv[0][1]) if s is state)
