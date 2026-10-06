"""``brion-state`` CLI. JSON on stdout, errors as JSON on stderr, stable exit codes.

Exit codes: 0 ok, 1 unexpected, 2 validation/usage, 3 invalid transition,
4 guard violation, 5 integrity, 6 concurrency, 7 audit chain broken.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from typing import Any, List, Optional

from . import __version__
from .errors import BrionError, GuardViolationError, ValidationError
from .machine import StateMachine, default_db_path
from .policy import SecurityFacts
from .transitions import RULES


def _facts(path: Optional[str]) -> SecurityFacts:
    if not path:
        raise ValidationError("--facts-file is required (observed device facts as JSON)")
    with (sys.stdin if path == "-" else open(path, encoding="utf-8")) as fh:
        return SecurityFacts.from_dict(json.load(fh))


def _json_arg(value: Optional[str]) -> Any:
    if value is None:
        return {}
    try:
        return json.loads(value)
    except json.JSONDecodeError as exc:
        raise ValidationError(f"invalid JSON: {exc}") from None


def _bool(value: str) -> bool:
    v = value.lower()
    if v in ("true", "1", "yes", "on"):
        return True
    if v in ("false", "0", "no", "off"):
        return False
    raise argparse.ArgumentTypeError("expected true/false")


def _out(obj: Any) -> None:
    json.dump(obj, sys.stdout, indent=2, sort_keys=True, default=str)
    sys.stdout.write("\n")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="brion-state", description=__doc__.splitlines()[0])
    p.add_argument("--db", default=default_db_path(), help="SQLite path (env BRION_DB)")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    def with_actor(sp: argparse.ArgumentParser, facts: bool = True) -> argparse.ArgumentParser:
        sp.add_argument("--actor", required=True)
        if facts:
            sp.add_argument("--facts-file", required=True, help="JSON file with observed facts, '-' = stdin")
        return sp

    s = with_actor(sub.add_parser("init", help="create FACTORY record (idempotent)"))
    s.add_argument("--configuration-version")

    s = with_actor(sub.add_parser("set-identity", help="assign installation id + serial (FACTORY only)"))
    s.add_argument("--installation-id", required=True)
    s.add_argument("--serial-number", required=True)

    sub.add_parser("status", help="print current record and allowed triggers")

    s = with_actor(sub.add_parser("fire", help="fire a lifecycle trigger"))
    s.add_argument("trigger", choices=sorted({r.trigger for r in RULES}))
    s.add_argument("--reason")
    s.add_argument("--context-json", help='e.g. {"integrations_validated": true}')
    s.add_argument("--expected-version", type=int)

    s = with_actor(sub.add_parser("update", help="update non-state fields"))
    s.add_argument("--activated", type=_bool)
    s.add_argument("--vpn-provisioned", type=_bool)
    s.add_argument("--backup-status")
    s.add_argument("--configuration-version")
    s.add_argument("--expected-version", type=int)

    s = with_actor(sub.add_parser("record-scan", help="persist a security scan result"))
    s.add_argument("--result", required=True, choices=["PASS", "CONDITIONAL", "FAIL"])
    s.add_argument("--scanner-version", required=True)
    s.add_argument("--report-sha256", required=True)
    s.add_argument("--summary-json", default="{}")
    s.add_argument("--started-at", required=True, help="ISO-8601 with timezone")

    s = sub.add_parser("history", help="audit log")
    s.add_argument("--limit", type=int, default=100)
    sub.add_parser("verify-audit", help="verify the audit hash chain")
    s = sub.add_parser("reconcile", help="compare record with observed facts")
    s.add_argument("--facts-file", required=True)
    s = sub.add_parser("boot-recover", help="startup recovery (SCANNING -> QUARANTINE)")
    s.add_argument("--facts-file", required=True)
    s.add_argument("--actor", default="system:brion-agent")
    return p


def run(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        with StateMachine.open(args.db) as m:
            if args.cmd == "init":
                rec = m.initialize(actor=args.actor, facts=_facts(args.facts_file),
                                   configuration_version=args.configuration_version)
                _out(rec.to_dict())
            elif args.cmd == "set-identity":
                _out(m.set_identity(installation_id=args.installation_id, serial_number=args.serial_number,
                                    actor=args.actor, facts=_facts(args.facts_file)).to_dict())
            elif args.cmd == "status":
                _out({"record": m.get().to_dict(), "allowed_triggers": m.allowed_triggers()})
            elif args.cmd == "fire":
                _out(m.fire(args.trigger, actor=args.actor, facts=_facts(args.facts_file), reason=args.reason,
                            context=_json_arg(args.context_json),
                            expected_version=args.expected_version).to_dict())
            elif args.cmd == "update":
                _out(m.update_fields(actor=args.actor, facts=_facts(args.facts_file), activated=args.activated,
                                     vpn_provisioned=args.vpn_provisioned, backup_status=args.backup_status,
                                     configuration_version=args.configuration_version,
                                     expected_version=args.expected_version).to_dict())
            elif args.cmd == "record-scan":
                try:
                    started = datetime.fromisoformat(args.started_at)
                except ValueError:
                    raise ValidationError("--started-at must be ISO-8601") from None
                _out(m.record_scan(result=args.result, scanner_version=args.scanner_version,
                                   report_sha256=args.report_sha256, summary=_json_arg(args.summary_json),
                                   started_at=started, actor=args.actor,
                                   facts=_facts(args.facts_file)).to_dict())
            elif args.cmd == "history":
                _out(m.history(args.limit))
            elif args.cmd == "verify-audit":
                problems = m.verify_audit()
                _out({"ok": not problems, "problems": problems})
                return 0 if not problems else 7
            elif args.cmd == "reconcile":
                _out(m.reconcile(_facts(args.facts_file)).to_dict())
            elif args.cmd == "boot-recover":
                rec, plan = m.recover_on_boot(_facts(args.facts_file), actor=args.actor)
                _out({"record": rec.to_dict(), "plan": plan.to_dict()})
        return 0
    except BrionError as exc:
        err = {"error": type(exc).__name__, "message": str(exc)}
        if isinstance(exc, GuardViolationError):
            err["violations"] = list(exc.violations)
        json.dump(err, sys.stderr)
        sys.stderr.write("\n")
        return exc.exit_code


def main() -> None:  # pragma: no cover
    sys.exit(run())
