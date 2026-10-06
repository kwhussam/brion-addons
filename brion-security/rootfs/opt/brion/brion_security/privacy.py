"""What may leave the device.

Scan raw data, IP/MAC addresses, device names, port lists, router credentials and
security details stay on the Raspberry Pi. Brion (central) may only ever receive the
payload built here – enforced by an explicit allow-list.
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Dict

CENTRAL_FIELDS = ("installation_id", "status", "timestamp")
_STATUS = ("PASSED", "CONDITIONAL", "FAILED")


def central_payload(installation_id: str, status: str, timestamp: datetime) -> Dict[str, str]:
    if not re.match(r"^BR-[0-9]{4}-[0-9]{5}$", installation_id or ""):
        raise ValueError("invalid installation_id")
    if status not in _STATUS:
        raise ValueError("invalid status")
    if timestamp.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    payload = {"installation_id": installation_id, "status": status,
               "timestamp": timestamp.isoformat(timespec="seconds")}
    assert tuple(payload) == CENTRAL_FIELDS
    return payload


def agent_summary(evaluation: Dict) -> Dict:
    """Summary stored by the (local) Brion Agent: counts and rule IDs only, no network details."""
    return {
        "overall": evaluation["overall"],
        "counts": {k: int(v) for k, v in evaluation["counts"].items()},
        "rules_version": int(evaluation["rules_version"]),
        "non_green_rules": sorted(f["rule_id"] for f in evaluation["findings"] if f["level"] != "GREEN"),
    }
