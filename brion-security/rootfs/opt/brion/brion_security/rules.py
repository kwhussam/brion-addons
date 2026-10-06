"""Rule engine: config/security_rules.yaml -> GREEN/YELLOW/RED findings -> PASSED/CONDITIONAL/FAILED.

Policy (which outcome gets which colour) lives in the YAML file; the checks themselves are
fixed Python functions so the rule file cannot execute code.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import yaml

LEVELS = ("GREEN", "YELLOW", "RED")
OVERALL = ("PASSED", "CONDITIONAL", "FAILED")
_ID_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,40}$")


class RuleError(Exception):
    pass


@dataclass
class ScanData:
    """Everything a check may look at (local only)."""
    network: Dict[str, Any]
    devices: List[Dict[str, Any]]
    router: Dict[str, Any]


@dataclass
class Finding:
    rule_id: str
    title: str
    level: str
    outcome: str
    detail: str               # local only – may contain IPs/MACs, never leaves the device
    recommendation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Evaluation:
    findings: List[Finding]
    counts: Dict[str, int]
    overall: str
    rules_version: int
    max_yellow_for_pass: int

    def to_dict(self) -> Dict[str, Any]:
        return {"findings": [f.to_dict() for f in self.findings], "counts": self.counts,
                "overall": self.overall, "rules_version": self.rules_version,
                "max_yellow_for_pass": self.max_yellow_for_pass}


# ----------------------------------------------------------------------- checks
CheckFn = Callable[[ScanData, Dict[str, Any]], Tuple[str, str]]
CHECKS: Dict[str, Tuple[Tuple[str, ...], CheckFn]] = {}
_SECURITY_ORDER = ["WPA3", "WPA2_WPA3", "WPA2", "WPA_WPA2", "UNKNOWN", "WPA", "WEP", "OPEN"]


def check(name: str, outcomes: Tuple[str, ...]):
    def deco(fn: CheckFn) -> CheckFn:
        CHECKS[name] = (outcomes, fn)
        return fn
    return deco


def _tri(value: Optional[bool], yes: str, no: str) -> str:
    return "unknown" if value is None else (yes if value else no)


def _state_de(value: Optional[bool]) -> str:
    return "nicht abrufbar" if value is None else ("aktiviert" if value else "deaktiviert")


_SEC_DE = {"WPA2_WPA3": "WPA2/WPA3", "WPA_WPA2": "WPA/WPA2", "OPEN": "offen (unverschlüsselt)", "UNKNOWN": "unbekannt"}


@check("wifi_security", tuple(_SECURITY_ORDER) + ("DISABLED",))
def _wifi(d: ScanData, p: Dict[str, Any]) -> Tuple[str, str]:
    nets = d.router.get("wifi")
    if nets is None:
        return "UNKNOWN", "WLAN-Konfiguration nicht abrufbar"
    active = [n for n in nets if n.get("enabled")]
    if not active:
        return "DISABLED", "kein WLAN aktiv"
    worst = max(active, key=lambda n: _SECURITY_ORDER.index(n.get("security", "UNKNOWN")))
    detail = ", ".join(f"{n.get('ssid') or 'WLAN ' + str(n.get('index'))}: "
                       f"{_SEC_DE.get(n.get('security'), n.get('security'))}" for n in active)
    return worst.get("security", "UNKNOWN"), detail


@check("upnp_enabled", ("enabled", "disabled", "unknown"))
def _upnp(d: ScanData, p: Dict[str, Any]) -> Tuple[str, str]:
    v = d.router.get("upnp_enabled")
    return _tri(v, "enabled", "disabled"), f"UPnP {_state_de(v)}"


@check("router_remote_access", ("enabled", "disabled", "unknown"))
def _remote(d: ScanData, p: Dict[str, Any]) -> Tuple[str, str]:
    v = d.router.get("remote_access_enabled")
    return _tri(v, "enabled", "disabled"), f"Internetzugriff auf die Router-Oberfläche {_state_de(v)}"


@check("firmware_update", ("available", "current", "unknown"))
def _firmware(d: ScanData, p: Dict[str, Any]) -> Tuple[str, str]:
    fw = d.router.get("firmware") or "unbekannt"
    return _tri(d.router.get("update_available"), "available", "current"), f"installierte Version {fw}"


@check("router_verified", ("verified", "unverified"))
def _verified(d: ScanData, p: Dict[str, Any]) -> Tuple[str, str]:
    ok = bool(d.router.get("authenticated"))
    return ("verified" if ok else "unverified"), (d.router.get("model") or "Router") + (
        " per TR-064 geprüft" if ok else " nicht mit Zugangsdaten geprüft")


@check("port_forward", ("exposed", "none", "unknown"))
def _port_forward(d: ScanData, p: Dict[str, Any]) -> Tuple[str, str]:
    maps = d.router.get("port_mappings")
    if maps is None:
        return "unknown", "Portfreigaben nicht abrufbar"
    self_ip = d.network.get("address")
    hits = []
    for m in maps:
        if m.get("enabled") is False:
            continue
        if p.get("any"):
            hits.append(m)
            continue
        if m.get("internal_port") in p.get("internal_ports", []) and (
                not p.get("to_self") or m.get("internal_client") == self_ip):
            hits.append(m)
    detail = "; ".join(f"WAN {m.get('external_port')} -> {m.get('internal_client')}:{m.get('internal_port')}"
                       for m in hits) or "keine"
    return ("exposed" if hits else "none"), detail


@check("unknown_devices", ("found", "none"))
def _unknown(d: ScanData, p: Dict[str, Any]) -> Tuple[str, str]:
    router_hosts = d.router.get("hosts")
    known_macs = {h.get("mac") for h in router_hosts or [] if h.get("mac")}
    unknown = []
    for dev in d.devices:
        if dev.get("is_self") or dev.get("is_gateway"):
            continue
        if router_hosts is not None:
            if dev.get("mac") and dev["mac"] not in known_macs:
                unknown.append(dev)
        elif not dev.get("vendor") and not dev.get("hostname"):
            unknown.append(dev)
    detail = ", ".join(f"{u.get('ip')} ({u.get('mac') or 'MAC ?'})" for u in unknown) or "keine"
    return ("found" if unknown else "none"), detail


@check("open_ports", ("found", "none"))
def _open_ports(d: ScanData, p: Dict[str, Any]) -> Tuple[str, str]:
    wanted = set(p.get("ports", []))
    hits = [(dev.get("ip"), sorted(wanted & set(dev.get("open_ports", [])))) for dev in d.devices]
    hits = [(ip, ports) for ip, ports in hits if ports]
    detail = "; ".join(f"{ip}: {', '.join(map(str, ports))}" for ip, ports in hits) or "keine"
    return ("found" if hits else "none"), detail


# ----------------------------------------------------------------------- rules
@dataclass
class Rule:
    id: str
    title: str
    check: str
    levels: Dict[str, str]
    params: Dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""


@dataclass
class RuleSet:
    version: int
    max_yellow_for_pass: int
    ports: List[int]
    max_hosts: int
    min_prefix: int
    rules: List[Rule]


def load(path: Path) -> RuleSet:
    try:
        doc = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise RuleError(f"cannot read rule file: {exc}") from None
    return parse(doc)


def parse(doc: Dict[str, Any]) -> RuleSet:
    if not isinstance(doc, dict) or not isinstance(doc.get("rules"), list) or not doc["rules"]:
        raise RuleError("rule file needs a non-empty 'rules' list")
    ev = doc.get("evaluation") or {}
    scan = doc.get("scan") or {}
    max_yellow = int(ev.get("max_yellow_for_pass", 2))
    ports = [int(p) for p in scan.get("ports", [])]
    if any(not 0 < p < 65536 for p in ports) or len(ports) > 64:
        raise RuleError("scan.ports: 1-64 TCP ports in range 1..65535")
    rules, seen = [], set()
    for raw in doc["rules"]:
        rid = str(raw.get("id", ""))
        if not _ID_RE.match(rid):
            raise RuleError(f"invalid rule id {rid!r}")
        if rid in seen:
            raise RuleError(f"duplicate rule id {rid}")
        seen.add(rid)
        name = raw.get("check")
        if name not in CHECKS:
            raise RuleError(f"{rid}: unknown check {name!r}")
        levels = {}
        for k, v in (raw.get("levels") or {}).items():
            if isinstance(k, bool):
                raise RuleError(f"{rid}: outcome names must be strings (YAML turned {k!r} into a boolean)")
            levels[str(k)] = str(v).upper()
        bad = {v for v in levels.values() if v not in LEVELS}
        if bad:
            raise RuleError(f"{rid}: invalid levels {sorted(bad)}")
        missing = set(CHECKS[name][0]) - set(levels)
        if missing:
            raise RuleError(f"{rid}: levels for outcomes {sorted(missing)} missing")
        rules.append(Rule(rid, str(raw.get("title") or rid), name, levels, dict(raw.get("params") or {}),
                          str(raw.get("recommendation") or "")))
    return RuleSet(int(doc.get("version", 1)), max_yellow, ports, int(scan.get("max_hosts", 512)),
                   int(scan.get("min_prefix", 22)), rules)


def overall(counts: Dict[str, int], max_yellow: int) -> str:
    if counts.get("RED", 0) > 0:
        return "FAILED"
    if counts.get("YELLOW", 0) > max_yellow:
        return "CONDITIONAL"
    return "PASSED"


def evaluate(rs: RuleSet, data: ScanData) -> Evaluation:
    findings = []
    for r in rs.rules:
        outcomes, fn = CHECKS[r.check]
        try:
            outcome, detail = fn(data, r.params)
        except Exception as exc:  # noqa: BLE001 - a broken check must never pass silently
            outcome, detail = None, f"Prüfung fehlgeschlagen: {type(exc).__name__}"
        level = r.levels.get(outcome, "RED") if outcome in outcomes else "RED"
        findings.append(Finding(r.id, r.title, level, outcome or "error", detail,
                                r.recommendation if level != "GREEN" else ""))
    counts = {lvl: sum(1 for f in findings if f.level == lvl) for lvl in LEVELS}
    return Evaluation(findings, counts, overall(counts, rs.max_yellow_for_pass), rs.version, rs.max_yellow_for_pass)
