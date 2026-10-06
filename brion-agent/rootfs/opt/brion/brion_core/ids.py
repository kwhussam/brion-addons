"""Installation ID and serial number validation."""
from __future__ import annotations

import re

from .errors import ValidationError

_INSTALLATION_ID_RE = re.compile(r"^BR-(\d{4})-(\d{5})$")
_HW_SERIAL_RE = re.compile(r"^[0-9a-f]{8,16}$")
_DEVICE_SERIAL_RE = re.compile(r"^PI-[0-9]{5}$")
MIN_YEAR, MAX_YEAR = 2024, 2099


def validate_installation_id(value: str) -> str:
    """Return the ID if it matches BR-YYYY-NNNNN (sequence 00001..99999)."""
    if not isinstance(value, str):
        raise ValidationError("installation_id must be a string")
    m = _INSTALLATION_ID_RE.match(value)
    if not m:
        raise ValidationError(f"installation_id {value!r} does not match BR-YYYY-NNNNN")
    year, seq = int(m.group(1)), int(m.group(2))
    if not MIN_YEAR <= year <= MAX_YEAR:
        raise ValidationError(f"installation_id year {year} outside {MIN_YEAR}..{MAX_YEAR}")
    if seq == 0:
        raise ValidationError("installation_id sequence must start at 00001")
    return value


def format_installation_id(year: int, sequence: int) -> str:
    if not 1 <= sequence <= 99999:
        raise ValidationError("sequence must be 1..99999")
    return validate_installation_id(f"BR-{year:04d}-{sequence:05d}")


def normalize_serial(value: str) -> str:
    """Brion device serial ``PI-NNNNN`` (label on the case) or a raw Raspberry Pi
    hardware serial (``/proc/device-tree/serial-number``, lower-case hex)."""
    if not isinstance(value, str):
        raise ValidationError("serial_number must be a string")
    v = value.strip()
    if _DEVICE_SERIAL_RE.match(v.upper()):
        return v.upper()
    if _HW_SERIAL_RE.match(v.lower()):
        return v.lower()
    raise ValidationError(f"serial_number {value!r} must be PI-NNNNN or 8-16 hex characters")


def normalize_hardware_serial(value: str) -> str:
    v = (value or "").strip().strip("\x00").lower()
    if not _HW_SERIAL_RE.match(v):
        raise ValidationError(f"hardware serial {value!r} must be 8-16 hex characters")
    return v
