"""Golden configuration rules shared by the build (control node) and the agent (device).

The golden configuration is identical for every device. It must never contain
customer data or credentials. These checks run twice: at build time and again
on the device before anything is written to /homeassistant (defence in depth).
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import posixpath
import re
import tarfile
import uuid
from typing import Dict, Iterable, List, Mapping, Tuple

from .errors import ValidationError
from .redaction import find_secrets

MANIFEST_NAME = "brion-manifest.json"
MAX_FILES = 500
MAX_TOTAL_BYTES = 20 * 1024 * 1024

# Paths (relative to the HA config dir) the golden bundle may write.
ALLOWED_FILES = ("configuration.yaml", "secrets.yaml")
MANAGED_DIRS = (
    "packages/brion/",
    "blueprints/automation/brion/",
    "blueprints/script/brion/",
    "custom_templates/brion/",
    "brion/",
)

# Integrations whose configuration always carries customer credentials.
FORBIDDEN_INTEGRATIONS = frozenset({
    "smartthings", "fritz", "fritzbox", "fritzbox_callmonitor", "homematic",
    "homematicip_cloud", "tibber", "netatmo", "tado", "nest", "ecobee",
    "google_assistant", "alexa", "wireguard", "mqtt",
})

_TEXT_RULES: Tuple[Tuple[str, "re.Pattern[str]"], ...] = (
    ("uses !secret (golden must not depend on customer secrets)", re.compile(r"!secret\b")),
    ("literal credential value", re.compile(
        r"^\s*(password|passwd|token|api_key|access_token|client_secret|username|private_key)\s*:\s*[^\s#{]",
        re.I | re.M)),
    ("wireguard configuration", re.compile(r"^\s*\[(Interface|Peer)\]\s*$|^\s*PrivateKey\s*=", re.M)),
)
_TOP_LEVEL_KEY = re.compile(r"^([a-z0-9_]+)\s*:", re.M)


def is_allowed_path(path: str) -> bool:
    return path in ALLOWED_FILES or any(path.startswith(d) for d in MANAGED_DIRS)


def normalize_member(name: str) -> str:
    if name.startswith("/") or "\\" in name or "\x00" in name:
        raise ValidationError(f"illegal path in bundle: {name!r}")
    norm = posixpath.normpath(name)
    if norm.startswith("../") or norm == ".." or norm.startswith("/"):
        raise ValidationError(f"path traversal in bundle: {name!r}")
    return norm[2:] if norm.startswith("./") else norm


def lint_text(path: str, text: str) -> List[str]:
    problems = [f"{path}: {hit}" for hit in find_secrets(text, path)]
    for label, rx in _TEXT_RULES:
        if rx.search(text):
            problems.append(f"{path}: {label}")
    if path.endswith((".yaml", ".yml")):
        for key in _TOP_LEVEL_KEY.findall(text):
            if key in FORBIDDEN_INTEGRATIONS:
                problems.append(f"{path}: forbidden customer integration '{key}'")
    if path == "secrets.yaml":
        meaningful = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
        if meaningful:
            problems.append("secrets.yaml must be empty in the golden configuration")
    return problems


def lint_files(files: Mapping[str, bytes]) -> List[str]:
    problems: List[str] = []
    if len(files) > MAX_FILES:
        problems.append(f"too many files ({len(files)} > {MAX_FILES})")
    if sum(len(v) for v in files.values()) > MAX_TOTAL_BYTES:
        problems.append("bundle too large")
    for path, data in sorted(files.items()):
        if not is_allowed_path(path):
            problems.append(f"{path}: path not allowed in golden configuration")
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            problems.append(f"{path}: not UTF-8 text")
            continue
        problems.extend(lint_text(path, text))
    return problems


def build_manifest(files: Mapping[str, bytes], meta: Mapping[str, str]) -> Dict:
    return {
        "format": 1,
        **dict(meta),
        "files": {p: hashlib.sha256(d).hexdigest() for p, d in sorted(files.items())},
    }


def write_bundle(files: Mapping[str, bytes], manifest: Mapping, fileobj) -> None:
    """Reproducible tar.gz: sorted entries, fixed mtime/owner/mode."""
    import gzip

    with gzip.GzipFile(fileobj=fileobj, mode="wb", mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as tf:
            entries = dict(files)
            entries[MANIFEST_NAME] = json.dumps(manifest, sort_keys=True, indent=2).encode()
            for path in sorted(entries):
                data = entries[path]
                info = tarfile.TarInfo(path)
                info.size, info.mtime, info.mode = len(data), 0, 0o644
                info.uid = info.gid = 0
                info.uname = info.gname = "root"
                tf.addfile(info, io.BytesIO(data))


def read_bundle(blob: bytes) -> Tuple[Dict, Dict[str, bytes]]:
    """Parse and fully validate a bundle without touching the filesystem."""
    files: Dict[str, bytes] = {}
    manifest = None
    total = 0
    try:
        tf = tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz")
    except (tarfile.TarError, OSError) as exc:
        raise ValidationError(f"bundle is not a valid tar.gz: {exc}") from None
    with tf:
        for m in tf.getmembers():
            name = normalize_member(m.name)
            if m.isdir():
                continue
            if not m.isfile():
                raise ValidationError(f"{name}: only regular files allowed (no links/devices)")
            total += m.size
            if total > MAX_TOTAL_BYTES or len(files) >= MAX_FILES:
                raise ValidationError("bundle exceeds size limits")
            data = tf.extractfile(m).read()
            if name == MANIFEST_NAME:
                manifest = json.loads(data.decode("utf-8"))
            elif name in files:
                raise ValidationError(f"duplicate entry {name}")
            else:
                files[name] = data
    if manifest is None:
        raise ValidationError("bundle has no manifest")
    expected = manifest.get("files", {})
    if set(expected) != set(files):
        raise ValidationError("manifest file list does not match bundle content")
    for p, d in files.items():
        if hashlib.sha256(d).hexdigest() != expected[p]:
            raise ValidationError(f"{p}: checksum mismatch")
    problems = lint_files(files)
    if problems:
        raise ValidationError("golden lint failed: " + "; ".join(problems[:20]))
    return manifest, files


def install_bundle(files: Mapping[str, bytes], dest_dir: str) -> Dict[str, List[str]]:
    """Write files atomically per file and prune stale files in managed dirs."""
    written, removed = [], []
    staging = os.path.join(dest_dir, f".brion-staging-{uuid.uuid4().hex}")
    os.makedirs(staging, mode=0o755)
    try:
        for path, data in sorted(files.items()):
            tmp = os.path.join(staging, path.replace("/", "__"))
            with open(tmp, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            target = os.path.join(dest_dir, path)
            os.makedirs(os.path.dirname(target) or dest_dir, exist_ok=True)
            os.replace(tmp, target)
            written.append(path)
        wanted = set(files)
        for d in MANAGED_DIRS:
            root = os.path.join(dest_dir, d)
            if not os.path.isdir(root):
                continue
            for cur, _dirs, names in os.walk(root):
                for n in names:
                    rel = os.path.relpath(os.path.join(cur, n), dest_dir).replace(os.sep, "/")
                    if rel not in wanted:
                        os.remove(os.path.join(cur, n))
                        removed.append(rel)
    finally:
        for n in os.listdir(staging):
            os.remove(os.path.join(staging, n))
        os.rmdir(staging)
    return {"written": written, "removed": removed}


def bundle_files_from_tree(root: str, exclude: Iterable[str] = ()) -> Dict[str, bytes]:
    files: Dict[str, bytes] = {}
    skip = set(exclude)
    for cur, dirs, names in os.walk(root):
        dirs[:] = sorted(d for d in dirs if not d.startswith("."))
        for n in sorted(names):
            if n.startswith(".") or n in skip:
                continue
            full = os.path.join(cur, n)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            with open(full, "rb") as fh:
                files[rel] = fh.read()
    return files
