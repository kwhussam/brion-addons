"""Local security report: HTML (Jinja2) and PDF (WeasyPrint, fallback: built-in text PDF)."""
from __future__ import annotations

import hashlib
import logging
import os
import textwrap
from pathlib import Path
from typing import Any, Dict, List, Tuple

from jinja2 import Environment

LOG = logging.getLogger("brion.security.report")
LEVEL_DE = {"GREEN": "GRÜN", "YELLOW": "GELB", "RED": "ROT"}


def render_html(env: Environment, result: Dict[str, Any], view: bool = False) -> str:
    return env.get_template("report.html.j2").render(r=result, view=view, level_de=LEVEL_DE)


# ------------------------------------------------------------------ PDF output
def _pdf_escape(text: str) -> bytes:
    raw = text.encode("cp1252", errors="replace")
    return raw.replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)")


def text_pdf(lines: List[Tuple[str, int, bool]]) -> bytes:
    """Minimal valid PDF 1.4 (A4, Helvetica/WinAnsi) without external dependencies."""
    width, height, margin = 595, 842, 50
    pages: List[List[bytes]] = [[]]
    y = height - margin
    for text, size, bold in lines:
        lead = size * 1.4
        for chunk in textwrap.wrap(text, width=int(95 * 10 / size)) or [""]:
            if y - lead < margin:
                pages.append([])
                y = height - margin
            y -= lead
            font = b"/F2" if bold else b"/F1"
            pages[-1].append(b"BT " + font + b" %d Tf %d %.1f Td (" % (size, margin, y) + _pdf_escape(chunk) + b") Tj ET")
    objs: List[bytes] = []
    kids = []
    objs.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objs.append(b"")  # pages placeholder
    objs.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
    objs.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")
    for i, content in enumerate(pages):
        footer = b"BT /F1 8 Tf %d 30 Td (" % margin + _pdf_escape(f"Brion Security-Protokoll - Seite {i + 1}/{len(pages)} - lokal, vertraulich") + b") Tj ET"
        stream = b"\n".join(content + [footer])
        objs.append(b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream")
        content_id = len(objs)
        objs.append(b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %d %d] /Contents %d 0 R "
                    b"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> >>" % (width, height, content_id))
        kids.append(len(objs))
    objs[1] = b"<< /Type /Pages /Kids [" + b" ".join(b"%d 0 R" % k for k in kids) + b"] /Count %d >>" % len(kids)
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for n, body in enumerate(objs, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % n + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    for off in offsets:
        out += b"%010d 00000 n \n" % off
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)
    return bytes(out)


def _text_lines(r: Dict[str, Any]) -> List[Tuple[str, int, bool]]:
    c = r["counts"]
    lines = [("Brion Sicherheitsprüfung – Protokoll", 18, True),
             (f"Installation {r.get('installation_id') or '-'} · Prüfung {r['scan_id']}", 9, False),
             (f"Zeitraum {r['started_at']} bis {r['finished_at']} · Regelwerk v{r['rules_version']}", 9, False),
             ("", 10, False), ("Security Check abgeschlossen", 13, True),
             (f"{c['GREEN']} GREEN    {c['YELLOW']} YELLOW    {c['RED']} RED", 12, False),
             (f"GESAMTSTATUS: {r['overall']}", 14, True), ("", 10, False), ("Prüfpunkte", 12, True)]
    for f in r["findings"]:
        lines.append((f"[{f['level']}] {f['title']}", 10, True))
        lines.append((f"Ergebnis: {f['detail']}", 9, False))
        if f.get("recommendation"):
            lines.append((f"Empfehlung: {f['recommendation']}", 9, False))
    net = r.get("network") or {}
    lines += [("", 10, False), ("Netzwerk", 12, True),
              (f"Subnetz {net.get('network')} · Gateway {net.get('gateway')} · DNS {', '.join(net.get('dns') or []) or '-'}", 9, False),
              (f"Router: {(r.get('router') or {}).get('model') or 'nicht erkannt'} · Firmware {(r.get('router') or {}).get('firmware') or '-'}", 9, False),
              ("", 10, False), (f"Geräte ({len(r.get('devices') or [])})", 12, True)]
    for d in r.get("devices") or []:
        lines.append((f"{d['ip']}  {d.get('mac') or '-'}  {d.get('vendor') or '-'}  {d.get('hostname') or ''}  "
                      f"Ports: {', '.join(map(str, d.get('open_ports') or [])) or '-'}", 8, False))
    lines += [("", 10, False), ("Dieses Protokoll verbleibt auf dem Gerät und ist von HA-/Cloud-Backups ausgeschlossen. "
               "Brion erhält ausschließlich Installations-ID, Status und Zeitpunkt.", 8, False)]
    return lines


def render_pdf(html: str, result: Dict[str, Any]) -> Tuple[bytes, str]:
    try:
        from weasyprint import HTML  # type: ignore
        return HTML(string=html).write_pdf(), "weasyprint"
    except Exception as exc:  # noqa: BLE001 - ImportError or missing system libraries
        LOG.info("WeasyPrint unavailable (%s) - using built-in PDF writer", type(exc).__name__)
        return text_pdf(_text_lines(result)), "builtin"


def write_reports(env: Environment, result: Dict[str, Any], directory: Path) -> Dict[str, Any]:
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    html = render_html(env, result)
    pdf, engine = render_pdf(html, result)
    out = {}
    for name, data in (("security-report.html", html.encode("utf-8")), ("security-report.pdf", pdf)):
        path = directory / name
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        out[name] = path
    return {"dir": str(directory), "pdf_sha256": hashlib.sha256(pdf).hexdigest(), "engine": engine}
