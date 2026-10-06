# Add-on `brion-security`

Lokaler Netzwerk-Sicherheitscheck während **QUARANTINE**. Läuft unter Home Assistant OS,
Oberfläche über HA-Ingress („Brion Security“ in der Seitenleiste).

## Ablauf

```
Ingress-UI ── POST /api/check/start (Router-Zugangsdaten nur im RAM)
   │
   ├─ Agent: Scan-Sitzung öffnen  (QUARANTINE → SCANNING, scan_id)
   ├─ Netzwerk: Subnetz, Gateway, DNS (Supervisor /network/info, Fallback /proc)
   ├─ nmap -sn <Subnetz>           (Geräte, MAC, Hersteller)
   ├─ nmap gezielte Ports          (nur scan.ports aus security_rules.yaml, kein -p-)
   ├─ TR-064 (FRITZ!Box)           (Modell, Firmware, Update, Hosts, UPnP, Portfreigaben,
   │                                Fernzugriff, WLAN-Typ – nur Get-Aktionen, nie WLAN-Schlüssel)
   │   └─ Passwort wird danach mit Nullen überschrieben
   ├─ Regelwerk → GREEN/YELLOW/RED → PASSED/CONDITIONAL/FAILED
   ├─ Bericht security-report.pdf + .html (lokal, /data/security, nicht im Backup)
   └─ Agent: Ergebnis zur scan_id  (SCANNING → PASSED/CONDITIONAL/FAILED)
```

Bewertung: **0 RED und ≤ 2 YELLOW → PASSED** · 0 RED und > 2 YELLOW → CONDITIONAL · ≥ 1 RED → FAILED
(Schwelle `evaluation.max_yellow_for_pass` in `config/security_rules.yaml`).

## API (nur über Ingress erreichbar)

| Methode | Pfad | Zweck |
|---|---|---|
| GET | `/api/status` | Status-Tabelle der Oberfläche, Lebenszyklus, `can_start`/`can_retry` |
| POST | `/api/check/start` | `{"router_user": "...", "router_password": "..."}` (beide optional) → 202 |
| GET | `/api/check/status` | Phase, Fortschritt, Fehler des letzten Laufs |
| GET | `/api/check/result` | Ergebnis (Zähler, Befunde, Netz-/Gerätedaten – lokal) |
| GET | `/api/report` | `security-report.pdf` (`?format=html` für HTML) |
| POST | `/api/check/retry` | in FAILED/CONDITIONAL: erneute Prüfung durch den angemeldeten HA-Benutzer |
| GET | `/result` | HTML-Ergebnisansicht |

Fehler kommen immer als `{"error": "<code>", "message": "..."}` und enthalten nie Eingabewerte.
Start nur in `QUARANTINE` (sonst 409 `not_in_quarantine`); läuft schon eine Prüfung: 409 `scan_running`;
Agent nicht erreichbar: 503.

## Datenschutz

| Bleibt lokal (nur `/data/security`, `backup_exclude`) | Agent (lokal, `brion.db`) | Brion-Zentrale (später) |
|---|---|---|
| IP/MAC, Gerätenamen, Hersteller, Portlisten, Router-Details, Befundtexte, Bericht | Gesamtstatus, Zähler, IDs der nicht-grünen Regeln, SHA-256 des PDF | **nur** `installation_id`, `status`, `timestamp` (`privacy.central_payload`) |

Router-Passwort: nur im RAM als überschreibbares `bytearray` (`sensitive.Secret`), Digest-Hash direkt
daraus berechnet (wird nie als String erzeugt und nie übertragen), nach der Router-Abfrage und in jedem
Fehlerpfad gelöscht; nie in DB, Bericht, Log oder Agent. Einschränkung: Beim Parsen des HTTP-Requests
entstehen in CPython kurzlebige unveränderliche Kopien, deren Referenzen sofort verworfen werden.

## Schnittstelle zum Agent

Der Agent ist alleiniger Schreiber des Lebenszyklus. Das Add-on ruft `http://127.0.0.1:8099/v1/internal/*`
mit seinem `SUPERVISOR_TOKEN` auf; der Agent prüft beim Supervisor (`/addons/self/info`), dass das Token
zu `*_brion_security` gehört. Ergebnisse sind an die `scan_id` der Sitzung gebunden (kein Replay,
Zeitfenster 1 h, nur Akteur `system:brion-security`).

## Optionen

| Option | Standard | Bedeutung |
|---|---|---|
| `bind_host` | `172.30.32.1` | nur hassio-Schnittstelle (Ingress), nicht das Kunden-LAN |
| `agent_url` | `http://127.0.0.1:8099` | Brion Agent (Host-Netz) |
| `router_host` | leer = Gateway | abweichende Router-Adresse |
| `retain_reports` | `5` | Anzahl lokal aufbewahrter Prüfungen |

## Tests

`tests/unit/test_security_rules.py`, `tests/unit/test_security_components.py`,
`tests/integration/test_security_addon.py` (echter Agent + Fake-Supervisor/HA/FRITZ!Box/nmap).
