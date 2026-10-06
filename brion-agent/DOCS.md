# Brion Agent

Der Brion Agent verwaltet den gesamten Lebenszyklus einer Brion-Installation auf
Home Assistant OS. Er **scannt selbst nicht**; die Netzwerkprüfung gehört
ausschließlich dem Add-on *Brion Security*. Der Agent übernimmt von dort nur
`status` und `timestamp`.

## Zustände

`FACTORY → QUARANTINE → SCANNING → PASSED | CONDITIONAL | FAILED → PROVISIONING → ACTIVE ⇄ MAINTENANCE`,
dazu `DISABLED` (Kill-Switch, aus jedem Zustand erreichbar).

Der Zustand liegt in SQLite unter `/data/brion/brion.db` (WAL, `synchronous=FULL`).
Jeder Übergang wird gegen den Graphen und die Fakten-Policy geprüft. Ungültige
Übergänge werden abgewiesen, ohne den Zustand oder das Audit-Log zu verändern.

| Zustand | WireGuard | Fernzugriff | Backup-Credentials | `input_boolean.brion_master_enable` |
|---|---|---|---|---|
| FACTORY, QUARANTINE, SCANNING | – | – | – | OFF |
| FAILED, CONDITIONAL | – | – | – | OFF, Hinweis „Das System bleibt im Quarantäne-Modus.“ |
| PASSED | – | – | – | OFF |
| PROVISIONING | wird eingerichtet | – | wird eingerichtet | OFF |
| ACTIVE | aktiv, Handshake geprüft | über VPN | vorhanden, geprüft | ON (eine manuelle Abschaltung wird respektiert) |
| MAINTENANCE | aktiv | über VPN | vorhanden | OFF |
| DISABLED | gelöscht | – | gelöscht | OFF |

## Start (Boot)

1. SQLite öffnen. Ist die Datenbank unbrauchbar, läuft der Agent **fail closed**:
   Credentials werden gelöscht, der Master-Schalter geht auf OFF, `/api/health` meldet `error`.
2. Installations-ID lesen.
3. Zustand lesen und Boot-Recovery ausführen: ein offener Scan wird abgebrochen,
   `PROVISIONING` endet mit `provisioning_failed`.
4. Security-Status lesen, sowohl aus dem eigenen Record als auch live aus Brion Security.
5. Nur die erlaubten Funktionen starten. In ACTIVE heißt das: VPN prüfen, Backup prüfen,
   Heartbeat starten und den Master-Schalter auf ON setzen.

## Aktivierung (nur in PASSED)

`POST /api/activate`, oder der Knopf „Aktivieren“ in der Seitenleiste, startet die
Aktivierung nur, wenn alle Vorbedingungen erfüllt sind:

- Zustand PASSED, `security_status` = PASS.
- Brion Security ist erreichbar und meldet ebenfalls PASSED, mit einem Zeitstempel innerhalb von ±5 Minuten.
- Das Activation Token aus der Werkstatt liegt vor und ist nicht abgelaufen.

Nach CONDITIONAL plus menschlicher Freigabe ist die Aktivierung nur mit der Option
`activate_after_conditional_acceptance: true` möglich.

Die Aktivierung läuft in diesen Schritten:

1. `provisioning_started`.
2. WireGuard-Schlüsselpaar erzeugen. Der private Schlüssel liegt nur in `/data/brion/wg/` (0600).
3. Activation API aufrufen. Gesendet werden ausschließlich `installation_id`,
   `activation_token`, `wireguard_public_key`, `security{status,timestamp}` und `agent_version`.
4. Die Antwort streng validieren und speichern: Peer, PSK, Backup-Zugang, Heartbeat-URL.
5. Tunnel aufbauen und auf den ersten Handshake warten (`handshake_timeout`).
6. Validierungen prüfen, dann `activation_completed`, dann ACTIVE und Master-Schalter ON.

Schlägt ein Schritt fehl, folgen `provisioning_failed`, das Löschen aller Credentials
und der Master-Schalter OFF; das Gerät ist danach im Zustand FAILED. Für einen neuen
Versuch sind eine erneute Sicherheitsprüfung und, nach einem bereits verbrauchten Token,
ein neues Activation Token aus der Werkstatt nötig.

## API

| Methode | Pfad | Zugriff |
|---|---|---|
| GET | `/api/health` | LAN ohne Token: nur `{"status": "ok\|degraded\|error"}` |
| GET | `/api/state` | Ingress (HA-Benutzer) oder LAN mit Bearer-Token |
| POST | `/api/transition` | authentifiziert; nur `rescan_requested`, `conditional_accepted`, `maintenance_started`, `maintenance_finished`, `disabled`, `reenabled` |
| POST | `/api/activate` | authentifiziert, liefert 202 und führt den Job im Hintergrund aus |
| POST | `/api/maintenance` | authentifiziert, `{"action": "start\|finish", "reason": "..."}` |

- Die LAN-API ist nur aktiv, wenn `api_token_sha256` (SHA-256 des Tokens) gesetzt ist.
- Abgewiesene Anmeldungen werden auditiert und gedrosselt.
- Übergänge, die einen Menschen erfordern (`conditional_accepted`, `reenabled`), brauchen
  einen HA-Ingress-Benutzer oder das Feld `operator`.
- Interne Trigger wie `scan_completed`, `activation_completed` oder `security_degraded`
  sind über die API nicht erreichbar.

## Audit

Jede Aktion landet in `audit_events`: Boot, Aktivierungsschritte, Master-Schalter,
API-Zugriffe (auch abgewiesene) und Wipe. Die Tabelle ist append-only und
hash-verkettet. Werte, die nach Secrets aussehen, werden durch
`{"redacted": true, "keys": [...]}` ersetzt. Vom WireGuard-Schlüssel wird nur ein
Fingerprint des öffentlichen Schlüssels protokolliert.

## Optionen

| Option | Bedeutung |
|---|---|
| `activation_url` | HTTPS-Endpunkt der Activation API |
| `activation_ca_file` | optionale CA-Datei (z. B. `/ssl/brion-ca.pem`) |
| `api_token_sha256` | SHA-256 des Tokens der Brion-Zentrale für die LAN-API; leer bedeutet LAN-API aus |
| `activate_after_conditional_acceptance` | Aktivierung nach freigegebenem CONDITIONAL erlauben (Standard: nein) |
| `handshake_timeout` | Sekunden, die auf den ersten WireGuard-Handshake gewartet wird |
| `workshop_mode`, `workshop_token_sha256` | Werkstatt-API, nur in FACTORY/QUARANTINE |

Die Optionen setzt ausschließlich die Ansible-Rolle `brion_addons`.
