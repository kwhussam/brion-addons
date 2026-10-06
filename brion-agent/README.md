# Add-on `brion-agent` (Phase 7)

Einziger Schreiber von `/data/brion/brion.db` (Paket `brion_core`, vendored via
`scripts/sync-core.sh`). Aufgaben: Boot-Recovery, Reconcile-Loop (Master-Switch,
Tunnel, Key-Wipe), WireGuard-Keypair lokal erzeugen, Aktivierung, interne API für
`brion-security` und den Werkstatt-Ansible-Lauf.

Geplante Add-on-Optionen: `host_network: true`, `privileged: [NET_ADMIN]`,
`homeassistant_api: true`, `hassio_api: true`, `backup_exclude: ["brion/wg/*", "brion/secrets/*"]`.
