// Relative URLs only – served below the Home Assistant ingress path.
(function () {
  const $ = (id) => document.getElementById(id);
  const LABELS = {
    rescan_requested: ["Erneute Sicherheitsprüfung", "", false],
    conditional_accepted: ["Befunde akzeptieren", "secondary", true],
    maintenance_started: ["Wartung starten", "secondary", true],
    maintenance_finished: ["Wartung beenden", "", false],
    disabled: ["Brion deaktivieren", "danger", true],
    reenabled: ["Wieder freigeben (Quarantäne)", "secondary", true],
    activate: ["System aktivieren", "", false],
  };
  const SEC = { PASS: "bestanden", CONDITIONAL: "mit Auflagen", CONDITIONAL_ACCEPTED: "mit Auflagen akzeptiert",
                FAIL: "nicht bestanden", UNKNOWN: "ausstehend" };
  let timer = null;

  async function api(path, body) {
    const opts = { cache: "no-store", headers: { "Content-Type": "application/json" } };
    if (body !== undefined) { opts.method = "POST"; opts.body = JSON.stringify(body); }
    const res = await fetch(path, opts);
    let data = {};
    try { data = await res.json(); } catch (e) { /* ignore */ }
    if (!res.ok) throw new Error(data.message || data.error || ("HTTP " + res.status));
    return data;
  }

  function cell(id, text, cls) { const el = $(id); el.textContent = text; el.className = cls || ""; }
  function fmt(ts) { if (!ts) return "–"; try { return new Date(ts).toLocaleString("de-DE"); } catch (e) { return ts; } }

  function render(s) {
    $("iid").textContent = s.installation_id || "–";
    $("state").textContent = s.state || "–";
    $("version").textContent = s.agent_version || "";
    $("message").textContent = s.message || "";
    const banner = $("banner-card");
    banner.className = "card " + (["FAILED", "CONDITIONAL", "DISABLED"].includes(s.state) ? "lock"
      : ["QUARANTINE", "SCANNING", "PASSED", "PROVISIONING", "MAINTENANCE", "FACTORY"].includes(s.state) ? "warn" : "ok");

    const sec = s.security || {};
    cell("t-security", SEC[sec.status] || sec.status || "–", sec.status === "PASS" ? "ok" : sec.status === "FAIL" ? "bad" : "warn");
    cell("t-security-ts", fmt(sec.last_check));
    const m = s.master_enable || {};
    cell("t-master", m.actual ? "AN" : "AUS", m.actual === m.expected ? (m.actual ? "ok" : "") : "warn");
    const rm = s.remote_maintenance || {};
    const tun = rm.tunnel || {};
    cell("t-vpn", !rm.vpn_provisioned ? "nicht eingerichtet" : tun.ok ? "verbunden" : tun.interface ? "keine Verbindung zum Hub" : "getrennt",
         !rm.vpn_provisioned ? "" : tun.ok ? "ok" : "warn");
    const b = (s.backup || {}).status;
    cell("t-backup", { NOT_CONFIGURED: "nicht eingerichtet", CONFIGURED: "eingerichtet", OK: "OK", FAILED: "Fehler" }[b] || "–",
         b === "OK" ? "ok" : b === "FAILED" ? "bad" : "");
    const hb = s.heartbeat || {};
    cell("t-heartbeat", hb.last_ok ? "zuletzt " + fmt(hb.last_ok) : hb.last_error ? "Fehler: " + hb.last_error : "–",
         hb.last_error ? "warn" : hb.last_ok ? "ok" : "");

    const acts = $("actions"); acts.innerHTML = "";
    let needsReason = false;
    (s.allowed_actions || []).forEach((a) => {
      const [label, cls, reason] = LABELS[a] || [a, "secondary", false];
      needsReason = needsReason || reason;
      const btn = document.createElement("button");
      btn.textContent = label; if (cls) btn.className = cls;
      btn.addEventListener("click", () => run(a, reason, btn));
      acts.appendChild(btn);
    });
    if (s.security_ui && ["QUARANTINE", "FAILED", "CONDITIONAL"].includes(s.state)) {
      const a = document.createElement("a");
      a.href = s.security_ui; a.target = "_top"; a.className = "button secondary"; a.textContent = "Brion Security öffnen";
      acts.appendChild(a);
    }
    $("reason-wrap").hidden = !needsReason;
    $("actions-card").hidden = acts.children.length === 0 && !(s.activation || {}).running;
    const act = s.activation || {};
    const info = $("activation");
    info.hidden = !(act.running || act.error);
    info.textContent = act.running ? "Aktivierung läuft: " + (act.step || "") : act.error ? "Aktivierung fehlgeschlagen: " + act.error : "";
    if (act.running && !timer) timer = setInterval(refresh, 2000);
    if (!act.running && timer) { clearInterval(timer); timer = null; }
  }

  async function run(action, needsReason, btn) {
    const err = $("action-error"); err.hidden = true;
    const reason = $("reason").value.trim();
    if (needsReason && !reason) { err.textContent = "Bitte eine Begründung angeben."; err.hidden = false; return; }
    btn.disabled = true;
    try {
      if (action === "activate") await api("api/activate", {});
      else if (action === "maintenance_started" || action === "maintenance_finished")
        await api("api/maintenance", { action: action === "maintenance_started" ? "start" : "finish", reason: reason || null });
      else await api("api/transition", { trigger: action, reason: reason || "Erneute Prüfung über Brion-Oberfläche" });
      $("reason").value = "";
    } catch (e) { err.textContent = e.message; err.hidden = false; }
    finally { btn.disabled = false; refresh(); }
  }

  async function refresh() {
    try { render(await api("api/state")); }
    catch (e) { $("message").textContent = "Status nicht abrufbar: " + e.message; }
  }
  refresh();
  setInterval(refresh, 15000);
})();
