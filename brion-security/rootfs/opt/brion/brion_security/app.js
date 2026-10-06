// Relative URLs only: the page is served below the Home Assistant ingress path.
(function () {
  const $ = (id) => document.getElementById(id);
  const CHECK_LABEL = { required: "erforderlich", running: "läuft", PASSED: "bestanden", CONDITIONAL: "bedingt bestanden",
                        FAILED: "nicht bestanden", unavailable: "nicht verfügbar" };
  let polling = null;

  function set(id, text, cls) { const el = $(id); el.textContent = text; el.className = cls || ""; }

  async function api(path, opts) {
    const res = await fetch(path, Object.assign({ headers: { "Content-Type": "application/json" }, cache: "no-store" }, opts || {}));
    let body = {};
    try { body = await res.json(); } catch (e) { /* empty */ }
    if (!res.ok) { const err = new Error(body.message || body.error || ("HTTP " + res.status)); err.body = body; throw err; }
    return body;
  }

  function render(s) {
    $("lifecycle").textContent = s.lifecycle_state || "unbekannt";
    $("installation").textContent = s.installation_id || "–";
    set("s-pi", s.device.connected ? "verbunden" : "nicht verbunden", s.device.connected ? "ok" : "bad");
    set("s-net", s.network.detected ? "erkannt" : "nicht erkannt", s.network.detected ? "ok" : "bad");
    set("s-router", s.router.model || "nicht erkannt", s.router.model ? "ok" : "warn");
    const cs = s.security_check;
    set("s-check", CHECK_LABEL[cs] || cs, cs === "PASSED" ? "ok" : cs === "FAILED" ? "bad" : "warn");
    set("s-remote", s.remote_maintenance ? "aktiv" : "deaktiviert", s.remote_maintenance ? "warn" : "ok");
    set("s-auto", s.automations ? "aktiviert" : "deaktiviert", s.automations ? "warn" : "ok");

    $("start-card").hidden = !(s.can_start || s.can_retry);
    $("start-btn").textContent = s.can_retry ? "Prüfung wiederholen" : "Sicherheitsprüfung starten";
    $("progress-card").hidden = !s.job || s.job.state !== "running";
    if (s.job && s.job.state === "running") {
      $("bar-fill").style.width = (s.job.progress || 0) + "%";
      $("phase").textContent = s.job.phase_label || "";
      if (!polling) polling = setInterval(refresh, 2000);
    } else if (polling) { clearInterval(polling); polling = null; loadResult(); }
    if (s.job && s.job.state === "error") { showError("Prüfung abgebrochen: " + (s.job.error || "Fehler")); }
  }

  async function loadResult() {
    try {
      const r = await api("api/check/result");
      $("result-card").hidden = false;
      $("c-green").textContent = r.counts.GREEN; $("c-yellow").textContent = r.counts.YELLOW; $("c-red").textContent = r.counts.RED;
      const o = $("overall"); o.textContent = r.overall; o.className = "overall " + r.overall;
      const ul = $("issues"); ul.innerHTML = "";
      r.findings.filter((f) => f.level !== "GREEN").forEach((f) => {
        const li = document.createElement("li"); li.textContent = f.level + ": " + f.title; ul.appendChild(li);
      });
    } catch (e) { $("result-card").hidden = true; }
  }

  function showError(msg) { const el = $("start-error"); el.textContent = msg; el.hidden = !msg; }

  async function refresh() {
    try { render(await api("api/status")); } catch (e) { showError("Status nicht abrufbar: " + e.message); }
  }

  $("start-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    showError("");
    const btn = $("start-btn"); btn.disabled = true;
    const pw = $("router-password");
    const body = JSON.stringify({ router_user: $("router-user").value, router_password: pw.value });
    pw.value = "";                       // Passwort sofort aus dem Formular entfernen
    const retry = btn.textContent.indexOf("wiederholen") >= 0;
    try { await api(retry ? "api/check/retry" : "api/check/start", { method: "POST", body: body }); }
    catch (e) { showError(e.message); }
    finally { btn.disabled = false; refresh(); }
  });

  refresh();
  loadResult();
})();
