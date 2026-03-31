/**
 * scanner.js — Scan form logic and result rendering.
 * Loaded only on the dashboard page.
 */

"use strict";

let _lastScanId = null; // track latest scan ID for export

/* ── Option helpers ──────────────────────────────── */
function getOptions() {
  return {
    ports:       document.getElementById("opt-ports")?.checked      ?? true,
    headers:     document.getElementById("opt-headers")?.checked    ?? true,
    tech:        document.getElementById("opt-tech")?.checked       ?? true,
    subdomains:  document.getElementById("opt-subdomains")?.checked ?? true,
    directories: document.getElementById("opt-dirs")?.checked       ?? false,
  };
}

/* ── Error / success helpers ─────────────────────── */
function showError(msg) {
  const el = document.getElementById("inputError");
  el.textContent = "⚠ " + msg;
  el.style.display = "block";
  setTimeout(() => { el.style.display = "none"; }, 6000);
}
function clearError() {
  document.getElementById("inputError").style.display = "none";
}
function setScanStatus(text, color) {
  const el = document.getElementById("scanStatus");
  if (!el) return;
  el.textContent = text;
  el.style.color = color || "";
}

/* ── Enter key triggers scan ─────────────────────── */
document.getElementById("urlInput")?.addEventListener("keydown", e => {
  if (e.key === "Enter") startScan();
});

/* ── Main scan function ──────────────────────────── */
async function startScan() {
  const raw = (document.getElementById("urlInput")?.value || "").trim();
  if (!raw) { showError("Target URL is required."); return; }

  clearError();
  const btn = document.getElementById("scanBtn");
  if (btn) btn.disabled = true;
  setScanStatus("● SCANNING", "var(--warn)");

  const messages = [
    "RESOLVING TARGET...", "PROBING OPEN PORTS...", "ENUMERATING SUBDOMAINS...",
    "DETECTING TECHNOLOGIES...", "ANALYZING HTTP HEADERS...", "COMPUTING RISK SCORE...",
  ];
  let mi = 0;
  showLoader(messages[0]);
  const msgTimer = setInterval(() => {
    mi = (mi + 1) % messages.length;
    document.getElementById("loaderText").textContent = messages[mi];
  }, 1900);

  try {
    const res  = await fetch("/api/scan", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ url: raw, options: getOptions() }),
    });

    const data = await res.json();
    if (!res.ok || !data.ok) {
      showError(data.error || "Scan failed. Check the URL and try again.");
      setScanStatus("● ERROR", "var(--danger)");
      return;
    }

    renderResults(data);
    loadHistory(); // refresh history panel
    setScanStatus("● READY", "");

  } catch {
    showError("Network error — is the server running?");
    setScanStatus("● ERROR", "var(--danger)");
  } finally {
    clearInterval(msgTimer);
    hideLoader();
    if (btn) btn.disabled = false;
  }
}

/* ── Export helpers ──────────────────────────────── */
function exportJSON() {
  if (_lastScanId) window.open(`/api/export/${_lastScanId}/json`, "_blank");
}
function exportPDF() {
  if (_lastScanId) window.open(`/api/export/${_lastScanId}/pdf`, "_blank");
}

/* ── Render full result ──────────────────────────── */
function renderResults(d) {
  const area = document.getElementById("resultsArea");
  area.style.display = "block";
  area.scrollIntoView({ behavior: "smooth", block: "start" });

  // Store scan ID for export (latest item in history won't be fetched yet)
  _lastScanId = null; // will be updated after history reload below
  // Re-fetch history to get the ID of the just-inserted scan
  setTimeout(() => {
    fetch("/api/history?limit=1")
      .then(r => r.json())
      .then(h => {
        if (h.items && h.items[0]) {
          _lastScanId = h.items[0].id;
          document.getElementById("exportBtns").style.display = "";
        }
      }).catch(() => {});
  }, 400);

  /* Risk banner */
  const risk  = d.risk || {};
  const lvlEl = document.getElementById("riskLevel");
  lvlEl.textContent = risk.level || "—";
  lvlEl.className   = "risk-level " + (risk.level || "");
  document.getElementById("gaugeScore").textContent = `${risk.score ?? "—"} / 100`;
  document.getElementById("gaugeFill").style.width  = `${risk.score ?? 0}%`;
  document.getElementById("riskHost").textContent   = d.target?.hostname || "—";

  /* Hints */
  const hintsEl = document.getElementById("hintsSection");
  const listEl  = document.getElementById("hintsList");
  if (risk.hints?.length) {
    hintsEl.style.display = "";
    listEl.innerHTML = risk.hints.map(h => `<li>${esc(h)}</li>`).join("");
  } else {
    hintsEl.style.display = "none";
  }

  renderIp(d.ip, d.http);
  renderTech(d.tech);
  renderHttp(d.http);
  renderPorts(d.ports);
  renderHeaders(d.headers);
  renderSubdomains(d.subdomains);
  renderDirs(d.directories);
}

/* ── Visibility helpers ──────────────────────────── */
const show = id => { const e = document.getElementById(id); if (e) e.style.display = ""; };
const hide = id => { const e = document.getElementById(id); if (e) e.style.display = "none"; };

/* ── KV row builder ──────────────────────────────── */
function kv(key, val, cls = "") {
  return `<div class="kv-row">
    <span class="kv-key">${esc(key)}</span>
    <span class="kv-val ${cls}">${esc(String(val ?? "—"))}</span>
  </div>`;
}

/* ── Individual panel renderers ──────────────────── */
function renderIp(ip, http) {
  show("cardIp");
  document.getElementById("ipContent").innerHTML = [
    kv("HOSTNAME",      ip?.hostname),
    kv("IP ADDRESS",    ip?.ip    || ip?.error || "—"),
    kv("HTTP STATUS",   http?.status_code),
    kv("RESPONSE TIME", http?.elapsed_ms ? http.elapsed_ms + " ms" : "—"),
    kv("FINAL URL",     http?.final_url),
  ].join("");
}

function renderTech(tech) {
  if (!tech || tech.enabled === false) { hide("cardTech"); return; }
  show("cardTech");
  let html = "";
  for (const [k, v] of Object.entries(tech.from_headers || {}))
    html += kv(k, v);
  if (tech.from_html?.length)
    html += kv("DETECTED LIBS", tech.from_html.join(", "));
  if (tech.notes?.length)
    html += tech.notes.map(n =>
      `<div class="kv-row"><span class="kv-key" style="color:var(--warn)">NOTE</span>
       <span class="kv-val warn">${esc(n)}</span></div>`
    ).join("");
  if (!html)
    html = '<p class="muted" style="padding:.2rem 0">No fingerprints detected.</p>';
  document.getElementById("techContent").innerHTML = html;
}

function renderHttp(http) {
  if (!http) { hide("cardHttp"); return; }
  show("cardHttp");
  const rh = http.response_headers || {};
  document.getElementById("httpContent").innerHTML = [
    kv("STATUS",       http.status_code),
    kv("SERVER",       rh["Server"]       || "—"),
    kv("X-POWERED-BY", rh["X-Powered-By"] || "—"),
    kv("CONTENT-TYPE", rh["Content-Type"] || "—"),
    kv("ELAPSED",      http.elapsed_ms ? http.elapsed_ms + " ms" : "—"),
    http.error ? kv("ERROR", http.error, "danger") : "",
  ].join("");
}

function renderPorts(ports) {
  if (!ports || ports.enabled === false || !Array.isArray(ports)) { hide("cardPorts"); return; }
  show("cardPorts");
  const open = ports.filter(p => p.state === "open").length;
  document.getElementById("portSummary").textContent = `${open} OPEN / ${ports.length} SCANNED`;
  document.getElementById("portsContent").innerHTML = ports.map(p =>
    `<div class="port-chip ${esc(p.state)}">
      <span><span class="port-num">${p.port}</span><span class="port-svc">${esc(p.service)}</span></span>
      <span class="port-state">${esc(p.state.toUpperCase())}</span>
    </div>`
  ).join("");
}

function renderHeaders(headers) {
  if (!headers || headers.enabled === false || !headers.details) { hide("cardHeaders"); return; }
  show("cardHeaders");
  document.getElementById("headerSummary").textContent =
    `${(headers.present || []).length} PRESENT / ${(headers.missing || []).length} MISSING`;
  document.getElementById("headersContent").innerHTML = (headers.details || []).map(h => {
    const ok    = h.present;
    const icon  = ok ? "✓" : "✗";
    const color = ok ? "var(--green)" : "var(--danger)";
    return `<div class="header-row">
      <span class="header-status" style="color:${color}">${icon}</span>
      <div>
        <div class="header-name">${esc(h.header)}</div>
        <div class="header-why">${esc(h.why)}</div>
        ${h.value ? `<div class="header-val">${esc(h.value)}</div>` : ""}
      </div>
    </div>`;
  }).join("");
}

function renderSubdomains(subs) {
  if (!subs || subs.enabled === false || !Array.isArray(subs)) { hide("cardSubdomains"); return; }
  show("cardSubdomains");
  document.getElementById("subSummary").textContent = `${subs.length} FOUND`;
  document.getElementById("subdomainsContent").innerHTML = subs.length
    ? subs.map(s =>
        `<div class="data-row">
          <span class="data-main">${esc(s.subdomain)}</span>
          <span class="data-sub">${esc(s.ip)}</span>
        </div>`
      ).join("")
    : '<p class="muted">No subdomains resolved from wordlist.</p>';
}

function renderDirs(dirs) {
  if (!dirs || dirs.enabled === false || !Array.isArray(dirs)) { hide("cardDirs"); return; }
  show("cardDirs");
  document.getElementById("dirSummary").textContent = `${dirs.length} FOUND`;
  document.getElementById("dirsContent").innerHTML = dirs.length
    ? dirs.map(d =>
        `<div class="data-row">
          <span class="data-main">${esc(d.path)}</span>
          <span class="status-pill s${d.status}">${d.status}</span>
        </div>`
      ).join("")
    : '<p class="muted">No paths discovered.</p>';
}
