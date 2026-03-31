/**
 * app.js — Shared utilities loaded on every page.
 * Handles: loader overlay, flash messages, history loader,
 * HTML escaping, typewriter effect.
 */

"use strict";

/* ── Loader ────────────────────────────────────────── */
function showLoader(msg) {
  document.getElementById("loaderText").textContent = msg || "PROCESSING...";
  document.getElementById("loadingOverlay").style.display = "flex";
}
function hideLoader() {
  document.getElementById("loadingOverlay").style.display = "none";
}

/* ── Escape HTML to prevent XSS ───────────────────── */
function esc(str) {
  if (str == null) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/* ── Typewriter effect ────────────────────────────── */
function typewrite(el, text, speed = 20) {
  el.textContent = "";
  let i = 0;
  const t = setInterval(() => {
    if (i < text.length) { el.textContent += text[i++]; }
    else clearInterval(t);
  }, speed);
}

/* ── Scan history (shared across pages) ───────────── */
function loadHistory() {
  const el = document.getElementById("historyContent");
  if (!el) return;
  el.innerHTML = '<p class="muted">Loading...</p>';

  fetch("/api/history?limit=15")
    .then(r => {
      if (r.status === 401) {
        el.innerHTML = '<p class="muted">Login required to view history.</p>';
        return null;
      }
      return r.json();
    })
    .then(data => {
      if (!data) return;
      if (!data.items || data.items.length === 0) {
        el.innerHTML = '<p class="muted">No scans yet. Run your first scan above.</p>';
        // Update stat cards
        const t = document.getElementById("statTotal");
        const h = document.getElementById("statHigh");
        if (t) t.textContent = "0";
        if (h) h.textContent = "0";
        return;
      }

      // Update stat summary pills
      const total = data.items.length;
      const high  = data.items.filter(i => i.risk_level === "HIGH").length;
      const tEl   = document.getElementById("statTotal");
      const hEl   = document.getElementById("statHigh");
      if (tEl) tEl.textContent = total;
      if (hEl) hEl.textContent = high;

      el.innerHTML = data.items.map(item => {
        const d = new Date(item.created_at);
        const timeStr = isNaN(d) ? item.created_at : d.toLocaleString();
        return `
          <div class="history-row">
            <span class="hist-host">${esc(item.hostname)}</span>
            <span class="hist-score ${esc(item.risk_level)}">${esc(item.risk_level)} — ${item.risk_score}</span>
            <span class="hist-time">${esc(timeStr)}</span>
            <span class="hist-export">
              <a href="/api/export/${item.id}/json" class="export-btn" title="Export JSON">↓ JSON</a>
              <a href="/api/export/${item.id}/pdf"  class="export-btn" title="Export PDF">↓ PDF</a>
            </span>
          </div>`;
      }).join("");
    })
    .catch(() => {
      if (el) el.innerHTML = '<p class="muted">Failed to load history.</p>';
    });
}

/* ── Auto-load history on dashboard ──────────────── */
document.addEventListener("DOMContentLoaded", () => {
  if (document.getElementById("historyContent")) loadHistory();
});
