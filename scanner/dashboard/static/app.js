const REFRESH_MS = 3000;

const els = {
  liveDot: document.getElementById("live-dot"),
  lastUpdated: document.getElementById("last-updated"),
  cardTotal: document.getElementById("card-total"),
  cardHigh: document.getElementById("card-high"),
  cardMedium: document.getElementById("card-medium"),
  cardLow: document.getElementById("card-low"),
  search: document.getElementById("search"),
  hideLow: document.getElementById("hide-low"),
  body: document.getElementById("process-body"),
};

let latestProcesses = [];

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str ?? "";
  return div.innerHTML;
}

function relativeTime(epochSeconds) {
  if (!epochSeconds) return "-";
  const deltaMs = Date.now() - epochSeconds * 1000;
  const seconds = Math.max(0, Math.round(deltaMs / 1000));
  if (seconds < 5) return "just now";
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

function meterClass(level) {
  if (level === "HIGH") return "high";
  if (level === "MEDIUM") return "medium";
  return "low";
}

function pctMeter(value, level) {
  if (value === null || value === undefined) {
    return `<span class="meter-label">&ndash;</span>`;
  }
  const pct = Math.round(value * 100);
  return `
    <span class="meter"><span class="meter-fill ${meterClass(level)}" style="width:${pct}%"></span></span>
    <span class="meter-label">${pct}%</span>
  `;
}

function renderTechniques(matched) {
  if (!matched || matched.length === 0) {
    return `<span class="tech-tag none">none</span>`;
  }
  return matched
    .map((name) => `<span class="tech-tag">${escapeHtml(name)}</span>`)
    .join("");
}

function rowHtml(p) {
  return `
    <tr>
      <td><span class="badge ${p.risk_level}">${p.risk_level}</span></td>
      <td>${p.risk_score}</td>
      <td>${pctMeter(p.ml_risk_score, p.risk_level)}</td>
      <td>${pctMeter(p.keylogger_api_score, p.risk_level)}</td>
      <td><div class="techniques">${renderTechniques(p.keylogger_apis_matched)}</div></td>
      <td><span class="exe-path" title="${escapeHtml(p.exe)}">${escapeHtml(p.exe)}</span></td>
      <td class="last-seen">${relativeTime(p.last_seen)}</td>
    </tr>
  `;
}

function applyFilters(processes) {
  const query = els.search.value.trim().toLowerCase();
  return processes.filter((p) => {
    if (els.hideLow.checked && p.risk_level === "LOW") return false;
    if (query && !p.exe.toLowerCase().includes(query)) return false;
    return true;
  });
}

function render() {
  const visible = applyFilters(latestProcesses);
  if (visible.length === 0) {
    els.body.innerHTML = `<tr><td colspan="7" class="empty">No processes match.</td></tr>`;
    return;
  }
  els.body.innerHTML = visible.map(rowHtml).join("");
}

async function refresh() {
  try {
    const res = await fetch("/api/state", { cache: "no-store" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();

    latestProcesses = data.processes || [];
    els.cardTotal.textContent = data.summary.total;
    els.cardHigh.textContent = data.summary.high;
    els.cardMedium.textContent = data.summary.medium;
    els.cardLow.textContent = data.summary.low;

    if (!data.state_file_found) {
      els.liveDot.className = "dot stale";
      els.lastUpdated.textContent = "waiting for temporal_state.json (run main_controller.py)";
    } else {
      els.liveDot.className = "dot live";
      els.lastUpdated.textContent = `updated ${new Date(data.generated_at * 1000).toLocaleTimeString()}`;
    }

    render();
  } catch (err) {
    els.liveDot.className = "dot error";
    els.lastUpdated.textContent = "connection lost, retrying…";
  }
}

els.search.addEventListener("input", render);
els.hideLow.addEventListener("change", render);

refresh();
setInterval(refresh, REFRESH_MS);
