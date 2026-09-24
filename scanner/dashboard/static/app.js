const REFRESH_MS = 3000;

const els = {
  liveDot: document.getElementById("live-dot"),
  lastUpdated: document.getElementById("last-updated"),
  refreshBtn: document.getElementById("refresh-btn"),
  cardTotal: document.getElementById("card-total"),
  cardHigh: document.getElementById("card-high"),
  cardMedium: document.getElementById("card-medium"),
  cardLow: document.getElementById("card-low"),
  search: document.getElementById("search"),
  riskFilter: document.getElementById("risk-filter"),
  body: document.getElementById("process-body"),
  table: document.getElementById("process-table"),
  emptyState: document.getElementById("empty-state"),
  emptyTitle: document.getElementById("empty-title"),
  emptySubtitle: document.getElementById("empty-subtitle"),
  emptyHint: document.getElementById("empty-hint"),
  menuBtn: document.getElementById("menu-btn"),
  sidebar: document.getElementById("sidebar"),
  sidebarBackdrop: document.getElementById("sidebar-backdrop"),
  sortScoreHeader: document.querySelector('th[data-sort="risk_score"]'),
};

let latestProcesses = [];
let activeRiskFilter = "ALL";
let sortDirection = "desc"; // scores sort desc by default (highest risk first)

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str ?? "";
  return div.innerHTML;
}

function relativeTime(epochSeconds) {
  if (!epochSeconds) return "–";
  const seconds = Math.max(0, Math.round(Date.now() / 1000 - epochSeconds));
  if (seconds < 5) return "just now";
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

function pctMeter(value) {
  if (value === null || value === undefined) {
    return `<span class="meter-pct">&ndash;</span>`;
  }
  const pct = Math.round(value * 100);
  return `
    <div class="meter-wrap">
      <span class="meter"><span class="meter-fill" style="width:${pct}%"></span></span>
      <span class="meter-pct">${pct}%</span>
    </div>
  `;
}

function renderTechniques(matched) {
  if (!matched || matched.length === 0) {
    return `<span class="tech-chip none">none</span>`;
  }
  return matched.map((name) => `<span class="tech-chip">${escapeHtml(name)}</span>`).join("");
}

function rowHtml(p) {
  return `
    <tr data-risk="${p.risk_level}">
      <td><span class="badge ${p.risk_level}">${p.risk_level}</span></td>
      <td class="score-cell">${p.risk_score}</td>
      <td>${pctMeter(p.ml_risk_score)}</td>
      <td>${pctMeter(p.keylogger_api_score)}</td>
      <td><div class="techniques">${renderTechniques(p.keylogger_apis_matched)}</div></td>
      <td><span class="exe-path" title="${escapeHtml(p.exe)}">${escapeHtml(p.exe)}</span></td>
      <td class="last-seen">${relativeTime(p.last_seen)}</td>
    </tr>
  `;
}

function applyFilters(processes) {
  const query = els.search.value.trim().toLowerCase();
  let rows = processes.filter((p) => {
    if (activeRiskFilter !== "ALL" && p.risk_level !== activeRiskFilter) return false;
    if (query && !p.exe.toLowerCase().includes(query)) return false;
    return true;
  });
  rows = rows.slice().sort((a, b) =>
    sortDirection === "desc" ? b.risk_score - a.risk_score : a.risk_score - b.risk_score
  );
  return rows;
}

function render() {
  const visible = applyFilters(latestProcesses);

  if (latestProcesses.length === 0) {
    els.table.hidden = true;
    els.emptyState.hidden = false;
    els.emptyHint.hidden = false;
    els.emptyTitle.textContent = "Waiting for data";
    els.emptySubtitle.textContent = "Run the monitor to start collecting risk data.";
    return;
  }

  if (visible.length === 0) {
    els.table.hidden = true;
    els.emptyState.hidden = false;
    els.emptyHint.hidden = true;
    els.emptyTitle.textContent = "No matches";
    els.emptySubtitle.textContent = "Nothing matches this filter. Try clearing the search or risk filter.";
    return;
  }

  els.table.hidden = false;
  els.emptyState.hidden = true;
  els.body.innerHTML = visible.map(rowHtml).join("");
}

async function refresh(isManual) {
  if (isManual) {
    els.refreshBtn.classList.remove("is-spinning");
    // restart the CSS animation
    void els.refreshBtn.offsetWidth;
    els.refreshBtn.classList.add("is-spinning");
  }
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
      els.liveDot.className = "pulse-dot stale";
      els.lastUpdated.textContent = "no data yet";
    } else {
      els.liveDot.className = "pulse-dot live";
      els.lastUpdated.textContent = `updated ${new Date(data.generated_at * 1000).toLocaleTimeString()}`;
    }

    render();
  } catch (err) {
    els.liveDot.className = "pulse-dot error";
    els.lastUpdated.textContent = "connection lost, retrying…";
  }
}

// --- toolbar interactions ---

els.search.addEventListener("input", render);

els.riskFilter.addEventListener("click", (evt) => {
  const btn = evt.target.closest(".seg-btn");
  if (!btn) return;
  activeRiskFilter = btn.dataset.filter;
  for (const el of els.riskFilter.querySelectorAll(".seg-btn")) {
    const active = el === btn;
    el.classList.toggle("is-active", active);
    el.setAttribute("aria-selected", String(active));
  }
  render();
});

els.sortScoreHeader.classList.add("sort-desc");
els.sortScoreHeader.addEventListener("click", () => {
  sortDirection = sortDirection === "desc" ? "asc" : "desc";
  els.sortScoreHeader.classList.toggle("sort-desc", sortDirection === "desc");
  els.sortScoreHeader.classList.toggle("sort-asc", sortDirection === "asc");
  render();
});

els.refreshBtn.addEventListener("click", () => refresh(true));

// --- mobile sidebar toggle ---

function openSidebar() {
  els.sidebar.classList.add("is-open");
  els.sidebarBackdrop.hidden = false;
  els.menuBtn.setAttribute("aria-expanded", "true");
}
function closeSidebar() {
  els.sidebar.classList.remove("is-open");
  els.sidebarBackdrop.hidden = true;
  els.menuBtn.setAttribute("aria-expanded", "false");
}
els.menuBtn.addEventListener("click", () => {
  els.sidebar.classList.contains("is-open") ? closeSidebar() : openSidebar();
});
els.sidebarBackdrop.addEventListener("click", closeSidebar);

// --- sidebar scroll-spy ---

const navLinks = document.querySelectorAll(".nav-link");
const sections = Array.from(navLinks)
  .map((link) => document.querySelector(link.getAttribute("href")))
  .filter(Boolean);
navLinks.forEach((link) => link.addEventListener("click", closeSidebar));
const pageTitle = document.getElementById("page-title");
const TITLES = { overview: "Overview", processes: "Tracked Processes", about: "About" };

function setActiveNav(id) {
  for (const link of navLinks) {
    link.classList.toggle("is-active", link.dataset.nav === id);
  }
  if (TITLES[id]) pageTitle.textContent = TITLES[id];
}

// "Last section whose top has scrolled past the offset line" -- unlike an
// IntersectionObserver band, this stays correct for a short trailing
// section (like About) that never fills the viewport on its own.
const SCROLL_SPY_OFFSET = 96;

function updateActiveSectionByScroll() {
  // The last section may be shorter than the viewport, so its top can
  // never scroll past SCROLL_SPY_OFFSET once the page hits its scroll
  // limit -- treat "scrolled to the bottom" as its own case rather than
  // relying purely on the offset-line crossing.
  const nearBottom =
    window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 4;
  if (nearBottom) {
    setActiveNav(sections[sections.length - 1].id);
    return;
  }

  let current = sections[0];
  for (const section of sections) {
    if (section.getBoundingClientRect().top - SCROLL_SPY_OFFSET <= 0) {
      current = section;
    }
  }
  if (current) setActiveNav(current.id);
}

let scrollTicking = false;
window.addEventListener("scroll", () => {
  if (scrollTicking) return;
  scrollTicking = true;
  requestAnimationFrame(() => {
    updateActiveSectionByScroll();
    scrollTicking = false;
  });
});
updateActiveSectionByScroll();

// --- boot ---

refresh(false);
setInterval(() => refresh(false), REFRESH_MS);
