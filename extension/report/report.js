/* PhishClean weekly safety report — rendered entirely from local storage
   (daily counts + the local threat log) via the background worker. */

const $ = (sel) => document.querySelector(sel);

const dayKey = (d) =>
  `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
const plural = (n, one, many) => `${n.toLocaleString()} ${n === 1 ? one : many}`;
const fmtDay = (d, opts) => d.toLocaleDateString(undefined, opts);

/* The 7 local days ending today, oldest first. */
function lastSevenDays() {
  const out = [];
  for (let i = 6; i >= 0; i--) {
    const d = new Date();
    d.setHours(12, 0, 0, 0);
    d.setDate(d.getDate() - i);
    out.push(d);
  }
  return out;
}

function renderChart(days, activity) {
  const chart = $("#chart");
  const tooltip = $("#tooltip");
  const table = $("#chart-table");
  const rows = days.map((d) => ({ d, ...(activity[dayKey(d)] || {}) }))
    .map((r) => ({ d: r.d, pages: r.pages || 0, threats: r.threats || 0 }));
  const max = Math.max(1, ...rows.map((r) => r.pages));
  const peakIndex = rows.reduce((best, r, i) => (r.pages > rows[best].pages ? i : best), 0);

  const axis = document.createElement("div");
  axis.className = "axis";

  rows.forEach((r, i) => {
    const col = document.createElement("div");
    col.className = "col";
    col.tabIndex = 0;
    const label = `${fmtDay(r.d, { weekday: "long", day: "numeric", month: "short" })}: ` +
      `${plural(r.pages, "page", "pages")} checked, ${plural(r.threats, "threat", "threats")} blocked`;
    col.setAttribute("aria-label", label);

    const bar = document.createElement("div");
    bar.className = r.pages ? "bar" : "bar zero";
    bar.style.height = `${(r.pages / max) * 100}%`;
    col.appendChild(bar);

    /* Direct label on the busiest day only — a number on every bar is noise. */
    if (i === peakIndex && r.pages) {
      const peak = document.createElement("span");
      peak.className = "peak";
      peak.style.bottom = `${(r.pages / max) * 100}%`;
      peak.textContent = r.pages.toLocaleString();
      col.appendChild(peak);
    }

    const show = () => {
      tooltip.hidden = false;
      tooltip.textContent = "";
      const title = document.createElement("div");
      title.textContent = fmtDay(r.d, { weekday: "short", day: "numeric", month: "short" });
      const pages = document.createElement("div");
      const pb = document.createElement("b");
      pb.textContent = r.pages.toLocaleString();
      pages.append(pb, ` ${r.pages === 1 ? "page" : "pages"} checked`);
      tooltip.append(title, pages);
      if (r.threats) {
        const t = document.createElement("div");
        t.textContent = `⚠ ${plural(r.threats, "threat", "threats")} blocked`;
        tooltip.append(t);
      }
      const card = chart.closest(".card").getBoundingClientRect();
      const box = col.getBoundingClientRect();
      const left = Math.min(Math.max(box.left - card.left + box.width / 2 - tooltip.offsetWidth / 2, 8),
        card.width - tooltip.offsetWidth - 8);
      tooltip.style.left = `${left}px`;
      tooltip.style.top = `${chart.offsetTop - 8}px`;
    };
    const hide = () => { tooltip.hidden = true; };
    col.addEventListener("mouseenter", show);
    col.addEventListener("focus", show);
    col.addEventListener("mouseleave", hide);
    col.addEventListener("blur", hide);
    chart.appendChild(col);

    const tick = document.createElement("span");
    tick.textContent = fmtDay(r.d, { weekday: "short" });
    if (i === rows.length - 1) tick.className = "today";
    /* Status marker under the day, so it never collides with the peak label:
       icon + count, never colour alone. */
    if (r.threats) {
      const flag = document.createElement("span");
      flag.className = "flag";
      flag.textContent = `⚠ ${r.threats}`;
      tick.appendChild(flag);
    }
    axis.appendChild(tick);

    const tr = document.createElement("tr");
    for (const v of [fmtDay(r.d, { weekday: "short", day: "numeric", month: "short" }), r.pages.toLocaleString(), r.threats.toLocaleString()]) {
      const td = document.createElement("td");
      td.textContent = v;
      tr.appendChild(td);
    }
    table.appendChild(tr);
  });
  chart.after(axis);
  return rows;
}

function renderThreats(threats, since) {
  const list = $("#threats");
  const recent = threats.filter((t) => Date.parse(t.occurred_at) >= since);
  if (!recent.length) {
    $("#threats-empty").hidden = false;
    return recent;
  }
  for (const t of recent.slice(0, 20)) {
    const li = document.createElement("li");
    const head = document.createElement("div");
    head.className = "threat-head";
    const domain = document.createElement("span");
    domain.className = "threat-domain";
    domain.textContent = t.domain || "Unknown site";
    const when = document.createElement("span");
    when.className = "threat-when";
    when.textContent = new Date(t.occurred_at).toLocaleString(undefined,
      { weekday: "short", hour: "numeric", minute: "2-digit" });
    head.append(domain, when);
    const level = document.createElement("span");
    level.className = `threat-level ${t.level === "danger" ? "danger" : "warning"}`;
    level.textContent = `${t.level === "danger" ? "⛔ High risk" : "⚠ Warning"} · score ${t.score ?? "?"}`;
    const reason = document.createElement("div");
    reason.className = "threat-reason";
    reason.textContent = (t.reasons && t.reasons[0]) || "";
    li.append(head, level, reason);
    list.appendChild(li);
  }
  if (recent.length > 20) {
    const more = document.createElement("li");
    more.className = "threat-reason";
    more.textContent = `…and ${recent.length - 20} more. The full list is in the PDF report in the toolbar popup.`;
    list.appendChild(more);
  }
  return recent;
}

function renderPlan(license) {
  const text = $("#plan-text");
  const cta = $("#plan-cta");
  if (license?.is_paid) {
    text.textContent = "All 20 checks are on. Thank you for supporting PhishClean.";
    return;
  }
  if (license?.trial_active) {
    const days = Math.max(0, Number(license.days_remaining || 0));
    text.textContent = `Your free trial has ${plural(days, "day", "days")} left, with all 20 checks on. ` +
      "When it ends, reported-phishing blocking, link safety and password-field checks keep running, and the other 17 pause.";
    cta.textContent = "Keep all 20 checks on";
  } else {
    text.textContent = "3 of 20 checks are running: reported-phishing blocking, link safety and password fields. " +
      "The other 17 are paused, including lookalike domains, fake virus warnings, leaked passwords, regional scam pages and HTTPS downgrades.";
    cta.textContent = "Turn the other 17 back on";
  }
  cta.hidden = false;
  cta.addEventListener("click", () => chrome.runtime.sendMessage({ type: "OPEN_PAYMENT" }));
}

async function init() {
  const resp = await chrome.runtime.sendMessage({ type: "GET_ACTIVITY" });
  const days = lastSevenDays();
  $("#range").textContent =
    `${fmtDay(days[0], { day: "numeric", month: "short" })} – ${fmtDay(days[6], { day: "numeric", month: "short", year: "numeric" })}`;

  const rows = renderChart(days, resp?.days || {});
  const since = new Date(days[0]).setHours(0, 0, 0, 0);
  const pages = rows.reduce((s, r) => s + r.pages, 0);
  const counted = rows.reduce((s, r) => s + r.threats, 0);
  const recent = renderThreats(resp?.threats || [], since);
  /* The threat log predates the daily counts, so for the first week after
     updating the log can know about blocks the counters never saw. */
  const threats = Math.max(counted, recent.length);

  $("#t-pages").textContent = pages.toLocaleString();
  $("#t-threats").textContent = threats.toLocaleString();
  $("#t-trusted").textContent = (resp?.trusted || 0).toLocaleString();

  const allTime = resp?.stats?.blocked || 0;
  $("#lede").textContent = pages
    ? `PhishClean checked ${plural(pages, "page", "pages")} this week and blocked ${plural(threats, "threat", "threats")}.` +
      (allTime > threats ? ` ${plural(allTime, "threat", "threats")} blocked since you installed it.` : "")
    : "No pages were checked this week. PhishClean counts pages as you browse, so this fills in as you use the browser.";

  renderPlan(resp?.license);

  $("#recovery").addEventListener("click", (e) => {
    e.preventDefault();
    chrome.runtime.sendMessage({ type: "OPEN_RECOVERY", from: "report" });
  });
}

init();
