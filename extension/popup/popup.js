/* PhishClean popup — shows protection status, stats, and trusted domain management */

const $ = (sel) => document.querySelector(sel);

async function getLicenseState() {
  return chrome.runtime.sendMessage({ type: "GET_LICENSE_STATE" });
}

async function getWhitelist() {
  const resp = await chrome.runtime.sendMessage({ type: "GET_WHITELIST" });
  return resp?.domains || [];
}

async function setWhitelist(domains) {
  await chrome.runtime.sendMessage({ type: "SET_WHITELIST", domains });
}

/* ── helpers ── */
function extractHostname(input) {
  const trimmed = (input || "").trim().toLowerCase();
  if (!trimmed) return "";
  try {
    if (trimmed.includes("://") || trimmed.includes("/")) {
      const url = new URL(trimmed.startsWith("http") ? trimmed : "https://" + trimmed);
      return url.hostname;
    }
  } catch { /* fall through */ }
  return trimmed.replace(/\/+$/, "");
}

function isValidDomain(d) {
  if (!d || d.length < 3) return false;
  if (d === "localhost") return true;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(d)) return false;
  if (d.startsWith("[")) return false;
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/.test(d)) return false;
  if (!d.includes(".") && d !== "localhost") return false;
  return true;
}

function showWlMsg(text, type) {
  const msg = $("#wl-msg");
  msg.textContent = text;
  msg.className = "wl-msg " + type;
  if (type === "success") {
    setTimeout(() => { msg.textContent = ""; msg.className = "wl-msg"; }, 2500);
  }
}

/* ── render badge ── */
function renderBadge(license) {
  const badge = $("#status-badge");
  if (license?.is_paid) {
    badge.textContent = "Pro";
    badge.className = "badge paid";
  } else if (license?.trial_active) {
    badge.textContent = "Trial";
    badge.className = "badge active";
  } else {
    /* No trial, no plan — still protected, just not fully. "Off" was wrong
       even before this change, because the link tooltips never stopped. */
    badge.textContent = "Free";
    badge.className = "badge trial";
  }
}

/* ── render license section ── */
function renderLicense(license) {
  const planEl = $("#plan-name");
  const trialRow = $("#trial-row");
  const countdown = $("#trial-countdown");
  const upgradeBtn = $("#btn-upgrade");

  /* Always remove stale trial warning banner on re-render */
  const oldWarning = document.querySelector(".trial-warning");
  if (oldWarning) oldWarning.remove();

  /* Remove stale manage link on re-render */
  const oldManage = document.querySelector(".manage-sub");
  if (oldManage) oldManage.remove();

  if (license?.is_paid) {
    planEl.textContent = license.plan_type === "annual" ? "Pro (Annual)" : "Pro (Monthly)";
    trialRow.style.display = "none";
    upgradeBtn.classList.add("hidden");

    /* Add "Manage Subscription" link */
    const manageLink = document.createElement("a");
    manageLink.href = "#";
    manageLink.className = "manage-sub";
    manageLink.textContent = "Manage subscription";
    manageLink.addEventListener("click", (e) => {
      e.preventDefault();
      manageLink.textContent = "Loading...";
      chrome.runtime.sendMessage({ type: "OPEN_PORTAL" }).then((resp) => {
        manageLink.textContent = "Manage subscription";
        if (!resp?.ok) {
          manageLink.textContent = "Contact support to manage";
          manageLink.addEventListener("click", (ev) => {
            ev.preventDefault();
            chrome.tabs.create({ url: "https://www.phishclean.com/#contact" });
          }, { once: true });
        }
      }).catch(() => { manageLink.textContent = "Manage subscription"; });
    });
    const licenseSection = $("#license-section");
    licenseSection.appendChild(manageLink);
  } else if (license?.trial_active) {
    const remaining = Math.max(0, Number(license?.days_remaining || 0));
    planEl.textContent = "15-Day Free Trial";
    trialRow.style.display = "flex";
    countdown.textContent = remaining <= 1 ? "1 day remaining" : `${remaining} days remaining`;
    upgradeBtn.classList.remove("hidden");
  } else {
    planEl.textContent = "Free";
    trialRow.style.display = "flex";
    countdown.textContent = "2 of 17 checks — the free two never expire";
    upgradeBtn.classList.remove("hidden");
  }
}

/* ── render stats ── */
function renderStats(stats) {
  $("#blocked-count").textContent = stats?.blocked || 0;
}

/* ── render report button ── */
var _cachedLicense = null;
var _cachedInstallId = "";
var _cachedStats = {};

function renderReportButton(license) {
  const btn = $("#btn-report");
  const textEl = $("#report-btn-text");
  if (!btn) return;

  if (license?.is_paid || license?.trial_active) {
    btn.classList.remove("locked");
    textEl.textContent = "Download PDF Report";
  } else {
    btn.classList.add("locked");
    textEl.textContent = "";
    textEl.appendChild(document.createTextNode("Download PDF Report "));
    const proBadge = document.createElement("span");
    proBadge.className = "report-pro-badge";
    proBadge.textContent = "PRO";
    textEl.appendChild(proBadge);
  }
}

/* ── render whitelist ── */
function renderWhitelist(domains) {
  const list = $("#wl-list");
  const empty = $("#wl-empty");
  $("#wl-count").textContent = domains.length;

  list.querySelectorAll(".wl-item").forEach((el) => el.remove());

  if (domains.length === 0) {
    empty.style.display = "block";
    return;
  }
  empty.style.display = "none";

  domains.forEach((domain) => {
    const item = document.createElement("div");
    item.className = "wl-item";

    const span = document.createElement("span");
    span.className = "wl-domain";
    span.textContent = domain;

    const btn = document.createElement("button");
    btn.className = "wl-remove";
    btn.dataset.domain = domain;
    btn.title = "Remove";
    btn.textContent = "\u2715";

    item.appendChild(span);
    item.appendChild(btn);
    list.appendChild(item);
  });
}

/* ── payment wall ── */
function showPaymentWall(installId) {
  const overlay = document.createElement("div");
  overlay.className = "paywall-overlay";
  overlay.innerHTML = `
    <div class="paywall">
      <div class="logo">
        <svg width="24" height="27" viewBox="0 0 32 36" fill="none"><path d="M16 1.5L3 7v10.5c0 9 5.5 16.5 13 18.5 7.5-2 13-9.5 13-18.5V7L16 1.5z" fill="#e2e8f0"/><path d="M16 4.5L6 9v8.5c0 7.5 4.5 13.5 10 15.5 5.5-2 10-8 10-15.5V9L16 4.5z" fill="#cbd5e1"/><path d="M11 18.5l3.5 3.5 7-7" stroke="#22c55e" stroke-width="2.8" stroke-linecap="round" stroke-linejoin="round"/></svg>
        <span class="logo-text">PhishClean</span>
      </div>
      <div class="paywall-title">Restore the other 15 checks</div>
      <p class="paywall-sub">Your trial has ended. Link safety and password-field checks keep running for free. Subscribe to turn the other 15 back on &mdash; token and secret leaks, lookalike domains, HTTPS downgrades.</p>
      <button class="paywall-btn primary" id="pw-monthly">$9/month</button>
      <button class="paywall-btn secondary" id="pw-annual">$59/year <span class="paywall-save">— Save 45%</span></button>
      <a href="#" class="paywall-skip" id="pw-skip">Open setup</a>
      <div class="paywall-support">
        <a href="https://www.phishclean.com/#contact">Contact support</a>
      </div>
    </div>
  `;
  document.body.appendChild(overlay);

  /* Straight to checkout, account or not. Billing is keyed by install_id
     (the webhook writes is_paid onto the licenses row), and an account can
     be added afterwards — adoptInstallPayment on the server carries the plan
     across. Sending an unconverted user to a signup form first was the
     single worst-converting step in the funnel (1.2% of installs ever made
     an account), so it no longer stands between them and paying. */
  const userId = _cachedLicense?.user_id || "";
  const base = "https://www.phishclean.com/billing";
  document.getElementById("pw-monthly").addEventListener("click", () => {
    chrome.tabs.create({ url: `${base}?install_id=${installId}&user_id=${encodeURIComponent(userId)}&plan=monthly` });
  });
  document.getElementById("pw-annual").addEventListener("click", () => {
    chrome.tabs.create({ url: `${base}?install_id=${installId}&user_id=${encodeURIComponent(userId)}&plan=annual` });
  });
  document.getElementById("pw-skip").addEventListener("click", (e) => {
    e.preventDefault();
    chrome.runtime.openOptionsPage();
  });
}

/* ── init ── */
async function init() {
  const resp = await getLicenseState();
  const license = resp?.license || {};
  const stats = resp?.stats || {};

  _cachedLicense = license;
  _cachedInstallId = resp?.install_id || "";
  _cachedStats = stats;

  renderBadge(license);
  renderLicense(license);
  renderStats(stats);
  renderReportButton(license);

  /* Show paywall overlay when setup or payment is still pending */
  if (license?.needs_account || license?.needs_payment) {
    showPaymentWall(license?.install_id || "");
  }

  const domains = await getWhitelist();
  renderWhitelist(domains);

  /* Background license refresh to catch recent payments */
  chrome.runtime.sendMessage({ type: "REFRESH_LICENSE_STATE" }).then((freshResp) => {
    const freshLicense = freshResp?.license;
    if (freshLicense && freshLicense.is_paid !== license.is_paid) {
      _cachedLicense = freshLicense;
      renderBadge(freshLicense);
      renderLicense(freshLicense);
      renderReportButton(freshLicense);
    }
  }).catch(() => {});
}

/* ── add domain helper ── */
async function addDomain(domain) {
  const current = await getWhitelist();
  if (current.includes(domain)) {
    showWlMsg(`${domain} is already trusted`, "error");
    return;
  }
  if (current.length >= 100) {
    showWlMsg("Maximum 100 trusted domains reached", "error");
    return;
  }
  const next = [...current, domain];
  await setWhitelist(next);
  renderWhitelist(next);
  showWlMsg(`${domain} added`, "success");
}

/* ── event listeners ── */

/* Trust the current tab's domain in one click */
$("#btn-add-wl").addEventListener("click", async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.url) return;
  try {
    const domain = new URL(tab.url).hostname;
    if (!domain) return;
    await addDomain(domain);
  } catch { /* ignore invalid URLs */ }
});

/* Manual domain add */
$("#btn-add-manual").addEventListener("click", async () => {
  const input = $("#wl-input");
  const raw = input.value;
  const domain = extractHostname(raw);
  if (!domain) {
    showWlMsg("Please enter a domain", "error");
    return;
  }
  if (!isValidDomain(domain)) {
    showWlMsg("Invalid domain format", "error");
    return;
  }
  await addDomain(domain);
  input.value = "";
});

/* Enter key on input */
$("#wl-input").addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    e.preventDefault();
    $("#btn-add-manual").click();
  }
});

/* Remove domain (event delegation) */
$("#wl-list").addEventListener("click", async (e) => {
  const btn = e.target.closest(".wl-remove");
  if (!btn) return;
  const domain = btn.dataset.domain;
  const current = await getWhitelist();
  const next = current.filter((d) => d !== domain);
  await setWhitelist(next);
  renderWhitelist(next);
});

/* Upgrade button */
$("#btn-upgrade").addEventListener("click", () => {
  chrome.runtime.sendMessage({ type: "OPEN_PAYMENT" });
});

/* Settings link */
$("#btn-options").addEventListener("click", (e) => {
  e.preventDefault();
  chrome.runtime.openOptionsPage();
});

/* Support link */
$("#btn-support").addEventListener("click", (e) => {
  e.preventDefault();
  chrome.tabs.create({ url: "https://www.phishclean.com/#contact" });
});

/* ── PDF Report download ── */
$("#btn-report").addEventListener("click", async () => {
  if (!_cachedLicense?.is_paid && !_cachedLicense?.trial_active) {
    $("#report-btn-text").textContent = "Included with a trial or plan";
    setTimeout(() => { $("#report-btn-text").textContent = "Download PDF Report"; }, 2000);
    return;
  }
  const nameResp = await chrome.runtime.sendMessage({ type: "GET_USER_NAME" });
  if (!nameResp?.name) {
    $("#name-prompt").classList.remove("hidden");
    $("#name-input").focus();
    return;
  }
  await doGenerateReport(nameResp.name);
});

$("#btn-name-save").addEventListener("click", async () => {
  const name = $("#name-input").value.trim();
  if (!name) return;
  await chrome.runtime.sendMessage({ type: "SET_USER_NAME", name });
  $("#name-prompt").classList.add("hidden");
  await doGenerateReport(name);
});

$("#name-input").addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    e.preventDefault();
    $("#btn-name-save").click();
  }
});

async function doGenerateReport(userName) {
  const btn = $("#btn-report");
  const textEl = $("#report-btn-text");
  btn.disabled = true;
  textEl.textContent = "Generating...";

  try {
    const threatResp = await chrome.runtime.sendMessage({ type: "GET_THREAT_LOG" });
    const domains = await getWhitelist();

    generatePhishCleanReport({
      userName: userName,
      installId: _cachedInstallId,
      stats: _cachedStats,
      license: _cachedLicense,
      threats: threatResp?.threats || [],
      trustedDomains: domains,
      generatedAt: new Date().toISOString()
    });
  } catch { /* PDF generation failed */
  } finally {
    btn.disabled = false;
    textEl.textContent = "Download PDF Report";
  }
}

init();
