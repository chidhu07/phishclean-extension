/* PhishClean service worker (background.js)
   Privacy: ONLY install_id + version are sent to the backend for license checks.
   No URLs, DOM, tokens, or browsing history ever leave the device.
   The breach checks (see breachCheck.js) make two more kinds of request, both
   to Have I Been Pwned and neither carrying anything about the user: the full
   public breach list, and a 5-character SHA-1 prefix for the password range
   lookup. The reported-phishing feed (lib/phishFeed.js) is one more download,
   from phishclean.com, of the same file for everyone; pages are matched
   against it here.
*/
/* Load shared public-suffix logic. In Chrome (service_worker) this is a
   single-file worker, so importScripts is required. In Firefox the file is
   listed alongside this one in the manifest's background.scripts, so the
   import throws harmlessly (PhishCleanPSL is already defined). */
try { importScripts("lib/publicSuffix.js", "lib/phishFeed.js"); } catch { /* already loaded (Firefox) */ }

const API_BASE = "https://www.phishclean.com/api";
const LICENSE_KEY = "phishclean_license";
const INSTALL_KEY = "phishclean_install_id";
const STATS_KEY = "phishclean_stats";
const WHITELIST_KEY = "phishclean_whitelist_domains";
const THREAT_LOG_KEY = "phishclean_threat_log";
const USER_NAME_KEY = "phishclean_user_name";
const AUTH_KEY = "phishclean_auth";
const ACCOUNT_PROMPT_KEY = "phishclean_account_prompted";
const TRIAL_ENDED_PROMPT_KEY = "phishclean_trial_ended_prompted";
const ACTIVITY_KEY = "phishclean_activity";
const THREAT_LOG_MAX = 200;
const ACTIVITY_DAYS_KEPT = 56;
const ACCOUNT_PROMPT_ALARM = "account-prompt";
const ACCOUNT_PROMPT_DELAY_DAYS = 3;
const WEEKLY_REPORT_ALARM = "weekly-report";
const WEEKLY_REPORT_NOTIFICATION = "weekly-report";
const WEEK_MINUTES = 7 * 24 * 60;
const RECOVERY_URL = "https://www.phishclean.com/help/clicked-a-phishing-link";
const BREACHES_KEY = "phishclean_breaches";
const BREACHES_URL = "https://haveibeenpwned.com/api/v3/breaches";
const BREACHES_ALARM = "breach-list";
const BREACHES_MAX_AGE_MS = 3 * 24 * 60 * 60 * 1000;
const PWNED_RANGE_URL = "https://api.pwnedpasswords.com/range/";
const PWNED_RANGE_CACHE_MAX = 50;
const FEED_ALARM = "phish-feed";

/* Service worker initialized */

/* ── helpers ── */
const nowIso = () => new Date().toISOString();
const uuid = () => crypto.randomUUID();
const getLocal = (keys) => chrome.storage.local.get(keys);
const setLocal = (obj) => chrome.storage.local.set(obj);
const proEnabled = (s) => !!(s?.trial_active || s?.is_paid);

/* ── one-time migration from phishitis_* to phishclean_* keys ── */
async function migrateStorageKeys() {
  const migrated = await getLocal(["_phishclean_migrated"]);
  if (migrated._phishclean_migrated) return;

  const OLD_MAP = {
    "phishitis_license": LICENSE_KEY,
    "phishitis_install_id": INSTALL_KEY,
    "phishitis_stats": STATS_KEY,
    "phishitis_whitelist_domains": WHITELIST_KEY
  };

  const oldData = await getLocal(Object.keys(OLD_MAP));
  const updates = { _phishclean_migrated: true };
  for (const [oldKey, newKey] of Object.entries(OLD_MAP)) {
    if (oldData[oldKey] !== undefined) {
      updates[newKey] = oldData[oldKey];
    }
  }
  await setLocal(updates);
}

/* ── install id ── */
async function ensureInstallId() {
  const data = await getLocal([INSTALL_KEY]);
  if (data[INSTALL_KEY]) return data[INSTALL_KEY];
  const id = uuid();
  await setLocal({ [INSTALL_KEY]: id, installed_at: nowIso() });
  return id;
}

async function getAuthSession() {
  const data = await getLocal([AUTH_KEY]);
  return data[AUTH_KEY] || null;
}

async function setAuthSession(session) {
  await setLocal({ [AUTH_KEY]: session || null });
}

async function clearAuthSession() {
  await chrome.storage.local.remove([AUTH_KEY]);
}

/* ── stats (blocked alerts counter) ── */
async function incrementBlockCount() {
  const data = await getLocal([STATS_KEY]);
  const stats = data[STATS_KEY] || { blocked: 0 };
  stats.blocked += 1;
  await setLocal({ [STATS_KEY]: stats });
  return stats;
}

/* ── threat log (local-only, newest-first) ── */
async function appendThreatLog(threat) {
  const data = await getLocal([THREAT_LOG_KEY]);
  const log = data[THREAT_LOG_KEY] || [];
  log.unshift(threat);
  if (log.length > THREAT_LOG_MAX) log.length = THREAT_LOG_MAX;
  await setLocal({ [THREAT_LOG_KEY]: log });
  return log;
}

/* ── daily activity (local-only) ──
   { "YYYY-MM-DD": { pages, threats } } for the last ACTIVITY_DAYS_KEPT days.
   Counts only — no URLs or domains — so it can feed the toolbar badge and the
   weekly report without adding anything sensitive to storage. Days are the
   user's local calendar days so "today" rolls over at their midnight. */
const dayKey = (d = new Date()) =>
  `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;

/* Every tab reports its scans here, so writes are serialised — a plain
   read-modify-write would drop counts when two pages finish together. */
let activityQueue = Promise.resolve();
function recordActivity(field) {
  activityQueue = activityQueue.then(async () => {
    const data = await getLocal([ACTIVITY_KEY]);
    const days = data[ACTIVITY_KEY] || {};
    const key = dayKey();
    const today = days[key] || { pages: 0, threats: 0 };
    today[field] = (today[field] || 0) + 1;
    days[key] = today;
    const keys = Object.keys(days).sort();
    while (keys.length > ACTIVITY_DAYS_KEPT) delete days[keys.shift()];
    await setLocal({ [ACTIVITY_KEY]: days });
  }).catch(() => { /* storage unavailable — the badge just stays stale */ });
  return activityQueue;
}

/* Totals for the 7 local days ending today. */
async function weekSummary() {
  const data = await getLocal([ACTIVITY_KEY]);
  const days = data[ACTIVITY_KEY] || {};
  let pages = 0, threats = 0;
  for (let i = 0; i < 7; i++) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    const day = days[dayKey(d)];
    if (day) { pages += day.pages || 0; threats += day.threats || 0; }
  }
  return { pages, threats };
}

/* ── badge management ──
   The "!" upgrade prompt wins when setup or payment is pending. Otherwise the
   badge shows how many pages were checked today — the protection is silent by
   design, and without a number on the icon it looks like it is doing nothing.
   Red on a day something was blocked, green otherwise. */
const badgeNumber = (n) => (n > 999 ? `${Math.floor(n / 1000)}k` : n > 0 ? String(n) : "");

async function updateBadge(license) {
  try {
    if (license === undefined) license = (await getLocal([LICENSE_KEY]))[LICENSE_KEY];
    if ((license?.needs_account || license?.needs_payment) && license?.last_checked_at) {
      chrome.action.setBadgeText({ text: "!" });
      chrome.action.setBadgeBackgroundColor({ color: "#ef4444" });
      chrome.action.setTitle({ title: "PhishClean — the trial has ended; 3 of 20 checks are running" });
      return;
    }
    const days = (await getLocal([ACTIVITY_KEY]))[ACTIVITY_KEY] || {};
    const today = days[dayKey()] || { pages: 0, threats: 0 };
    chrome.action.setBadgeText({ text: badgeNumber(today.pages || 0) });
    chrome.action.setBadgeBackgroundColor({ color: today.threats ? "#dc2626" : "#16a34a" });
    const pages = today.pages || 0, threats = today.threats || 0;
    chrome.action.setTitle({
      title: `PhishClean — ${pages} ${pages === 1 ? "page" : "pages"} checked today, ` +
             `${threats} ${threats === 1 ? "threat" : "threats"} blocked`
    });
  } catch { /* action API unavailable in this context */ }
}

/* ── weekly report ──
   One notification a week, and only when there is something to report. It
   opens report/report.html, which is built from the same local counts. */
async function ensureWeeklyReportAlarm() {
  const existing = await chrome.alarms.get(WEEKLY_REPORT_ALARM);
  if (existing) return;
  chrome.alarms.create(WEEKLY_REPORT_ALARM, {
    when: Date.now() + WEEK_MINUTES * 60 * 1000,
    periodInMinutes: WEEK_MINUTES
  });
}

async function sendWeeklyReport() {
  if (!chrome.notifications?.create) return;
  const { pages, threats } = await weekSummary();
  if (!pages) return; /* an empty report is noise — the browser was barely used */
  const title = threats
    ? `PhishClean blocked ${threats} ${threats === 1 ? "threat" : "threats"} this week`
    : "Your week with PhishClean";
  const message = `${pages.toLocaleString()} ${pages === 1 ? "page" : "pages"} checked` +
    (threats ? `, ${threats} blocked.` : ", nothing dangerous found.") +
    " Click to see your weekly safety report.";
  chrome.notifications.create(WEEKLY_REPORT_NOTIFICATION, {
    type: "basic",
    iconUrl: chrome.runtime.getURL("icons/icon128.png"),
    title,
    message
  });
}

const openReport = () => chrome.tabs.create({ url: chrome.runtime.getURL("report/report.html") });

if (chrome.notifications?.onClicked) {
  chrome.notifications.onClicked.addListener((id) => {
    if (id !== WEEKLY_REPORT_NOTIFICATION) return;
    openReport();
    chrome.notifications.clear(id);
  });
}

/* ── Have I Been Pwned: breached-site list ──
   The whole public list (~1 MB, ~900 domains) is downloaded and matched
   locally, so the site the user is on is never sent anywhere. It changes by a
   handful of entries a week; every three days is plenty. Only verified
   breaches of a real site are kept — spam lists, malware and stealer-log dumps
   are not a breach of the site they name. Where a domain has had more than
   one breach, the most recent one is kept. */
let breachRefresh = null;
function refreshBreaches() {
  if (breachRefresh) return breachRefresh;
  breachRefresh = (async () => {
    const cached = (await getLocal([BREACHES_KEY]))[BREACHES_KEY];
    if (cached && Date.now() - cached.fetched_at < BREACHES_MAX_AGE_MS) return cached;
    const r = await fetch(BREACHES_URL);
    if (!r.ok) throw new Error(`breach list ${r.status}`);
    const domains = {};
    for (const b of await r.json()) {
      if (!b.Domain || !b.IsVerified || b.IsFabricated || b.IsSpamList ||
          b.IsMalware || b.IsStealerLog || b.IsRetired) continue;
      const domain = b.Domain.toLowerCase();
      if (domains[domain] && domains[domain].date >= b.BreachDate) continue;
      domains[domain] = { title: b.Title, date: b.BreachDate, count: b.PwnCount, data: b.DataClasses || [] };
    }
    const next = { fetched_at: Date.now(), domains };
    await setLocal({ [BREACHES_KEY]: next });
    return next;
  })().catch(async () => {
    /* Offline or rate-limited — keep serving the last good copy. */
    return (await getLocal([BREACHES_KEY]))[BREACHES_KEY] || null;
  }).finally(() => { breachRefresh = null; });
  return breachRefresh;
}

async function breachForDomain(domain) {
  const list = await refreshBreaches();
  return list?.domains?.[String(domain || "").toLowerCase()] || null;
}

/* ── Have I Been Pwned: Pwned Passwords range lookup ──
   Receives only the first 5 hex characters of a SHA-1 hash; the content
   script does the hashing and the matching, so the password never reaches
   this worker. Add-Padding makes every response a similar size so the prefix
   cannot be inferred from traffic volume. */
const pwnedRangeCache = new Map();
async function pwnedRange(prefix) {
  if (!/^[0-9A-F]{5}$/.test(prefix || "")) throw new Error("bad prefix");
  if (pwnedRangeCache.has(prefix)) return pwnedRangeCache.get(prefix);
  const r = await fetch(PWNED_RANGE_URL + prefix, { headers: { "Add-Padding": "true" } });
  if (!r.ok) throw new Error(`range ${r.status}`);
  const body = await r.text();
  pwnedRangeCache.set(prefix, body);
  if (pwnedRangeCache.size > PWNED_RANGE_CACHE_MAX) {
    pwnedRangeCache.delete(pwnedRangeCache.keys().next().value);
  }
  return body;
}

/* Price labels for the popup and settings. The server picks them from the
   country of the IP the licence check came from (rupees for India), the same
   decision /billing makes, so the price shown is the price charged. */
function priceLabels(pricing) {
  const monthly = pricing?.monthly?.label;
  const annual = pricing?.annual?.label;
  return monthly && annual ? { monthly, annual } : null;
}

/* ── API calls (license only — no user data) ── */
async function registerInstall() {
  const installId = await ensureInstallId();
  const version = chrome.runtime.getManifest().version;
  try {
    const r = await fetch(`${API_BASE}/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ install_id: installId, version })
    });
    const data = await r.json();
    if (!r.ok) throw new Error(data.error || "register failed");
    const license = {
      install_id: installId,
      user_id: data.user_id || null,
      email: data.email || null,
      trial_expires_at: data.trial_expires_at || null,
      trial_active: !!data.trial_active,
      is_paid: !!data.is_paid,
      trial_expired: !data.trial_active && !data.is_paid,
      pro_enabled: proEnabled(data),
      plan_type: data.plan_type || null,
      auth_required: !!data.auth_required,
      has_account: !!data.has_account,
      needs_account: !!data.needs_account,
      needs_payment: !!data.needs_payment,
      is_authenticated: !!data.is_authenticated,
      protection_level: data.protection_level || "free",
      days_remaining: data.days_remaining || 0,
      pricing: priceLabels(data.pricing),
      last_checked_at: nowIso()
    };
    await setLocal({ [LICENSE_KEY]: license });
    updateBadge(license);
    return license;
  } catch (err) {
    /* Offline at install. The trial is granted server-side on the first
       request that lands, so nothing is lost by waiting — but this must not
       claim an account is required, because that would show a paywall to
       someone whose trial has not started yet. Fall back to the free tier:
       the two permanent signals run locally and need no licence at all. */
    const license = {
      install_id: installId,
      user_id: null,
      email: null,
      trial_active: false,
      is_paid: false,
      trial_expired: false,
      pro_enabled: false,
      plan_type: null,
      auth_required: false,
      has_account: false,
      needs_account: false,
      needs_payment: false,
      is_authenticated: false,
      free_tier: true,
      protection_level: "free",
      days_remaining: 0,
      last_checked_at: nowIso()
    };
    await setLocal({ [LICENSE_KEY]: license });
    updateBadge(license);
    return license;
  }
}

/* Ask for an email once, at the highest-intent moment available: right after
   we caught something, or on day 3 if nothing has been caught by then. Never
   at install — the trial runs without an account, so there is nothing to ask
   for until we have shown the user why it is worth giving. */
async function maybePromptForAccount(reason) {
  const data = await getLocal([ACCOUNT_PROMPT_KEY, LICENSE_KEY, AUTH_KEY]);
  if (data[ACCOUNT_PROMPT_KEY]) return;              /* asked once, that's it */
  if (data[AUTH_KEY]?.accessToken) return;           /* already signed in */
  if (data[LICENSE_KEY]?.has_account) return;
  await setLocal({ [ACCOUNT_PROMPT_KEY]: { at: nowIso(), reason } });
  try { await chrome.runtime.openOptionsPage(); } catch { /* no window available */ }
}

/* Tell the user once that the trial is over. Until now nothing did: the
   extension is passive, so the only signs were a "!" badge and a paywall
   inside a popup that a protected user has no reason to open. Every expired
   install in the funnel data sat on the free tier without ever seeing an
   offer. Fires on the first status refresh that reports an ended trial — a
   real one, i.e. trial_expires_at is set — including installs that expired
   before this shipped. Once, then never again. */
async function maybePromptTrialEnded(license) {
  if (!license?.trial_expires_at || license.trial_active || license.is_paid) return;
  const data = await getLocal([TRIAL_ENDED_PROMPT_KEY]);
  if (data[TRIAL_ENDED_PROMPT_KEY]) return;
  await setLocal({ [TRIAL_ENDED_PROMPT_KEY]: { at: nowIso() } });
  try { await chrome.runtime.openOptionsPage(); } catch { /* no window available */ }
}

async function refreshStatus() {
  const installId = await ensureInstallId();
  try {
    const auth = await getAuthSession();
    const headers = { "Content-Type": "application/json" };
    if (auth?.accessToken) headers.Authorization = `Bearer ${auth.accessToken}`;
    const r = await fetch(`${API_BASE}/status`, {
      method: "POST",
      headers,
      body: JSON.stringify({ install_id: installId })
    });
    const data = await r.json();
    if (!r.ok) throw new Error(data.error || "status failed");
    const license = {
      install_id: installId,
      user_id: data.user_id || null,
      email: data.email || auth?.user?.email || null,
      trial_expires_at: data.trial_expires_at || null,
      trial_active: !!data.trial_active,
      is_paid: !!data.is_paid,
      trial_expired: !data.trial_active && !data.is_paid,
      pro_enabled: proEnabled(data),
      plan_type: data.plan_type || null,
      has_subscription: !!data.has_subscription,
      auth_required: !!data.auth_required,
      has_account: !!data.has_account,
      needs_account: !!data.needs_account,
      needs_payment: !!data.needs_payment,
      is_authenticated: !!data.is_authenticated,
      protection_level: data.protection_level || "free",
      days_remaining: data.days_remaining || 0,
      pricing: priceLabels(data.pricing),
      last_checked_at: nowIso()
    };
    await setLocal({ [LICENSE_KEY]: license });
    updateBadge(license);
    maybePromptTrialEnded(license);
    return license;
  } catch (err) {
    const local = await getLocal([LICENSE_KEY]);
    return local[LICENSE_KEY] || null;
  }
}

async function authenticateExtensionAccount(payload) {
  const installId = await ensureInstallId();
  const r = await fetch(`${API_BASE}/extension-auth`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      ...payload,
      install_id: installId
    })
  });
  const data = await r.json();
  if (!r.ok) throw new Error(data.error || "auth failed");

  await setAuthSession({
    accessToken: data.accessToken,
    refreshToken: data.refreshToken,
    expiresAt: data.expiresAt,
    user: data.user || null
  });

  const license = {
    install_id: installId,
    user_id: data.license?.user_id || data.user?.id || null,
    email: data.license?.email || data.user?.email || null,
    trial_expires_at: data.license?.trial_expires_at || null,
    trial_active: !!data.license?.trial_active,
    is_paid: !!data.license?.is_paid,
    trial_expired: !!data.license?.trial_expired,
    pro_enabled: !!data.license?.pro_enabled,
    plan_type: data.license?.plan_type || null,
    has_subscription: !!data.license?.has_subscription,
    auth_required: !!data.license?.auth_required,
    has_account: !!data.license?.has_account,
    needs_account: !!data.license?.needs_account,
    needs_payment: !!data.license?.needs_payment,
    is_authenticated: !!data.license?.is_authenticated,
    protection_level: data.license?.protection_level || "free",
    days_remaining: data.license?.days_remaining || 0,
    last_checked_at: nowIso()
  };
  await setLocal({ [LICENSE_KEY]: license });
  updateBadge(license);
  return { user: data.user || null, license };
}

/* Tell the browser where to go when the extension is removed. This transmits
   the install id and nothing else — it lets us count uninstalls, which is the
   only way to distinguish "still installed and unconverted" from "gone". */
async function setUninstallPing() {
  try {
    const installId = await ensureInstallId();
    chrome.runtime.setUninstallURL(
      `${API_BASE}/status?install_id=${encodeURIComponent(installId)}&event=uninstall`
    );
  } catch { /* not fatal — setUninstallURL is unavailable in some contexts */ }
}

/* ── lifecycle ── */
chrome.runtime.onInstalled.addListener(async (details) => {
  /* Migrate old storage keys before anything else */
  await migrateStorageKeys();

  if (details.reason === "install") {
    await setLocal({ [STATS_KEY]: { blocked: 0 } });
  }
  await registerInstall();
  await setUninstallPing();
  if (details.reason === "install") {
    await chrome.runtime.openOptionsPage();
    /* Fallback ask, only if no detection has fired first — see
       maybePromptForAccount, which no-ops once either path has run. */
    chrome.alarms.create(ACCOUNT_PROMPT_ALARM, {
      when: Date.now() + ACCOUNT_PROMPT_DELAY_DAYS * 24 * 60 * 60 * 1000
    });
  }

  /* Set up periodic license check every 6 hours */
  chrome.alarms.create("license-check", { periodInMinutes: 360 });
  chrome.alarms.create(BREACHES_ALARM, { periodInMinutes: 24 * 60 });
  refreshBreaches();
  chrome.alarms.create(FEED_ALARM, { periodInMinutes: 12 * 60 });
  globalThis.PhishCleanFeed?.refresh();
  /* Installs and updates both land here, so existing users get the weekly
     report a week after updating rather than never. */
  await ensureWeeklyReportAlarm();
});

/* Store installs update themselves, but the browser can hold a downloaded
   update until it restarts. Apply it as soon as it arrives so fixes (and
   payment-flow changes) reach users the same day. No update_url: the stores
   own updates, and Chrome rejects a self-hosted one for store items. */
chrome.runtime.onUpdateAvailable.addListener(() => chrome.runtime.reload());

chrome.runtime.onStartup.addListener(async () => {
  await setUninstallPing();
  await ensureWeeklyReportAlarm();
  globalThis.PhishCleanFeed?.refresh();
  const license = await refreshStatus();
  updateBadge(license);
});

/* ── alarms: periodic license refresh ── */
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "license-check") refreshStatus();
  if (alarm.name === ACCOUNT_PROMPT_ALARM) maybePromptForAccount("day-3");
  if (alarm.name === WEEKLY_REPORT_ALARM) sendWeeklyReport();
  if (alarm.name === BREACHES_ALARM) refreshBreaches();
  if (alarm.name === FEED_ALARM) globalThis.PhishCleanFeed?.refresh();
});

/* ── checkout return: pick the payment up now, not at the next 6-hour check ──
   Dodo redirects to /payment-success once the buyer pays, but the webhook
   that marks the install paid can land a few seconds later, so keep checking
   for about a minute until it shows up. */
const PAYMENT_SUCCESS_URL = /^https:\/\/(www\.)?phishclean\.com\/payment-success/;
let paymentRefreshRunning = false;

async function refreshAfterPayment() {
  if (paymentRefreshRunning) return;
  paymentRefreshRunning = true;
  try {
    for (const waitMs of [0, 3000, 7000, 15000, 30000]) {
      if (waitMs) await new Promise((r) => setTimeout(r, waitMs));
      const license = await refreshStatus();
      if (license?.is_paid) break;
    }
  } finally {
    paymentRefreshRunning = false;
  }
}

chrome.tabs.onUpdated.addListener((tabId, info, tab) => {
  if (info.status === "complete" && PAYMENT_SUCCESS_URL.test(tab.url || "")) refreshAfterPayment();
});

/* The payment page's buttons can't do their job from the page: a tab the
   extension opened can't close itself, and history.back() returns to the
   checkout. The content script forwards the clicks here instead. */
async function handlePaymentPageAction(action, tabId) {
  if (action === "return") {
    const optionsUrl = chrome.runtime.getURL("options/options.html");
    const optionsTab = (await chrome.tabs.query({})).find((t) => (t.url || "").startsWith(optionsUrl));
    if (optionsTab) {
      await chrome.tabs.update(optionsTab.id, { active: true });
      await chrome.windows.update(optionsTab.windowId, { focused: true }).catch(() => {});
    } else {
      await chrome.runtime.openOptionsPage();
    }
  }
  if (tabId != null) await chrome.tabs.remove(tabId).catch(() => {});
}

/* ── webNavigation: detect HTTPS → HTTP downgrade redirects ── */
const tabLastProtocol = new Map();

chrome.webNavigation.onCommitted.addListener((details) => {
  /* Only track main frame navigations */
  if (details.frameId !== 0) return;

  try {
    const url = new URL(details.url);
    const h = url.hostname.toLowerCase();
    /* Skip localhost / loopback — not a real downgrade */
    if (h === "localhost" || h === "127.0.0.1" || h === "[::1]") return;

    const prev = tabLastProtocol.get(details.tabId);
    const curr = url.protocol;

    tabLastProtocol.set(details.tabId, curr);

    if (prev === "https:" && curr === "http:") {
      sendToContentScript(details.tabId, { type: "HTTPS_DOWNGRADE" });
    }
  } catch { /* ignore parse errors */ }
});

/* Clean up tab tracking on close */
chrome.tabs.onRemoved.addListener((tabId) => {
  tabLastProtocol.delete(tabId);
});

/* ── webRequest: detect Authorization headers to third-party domains ──
   Shared registrable-domain logic (see lib/publicSuffix.js). This webRequest
   observer is the resilient fallback for pages whose CSP blocks the injected
   page-context networkHook.js, which otherwise catches the same fetch/XHR
   Authorization headers. */
const registrable = (host) => globalThis.PhishCleanPSL.registrable(host);

chrome.webRequest.onBeforeSendHeaders.addListener(
  (details) => {
    if (!details.requestHeaders) return;
    const authHeader = details.requestHeaders.find(
      (h) => h.name.toLowerCase() === "authorization"
    );
    if (!authHeader) return;

    /* Compare request URL domain to the tab's origin */
    try {
      const reqHost = new URL(details.url).hostname;
      if (details.tabId < 0) return;

      chrome.tabs.get(details.tabId, (tab) => {
        if (chrome.runtime.lastError || !tab?.url) return;
        const tabHost = new URL(tab.url).hostname;

        if (registrable(reqHost) !== registrable(tabHost)) {
          sendToContentScript(details.tabId, { type: "AUTH_HEADER_THIRD_PARTY" });
        }
      });
    } catch { /* ignore parse errors */ }
  },
  { urls: ["<all_urls>"] },
  ["requestHeaders"]
);

/* ── retry helper for messaging content scripts ── */
function sendToContentScript(tabId, message, retries = 3) {
  chrome.tabs.sendMessage(tabId, message, () => {
    if (chrome.runtime.lastError && retries > 0) {
      setTimeout(() => sendToContentScript(tabId, message, retries - 1), 500);
    }
  });
}

/* ── message handler (popup, content script, options page) ── */
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    switch (msg?.type) {
      case "GET_LICENSE_STATE": {
        const data = await getLocal([LICENSE_KEY, INSTALL_KEY, STATS_KEY, AUTH_KEY]);
        sendResponse({
          install_id: data[INSTALL_KEY] || null,
          license: data[LICENSE_KEY] || null,
          auth: data[AUTH_KEY] || null,
          stats: data[STATS_KEY] || { blocked: 0 }
        });
        break;
      }
      case "PAYMENT_PAGE_ACTION": {
        if (!PAYMENT_SUCCESS_URL.test(sender.tab?.url || "")) {
          sendResponse({ ok: false });
          break;
        }
        await handlePaymentPageAction(msg.action, sender.tab.id);
        sendResponse({ ok: true });
        break;
      }
      case "LEAVE_PAGE": {
        /* From the warning's "Go Back" when history cannot take the user off
           the flagged site. Chrome's own "Back to safety" lands on a new tab
           page; Firefox refuses about:newtab from an extension, so blank. */
        const tabId = sender.tab?.id;
        if (tabId != null) {
          try {
            await chrome.tabs.update(tabId, { url: "chrome://newtab/" });
          } catch {
            await chrome.tabs.update(tabId, { url: "about:blank" }).catch(() => {});
          }
        }
        sendResponse({ ok: true });
        break;
      }
      case "REFRESH_LICENSE_STATE": {
        const license = await refreshStatus();
        sendResponse({ ok: true, license });
        break;
      }
      case "INCREMENT_BLOCK_COUNT": {
        const stats = await incrementBlockCount();
        if (msg.threat) await appendThreatLog(msg.threat);
        await recordActivity("threats");
        updateBadge();
        sendResponse({ ok: true, stats });
        /* We just caught something for this user. If they have no account,
           this is the moment to ask — not install, and not day 3. */
        maybePromptForAccount("first-detection");
        break;
      }
      case "PAGE_SCANNED": {
        await recordActivity("pages");
        updateBadge();
        sendResponse({ ok: true });
        break;
      }
      case "GET_ACTIVITY": {
        const data = await getLocal([ACTIVITY_KEY, THREAT_LOG_KEY, STATS_KEY, LICENSE_KEY, WHITELIST_KEY, "installed_at"]);
        sendResponse({
          days: data[ACTIVITY_KEY] || {},
          threats: data[THREAT_LOG_KEY] || [],
          stats: data[STATS_KEY] || { blocked: 0 },
          license: data[LICENSE_KEY] || null,
          trusted: (data[WHITELIST_KEY] || []).length,
          installed_at: data.installed_at || null
        });
        break;
      }
      case "OPEN_REPORT": {
        await openReport();
        sendResponse({ ok: true });
        break;
      }
      case "OPEN_RECOVERY": {
        const from = encodeURIComponent(msg.from || "popup");
        await chrome.tabs.create({ url: `${RECOVERY_URL}?utm_source=extension&utm_medium=${from}` });
        sendResponse({ ok: true });
        break;
      }
      case "BREACH_FOR_DOMAIN": {
        sendResponse({ breach: await breachForDomain(msg.domain) });
        break;
      }
      case "FEED_CHECK": {
        /* The content script sends its own hostname; the match is local. */
        let listed = false;
        try { listed = !!(await globalThis.PhishCleanFeed?.isListed(msg.host)); } catch { /* no feed yet */ }
        sendResponse({ listed });
        break;
      }
      case "PWNED_RANGE": {
        try {
          sendResponse({ ok: true, body: await pwnedRange(msg.prefix) });
        } catch (error) {
          sendResponse({ ok: false, error: error?.message || "range lookup failed" });
        }
        break;
      }
      case "GET_THREAT_LOG": {
        const data = await getLocal([THREAT_LOG_KEY]);
        sendResponse({ threats: data[THREAT_LOG_KEY] || [] });
        break;
      }
      case "GET_USER_NAME": {
        const data = await getLocal([USER_NAME_KEY]);
        sendResponse({ name: data[USER_NAME_KEY] || "" });
        break;
      }
      case "SET_USER_NAME": {
        await setLocal({ [USER_NAME_KEY]: msg.name || "" });
        sendResponse({ ok: true });
        break;
      }
      case "GET_WHITELIST": {
        const data = await getLocal([WHITELIST_KEY]);
        sendResponse({ domains: data[WHITELIST_KEY] || [] });
        break;
      }
      case "SET_WHITELIST": {
        await setLocal({ [WHITELIST_KEY]: msg.domains || [] });
        sendResponse({ ok: true });
        break;
      }
      case "AUTH_WITH_ACCOUNT": {
        try {
          const result = await authenticateExtensionAccount({
            mode: msg.mode,
            email: msg.email,
            password: msg.password,
            fullName: msg.fullName || ""
          });
          sendResponse({ ok: true, ...result });
        } catch (error) {
          sendResponse({ ok: false, error: error?.message || "Authentication failed" });
        }
        break;
      }
      case "LOGOUT_ACCOUNT": {
        /* Unlink the install server-side so /status stops reporting the
           account's trial/paid state for this install after logout. */
        const installId = await ensureInstallId();
        const auth = await getAuthSession();
        try {
          const headers = { "Content-Type": "application/json" };
          if (auth?.accessToken) headers.Authorization = `Bearer ${auth.accessToken}`;
          await fetch(`${API_BASE}/extension-auth`, {
            method: "POST",
            headers,
            body: JSON.stringify({ mode: "logout", install_id: installId })
          });
        } catch { /* offline: still clear the local session */ }
        await clearAuthSession();
        const license = await refreshStatus();
        sendResponse({ ok: true, license });
        break;
      }
      case "OPEN_ONBOARDING": {
        await chrome.runtime.openOptionsPage();
        sendResponse({ ok: true });
        break;
      }
      case "OPEN_PAYMENT": {
        /* No account gate. Checkout is keyed by install_id; user_id rides
           along only when one exists so the account row is updated too. */
        const data = await getLocal([INSTALL_KEY, AUTH_KEY, LICENSE_KEY]);
        const id = data[INSTALL_KEY] || "";
        const userId = data[AUTH_KEY]?.user?.id || data[LICENSE_KEY]?.user_id || "";
        const url = `https://www.phishclean.com/billing?install_id=${encodeURIComponent(id)}&user_id=${encodeURIComponent(userId)}`;
        await chrome.tabs.create({ url });
        sendResponse({ ok: true });
        break;
      }
      case "OPEN_PORTAL": {
        const data = await getLocal([INSTALL_KEY, AUTH_KEY]);
        const id = data[INSTALL_KEY] || "";
        try {
          const headers = { "Content-Type": "application/json" };
          if (data[AUTH_KEY]?.accessToken) {
            headers.Authorization = `Bearer ${data[AUTH_KEY].accessToken}`;
          }
          const r = await fetch(`${API_BASE}/portal`, {
            method: "POST",
            headers,
            body: JSON.stringify({ install_id: id })
          });
          const resp = await r.json();
          if (resp.link) {
            await chrome.tabs.create({ url: resp.link });
            sendResponse({ ok: true });
          } else {
            sendResponse({ ok: false, error: resp.error || "no link" });
          }
        } catch {
          sendResponse({ ok: false, error: "portal request failed" });
        }
        break;
      }
      default:
        sendResponse({ ok: false, error: "unknown message" });
    }
  })();
  return true; /* keep channel open for async response */
});
