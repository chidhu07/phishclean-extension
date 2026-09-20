/* PhishClean service worker (background.js)
   Privacy: ONLY install_id + version are sent to the backend for license checks.
   No URLs, DOM, tokens, or browsing history ever leave the device.
*/
/* Load shared public-suffix logic. In Chrome (service_worker) this is a
   single-file worker, so importScripts is required. In Firefox the file is
   listed alongside this one in the manifest's background.scripts, so the
   import throws harmlessly (PhishCleanPSL is already defined). */
try { importScripts("lib/publicSuffix.js"); } catch { /* already loaded (Firefox) */ }

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
const THREAT_LOG_MAX = 200;
const ACCOUNT_PROMPT_ALARM = "account-prompt";
const ACCOUNT_PROMPT_DELAY_DAYS = 3;

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

/* ── badge management ── */
function updateBadge(license) {
  if ((license?.needs_account || license?.needs_payment) && license?.last_checked_at) {
    chrome.action.setBadgeText({ text: "!" });
    chrome.action.setBadgeBackgroundColor({ color: "#ef4444" });
  } else {
    chrome.action.setBadgeText({ text: "" });
  }
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
});

chrome.runtime.onStartup.addListener(async () => {
  await setUninstallPing();
  const license = await refreshStatus();
  updateBadge(license);
});

/* ── alarms: periodic license refresh ── */
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "license-check") refreshStatus();
  if (alarm.name === ACCOUNT_PROMPT_ALARM) maybePromptForAccount("day-3");
});

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
      case "REFRESH_LICENSE_STATE": {
        const license = await refreshStatus();
        sendResponse({ ok: true, license });
        break;
      }
      case "INCREMENT_BLOCK_COUNT": {
        const stats = await incrementBlockCount();
        if (msg.threat) await appendThreatLog(msg.threat);
        sendResponse({ ok: true, stats });
        /* We just caught something for this user. If they have no account,
           this is the moment to ask — not install, and not day 3. */
        maybePromptForAccount("first-detection");
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
