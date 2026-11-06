/**
 * Browser verification for the 1.11.0 sign-in tricks: browser-in-the-browser
 * fake popups and device-code phishing.
 *
 * Pages are served through context.route() over https on .example hosts.
 * Nothing is typed or sent.
 *
 * Run: node tests/sign-in-tricks-verify.mjs   (EXT_DIR=dist/chrome for the store build)
 */
import { chromium } from "playwright";
import { readFileSync, mkdtempSync, mkdirSync } from "fs";
import { resolve, dirname, join } from "path";
import { fileURLToPath } from "url";
import { tmpdir } from "os";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, "..");
const EXT = resolve(ROOT, process.env.EXT_DIR || "extension");
const SHOTS = resolve(__dirname, "screenshots");
let pass = 0, fail = 0;
const ok = (label, cond, detail = "") => {
  console.log(`  ${cond ? "PASS" : "FAIL"}: ${label}${cond ? "" : detail ? " — " + detail : ""}`);
  cond ? pass++ : fail++;
};
const fixture = (name) => readFileSync(resolve(__dirname, name), "utf8");
const TRIAL = { install_id: "test", trial_active: true, is_paid: false, pro_enabled: true };
const FREE = { install_id: "test", trial_active: false, is_paid: false, pro_enabled: false };
mkdirSync(SHOTS, { recursive: true });

const context = await chromium.launchPersistentContext(mkdtempSync(join(tmpdir(), "phishclean-signin-")), {
  headless: false,
  args: [
    `--disable-extensions-except=${EXT}`, `--load-extension=${EXT}`,
    "--no-first-run", "--no-default-browser-check", "--no-sandbox",
    "--disable-features=DisableLoadExtensionCommandLineSwitch",
  ],
});
await context.route("**://www.phishclean.com/**", (route) => route.abort());
const serve = (pattern, file) => context.route(pattern, (r) => r.fulfill({ status: 200, contentType: "text/html", body: fixture(file) }));
await serve("https://free-skins-drop.example/**", "test-bitb.html");
await serve("https://doc-share-portal.example/**", "test-device-code.html");
await serve("https://security-tips.example/**", "test-bitb-article.html");

try {
  let [worker] = context.serviceWorkers();
  if (!worker) worker = await context.waitForEvent("serviceworker", { timeout: 30000 });
  await new Promise((r) => setTimeout(r, 1500));

  let license = TRIAL;
  const setLicense = (l) => { license = l; return worker.evaluate((v) => chrome.storage.local.set({ phishclean_license: v }), l); };
  const open = async (url, wait = 1800) => {
    await setLicense(license);
    const page = await context.newPage();
    await page.goto(url);
    await page.waitForTimeout(wait);
    return page;
  };
  const modalShown = async (page) => (await page.locator("#phishclean-root").count()) === 1;
  /* Positive checks wait for the warning instead of a fixed delay (slow CI). */
  const warned = (page) => page.locator("#phishclean-root").waitFor({ state: "attached", timeout: 6000 }).then(() => true, () => false);
  const logged = () => worker.evaluate(() =>
    chrome.storage.local.get("phishclean_threat_log").then((d) => (d.phishclean_threat_log || []).flatMap((t) => t.signals || [])));

  await setLicense(TRIAL);

  console.log("\n1. Browser-in-the-browser");
  let page = await open("https://free-skins-drop.example/claim");
  ok("fake Google sign-in window on a skins site: warning", await warned(page));
  await page.screenshot({ path: join(SHOTS, "browser-in-browser.png") });
  await page.close();
  ok("logged as BROWSER_IN_BROWSER", (await logged()).includes("BROWSER_IN_BROWSER"));
  page = await open("https://security-tips.example/bitb-explained");
  ok("article explaining the trick: no warning", !(await modalShown(page)));
  await page.close();

  console.log("\n2. Device-code phishing");
  page = await open("https://doc-share-portal.example/view");
  ok("shared-document page with a devicelogin code: warning", await warned(page));
  await page.screenshot({ path: join(SHOTS, "device-code.png") });
  await page.close();
  ok("logged as DEVICE_CODE_PHISH", (await logged()).includes("DEVICE_CODE_PHISH"));

  console.log("\n3. Wrong-warning report sends only domain, check names and version");
  let reportBody = null;
  await context.unroute("**://www.phishclean.com/**");
  await context.route("**://www.phishclean.com/**", (r) => {
    if (r.request().url().includes("mode=false_positive")) { reportBody = r.request().postDataJSON(); return r.fulfill({ status: 200, contentType: "application/json", body: '{"ok":true}' }); }
    return r.abort();
  });
  const extId = new URL(worker.url()).host;
  page = await context.newPage();
  await page.goto(`chrome-extension://${extId}/popup/popup.html`);
  const resp = await page.evaluate(() => chrome.runtime.sendMessage({ type: "REPORT_FALSE_POSITIVE", domain: "free-skins-drop.example", signals: ["BROWSER_IN_BROWSER", "PASSWORD_FIELD"], url: "https://free-skins-drop.example/secret?token=abc" }));
  await page.close();
  ok("report: background answers ok", resp?.ok === true, JSON.stringify(resp));
  ok("report: sent the domain and check names", reportBody?.domain === "free-skins-drop.example" && reportBody?.signals?.includes("BROWSER_IN_BROWSER"), JSON.stringify(reportBody));
  ok("report: nothing else in the body", reportBody && Object.keys(reportBody).sort().join(",") === "domain,signals,version", JSON.stringify(reportBody));
  await context.unroute("**://www.phishclean.com/**");
  await context.route("**://www.phishclean.com/**", (r) => r.abort());

  console.log("\n4. Free tier");
  await setLicense(FREE);
  page = await open("https://free-skins-drop.example/claim");
  ok("free tier: browser-in-browser check is paused", !(await modalShown(page)));
  await page.close();
  page = await open("https://doc-share-portal.example/view");
  ok("free tier: device-code check is paused", !(await modalShown(page)));
  await page.close();
} finally {
  await context.close();
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
