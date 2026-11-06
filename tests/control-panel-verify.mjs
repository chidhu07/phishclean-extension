/**
 * Browser verification for the exposed refrigeration-controller notice
 * (guards.js + riskEngine.detectExposedControlPanel).
 *
 * Pages are served through context.route() on a public-looking IP, a
 * dynamic-DNS name and a private IP. Nothing is typed or sent.
 *
 * Run: node tests/control-panel-verify.mjs   (EXT_DIR=dist/chrome for the store build)
 */
import { chromium } from "playwright";
import { mkdtempSync, mkdirSync } from "fs";
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
mkdirSync(SHOTS, { recursive: true });

const LOGIN = (title) => `<!doctype html><html><head><title>${title}</title></head><body style="font-family:sans-serif;background:#e8edf3">
  <div style="max-width:320px;margin:120px auto;background:#fff;padding:24px;border-radius:8px">
  <h2>${title}</h2><label>User <input name="u"></label><br><br><label>Password <input type="password" name="p"></label><br><br><button>Log in</button></div></body></html>`;
const FREE = { install_id: "test", trial_active: false, is_paid: false, pro_enabled: false };

const context = await chromium.launchPersistentContext(mkdtempSync(join(tmpdir(), "phishclean-panel-")), {
  headless: false,
  args: [
    `--disable-extensions-except=${EXT}`, `--load-extension=${EXT}`,
    "--no-first-run", "--no-default-browser-check", "--no-sandbox",
    "--disable-features=DisableLoadExtensionCommandLineSwitch",
  ],
});
await context.route("**://www.phishclean.com/**", (route) => route.abort());
const serve = (host, html) => context.route((u) => u.hostname === host, (r) => r.fulfill({ status: 200, contentType: "text/html", body: html }));
await serve("81.12.40.7", LOGIN("AK-SM 800A Login"));
await serve("store-42.ddns.net", LOGIN("XWEB EVO"));
await serve("192.168.1.20", LOGIN("AK-SM 800A Login"));
await serve("81.12.40.8", LOGIN("Router login"));

try {
  let [worker] = context.serviceWorkers();
  if (!worker) worker = await context.waitForEvent("serviceworker", { timeout: 30000 });
  await new Promise((r) => setTimeout(r, 1500));
  /* Free plan on purpose: the notice is free for everyone. */
  await worker.evaluate((v) => chrome.storage.local.set({ phishclean_license: v, phishclean_account_prompted: true }), FREE);

  const open = async (url) => { const page = await context.newPage(); await page.goto(url); return page; };
  const shown = (page, timeout = 6000) => page.locator("#phishclean-panel-notice").waitFor({ state: "attached", timeout }).then(() => true, () => false);

  console.log("\nExposed controller on a public IP (free plan)");
  let page = await open("http://81.12.40.7/login");
  ok("notice shown", await shown(page));
  await page.screenshot({ path: resolve(SHOTS, "control-panel-notice.png") });
  ok("login page still usable (no blocking overlay)", await page.locator("input[type=password]").isEditable());
  await page.close();

  console.log("\nExposed controller on a dynamic-DNS name");
  page = await open("http://store-42.ddns.net/");
  ok("notice shown", await shown(page));
  await page.close();

  console.log("\nSame controller on the store network");
  page = await open("http://192.168.1.20/login");
  ok("no notice on a private IP", !(await shown(page, 5000)));
  await page.close();

  console.log("\nOther login page on a public IP");
  page = await open("http://81.12.40.8/");
  ok("no notice for an unrelated login", !(await shown(page, 5000)));
  await page.close();

  console.log("\n\"Don't warn me for this address\"");
  page = await open("http://81.12.40.7/login");
  await shown(page);
  /* closed shadow root: click by position is brittle, so use the stored list instead */
  await worker.evaluate(() => chrome.storage.local.set({ phishclean_panel_ok: ["81.12.40.7"] }));
  await page.close();
  page = await open("http://81.12.40.7/login");
  ok("muted address shows no notice", !(await shown(page, 5000)));
  await page.close();
} finally {
  await context.close();
}
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
