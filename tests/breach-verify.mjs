/**
 * Browser verification for the Have I Been Pwned breach checks (breachCheck.js).
 * Loads the unpacked extension, drives tests/test-password.html and checks:
 *   - the breach list downloads and parses (real network call to HIBP)
 *   - the breached-site notice shows on a listed domain, once per domain
 *   - the leaked-password notice is trial/paid only (real range API call)
 *   - a changed password takes the leak notice down
 * localhost stands in for a breached domain by seeding the cached list.
 *
 * Run: node tests/breach-verify.mjs   (screenshots land in tests/screenshots/)
 */
import { chromium } from "playwright";
import { createServer } from "http";
import { readFileSync, existsSync, mkdtempSync, mkdirSync } from "fs";
import { resolve, dirname, join } from "path";
import { fileURLToPath } from "url";
import { tmpdir } from "os";

const __dirname = dirname(fileURLToPath(import.meta.url));
const EXT = resolve(__dirname, "..", process.env.EXT_DIR || "extension");
const SHOTS = resolve(__dirname, "screenshots");
const PORT = 8081;
const PAGE = `http://localhost:${PORT}/test-password.html`;

let pass = 0, fail = 0;
const ok = (label, cond, detail = "") => {
  console.log(`  ${cond ? "PASS" : "FAIL"}: ${label}${cond ? "" : detail ? " — " + detail : ""}`);
  cond ? pass++ : fail++;
};

const server = await new Promise((r) => {
  const s = createServer((req, res) => {
    const file = resolve(__dirname, "." + new URL(req.url, "http://x").pathname);
    if (!existsSync(file)) { res.writeHead(404); res.end(); return; }
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end(readFileSync(file));
  });
  s.listen(PORT, () => r(s));
});

mkdirSync(SHOTS, { recursive: true });
const context = await chromium.launchPersistentContext(mkdtempSync(join(tmpdir(), "phishclean-breach-")), {
  headless: false,
  args: [
    `--disable-extensions-except=${EXT}`, `--load-extension=${EXT}`,
    "--no-first-run", "--no-default-browser-check", "--no-sandbox",
    "--disable-features=DisableLoadExtensionCommandLineSwitch",
  ],
});

/* Block our backend: registerInstall would otherwise grant a real trial
   (overwriting the seeded licence) and add a test install to the prod DB.
   Have I Been Pwned stays reachable — those calls are what is under test. */
await context.route("**://www.phishclean.com/**", (r) => r.abort());

try {
  let [worker] = context.serviceWorkers();
  if (!worker) worker = await context.waitForEvent("serviceworker", { timeout: 30000 });

  const FREE = { install_id: "test", trial_active: false, is_paid: false, pro_enabled: false };
  const TRIAL = { install_id: "test", trial_active: true, is_paid: false, pro_enabled: true };
  await new Promise((r) => setTimeout(r, 1000)); /* let onInstalled settle */
  const setLicense = (l) => worker.evaluate((l) => chrome.storage.local.set({ phishclean_license: l }), l);
  const noticeCount = (page) => page.locator("#phishclean-breach").count();

  console.log("\nBreach list download");
  const adobe = await worker.evaluate(() => breachForDomain("adobe.com"));
  ok("adobe.com is in the downloaded list", adobe?.title === "Adobe", JSON.stringify(adobe));
  const size = await worker.evaluate(() =>
    chrome.storage.local.get("phishclean_breaches").then((d) => Object.keys(d.phishclean_breaches?.domains || {}).length));
  ok("list has hundreds of domains", size > 500, String(size));
  ok("unbreached domain is not listed", (await worker.evaluate(() => breachForDomain("phishclean.com"))) === null);

  /* Make localhost look breached. */
  await worker.evaluate(() => chrome.storage.local.get("phishclean_breaches").then(({ phishclean_breaches: b }) => {
    b.domains.localhost = { title: "Example Shop", date: "2024-03-15", count: 12400000, data: ["Email addresses", "Names", "Passwords", "Phone numbers"] };
    return chrome.storage.local.set({ phishclean_breaches: b, phishclean_breach_seen: [] });
  }));

  console.log("\nFree tier");
  await setLicense(FREE);
  let page = await context.newPage();
  await page.goto(PAGE);
  await page.click('input[type="password"]');
  await page.waitForTimeout(800);
  ok("breached-site notice shows on focus", (await noticeCount(page)) === 1);
  await page.screenshot({ path: join(SHOTS, "breach-site-free.png") });
  await page.keyboard.type("password123");
  await page.waitForTimeout(2000);
  await page.keyboard.press("Escape");
  await page.locator('input[name="username"]').click();
  await page.waitForTimeout(1500);
  ok("free tier gets no leaked-password notice", (await noticeCount(page)) === 0);
  await page.close();

  page = await context.newPage();
  await page.goto(PAGE);
  await page.click('input[type="password"]');
  await page.waitForTimeout(800);
  ok("breached-site notice is not repeated for the same domain", (await noticeCount(page)) === 0);
  await page.close();

  console.log("\nTrial");
  await setLicense(TRIAL);
  page = await context.newPage();
  await page.goto(PAGE);
  await page.click('input[type="password"]');
  await page.keyboard.type("password123");
  await page.waitForTimeout(2500);
  ok("leaked password shows a notice while typing", (await noticeCount(page)) === 1);
  await page.screenshot({ path: join(SHOTS, "breach-password-trial.png") });
  await page.keyboard.type("-Qv7#zW!p9Lr2");
  await page.waitForTimeout(150);
  ok("notice comes down when the password changes", (await noticeCount(page)) === 0);
  await page.waitForTimeout(2500);
  ok("strong password gets no notice", (await noticeCount(page)) === 0);
  await page.close();
} finally {
  await context.close();
  server.close();
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
