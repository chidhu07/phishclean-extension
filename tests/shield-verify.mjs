/**
 * Browser verification for the 1.7.0 checks: search result badges, the
 * "click Allow" notification trap and fake online shops.
 *
 * Every page is served through context.route() over https, so the content
 * scripts see real hostnames (www.google.com, nike-outlet-sale.example) and a
 * secure context — notification prompts only exist on https.
 *
 * Run: node tests/shield-verify.mjs   (EXT_DIR=dist/chrome for the store build)
 */
import { chromium } from "playwright";
import { readFileSync, mkdtempSync, mkdirSync } from "fs";
import { resolve, dirname, join } from "path";
import { fileURLToPath } from "url";
import { tmpdir } from "os";
import { encodeFeed, prefixOf } from "../scripts/build-phish-feed.mjs";

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
const feed = encodeFeed([prefixOf("wildcard", "phish-test.example")], Date.now());

const TRIAL = { install_id: "test", trial_active: true, is_paid: false, pro_enabled: true };
const FREE = { install_id: "test", trial_active: false, is_paid: false, pro_enabled: false };

mkdirSync(SHOTS, { recursive: true });
const context = await chromium.launchPersistentContext(mkdtempSync(join(tmpdir(), "phishclean-shield-")), {
  headless: false,
  args: [
    `--disable-extensions-except=${EXT}`, `--load-extension=${EXT}`,
    "--no-first-run", "--no-default-browser-check", "--no-sandbox",
    "--disable-features=DisableLoadExtensionCommandLineSwitch",
  ],
});

await context.route("**://www.phishclean.com/**", (route) => {
  if (route.request().url().endsWith("/feeds/phish-v1.bin")) {
    return route.fulfill({ status: 200, contentType: "application/octet-stream", body: Buffer.from(feed), headers: { ETag: '"s1"' } });
  }
  return route.abort();
});
const serve = (pattern, file) => context.route(pattern, (r) => r.fulfill({ status: 200, contentType: "text/html", body: fixture(file) }));
await serve("https://www.google.com/search**", "test-search-results.html");
await serve("https://notify-bait.example/**", "test-notification-bait.html");
await serve("https://nike-outlet-sale.example/**", "test-fake-shop.html");
await serve("https://harbor-outfitters.example/**", "test-real-shop-sale.html");

try {
  let [worker] = context.serviceWorkers();
  if (!worker) worker = await context.waitForEvent("serviceworker", { timeout: 30000 });
  await new Promise((r) => setTimeout(r, 1500));
  const setLicense = (l) => worker.evaluate((v) => chrome.storage.local.set({ phishclean_license: v }), l);
  const meta = await worker.evaluate(() => PhishCleanFeed.refresh(true));
  ok("test feed loaded", meta?.count === 1, JSON.stringify(meta));

  const open = async (url, wait = 1800) => {
    const page = await context.newPage();
    await page.goto(url);
    await page.waitForTimeout(wait);
    return page;
  };
  const modalShown = async (page) => (await page.locator("#phishclean-root").count()) === 1;
  const badges = (page) => page.$$eval(".phishclean-search-badge", (els) =>
    els.map((el) => ({ level: el.dataset.level, label: el.textContent.trim(), title: el.closest("a")?.textContent.trim() })));

  console.log("\n1. Search result badges");
  await setLicense(TRIAL);
  let page = await open("https://www.google.com/search?q=paypal+login");
  let marks = await badges(page);
  const levelOf = (t) => marks.find((m) => m.title?.includes(t))?.level || null;
  ok("real PayPal result: green", levelOf("Log in to your PayPal") === "safe", JSON.stringify(marks));
  ok("reported phishing result (via /url?q=): red", levelOf("PayPal Login - Secure") === "danger");
  ok("lookalike result: amber", levelOf("PayPal account verification") === "caution");
  ok("brand-prefixed real business: no badge", levelOf("Applebee") === null);
  ok("unknown site: no badge", levelOf("Small Bakery") === null);
  ok("scam ad for a brand sign-in: amber 'Not Amazon'", marks.some((m) => m.title?.includes("Sign In to Your Account") && m.level === "caution" && m.label.includes("Not Amazon")), JSON.stringify(marks));
  ok("ad through Google's aclk redirect is read and marked", levelOf("PayPal Customer Service") === "caution");
  ok("the brand's own ad: green", marks.some((m) => m.title?.endsWith("Amazon Business - Sign In") && m.level === "safe"));
  ok("no full-page warning on the results page", !(await modalShown(page)));
  await page.screenshot({ path: join(SHOTS, "search-badges.png") });

  await page.evaluate(() => {
    const div = document.createElement("div");
    div.className = "g";
    div.innerHTML = '<a href="https://another.phish-test.example/"><h3>More results: PayPal</h3></a>';
    document.getElementById("rso").appendChild(div);
  });
  await page.waitForTimeout(1200);
  marks = await badges(page);
  ok("results loaded later are marked too", levelOf("More results") === "danger", JSON.stringify(marks));
  ok("each result gets one badge", marks.length === 7, String(marks.length));
  await page.close();

  await setLicense(FREE);
  page = await open("https://www.google.com/search?q=paypal+login");
  marks = await badges(page);
  ok("free tier: reported result still red", levelOf("PayPal Login - Secure") === "danger", JSON.stringify(marks));
  ok("free tier: lookalike badge is a paid check", levelOf("PayPal account verification") === null);
  await page.close();

  await worker.evaluate(() => chrome.storage.local.set({ phishclean_search_badges: false }));
  page = await open("https://www.google.com/search?q=paypal+login");
  ok("switched off in settings: no badges", (await badges(page)).length === 0);
  await page.close();
  await worker.evaluate(() => chrome.storage.local.remove("phishclean_search_badges"));

  console.log("\n2. Notification trap");
  await setLicense(TRIAL);
  page = await open("https://notify-bait.example/");
  ok("trial: warning on a 'click Allow if you are not a robot' page", await modalShown(page));
  await page.screenshot({ path: join(SHOTS, "notification-bait.png") });
  const log = await worker.evaluate(() => chrome.storage.local.get("phishclean_threat_log").then((d) => d.phishclean_threat_log || []));
  ok("logged as NOTIFICATION_BAIT", log.some((t) => t.signals?.includes("NOTIFICATION_BAIT")));
  await page.close();

  console.log("\n3. Fake shop");
  page = await open("https://nike-outlet-sale.example/");
  ok("trial: warning on a fake brand outlet", await modalShown(page));
  await page.screenshot({ path: join(SHOTS, "fake-shop.png") });
  await page.close();
  page = await open("https://harbor-outfitters.example/");
  ok("no warning on a real shop's clearance sale", !(await modalShown(page)));
  await page.close();
  await setLicense(FREE);
  page = await open("https://nike-outlet-sale.example/");
  ok("free tier: fake-shop check is paused", !(await modalShown(page)));
  await page.close();

  console.log("\n4. Settings");
  const extId = worker.url().split("/")[2];
  page = await context.newPage();
  const errors = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto(`chrome-extension://${extId}/options/options.html`);
  await page.waitForTimeout(800);
  ok("options: badge switch on by default", await page.isChecked("#search-badges"));
  await page.click("#search-badges");
  await page.waitForTimeout(300);
  const stored = await worker.evaluate(() => chrome.storage.local.get("phishclean_search_badges").then((d) => d.phishclean_search_badges));
  ok("options: switching off is saved", stored === false, String(stored));
  ok("options: no JS errors", errors.length === 0, errors.join("; "));
  await page.close();
} finally {
  await context.close();
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
