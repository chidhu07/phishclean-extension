/**
 * Browser verification for the 1.8.0 hacked-site checks: fake browser
 * updates and card skimmers on checkout pages.
 *
 * Pages are served through context.route() over https on .example hosts
 * (plus api.stripe.com, answered locally). Nothing is downloaded or sent.
 *
 * Run: node tests/hacked-site-verify.mjs   (EXT_DIR=dist/chrome for the store build)
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
const context = await chromium.launchPersistentContext(mkdtempSync(join(tmpdir(), "phishclean-hacked-")), {
  headless: false,
  args: [
    `--disable-extensions-except=${EXT}`, `--load-extension=${EXT}`,
    "--no-first-run", "--no-default-browser-check", "--no-sandbox",
    "--disable-features=DisableLoadExtensionCommandLineSwitch",
  ],
});

await context.route("**://www.phishclean.com/**", (route) => route.abort());
const serve = (pattern, file) => context.route(pattern, (r) => r.fulfill({ status: 200, contentType: "text/html", body: fixture(file) }));
await serve("https://hacked-blog.example/**", "test-fake-update.html");
await serve("https://bank.example/**", "test-unsupported-browser.html");
await context.route("https://harbor-outfitters.example/**", (r) => r.request().url().includes("/api/")
  ? r.fulfill({ status: 200, body: "{}" })
  : r.fulfill({ status: 200, contentType: "text/html", body: fixture("test-checkout-skimmer.html") }));
const sink = (r) => r.fulfill({ status: 204, body: "" });
await context.route("https://metrics-cdn.example/**", sink);
await context.route("https://api.stripe.com/**", sink);
await context.route("https://update-cdn.example/**", (r) => r.abort());

try {
  let [worker] = context.serviceWorkers();
  if (!worker) worker = await context.waitForEvent("serviceworker", { timeout: 30000 });
  await new Promise((r) => setTimeout(r, 1500));
  /* The worker replaces the licence after a few seconds when it cannot reach
     the licence server (blocked here), so each page sets it again first. */
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
  const logged = () => worker.evaluate(() =>
    chrome.storage.local.get("phishclean_threat_log").then((d) => (d.phishclean_threat_log || []).flatMap((t) => t.signals || [])));

  await setLicense(TRIAL);

  console.log("\n1. Fake browser update");
  let page = await open("https://hacked-blog.example/");
  ok("update page with a script download: warning", await modalShown(page));
  await page.screenshot({ path: join(SHOTS, "fake-browser-update.png") });
  await page.close();
  page = await open("https://hacked-blog.example/?mode=button");
  ok("update page with a scripted button: warning", await modalShown(page));
  await page.close();
  page = await open("https://bank.example/unsupported");
  ok("real unsupported-browser notice: no warning", !(await modalShown(page)));
  await page.close();
  ok("logged as FAKE_BROWSER_UPDATE", (await logged()).includes("FAKE_BROWSER_UPDATE"));

  console.log("\n2. Card skimmer");
  const checkout = async (query) => {
    const p = await open(`https://harbor-outfitters.example/checkout${query}`, 1500);
    await p.fill("#cardnumber", "4242 4242 4242 4242");
    await p.click('input[name="exp"]');
    await p.waitForTimeout(1200);
    return p;
  };
  for (const via of ["fetch", "img", "beacon", "xhr"]) {
    page = await checkout(`?via=${via}`);
    ok(`card sent to an unrelated host by ${via}: warning`, await modalShown(page));
    if (via === "fetch") await page.screenshot({ path: join(SHOTS, "card-skimmer.png") });
    await page.close();
  }
  ok("logged as CARD_SKIMMER", (await logged()).includes("CARD_SKIMMER"));
  page = await checkout("?dest=stripe");
  ok("card sent to Stripe: no warning", !(await modalShown(page)));
  await page.close();
  page = await checkout("?dest=self");
  ok("card sent to the shop's own API: no warning", !(await modalShown(page)));
  await page.close();
  page = await open("https://harbor-outfitters.example/checkout", 1500);
  await page.fill("#cardnumber", "1234 5678 9012 3456");
  await page.click('input[name="exp"]');
  await page.waitForTimeout(1200);
  ok("a number that is not a card: no warning", !(await modalShown(page)));
  await page.close();

  console.log("\n3. Free tier");
  await setLicense(FREE);
  page = await open("https://hacked-blog.example/");
  ok("free tier: fake update check is paused", !(await modalShown(page)));
  await page.close();
  page = await checkout("");
  ok("free tier: skimmer check is paused", !(await modalShown(page)));
  await page.close();
} finally {
  await context.close();
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
