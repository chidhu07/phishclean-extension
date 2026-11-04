/**
 * Browser verification for the fake CAPTCHA ("ClickFix") check: the page's
 * own clipboard writes are seen through clipboardHook.js, the warning shows
 * on the free tier, and a real install page with copy buttons stays quiet.
 *
 * Pages are served through context.route() over https on .example hosts.
 * The copied command points at a reserved .example host and is never run.
 *
 * Run: node tests/fake-captcha-verify.mjs   (EXT_DIR=dist/chrome for the store build)
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
const context = await chromium.launchPersistentContext(mkdtempSync(join(tmpdir(), "phishclean-captcha-")), {
  headless: false,
  args: [
    `--disable-extensions-except=${EXT}`, `--load-extension=${EXT}`,
    "--no-first-run", "--no-default-browser-check", "--no-sandbox",
    "--disable-features=DisableLoadExtensionCommandLineSwitch",
  ],
});

await context.route("**://www.phishclean.com/**", (route) => route.abort());
const serve = (pattern, file) => context.route(pattern, (r) => r.fulfill({ status: 200, contentType: "text/html", body: fixture(file) }));
await serve("https://verify-human.example/**", "test-fake-captcha.html");
await serve("https://cli.example/**", "test-install-docs.html");

try {
  let [worker] = context.serviceWorkers();
  if (!worker) worker = await context.waitForEvent("serviceworker", { timeout: 30000 });
  await new Promise((r) => setTimeout(r, 1500));
  const setLicense = (l) => worker.evaluate((v) => chrome.storage.local.set({ phishclean_license: v }), l);

  const open = async (url, wait = 1500) => {
    const page = await context.newPage();
    await page.goto(url);
    await page.waitForTimeout(wait);
    return page;
  };
  const modalShown = async (page) => (await page.locator("#phishclean-root").count()) === 1;
  const lastLogged = () => worker.evaluate(() =>
    chrome.storage.local.get("phishclean_threat_log").then((d) => (d.phishclean_threat_log || []).at(-1) || null));

  await setLicense(FREE);

  console.log("\n1. Fake CAPTCHA, free tier");
  for (const [label, query] of [
    ["navigator.clipboard.writeText", ""],
    ["hidden textarea + execCommand", "?mode=exec"],
    ["copy-event setData", "?mode=setdata"],
  ]) {
    const page = await open(`https://verify-human.example/${query}`);
    /* The robot check alone, before the click, is a real CAPTCHA's text too. */
    ok(`${label}: no warning before the click`, !(await modalShown(page)));
    await page.click("#robot-check");
    await page.waitForTimeout(1500);
    ok(`${label}: warning after the click`, await modalShown(page));
    if (!query) await page.screenshot({ path: join(SHOTS, "fake-captcha.png") });
    await page.close();
  }
  const logged = await lastLogged();
  ok("logged as FAKE_CAPTCHA", logged?.signals?.includes("FAKE_CAPTCHA"), JSON.stringify(logged?.signals));

  console.log("\n2. Hacked site: lure over a long article");
  let page = await open("https://verify-human.example/?long=1");
  await page.click("#robot-check");
  await page.waitForTimeout(1500);
  ok("long page + copied command with decoy: warning", await modalShown(page));
  await page.close();
  page = await open("https://verify-human.example/?long=1&decoy=0");
  await page.click("#robot-check");
  await page.waitForTimeout(1500);
  ok("long page + copied command, no decoy: warning from the steps", await modalShown(page));
  await page.close();

  console.log("\n3. Real install page");
  await setLicense(TRIAL);
  page = await open("https://cli.example/install");
  await page.click("#copy-unix");
  await page.waitForTimeout(800);
  await page.click("#copy-win");
  await page.waitForTimeout(1500);
  ok("copying install commands: no warning", !(await modalShown(page)));
  await page.close();
} finally {
  await context.close();
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
