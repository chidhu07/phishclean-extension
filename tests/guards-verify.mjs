/**
 * Browser verification for 1.10.0: Paste Guard, download warnings, and link
 * badges on webmail, AI-answer and Brave Search pages.
 *
 * Every host is served through context.route(); nothing reaches the real
 * sites. phish-test.example is the one host on the test phishing feed.
 *
 * Run: node tests/guards-verify.mjs   (EXT_DIR=dist/chrome for the store build)
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
const SEED = "machine quarter helmet art ski symbol carpet print never praise home buyer";
const CARD = "4111 1111 1111 1111";

mkdirSync(SHOTS, { recursive: true });
const context = await chromium.launchPersistentContext(mkdtempSync(join(tmpdir(), "phishclean-guards-")), {
  headless: false,
  acceptDownloads: true,
  args: [
    `--disable-extensions-except=${EXT}`, `--load-extension=${EXT}`,
    "--no-first-run", "--no-default-browser-check", "--no-sandbox",
    "--disable-features=DisableLoadExtensionCommandLineSwitch",
  ],
});

await context.route("**://www.phishclean.com/**", (route) => {
  if (route.request().url().endsWith("/feeds/phish-v1.bin")) {
    return route.fulfill({ status: 200, contentType: "application/octet-stream", body: Buffer.from(feed), headers: { ETag: '"g1"' } });
  }
  return route.abort();
});
/* The guard pages: any path under /files/ is a file download. */
const guardPage = (r) => {
  const url = new URL(r.request().url());
  if (url.pathname.startsWith("/files/")) {
    return r.fulfill({ status: 200, body: "MZ test file", headers: {
      "content-type": "application/octet-stream",
      "content-disposition": `attachment; filename="${url.pathname.split("/").pop()}"` } });
  }
  return r.fulfill({ status: 200, contentType: "text/html", body: fixture("test-paste-download.html") });
};
for (const h of ["https://notes-app.example/**", "http://shop-checkout.example/**", "https://phish-test.example/**"]) await context.route(h, guardPage);
for (const h of ["https://mail.google.com/**", "https://chatgpt.com/**", "https://search.brave.com/**", "https://www.example-blog.example/**"]) {
  await context.route(h, (r) => r.fulfill({ status: 200, contentType: "text/html", body: fixture("test-link-surfaces.html") }));
}

try {
  let [worker] = context.serviceWorkers();
  if (!worker) worker = await context.waitForEvent("serviceworker", { timeout: 30000 });
  await new Promise((r) => setTimeout(r, 1500));
  /* Startup registration writes the licence it gets back; let it finish so
     it can't overwrite the test licence halfway through. */
  for (let i = 0; i < 40; i++) {
    const done = await worker.evaluate(() => chrome.storage.local.get("phishclean_license").then((d) => !!d.phishclean_license?.last_checked_at));
    if (done) break;
    await new Promise((r) => setTimeout(r, 250));
  }
  let license = TRIAL;
  const setLicense = (l) => { license = l; return worker.evaluate((v) => chrome.storage.local.set({ phishclean_license: v }), l); };
  /* The first warning otherwise opens the one-time account prompt, and the
     options page it opens refreshes the licence from the (blocked) server. */
  await worker.evaluate(() => chrome.storage.local.set({ phishclean_account_prompted: { at: new Date().toISOString(), reason: "test" } }));
  const meta = await worker.evaluate(() => PhishCleanFeed.refresh(true));
  ok("test feed loaded", meta?.count === 1, JSON.stringify(meta));

  const open = async (url, wait = 1500) => {
    await setLicense(license);
    const page = await context.newPage();
    await page.goto(url);
    await page.waitForTimeout(wait);
    /* The page's own warning (reported site, plain-HTTP password) comes
       first; dismiss it to get at the form. */
    if (await page.locator("#phishclean-root").count()) {
      await page.keyboard.press("Escape");
      await page.waitForTimeout(200);
    }
    return page;
  };
  const guardShown = async (page) => (await page.locator("#phishclean-guard").count()) === 1;
  const paste = (page, sel, text) => page.evaluate(([s, t]) => {
    const el = document.querySelector(s);
    el.focus();
    const dt = new DataTransfer();
    dt.setData("text/plain", t);
    return el.dispatchEvent(new ClipboardEvent("paste", { clipboardData: dt, bubbles: true, cancelable: true, composed: true }));
  }, [sel, text]);
  const value = (page, sel) => page.$eval(sel, (el) => el.value ?? el.textContent);
  const downloadAfter = async (page, action) => {
    const wait = page.waitForEvent("download", { timeout: 2500 }).then((d) => d.suggestedFilename()).catch(() => null);
    await action();
    return wait;
  };

  console.log("\n1. Paste Guard");
  await setLicense(TRIAL);
  let page = await open("https://notes-app.example/account");
  await paste(page, "#notes", SEED);
  await page.waitForTimeout(300);
  ok("recovery phrase on an ordinary site: asks first", await guardShown(page));
  await page.screenshot({ path: resolve(SHOTS, "guard-seed.png") });
  await page.keyboard.press("Enter"); /* focus starts on "Don't paste" */
  await page.waitForTimeout(200);
  ok("Don't paste: closed, nothing pasted", !(await guardShown(page)) && (await value(page, "#notes")) === "");
  await paste(page, "#rich", SEED);
  await page.waitForTimeout(300);
  ok("recovery phrase into a rich text box: asks first", await guardShown(page));
  await page.keyboard.press("Tab");
  await page.keyboard.press("Enter"); /* "Paste anyway" */
  await page.waitForTimeout(300);
  ok("Paste anyway: the phrase lands in the box", (await value(page, "#rich")).trim() === SEED, await value(page, "#rich"));
  await paste(page, "#card", CARD);
  await page.waitForTimeout(300);
  ok("card number on an ordinary https site: no prompt", !(await guardShown(page)));
  await paste(page, "#password", "Correct-Horse-9");
  await page.waitForTimeout(300);
  ok("password on an ordinary https site: no prompt", !(await guardShown(page)));
  await page.close();

  page = await open("http://shop-checkout.example/pay");
  await paste(page, "#card", CARD);
  await page.waitForTimeout(300);
  ok("card number on a plain-HTTP page: asks first", await guardShown(page));
  await page.screenshot({ path: resolve(SHOTS, "guard-card.png") });
  await page.keyboard.press("Tab");
  await page.keyboard.press("Enter");
  await page.waitForTimeout(300);
  ok("Paste anyway: the card number lands in the field", (await value(page, "#card")) === CARD, await value(page, "#card"));
  await page.close();

  page = await open("https://phish-test.example/login");
  await paste(page, "#password", "Correct-Horse-9");
  await page.waitForTimeout(300);
  ok("password on a reported site (after Ignore): asks first", await guardShown(page));
  await page.keyboard.press("Escape");
  await page.waitForTimeout(200);
  ok("Escape: closed, nothing pasted", !(await guardShown(page)) && (await value(page, "#password")) === "");
  await page.close();

  await setLicense(FREE);
  page = await open("https://notes-app.example/account");
  await paste(page, "#notes", SEED);
  await page.waitForTimeout(300);
  ok("free tier: Paste Guard is paused", !(await guardShown(page)));
  await page.close();

  console.log("\n2. Download warnings");
  await setLicense(TRIAL);
  page = await open("https://notes-app.example/docs");
  let file = await downloadAfter(page, () => page.click("#pdf"));
  ok("PDF: downloads with no prompt", file === "statement.pdf" && !(await guardShown(page)), String(file));
  file = await downloadAfter(page, () => page.click("#disguised"));
  ok("invoice.pdf.exe: held back and asks first", file === null && (await guardShown(page)), String(file));
  await page.screenshot({ path: resolve(SHOTS, "guard-disguised.png") });
  await page.keyboard.press("Enter");
  await page.waitForTimeout(200);
  file = await downloadAfter(page, () => page.click("#script"));
  ok("fix.hta: held back and asks first", file === null && (await guardShown(page)), String(file));
  file = await downloadAfter(page, async () => { await page.keyboard.press("Tab"); await page.keyboard.press("Enter"); });
  ok("Download anyway: the file downloads", file === "fix.hta", String(file));
  file = await downloadAfter(page, () => page.click("#program"));
  ok("program from an ordinary https site: no prompt", file === "ZoomInstaller.exe" && !(await guardShown(page)), String(file));
  file = await downloadAfter(page, () => page.click("#smuggle"));
  ok("file built by the page (blob .iso): held back and asks first", file === null && (await guardShown(page)), String(file));
  await page.screenshot({ path: resolve(SHOTS, "guard-smuggled.png") });
  await page.keyboard.press("Escape");
  await page.close();

  page = await open("http://shop-checkout.example/app");
  file = await downloadAfter(page, () => page.click("#program"));
  ok("program from a plain-HTTP page: held back and asks first", file === null && (await guardShown(page)), String(file));
  await page.keyboard.press("Escape");
  await page.close();

  await setLicense(FREE);
  page = await open("https://notes-app.example/docs");
  file = await downloadAfter(page, () => page.click("#disguised"));
  ok("free tier: download warnings are paused", file === "invoice.pdf.exe" && !(await guardShown(page)), String(file));
  await page.close();

  console.log("\n3. Link badges outside search pages");
  const badgeOf = (page, id) => page.$eval(`#${id}`, (a) => {
    const b = a.querySelector(".phishclean-search-badge");
    return b ? `${b.dataset.level}:${b.textContent.trim()}` : null;
  }).catch(() => "missing");
  const badgeCount = (page) => page.locator(".phishclean-search-badge").count();

  await setLicense(TRIAL);
  page = await open("https://mail.google.com/mail/u/0/#inbox", 2200);
  ok("webmail: reported link gets the red badge", (await badgeOf(page, "reported"))?.startsWith("danger"), await badgeOf(page, "reported"));
  ok("webmail: Outlook Safe Links wrapper is seen through", (await badgeOf(page, "wrapped"))?.startsWith("danger"), await badgeOf(page, "wrapped"));
  ok("webmail: lookalike gets the amber badge", (await badgeOf(page, "lookalike"))?.startsWith("caution"), await badgeOf(page, "lookalike"));
  ok("webmail: well-known site gets no green tick", (await badgeOf(page, "trusted")) === null, await badgeOf(page, "trusted"));
  ok("webmail: unknown site and own links get nothing", (await badgeOf(page, "unknown")) === null && (await badgeOf(page, "internal")) === null);
  ok("webmail: image-only link is left alone", (await badgeOf(page, "image")) === null);
  await page.locator(".message").screenshot({ path: resolve(SHOTS, "badges-webmail.png") });
  await page.close();

  page = await open("https://chatgpt.com/c/test", 2200);
  ok("AI answer: reported link gets the red badge", (await badgeOf(page, "reported"))?.startsWith("danger"));
  ok("AI answer: router address gets no IP badge", (await badgeOf(page, "router")) === null, await badgeOf(page, "router"));
  await page.close();

  page = await open("https://search.brave.com/search?q=project", 2200);
  ok("Brave Search: well-known result gets the green tick", (await badgeOf(page, "brave-good"))?.startsWith("safe"), await badgeOf(page, "brave-good"));
  ok("Brave Search: reported result gets one red badge", (await badgeOf(page, "brave-bad"))?.startsWith("danger") &&
    (await page.locator("#brave-bad .phishclean-search-badge").count()) === 1);
  await page.close();

  page = await open("https://www.example-blog.example/post", 2200);
  ok("ordinary site: no link badges", (await badgeCount(page)) === 0);
  await page.close();

  await setLicense(FREE);
  page = await open("https://mail.google.com/mail/u/0/#inbox", 2200);
  ok("free tier: reported link still gets the red badge", (await badgeOf(page, "reported"))?.startsWith("danger"));
  ok("free tier: lookalike badge is paused", (await badgeOf(page, "lookalike")) === null);
  await page.close();
} catch (e) {
  console.error(e);
  fail++;
} finally {
  await context.close();
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
