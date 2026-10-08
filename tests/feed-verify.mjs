/**
 * Verification for the reported-phishing feed.
 *
 *  1. Build rules (scripts/build-phish-feed.mjs): popular hosts are dropped,
 *     hosting-platform customers are exact-only, other domains are wildcards.
 *  2. The extension's matcher (extension/lib/phishFeed.js) reads what the
 *     build writes: same hashing, same normalisation, binary search.
 *  3. The real feed, if public/feeds/phish-v1.bin exists (run
 *     `node scripts/build-phish-feed.mjs` first): a sample of listed hosts
 *     match, and none of the Tranco top 1,000 sites do.
 *  4. In the browser: the unpacked extension downloads a test feed, warns on a
 *     listed host and its subdomains on the free tier, leaves unlisted hosts
 *     alone, respects "Trust this domain", and the popup says the list is loaded.
 *  5. The fake virus / tech support scam warning (paid): shown on a scam page
 *     during the trial, not on an article about scams, not on the free tier.
 *     These pages are served from plain-HTTP *.example hosts, which also
 *     guards against the content script dying in insecure contexts.
 *
 * Run: node tests/feed-verify.mjs   (add --no-browser to skip part 4)
 */
import { chromium } from "playwright";
import { createServer } from "http";
import { readFileSync, existsSync, mkdtempSync, mkdirSync } from "fs";
import { resolve, dirname, join } from "path";
import { fileURLToPath } from "url";
import { tmpdir } from "os";
import vm from "vm";
import {
  classify, encodeFeed, normalizeHost, parsePsl, prefixOf,
} from "../scripts/build-phish-feed.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, "..");
const EXT = resolve(ROOT, process.env.EXT_DIR || "extension");
const SHOTS = resolve(__dirname, "screenshots");
const PORT = 8083;

let pass = 0, fail = 0;
const ok = (label, cond, detail = "") => {
  console.log(`  ${cond ? "PASS" : "FAIL"}: ${label}${cond ? "" : detail ? " — " + detail : ""}`);
  cond ? pass++ : fail++;
};

/* Load the extension's matcher into this process. It only touches chrome.*
   inside refresh(), which is not called here. */
const sandbox = { crypto: globalThis.crypto, TextEncoder, Uint8Array, DataView, String, Promise };
sandbox.globalThis = sandbox;
vm.runInNewContext(readFileSync(resolve(EXT, "lib/phishFeed.js"), "utf8"), sandbox);
const Feed = sandbox.PhishCleanFeed;

const feedOf = (entries) => {
  const buf = encodeFeed(entries.map(([kind, host]) => prefixOf(kind, host)), Date.now());
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.length);
};
async function listed(feed, host) {
  for (const c of Feed.candidates(host)) {
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(c));
    if (Feed.contains(feed, new Uint8Array(digest, 0, 6))) return true;
  }
  return false;
}

console.log("\n1. Build rules");
const psl = parsePsl("com\nio\ngithub.io\nco.uk\n*.ck\n!www.ck\n");
const top = new Set(["google.com", "gravatar.com", "weebly.com", "github.io"]);
ok("sites.google.com is dropped (google.com is popular)", classify("sites.google.com", psl, top) === null);
ok("gravatar.com is dropped", classify("gravatar.com", psl, top) === null);
ok("weebly.com root is dropped", classify("weebly.com", psl, top) === null);
ok("a weebly customer is kept, exact only", classify("paypal-verify.weebly.com", psl, top)?.kind === "exact");
ok("a github.io user site is a wildcard (PSL private suffix)", classify("evil.github.io", psl, top)?.kind === "wildcard");
ok("an unknown registrable domain is a wildcard", classify("secure-paypa1.com", psl, top)?.kind === "wildcard");
ok("a subdomain of an unknown domain is exact", classify("login.secure-paypa1.com", psl, top)?.kind === "exact");
ok("blogspot country blogs are exact", classify("fake.blogspot.fi", psl, top)?.kind === "exact");
ok("hosts are normalised (case, www, trailing dot)", normalizeHost(" WWW.Evil.COM. ") === "evil.com");
ok("comments and junk are skipped", normalizeHost("# comment") === "" && normalizeHost("not a host") === "");

console.log("\n2. Matcher reads the build format");
const small = Feed.parse(feedOf([["wildcard", "secure-paypa1.com"], ["exact", "paypal-verify.weebly.com"]]));
ok("header parses", small?.count === 2);
ok("bad magic is rejected", Feed.parse(new ArrayBuffer(16)) === null);
ok("listed wildcard matches", await listed(small, "secure-paypa1.com"));
ok("wildcard matches www. and subdomains", await listed(small, "www.secure-paypa1.com") && await listed(small, "a.b.secure-paypa1.com"));
ok("exact entry matches itself", await listed(small, "paypal-verify.weebly.com"));
ok("exact entry does not match its parent", !(await listed(small, "weebly.com")));
ok("exact entry does not match a sibling", !(await listed(small, "my-bakery.weebly.com")));
ok("unlisted host does not match", !(await listed(small, "paypal.com")));

const REAL = resolve(ROOT, "public/feeds/phish-v1.bin");
if (existsSync(REAL)) {
  console.log("\n3. Real feed");
  const raw = readFileSync(REAL);
  const real = Feed.parse(raw.buffer.slice(raw.byteOffset, raw.byteOffset + raw.length));
  ok("real feed parses", real?.count > 50000, String(real?.count));
  const popular = ["google.com", "sites.google.com", "docs.google.com", "github.com", "gravatar.com",
    "pastebin.com", "telegra.ph", "mercadolibre.com.ar", "paypal.com", "microsoft.com",
    "login.microsoftonline.com", "amazon.com", "phishclean.com", "weebly.com", "000webhostapp.com"];
  const hits = [];
  for (const h of popular) if (await listed(real, h)) hits.push(h);
  ok("well-known sites are not listed", hits.length === 0, hits.join(", "));
  try {
    const id = (await (await fetch("https://tranco-list.eu/top-1m-id")).text()).trim();
    const csv = await (await fetch(`https://tranco-list.eu/download/${id}/1000`)).text();
    const top1k = csv.split("\n").map((l) => l.split(",")[1]?.trim()).filter(Boolean);
    const topHits = [];
    for (const h of top1k) if (await listed(real, h)) topHits.push(h);
    ok(`none of the Tranco top ${top1k.length} are listed`, topHits.length === 0, topHits.join(", "));
  } catch (e) { console.log(`  SKIP: Tranco unreachable (${e.message})`); }
  try {
    const src = await (await fetch("https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-NEW-today.txt")).text();
    const fresh = src.split("\n").map(normalizeHost).filter(Boolean).slice(0, 50);
    let matched = 0;
    for (const h of fresh) if (await listed(real, h)) matched++;
    console.log(`  info: ${matched} of ${fresh.length} hosts reported today are already in the built feed`);
  } catch { /* informational only */ }
} else {
  console.log("\n3. Real feed — SKIP (run node scripts/build-phish-feed.mjs first)");
}

if (!process.argv.includes("--no-browser")) {
  console.log("\n4. Browser");
  const testFeed = Buffer.from(feedOf([["wildcard", "phish-test.example"], ["exact", "victim.hosting-test.example"]]));
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
  const context = await chromium.launchPersistentContext(mkdtempSync(join(tmpdir(), "phishclean-feed-")), {
    headless: false,
    args: [
      `--disable-extensions-except=${EXT}`, `--load-extension=${EXT}`,
      "--no-first-run", "--no-default-browser-check", "--no-sandbox",
      "--disable-features=DisableLoadExtensionCommandLineSwitch",
      "--host-resolver-rules=MAP *.example 127.0.0.1",
    ],
  });
  /* Serve the test feed; abort the rest of our backend so no test install
     reaches the production database. */
  await context.route("**://www.phishclean.com/**", (route) => {
    if (route.request().url().endsWith("/feeds/phish-v1.bin")) {
      return route.fulfill({ status: 200, contentType: "application/octet-stream", body: testFeed, headers: { ETag: '"t1"' } });
    }
    return route.abort();
  });
  try {
    let [worker] = context.serviceWorkers();
    if (!worker) worker = await context.waitForEvent("serviceworker", { timeout: 30000 });
    await new Promise((r) => setTimeout(r, 1500));
    await worker.evaluate(() => chrome.storage.local.set({
      phishclean_license: { install_id: "test", trial_active: false, is_paid: false, pro_enabled: false },
    }));
    const meta = await worker.evaluate(() => PhishCleanFeed.refresh(true));
    ok("worker downloads and stores the feed", meta?.count === 2, JSON.stringify(meta));

    const modal = async (url) => {
      const page = await context.newPage();
      await page.goto(url);
      await page.waitForTimeout(1500);
      const shown = (await page.locator("#phishclean-root").count()) === 1;
      return { page, shown };
    };
    let { page, shown } = await modal(`http://phish-test.example:${PORT}/test-safe-login.html`);
    ok("free tier: warning on a listed domain", shown);
    await page.screenshot({ path: join(SHOTS, "feed-reported-free.png") });
    await page.close();
    ({ page, shown } = await modal(`http://login.phish-test.example:${PORT}/test-safe-login.html`));
    ok("warning on a subdomain of a listed domain", shown);
    await page.close();
    ({ page, shown } = await modal(`http://victim.hosting-test.example:${PORT}/test-safe-login.html`));
    ok("warning on an exact-listed host", shown);
    await page.close();
    ({ page, shown } = await modal(`http://bakery.hosting-test.example:${PORT}/test-safe-login.html`));
    ok("no warning on a sibling of an exact-listed host", !shown);
    await page.close();
    ({ page, shown } = await modal(`http://clean.example:${PORT}/test-safe-login.html`));
    ok("no warning on an unlisted host", !shown);
    await page.close();

    await worker.evaluate(() => chrome.storage.local.set({ phishclean_whitelist_domains: ["phish-test.example"] }));
    ({ page, shown } = await modal(`http://phish-test.example:${PORT}/test-safe-login.html`));
    ok("a trusted domain is not warned about", !shown);
    await page.close();

    const extId = worker.url().split("/")[2];
    page = await context.newPage();
    await page.goto(`chrome-extension://${extId}/popup/popup.html`);
    await page.waitForTimeout(1000);
    const line = await page.locator("#feed-line").textContent();
    ok("popup says the list is loaded", /Blocking 2 reported phishing sites/.test(line || ""), line);
    await page.close();

    console.log("\n5. Fake virus warning (paid check), on plain-HTTP hosts");
    await worker.evaluate(() => chrome.storage.local.set({
      phishclean_license: { install_id: "test", trial_active: true, is_paid: false, pro_enabled: true },
    }));
    ({ page, shown } = await modal(`http://scam.example:${PORT}/test-tech-support-scam.html`));
    ok("trial: warning on a fake virus page", shown);
    await page.screenshot({ path: join(SHOTS, "tech-scam-trial.png") });
    await page.close();
    /* The modal's shadow root is closed, so check which signal it logged. */
    const logged = await worker.evaluate(() => chrome.storage.local.get("phishclean_threat_log")
      .then((d) => (d.phishclean_threat_log || [])[0]?.signals || []));
    ok("it is logged as TECH_SUPPORT_SCAM", logged.includes("TECH_SUPPORT_SCAM"), JSON.stringify(logged));
    ({ page, shown } = await modal(`http://news.example:${PORT}/test-scam-article.html`));
    ok("trial: no warning on an article about the scam", !shown);
    await page.close();
    await worker.evaluate(() => chrome.storage.local.set({
      phishclean_license: { install_id: "test", trial_active: false, is_paid: false, pro_enabled: false },
    }));
    ({ page, shown } = await modal(`http://scam2.example:${PORT}/test-tech-support-scam.html`));
    ok("free tier: the paid check does not run", !shown);
    await page.close();
  } finally {
    await context.close();
    server.close();
  }
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
