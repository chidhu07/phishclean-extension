/* Rules for what hacked sites and scam ads show visitors (riskEngine.js):
   fake browser updates, card skimmer destinations and brand sign-in ads.
   Run: node --test tests/hacked-site.test.mjs */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const load = (ctx, file) => vm.runInNewContext(readFileSync(resolve(ROOT, file), "utf8"), ctx);
const ctx = { window: {}, URL };
ctx.globalThis = ctx;
load(ctx, "extension/lib/publicSuffix.js");
load(ctx, "extension/riskEngine.js");
const engine = ctx.window.PhishCleanRiskEngine;

/* ── Fake browser update ── */
const UPDATE = "An error occurred in your browser. Your Chrome is out of date. Update Chrome to continue to this page.";
const link = (href, label = "Update Chrome", download = false) => ({ href, label, download });
const button = (label) => ({ href: "", label, download: false });

const fakeUpdates = {
  "script download": ["hacked-blog.example", UPDATE, [link("https://update-cdn.example/Chrome.Update.js")]],
  "zip download": ["hacked-blog.example", UPDATE, [link("https://cdn.example/files/ChromeSetup.zip?v=2")]],
  "download attribute on a blob": ["hacked-blog.example", UPDATE, [link("blob:https://hacked-blog.example/5c1e", "Update", true)]],
  "scripted button, no link": ["hacked-blog.example", UPDATE, [button("Update Chrome")]],
  "Edge wording": ["shop.example", "Microsoft Edge update required. Your browser version is outdated.", [button("Install update")]],
  "critical update": ["news.example", "Critical security update. Your browser is out of date.", [link("https://x.example/update.msix", "Download now")]],
};
for (const [name, [host, text, actions]] of Object.entries(fakeUpdates)) {
  test(`fake update flags: ${name}`, () => assert.equal(engine.detectFakeBrowserUpdate(host, text, actions), true));
}

const realUpdates = {
  "unsupported-browser notice linking to the makers": ["bank.example",
    "Your browser is out of date. Update your browser to continue.",
    [link("https://www.google.com/chrome/"), link("https://www.mozilla.org/firefox/new/", "Update Firefox")]],
  "the browser maker's own site": ["www.google.com", UPDATE, [link("https://dl.google.com/chrome/install/ChromeSetup.exe")]],
  "no update wording": ["hacked-blog.example", "Download our app", [link("https://hacked-blog.example/app.zip", "Download now")]],
  "news article about the update": ["news.example",
    "Google released Chrome 131 today. " + "Security fixes are included in this release. ".repeat(120) + UPDATE,
    [link("https://news.example/chrome-update.zip")]],
  "article quoting the lure": ["news.example", "Fake pages say 'your chrome is out of date' and offer a file.",
    [link("https://news.example/sample.zip")]],
  "update wording, but only an ordinary link": ["hacked-blog.example", UPDATE, [link("https://hacked-blog.example/about", "About us")]],
};
for (const [name, [host, text, actions]] of Object.entries(realUpdates)) {
  test(`fake update does not flag: ${name}`, () => assert.equal(engine.detectFakeBrowserUpdate(host, text, actions), false));
}

/* ── Card skimmer destinations ── */
test("card destinations a checkout is expected to use", () => {
  for (const to of ["api.stripe.com", "m.stripe.network", "deposit.us.shopifycs.com", "api.razorpay.com",
    "api.harbor-outfitters.example", "harbor-outfitters-api.example"]) {
    assert.equal(engine.isExpectedCardDestination("harbor-outfitters.example", to), true, to);
  }
  assert.equal(engine.isExpectedCardDestination("shop.example", "shop.example"), true, "same site");
});

test("card destinations that mean a skimmer", () => {
  for (const to of ["metrics-cdn.example", "www.google-analytics.com", "collector.vercel.app",
    "stripe-js.example", "harbor-outfitter.example"]) {
    assert.equal(engine.isExpectedCardDestination("harbor-outfitters.example", to), false, to);
  }
});

/* ── Brand sign-in ads ── */
test("ads for a brand's sign-in that lead elsewhere", () => {
  assert.equal(engine.adBrandMismatch("bizaccount-portal.example", "Amazon Business - Sign In to Your Account"), "Amazon");
  assert.equal(engine.adBrandMismatch("paypal-help-desk.example", "PayPal Customer Service - Official Site"), "PayPal");
  assert.equal(engine.adBrandMismatch("secure-portal.example", "Bank of America Login"), "Bank of America");
});

test("ads that are fine", () => {
  assert.equal(engine.adBrandMismatch("amazon.com", "Amazon Business - Sign In"), null, "the brand's own ad");
  assert.equal(engine.adBrandMismatch("business.amazon.com", "Amazon Business Login"), null);
  assert.equal(engine.adBrandMismatch("dell.example", "Microsoft 365 Business Premium - Buy Now"), null, "reseller product ad");
  assert.equal(engine.adBrandMismatch("bestbuy.example", "Apple iPhone 16 Deals"), null);
  assert.equal(engine.adBrandMismatch("bakery.example", "Sign in to order cakes"), null, "no brand");
});

test("both new signals alert on their own and are paid checks", () => {
  const S = engine.SIGNALS;
  for (const s of [S.FAKE_BROWSER_UPDATE, S.CARD_SKIMMER]) {
    assert.equal(engine.scoreSignals(new Set([s]), true).shouldAlert, true, s);
    assert.equal(engine.scoreSignals(new Set([s]), false).shouldAlert, false, s);
  }
});
