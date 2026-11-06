/* Rules for the notification-bait and fake-shop signals (riskEngine.js) and
   the search result badges (searchBadges.js).
   Run: node --test tests/shield.test.mjs */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const load = (ctx, file) => vm.runInNewContext(readFileSync(resolve(ROOT, file), "utf8"), ctx);
const ctx = { window: {} };
ctx.globalThis = ctx;
load(ctx, "extension/lib/publicSuffix.js");
load(ctx, "extension/riskEngine.js");
const engine = ctx.window.PhishCleanRiskEngine;

const textOf = (file) => readFileSync(resolve(ROOT, "tests", file), "utf8")
  .replace(/<title>[\s\S]*?<\/title>/g, "")
  .replace(/<style[\s\S]*?<\/style>/g, "")
  .replace(/<!--[\s\S]*?-->/g, "")
  .replace(/<[^>]+>/g, " ")
  .replace(/&[a-z#0-9]+;/gi, " ");

/* ── Notification bait ── */
const baits = {
  "robot check": 'Click "Allow" if you are not a robot',
  "video pretext": "Your video is ready. Press Allow to watch the video.",
  "download pretext": "Click Allow to continue to your download",
  "age check": "Tap Allow to confirm you are 18+",
  "fixture page": textOf("test-notification-bait.html"),
};
for (const [name, text] of Object.entries(baits)) {
  test(`notification bait flags: ${name}`, () => assert.equal(engine.detectNotificationBait(text, "default"), true));
}

const notBaits = {
  "no pretext": "Click Allow to receive order updates from our shop.",
  "cookie banner": "We use cookies. Accept all or manage preferences to continue.",
  "help article quoting the phrase": "Spam sites say 'click allow if you are not a robot'. Never do it.",
  "long article": "lorem ipsum ".repeat(400) + "click allow if you are not a robot",
};
for (const [name, text] of Object.entries(notBaits)) {
  test(`notification bait does not flag: ${name}`, () => assert.equal(engine.detectNotificationBait(text, "default"), false));
}

test("notification bait is skipped once the site can no longer ask", () => {
  assert.equal(engine.detectNotificationBait(baits["robot check"], "denied"), false);
  assert.equal(engine.detectNotificationBait(baits["robot check"], "granted"), false);
});

/* ── Fake shop ── */
test("fake shop: brand in domain + deep discounts", () => {
  const r = engine.detectFakeShop("nike-outlet-sale.shop", textOf("test-fake-shop.html"), true);
  assert.equal(r?.brand, "nike");
});

test("fake shop: brand glued into the label", () => {
  assert.equal(engine.detectFakeShop("nikeoutletstore.com", textOf("test-fake-shop.html"), false)?.brand, "nike");
});

test("fake shop: four weak cues without a brand", () => {
  const text = "Closing down sale! Add to cart. Wool coat $200 $29 -85%. Boots $150 $25 -83%. Bag $90 $15 -83%.";
  assert.ok(engine.detectFakeShop("cheap-goods-deals.top", text, true));
});

const realShops = {
  "brand's own domain": ["nike.com", textOf("test-fake-shop.html"), true],
  "indie shop clearance on .com": ["harbor-outfitters.com", textOf("test-real-shop-sale.html"), false],
  "indie shop on .shop with policies": ["harbor.shop", textOf("test-real-shop-sale.html"), false],
  "brand review blog, no shop": ["nike-shoe-reviews.com", "Our review of the Air Max 270, which retails for $160. 81% of readers liked it.", true],
  "100% cotton is not a discount": ["nike-fan-tees.com", "Add to cart. 100% cotton tee $20, 100% cotton hoodie $40, 50% wool $60", true],
  "trusted platform": ["amazon.com", textOf("test-fake-shop.html"), true],
};
for (const [name, [host, text, missing]] of Object.entries(realShops)) {
  test(`fake shop does not flag: ${name}`, () => assert.equal(engine.detectFakeShop(host, text, missing), null));
}

test("both new signals alert on their own and are paid checks", () => {
  const S = engine.SIGNALS;
  for (const s of [S.NOTIFICATION_BAIT, S.FAKE_SHOP]) {
    assert.equal(engine.scoreSignals(new Set([s]), true).shouldAlert, true, s);
    assert.equal(engine.scoreSignals(new Set([s]), false).shouldAlert, false, s);
  }
  assert.equal(Object.keys(S).length, 29, "signal count is quoted in the extension copy");
});

/* ── Search badges ── */
function loadBadges(href) {
  const u = new URL(href);
  const c = {
    window: { PhishCleanRiskEngine: engine },
    location: { href, hostname: u.hostname, pathname: u.pathname },
    document: { querySelectorAll: () => [], documentElement: {} },
    chrome: { storage: { local: { get: () => new Promise(() => {}) } } },
    MutationObserver: class { observe() {} },
    URL, atob, setTimeout, clearTimeout,
  };
  c.globalThis = c;
  load(c, "extension/searchBadges.js");
  return c.window.PhishCleanSearchBadges;
}

test("badges only load on result pages", () => {
  assert.ok(loadBadges("https://www.google.com/search?q=x"));
  assert.ok(loadBadges("https://www.google.co.uk/search?q=x"));
  assert.ok(loadBadges("https://www.bing.com/search?q=x"));
  assert.ok(loadBadges("https://duckduckgo.com/?q=x"));
  assert.equal(loadBadges("https://www.google.com/maps"), undefined);
  assert.equal(loadBadges("https://example.com/search"), undefined);
});

test("real destinations are read out of redirect links", () => {
  const g = loadBadges("https://www.google.com/search?q=x");
  assert.equal(g.resultUrl("https://evil.example/a"), "https://evil.example/a");
  assert.equal(g.resultUrl("/url?q=https://evil.example/a&sa=U"), "https://evil.example/a");
  assert.equal(g.resultUrl("/preferences"), null);
  const b = loadBadges("https://www.bing.com/search?q=x");
  const encoded = "a1" + Buffer.from("https://evil.example/login").toString("base64url");
  assert.equal(b.resultUrl(`https://www.bing.com/ck/a?!&&p=abc&u=${encoded}&ntb=1`), "https://evil.example/login");
  const d = loadBadges("https://html.duckduckgo.com/html/");
  assert.equal(d.resultUrl("//duckduckgo.com/l/?uddg=https%3A%2F%2Fevil.example%2F"), "https://evil.example/");
});

test("badge verdicts", () => {
  const g = loadBadges("https://www.google.com/search?q=x");
  assert.equal(g.verdict("anything.example", true, false).level, "danger", "reported list is free");
  assert.equal(g.verdict("paypal.com", false, false).level, "safe");
  assert.equal(g.verdict("paypal-secure-login.com", false, false), null, "lookalikes are a paid check");
  assert.equal(g.verdict("paypal-secure-login.com", false, true).level, "caution");
  assert.equal(g.verdict("paypa1.com", false, true).level, "caution");
  assert.equal(g.verdict("applebees.com", false, true), null, "brand prefix of a real business");
  assert.equal(g.verdict("dhs.gov", false, true), null, "one letter from a short brand");
  assert.equal(g.verdict("small-bakery.com", false, true), null, "unknown sites get no badge");
});
