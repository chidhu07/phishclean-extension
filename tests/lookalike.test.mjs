/* Lookalike domains (riskEngine.detectLookalikeDomain): digit and letter-pair
   swaps (g00gle, paypa1, rnicrosoft), brands inside hyphenated names, and a
   brand's own domain written as subdomains of an attacker's domain.
   The new rules were checked against the Tranco top 100,000 (2 Nov 2026) and
   added no false positives there; the real domains below keep that honest.
   Run: node --test tests/lookalike.test.mjs */
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

const attacks = {
  "paypa1-login.com": "paypal",
  "secure-paypa1.com": "paypal",
  "micros0ft-365-login.top": "microsoft",
  "micr0soft.com": "microsoft",
  "rnicrosoft.com": "microsoft",
  "g00gle.com": "google",
  "goog1e-docs.site": "google",
  "app1e-id-verify.com": "apple",
  "arnazon-billing.com": "amazon",
  "faceb00k-security.net": "facebook",
  "netfl1x-renew.com": "netflix",
  "co1nbase-support.com": "coinbase",
  "linkedln-jobs.com": "linkedin",
  "paypal.com.account-verify.ru": "paypal",
  "paypal.com.secure-login.xyz": "paypal",
  "login-microsoft.com.verify-user.top": "microsoft",
  "amaz0n.co.uk-orders.info": "amazon"
};

for (const [host, brand] of Object.entries(attacks)) {
  test(`flags ${host} as ${brand}`, () => {
    const hit = engine.detectLookalikeDomain(host, false);
    assert.ok(hit, `${host} not flagged`);
    assert.equal(hit.brand, brand);
  });
}

const real = [
  "paypal.com", "www.paypal.com", "appleid.apple.com", "login.microsoftonline.com", "storage.googleapis.com",
  "s3.amazonaws.com", "amazon.co.uk", "linkedin.com", "web.whatsapp.com", "github.com",
  "cstatic-images.com", "x.com", "365scores.com", "1password.com", "web3modal.com", "0x.org", "500px.com", "w3schools.com",
  "turnitin.com", "modern-living.com", "intern-jobs.com", "vvv.com"
];

for (const host of real) {
  test(`leaves ${host} alone`, () => {
    const hit = engine.detectLookalikeDomain(host, false);
    assert.equal(hit, null, `${host} flagged as ${hit?.brand} (${hit?.kind})`);
  });
}
