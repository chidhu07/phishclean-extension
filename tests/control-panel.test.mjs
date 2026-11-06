/* Refrigeration controllers open to the internet (riskEngine.js
   detectExposedControlPanel), the free notice in guards.js.
   Run: node --test tests/control-panel.test.mjs */
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
const detect = engine.detectExposedControlPanel;

test("public addresses: public IPv4, public IPv6, dynamic-DNS names", () => {
  for (const h of ["81.12.40.7", "[2a01:4f8::1]", "store-42.ddns.net", "kyl.myfritz.net"]) assert.equal(engine.isPublicAddress(h), true, h);
  for (const h of ["192.168.1.20", "10.0.0.5", "172.20.1.1", "127.0.0.1", "169.254.3.3", "100.72.0.9",
    "[::1]", "[fd12::1]", "[fe80::1]", "fridge.local", "storeview.example.com", "danfoss.com"]) {
    assert.equal(engine.isPublicAddress(h), false, h);
  }
});

test("a Danfoss or XWEB login title on a public address is flagged with its family", () => {
  assert.equal(detect("81.12.40.7", "AK-SM 800A Login", "", true), "Danfoss");
  assert.equal(detect("81.12.40.7", "StoreView", "", false), "Danfoss");
  assert.equal(detect("[2a01:4f8::1]", "XWEB EVO", "", true), "Copeland/Dixell XWEB");
  assert.equal(detect("shop12.duckdns.org", "Dixell XWEB500 - Login", "", true), "Copeland/Dixell XWEB");
});

test("a body-text match needs a password field", () => {
  assert.equal(detect("81.12.40.7", "Login", "Danfoss AK-SC 355 supervisor. User name Password", true), "Danfoss");
  assert.equal(detect("81.12.40.7", "News", "How the Danfoss and Copeland XWEB fridge attacks worked", false), "");
});

test("the same panel on the store network or a named site is not flagged", () => {
  assert.equal(detect("192.168.1.20", "AK-SM 800A Login", "", true), "");
  assert.equal(detect("10.4.0.2", "XWEB EVO", "", true), "");
  assert.equal(detect("www.danfoss.com", "Danfoss AK-SM 800A system manager", "", false), "");
  assert.equal(detect("81.12.40.7", "Router login", "admin password", true), "");
});
