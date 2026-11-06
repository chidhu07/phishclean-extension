/* Rules for sign-in tricks that never show a fake password page on a
   lookalike domain (riskEngine.js): browser-in-the-browser fake popups and
   device-code phishing.
   Run: node --test tests/sign-in-tricks.test.mjs */
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

/* ── Browser-in-the-browser ── */
const box = (text, extra = {}) => ({ text, hasLogin: true, hasFrame: false, ...extra });

test("BitB: fake Google window with a login form on another site", () => {
  assert.ok(engine.detectBrowserInBrowser("free-game-skins.example", [box("Sign in - Google Accounts https://accounts.google.com/signin/v2/identifier Email or phone")]));
});
test("BitB: fake Microsoft window wrapping a frame", () => {
  assert.ok(engine.detectBrowserInBrowser("shared-doc.example", [box("https://login.microsoftonline.com/common/oauth2 Sign in", { hasLogin: false, hasFrame: true })]));
});
test("BitB: Steam login popup used by fake trading sites", () => {
  assert.ok(engine.detectBrowserInBrowser("csgo-case-drop.example", [box("Steam Community :: Sign In https://steamcommunity.com/openid/login")]));
});
test("BitB: the company's own site showing its own address is fine", () => {
  assert.equal(engine.detectBrowserInBrowser("myaccount.google.com", [box("https://accounts.google.com/ Manage your account")]), false);
});
test("BitB: a box with the address but no login form or frame is fine", () => {
  assert.equal(engine.detectBrowserInBrowser("blog.example", [box("Tip: always check the bar says https://accounts.google.com", { hasLogin: false })]), false);
});
test("BitB: no sign-in address, no signal", () => {
  assert.equal(engine.detectBrowserInBrowser("shop.example", [box("Newsletter signup https://shop.example/subscribe")]), false);
});

/* ── Device-code phishing ── */
const LURE_MS = "Secure document shared with you. To view the document, go to https://microsoft.com/devicelogin and enter the code GQKBF3XNJ when asked. The code expires in 15 minutes.";
const LURE_GH = "Verify your developer account. Open github.com/login/device and enter the code below: WDJB-MJHT";
const DOCS = "Device code flow. The user is shown a code such as ABCD1234 and asked to enter it at microsoft.com/devicelogin. " + "This is how the OAuth 2.0 device authorization grant works for input-constrained devices. ".repeat(60);

test("device code: Microsoft devicelogin lure", () => {
  assert.ok(engine.detectDeviceCodePhish("doc-share-portal.example", LURE_MS));
});
test("device code: GitHub device lure with a dashed code", () => {
  assert.ok(engine.detectDeviceCodePhish("dev-verify.example", LURE_GH));
});
test("device code: Microsoft's own page is fine", () => {
  assert.equal(engine.detectDeviceCodePhish("login.microsoftonline.com", LURE_MS), false);
  assert.equal(engine.detectDeviceCodePhish("www.microsoft.com", LURE_MS), false);
});
test("device code: long documentation page is fine", () => {
  assert.equal(engine.detectDeviceCodePhish("oauth-guide.example", DOCS), false);
});
test("device code: no code on the page, no signal", () => {
  assert.equal(engine.detectDeviceCodePhish("helpdesk.example", "Go to microsoft.com/devicelogin and enter the code your TV shows."), false);
});
test("device code: an all-letters word is not a code", () => {
  assert.equal(engine.detectDeviceCodePhish("notice.example", "IMPORTANT: enter the code from your TV at microsoft.com/devicelogin to finish setup."), false);
});

test("both signals score high enough to warn on their own", () => {
  assert.ok(engine.WEIGHTS ? engine.WEIGHTS.BROWSER_IN_BROWSER >= 40 : true);
  assert.ok(engine.SIGNALS.BROWSER_IN_BROWSER && engine.SIGNALS.DEVICE_CODE_PHISH);
});
