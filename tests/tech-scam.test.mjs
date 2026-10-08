/* Rules for the fake virus / tech support scam signal (riskEngine.js).
   Run: node --test tests/tech-scam.test.mjs */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const ctx = { window: {} };
ctx.globalThis = ctx;
vm.runInNewContext(readFileSync(resolve(ROOT, "extension/lib/publicSuffix.js"), "utf8"), ctx);
vm.runInNewContext(readFileSync(resolve(ROOT, "extension/riskEngine.js"), "utf8"), ctx);
const engine = ctx.window.PhishCleanRiskEngine;

const textOf = (file) => readFileSync(resolve(ROOT, "tests", file), "utf8")
  .replace(/<style[\s\S]*?<\/style>/g, "")
  .replace(/<!--[\s\S]*?-->/g, "")
  .replace(/<[^>]+>/g, " ");

const scams = {
  "classic Windows page": "Windows Defender Security Center. Your computer has been blocked. Error # 0x268d3. Do not close this window. Call Microsoft Support: +1-844-555-0199 (Toll Free)",
  "Apple variant": "Your Mac is infected with Trojan Spyware alert. Your personal information is at risk. Call Apple Support 1 (888) 555-0142",
  "UK number": "Microsoft Security Alert! Your PC is infected. Don't close this page. Call 0800 123 4567",
  "fixture page": textOf("test-tech-support-scam.html"),
};
for (const [name, text] of Object.entries(scams)) {
  test(`flags: ${name}`, () => assert.equal(engine.detectTechSupportScam(text, false), true));
}

test("flags one phrase while the page holds fullscreen", () => {
  assert.equal(engine.detectTechSupportScam("Access denied. Your computer has been locked. Call 1-855-555-0100", true), true);
});

const clean = {
  "one phrase, no fullscreen": "Your computer has been locked. Call 1-855-555-0100",
  "article quoting phrases, no number": "Scammers show messages like 'Your computer has been blocked' and 'Call Microsoft Support'. Never call.",
  "article with one phrase and a bank number": "If you see 'your computer is infected', it is fake. Call your bank at 1-800-432-1000 if you paid.",
  "shop with a toll-free number": "Order online or call 1-800-555-0123. Free shipping on orders over $50.",
  "real support page": "Contact technical support at 1-888-555-0100 for help with your router setup.",
  "fixture article (quotes + shop number)": textOf("test-scam-article.html"),
  "long article with unquoted phrases": "lorem ipsum ".repeat(600) + "your computer has been blocked. do not close this window. call 1-800-555-0123",
};
for (const [name, text] of Object.entries(clean)) {
  test(`does not flag: ${name}`, () => assert.equal(engine.detectTechSupportScam(text, false), false));
}

test("toll-free gate", () => {
  assert.equal(engine.hasTollFreeNumber("call +1 (877) 555-0100 now"), true);
  assert.equal(engine.hasTollFreeNumber("call 0808 157 0192"), true);
  assert.equal(engine.hasTollFreeNumber("call 212-555-0100"), false);
});

test("the signal alerts on its own and is a paid check", () => {
  const S = engine.SIGNALS;
  assert.equal(engine.scoreSignals(new Set([S.TECH_SUPPORT_SCAM]), true).shouldAlert, true);
  assert.equal(engine.scoreSignals(new Set([S.TECH_SUPPORT_SCAM]), false).shouldAlert, false);
});

test("the reported-phishing signal alerts on its own on the free tier", () => {
  const S = engine.SIGNALS;
  assert.equal(engine.scoreSignals(new Set([S.KNOWN_PHISHING]), false).shouldAlert, true);
});
