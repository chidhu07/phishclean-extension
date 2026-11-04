/* Rules behind Paste Guard and the download warnings (riskEngine.js
   classifyPaste / classifyDownload, used by guards.js), and the link badges
   on webmail, social and AI-answer pages (searchBadges.js).
   Run: node --test tests/guards.test.mjs */
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

/* ── Recovery phrases ──
   Random phrases from the BIP-39 English list. The rule was also run against
   20,000 random phrases of every length with no misses. */
const SEEDS = {
  "12 words": "machine quarter helmet art ski symbol carpet print never praise home buyer",
  "24 words": "glance lyrics core rate father attend crash flower gadget also example item beef salute nothing celery punch bulb motor inside bomb example gorilla congress",
  "18 words": "visit worry crunch oil citizen lava perfect office ghost detect sock fault theme city fever purse frown recall",
  "12 words, line breaks": "royal supply scissors coach\ntask heart wing sail\nchef drama consider solve",
  "numbered list": "1. royal 2. supply 3. scissors 4. coach 5. task 6. heart 7. wing 8. sail 9. chef 10. drama 11. consider 12. solve",
  "words BIP-39 shares with English": "that this what you when have they there then where will just",
};
for (const [name, text] of Object.entries(SEEDS)) {
  test(`recovery phrase: ${name}`, () => assert.equal(engine.classifyPaste(text, "text"), "seed"));
}

const NOT_SEEDS = {
  "search with 'the'": "how to fix the laptop screen when it goes black and flickers",
  "chat message": "can you send me your notes from the meeting today please thanks",
  "11 words": "machine quarter helmet art ski symbol carpet print never praise home",
  "13 words": "machine quarter helmet art ski symbol carpet print never praise home buyer cat",
  "capitalised": "Machine quarter helmet art ski symbol carpet print never praise home buyer",
  "with punctuation": "machine, quarter, helmet, art, ski, symbol, carpet, print, never, praise, home, buyer",
  "a long word": "machine quarter helmet art ski symbol carpet print never praise home buyerstuff",
  "an address": "221B Baker Street London",
};
for (const [name, text] of Object.entries(NOT_SEEDS)) {
  test(`not a recovery phrase: ${name}`, () => assert.notEqual(engine.classifyPaste(text, "text"), "seed"));
}

/* ── Card numbers (network test numbers) ── */
for (const card of ["4111 1111 1111 1111", "4111111111111111", "5555-5555-5555-4444", "378282246310005", "6011 1111 1111 1117", " 4012888888881881 "]) {
  test(`card number: ${card.trim()}`, () => assert.equal(engine.classifyPaste(card, "text"), "card"));
}
for (const notCard of ["4111 1111 1111 1112", "1111111111111111", "0000 0000 0000 0000", "+1 415 555 0132", "123456", "2026-11-02", "4111 1111 1111 1111 5555 5555"]) {
  test(`not a card number: ${notCard}`, () => assert.notEqual(engine.classifyPaste(notCard, "text"), "card"));
}

test("anything pasted into a password field is a password", () => {
  assert.equal(engine.classifyPaste("hunter2-Correct-Horse", "password"), "password");
  assert.equal(engine.classifyPaste("hunter2-Correct-Horse", "text"), null);
  assert.equal(engine.classifyPaste("   ", "password"), null);
});

/* ── Downloads ── */
const D = (href, attr) => engine.classifyDownload(href, attr);

test("disguised file names", () => {
  assert.equal(D("https://files.example/invoice.pdf.exe")?.kind, "disguised");
  assert.equal(D("https://files.example/x", "Scan_0042.jpg.scr")?.kind, "disguised");
  assert.equal(D("https://files.example/x", "contract.docx          .exe")?.kind, "disguised");
  /* U+202E: "invoice‮fdp.exe" displays as "invoiceexe.pdf" */
  const flipped = D("https://files.example/x", "invoice‮fdp.exe");
  assert.equal(flipped?.kind, "disguised");
  assert.equal(flipped.file, "invoicefdp.exe");
  assert.equal(D("https://files.example/Invoice%20March.pdf.exe")?.file, "Invoice March.pdf.exe");
});

test("files the page built itself", () => {
  assert.equal(D("blob:https://mail.example/1b2c", "Document.iso")?.kind, "smuggled");
  assert.equal(D("data:application/octet-stream;base64,TVqQ", "update.hta")?.kind, "smuggled");
  assert.equal(D("blob:https://app.example/9f", "export.csv"), null);
});

test("scripts", () => {
  for (const f of ["fix.hta", "setup.vbs", "run.ps1", "install.bat", "invoice.lnk", "x.wsf", "addin.xll"]) {
    assert.equal(D(`https://cdn.example/${f}`)?.kind, "script", f);
  }
  /* A plain .js link opens as text; only a requested download counts. */
  assert.equal(D("https://cdn.example/app.js"), null);
  assert.equal(D("https://cdn.example/app.js", "")?.kind, "script");
  assert.equal(D("https://cdn.example/x", "Payment.js")?.kind, "script");
});

test("programs", () => {
  for (const f of ["ZoomInstaller.exe", "setup.msi", "Signal.dmg", "app.apk", "disk.iso", "tool.jar"]) {
    assert.equal(D(`https://dl.example/${f}`)?.kind, "program", f);
  }
});

test("ordinary files and pages are not downloads to warn about", () => {
  for (const href of ["https://example.com/report.pdf", "https://example.com/photo.jpg", "https://example.com/archive.zip",
    "https://example.com/", "https://example.com/blog/setup-exe-guide", "https://www.example.com", "mailto:a@example.com", "javascript:void(0)"]) {
    assert.equal(D(href), null, href);
  }
  /* "example.com" in the last path segment is a host, not a .com program. */
  assert.equal(D("https://web.archive.org/web/2020/example.com"), null);
});

/* ── Link badges beyond search pages ── */
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

test("badges load on mail, social, chat and AI pages, and Brave Search", () => {
  for (const href of ["https://mail.google.com/mail/u/0/#inbox", "https://outlook.live.com/mail/0/", "https://outlook.office.com/mail/",
    "https://www.facebook.com/", "https://x.com/home", "https://www.reddit.com/r/scams", "https://www.linkedin.com/feed/",
    "https://web.whatsapp.com/", "https://chatgpt.com/c/1", "https://www.perplexity.ai/search/x", "https://gemini.google.com/app",
    "https://claude.ai/chat/1", "https://search.brave.com/search?q=x"]) {
    assert.ok(loadBadges(href), href);
  }
  assert.equal(loadBadges("https://www.example-shop.com/"), undefined);
  assert.equal(loadBadges("https://docs.google.com/document/d/1"), undefined);
});

test("real address behind mail and social link wrappers", () => {
  const b = loadBadges("https://outlook.live.com/mail/0/");
  assert.equal(b.resultUrl("https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fpaypa1-login.com%2Fx&data=1"), "https://paypa1-login.com/x");
  assert.equal(b.resultUrl("https://l.facebook.com/l.php?u=https%3A%2F%2Fevil.example%2F&h=AT0"), "https://evil.example/");
  assert.equal(b.resultUrl("https://www.youtube.com/redirect?event=video_description&q=https%3A%2F%2Fgiveaway.example%2F"), "https://giveaway.example/");
  assert.equal(b.resultUrl("https://www.linkedin.com/redir/redirect?url=https%3A%2F%2Fjob-offer.example%2F"), "https://job-offer.example/");
  assert.equal(b.resultUrl("https://www.google.com/url?q=https://evil.example/&sa=D"), "https://evil.example/");
  assert.equal(b.resultUrl("https://out.reddit.com/t3_x?url=https%3A%2F%2Fevil.example%2F"), "https://evil.example/");
  /* Wrapper with nothing usable inside: no badge rather than a badge for the wrapper. */
  assert.equal(b.resultUrl("https://l.facebook.com/l.php?u=javascript%3Aalert(1)"), null);
});

test("X: the address comes from the link text, not t.co", () => {
  const b = loadBadges("https://x.com/home");
  assert.equal(b.resultUrl("https://t.co/AbC123", "paypa1-secure.com/login…"), "https://paypa1-secure.com/");
  assert.equal(b.resultUrl("https://t.co/AbC123", "https://evil.example/claim"), "https://evil.example/");
  assert.equal(b.resultUrl("https://t.co/AbC123", "Read the thread"), null);
});

test("router and local addresses in answers get no IP badge", () => {
  const b = loadBadges("https://chatgpt.com/c/1");
  for (const h of ["192.168.1.1", "10.0.0.1", "172.16.0.5", "127.0.0.1", "169.254.1.1"]) assert.ok(b.isPrivateIp(h), h);
  for (const h of ["45.33.32.156", "172.32.0.1", "8.8.8.8"]) assert.ok(!b.isPrivateIp(h), h);
  assert.equal(b.verdict("192.168.1.1", false, true), null);
  assert.equal(b.verdict("45.33.32.156", false, true)?.level, "caution");
});
