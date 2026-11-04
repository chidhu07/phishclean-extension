/* PhishClean Paste Guard and download warnings
   Both ask before something happens rather than scoring the page:

   Paste Guard: pasting a wallet recovery phrase into any website, or a card
   number or password into a page that already looks wrong (reported,
   lookalike address, not encrypted, or flagged by the other checks).

   Download warnings: a file that runs code when opened, if its name is
   disguised ("invoice.pdf.exe"), if the page built it itself (blob:/data:,
   "HTML smuggling"), if it is a script, or if it is a program and the page
   or the link looks wrong.

   The rules are classifyPaste / classifyDownload in riskEngine.js. Nothing
   pasted, typed or downloaded is sent anywhere; the clipboard text is read
   from the paste event, on the device, only to classify it.
   Trial and paid plans only, like the other paused checks.
*/
(() => {
  const engine = window.PhishCleanRiskEngine;
  const page = window.PhishCleanPage;
  if (!engine || !page) return;

  const host = () => location.hostname.toLowerCase();
  let ready = false;
  page.ready().then(() => { ready = true; }).catch(() => {});

  /* Guards decide synchronously inside the event, so they stand back until
     the licence and trusted lists are loaded (a few milliseconds after the
     page starts). */
  const active = () => ready && page.proEnabled() && !page.isWhitelisted();

  const isPublicIp = (h) => /^(\d{1,3}\.){3}\d{1,3}$/.test(h) &&
    !/^(10\.|127\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.)/.test(h);

  /* Why this address is not one to trust with a password, card or program,
     or "" if nothing is wrong with it. */
  function addressConcern(h, protocol) {
    if (!h || engine.isLocalhost(h)) return "";
    if (protocol === "http:") return `${h} is not encrypted (no HTTPS), so what you send can be read on the way.`;
    if (engine.isTrustedDomain(h)) return "";
    const look = engine.detectLookalikeDomain(h, true);
    if (look?.lookalike) {
      const brand = look.brand ? look.brand.charAt(0).toUpperCase() + look.brand.slice(1) : "";
      return brand ? `${h} looks like ${brand} but is not ${brand}'s site.` : `${h} uses lookalike characters to imitate another site.`;
    }
    if (isPublicIp(h)) return `${h} is a bare IP address, not a named site.`;
    return "";
  }

  function pageConcern() {
    const signals = page.signals();
    if (signals.has(engine.SIGNALS.KNOWN_PHISHING)) return "This site is on the reported-phishing list.";
    const own = addressConcern(host(), location.protocol);
    if (own) return own;
    if (engine.scoreSignals(signals, true).shouldAlert) return "PhishClean already found signs this page may not be safe.";
    return "";
  }

  function linkConcern(href) {
    try {
      const u = new URL(href);
      return /^https?:$/.test(u.protocol) ? addressConcern(u.hostname.toLowerCase(), u.protocol) : "";
    } catch { return ""; }
  }

  /* ── the prompt ── */
  let open = false;

  function ask({ title, body, cancel, proceed, reason }) {
    if (open) return Promise.resolve(false);
    open = true;
    const lastFocused = document.activeElement;
    chrome.runtime.sendMessage({
      type: "INCREMENT_BLOCK_COUNT",
      threat: {
        domain: location.hostname,
        url: location.href.substring(0, 200),
        score: 0,
        level: "warning",
        reasons: [reason],
        signals: [],
        occurred_at: new Date().toISOString()
      }
    }).catch(() => {});

    return new Promise((resolve) => {
      const wrapper = document.createElement("div");
      wrapper.id = "phishclean-guard";
      const shadow = wrapper.attachShadow({ mode: "closed" });
      shadow.innerHTML = `
        <style>
          *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
          :host { all: initial; }
          .overlay { position: fixed; inset: 0; z-index: 2147483647; background: rgba(0,0,0,0.55);
            display: flex; align-items: center; justify-content: center;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
          .modal { width: min(440px, 92vw); background: #0f1117; color: #e2e8f0; border: 1px solid #1e293b;
            border-radius: 14px; padding: 22px; box-shadow: 0 24px 48px rgba(0,0,0,0.4); }
          .head { display: flex; gap: 12px; align-items: flex-start; margin-bottom: 14px; }
          .title { font-size: 16px; font-weight: 600; color: #f1f5f9; line-height: 1.35; }
          .body { font-size: 13px; color: #94a3b8; line-height: 1.55; margin-top: 4px; }
          .reason { font-size: 13px; color: #fcd34d; background: rgba(245,158,11,0.08);
            border: 1px solid rgba(245,158,11,0.2); border-radius: 8px; padding: 8px 10px; margin-bottom: 16px; line-height: 1.5; }
          .actions { display: flex; gap: 8px; flex-wrap: wrap; }
          .btn { border: none; border-radius: 8px; padding: 9px 14px; font-size: 13px; font-weight: 500; cursor: pointer; font-family: inherit; }
          .cancel { background: #dc2626; color: #fff; }
          .cancel:hover { background: #b91c1c; }
          .proceed { background: #1e293b; color: #94a3b8; border: 1px solid #334155; }
          .proceed:hover { background: #334155; color: #e2e8f0; }
          .privacy { margin-top: 14px; font-size: 11px; color: #475569; }
        </style>
        <div class="overlay">
          <div class="modal" role="alertdialog" aria-modal="true" aria-labelledby="t" aria-describedby="b">
            <div class="head">
              <svg width="30" height="34" viewBox="0 0 32 36" fill="none" style="flex-shrink:0"><path d="M16 1.5L3 7v10.5c0 9 5.5 16.5 13 18.5 7.5-2 13-9.5 13-18.5V7L16 1.5z" fill="#f59e0b"/><path d="M16 4.5L6 9v8.5c0 7.5 4.5 13.5 10 15.5 5.5-2 10-8 10-15.5V9L16 4.5z" fill="#d97706"/><path d="M16 11v9" stroke="#fff" stroke-width="2.8" stroke-linecap="round"/><circle cx="16" cy="25" r="1.7" fill="#fff"/></svg>
              <div><div class="title" id="t"></div><div class="body" id="b"></div></div>
            </div>
            <div class="reason" id="r"></div>
            <div class="actions">
              <button class="btn cancel" id="cancel"></button>
              <button class="btn proceed" id="proceed"></button>
            </div>
            <p class="privacy">PhishClean checked this on your device. Nothing was sent anywhere.</p>
          </div>
        </div>`;
      /* textContent: file names and hosts come from the page. */
      shadow.getElementById("t").textContent = title;
      shadow.getElementById("b").textContent = body;
      shadow.getElementById("r").textContent = reason;
      shadow.getElementById("cancel").textContent = cancel;
      shadow.getElementById("proceed").textContent = proceed;

      const done = (ok) => {
        wrapper.remove();
        open = false;
        try { lastFocused?.focus?.(); } catch { /* element gone */ }
        resolve(ok);
      };
      shadow.getElementById("cancel").onclick = () => done(false);
      shadow.getElementById("proceed").onclick = () => done(true);
      const buttons = [shadow.getElementById("cancel"), shadow.getElementById("proceed")];
      shadow.querySelector(".overlay").addEventListener("keydown", (e) => {
        if (e.key === "Escape") { e.preventDefault(); done(false); }
        if (e.key === "Tab") {
          e.preventDefault();
          buttons[buttons.indexOf(shadow.activeElement) === 0 ? 1 : 0].focus();
        }
      });
      document.documentElement.appendChild(wrapper);
      buttons[0].focus();
    });
  }

  /* ── Paste Guard ── */
  const TEXT_INPUT = /^(text|password|email|tel|number|search|url|)$/;

  function editableTarget(e) {
    const el = e.composedPath?.()[0] || e.target;
    if (!(el instanceof Element)) return null;
    if (el.tagName === "TEXTAREA") return el;
    if (el.tagName === "INPUT") return TEXT_INPUT.test((el.getAttribute("type") || "").toLowerCase()) ? el : null;
    return el.closest?.('[contenteditable=""], [contenteditable="true"], [contenteditable="plaintext-only"]') || null;
  }

  const PASTE_COPY = {
    seed: {
      title: "Don't paste your recovery phrase",
      body: "Real wallets never ask for your recovery phrase on a website. Anyone who has these words can take everything in the wallet, and there is no way to get it back.",
      cancel: "Don't paste",
      proceed: "Paste anyway"
    },
    card: {
      title: "Paste your card number here?",
      body: "Card numbers pasted into a fake checkout go straight to the scammer. Check the address before you pay.",
      cancel: "Don't paste",
      proceed: "Paste anyway"
    },
    password: {
      title: "Paste your password here?",
      body: "A password pasted into a fake login page is sent straight to whoever made it. Check the address first.",
      cancel: "Don't paste",
      proceed: "Paste anyway"
    }
  };

  window.addEventListener("paste", (e) => {
    if (!active()) return;
    const target = editableTarget(e);
    if (!target) return;
    const text = e.clipboardData?.getData("text/plain") || "";
    const type = target.tagName === "INPUT" ? (target.getAttribute("type") || "").toLowerCase() : "";
    const kind = engine.classifyPaste(text, type);
    if (!kind) return;
    /* A recovery phrase is never safe to paste into a website; a card or
       password only needs a second look where the page looks wrong. */
    const reason = kind === "seed"
      ? `You're about to paste what looks like a wallet recovery phrase into ${host()}.`
      : pageConcern();
    if (!reason) return;

    e.preventDefault();
    e.stopImmediatePropagation();
    ask({ ...PASTE_COPY[kind], reason }).then((ok) => {
      if (!ok) return;
      target.focus();
      /* insertText goes through the page's own input handling, like a real
         paste would, and doesn't fire another paste event. */
      if (!document.execCommand("insertText", false, text) && "value" in target) {
        target.setRangeText(text, target.selectionStart ?? target.value.length, target.selectionEnd ?? target.value.length, "end");
        target.dispatchEvent(new Event("input", { bubbles: true }));
      }
    });
  }, true);

  /* ── Download warnings ── */
  const DOWNLOAD_COPY = {
    disguised: (file) => ({
      title: "This file is disguised",
      body: `"${file}" is named to look like a document or picture, but it is a program that runs when you open it. Real documents don't do that.`
    }),
    smuggled: (file) => ({
      title: "This page made this file itself",
      body: `"${file}" wasn't downloaded from a server; the page assembled it in your browser. Attackers do this to get malware past email and download filters.`
    }),
    script: (file) => ({
      title: "This file runs code when opened",
      body: `"${file}" is a script. Opening it can install software or change settings on your computer, and websites almost never need you to run one.`
    }),
    program: (file) => ({
      title: "Download this program?",
      body: `"${file}" is a program, and something about where it comes from looks wrong. Get software from the maker's own website instead.`
    })
  };

  /* Clicks we let through after the user chose "Download anyway". */
  const allowed = new WeakSet();

  window.addEventListener("click", (e) => {
    if (e.button !== 0 || !active()) return;
    const a = e.composedPath?.().find((n) => n instanceof Element && n.tagName === "A" && n.hasAttribute("href")) ||
      (e.target instanceof Element && e.target.closest("a[href]"));
    if (!a || allowed.has(a)) return;
    const hit = engine.classifyDownload(a.href, a.hasAttribute("download") ? a.getAttribute("download") : undefined);
    if (!hit) return;

    let reason = "";
    if (hit.kind === "disguised" || hit.kind === "smuggled") {
      reason = pageConcern() || `Found on ${host()}.`;
    } else if (hit.kind === "script") {
      const linkHost = engine.hostname(a.href);
      if (linkHost && engine.isTrustedDomain(linkHost)) return;
      reason = pageConcern() || linkConcern(a.href) || `Offered by ${host()}.`;
    } else {
      reason = pageConcern() || linkConcern(a.href);
    }
    if (!reason) return;

    e.preventDefault();
    e.stopImmediatePropagation();
    const copy = DOWNLOAD_COPY[hit.kind](hit.file);
    ask({ ...copy, reason, cancel: "Don't download", proceed: "Download anyway" }).then((ok) => {
      if (!ok) return;
      allowed.add(a);
      a.click();
      setTimeout(() => allowed.delete(a), 1000);
    });
  }, true);

  window.PhishCleanGuards = { addressConcern };
})();
