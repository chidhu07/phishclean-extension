/* PhishClean content script
   All detection runs 100% locally. No page data is ever sent to any server.
*/
(() => {
  /* Our checkout return page: its buttons need the extension to close the
     tab or open the extension. The data attribute tells the page's own
     script to stand back. */
  if (/^(www\.)?phishclean\.com$/.test(location.hostname) && location.pathname.startsWith("/payment-success")) {
    document.documentElement.dataset.phishcleanExtension = "1";
    for (const [id, action] of [["return-btn", "return"], ["close-btn", "close"]]) {
      document.getElementById(id)?.addEventListener("click", () => {
        chrome.runtime.sendMessage({ type: "PAYMENT_PAGE_ACTION", action }).catch(() => {});
      });
    }
  }

  const engine = window.PhishCleanRiskEngine;
  if (!engine) return;

  const WHITELIST_KEY = "phishclean_whitelist_domains";
  const ORG_TRUSTED_KEY = "phishclean_org_trusted";
  const LICENSE_KEY = "phishclean_license";
  const COOLDOWN_MS = 5 * 60 * 1000; /* 5 minutes between identical alerts */

  const state = {
    signals: new Set(),
    whitelist: [],
    proEnabled: false,
    serviceEnabled: false,
    ignoreOnce: false,
    lastFingerprint: "",
    lastAlertAt: 0,
    modalShown: false,
    clipboard: "",
    skimmerHost: ""
  };

  const host = () => location.hostname.toLowerCase();

  /* ── load stored whitelist + license ── */
  async function loadLocalState() {
    const data = await chrome.storage.local.get([WHITELIST_KEY, LICENSE_KEY, ORG_TRUSTED_KEY]);
    state.whitelist = data[WHITELIST_KEY] || [];
    state.orgTrusted = data[ORG_TRUSTED_KEY] || [];
    const license = data[LICENSE_KEY];
    /* Detection always runs. The licence decides how much of it: without a
       trial or a plan we still run the free signals, which is why
       serviceEnabled is no longer tied to proEnabled. A missing licence means
       we have not reached the server yet — that must not disable protection,
       so it degrades to the free tier rather than to nothing. */
    state.proEnabled = !!(license?.trial_active || license?.is_paid);
    state.serviceEnabled = true;
    state.ignoreOnce = sessionStorage.getItem(`phishclean_ignore_${host()}`) === "1";
  }

  let stateLoading = null;
  const stateLoaded = () => stateLoading || (stateLoading = loadLocalState());

  function isWhitelisted() {
    const h = host();
    /* The user's own list is exact hosts; the organisation's (set by IT
       policy) covers subdomains too, e.g. corp.example.com and sso.corp... */
    return state.whitelist.includes(h) ||
      (state.orgTrusted || []).some((d) => h === d || h.endsWith("." + d));
  }

  /* guards.js (Paste Guard, download warnings) runs in this same isolated
     world and asks about this page through here; the page itself can't see
     it. */
  window.PhishCleanPage = {
    ready: () => stateLoaded(),
    signals: () => state.signals,
    proEnabled: () => state.proEnabled,
    isWhitelisted: () => isWhitelisted()
  };

  async function addToWhitelist() {
    const next = [...new Set([...state.whitelist, host()])];
    state.whitelist = next;
    await chrome.storage.local.set({ [WHITELIST_KEY]: next });
  }

  /* ── signal detectors ── */

  /* FREE: password field */
  function detectPasswordFields() {
    const count = document.querySelectorAll('input[type="password"]').length;
    if (count > 0) state.signals.add(engine.SIGNALS.PASSWORD_FIELD);
  }

  /* FREE: host is on the reported-phishing list. The background matches it
     against the local copy of the feed; only this page's hostname crosses to
     the worker, and nothing leaves the device. */
  async function detectReportedPhishing() {
    try {
      const r = await chrome.runtime.sendMessage({ type: "FEED_CHECK", host: host() });
      if (r?.listed) state.signals.add(engine.SIGNALS.KNOWN_PHISHING);
    } catch { /* worker unavailable — the other checks still run */ }
  }

  /* FREE: form action domain mismatch */
  function detectDomainMismatch() {
    const pageHost = host();
    for (const form of document.querySelectorAll("form[action]")) {
      const actionHost = engine.hostname(form.action);
      if (actionHost && engine.isThirdParty(pageHost, actionHost)) {
        state.signals.add(engine.SIGNALS.DOMAIN_MISMATCH);
        break;
      }
    }
  }

  /* PRO: hidden/off-screen iframes (only third-party — same-domain iframes are normal) */
  function detectHiddenIframes() {
    const pageHost = host();
    for (const f of document.querySelectorAll("iframe")) {
      const iframeSrc = f.src || "";
      if (!iframeSrc || iframeSrc === "about:blank") continue;
      const iframeHost = engine.hostname(iframeSrc);
      if (!iframeHost || !engine.isThirdParty(pageHost, iframeHost)) continue;
      if (engine.isTrustedDomain(iframeHost)) continue;

      const r = f.getBoundingClientRect();
      const s = getComputedStyle(f);
      const hidden = s.display === "none" || s.visibility === "hidden" || s.opacity === "0";
      const tiny = r.width <= 2 || r.height <= 2;
      const offscreen = r.right < 0 || r.bottom < 0 || r.left > innerWidth || r.top > innerHeight;
      if (hidden || tiny || offscreen) {
        state.signals.add(engine.SIGNALS.HIDDEN_IFRAME);
        break;
      }
    }
  }

  /* PRO: JWT in URL */
  function detectJwtInUrl() {
    if (engine.isJwtLike(location.href)) state.signals.add(engine.SIGNALS.JWT_URL);
  }

  /* PRO: suspicious query params */
  function detectSuspiciousQuery() {
    if (engine.hasSuspiciousQuery(location.href)) state.signals.add(engine.SIGNALS.QUERY_TOKEN_PATTERN);
  }

  /* PRO: raw login password in the URL */
  function detectCredentialInUrl() {
    if (engine.hasCredentialInQuery(location.href)) state.signals.add(engine.SIGNALS.CREDENTIAL_IN_URL);
  }

  /* PRO: visual anomalies (unusual form structures) */
  function detectVisualAnomalies() {
    for (const form of document.querySelectorAll("form")) {
      const pwdCount = form.querySelectorAll('input[type="password"]').length;
      const hasUser = form.querySelector(
        'input[type="email"], input[name*="user" i], input[name*="email" i], input[name*="login" i]'
      );
      const hasSubmit = form.querySelector('button[type="submit"], input[type="submit"]');

      if (pwdCount >= 1 && !hasUser) state.signals.add(engine.SIGNALS.SUSPICIOUS_LOGIN_REGION);
      if (pwdCount >= 2) state.signals.add(engine.SIGNALS.VISUAL_ANOMALY);
      if (pwdCount >= 1 && !hasSubmit) state.signals.add(engine.SIGNALS.VISUAL_ANOMALY);
    }
  }

  /* PRO: trusted-brand backlink impersonation */
  function detectBacklinkImpersonation() {
    const refs = [];
    const collect = (selector, attr, type) => {
      for (const node of document.querySelectorAll(selector)) {
        const raw = node.getAttribute(attr);
        if (!raw) continue;
        try {
          const resolved = new URL(raw, location.href);
          if (!/^https?:$/i.test(resolved.protocol)) continue;
          refs.push({ type, url: resolved.href });
        } catch { /* ignore invalid urls */ }
      }
    };

    collect("a[href]", "href", "anchor");
    collect("img[src]", "src", "image");
    collect("script[src]", "src", "script");
    /* Only stylesheets: preconnect, icon and canonical links say nothing about
       what the page pretends to be. */
    collect('link[rel~="stylesheet"][href]', "href", "stylesheet");
    collect("form[action]", "action", "form_action");
    collect("iframe[src]", "src", "iframe");

    const hasPassword = document.querySelectorAll('input[type="password"]').length > 0;
    const result = engine.analyzeBacklinkRefs(location.href, refs, hasPassword);
    /* Linking to big brands is what ordinary sites do (footers, "Sign in with
       Google", Google Fonts). It only means impersonation when the page also
       has something to collect: a password field, or a form or hotlinked logo
       dressed up as the brand. */
    const collects = hasPassword ||
      result.signals.includes("form_submits_to_trusted_domain") ||
      (result.signals.includes("hotlinked_brand_asset") && document.querySelector("form input:not([type=hidden])"));
    if (!collects) return;
    if (result.riskScore >= 55 || (result.riskScore >= 40 && result.backlinks.length >= 3)) {
      state.signals.add(engine.SIGNALS.BACKLINK_IMPERSONATION);
    }
  }

  /* PRO: token data in localStorage */
  function detectTokenStorage() {
    try {
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i) || "";
        if (!/(token|auth|jwt|session|bearer)/i.test(key)) continue;
        const val = localStorage.getItem(key) || "";
        if (engine.isJwtLike(val) || val.length > 120) {
          state.signals.add(engine.SIGNALS.TOKEN_STORAGE_PATTERN);
          break;
        }
      }
    } catch { /* some pages block storage access */ }
  }

  /* PRO: HTTP page with password field — credentials sent in clear text */
  function detectHttpPassword() {
    if (location.protocol !== "http:") return;
    if (engine.isLocalhost(host())) return;
    if (document.querySelectorAll('input[type="password"]').length > 0) {
      state.signals.add(engine.SIGNALS.HTTP_PASSWORD);
    }
  }

  /* PRO: navigated from HTTPS to HTTP (context switch via referrer) */
  function detectHttpFromHttps() {
    if (location.protocol !== "http:") return;
    if (engine.isLocalhost(host())) return;
    try {
      const ref = document.referrer;
      if (ref && new URL(ref).protocol === "https:") {
        state.signals.add(engine.SIGNALS.HTTP_FROM_HTTPS);
      }
    } catch { /* invalid referrer URL */ }
  }

  /* PRO: lookalike / homograph / typosquat domain */
  function detectLookalikeDomain() {
    if (typeof engine.detectLookalikeDomain !== "function") return;
    const hasPassword = document.querySelectorAll('input[type="password"]').length > 0;
    const result = engine.detectLookalikeDomain(host(), hasPassword);
    if (result?.lookalike) state.signals.add(engine.SIGNALS.LOOKALIKE_DOMAIN);
  }

  /* PRO: regional scam script (India) — see detectRegionalScam in riskEngine.
     The field check runs first because it is cheap and rules out almost every
     page; the page text is only read when a card/UPI/OTP field exists. */
  function detectRegionalScam() {
    if (typeof engine.detectRegionalScam !== "function") return;
    if (state.signals.has(engine.SIGNALS.REGIONAL_SCAM)) return;
    /* Only fields that can hold typed data. A checklist item labelled "I
       entered my UPI or OTP details" (our own help page has one) is advice,
       not a request for them. */
    const fields = document.querySelectorAll(
      "input:not([type=hidden]):not([type=checkbox]):not([type=radio]):not([type=button]):not([type=submit]):not([type=reset]):not([type=image]):not([type=file]):not([type=range]):not([type=color]), select"
    );
    let sensitive = false;
    for (let i = 0; i < fields.length && i < 200 && !sensitive; i++) {
      const f = fields[i];
      const label = f.labels?.[0]?.textContent || "";
      sensitive = engine.isSensitiveFieldText(
        [f.name, f.id, f.placeholder, f.autocomplete, f.getAttribute("aria-label"), label].join(" ")
      );
    }
    if (!sensitive) return;
    const text = document.body?.innerText || "";
    if (engine.detectRegionalScam(host(), text, true)) state.signals.add(engine.SIGNALS.REGIONAL_SCAM);
  }

  /* PRO: fake virus / tech support scam page — see detectTechSupportScam in
     riskEngine. textContent is a cheap gate (no layout); the visible text is
     only read when the page prints a toll-free number at all. */
  function detectTechSupportScam() {
    if (typeof engine.detectTechSupportScam !== "function") return;
    if (state.signals.has(engine.SIGNALS.TECH_SUPPORT_SCAM)) return;
    const raw = document.body?.textContent || "";
    if (!engine.hasTollFreeNumber(raw.slice(0, 60000))) return;
    const text = document.body.innerText || "";
    if (engine.detectTechSupportScam(text, !!document.fullscreenElement)) {
      state.signals.add(engine.SIGNALS.TECH_SUPPORT_SCAM);
    }
  }

  /* PRO: "click Allow to prove you're not a robot" — see
     detectNotificationBait in riskEngine. Pages that can no longer ask
     (permission already granted or blocked) are skipped there. */
  function detectNotificationBait() {
    if (typeof engine.detectNotificationBait !== "function") return;
    if (state.signals.has(engine.SIGNALS.NOTIFICATION_BAIT)) return;
    const raw = document.body?.textContent || "";
    if (!/allow/i.test(raw.slice(0, 20000))) return;
    let permission = "default";
    try { permission = Notification.permission; } catch { /* no Notification API */ }
    if (engine.detectNotificationBait(document.body.innerText || "", permission)) {
      state.signals.add(engine.SIGNALS.NOTIFICATION_BAIT);
    }
  }

  /* PRO: fake online store — see detectFakeShop in riskEngine. A real shop
     links its contact, returns and privacy pages; many fakes leave them out. */
  const POLICY_LINK_RE = /contact|refund|return|privacy|terms|shipping|impressum|about/i;
  function detectFakeShop() {
    if (typeof engine.detectFakeShop !== "function") return;
    if (state.signals.has(engine.SIGNALS.FAKE_SHOP)) return;
    const raw = document.body?.textContent || "";
    if (!/%/.test(raw) || !/cart|bag|basket|buy|checkout|shop/i.test(raw)) return;
    let missingPolicies = true;
    for (const a of document.querySelectorAll("a[href]")) {
      if (a.protocol === "mailto:" || POLICY_LINK_RE.test(a.getAttribute("href") || "") ||
          POLICY_LINK_RE.test(a.textContent || "")) { missingPolicies = false; break; }
    }
    if (engine.detectFakeShop(host(), document.body.innerText || "", missingPolicies)) {
      state.signals.add(engine.SIGNALS.FAKE_SHOP);
    }
  }

  /* FREE: fake CAPTCHA that has you paste a command ("ClickFix") — see
     detectFakeCaptcha in riskEngine. The clipboard hook only goes into pages
     that mention a robot check or a keyboard shortcut at all, and the visible
     text is only read once the page copied something or names a shortcut. */
  const CAPTCHA_HOOK_GATE_RE = /robot|captcha|verif|human|camera|webcam|microphone|win(?:dows)?\s*(?:key\s*)?\+|ctrl\s*\+\s*v|⊞/i;
  const CAPTCHA_TEXT_GATE_RE = /win(?:dows)?[\s\S]{0,24}\+|ctrl\s*\+|⌘|⊞|paste|terminal|run (?:dialog|box)|address bar/i;
  let clipboardHookInjected = false;

  function injectClipboardHook() {
    if (clipboardHookInjected) return;
    clipboardHookInjected = true;
    try {
      const script = document.createElement("script");
      script.src = chrome.runtime.getURL("clipboardHook.js");
      script.dataset.nonce = hookNonce;
      (document.head || document.documentElement).appendChild(script);
      script.onload = () => script.remove();
    } catch { /* hook injection failed — the text-only rule still runs */ }
  }

  function detectFakeCaptcha() {
    if (typeof engine.detectFakeCaptcha !== "function") return;
    if (state.signals.has(engine.SIGNALS.FAKE_CAPTCHA)) return;
    const raw = (document.body?.textContent || "").slice(0, 30000);
    if (!state.clipboard && !CAPTCHA_HOOK_GATE_RE.test(raw)) return;
    injectClipboardHook();
    if (!engine.isShellCommand(state.clipboard) && !CAPTCHA_TEXT_GATE_RE.test(raw)) return;
    if (engine.detectFakeCaptcha(document.body?.innerText || "", state.clipboard)) {
      state.signals.add(engine.SIGNALS.FAKE_CAPTCHA);
    }
  }

  /* FREE: fake interview "fix your camera" — see detectFakeInterviewFix in
     riskEngine. Same clipboard hook as the fake CAPTCHA; the visible text is
     only read when the page talks about a camera or microphone at all. */
  const INTERVIEW_TEXT_GATE_RE = /camera|webcam|microphone|\bmic\b/i;

  function detectFakeInterviewFix() {
    if (typeof engine.detectFakeInterviewFix !== "function") return;
    if (state.signals.has(engine.SIGNALS.FAKE_INTERVIEW_FIX)) return;
    const raw = (document.body?.textContent || "").slice(0, 30000);
    if (!INTERVIEW_TEXT_GATE_RE.test(raw)) return;
    injectClipboardHook();
    if (engine.detectFakeInterviewFix(document.body?.innerText || "", state.clipboard)) {
      state.signals.add(engine.SIGNALS.FAKE_INTERVIEW_FIX);
    }
  }

  /* The page's links and buttons, for the checks that ask "is there a file
     to run here, and does any link go to the real vendor?" */
  function pageActions() {
    const actions = [];
    for (const el of document.querySelectorAll('a[href], button, [role="button"], input[type="button"], input[type="submit"]')) {
      if (actions.length >= 200) break;
      const href = el.tagName === "A" && /^(?:https?|blob|data):/i.test(el.href) ? el.href : "";
      actions.push({
        href,
        download: el.tagName === "A" && el.hasAttribute("download"),
        label: (el.textContent || el.value || el.getAttribute("aria-label") || "").trim().slice(0, 80)
      });
    }
    return actions;
  }

  /* PRO: fake browser update — see detectFakeBrowserUpdate in riskEngine.
     The page text is only read when it mentions a browser and an update. */
  function detectFakeBrowserUpdate() {
    if (typeof engine.detectFakeBrowserUpdate !== "function") return;
    if (state.signals.has(engine.SIGNALS.FAKE_BROWSER_UPDATE)) return;
    const raw = (document.body?.textContent || "").slice(0, 20000);
    if (!/update|upgrade|out of date|outdated/i.test(raw) || !/browser|chrome|edge|firefox|safari|opera/i.test(raw)) return;
    if (engine.detectFakeBrowserUpdate(host(), document.body.innerText || "", pageActions())) {
      state.signals.add(engine.SIGNALS.FAKE_BROWSER_UPDATE);
    }
  }

  /* PRO: fake meeting app download — see detectFakeMeetingApp in riskEngine.
     The page text is only read when it mentions a meeting and a download. */
  function detectFakeMeetingApp() {
    if (typeof engine.detectFakeMeetingApp !== "function") return;
    if (state.signals.has(engine.SIGNALS.FAKE_MEETING_APP)) return;
    const raw = (document.body?.textContent || "").slice(0, 20000);
    if (!/download|install|update/i.test(raw) || !/meeting|interview|call|webinar|zoom|teams/i.test(raw)) return;
    if (engine.detectFakeMeetingApp(host(), document.body.innerText || "", pageActions())) {
      state.signals.add(engine.SIGNALS.FAKE_MEETING_APP);
    }
  }

  /* PRO: browser-in-the-browser — see detectBrowserInBrowser in riskEngine.
     Only runs when the page text contains a sign-in address at all; then
     each text node holding one is walked up to its nearest fixed/absolute,
     popup-sized box, and that box is described to the engine. */
  const BITB_ADDRESS_RE = /https?:\/\/(?:accounts\.google|login\.microsoftonline|login\.live|appleid\.apple|(?:www\.)?facebook|github|discord|steamcommunity|(?:www\.)?paypal|login\.yahoo|x|twitter|(?:www\.)?linkedin|id\.atlassian|account\.live)\.com/i;
  function detectBrowserInBrowser() {
    if (typeof engine.detectBrowserInBrowser !== "function") return;
    if (state.signals.has(engine.SIGNALS.BROWSER_IN_BROWSER)) return;
    if (!BITB_ADDRESS_RE.test((document.body?.textContent || "").slice(0, 50000))) return;
    const boxes = [];
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    let node, seen = 0;
    while ((node = walker.nextNode()) && seen < 400) {
      seen++;
      if (!BITB_ADDRESS_RE.test(node.nodeValue || "")) continue;
      let el = node.parentElement;
      for (let depth = 0; el && depth < 8; depth++, el = el.parentElement) {
        const cs = getComputedStyle(el);
        if (cs.position !== "fixed" && cs.position !== "absolute") continue;
        const r = el.getBoundingClientRect();
        if (r.width < 240 || r.width > 1000 || r.height < 200 || cs.display === "none" || cs.visibility === "hidden") continue;
        boxes.push({
          text: (el.textContent || "").slice(0, 3000),
          hasLogin: !!el.querySelector('input[type="password"], input[type="email"], input[autocomplete="username"], input[name*="user" i], input[name*="email" i]'),
          hasFrame: !!el.querySelector("iframe")
        });
        break;
      }
      if (boxes.length >= 5) break;
    }
    if (boxes.length && engine.detectBrowserInBrowser(host(), boxes)) {
      state.signals.add(engine.SIGNALS.BROWSER_IN_BROWSER);
    }
  }

  /* PRO: device-code phishing — see detectDeviceCodePhish in riskEngine.
     The page text is only read when it names a device sign-in address. */
  function detectDeviceCodePhish() {
    if (typeof engine.detectDeviceCodePhish !== "function") return;
    if (state.signals.has(engine.SIGNALS.DEVICE_CODE_PHISH)) return;
    const raw = (document.body?.textContent || "").slice(0, 20000);
    if (!/devicelogin|deviceauth|login\/device|google\.com\/device/i.test(raw)) return;
    if (engine.detectDeviceCodePhish(host(), document.body.innerText || "")) {
      state.signals.add(engine.SIGNALS.DEVICE_CODE_PHISH);
    }
  }

  /* PRO: secret leak scanner — hardcoded API keys in page source + same-origin bundles */
  function applySecretResult(result) {
    if (!result || result.skipped || !result.found) return;
    if (result.secrets.some((s) => !s.isPrivateKey)) {
      state.signals.add(engine.SIGNALS.HARDCODED_SECRET);
    }
    if (result.hasPrivateKey) {
      state.signals.add(engine.SIGNALS.PRIVATE_KEY_EXPOSED);
    }
  }

  async function detectSecretLeaks() {
    const scanner = window.PhishCleanSecretScanner;
    if (!scanner) return;
    /* Inline scan is synchronous and fast. */
    applySecretResult(scanner.scanPageSource());
    /* External same-origin bundles are fetched asynchronously; re-alert if they
       surface anything the inline pass missed. */
    if (typeof scanner.scanExternalScripts === "function") {
      try {
        const before = state.signals.size;
        applySecretResult(await scanner.scanExternalScripts());
        if (state.signals.size > before) await maybeAlert();
      } catch { /* ignore external scan errors */ }
    }
  }

  /* PRO: intercept fetch/XHR Authorization headers to third-party domains */
  /* Not crypto.randomUUID(): it only exists in secure contexts, so on a plain
     http:// page it threw here and took every check on the page down with it
     — the pages where the HTTP-password checks matter most. */
  const hookNonce = Array.from(crypto.getRandomValues(new Uint8Array(16)),
    (b) => b.toString(16).padStart(2, "0")).join("");

  function injectNetworkHook() {
    try {
      const script = document.createElement("script");
      script.src = chrome.runtime.getURL("networkHook.js");
      script.dataset.nonce = hookNonce;
      (document.head || document.documentElement).appendChild(script);
      script.onload = () => script.remove();
    } catch { /* network hook injection failed */ }
  }

  /* ── cooldown & fingerprinting ── */
  function fingerprint(reasons) {
    return `${host()}${location.pathname}::${reasons.slice().sort().join("|")}`;
  }

  function inCooldown(fp) {
    return state.lastFingerprint === fp && Date.now() - state.lastAlertAt < COOLDOWN_MS;
  }

  /* ── shadow DOM modal ── */
  function showModal(score, reasons, level) {
    if (state.modalShown) return;
    state.modalShown = true;
    /* Remember focus so we can restore it when the dialog is dismissed. */
    const lastFocused = document.activeElement;

    /* Tell background to count this block and log threat details */
    chrome.runtime.sendMessage({
      type: "INCREMENT_BLOCK_COUNT",
      threat: {
        domain: location.hostname,
        url: location.href.substring(0, 200),
        score: score,
        level: level,
        reasons: reasons,
        signals: [...state.signals],
        occurred_at: new Date().toISOString()
      }
    }).catch(() => {});

    const wrapper = document.createElement("div");
    wrapper.id = "phishclean-root";
    const shadow = wrapper.attachShadow({ mode: "closed" });

    const levelColor = level === "danger" ? "#ef4444" : level === "warning" ? "#f59e0b" : "#22c55e";
    const reported = state.signals.has(engine.SIGNALS.KNOWN_PHISHING);
    const fakeAlert = state.signals.has(engine.SIGNALS.TECH_SUPPORT_SCAM);
    const allowBait = state.signals.has(engine.SIGNALS.NOTIFICATION_BAIT);
    const fakeShop = state.signals.has(engine.SIGNALS.FAKE_SHOP);
    const fakeCaptcha = state.signals.has(engine.SIGNALS.FAKE_CAPTCHA);
    const fakeUpdate = state.signals.has(engine.SIGNALS.FAKE_BROWSER_UPDATE);
    const skimmer = state.signals.has(engine.SIGNALS.CARD_SKIMMER);
    const interviewFix = state.signals.has(engine.SIGNALS.FAKE_INTERVIEW_FIX);
    const meetingApp = state.signals.has(engine.SIGNALS.FAKE_MEETING_APP);
    const bitb = state.signals.has(engine.SIGNALS.BROWSER_IN_BROWSER);
    const deviceCode = state.signals.has(engine.SIGNALS.DEVICE_CODE_PHISH);
    const title = skimmer ? "Your card number was sent to another site"
      : deviceCode ? "Don't enter that code"
      : bitb ? "Fake sign-in window"
      : interviewFix ? "Fake interview: don't run that fix"
      : fakeCaptcha ? "Don't paste that command"
      : meetingApp ? "Fake meeting app"
      : fakeUpdate ? "Fake browser update"
      : fakeAlert ? "Fake virus warning"
        : reported ? "Reported phishing site"
          : allowBait ? "Don't click Allow"
            : fakeShop ? "This may be a fake shop"
              : "Potential Risk Detected";
    const subtitle = skimmer
      ? `This checkout sent the card number you typed to ${state.skimmerHost}, which is not a payment company. Don't submit the form. If you already paid, call your bank and ask them to block the card.`
      : deviceCode
      ? "Entering this code at Microsoft's, GitHub's or Google's device page would sign the attacker's device into your account, no password needed. Close the tab. If you already entered it, sign out of all sessions and change your password."
      : bitb
      ? "This sign-in box is drawn by the page, not opened by your browser, so the address in it proves nothing. Don't type anything into it. Go to the real site by typing its address yourself."
      : interviewFix
      ? "Real interview platforms never ask you to paste commands to fix your camera. Don't open Terminal, PowerShell or the Run box. Close the tab and stop talking to this recruiter; whatever it copied stays harmless until you run it."
      : meetingApp
      ? "Zoom, Teams and Google Meet invitations open in the browser or on the maker's own site. Don't open this file. If you already ran it, disconnect from the internet and treat the computer as compromised."
      : fakeUpdate
      ? "Your browser updates itself; no website needs you to download an update. Don't open the file. If you already ran it, disconnect from the internet and run a full malware scan."
      : fakeCaptcha
      ?"This is not a real CAPTCHA. Don't press Windows+R, paste or press Enter anywhere this page told you to. Close the tab; whatever it copied stays harmless until you run it."
      : fakeAlert
      ? "Nothing on your computer is infected. This page is pretending to be a security alert, and the number on it goes to scammers. Don't call it."
      : reported
        ? "This site has been reported for stealing passwords or payment details."
        : allowBait
          ? "There is nothing to verify. Allow would let this site push spam and fake virus alerts to your desktop. Click Block or close the prompt."
          : fakeShop
            ? "Check the brand's official website before you pay. If you already paid by card, call your bank and ask for a chargeback."
            : "PhishClean found signs this page may not be safe.";
    /* A scam page in fullscreen would hide this warning behind itself. */
    if (document.fullscreenElement) document.exitFullscreen?.().catch(() => {});
    const licenseNote = reported
      ? "Caught by the reported-phishing list, which stays free. New phishing pages often go unreported for days; the lookalike-domain and fake-login checks that catch those are paused on this install."
      : interviewFix
      ? "Caught by the fake interview check, which stays free. Twenty-two more &mdash; fake meeting apps, lookalike domains, fake brand logins, leaked passwords &mdash; and the coding-test repo check are paused on this install."
      : fakeCaptcha
      ? "Caught by the fake CAPTCHA check, which stays free. Twenty-two more &mdash; lookalike domains, fake brand logins, fake shops, fake virus warnings, leaked passwords &mdash; are paused on this install."
      : "Caught by the checks that never expire. Twenty-two more &mdash; lookalike domains, fake brand logins, fake shops, fake virus warnings, leaked passwords &mdash; are paused on this install.";

    shadow.innerHTML = `
      <style>
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        :host { all: initial; }
        .overlay {
          position: fixed; inset: 0; z-index: 2147483647;
          background: rgba(0,0,0,0.6); backdrop-filter: blur(4px);
          display: flex; align-items: center; justify-content: center;
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
          animation: fadeIn 0.2s ease-out;
        }
        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
        @keyframes slideUp { from { opacity: 0; transform: translateY(16px); } to { opacity: 1; transform: translateY(0); } }
        .modal {
          width: min(520px, 92vw); background: #0f1117; color: #e2e8f0;
          border-radius: 16px; border: 1px solid #1e293b;
          padding: 28px; box-shadow: 0 24px 48px rgba(0,0,0,0.4);
          animation: slideUp 0.25s ease-out;
        }
        .header { display: flex; align-items: center; gap: 14px; margin-bottom: 20px; }
        .shield { width: 40px; height: 40px; border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 20px; }
        .shield.danger { background: rgba(239,68,68,0.15); }
        .shield.warning { background: rgba(245,158,11,0.15); }
        .shield.safe { background: rgba(34,197,94,0.15); }
        .title { font-size: 18px; font-weight: 600; color: #f1f5f9; }
        .subtitle { font-size: 13px; color: #94a3b8; margin-top: 2px; }

        .score-row { display: flex; align-items: baseline; gap: 8px; margin-bottom: 18px; }
        .score-num { font-size: 48px; font-weight: 700; line-height: 1; }
        .score-label { font-size: 13px; color: #64748b; }

        .reasons { list-style: none; margin-bottom: 20px; }
        .reasons li { padding: 8px 12px; border-radius: 8px; background: #1e293b; margin-bottom: 6px; font-size: 13px; color: #cbd5e1; line-height: 1.5; }
        .reasons li::before { content: "\\26A0\\FE0F"; margin-right: 8px; }

        .license-note { font-size: 12px; color: #f59e0b; margin-bottom: 16px; padding: 8px 12px; background: rgba(245,158,11,0.08); border-radius: 8px; border: 1px solid rgba(245,158,11,0.15); }
        .license-note.hidden { display: none; }

        .actions { display: flex; gap: 8px; flex-wrap: wrap; }
        .btn { border: none; border-radius: 8px; padding: 10px 16px; font-size: 13px; font-weight: 500; cursor: pointer; transition: background 0.15s; }
        .btn-back { background: #dc2626; color: #fff; }
        .btn-back:hover { background: #b91c1c; }
        .btn-ignore { background: #1e293b; color: #94a3b8; border: 1px solid #334155; }
        .btn-ignore:hover { background: #334155; color: #e2e8f0; }
        .btn-whitelist { background: #1e293b; color: #94a3b8; border: 1px solid #334155; }
        .btn-whitelist:hover { background: #334155; color: #e2e8f0; }
        .btn-upgrade { background: #2563eb; color: #fff; }
        .btn-upgrade:hover { background: #1d4ed8; }
        .btn-upgrade.hidden { display: none; }

        .help-link { display: block; margin-top: 16px; font-size: 13px; color: #93c5fd; text-decoration: none; }
        .help-link:hover { text-decoration: underline; }
        .fp { margin-top: 10px; font-size: 12px; color: #64748b; }
        .fp a { color: #94a3b8; }
        .fp-confirm { margin-top: 10px; font-size: 12px; color: #cbd5e1; background: #111827; border: 1px solid #1e293b; border-radius: 8px; padding: 10px 12px; line-height: 1.5; }
        .fp-confirm .fp-actions { margin-top: 8px; display: flex; gap: 8px; }
        .fp-confirm button { font: inherit; font-size: 12px; padding: 5px 12px; border-radius: 6px; border: 1px solid #334155; background: #1e293b; color: #e2e8f0; cursor: pointer; }
        .fp-confirm button.fp-send { background: #2563eb; border-color: #2563eb; color: #fff; }
        .hidden { display: none !important; }
        .privacy { margin-top: 16px; font-size: 11px; color: #475569; text-align: center; }
        .privacy span { color: #22c55e; }
      </style>

      <div class="overlay">
        <div class="modal" role="dialog" aria-modal="true" aria-label="Security warning">
          <div class="header">
            <svg width="36" height="40" viewBox="0 0 32 36" fill="none" style="flex-shrink:0"><path d="M16 1.5L3 7v10.5c0 9 5.5 16.5 13 18.5 7.5-2 13-9.5 13-18.5V7L16 1.5z" fill="${level === 'danger' ? '#dc2626' : '#f59e0b'}"/><path d="M16 4.5L6 9v8.5c0 7.5 4.5 13.5 10 15.5 5.5-2 10-8 10-15.5V9L16 4.5z" fill="${level === 'danger' ? '#b91c1c' : '#d97706'}"/><path d="M11 18.5l3.5 3.5 7-7" stroke="#fff" stroke-width="2.8" stroke-linecap="round" stroke-linejoin="round" opacity="0.9"/></svg>
            <div>
              <div class="title">${title}</div>
              <div class="subtitle">${subtitle}</div>
            </div>
          </div>

          <div class="score-row">
            <div class="score-num" style="color:${levelColor}">${score}</div>
            <div class="score-label">risk score</div>
          </div>

          <ul class="reasons" id="reasons"></ul>

          <div class="license-note ${state.proEnabled ? "hidden" : ""}" id="license-note">
            ${licenseNote}
          </div>

          <div class="actions">
            <button class="btn btn-back" id="btn-back">Go Back</button>
            <button class="btn btn-ignore" id="btn-ignore">Ignore Once</button>
            <button class="btn btn-whitelist" id="btn-wl">Trust this domain</button>
            <button class="btn btn-upgrade ${state.proEnabled ? "hidden" : ""}" id="btn-up">Restore the other 24 checks</button>
          </div>

          ${interviewFix || meetingApp
            ? `<a class="help-link" id="btn-help" href="https://www.phishclean.com/blog/fake-job-interview-coding-test-malware?utm_source=extension&amp;utm_medium=warning#already-ran" target="_blank" rel="noopener">${meetingApp ? "Already opened the file?" : "Already ran the command?"} What to do now &rarr;</a>`
            : fakeCaptcha || fakeUpdate
            ? `<a class="help-link" id="btn-help" href="https://www.phishclean.com/blog/captcha-told-me-to-press-win-r-is-it-a-virus?utm_source=extension&amp;utm_medium=warning#already-ran" target="_blank" rel="noopener">${fakeUpdate ? "Already opened the file?" : "Already pasted it and pressed Enter?"} What to do now &rarr;</a>`
            : fakeAlert
            ? `<a class="help-link" id="btn-help" href="https://www.phishclean.com/blog/how-to-remove-fake-virus-popup?utm_source=extension&amp;utm_medium=warning#already-called" target="_blank" rel="noopener">Already called the number or let someone onto your computer? What to do now &rarr;</a>`
            : `<a class="help-link" id="btn-help" href="https://www.phishclean.com/help/clicked-a-phishing-link?utm_source=extension&amp;utm_medium=warning" target="_blank" rel="noopener">Already typed a password or card details here? What to do now &rarr;</a>`}

          <p class="fp" id="fp-row">Wrong warning? <a href="#" id="btn-fp">Tell PhishClean</a></p>
          <div class="fp-confirm hidden" id="fp-confirm">
            <div id="fp-text"></div>
            <div class="fp-actions"><button class="fp-send" id="fp-send">Send</button><button id="fp-cancel">Cancel</button></div>
          </div>

          <p class="privacy"><span>&#x2713;</span> All analysis runs on your device. Nothing is sent unless you report a wrong warning.</p>
        </div>
      </div>
    `;

    /* Populate reasons */
    const list = shadow.getElementById("reasons");
    reasons.forEach((r) => {
      const li = document.createElement("li");
      li.textContent = r;
      list.appendChild(li);
    });

    /* Button handlers */
    /* "Go Back" must always leave the flagged site. history.back() alone does
       not: a page opened in a new tab has no history, and a back step that is
       only a #hash or pushState change keeps this same document on screen.
       If we are still here shortly after going back, let the background send
       the tab to a new tab page instead. */
    shadow.getElementById("btn-back").onclick = () => {
      wrapper.remove();
      const origin = location.origin;
      const leave = () => chrome.runtime.sendMessage({ type: "LEAVE_PAGE" }).catch(() => {});
      if (history.length <= 1) return leave();
      history.back();
      setTimeout(() => { if (location.origin === origin) leave(); }, 700);
    };
    shadow.getElementById("btn-ignore").onclick = () => {
      state.ignoreOnce = true;
      sessionStorage.setItem(`phishclean_ignore_${host()}`, "1");
      wrapper.remove();
      state.modalShown = false;
    };
    shadow.getElementById("btn-wl").onclick = async () => {
      await addToWhitelist();
      const toast = document.createElement("div");
      toast.textContent = "\u2713 " + host() + " added to trusted domains";
      toast.style.cssText = "position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background:#0f1117;color:#4ade80;padding:10px 20px;border-radius:8px;font-size:13px;z-index:2147483647;border:1px solid #1e293b;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;transition:opacity 0.3s;";
      document.documentElement.appendChild(toast);
      setTimeout(() => { toast.style.opacity = "0"; }, 2700);
      setTimeout(() => { toast.remove(); }, 3000);
      wrapper.remove();
      state.modalShown = false;
    };
    shadow.getElementById("btn-up").onclick = () => {
      chrome.runtime.sendMessage({ type: "OPEN_PAYMENT" });
    };
    /* "Wrong warning?": says exactly what would be sent (this domain and the
       check names, nothing from the page), and sends only after Send. */
    const fpConfirm = shadow.getElementById("fp-confirm");
    shadow.getElementById("btn-fp").onclick = (e) => {
      e.preventDefault();
      shadow.getElementById("fp-text").textContent =
        `Send PhishClean this site's address (${host()}) and the names of the checks that fired, so the warning can be fixed? Nothing from the page itself is sent.`;
      fpConfirm.classList.remove("hidden");
      shadow.getElementById("fp-row").classList.add("hidden");
    };
    shadow.getElementById("fp-cancel").onclick = () => {
      fpConfirm.classList.add("hidden");
      shadow.getElementById("fp-row").classList.remove("hidden");
    };
    shadow.getElementById("fp-send").onclick = async () => {
      const resp = await chrome.runtime.sendMessage({ type: "REPORT_FALSE_POSITIVE", domain: host(), signals: [...state.signals] }).catch(() => null);
      fpConfirm.textContent = resp?.ok
        ? "Thanks, sent. If you trust this site, \"Trust this domain\" stops warnings here."
        : "Couldn't send right now. You can still use \"Trust this domain\".";
    };

    /* ── accessibility: focus management, Escape to dismiss, Tab trap ── */
    const dismiss = () => {
      state.ignoreOnce = true;
      sessionStorage.setItem(`phishclean_ignore_${host()}`, "1");
      wrapper.remove();
      state.modalShown = false;
      if (lastFocused && typeof lastFocused.focus === "function") {
        try { lastFocused.focus(); } catch { /* element gone */ }
      }
    };

    const overlay = shadow.querySelector(".overlay");
    const focusables = Array.from(shadow.querySelectorAll("button:not(.hidden), a[href]"));
    overlay.addEventListener("keydown", (e) => {
      if (e.key === "Escape") {
        e.preventDefault();
        dismiss();
        return;
      }
      if (e.key === "Tab" && focusables.length) {
        const first = focusables[0];
        const last = focusables[focusables.length - 1];
        const active = shadow.activeElement;
        if (e.shiftKey && active === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && active === last) {
          e.preventDefault();
          first.focus();
        }
      }
    });

    document.documentElement.appendChild(wrapper);
    /* Move focus into the dialog so keyboard/AT users land on the safe default. */
    (shadow.getElementById("btn-back") || focusables[0])?.focus();
  }

  /* ── main alert logic ── */
  async function maybeAlert() {
    /* A background message (HTTPS downgrade, auth header) can arrive before
       run() has read the trusted lists; decide only once they are loaded. */
    await stateLoaded();
    if (isWhitelisted() || state.ignoreOnce) return;

    const result = engine.scoreSignals(state.signals, state.proEnabled);
    if (!result.shouldAlert) return;

    const fp = fingerprint(result.reasons);
    if (inCooldown(fp)) return;

    state.lastFingerprint = fp;
    state.lastAlertAt = Date.now();

    showModal(result.score, result.reasons, result.level);
  }

  /* ── listen for background.js webRequest signal ── */
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (engine.isTrustedDomain(host())) return true;

    if (msg?.type === "AUTH_HEADER_THIRD_PARTY") {
      state.signals.add(engine.SIGNALS.AUTH_HEADER_THIRD_PARTY);
      maybeAlert();
      sendResponse({ received: true });
    }
    if (msg?.type === "HTTPS_DOWNGRADE") {
      state.signals.add(engine.SIGNALS.HTTPS_DOWNGRADE);
      maybeAlert();
      sendResponse({ received: true });
    }
    return true;
  });

  /* ── listen for injected page script signal (nonce-authenticated) ── */
  window.addEventListener("message", (event) => {
    if (event.source !== window) return;
    if (event.data?.source !== "phishclean") return;
    if (event.data?.nonce !== hookNonce) return;
    if (event.data?.type === "AUTH_HEADER_THIRD_PARTY") {
      state.signals.add(engine.SIGNALS.AUTH_HEADER_THIRD_PARTY);
      maybeAlert();
    }
    /* The hook saw the typed card number leave the page; only the host
       comes with the message. It ends up in the warning, so it must be a
       plain hostname whatever the page posted. */
    if (event.data?.type === "CARD_SENT" && /^[a-z0-9.-]{1,253}$/i.test(event.data.to || "")) {
      if (!engine.isExpectedCardDestination(host(), event.data.to)) {
        state.skimmerHost = event.data.to.toLowerCase();
        state.signals.add(engine.SIGNALS.CARD_SKIMMER);
        maybeAlert();
      }
    }
    /* The fake CAPTCHA usually copies on the checkbox click and shows the
       "press Windows+R" steps a moment later, often by unhiding them, which
       the DOM observer (child changes only) does not see. Check again then. */
    if (event.data?.type === "CLIPBOARD_WRITE" && typeof event.data.text === "string") {
      state.clipboard = event.data.text;
      const check = () => {
        if (state.modalShown) return;
        try { detectFakeCaptcha(); } catch { /* skip */ }
        try { detectFakeInterviewFix(); } catch { /* skip */ }
        maybeAlert();
      };
      check();
      setTimeout(check, 1000);
      setTimeout(check, 3000);
    }
  });

  /* ── detectors ──
     FREE runs on every page forever, with or without an account. PRO runs
     during the 7-day trial and on a paid plan. The split mirrors
     FREE_SIGNALS in riskEngine.js, which already drops pro signals from the
     score when proEnabled is false — running the pro detectors for a free
     user would burn the work and discard the result, and two of them
     (detectTokenStorage, detectBacklinkImpersonation) are the expensive
     ones. */
  const FREE_DETECTORS = [detectPasswordFields, detectDomainMismatch, detectFakeCaptcha, detectFakeInterviewFix];

  const PRO_DETECTORS = [
    detectHiddenIframes, detectJwtInUrl, detectSuspiciousQuery,
    detectCredentialInUrl,
    detectVisualAnomalies, detectBacklinkImpersonation, detectTokenStorage,
    detectHttpPassword, detectHttpFromHttps, detectLookalikeDomain,
    detectRegionalScam, detectTechSupportScam, detectNotificationBait,
    detectFakeShop, detectFakeBrowserUpdate, detectFakeMeetingApp,
    detectBrowserInBrowser, detectDeviceCodePhish
  ];

  function runSyncDetectors() {
    for (const d of FREE_DETECTORS) { try { d(); } catch { /* skip */ } }
    if (!state.proEnabled) return;
    for (const d of PRO_DETECTORS) { try { d(); } catch { /* skip */ } }
  }

  /* ── live re-scanning: DOM mutations + SPA navigations ── */
  let observer = null;
  let rescanTimer = 0;
  let lastUrl = location.href;

  function scheduleRescan() {
    clearTimeout(rescanTimer);
    rescanTimer = setTimeout(() => { rescanNow(); }, 500);
  }

  async function rescanNow() {
    /* SPA route change — treat as a fresh page and reset accumulated state. */
    if (location.href !== lastUrl) {
      lastUrl = location.href;
      if (engine.isTrustedDomain(host())) return;
      state.signals = new Set();
      state.clipboard = "";
      state.skimmerHost = "";
      state.modalShown = false;
      state.lastFingerprint = "";
      state.ignoreOnce = sessionStorage.getItem(`phishclean_ignore_${host()}`) === "1";
    }
    if (state.modalShown) return;            /* a modal is already up */
    if (isWhitelisted() || state.ignoreOnce) return;
    runSyncDetectors();
    await maybeAlert();
  }

  function observeChanges() {
    if (observer) return;
    try {
      observer = new MutationObserver(() => scheduleRescan());
      observer.observe(document.documentElement, { childList: true, subtree: true });
    } catch { /* observation unavailable */ }
    window.addEventListener("popstate", scheduleRescan);
    window.addEventListener("hashchange", scheduleRescan);
    /* Scam pages grab fullscreen to hide the address bar and close button. */
    document.addEventListener("fullscreenchange", scheduleRescan);
  }

  /* ── run all detectors ── */
  async function run() {
    try {
      if (engine.isTrustedDomain(host())) {
        /* Trusted platforms skip the heuristics, but some of them host other
           people's pages (github.io, amazonaws.com), and one of those can be
           on the reported list. The feed already leaves out the platforms'
           own domains, so only a specific reported host warns here. */
        await stateLoaded();
        if (isWhitelisted()) return;
        await detectReportedPhishing();
        await maybeAlert();
        return;
      }

      await stateLoaded();
      if (isWhitelisted()) return;

      const reported = detectReportedPhishing();
      runSyncDetectors();
      await reported;
      /* Counted for the badge and weekly report only after the early returns
         above, so trusted and whitelisted pages — which are not scanned — are
         not claimed as checked. */
      chrome.runtime.sendMessage({ type: "PAGE_SCANNED" }).catch(() => {});

      /* Both of these feed pro-only signals: the network hook reports
         third-party Authorization headers, and the scanner reports hardcoded
         secrets and private keys. Skip them on the free tier — the hook
         injects a script into the page and the scanner fetches same-origin
         bundles, neither of which is worth doing to discard the result. */
      if (state.proEnabled) {
        injectNetworkHook();
        detectSecretLeaks();
      }

      await maybeAlert();
      observeChanges();
    } catch { /* detection error — fail silently */ }
  }

  run();
})();
