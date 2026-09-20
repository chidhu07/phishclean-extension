/* PhishClean content script
   All detection runs 100% locally. No page data is ever sent to any server.
*/
(() => {
  const engine = window.PhishCleanRiskEngine;
  if (!engine) return;

  const WHITELIST_KEY = "phishclean_whitelist_domains";
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
    modalShown: false
  };

  const host = () => location.hostname.toLowerCase();

  /* ── load stored whitelist + license ── */
  async function loadLocalState() {
    const data = await chrome.storage.local.get([WHITELIST_KEY, LICENSE_KEY]);
    state.whitelist = data[WHITELIST_KEY] || [];
    const license = data[LICENSE_KEY];
    /* Detection always runs. The licence decides how much of it: without a
       trial or a plan we still run the two free signals, which is why
       serviceEnabled is no longer tied to proEnabled. A missing licence means
       we have not reached the server yet — that must not disable protection,
       so it degrades to the free tier rather than to nothing. */
    state.proEnabled = !!(license?.trial_active || license?.is_paid);
    state.serviceEnabled = true;
    state.ignoreOnce = sessionStorage.getItem(`phishclean_ignore_${host()}`) === "1";
  }

  function isWhitelisted() {
    return state.whitelist.includes(host());
  }

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
    collect("link[href]", "href", "stylesheet");
    collect("form[action]", "action", "form_action");
    collect("iframe[src]", "src", "iframe");

    const result = engine.analyzeBacklinkRefs(location.href, refs, document.querySelectorAll('input[type="password"]').length > 0);
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
  const hookNonce = crypto.randomUUID();

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

        .privacy { margin-top: 16px; font-size: 11px; color: #475569; text-align: center; }
        .privacy span { color: #22c55e; }
      </style>

      <div class="overlay">
        <div class="modal" role="dialog" aria-modal="true" aria-label="Security warning">
          <div class="header">
            <svg width="36" height="40" viewBox="0 0 32 36" fill="none" style="flex-shrink:0"><path d="M16 1.5L3 7v10.5c0 9 5.5 16.5 13 18.5 7.5-2 13-9.5 13-18.5V7L16 1.5z" fill="${level === 'danger' ? '#dc2626' : '#f59e0b'}"/><path d="M16 4.5L6 9v8.5c0 7.5 4.5 13.5 10 15.5 5.5-2 10-8 10-15.5V9L16 4.5z" fill="${level === 'danger' ? '#b91c1c' : '#d97706'}"/><path d="M11 18.5l3.5 3.5 7-7" stroke="#fff" stroke-width="2.8" stroke-linecap="round" stroke-linejoin="round" opacity="0.9"/></svg>
            <div>
              <div class="title">Potential Risk Detected</div>
              <div class="subtitle">PhishClean found signs this page may not be safe.</div>
            </div>
          </div>

          <div class="score-row">
            <div class="score-num" style="color:${levelColor}">${score}</div>
            <div class="score-label">risk score</div>
          </div>

          <ul class="reasons" id="reasons"></ul>

          <div class="license-note ${state.proEnabled ? "hidden" : ""}" id="license-note">
            Caught by the two checks that never expire. Fifteen more &mdash; token and secret leaks, lookalike domains, HTTPS downgrades &mdash; are paused on this install.
          </div>

          <div class="actions">
            <button class="btn btn-back" id="btn-back">Go Back</button>
            <button class="btn btn-ignore" id="btn-ignore">Ignore Once</button>
            <button class="btn btn-whitelist" id="btn-wl">Trust this domain</button>
            <button class="btn btn-upgrade ${state.proEnabled ? "hidden" : ""}" id="btn-up">Restore the other 15 checks</button>
          </div>

          <p class="privacy"><span>&#x2713;</span> All analysis runs on your device. No browsing data is sent to any server.</p>
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
    shadow.getElementById("btn-back").onclick = () => { wrapper.remove(); history.back(); };
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
    const focusables = Array.from(shadow.querySelectorAll("button:not(.hidden)"));
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
  });

  /* ── detectors ──
     FREE runs on every page forever, with or without an account. PRO runs
     during the 15-day trial and on a paid plan. The split mirrors
     FREE_SIGNALS in riskEngine.js, which already drops pro signals from the
     score when proEnabled is false — running the pro detectors for a free
     user would burn the work and discard the result, and two of them
     (detectTokenStorage, detectBacklinkImpersonation) are the expensive
     ones. */
  const FREE_DETECTORS = [detectPasswordFields, detectDomainMismatch];

  const PRO_DETECTORS = [
    detectHiddenIframes, detectJwtInUrl, detectSuspiciousQuery,
    detectCredentialInUrl,
    detectVisualAnomalies, detectBacklinkImpersonation, detectTokenStorage,
    detectHttpPassword, detectHttpFromHttps, detectLookalikeDomain
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
  }

  /* ── run all detectors ── */
  async function run() {
    try {
      if (engine.isTrustedDomain(host())) return;

      await loadLocalState();
      if (isWhitelisted()) return;

      runSyncDetectors();

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
