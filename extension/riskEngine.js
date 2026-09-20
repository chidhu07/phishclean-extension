/* PhishClean risk scoring engine
   100% local — no network calls. Modular signal detection + weighted scoring.
   To add a new heuristic: add to SIGNALS, WEIGHTS, REASON_TEXT, then detect in contentScript.
*/
(() => {
  const SIGNALS = {
    PASSWORD_FIELD: "PASSWORD_FIELD",
    DOMAIN_MISMATCH: "DOMAIN_MISMATCH",
    HIDDEN_IFRAME: "HIDDEN_IFRAME",
    JWT_URL: "JWT_URL",
    AUTH_HEADER_THIRD_PARTY: "AUTH_HEADER_THIRD_PARTY",
    QUERY_TOKEN_PATTERN: "QUERY_TOKEN_PATTERN",
    CREDENTIAL_IN_URL: "CREDENTIAL_IN_URL",
    VISUAL_ANOMALY: "VISUAL_ANOMALY",
    SUSPICIOUS_LOGIN_REGION: "SUSPICIOUS_LOGIN_REGION",
    TOKEN_STORAGE_PATTERN: "TOKEN_STORAGE_PATTERN",
    HTTP_PASSWORD: "HTTP_PASSWORD",
    HTTPS_DOWNGRADE: "HTTPS_DOWNGRADE",
    HTTP_FROM_HTTPS: "HTTP_FROM_HTTPS",
    BACKLINK_IMPERSONATION: "BACKLINK_IMPERSONATION",
    HARDCODED_SECRET: "HARDCODED_SECRET",
    PRIVATE_KEY_EXPOSED: "PRIVATE_KEY_EXPOSED",
    LOOKALIKE_DOMAIN: "LOOKALIKE_DOMAIN"
  };

  const WEIGHTS = {
    PASSWORD_FIELD: 20,
    DOMAIN_MISMATCH: 30,
    HIDDEN_IFRAME: 15,
    JWT_URL: 35,
    AUTH_HEADER_THIRD_PARTY: 30,
    QUERY_TOKEN_PATTERN: 20,
    CREDENTIAL_IN_URL: 40,
    VISUAL_ANOMALY: 10,
    SUSPICIOUS_LOGIN_REGION: 10,
    TOKEN_STORAGE_PATTERN: 10,
    HTTP_PASSWORD: 15,
    HTTPS_DOWNGRADE: 25,
    HTTP_FROM_HTTPS: 10,
    BACKLINK_IMPERSONATION: 35,
    HARDCODED_SECRET: 30,
    PRIVATE_KEY_EXPOSED: 40,
    LOOKALIKE_DOMAIN: 35
  };

  const THRESHOLD = 40;

  /* Free tier only gets basic signals; Pro unlocks the rest */
  const FREE_SIGNALS = new Set([SIGNALS.PASSWORD_FIELD, SIGNALS.DOMAIN_MISMATCH]);

  const REASON_TEXT = {
    PASSWORD_FIELD: "This page contains a password field.",
    DOMAIN_MISMATCH: "The login form submits data to a different domain.",
    HIDDEN_IFRAME: "A hidden or off-screen iframe was detected — possible credential capture.",
    JWT_URL: "A token-like value (JWT) appears directly in the URL.",
    AUTH_HEADER_THIRD_PARTY: "Authorization credentials are being sent to a third-party domain.",
    QUERY_TOKEN_PATTERN: "Sensitive parameters (token, auth, session, key) found in the URL.",
    CREDENTIAL_IN_URL: "A password appears directly in the URL — credentials in a URL leak into browser history, server logs, and referrer headers.",
    VISUAL_ANOMALY: "The login form structure looks unusual.",
    SUSPICIOUS_LOGIN_REGION: "Login area layout doesn't match typical patterns.",
    TOKEN_STORAGE_PATTERN: "Sensitive token data is exposed in browser storage.",
    HTTP_PASSWORD: "This page uses an unencrypted connection (HTTP) with a password field — credentials could be intercepted.",
    HTTPS_DOWNGRADE: "You were redirected from a secure (HTTPS) page to an insecure (HTTP) page — possible downgrade attack.",
    HTTP_FROM_HTTPS: "You navigated from a secure (HTTPS) site to an insecure (HTTP) page.",
    BACKLINK_IMPERSONATION: "This page borrows trust by linking to real brand assets or policy pages from an unrelated domain.",
    HARDCODED_SECRET: "Hardcoded API keys or secrets were found in this page's source code.",
    PRIVATE_KEY_EXPOSED: "A cryptographic private key is exposed in this page — critical security risk.",
    LOOKALIKE_DOMAIN: "This domain closely imitates a well-known brand — likely a lookalike (typosquatting or homograph) phishing site."
  };

  /* JWT pattern: three base64url segments separated by dots */
  const JWT_RE = /[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/;

  /* Query param names that likely carry auth tokens */
  const SUSPICIOUS_PARAMS = /^(token|auth|session|jwt|bearer|access|key|secret|api_key|apikey)$/i;

  /* Query param names that carry a raw login password — these must never be in
     a URL. Kept conservative (password family only) to avoid false positives on
     benign params like ?email= or ?user= that legitimately appear in links. */
  const CREDENTIAL_PARAMS = /^(password|passwd|pwd|passphrase)$/i;

  function isJwtLike(value) {
    return JWT_RE.test(value || "");
  }

  function hostname(input) {
    try { return new URL(input).hostname.toLowerCase(); }
    catch { return ""; }
  }

  /* Registrable-domain logic is shared with the service worker and networkHook.
     See lib/publicSuffix.js (loaded before this script). Fall back to a local
     two-label implementation if it is somehow unavailable. */
  const PSL = (typeof globalThis !== "undefined" && globalThis.PhishCleanPSL) || null;

  const registrable = PSL
    ? PSL.registrable
    : function (host) {
        const p = (host || "").toLowerCase().split(".").filter(Boolean);
        return p.length < 2 ? (host || "").toLowerCase() : `${p[p.length - 2]}.${p[p.length - 1]}`;
      };

  function isThirdParty(fromHost, toHost) {
    return registrable(fromHost) !== registrable(toHost);
  }

  const BRAND_DOMAINS = {
    PayPal: ["paypal.com", "paypalobjects.com", "paypal.me"],
    Apple: ["apple.com", "icloud.com", "appleid.apple.com"],
    Google: ["google.com", "googleapis.com", "gstatic.com", "accounts.google.com", "googleusercontent.com"],
    Microsoft: ["microsoft.com", "microsoftonline.com", "live.com", "outlook.com", "office.com"],
    Amazon: ["amazon.com", "amazonaws.com", "amazon.co.uk", "media-amazon.com"],
    Netflix: ["netflix.com", "nflximg.net", "nflxext.com"],
    Facebook: ["facebook.com", "fb.com", "fbcdn.net", "instagram.com"],
    GitHub: ["github.com", "githubassets.com", "githubusercontent.com"],
    LinkedIn: ["linkedin.com", "licdn.com"],
    DHL: ["dhl.com", "dhl.de"],
    FedEx: ["fedex.com"],
    Chase: ["chase.com", "jpmorganchase.com"],
    "Bank of America": ["bankofamerica.com", "bac.com"]
  };

  const DOMAIN_TO_BRAND = [];
  Object.entries(BRAND_DOMAINS).forEach(([brand, domains]) => {
    domains.forEach((domain) => DOMAIN_TO_BRAND.push([domain, brand]));
  });

  function normalizeHost(host) {
    return (host || "").toLowerCase().replace(/^www\./, "");
  }

  function matchTrustedBrand(host) {
    const normalized = normalizeHost(host);
    for (const [domain, brand] of DOMAIN_TO_BRAND) {
      if (normalized === domain || normalized.endsWith("." + domain)) return brand;
    }
    return null;
  }

  /* ── Lookalike / homograph / typosquat domain detection ──
     Brand second-level labels (the "paypal" in paypal.com) we defend against
     impersonation of. Derived from BRAND_DOMAINS plus a few common targets. */
  const BRAND_SLDS = (() => {
    const set = new Set();
    Object.values(BRAND_DOMAINS).forEach((domains) => {
      domains.forEach((d) => {
        const label = registrable(d).split(".")[0];
        if (label && label.length >= 4) set.add(label);
      });
    });
    ["paypal", "apple", "google", "microsoft", "amazon", "netflix", "facebook",
     "instagram", "whatsapp", "github", "linkedin", "outlook", "office365",
     "wellsfargo", "citibank", "coinbase", "binance", "metamask", "dhl", "fedex"]
      .forEach((b) => set.add(b));
    return set;
  })();

  /* Bounded Levenshtein — stops early once distance exceeds `max`. */
  function levenshtein(a, b, max = 2) {
    a = a || ""; b = b || "";
    if (Math.abs(a.length - b.length) > max) return max + 1;
    const prev = new Array(b.length + 1);
    for (let j = 0; j <= b.length; j++) prev[j] = j;
    for (let i = 1; i <= a.length; i++) {
      let diag = prev[0];
      prev[0] = i;
      let rowMin = prev[0];
      for (let j = 1; j <= b.length; j++) {
        const tmp = prev[j];
        prev[j] = a[i - 1] === b[j - 1]
          ? diag
          : 1 + Math.min(diag, prev[j], prev[j - 1]);
        diag = tmp;
        if (prev[j] < rowMin) rowMin = prev[j];
      }
      if (rowMin > max) return max + 1; /* early out — can't get better */
    }
    return prev[b.length];
  }

  /* Does the host contain an IDN/punycode label (potential homograph)? */
  function hasPunycodeLabel(host) {
    return (host || "").toLowerCase().split(".").some((l) => l.startsWith("xn--"));
  }

  /**
   * Detect whether `host` is a lookalike of a known brand.
   * @param {string}  host        — page hostname
   * @param {boolean} hasPassword — whether the page has a credential field
   * @returns {{ lookalike, brand, kind } | null}
   */
  function detectLookalikeDomain(host, hasPassword) {
    const norm = normalizeHost(host);
    if (!norm || isLocalhost(norm) || isTrustedDomain(norm)) return null;

    const reg = registrable(norm);
    const sld = reg.split(".")[0];
    if (!sld) return null;

    /* Homograph: IDN/punycode domain presenting a login form. Legit IDN sites
       exist, so we only flag when credentials are being collected. */
    if (hasPunycodeLabel(norm) && hasPassword) {
      return { lookalike: true, brand: null, kind: "homograph" };
    }

    for (const brand of BRAND_SLDS) {
      if (sld === brand) continue; /* exact SLD handled by trusted-domain list */

      /* Typosquat: one or two edits away (paypa1, gogle, micrsoft). */
      if (Math.abs(sld.length - brand.length) <= 2 && levenshtein(sld, brand, 2) <= 1) {
        return { lookalike: true, brand, kind: "typosquat" };
      }

      /* Brand name embedded with decoration: paypal-secure, secure-paypal,
         login-apple, paypal.com.evil (brand appears as its own token but the
         registrable domain is not the real brand). */
      if (sld.length > brand.length && sld.includes(brand)) {
        const boundaryRe = new RegExp(`(^|[^a-z0-9])${brand}([^a-z0-9]|$)`);
        const decorated = `-${sld}-`.replace(/[^a-z0-9]/g, "-");
        if (boundaryRe.test(decorated) || sld.startsWith(brand) || sld.endsWith(brand)) {
          return { lookalike: true, brand, kind: "brand-embedded" };
        }
      }
    }
    return null;
  }

  function backlinkSignalFor(type, href) {
    if (type === "image") return "hotlinked_brand_asset";
    if (type === "script") return "loads_brand_script";
    if (type === "iframe") return "loads_brand_iframe";
    if (type === "form_action") return "form_submits_to_trusted_domain";
    if (type === "anchor" && /privacy|terms|legal|cookie/i.test(href)) return "legit_policy_link";
    if (type === "anchor" && /support|help|contact|customer-service/i.test(href)) return "legit_support_link";
    if (type === "stylesheet") return "loads_brand_stylesheet";
    return "links_to_trusted_domain";
  }

  function analyzeBacklinkRefs(pageUrl, refs, hasPasswordField) {
    const pageHost = normalizeHost(hostname(pageUrl));
    const pageBrand = matchTrustedBrand(pageHost);
    const backlinks = [];
    const detectedBrands = new Set();
    const detectedSignals = new Set();
    const brandCounts = {};
    const seen = new Set();

    for (const ref of refs || []) {
      if (!ref || !ref.url || !ref.type) continue;
      const targetHost = normalizeHost(hostname(ref.url));
      if (!targetHost || registrable(targetHost) === registrable(pageHost)) continue;

      const brand = matchTrustedBrand(targetHost);
      if (!brand) continue;

      const signal = backlinkSignalFor(ref.type, ref.url);
      const key = `${ref.type}|${targetHost}|${brand}|${signal}`;
      if (seen.has(key)) continue;
      seen.add(key);

      backlinks.push({
        href: ref.url,
        type: ref.type,
        target_domain: targetHost,
        trusted_brand: brand,
        signal
      });
      detectedBrands.add(brand);
      detectedSignals.add(signal);
      brandCounts[brand] = (brandCounts[brand] || 0) + 1;
    }

    const dominantBrandCount = Math.max(0, ...Object.values(brandCounts));
    const strongBrandBorrowing =
      detectedSignals.has("hotlinked_brand_asset") ||
      detectedSignals.has("legit_policy_link") ||
      detectedSignals.has("legit_support_link") ||
      detectedSignals.has("form_submits_to_trusted_domain");

    let riskScore = 0;
    if (!pageBrand && detectedBrands.size > 0) riskScore += 35;
    if (detectedBrands.size === 1 && dominantBrandCount >= 2) riskScore += 20;
    if (strongBrandBorrowing) riskScore += 18;
    if (hasPasswordField && detectedBrands.size > 0 && !pageBrand) riskScore += 20;
    riskScore += Math.min(backlinks.length * 3, 12);
    riskScore = Math.min(riskScore, 100);

    return {
      pageDomain: pageHost,
      pageBrand,
      riskScore,
      backlinks,
      impersonatedBrands: Array.from(detectedBrands),
      signals: Array.from(detectedSignals)
    };
  }

  function hasSuspiciousQuery(url) {
    try {
      const u = new URL(url);
      for (const [k, v] of u.searchParams.entries()) {
        if (SUSPICIOUS_PARAMS.test(k)) return true;
        if (isJwtLike(v)) return true;
      }
      return false;
    } catch { return false; }
  }

  function hasCredentialInQuery(url) {
    try {
      const u = new URL(url);
      for (const k of u.searchParams.keys()) {
        if (CREDENTIAL_PARAMS.test(k)) return true;
      }
      return false;
    } catch { return false; }
  }

  /**
   * Score a set of detected signals.
   * @param {Set<string>} signalSet  — active signal keys
   * @param {boolean}     proEnabled — whether Pro features are unlocked
   * @returns {{ score, reasons, level, shouldAlert }}
   */
  function scoreSignals(signalSet, proEnabled) {
    const reasons = [];
    let score = 0;

    for (const signal of Object.values(SIGNALS)) {
      if (!signalSet.has(signal)) continue;
      if (!proEnabled && !FREE_SIGNALS.has(signal)) continue;
      score += WEIGHTS[signal] || 0;
      reasons.push(REASON_TEXT[signal] || signal);
    }

    const level = score >= 50 ? "danger" : score >= 25 ? "warning" : "safe";

    return { score, reasons, level, shouldAlert: score >= THRESHOLD };
  }

  function isLocalhost(h) {
    return h === "localhost" || h === "127.0.0.1" || h === "[::1]";
  }

  /* ── Built-in trusted domains — never trigger alerts on these ── */
  const TRUSTED_DOMAINS = [
    /* Major global platforms */
    "google.com", "google.co.in", "google.co.uk", "google.co.jp",
    "googleapis.com", "gstatic.com", "youtube.com",
    "github.com", "github.io", "githubassets.com",
    "amazon.com", "amazon.in", "amazon.co.uk", "amazon.co.jp",
    "amazon.de", "amazonaws.com",
    "microsoft.com", "live.com", "outlook.com", "office.com",
    "office365.com", "microsoftonline.com", "azure.com",
    "linkedin.com",
    "netflix.com",
    "apple.com", "icloud.com",
    "facebook.com", "meta.com", "instagram.com", "whatsapp.com",
    "twitter.com", "x.com",
    "yahoo.com",
    "dropbox.com",
    "zoom.us",
    "slack.com",
    "notion.so",
    "spotify.com",

    /* Payment & checkout */
    "paypal.com",
    "stripe.com",
    "dodopayments.com",
    "braintreegateway.com",
    "adyen.com",
    "gocardless.com",
    "chargebee.com",

    /* Auth providers, SSO & security widgets */
    "auth0.com",
    "okta.com", "oktacdn.com",
    "onelogin.com",
    "duo.com",
    "recaptcha.net",
    "hcaptcha.com",
    "challenges.cloudflare.com",

    /* Indian banking & fintech */
    "sbi.co.in", "onlinesbi.sbi",
    "hdfcbank.com", "hdfcsec.com",
    "icicibank.com", "icicidirect.com",
    "axisbank.com",
    "kotak.com",
    "zerodha.com", "kite.zerodha.com",
    "razorpay.com",
    "paytm.com",
    "phonepe.com",
    "npci.org.in",
    "upigateway.com",
    "billdesk.com",

    /* Dev & cloud platforms */
    "vercel.app", "vercel.com",
    "netlify.app", "netlify.com",
    "cloudflare.com",
    "heroku.com",
    "supabase.com", "supabase.co",
    "firebase.google.com", "firebaseapp.com",
  ];

  /**
   * Check if a hostname belongs to a trusted domain.
   * Uses suffix matching: "accounts.google.com" matches "google.com".
   */
  function isTrustedDomain(h) {
    const lower = (h || "").toLowerCase();
    for (const d of TRUSTED_DOMAINS) {
      if (lower === d || lower.endsWith("." + d)) return true;
    }
    return false;
  }

  /* Expose as global for content script */
  window.PhishCleanRiskEngine = {
    SIGNALS, WEIGHTS, THRESHOLD, FREE_SIGNALS,
    REASON_TEXT, isJwtLike, hostname, isThirdParty,
    hasSuspiciousQuery, hasCredentialInQuery, scoreSignals, isLocalhost,
    isTrustedDomain, TRUSTED_DOMAINS,
    BRAND_DOMAINS, matchTrustedBrand, analyzeBacklinkRefs,
    detectLookalikeDomain, levenshtein, BRAND_SLDS
  };
})();

