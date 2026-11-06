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
    LOOKALIKE_DOMAIN: "LOOKALIKE_DOMAIN",
    REGIONAL_SCAM: "REGIONAL_SCAM",
    KNOWN_PHISHING: "KNOWN_PHISHING",
    TECH_SUPPORT_SCAM: "TECH_SUPPORT_SCAM",
    NOTIFICATION_BAIT: "NOTIFICATION_BAIT",
    FAKE_SHOP: "FAKE_SHOP",
    FAKE_CAPTCHA: "FAKE_CAPTCHA",
    FAKE_BROWSER_UPDATE: "FAKE_BROWSER_UPDATE",
    CARD_SKIMMER: "CARD_SKIMMER",
    FAKE_INTERVIEW_FIX: "FAKE_INTERVIEW_FIX",
    FAKE_MEETING_APP: "FAKE_MEETING_APP",
    BROWSER_IN_BROWSER: "BROWSER_IN_BROWSER",
    DEVICE_CODE_PHISH: "DEVICE_CODE_PHISH"
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
    LOOKALIKE_DOMAIN: 35,
    /* Alerts on its own: it already requires a known scam script, a card/UPI/
       OTP field and an unofficial domain all at once. */
    REGIONAL_SCAM: 45,
    /* A reported phishing host (lib/phishFeed.js). Alerts on its own. */
    KNOWN_PHISHING: 60,
    /* Already requires a support number plus two scam-script phrases. */
    TECH_SUPPORT_SCAM: 60,
    /* Already requires "click Allow" plus a fake reason (robot check, video,
       download) on a short page that can still ask for the permission. */
    NOTIFICATION_BAIT: 45,
    /* Already requires a shop, implausible discounts and a brand name in a
       domain the brand does not own (or four weaker cues together). */
    FAKE_SHOP: 45,
    /* Already requires a copied command next to a robot check or a Run-box
       shortcut, or all three text cues on a short page. */
    FAKE_CAPTCHA: 60,
    /* Already requires an "update your browser" message and a file to run
       (or an update button with no link to the real browser maker) on a
       short page that is not the browser maker's own. */
    FAKE_BROWSER_UPDATE: 50,
    /* The card number typed into this page left it for a host that is not a
       payment company, the site itself or a well-known platform. */
    CARD_SKIMMER: 50,
    /* Already requires a camera or microphone error inside an interview or
       meeting, plus a copied command or the paste steps on a short page. */
    FAKE_INTERVIEW_FIX: 60,
    /* Already requires "download the meeting app to join", a file to run
       (or a download button) and a site that is not the meeting company's. */
    FAKE_MEETING_APP: 50,
    /* Already requires a positioned box that shows a real sign-in address as
       page text around a login form or frame, on another company's site. */
    BROWSER_IN_BROWSER: 55,
    /* Already requires a device sign-in address, a code to enter and a short
       page on a site that is not Microsoft's, GitHub's or Google's. */
    DEVICE_CODE_PHISH: 55
  };

  const THRESHOLD = 40;

  /* Free tier only gets basic signals; Pro unlocks the rest. The reported-
     phishing list is free: holding back a warning about a page already known
     to be phishing would only hurt the user it failed. So is the fake
     CAPTCHA check: the next step on that page installs malware, and on hacked
     sites it runs on domains no list or lookalike check would flag. The fake
     interview "camera fix" is the same trick aimed at job seekers. */
  const FREE_SIGNALS = new Set([SIGNALS.PASSWORD_FIELD, SIGNALS.DOMAIN_MISMATCH, SIGNALS.KNOWN_PHISHING, SIGNALS.FAKE_CAPTCHA, SIGNALS.FAKE_INTERVIEW_FIX]);

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
    LOOKALIKE_DOMAIN: "This domain closely imitates a well-known brand — likely a lookalike (typosquatting or homograph) phishing site.",
    KNOWN_PHISHING: "This site is on a list of reported phishing sites. It was checked on your device; the address was not sent anywhere.",
    TECH_SUPPORT_SCAM: "This page imitates a virus or security warning and tells you to call a support number. Real security software never does that; the number goes to scammers.",
    NOTIFICATION_BAIT: "This page tells you to click \"Allow\" to prove you are human, play a video or start a download. That button only lets the site send you notifications, which spam sites fill with fake virus alerts, scam offers and adult ads.",
    FAKE_SHOP: "This looks like a fake online store: prices far below what the real product costs, on a site that is not the brand's own. Fake stores take the payment and send nothing, or a counterfeit.",
    FAKE_CAPTCHA: "This page tells you to press Windows+R (or open a terminal) and paste something to prove you are human. No real CAPTCHA does that. What it copied to your clipboard is a command that installs password-stealing malware.",
    FAKE_BROWSER_UPDATE: "This page says your browser is out of date and offers a file to install. Browsers update themselves; a website asking you to download an update is how hacked sites spread malware.",
    CARD_SKIMMER: "This page sent the card number you typed to another site that is not a payment company. That is how card skimmers on hacked shops steal cards.",
    FAKE_INTERVIEW_FIX: "This interview or meeting page says your camera or microphone is broken and tells you to paste a fix into Terminal, PowerShell or the Run box. No real interview platform does that. Fake job interviews use it to install malware that steals crypto wallets, passwords and work logins.",
    FAKE_MEETING_APP: "This page says you need to download a meeting app to join an interview or call, and the file does not come from the company that makes the app. Fake meeting apps are how fake recruiters get malware onto a laptop.",
    BROWSER_IN_BROWSER: "This page draws a fake sign-in window with a real-looking address bar. A real sign-in popup is a separate browser window; this one is part of the page, and whatever you type goes to the site that drew it.",
    DEVICE_CODE_PHISH: "This page gives you a code to enter at Microsoft's, GitHub's or Google's device sign-in page. Entering it would sign someone else's device into your account, without them ever needing your password.",
    REGIONAL_SCAM: "This page follows a known scam script (fake traffic e-challan, KYC update, electricity disconnection, held parcel, tax refund or reward points) and asks for card, UPI or OTP details on a site that is not the real bank or government service."
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

  const INFRA_HOSTS = [
    "fonts.googleapis.com", "fonts.gstatic.com", "ajax.googleapis.com",
    "www.gstatic.com", "gstatic.com", "storage.googleapis.com",
    "raw.githubusercontent.com", "avatars.githubusercontent.com"
  ];

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
     "wellsfargo", "citibank", "coinbase", "binance", "metamask", "dhl", "fedex",
     /* Fake recruiters and trojanized developer tools: exchanges and wallets,
        code hosts and package registries, and the scheduling and Terraform
        sites their lures copy (hashicorp-terraform.io, calendly-meet.com).
        Short or dictionary-like names (zoom, teams, ledger, kraken, okx)
        stay out: one edit away from them is an ordinary word or brand. */
     "bybit", "kucoin", "upbit", "trezor", "trustwallet", "gitlab", "bitbucket",
     "npmjs", "terraform", "hashicorp", "calendly"]
      .forEach((b) => set.add(b));
    return set;
  })();

  /* Indian banks, payment apps and government services that scam pages
     impersonate. Matched more strictly than BRAND_SLDS: only as a whole
     hyphen/dot-separated token (sbi-kyc-update.com, hdfcbank.verify-now.xyz),
     never as a prefix, because the real brands own many prefixed domains
     (sbicard.com, kotaksecurities.com, paytmmall.com). Typosquats are only
     checked for names of 8+ letters — short ones collide with real words
     (kotak/kodak, phonepe/phoneme). */
  const REGIONAL_BRAND_SLDS = [
    "sbi", "onlinesbi", "yonosbi", "hdfc", "hdfcbank", "hdfc-bank", "icici", "icicibank",
    "icici-bank", "axisbank", "axis-bank", "kotak", "india-post",
    "paytm", "phonepe", "bhim", "npci", "indiapost", "parivahan", "echallan",
    "incometax", "irctc", "uidai", "aadhaar", "flipkart"
  ];

  /* Registries only real Indian government bodies and banks can register in
     (gov.in/nic.in via NIC, bank.in via IDRBT for RBI-regulated banks, and
     SBI's own .sbi TLD), plus official sites the regional checks would
     otherwise match. */
  const INDIA_OFFICIAL_SUFFIXES = ["gov.in", "nic.in", "bank.in", "sbi"];
  const INDIA_OFFICIAL_DOMAINS = [
    "sbicard.com", "sbilife.co.in", "sbimf.com", "sbigeneral.in", "hdfc.com", "hdfclife.com",
    "hdfcergo.com", "icicilombard.com", "iciciprulife.com", "kotak811.com", "irctc.co.in",
    "flipkart.com", "amazon.in", "mobikwik.com", "freecharge.in", "cred.club", "airtel.in",
    "jio.com", "delhivery.com", "bluedart.com", "dtdc.in", "dtdc.com", "ecomexpress.in",
    "xpressbees.com", "shiprocket.in", "tatapower.com", "adanielectricity.com", "bescom.co.in",
    "bsesdelhi.com", "tatapower-ddl.com", "torrentpower.com", "cesc.co.in", "mahadiscom.in",
    "kseb.in", "fastag.ihmcl.com", "ihmcl.co.in"
  ];

  function isIndianOfficialHost(host) {
    const h = normalizeHost(host);
    const match = (d) => h === d || h.endsWith("." + d);
    return INDIA_OFFICIAL_SUFFIXES.some(match) || INDIA_OFFICIAL_DOMAINS.some(match) || isTrustedDomain(h);
  }

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

  /* ASCII homoglyphs: digits and letter pairs that read as a brand's letters
     at a glance (g00gle, paypa1, rnicrosoft, vvellsfargo). "1" is tried as
     both "l" and "i" (paypa1, m1crosoft). Only labels that mix letters with
     these characters change, so plain words and numbers are left alone. */
  const HOMOGLYPH_SWAPS = [[/rn/g, "m"], [/vv/g, "w"], [/0/g, "o"], [/3/g, "e"], [/5/g, "s"], [/\$/g, "s"]];
  function deHomoglyph(label) {
    if (!/[a-z]/.test(label) || !/[0-9]|rn|vv/.test(label)) return [];
    let base = label;
    for (const [re, to] of HOMOGLYPH_SWAPS) base = base.replace(re, to);
    const out = new Set([base.replace(/1/g, "l"), base.replace(/1/g, "i")]);
    out.delete(label);
    return [...out];
  }

  /* TLD-like labels that make "paypal.com.verify-account.ru" read as PayPal. */
  const BRAND_TLD_LABELS = new Set(["com", "net", "org", "co", "io", "app", "us", "uk", "in", "de", "fr", "ca", "au"]);

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

    /* A hyphenated label is read word by word, so each word is checked on
       its own: paypa1-login, micros0ft-365-login, secure-app1e-id. */
    const words = sld.split("-").filter((w) => w.length >= 4);
    for (const word of words) {
      for (const v of deHomoglyph(word)) {
        if (BRAND_SLDS.has(v)) return { lookalike: true, brand: v, kind: "typosquat" };
      }
      /* One slip in a long brand name (linkedln-jobs). Short names stay out:
         one letter from them is usually an ordinary word. */
      if (words.length > 1 && word.length >= 7) {
        for (const brand of BRAND_SLDS) {
          if (brand.length >= 8 && word !== brand && levenshtein(word, brand, 1) <= 1) {
            return { lookalike: true, brand, kind: "typosquat" };
          }
        }
      }
    }

    /* The brand's own domain written as subdomains of someone else's:
       paypal.com.account-verify.ru, login-microsoft.com.verify-user.top. */
    const labels = norm.split(".");
    const regLabels = reg.split(".").length;
    for (let i = 0; i < labels.length - regLabels - 1; i++) {
      if (!BRAND_TLD_LABELS.has(labels[i + 1])) continue;
      const parts = labels[i].split("-").flatMap((p) => [p, ...deHomoglyph(p)]);
      const brand = parts.find((p) => BRAND_SLDS.has(p) && p !== sld);
      if (brand) return { lookalike: true, brand, kind: "brand-embedded" };
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

    if (!isIndianOfficialHost(norm)) {
      /* Whole host, not just the SLD: hdfcbank.secure-verify.xyz puts the
         brand in a subdomain of a domain the attacker owns. */
      const tokens = `-${norm.replace(/[^a-z0-9]/g, "-")}-`;
      for (const brand of REGIONAL_BRAND_SLDS) {
        if (tokens.includes(`-${brand}-`)) {
          return { lookalike: true, brand, kind: "brand-embedded" };
        }
        if (brand.length >= 8 && sld !== brand &&
            Math.abs(sld.length - brand.length) <= 1 && levenshtein(sld, brand, 1) <= 1) {
          return { lookalike: true, brand, kind: "typosquat" };
        }
      }
    }
    return null;
  }

  /* ── Regional scam scripts (India) ──
     The recurring SMS/WhatsApp scams all land on a page that retells a short
     story and then asks for card, UPI or OTP details. Matching the story alone
     would flag news articles about the scam; matching payment fields alone
     would flag every checkout. Together, on a domain that is not the real
     bank or government service, they are the scam. Patterns cover English and
     Hindi, which is what these pages are written in. */
  const REGIONAL_SCAM_LURES = [
    { kind: "e-challan", re: /\be-?challan\b|traffic (?:fine|challan|violation)|pending challan|ई-?चालान|चालान/ },
    { kind: "kyc", re: /\b(?:update|complete|re-?verify|pending|expired?)\b[^.]{0,40}\bkyc\b|\bkyc\b[^.]{0,40}\b(?:update|pending|expire[sd]?|blocked|suspended|deactivat)|केवाईसी/ },
    { kind: "electricity", re: /electricity (?:bill|connection|power)[^.]{0,80}(?:disconnect|cut off|suspend)|power (?:supply )?will be (?:disconnected|cut)|बिजली[^।]{0,60}(?:कट|काट|बंद)/ },
    { kind: "parcel", re: /\bindia ?post\b|(?:parcel|package|shipment|consignment)[^.]{0,60}(?:on hold|is held|been held|could not be delivered|undeliver|address (?:is )?incomplete|redeliver)/ },
    { kind: "tax-refund", re: /income ?tax refund|tax refund of (?:rs\.?|inr|₹)|आयकर रिफंड/ },
    { kind: "fastag", re: /fastag[^.]{0,40}(?:kyc|blocked|deactivat|expir|blacklist)/ }
  ];
  /* Reward-points pages only count when they name a bank — legitimate
     retailers run points promotions next to card forms all the time. */
  const REWARD_POINTS_RE = /(?:reward|credit card) points?[^.]{0,60}(?:expir|redeem)/;
  const INDIAN_BANK_RE = /\b(?:sbi|yono|hdfc|icici|axis|kotak|pnb|punjab national|bank of baroda|canara|union bank|indusind)\b/;

  /* Form fields that only a payment or account-takeover page needs. Tested
     against each field's name, id, placeholder, autocomplete and label. */
  /* "(?:^|[^a-z])" rather than \b so upi_id and otpInput match (underscore
     and camelCase defeat \b) while groupid and hotpot do not. */
  const SENSITIVE_FIELD_RE = /card[ _-]?(?:no|num|number)|cc-?(?:number|csc|exp)|cvv|cvc|expiry|valid (?:thru|till)|(?:^|[^a-z])upi|(?:^|[^a-z])m-?pin|atm ?pin|(?:^|[^a-z])otp|one.time.pass|aadhaa?r|(?:^|[^a-z])pan[ _-]?(?:no|num|number|card)|net ?banking|ifsc/;

  /**
   * @param {string}  host               — page hostname
   * @param {string}  text               — visible page text (any case)
   * @param {boolean} hasSensitiveFields — page asks for card/UPI/OTP-type data
   * @returns {{ kind: string } | null}
   */
  function detectRegionalScam(host, text, hasSensitiveFields) {
    if (!hasSensitiveFields || isIndianOfficialHost(host)) return null;
    const t = (text || "").toLowerCase().slice(0, 30000);
    for (const { kind, re } of REGIONAL_SCAM_LURES) {
      if (re.test(t)) return { kind };
    }
    if (REWARD_POINTS_RE.test(t) && INDIAN_BANK_RE.test(t)) return { kind: "reward-points" };
    return null;
  }

  /* Fake virus / tech support scam pages: a fake security alert with a number
     to call. It takes a toll-free number AND two distinct scam phrases, or one
     phrase while the page holds the screen in fullscreen. An article about
     these scams quotes a phrase or two but rarely prints a live support
     number beside them; a scam page always does, because the call is the
     whole point. Numbers: US/Canada 8xx, UK 0800/0808, AU and IN 1800. */
  const TOLL_FREE_RE = /(?:\+?1[\s.-]?)?\(?8(?:00|33|44|55|66|77|88)\)?[\s.-]?\d{3}[\s.-]?\d{4}\b|\b080[08][\s-]?\d{3}[\s-]?\d{3,4}\b|\b1[\s-]?800[\s-]?\d{3}[\s-]?\d{3,4}\b/;
  const TECH_SCAM_CUES = [
    /\b(?:your|this)\s+(?:computer|pc|device|system|windows|mac|laptop|browser)\s+(?:has been|is|was|have been)\s+(?:blocked|locked|infected|compromised|disabled|hacked|suspended)/,
    /\b(?:do not|don.?t)\s+(?:close|restart|shut ?down|turn off|ignore|reboot)\s+(?:this|your)\s+(?:page|window|computer|pc|browser|device|tab)/,
    /\b(?:call|contact)\s+(?:microsoft|windows|apple|mac|technical|tech|geek squad|norton|mcafee)\s*(?:support|help|technicians?|helpline|engineers?)/,
    /\b(?:trojan|spyware|zeus|pornographic|adware)\s+(?:virus|spyware|alert|detected|infection|malware)/,
    /\berror\s*(?:code)?\s*[#:]?\s*0x[0-9a-f]{4,}/,
    /\b(?:windows|microsoft)\s+(?:defender|security|firewall)\s+(?:alert|warning|center|notification)/,
    /\b(?:your|the)\s+(?:personal|banking|credit card|login|financial)\s+(?:information|details|data|credentials)\s+(?:is|are|may be|has been|have been|will be)\s+(?:at risk|stolen|compromised|exposed|deleted)/,
    /\bfor\s+(?:security|safety)\s+reasons?,?\s+(?:your|this)\s+(?:computer|pc|device|access)\s+(?:has been|is)\s+(?:blocked|locked|suspended)/
  ];

  function hasTollFreeNumber(text) {
    return TOLL_FREE_RE.test(text || "");
  }

  /* A phrase in quotation marks is someone describing the scam, not the scam. */
  const QUOTE_BEFORE_RE = /["“‘'«]\s*$/;
  function countsAsCue(t, re) {
    for (const m of t.matchAll(new RegExp(re.source, "g"))) {
      if (!QUOTE_BEFORE_RE.test(t.slice(Math.max(0, m.index - 3), m.index))) return true;
    }
    return false;
  }

  /* A scam page is one alert box; an article about scams is long. */
  const SCAM_PAGE_MAX_CHARS = 6000;

  /**
   * @param {string} text  visible page text
   * @param {boolean} fullscreen  the page currently holds fullscreen
   */
  function detectTechSupportScam(text, fullscreen) {
    const t = (text || "").toLowerCase();
    if (!fullscreen && t.length > SCAM_PAGE_MAX_CHARS) return false;
    if (!TOLL_FREE_RE.test(t)) return false;
    let cues = 0;
    for (const re of TECH_SCAM_CUES) if (countsAsCue(t, re)) cues++;
    return cues >= 2 || (cues >= 1 && !!fullscreen);
  }

  /* ── Notification permission bait ──
     "Click Allow to verify you are not a robot / to watch the video / to
     start your download." Allow is the browser's notification prompt, and the
     site then pushes fake virus alerts and scam ads to the desktop for weeks.
     It takes the instruction to press Allow and a fake reason for it, on a
     short page, while the site can still ask (permission is "default"). A
     help article explaining the trick quotes the phrase or runs long. */
  const ALLOW_CUE_RE = /\b(?:click|press|tap|hit|select|choose)\s+(?:on\s+)?(?:the\s+)?allow\b/;
  const ALLOW_REASON_RES = [
    /\b(?:not|aren.?t)\s+a\s+robot\b/,
    /\b(?:verify|confirm|prove)\s+(?:that\s+)?(?:you\s+are|you.?re)\s+(?:a\s+)?(?:human|not a robot|18|over 18|an adult)/,
    /\bto\s+(?:continue|proceed|watch|play|view|see|access|download|start|unlock|get|claim|enter)\b/,
    /\b(?:your|the)\s+(?:download|file|video|stream|movie|link|content|prize|reward)\s+is\s+(?:ready|almost ready|loading|waiting)/,
    /\b(?:captcha|age verification|human verification)\b/
  ];
  const NOTIFICATION_PAGE_MAX_CHARS = 4000;

  /**
   * @param {string} text        visible page text
   * @param {string} permission  Notification.permission for this origin
   */
  function detectNotificationBait(text, permission) {
    if (permission && permission !== "default") return false;
    const t = (text || "").toLowerCase().replace(/["“”'‘’«»]allow["“”'‘’«»]/g, "allow");
    if (t.length > NOTIFICATION_PAGE_MAX_CHARS) return false;
    if (!countsAsCue(t, ALLOW_CUE_RE)) return false;
    return ALLOW_REASON_RES.some((re) => countsAsCue(t, re));
  }

  /* ── Fake online stores ──
     Social-media ads lead to stores selling branded goods at 70-90% off on
     domains like nike-outlet-sale.shop; they take the card and ship nothing
     or a counterfeit. Discounts alone are every clearance sale and a cheap
     TLD alone is every small business, so it takes a shop with implausible
     discounts AND a famous brand in a domain the brand does not own, or four
     weaker cues at once: implausible discounts, a throwaway TLD, closing-down
     urgency and no contact, returns or policy pages. */
  const SHOP_CUE_RE = /\b(?:add to (?:cart|bag|basket)|buy (?:it )?now|checkout|shop now|in stock)\b/;
  const PRICE_RE = /(?:[$€£₹]\s?\d[\d,.]*|\b\d[\d,.]*\s?(?:usd|eur|gbp|aud|cad)\b)/g;
  /* "-75%" badges and "75% off"; never a bare "100% cotton". */
  const DISCOUNT_RE = /(?:^|[\s(])[-–]\s?(\d{2})\s?%|\b(\d{2})\s?%\s?(?:off|discount)\b/g;
  const UP_TO_DEEP_RE = /\bup to\s+[7-9]\d\s?%\s?off\b/;
  const SHOP_URGENCY_RE = /\b(?:closing down|store closing|shop closing|going out of business|liquidation|clearance sale|final (?:clearance|hours|day)|last day|warehouse clearance|everything must go|only today)\b/;
  const THROWAWAY_TLDS = new Set([
    "shop", "store", "top", "xyz", "online", "buzz", "icu", "vip", "club", "cfd",
    "sbs", "lol", "bond", "click", "cyou", "monster", "site", "fun", "live",
    "best", "boutique", "sale", "life", "today", "space", "website"
  ]);
  /* Brands fake stores sell most. Matched as a hyphen/dot token anywhere in
     the host or as the start/end of the registrable label; never when the
     label IS the brand (nike.com). */
  const SHOP_BRANDS = [
    "nike", "adidas", "puma", "reebok", "newbalance", "converse", "crocs",
    "ugg", "skechers", "asics", "lululemon", "northface", "patagonia",
    "rayban", "oakley", "pandora", "swarovski", "rolex", "casio", "fossil",
    "michaelkors", "katespade", "louisvuitton", "gucci", "prada", "chanel",
    "dior", "hermes", "balenciaga", "burberry", "moncler", "canadagoose",
    "lego", "dyson", "yeti", "stanley", "lancome", "sephora", "ikea", "apple",
    "samsung", "bose", "lenovo", "dewalt", "makita", "milwaukee",
    "birkenstock", "drmartens", "timberland", "levis", "tommyhilfiger", "ralphlauren",
    "hugoboss", "underarmour", "fjallraven", "hoka", "salomon"
  ];

  function brandInShopHost(host) {
    const norm = normalizeHost(host);
    if (!norm || isTrustedDomain(norm)) return null;
    const label = registrable(norm).split(".")[0];
    const tokens = `-${norm.replace(/[^a-z0-9]/g, "-")}-`;
    for (const brand of SHOP_BRANDS) {
      if (label === brand) continue;
      if (tokens.includes(`-${brand}-`)) return brand;
      if (brand.length >= 4 && label.length > brand.length &&
          (label.startsWith(brand) || label.endsWith(brand))) return brand;
    }
    return null;
  }

  function deepDiscountCount(t) {
    let n = 0;
    for (const m of t.matchAll(DISCOUNT_RE)) {
      if (Number(m[1] || m[2]) >= 60) n++;
    }
    return n;
  }

  /**
   * @param {string}  host            page hostname
   * @param {string}  text            visible page text
   * @param {boolean} missingPolicies page has no contact, returns, privacy or terms link
   * @returns {{ brand: string|null, cues: string[] } | null}
   */
  function detectFakeShop(host, text, missingPolicies) {
    const norm = normalizeHost(host);
    if (!norm || isLocalhost(norm) || isTrustedDomain(norm)) return null;
    const t = (text || "").toLowerCase().slice(0, 40000);
    if (!SHOP_CUE_RE.test(t)) return null;
    if ((t.match(PRICE_RE) || []).length < 3) return null;
    if (deepDiscountCount(t) < 2 && !UP_TO_DEEP_RE.test(t)) return null;

    const brand = brandInShopHost(norm) || detectLookalikeDomain(norm, false)?.brand || null;
    const cues = ["deep-discounts"];
    if (THROWAWAY_TLDS.has(norm.split(".").pop())) cues.push("throwaway-tld");
    if (SHOP_URGENCY_RE.test(t)) cues.push("closing-down");
    if (missingPolicies) cues.push("no-policies");
    if (brand) cues.push("brand-in-domain");

    return brand || cues.length >= 4 ? { brand, cues } : null;
  }

  /* ── Fake CAPTCHA ("ClickFix") ──
     A fake robot check copies a command to the clipboard and tells you to
     press Windows+R (or open Terminal, or the File Explorer address bar),
     paste and press Enter. The command installs a password stealer. Hacked
     sites show these on their own domains, so this is a page check, not a
     domain check. Install docs also copy commands and say "paste this in a
     terminal", so a copied command only counts next to a robot-check cue, or
     next to a Run-box shortcut on a short page. Without a copied command a
     short page needs all three: the shortcut, the paste and the robot check.
     Articles about the trick are long or quote the steps. */
  const KEY_SEP = String.raw`\s*(?:\+|and|&)?\s*["'“]?`;
  const RUN_DIALOG_RES = [
    new RegExp(String.raw`(?:\bwin(?:dows)?(?:\s+(?:logo\s+)?(?:key|button))?|⊞)${KEY_SEP}[rx]\b`),
    /\brun\s+(?:dialog|box|window|command box)\b/,
    /\bfile explorer\b[^.]{0,80}\baddress bar\b/
  ];
  const TERMINAL_RES = [
    /\bopen\s+(?:the\s+|a\s+)?terminal\b/,
    new RegExp(String.raw`(?:\bcmd|\bcommand|⌘)${KEY_SEP}space\b`)
  ];
  const PASTE_RES = [
    new RegExp(String.raw`(?:\bctrl|\bcontrol|\bcmd|\bcommand|⌘)${KEY_SEP}v\b`),
    /\bpaste\b/
  ];
  const ROBOT_CHECK_RES = [
    /\bnot\s+a\s+(?:robot|bot)\b/,
    /\b(?:re)?captcha\b/,
    /\b(?:verify|verifying|confirm|prove)\s+(?:that\s+)?(?:you\s+are|you.?re)\s+(?:a\s+)?(?:human|not a (?:robot|bot))/,
    /\b(?:human|robot|bot)\s+(?:verification|check)\b/,
    /\bverification\s+(?:id|steps?)\b/
  ];
  /* What the copied text runs: Windows shells and built-in tools that fetch
     or launch code, or a download piped into a shell on macOS and Linux. */
  const SHELL_COMMAND_RE = /\b(?:powershell|pwsh|mshta|cmd(?:\.exe)?\s+\/[ck]|curl|wget|iwr|irm|iex|invoke-(?:webrequest|restmethod|expression)|start-process|bitsadmin|certutil|rundll32|regsvr32|msiexec|conhost|wscript|cscript|finger|osascript|(?:ba|z)?sh\s+-c|base64\s+(?:-d|--decode))\b/;
  const CAPTCHA_PAGE_MAX_CHARS = 6000;

  function isShellCommand(text) {
    return SHELL_COMMAND_RE.test((text || "").toLowerCase());
  }

  /**
   * @param {string} text       visible page text
   * @param {string} clipboard  last text the page itself wrote to the clipboard
   */
  function detectFakeCaptcha(text, clipboard) {
    const t = (text || "").toLowerCase().replace(/\s+/g, " ");
    const clip = (clipboard || "").toLowerCase().slice(0, 4000);
    const any = (res) => res.some((re) => countsAsCue(t, re));
    const short = t.length <= CAPTCHA_PAGE_MAX_CHARS;
    const runBox = any(RUN_DIALOG_RES);

    if (clip && SHELL_COMMAND_RE.test(clip)) {
      /* The decoy comment these commands end with ("# I am not a robot -
         reCAPTCHA Verification ID: 4823") is the scam talking. URLs and
         hostnames are left out: a CAPTCHA API call names its own host. */
      const words = clip.replace(/\S*[./]\S*/g, " ");
      if (ROBOT_CHECK_RES.some((re) => re.test(words))) return true;
      const robot = any(ROBOT_CHECK_RES);
      return (robot && runBox) || (short && (robot || runBox));
    }
    if (!short) return false;
    return (runBox || any(TERMINAL_RES)) && any(PASTE_RES) && any(ROBOT_CHECK_RES);
  }

  /* ── Fake interview "camera fix" ──
     The fake-recruiter version of the same trick (Sekoia named it ClickFake
     Interview): a video interview site says your camera or microphone is
     blocked and tells you to paste a "fix" into Terminal, PowerShell or the
     Run box. It installs a backdoor aimed at the wallets, passwords and cloud
     keys on the candidate's laptop. Help pages for real camera trouble print
     terminal commands too, so the device error only counts inside an
     interview or meeting, and then needs a copied download command, or the
     paste steps on a short page. */
  const DEVICE_ERROR_RES = [
    /\b(?:camera|webcam|microphone|mic|audio|video)\s+(?:access\s+)?(?:is\s+|was\s+|has been\s+)?(?:blocked|not working|not detected|not found|unavailable|error|failed|denied|disabled)/,
    /\b(?:camera|webcam|microphone|audio|video)\s+(?:driver|permission)s?\s+(?:error|issue|problem|update|is outdated|out of date|missing|failed)/,
    /\b(?:fix|repair|update|reset|reinstall)\s+(?:your\s+|the\s+)?(?:camera|webcam|microphone|audio|video)(?:\s+drivers?)?\b/,
    /\b(?:could not|couldn.?t|can.?t|cannot|unable to|failed to)\s+(?:access|start|detect|connect to|find)\s+(?:your\s+|the\s+)?(?:camera|webcam|microphone)/
  ];
  const MEETING_CONTEXT_RE = /\b(?:interview|interviewer|recruiter|recruitment|candidate|hiring manager|video (?:call|meeting|interview|question|response)|meeting room|(?:join|joining|enter|start)\s+(?:the\s+|your\s+|this\s+)?(?:meeting|call|interview|session))\b/;
  const FIX_STEP_RES = [...RUN_DIALOG_RES, ...TERMINAL_RES, /\b(?:open|launch|run)\s+(?:the\s+|a\s+)?(?:command prompt|powershell|cmd|terminal)\b/];

  /**
   * @param {string} text       visible page text
   * @param {string} clipboard  last text the page itself wrote to the clipboard
   */
  function detectFakeInterviewFix(text, clipboard) {
    const t = (text || "").toLowerCase().replace(/\s+/g, " ");
    const any = (res) => res.some((re) => countsAsCue(t, re));
    if (!any(DEVICE_ERROR_RES) || !countsAsCue(t, MEETING_CONTEXT_RE)) return false;
    const short = t.length <= CAPTCHA_PAGE_MAX_CHARS;
    const steps = any(FIX_STEP_RES);
    if (isShellCommand(clipboard)) return short || steps;
    return short && steps && any(PASTE_RES);
  }

  /* ── Fake browser update ──
     The classic payload on hacked WordPress sites: the page is replaced by
     "Your Chrome is out of date — Update Chrome" and the button downloads a
     script or installer that loads malware. Real browsers update themselves
     and never ask a website to deliver the update. Legitimate "unsupported
     browser" notices link to the browser maker's site, so a link there
     clears the page; a file to run, or an update button that goes nowhere
     real, does not. */
  const BROWSER_VENDOR_DOMAINS = [
    "google.com", "mozilla.org", "firefox.com", "microsoft.com", "apple.com",
    "opera.com", "brave.com", "vivaldi.com", "duckduckgo.com"
  ];
  const BROWSER_NAMES = String.raw`(?:web browser|browser|google chrome|chrome|microsoft edge|edge|firefox|safari|opera)`;
  const UPDATE_CUE_RES = [
    new RegExp(String.raw`\b(?:your|this)\s+${BROWSER_NAMES}\s+(?:version\s+)?(?:is|seems|appears to be)\s+(?:out of date|outdated|too old|obsolete|not up to date)`),
    new RegExp(String.raw`\b(?:update|upgrade)\s+(?:your\s+)?${BROWSER_NAMES}\s+(?:now|immediately|to (?:continue|view|access|load|see|display))`),
    new RegExp(String.raw`\b${BROWSER_NAMES}\s+(?:update|upgrade)\s+(?:is\s+)?(?:required|needed|necessary|available)\b`),
    /\bcritical\s+(?:browser|security)\s+update\b/
  ];
  const UPDATE_BUTTON_RE = /\b(?:update|upgrade|install|download)\s+(?:now|update|the update|chrome|google chrome|edge|firefox|browser|your browser)\b/;
  const EXECUTABLE_PATH_RE = /\.(?:exe|msi|msix|appx|zip|rar|7z|js|jse|vbs|vbe|wsf|hta|bat|cmd|scr|ps1|lnk|iso|img|apk|dmg|pkg)$/i;
  const UPDATE_PAGE_MAX_CHARS = 4000;

  function isBrowserVendor(host) {
    const h = normalizeHost(host);
    return BROWSER_VENDOR_DOMAINS.some((d) => h === d || h.endsWith("." + d));
  }

  /**
   * @param {string} host    page hostname
   * @param {string} text    visible page text
   * @param {{href: string, download: boolean, label: string}[]} actions
   *        the page's links and buttons (href is "" for a button)
   */
  function detectFakeBrowserUpdate(host, text, actions) {
    const norm = normalizeHost(host);
    if (!norm || isLocalhost(norm) || isTrustedDomain(norm) || isBrowserVendor(norm)) return false;
    const t = (text || "").toLowerCase().replace(/\s+/g, " ");
    if (t.length > UPDATE_PAGE_MAX_CHARS) return false;
    if (!UPDATE_CUE_RES.some((re) => countsAsCue(t, re))) return false;

    let vendorLink = false, file = false, updateButton = false;
    for (const a of actions || []) {
      const label = (a.label || "").toLowerCase();
      if (a.href) {
        let u = null;
        try { u = new URL(a.href); } catch { /* not a URL */ }
        if (u && isBrowserVendor(u.hostname)) { vendorLink = true; continue; }
        if (a.download || (u && EXECUTABLE_PATH_RE.test(u.pathname))) { file = true; continue; }
      }
      if (UPDATE_BUTTON_RE.test(label)) updateButton = true;
    }
    return file || (updateButton && !vendorLink);
  }

  /* ── Fake meeting app ──
     The other door fake recruiters use: "to join the interview, download our
     meeting client" (or a "Zoom SDK update"), served from a lookalike site.
     Real invitations open in the browser or link to the meeting company's
     own download page, so a link there clears the page; a file from anywhere
     else, or a download button that goes nowhere real, does not. */
  const MEETING_VENDOR_DOMAINS = [
    "zoom.us", "zoom.com", "zoomgov.com", "microsoft.com", "cloud.microsoft", "live.com",
    "office.com", "skype.com", "google.com", "webex.com", "cisco.com", "goto.com",
    "gotomeeting.com", "bluejeans.com", "whereby.com", "slack.com", "discord.com",
    "apple.com", "ringcentral.com", "jitsi.org", "8x8.vc"
  ];
  const MEETING_APP_NAMES = String.raw`(?:zoom|microsoft teams|teams|google meet|webex|skype|gotomeeting|bluejeans|meeting|video call|conference|interview)`;
  const MEETING_APP_CUE_RES = [
    new RegExp(String.raw`\b(?:download|install|update|get)\s+(?:the\s+|our\s+)?(?:latest\s+)?${MEETING_APP_NAMES}\s+(?:app|application|client|desktop app|sdk|plugin|extension|update|launcher|software)\b`),
    new RegExp(String.raw`\b${MEETING_APP_NAMES}\s+(?:app|client|sdk|plugin|launcher|software)\s+(?:is\s+)?(?:required|needed|outdated|out of date|not installed|missing)`),
    /\b(?:to|before you(?: can)?)\s+(?:join|enter|start)\s+(?:the\s+|this\s+|your\s+)?(?:meeting|interview|call|session|webinar)[^.]{0,60}\b(?:download|install|update)\b/
  ];
  const JOIN_CONTEXT_RE = /\b(?:join(?:ing)?|enter|start)\s+(?:the\s+|this\s+|your\s+)?(?:meeting|interview|call|session|conference|webinar)\b|\bmeeting id\b|\binvited you\b|\binterview(?:er)?\b/;
  const MEETING_BUTTON_RE = /\b(?:download|install|update)\b/;
  const MEETING_PAGE_MAX_CHARS = 4000;

  function isMeetingVendor(host) {
    const h = normalizeHost(host);
    return MEETING_VENDOR_DOMAINS.some((d) => h === d || h.endsWith("." + d));
  }

  /**
   * @param {string} host    page hostname
   * @param {string} text    visible page text
   * @param {{href: string, download: boolean, label: string}[]} actions
   *        the page's links and buttons (href is "" for a button)
   */
  function detectFakeMeetingApp(host, text, actions) {
    const norm = normalizeHost(host);
    if (!norm || isLocalhost(norm) || isTrustedDomain(norm) || isMeetingVendor(norm)) return false;
    const t = (text || "").toLowerCase().replace(/\s+/g, " ");
    if (t.length > MEETING_PAGE_MAX_CHARS) return false;
    if (!MEETING_APP_CUE_RES.some((re) => countsAsCue(t, re)) || !JOIN_CONTEXT_RE.test(t)) return false;

    let vendorLink = false, file = false, button = false;
    for (const a of actions || []) {
      const label = (a.label || "").toLowerCase();
      if (a.href) {
        let u = null;
        try { u = new URL(a.href); } catch { /* not a URL */ }
        if (u && isMeetingVendor(u.hostname)) { vendorLink = true; continue; }
        if (a.download || (u && EXECUTABLE_PATH_RE.test(u.pathname))) { file = true; continue; }
      }
      if (MEETING_BUTTON_RE.test(label)) button = true;
    }
    return file || (button && !vendorLink);
  }

  /* ── Browser-in-the-browser ──
     A fake sign-in "window" drawn inside the page: a box with an address bar
     that shows a real sign-in address (accounts.google.com, login.microsoft-
     online.com…) around a login form or frame, on a site that isn't that
     company's. A real popup is a separate browser window, so its address
     never appears as page text. contentScript passes only positioned boxes
     (fixed or absolute, popup-sized) whose text contains such an address. */
  const SIGN_IN_ADDRESS_RE = /\bhttps?:\/\/((?:accounts\.google\.com|login\.microsoftonline\.com|login\.live\.com|appleid\.apple\.com|(?:www\.)?facebook\.com|github\.com|discord\.com|steamcommunity\.com|(?:www\.)?paypal\.com|login\.yahoo\.com|x\.com|twitter\.com|(?:www\.)?linkedin\.com|id\.atlassian\.com|account\.live\.com))(?=[\/\s?#]|$)/i;

  function signInAddressIn(text) {
    const m = (text || "").match(SIGN_IN_ADDRESS_RE);
    return m ? m[1].toLowerCase() : "";
  }

  /* boxes: [{ text, hasLogin, hasFrame }] */
  function detectBrowserInBrowser(host, boxes) {
    const norm = normalizeHost(host);
    if (!norm || isLocalhost(norm)) return false;
    for (const box of boxes || []) {
      const shown = signInAddressIn(box.text);
      if (!shown || !(box.hasLogin || box.hasFrame)) continue;
      const shownReg = registrable(normalizeHost(shown));
      /* The company's own site showing its own address is fine. */
      if (registrable(norm) === shownReg) continue;
      return true;
    }
    return false;
  }

  /* ── Device-code phishing ──
     The page shows a short code and tells you to enter it at Microsoft's,
     GitHub's or Google's device sign-in page. Entering it signs the
     attacker's device into your account (EvilTokens and similar kits), and
     the sign-in itself happens on the real site, so no password field or
     lookalike ever appears. Docs that explain the flow are long pages on
     trusted domains; the lure is a short page with a code to copy. */
  const DEVICE_LOGIN_RE = /(?:microsoft\.com\/devicelogin|aka\.ms\/devicelogin|login\.microsoftonline\.com\/(?:common\/oauth2\/)?deviceauth|github\.com\/login\/device|google\.com\/device)\b/i;
  const DEVICE_CODE_RE = /\b(?:[A-Z0-9]{4}-[A-Z0-9]{4}|(?=[A-Z0-9]{8,9}\b)(?=[A-Z0-9]*\d)[A-Z0-9]*[A-Z][A-Z0-9]*)\b/;
  const ENTER_CODE_RE = /\b(?:enter|type|paste|use|input)\b[^.]{0,40}\bcode\b|\bcode\b[^.]{0,30}\b(?:below|above|shown)\b/i;
  const DEVICE_OWNER_DOMAINS = ["microsoft.com", "microsoftonline.com", "live.com", "aka.ms", "github.com", "google.com", "office.com", "azure.com"];
  const DEVICE_PAGE_MAX_CHARS = 4000;

  function detectDeviceCodePhish(host, text) {
    const norm = normalizeHost(host);
    if (!norm || isLocalhost(norm) || isTrustedDomain(norm)) return false;
    if (DEVICE_OWNER_DOMAINS.some((d) => norm === d || norm.endsWith("." + d))) return false;
    const t = (text || "").replace(/\s+/g, " ");
    if (t.length > DEVICE_PAGE_MAX_CHARS) return false;
    return DEVICE_LOGIN_RE.test(t) && ENTER_CODE_RE.test(t) && DEVICE_CODE_RE.test(t);
  }

  /* ── Refrigeration controllers open to the internet ──
     The 2026 supermarket fridge attacks (CERT-FR CERTFR-2026-ALE-012) went
     through controller web pages left on the public internet. This is not a
     phishing signal: guards.js shows a notice telling whoever opened the
     panel (usually the store or its contractor) that anyone can reach it.
     Only public IP addresses and dynamic-DNS names count, because a panel
     reached on the store network or through a VPN is the safe setup. */
  const CONTROL_PANEL_RE = /\b(?:AK-?S[MC] ?\d{3}A?|StoreView|XWEB(?: ?(?:\d{3,4}|EVO|Pro))?|Dixell|Danfoss|Copeland)\b/i;
  const PANEL_FAMILIES = [[/AK-?S[MC]|StoreView|Danfoss/i, "Danfoss"], [/XWEB|Dixell|Copeland/i, "Copeland/Dixell XWEB"]];
  const DYNAMIC_DNS = [
    "dyndns.org", "dyndns.biz", "dnsalias.com", "no-ip.org", "no-ip.biz", "noip.me", "ddns.net",
    "hopto.org", "zapto.org", "sytes.net", "duckdns.org", "dynu.net", "freeddns.org", "changeip.com",
    "myfritz.net", "synology.me"
  ];
  const PRIVATE_V4 = /^(?:0\.|10\.|127\.|169\.254\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/;

  function isPublicAddress(host) {
    const h = (host || "").toLowerCase();
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(h)) return !PRIVATE_V4.test(h);
    if (h.startsWith("[")) return !/^\[(?:::1?|f[cd]|fe[89ab])/.test(h); // loopback, unique-local, link-local
    return DYNAMIC_DNS.some((d) => h === d || h.endsWith("." + d));
  }

  /* The panel's product family, or "" when the page isn't one of these
     panels or isn't reached over the public internet. A match in the page
     text also needs a password field, so an article about the attacks
     doesn't count. */
  function detectExposedControlPanel(host, title, text, hasPassword) {
    if (!isPublicAddress(host)) return "";
    const t = title || "";
    const body = (text || "").slice(0, 3000);
    const src = CONTROL_PANEL_RE.test(t) ? t : hasPassword && CONTROL_PANEL_RE.test(body) ? body : "";
    if (!src) return "";
    return PANEL_FAMILIES.find(([re]) => re.test(src))[1];
  }

  /* ── Card skimmers ──
     networkHook.js reports the host when a request out of the page carries
     the card number typed into a card field (plain, URL-encoded or base64).
     Payment companies and the shop's own domains are expected destinations;
     anything else is a skimmer. The trusted-platform list does not apply:
     skimmers send cards to Google Analytics and free app hosting on purpose,
     because those requests look routine. */
  const PAYMENT_DOMAINS = [
    "stripe.com", "stripe.network", "paypal.com", "braintreegateway.com", "braintree-api.com",
    "adyen.com", "adyenpayments.com", "checkout.com", "squareup.com", "square.com",
    "authorize.net", "cybersource.com", "worldpay.com", "globalpay.com", "globalpayments.com",
    "razorpay.com", "payu.in", "payu.com", "cashfree.com", "paytm.in", "paytm.com",
    "ccavenue.com", "billdesk.com", "juspay.in", "mollie.com", "klarna.com", "afterpay.com",
    "affirm.com", "networkmerchants.com", "nmi.com", "bluesnap.com", "2checkout.com",
    "verifone.cloud", "nuvei.com", "safecharge.com", "moneris.com", "paysafe.com",
    "payeezy.com", "firstdata.com", "clover.com", "paymentech.com", "elavon.com",
    "opayo.co.uk", "sagepay.com", "shopifycs.com", "shopify.com", "bigcommerce.com",
    "recurly.com", "chargebee.com", "spreedly.com", "verygoodvault.com", "basistheory.com",
    "tokenex.com", "paddle.com", "fastspring.com", "dodopayments.com", "gocardless.com",
    "mercadopago.com", "pagseguro.com.br", "ebanx.com", "dlocal.com", "xendit.co",
    "midtrans.com", "paystack.co", "flutterwave.com", "yookassa.ru", "cardinalcommerce.com"
  ];

  function isPaymentHost(host) {
    const h = normalizeHost(host);
    return PAYMENT_DOMAINS.some((d) => h === d || h.endsWith("." + d));
  }

  function isExpectedCardDestination(pageHost, toHost) {
    const to = normalizeHost(toHost);
    if (!to || !isThirdParty(pageHost, to)) return true;
    if (isPaymentHost(to)) return true;
    /* The shop's own API on a sibling domain: shop.com → shop-api.com */
    const label = registrable(normalizeHost(pageHost)).split(".")[0];
    return label.length >= 4 && `-${to.replace(/[^a-z0-9]/g, "-")}-`.includes(`-${label}-`);
  }

  /* ── Sponsored search results ──
     Scam ads buy brand searches ("amazon business login") and lead to a
     fake sign-in page, sometimes followed by a fake CAPTCHA. An ad that names
     a brand next to sign-in wording but leads somewhere the brand does not
     own gets a warning badge. Resellers advertise brand products all the
     time, so product ads ("Microsoft 365 Business Premium") do not count. */
  const AD_LOGIN_INTENT_RE = /\b(?:sign[\s-]?in|log[\s-]?in|login|my account|account login|customer (?:service|support|care)|support (?:number|center|centre)|official (?:site|website)|wallet|verify|verification|password|billing)\b/;

  function adBrandMismatch(host, title) {
    const t = (title || "").toLowerCase();
    if (!AD_LOGIN_INTENT_RE.test(t)) return null;
    for (const brand of Object.keys(BRAND_DOMAINS)) {
      if (!new RegExp(`\\b${brand.toLowerCase()}\\b`).test(t)) continue;
      return matchTrustedBrand(host) === brand ? null : brand;
    }
    return null;
  }

  function isSensitiveFieldText(value) {
    return SENSITIVE_FIELD_RE.test((value || "").toLowerCase());
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

      /* Shared web infrastructure, not brand identity: half the web loads it. */
      if (INFRA_HOSTS.includes(targetHost)) continue;
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

  /* ── Paste Guard and download warnings (guards.js) ──
     Not scored signals: they act on what the user is about to do, so they
     ask before it happens instead of adding to the page's score. */

  /* A wallet recovery phrase is 12 to 24 lowercase words of 3 to 8 letters.
     None of these common words is in the BIP-39 list, so a search or chat
     message of the same shape is ruled out by containing one. ("that",
     "what", "you", "when" and "have" ARE in the list, so they can't help.) */
  const SEED_LENGTHS = new Set([12, 15, 18, 21, 24]);
  const NOT_SEED_WORDS = new Set([
    "the", "and", "with", "from", "how", "why", "your", "are", "was", "for", "not", "but",
    "its", "his", "her", "them", "than", "has", "had", "which", "who", "does", "did",
    "our", "out", "get", "got", "some"
  ]);

  function isSeedPhrase(text) {
    /* Phrases copied from a numbered list: "1. abandon 2. ability …" */
    const words = String(text || "").replace(/(^|\s)\d{1,2}[.):]?(?=\s)/g, " ").trim().split(/\s+/);
    if (!SEED_LENGTHS.has(words.length)) return false;
    return words.every((w) => /^[a-z]{3,8}$/.test(w) && !NOT_SEED_WORDS.has(w));
  }

  /* 13 to 19 digits, optionally grouped, passing the Luhn check every card
     number carries. */
  function isCardNumber(text) {
    const s = String(text || "").trim();
    if (!/^[\d -]{13,23}$/.test(s)) return false;
    const d = s.replace(/\D/g, "");
    if (d.length < 13 || d.length > 19 || /^(\d)\1+$/.test(d)) return false;
    let sum = 0;
    for (let i = 0; i < d.length; i++) {
      let n = +d[d.length - 1 - i];
      if (i % 2) { n *= 2; if (n > 9) n -= 9; }
      sum += n;
    }
    return sum % 10 === 0;
  }

  /* What is being pasted: "seed", "card", "password" (anything pasted into
     a password field) or null. */
  function classifyPaste(text, fieldType) {
    if (isSeedPhrase(text)) return "seed";
    if (isCardNumber(text)) return "card";
    if (fieldType === "password" && String(text || "").trim()) return "password";
    return null;
  }

  /* Files that run code when opened. Scripts are almost never something a
     website should hand an ordinary user; programs are, so those only warn
     when something else about the page or link is off (guards.js). */
  const SCRIPT_EXT = "hta|vbs|vbe|js|jse|wsf|wsh|ps1|bat|cmd|scr|pif|lnk|reg|cpl|msc|xll";
  const PROGRAM_EXT = "exe|msi|msix|appx|msixbundle|appxbundle|dmg|pkg|apk|iso|img|vhd|vhdx|jar|appimage";
  const RUNNABLE_RE = new RegExp(`\\.(${SCRIPT_EXT}|${PROGRAM_EXT})$`, "i");
  const SCRIPT_RE = new RegExp(`\\.(${SCRIPT_EXT})$`, "i");
  /* "invoice.pdf.exe", "invoice.pdf          .exe" */
  const DISGUISED_RE = new RegExp(`\\.(pdf|docx?|xlsx?|pptx?|txt|rtf|csv|jpe?g|png|gif|heic|mp[34]|mov|avi|wav|zip)\\s*\\.(${SCRIPT_EXT}|${PROGRAM_EXT})$|\\s{5,}\\.\\w+$`, "i");

  function downloadFileName(href, downloadAttr) {
    if (downloadAttr && downloadAttr.trim()) return downloadAttr.trim().split(/[\\/]/).pop();
    try {
      const u = new URL(href);
      if (!/^https?:$/.test(u.protocol)) return "";
      return decodeURIComponent(u.pathname.split("/").pop() || "");
    } catch { return ""; }
  }

  /* A link the user clicked: is it a file that runs code, and what kind?
     {kind: "disguised" | "smuggled" | "script" | "program", file} or null.
     "smuggled": the page built the file itself (blob: or data: link), a
     trick for getting malware past email and download filters. */
  function classifyDownload(href, downloadAttr) {
    const hasAttr = typeof downloadAttr === "string";
    const file = downloadFileName(href, downloadAttr);
    /* U+202E flips the rest of the name: "invoice‮fdp.exe" shows as
       "invoiceexe.pdf". */
    const flipped = /[‪-‮⁦-⁩]/.test(file);
    const clean = file.replace(/[‪-‮⁦-⁩]/g, "");
    if (!RUNNABLE_RE.test(clean)) return null;
    if (flipped || DISGUISED_RE.test(clean)) return { kind: "disguised", file: clean };
    if (/^(blob|data):/i.test(href)) return { kind: "smuggled", file: clean };
    if (SCRIPT_RE.test(clean)) {
      /* A plain link to a .js file opens it as text; it only lands on disk
         when the page asks for a download. */
      if (/\.jse?$/i.test(clean) && !hasAttr) return null;
      return { kind: "script", file: clean };
    }
    return { kind: "program", file: clean };
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

    /* Our own site: its help pages quote scam scripts on purpose */
    "phishclean.com",

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
    detectLookalikeDomain, levenshtein, BRAND_SLDS,
    detectRegionalScam, isSensitiveFieldText, isIndianOfficialHost,
    hasTollFreeNumber, detectTechSupportScam,
    detectNotificationBait, detectFakeShop, brandInShopHost,
    detectFakeCaptcha, isShellCommand,
    detectFakeBrowserUpdate, isBrowserVendor,
    detectFakeInterviewFix, detectFakeMeetingApp, isMeetingVendor,
    detectBrowserInBrowser, detectDeviceCodePhish,
    isPublicAddress, detectExposedControlPanel,
    isPaymentHost, isExpectedCardDestination, adBrandMismatch,
    isSeedPhrase, isCardNumber, classifyPaste, classifyDownload
  };
})();

