/* PhishClean Secret Leak Scanner
   Passively scans inline <script> tags, meta tags, and data attributes
   for hardcoded API keys, secrets, and credentials.
   100% local — nothing leaves the browser.
*/
(() => {
  const PATTERNS = [
    {
      name: "AWS Access Key",
      regex: /(?:AKIA|ABIA|ACCA)[0-9A-Z]{16}/g,
      score: 30,
      isPrivateKey: false,
    },
    {
      name: "AWS Secret Key",
      regex: /(?:aws_secret_access_key|aws_secret_key|secret_key)\s*[=:]\s*['"][A-Za-z0-9/+=]{40}['"]/gi,
      score: 30,
      isPrivateKey: false,
    },
    {
      name: "Stripe Live Secret Key",
      regex: /sk_live_[0-9a-zA-Z]{24,}/g,
      score: 30,
      isPrivateKey: false,
    },
    {
      name: "GitHub Token",
      regex: /(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}/g,
      score: 30,
      isPrivateKey: false,
    },
    {
      name: "Google API Key",
      regex: /AIza[0-9A-Za-z_-]{35}/g,
      score: 15,
      isPrivateKey: false,
    },
    {
      name: "Slack Token",
      regex: /xox[baprs]-[0-9a-zA-Z-]{10,}/g,
      score: 30,
      isPrivateKey: false,
    },
    {
      name: "Twilio API Key",
      regex: /SK[0-9a-fA-F]{32}/g,
      score: 30,
      isPrivateKey: false,
    },
    {
      name: "SendGrid Key",
      regex: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g,
      score: 30,
      isPrivateKey: false,
    },
    {
      name: "Private Key",
      regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g,
      score: 40,
      isPrivateKey: true,
    },
    {
      name: "Hardcoded Bearer Token",
      regex: /['"]Bearer\s+[A-Za-z0-9_-]{20,}['"]/g,
      score: 25,
      isPrivateKey: false,
    },
    {
      name: "Supabase Service Role Key",
      regex: /service_role['"]?\s*[=:]\s*['"]?eyJ[A-Za-z0-9_-]{50,}/g,
      score: 30,
      isPrivateKey: false,
    },
  ];

  /* Known test / example key fragments — skip these */
  const TEST_FRAGMENTS = [
    "akiaiosfodnn7example", "wjalrxutnfemi",
    "sk_test_", "pk_test_",
    "ghp_xxxx", "your_api_key", "insert_your", "replace_me",
    "example", "sample", "test_key", "dummy", "placeholder",
  ];

  /* Domains where code samples with keys are expected */
  const DOC_DOMAINS = [
    "developer.mozilla.org", "docs.github.com", "docs.aws.amazon.com",
    "firebase.google.com", "supabase.com", "stripe.com",
    "stackoverflow.com", "github.com", "codesandbox.io",
    "codepen.io", "jsfiddle.net", "replit.com", "medium.com", "dev.to",
  ];

  function isTestKey(value) {
    const lower = value.toLowerCase();
    return TEST_FRAGMENTS.some((f) => lower.includes(f));
  }

  function isDocDomain(hostname) {
    return DOC_DOMAINS.some((d) => hostname === d || hostname.endsWith("." + d));
  }

  function scanText(text, results, seen) {
    for (const pattern of PATTERNS) {
      pattern.regex.lastIndex = 0;
      let match;
      while ((match = pattern.regex.exec(text)) !== null) {
        const value = match[0];
        const dedupeKey = pattern.name + ":" + value.substring(0, 20);
        if (seen.has(dedupeKey)) continue;
        seen.add(dedupeKey);
        if (isTestKey(value)) continue;
        results.push({
          name: pattern.name,
          score: pattern.score,
          isPrivateKey: pattern.isPrivateKey,
          snippet: value.substring(0, 20) + "...",
        });
      }
    }
  }

  /**
   * Scan page source for hardcoded secrets.
   * @returns {{ found, secrets[], hasPrivateKey }}
   */
  function scanPageSource() {
    if (isDocDomain(location.hostname)) {
      return { found: false, secrets: [], hasPrivateKey: false, skipped: true };
    }

    const secrets = [];
    const seen = new Set();

    /* 1. Inline <script> tags (no src) */
    for (const script of document.querySelectorAll("script:not([src])")) {
      const content = script.textContent;
      if (!content || content.length < 10) continue;
      scanText(content, secrets, seen);
    }

    /* 2. <meta> tags with long content */
    for (const meta of document.querySelectorAll("meta[content]")) {
      const content = meta.getAttribute("content");
      if (content && content.length > 20) {
        scanText(content, secrets, seen);
      }
    }

    /* 3. data-* attributes on body */
    const bodyData = document.body?.dataset || {};
    for (const val of Object.values(bodyData)) {
      if (val && val.length > 20) scanText(val, secrets, seen);
    }

    return {
      found: secrets.length > 0,
      secrets,
      hasPrivateKey: secrets.some((s) => s.isPrivateKey),
    };
  }

  /* Limits for external bundle scanning — keep it cheap and non-blocking. */
  const MAX_EXTERNAL_SCRIPTS = 6;
  const MAX_SCRIPT_BYTES = 512 * 1024; /* skip anything larger than 512 KB */

  /**
   * Scan same-origin external <script src> bundles for hardcoded secrets.
   * Most real leaks live in bundled JS, not inline tags. Cross-origin scripts
   * are skipped (fetch would be opaque and it's not this page's secret to leak).
   * @returns {Promise<{ found, secrets[], hasPrivateKey }>}
   */
  async function scanExternalScripts() {
    if (isDocDomain(location.hostname)) {
      return { found: false, secrets: [], hasPrivateKey: false, skipped: true };
    }

    const secrets = [];
    const seen = new Set();
    const origin = location.origin;

    const srcs = [];
    for (const script of document.querySelectorAll("script[src]")) {
      let abs;
      try { abs = new URL(script.src, location.href); } catch { continue; }
      if (abs.origin !== origin) continue; /* same-origin only */
      srcs.push(abs.href);
      if (srcs.length >= MAX_EXTERNAL_SCRIPTS) break;
    }

    await Promise.all(srcs.map(async (url) => {
      try {
        const res = await fetch(url, { credentials: "omit", cache: "force-cache" });
        if (!res.ok) return;
        const len = Number(res.headers.get("content-length") || 0);
        if (len && len > MAX_SCRIPT_BYTES) return;
        const text = await res.text();
        if (text.length > MAX_SCRIPT_BYTES) return;
        scanText(text, secrets, seen);
      } catch { /* network/CORS error — skip this bundle */ }
    }));

    return {
      found: secrets.length > 0,
      secrets,
      hasPrivateKey: secrets.some((s) => s.isPrivateKey),
    };
  }

  window.PhishCleanSecretScanner = { scanPageSource, scanExternalScripts, PATTERNS, DOC_DOMAINS };
})();
