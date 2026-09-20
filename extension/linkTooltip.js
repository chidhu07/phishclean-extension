/* PhishClean Link Tooltip
   Hover over any link to see a safety indicator.
   Runs URL-level checks using riskEngine.js — no network calls, 100% local.
*/
(() => {
  const engine = window.PhishCleanRiskEngine;
  if (!engine) return;

  /* ── config ── */
  const DEBOUNCE_MS = 300;
  const TOOLTIP_OFFSET = 8;
  const MAX_CACHE = 500;

  /* Known URL shorteners — display text is more meaningful than href for these */
  const SHORTENERS = new Set([
    "t.co", "bit.ly", "goo.gl", "tinyurl.com", "ow.ly", "is.gd",
    "buff.ly", "dlvr.it", "lnkd.in", "rb.gy", "cutt.ly", "shorturl.at"
  ]);

  /* ── URL-level checks ── */

  function hasPunycode(href) {
    try {
      const h = new URL(href).hostname;
      return h.startsWith("xn--") || /xn--/.test(h);
    } catch { return false; }
  }

  function isIpUrl(href) {
    try {
      const h = new URL(href).hostname;
      return /^(\d{1,3}\.){3}\d{1,3}$/.test(h) || h.startsWith("[");
    } catch { return false; }
  }

  function hasTextMismatch(anchor) {
    const text = (anchor.textContent || "").trim();
    if (!/^https?:\/\//i.test(text) && !/^www\./i.test(text)) return false;
    try {
      const textHost = engine.hostname(text.startsWith("www.") ? "https://" + text : text);
      const hrefHost = engine.hostname(anchor.href);
      if (!textHost || !hrefHost) return false;
      /* Shortener hrefs always mismatch display text — that's normal */
      if (SHORTENERS.has(hrefHost)) return false;
      return engine.isThirdParty(textHost, hrefHost);
    } catch { return false; }
  }

  function isDowngrade(href) {
    try {
      return location.protocol === "https:" && new URL(href).protocol === "http:";
    } catch { return false; }
  }

  function hasSuspiciousExt(href) {
    try {
      const path = new URL(href).pathname.toLowerCase();
      return /\.(exe|scr|bat|cmd|msi|ps1|vbs|jar|apk|dmg)$/i.test(path);
    } catch { return false; }
  }

  function hasTooManySubdomains(href) {
    try {
      const parts = new URL(href).hostname.split(".");
      return parts.length >= 5;
    } catch { return false; }
  }

  /**
   * Get the "real" URL to check.
   * For shorteners like t.co, use the visible text if it looks like a URL.
   */
  function resolveDisplayUrl(anchor) {
    const href = anchor.href || "";
    try {
      const hrefHost = new URL(href).hostname;
      if (SHORTENERS.has(hrefHost)) {
        const text = (anchor.textContent || "").trim();
        if (/^https?:\/\//i.test(text)) return text;
        if (/^[a-z0-9][\w.-]+\.[a-z]{2,}/i.test(text)) return "https://" + text;
      }
    } catch {}
    return href;
  }

  /**
   * Analyze a link and return { level, signals, displayHost }
   */
  function analyzeLink(anchor) {
    const rawHref = anchor.href;
    if (!rawHref) return null;

    try {
      const proto = new URL(rawHref).protocol;
      if (proto !== "http:" && proto !== "https:") return null;
    } catch { return null; }

    /* Resolve the display URL (handles t.co etc.) */
    const href = resolveDisplayUrl(anchor);
    const linkHost = engine.hostname(href);
    if (!linkHost) return null;

    const displayHost = linkHost;

    /* Skip localhost */
    if (engine.isLocalhost(linkHost)) return null;

    /* Trusted domains — show green checkmark */
    if (engine.isTrustedDomain(linkHost)) {
      return { level: "safe", signals: [], displayHost };
    }

    /* Same-domain links — show green checkmark */
    if (!engine.isThirdParty(location.hostname, linkHost)) {
      return { level: "safe", signals: [], displayHost };
    }

    const signals = [];

    if (hasPunycode(href)) signals.push("Punycode domain — possible lookalike");
    if (isIpUrl(href)) signals.push("Links to a raw IP address");
    if (hasTextMismatch(anchor)) signals.push("Display text doesn't match actual URL");
    if (isDowngrade(href)) signals.push("HTTP link on HTTPS page — possible downgrade");
    if (engine.isJwtLike(href)) signals.push("JWT token found in URL");
    if (engine.hasSuspiciousQuery(href)) signals.push("Suspicious auth parameters in URL");
    if (engine.hasCredentialInQuery(href)) signals.push("Password exposed in URL");
    if (hasSuspiciousExt(href)) signals.push("Links to a potentially dangerous file type");
    if (hasTooManySubdomains(href)) signals.push("Excessive subdomains — possible spoofing");

    /* Check if the shortener is hiding the real destination */
    try {
      const rawHost = new URL(rawHref).hostname;
      if (SHORTENERS.has(rawHost)) {
        const text = (anchor.textContent || "").trim();
        if (!/^https?:\/\//i.test(text) && !/^[a-z0-9][\w.-]+\.[a-z]{2,}/i.test(text)) {
          signals.push("Shortened URL — destination hidden");
        }
      }
    } catch {}

    const level = signals.length >= 2 ? "danger" : signals.length === 1 ? "caution" : "safe";
    return { level, signals, displayHost };
  }

  /* ── cache ── */
  const cache = new Map();

  function getCacheKey(anchor) {
    return (anchor.href || "") + "|" + (anchor.textContent || "").trim().substring(0, 50);
  }

  /* ── tooltip UI (plain DOM, all inline styles to avoid page CSS conflicts) ── */
  let tooltipEl = null;
  let currentAnchor = null;
  let debounceTimer = null;

  function ensureTooltip() {
    if (tooltipEl) return;
    tooltipEl = document.createElement("div");
    tooltipEl.id = "phishclean-link-tooltip";
    document.body.appendChild(tooltipEl);
  }

  const THEME = {
    safe:    { bg: "#f0fdf4", border: "#86efac", text: "#166534", icon: "\u2713", iconClass: "safe", label: "Link looks safe" },
    caution: { bg: "#fffbeb", border: "#fcd34d", text: "#92400e", icon: "!", iconClass: "caution", label: "Proceed with caution" },
    danger:  { bg: "#fef2f2", border: "#fca5a5", text: "#991b1b", icon: "\u2717", iconClass: "danger", label: "Suspicious link" }
  };

  function showTooltip(anchor, result) {
    ensureTooltip();
    const t = THEME[result.level];
    const rect = anchor.getBoundingClientRect();

    /* ── Safe links: small green checkmark only ── */
    if (result.level === "safe") {
      tooltipEl.innerHTML = `<span style="color:#16a34a;font-size:13px;font-weight:bold">&#x2713;</span>`;
      const top = rect.top + (rect.height / 2) - 12;
      const left = rect.right + 4;
      tooltipEl.style.cssText = [
        "position:fixed",
        "z-index:2147483647",
        "pointer-events:none",
        "width:22px",
        "height:22px",
        "border-radius:50%",
        "background:#dcfce7",
        "border:1px solid #86efac",
        "display:flex",
        "align-items:center",
        "justify-content:center",
        "box-shadow:0 2px 6px rgba(0,0,0,0.12)",
        `top:${top}px`,
        `left:${left}px`,
        "visibility:visible",
        "opacity:1"
      ].join(" !important;") + " !important";
      return;
    }

    /* ── Caution / Danger: full tooltip with signals ── */
    const iconBg = { caution: "#fef3c7", danger: "#fee2e2" }[result.level];

    let html = `<span style="display:inline-flex;align-items:center;justify-content:center;width:16px;height:16px;border-radius:50%;font-size:10px;background:${iconBg}">${t.icon}</span> <b>${t.label}</b>`;

    if (result.signals.length > 0) {
      html += `<br/>`;
      result.signals.forEach(s => { html += `• ${s}<br/>`; });
    }

    if (result.displayHost) {
      html += `<small style="color:#64748b">&rarr; ${result.displayHost}</small>`;
    }

    let top = rect.bottom + TOOLTIP_OFFSET;
    let left = rect.left;
    if (left > window.innerWidth - 300) left = window.innerWidth - 300;
    if (left < 8) left = 8;
    if (top > window.innerHeight - 60) top = rect.top - 60;

    tooltipEl.innerHTML = html;
    tooltipEl.style.cssText = [
      "position:fixed",
      "z-index:2147483647",
      "pointer-events:none",
      "padding:8px 12px",
      "border-radius:10px",
      "font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif",
      "font-size:12px",
      "line-height:1.5",
      "max-width:340px",
      "box-shadow:0 4px 16px rgba(0,0,0,0.18)",
      "white-space:normal",
      "text-align:left",
      `background:${t.bg}`,
      `border:1px solid ${t.border}`,
      `color:${t.text}`,
      `top:${top}px`,
      `left:${left}px`,
      "display:block",
      "visibility:visible",
      "opacity:1"
    ].join(" !important;") + " !important";

  }

  function hideTooltip() {
    if (tooltipEl) {
      tooltipEl.style.cssText = "display:none !important";
    }
    currentAnchor = null;
  }

  /* ── event handling ── */

  function findAnchor(el) {
    let depth = 0;
    while (el && el !== document.body && depth < 10) {
      if (el.tagName === "A" && el.href && !el.dataset.phishcleanSkip) return el;
      el = el.parentElement;
      depth++;
    }
    return null;
  }

  document.addEventListener("mouseover", (e) => {
    const anchor = findAnchor(e.target);

    if (!anchor) {
      if (currentAnchor) {
        clearTimeout(debounceTimer);
        hideTooltip();
      }
      return;
    }

    if (anchor === currentAnchor) return;

    clearTimeout(debounceTimer);
    hideTooltip();
    currentAnchor = anchor;

    debounceTimer = setTimeout(() => {
      if (currentAnchor !== anchor) return;

      const key = getCacheKey(anchor);
      let result = cache.get(key);

      if (!result) {
        result = analyzeLink(anchor);
        if (result && cache.size < MAX_CACHE) cache.set(key, result);
      }

      if (result && currentAnchor === anchor) {
        showTooltip(anchor, result);
      }
    }, DEBOUNCE_MS);
  }, true);

  document.addEventListener("mouseout", (e) => {
    const anchor = findAnchor(e.target);
    if (anchor && anchor === currentAnchor) {
      clearTimeout(debounceTimer);
      hideTooltip();
    }
  }, true);

  window.addEventListener("scroll", () => {
    if (currentAnchor) {
      clearTimeout(debounceTimer);
      hideTooltip();
    }
  }, { passive: true });

})();
