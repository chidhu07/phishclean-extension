/* PhishClean search result badges
   Marks results on Google, Bing and DuckDuckGo before you click them: red for
   a reported phishing site, amber for a lookalike of a well-known brand,
   green for well-known sites. Unknown sites get no badge — no badge is not a
   "safe" verdict. Result hostnames are matched against the local copy of the
   reported-phishing list in the service worker; nothing leaves the device.
*/
(() => {
  const engine = window.PhishCleanRiskEngine;
  if (!engine) return;

  const BADGES_KEY = "phishclean_search_badges";
  const LICENSE_KEY = "phishclean_license";
  const DONE_ATTR = "phishcleanBadge";

  /* Each engine: where its result title links are, and how to read the real
     destination out of its redirect link. */
  const ENGINES = [
    {
      host: /^(www\.)?google\.[a-z]{2,3}(\.[a-z]{2})?$/,
      path: /^\/search/,
      titles: () => Array.from(document.querySelectorAll("#search a h3, #rso a h3"), (h3) => ({ link: h3.closest("a"), slot: h3 }))
    },
    {
      host: /^(www\.|cn\.)?bing\.com$/,
      path: /^\/search/,
      titles: () => Array.from(document.querySelectorAll("#b_results h2 > a[href]"), (a) => ({ link: a, slot: a.parentElement }))
    },
    {
      host: /^(html\.|lite\.)?duckduckgo\.com$/,
      path: /^\/(html|lite)?\/?$/,
      titles: () => Array.from(document.querySelectorAll('a[data-testid="result-title-a"], a.result__a, a.result-link'), (a) => ({ link: a, slot: a }))
    }
  ];

  const current = ENGINES.find((e) => e.host.test(location.hostname) && e.path.test(location.pathname));
  if (!current) return;

  /* Google: /url?q=…  Bing: /ck/a?…&u=a1<base64url>  DuckDuckGo: /l/?uddg=… */
  function resultUrl(href) {
    let u;
    try { u = new URL(href, location.href); } catch { return null; }
    if (engine.isThirdParty(location.hostname, u.hostname)) return u.href;
    const p = u.searchParams;
    const direct = p.get("q") || p.get("url") || p.get("uddg");
    if (direct && /^https?:\/\//i.test(direct)) return direct;
    const bing = p.get("u");
    if (bing && bing.startsWith("a1")) {
      try {
        const b64 = bing.slice(2).replace(/-/g, "+").replace(/_/g, "/");
        const decoded = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
        if (/^https?:\/\//i.test(decoded)) return decoded;
      } catch { /* not base64 */ }
    }
    return null;
  }

  function isIpHost(h) {
    return /^(\d{1,3}\.){3}\d{1,3}$/.test(h) || h.startsWith("[");
  }

  /* Lookalikes for a search page are stricter than on the page itself: a
     result list is full of real businesses whose names start with a brand
     (applebees.com) or sit one letter from a short one (dhs.gov vs dhl), so
     only typosquats of names of 5+ letters and brands standing as their own
     hyphen/dot token (paypal-secure.com) are marked. */
  function lookalikeOf(host) {
    const hit = engine.detectLookalikeDomain(host, false);
    if (!hit?.brand) return null;
    if (hit.kind === "typosquat") return hit.brand.length >= 5 ? hit.brand : null;
    const tokens = `-${host.replace(/[^a-z0-9]/g, "-")}-`;
    return tokens.includes(`-${hit.brand}-`) ? hit.brand : null;
  }

  const brandName = (b) => b.charAt(0).toUpperCase() + b.slice(1);

  function verdict(host, listed, pro) {
    if (listed) {
      return { level: "danger", label: "Reported phishing", tip: "PhishClean: this site is on the reported-phishing list. Don't enter passwords or card details on it." };
    }
    if (engine.isTrustedDomain(host)) {
      return { level: "safe", tip: "PhishClean: a well-known site" };
    }
    if (!pro) return null;
    const brand = lookalikeOf(host);
    if (brand) {
      return { level: "caution", label: "Lookalike", tip: `PhishClean: this address looks like ${brandName(brand)} but is not ${brandName(brand)}'s site.` };
    }
    if (host.split(".").some((l) => l.startsWith("xn--"))) {
      return { level: "caution", tip: "PhishClean: this address uses lookalike international characters." };
    }
    if (isIpHost(host)) {
      return { level: "caution", tip: "PhishClean: this result links to a bare IP address, not a named site." };
    }
    return null;
  }

  const COLORS = {
    danger:  { fg: "#ffffff", bg: "#dc2626" },
    caution: { fg: "#78350f", bg: "#fcd34d" },
    safe:    { fg: "#166534", bg: "#dcfce7" }
  };
  const ICON = {
    danger: "&#x2715;",
    caution: "!",
    safe: "&#x2713;"
  };

  function badge(v) {
    const c = COLORS[v.level];
    const el = document.createElement("span");
    el.className = "phishclean-search-badge";
    el.dataset.level = v.level;
    el.setAttribute("role", "img");
    el.setAttribute("aria-label", v.tip);
    el.title = v.tip;
    el.innerHTML = `<span aria-hidden="true">${ICON[v.level]}</span>${v.label ? `<span>${v.label}</span>` : ""}`;
    el.style.cssText = [
      "display:inline-flex", "align-items:center", "gap:4px",
      "vertical-align:middle", "margin:0 6px 0 0",
      v.label ? "padding:1px 7px" : "width:18px;justify-content:center",
      "height:18px", "border-radius:9px",
      `background:${c.bg}`, `color:${c.fg}`,
      "font:600 11px/18px -apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif",
      "letter-spacing:0", "text-decoration:none", "white-space:nowrap", "cursor:help"
    ].join(" !important;") + " !important";
    /* The badge sits inside the result link; a click on it is for reading the
       tip, not for leaving. */
    el.addEventListener("click", (e) => { e.preventDefault(); e.stopPropagation(); }, true);
    return el;
  }

  let pro = false;

  async function mark() {
    const pending = [];
    for (const { link, slot } of current.titles()) {
      if (!link || !slot || slot.dataset[DONE_ATTR]) continue;
      const url = resultUrl(link.getAttribute("href") || "");
      const host = url && engine.hostname(url);
      if (!host || !/^https?:/i.test(url)) continue;
      slot.dataset[DONE_ATTR] = "1";
      link.dataset.phishcleanSkip = "1"; /* no hover tooltip on top of the badge */
      pending.push({ slot, host: host.replace(/^www\./, "") });
    }
    if (!pending.length) return;

    let listed = new Set();
    try {
      const hosts = [...new Set(pending.map((p) => p.host))];
      const r = await chrome.runtime.sendMessage({ type: "FEED_CHECK_MANY", hosts });
      listed = new Set(r?.listed || []);
    } catch { /* worker unavailable — heuristics still apply */ }

    for (const { slot, host } of pending) {
      const v = verdict(host, listed.has(host), pro);
      if (v) slot.prepend(badge(v));
    }
  }

  let timer = 0;
  const schedule = () => { clearTimeout(timer); timer = setTimeout(mark, 300); };

  chrome.storage.local.get([BADGES_KEY, LICENSE_KEY]).then((data) => {
    if (data[BADGES_KEY] === false) return;
    const license = data[LICENSE_KEY];
    pro = !!(license?.trial_active || license?.is_paid);
    mark();
    /* Results load in pages (Google "More results", DuckDuckGo infinite
       scroll) and on in-place navigations between searches. */
    new MutationObserver(schedule).observe(document.documentElement, { childList: true, subtree: true });
  }).catch(() => {});

  window.PhishCleanSearchBadges = { resultUrl, verdict, lookalikeOf };
})();
