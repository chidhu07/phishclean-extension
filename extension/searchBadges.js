/* PhishClean link badges
   Marks results on Google, Bing, DuckDuckGo and Brave Search before you click
   them: red for a reported phishing site, amber for a lookalike of a
   well-known brand, green for well-known sites. Unknown sites get no badge —
   no badge is not a "safe" verdict.

   The same red and amber marks (never green: a mailbox or chat full of green
   ticks is noise) go on links in webmail, social media, chat apps and AI
   answers, where phishing links arrive without a search page around them.

   Hostnames are matched against the local copy of the reported-phishing list
   in the service worker; nothing leaves the device.
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
      titles: () => [
        ...Array.from(document.querySelectorAll("#search a h3, #rso a h3"), (h3) => ({ link: h3.closest("a"), slot: h3 })),
        /* Sponsored results sit above and below the results, outside #search. */
        ...Array.from(document.querySelectorAll('#tads a [role="heading"], #tvcap a [role="heading"], #bottomads a [role="heading"], #tads a h3, #bottomads a h3'),
          (heading) => ({ link: heading.closest("a"), slot: heading }))
      ]
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
    },
    {
      host: /^search\.brave\.com$/,
      path: /^\/search/,
      titles: () => Array.from(
        document.querySelectorAll('#results [data-type="web"] a[href^="http"], #results a.heading-serpresult'),
        (a) => ({ link: a, slot: a.querySelector(".search-snippet-title, .snippet-title, .title") })
      )
    }
  ];

  /* Places where links reach people with no search page around them. Every
     outside link on the page counts: these apps' own navigation stays on
     their own domain, so what is left is links people were sent. */
  const SURFACES = [
    /^mail\.google\.com$/, /^outlook\.(live|office|office365)\.com$/, /^mail\.yahoo\.com$/, /^mail\.aol\.com$/,
    /^(www\.|m\.)?facebook\.com$/, /^(www\.)?messenger\.com$/, /^(www\.)?instagram\.com$/,
    /^(x|twitter)\.com$/, /^(www\.|old\.|new\.)?reddit\.com$/, /^(www\.)?linkedin\.com$/,
    /^(www\.|m\.)?youtube\.com$/, /^web\.whatsapp\.com$/, /^web\.telegram\.org$/,
    /^discord\.com$/, /^app\.slack\.com$/, /^teams\.(microsoft|live)\.com$/,
    /^chatgpt\.com$/, /^chat\.openai\.com$/, /^(www\.)?perplexity\.ai$/, /^gemini\.google\.com$/,
    /^copilot\.microsoft\.com$/, /^claude\.ai$/, /^chat\.deepseek\.com$/, /^(www\.)?meta\.ai$/, /^grok\.com$/,
    /^search\.brave\.com$/
  ];

  const engineHere = ENGINES.find((e) => e.host.test(location.hostname) && e.path.test(location.pathname));
  const surfaceHere = SURFACES.some((re) => re.test(location.hostname));
  if (!engineHere && !surfaceHere) return;

  /* Outside links on a surface page that have text to put a badge in front
     of (a badge inside an image link would push the picture around). */
  function surfaceLinks() {
    const found = [];
    for (const a of document.querySelectorAll("a[href]")) {
      if (found.length >= 400) break;
      if (a.dataset[DONE_ATTR] || a.closest(".phishclean-search-badge")) continue;
      if (!/^https?:/i.test(a.href) || !(a.textContent || "").trim()) continue;
      found.push({ link: a, slot: a, surface: true });
    }
    return found;
  }

  /* Brave Search puts its AI answer beside the results, so it is both: the
     results get the full badges, then every other outside link the surface
     marks. */
  const current = {
    titles: () => [
      ...(engineHere ? engineHere.titles() : []),
      ...(surfaceHere ? surfaceLinks() : [])
    ]
  };

  /* Link wrappers that mail and social sites put around outside links, and
     the parameter that holds the real address. */
  const REDIRECTORS = [
    [/(^|\.)safelinks\.protection\.outlook\.com$/, "url"],
    [/^(l|lm)\.facebook\.com$/, "u"], [/^l\.instagram\.com$/, "u"],
    [/^l\.messenger\.com$/, "u"], [/^out\.reddit\.com$/, "url"],
    [/^(www\.)?youtube\.com$/, "q", /^\/redirect/], [/^(www\.)?linkedin\.com$/, "url", /^\/redir\//],
    [/^(www\.)?google\.[a-z.]+$/, "q", /^\/url$/], [/^slack-redir\.net$/, "url"]
  ];

  function unwrap(u) {
    for (const [host, param, path] of REDIRECTORS) {
      if (!host.test(u.hostname) || (path && !path.test(u.pathname))) continue;
      const real = u.searchParams.get(param);
      return real && /^https?:\/\//i.test(real) ? real : null;
    }
    return undefined;
  }

  /* X shows the real address as the link text and hides it behind t.co. */
  function shownAddress(text) {
    const m = (text || "").trim().match(/^(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/?#]|…|$)/i);
    return m ? `https://${m[1]}/` : null;
  }

  /* Google: /url?q=…  Google ads: googleadservices.com/pagead/aclk?…&adurl=…
     Bing: /ck/a?…&u=a1<base64url>  DuckDuckGo: /l/?uddg=…
     Outlook, Facebook, YouTube, LinkedIn, Reddit: see REDIRECTORS. */
  function resultUrl(href, text = "") {
    let u;
    try { u = new URL(href, location.href); } catch { return null; }
    if (/(^|\.)googleadservices\.com$/.test(u.hostname) || u.pathname.endsWith("/aclk")) {
      const ad = u.searchParams.get("adurl");
      return ad && /^https?:\/\//i.test(ad) ? ad : null;
    }
    const unwrapped = unwrap(u);
    if (unwrapped !== undefined) return unwrapped;
    if (u.hostname === "t.co") return shownAddress(text);
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

  /* Router pages and local servers that AI answers and chats link to. */
  function isPrivateIp(h) {
    return /^(10\.|127\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.)/.test(h) || h === "[::1]";
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

  const AD_SELECTOR = '#tads, #tvcap, #bottomads, .b_ad, .result--ad, [data-testid="ad"], [data-text-ad]';

  function verdict(host, listed, pro, adTitle = "") {
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
    const adBrand = adTitle && engine.adBrandMismatch(host, adTitle);
    if (adBrand) {
      return { level: "caution", label: `Not ${adBrand}`, tip: `PhishClean: this ad mentions ${adBrand} sign-in or support, but leads to ${host}, not ${adBrand}'s site. Scam ads copy brand names; type the brand's address yourself.` };
    }
    if (host.split(".").some((l) => l.startsWith("xn--"))) {
      return { level: "caution", tip: "PhishClean: this address uses lookalike international characters." };
    }
    if (isIpHost(host) && !isPrivateIp(host)) {
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
    for (const { link, slot, surface } of current.titles()) {
      /* On Brave Search a result link comes round again as a surface link. */
      if (!link || !slot || slot.dataset[DONE_ATTR] || (surface && link.dataset[DONE_ATTR])) continue;
      const url = resultUrl(link.getAttribute("href") || "", link.textContent);
      const host = url && engine.hostname(url);
      if (!host || !/^https?:/i.test(url)) continue;
      slot.dataset[DONE_ATTR] = "1";
      link.dataset[DONE_ATTR] = "1";
      /* A surface's links back to itself (profiles, threads) need no mark. */
      if (surface && !engine.isThirdParty(location.hostname, host)) continue;
      const adTitle = link.closest(AD_SELECTOR) ? (slot.textContent || "") : "";
      pending.push({ link, slot, surface, host: host.replace(/^www\./, ""), adTitle });
    }
    if (!pending.length) return;

    let listed = new Set();
    try {
      const hosts = [...new Set(pending.map((p) => p.host))];
      const r = await chrome.runtime.sendMessage({ type: "FEED_CHECK_MANY", hosts });
      listed = new Set(r?.listed || []);
    } catch { /* worker unavailable — heuristics still apply */ }

    for (const { link, slot, surface, host, adTitle } of pending) {
      const v = verdict(host, listed.has(host), pro, adTitle);
      if (!v || (surface && v.level === "safe")) continue;
      link.dataset.phishcleanSkip = "1"; /* no hover tooltip on top of the badge */
      slot.prepend(badge(v));
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

  window.PhishCleanSearchBadges = { resultUrl, verdict, lookalikeOf, isPrivateIp };
})();
