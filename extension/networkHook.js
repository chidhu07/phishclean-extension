/* PhishClean network hook — injected into page context as web_accessible_resource.
   Intercepts fetch/XHR Authorization headers sent to third-party domains
   and notifies the content script via nonce-authenticated postMessage. */
(() => {
  const nc = document.currentScript?.dataset?.nonce || "";
  const h = location.hostname;
  const hn = u => { try { return new URL(u, location.href).hostname; } catch { return ""; } };
  const MT = new Set(["co.uk","co.in","co.jp","co.kr","co.nz","co.za","co.id","co.th","com.au","com.br","com.cn","com.hk","com.mx","com.sg","com.tw","com.tr","org.uk","org.au","net.au","ac.uk","gov.uk","gov.in","ne.jp","or.jp"]);
  const rg = d => { const p = d.split("."); if (p.length < 2) return d; const l2 = p.slice(-2).join("."); return p.length >= 3 && MT.has(l2) ? p.slice(-3).join(".") : l2; };
  const tp = (a, b) => rg(a) !== rg(b);

  /* Card skimmers: a script on a checkout page sending the card number typed
     into a card field to another site. Only the destination host is
     reported; the content script decides whether it is a payment company.
     The card number itself never leaves this function. */
  const CARD_FIELD_RE = /card|cc-?num|cc-?number|\bpan\b|kartennummer|tarjeta|carte|cart[aã]o/i;
  const luhn = (d) => {
    let sum = 0, alt = false;
    for (let i = d.length - 1; i >= 0; i--) {
      let n = d.charCodeAt(i) - 48;
      if (alt) { n *= 2; if (n > 9) n -= 9; }
      sum += n; alt = !alt;
    }
    return sum % 10 === 0;
  };
  const typedCards = () => {
    const out = [];
    for (const el of document.querySelectorAll("input")) {
      const d = (el.value || "").replace(/[\s-]/g, "");
      if (!/^\d{13,19}$/.test(d) || !luhn(d)) continue;
      if (CARD_FIELD_RE.test([el.name, el.id, el.autocomplete, el.placeholder, el.getAttribute("aria-label")].join(" "))) out.push(d);
    }
    return out;
  };
  const unb64 = (m) => { try { const b = m.replace(/-/g, "+").replace(/_/g, "/"); return atob(b + "=".repeat((4 - (b.length % 4)) % 4)); } catch { return ""; } };
  const decoded = (s) => {
    let out = s;
    try { out += " " + decodeURIComponent(s.replace(/\+/g, " ")); } catch { /* not URL-encoded */ }
    for (const m of out.match(/[A-Za-z0-9+/_-]{16,}={0,2}/g) || []) out += " " + unb64(m);
    return out;
  };
  const bodyText = (b) => {
    try {
      if (b == null) return "";
      if (typeof b === "string") return b;
      if (b instanceof URLSearchParams) return b.toString();
      if (b instanceof FormData) return [...b.entries()].map(([k, v]) => k + "=" + (typeof v === "string" ? v : "")).join("&");
      if (b instanceof ArrayBuffer || ArrayBuffer.isView(b)) return new TextDecoder().decode(b);
    } catch { /* unreadable body */ }
    return "";
  };
  const checkCard = (url, body) => {
    try {
      const to = hn(String(url || ""));
      if (!to || !tp(h, to)) return;
      const cards = typedCards();
      if (!cards.length) return;
      const hay = decoded(String(url) + " " + bodyText(body)).replace(/[\s-]/g, "");
      if (cards.some((c) => hay.includes(c) || hay.includes([...c].reverse().join("")))) {
        window.postMessage({ source: "phishclean", type: "CARD_SENT", to, nonce: nc }, "*");
      }
    } catch { /* swallow */ }
  };

  const _fetch = window.fetch;
  window.fetch = function (input, init = {}) {
    try {
      const url = typeof input === "string" ? input : (input?.url || "");
      checkCard(url, init?.body);
      const hd = new Headers(init.headers || input?.headers || {});
      if (hd.has("Authorization")) {
        const to = hn(url);
        if (to && tp(h, to)) window.postMessage({ source: "phishclean", type: "AUTH_HEADER_THIRD_PARTY", nonce: nc }, "*");
      }
    } catch { /* swallow */ }
    return _fetch.apply(this, arguments);
  };

  const _open = XMLHttpRequest.prototype.open;
  const _setH = XMLHttpRequest.prototype.setRequestHeader;
  const _send = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.send = function (body) { checkCard(this.__pUrl, body); return _send.apply(this, arguments); };
  XMLHttpRequest.prototype.open = function (m, url) { this.__pUrl = url; return _open.apply(this, arguments); };
  XMLHttpRequest.prototype.setRequestHeader = function (n, v) {
    try {
      if (n.toLowerCase() === "authorization") {
        const to = hn(this.__pUrl || "");
        if (to && tp(h, to)) window.postMessage({ source: "phishclean", type: "AUTH_HEADER_THIRD_PARTY", nonce: nc }, "*");
      }
    } catch { /* swallow */ }
    return _setH.apply(this, arguments);
  };

  /* The other ways skimmers send data out: beacons, image pixels, sockets. */
  if (Navigator.prototype.sendBeacon) {
    const _beacon = Navigator.prototype.sendBeacon;
    Navigator.prototype.sendBeacon = function (url, data) { checkCard(url, data); return _beacon.apply(this, arguments); };
  }
  const imgSrc = Object.getOwnPropertyDescriptor(HTMLImageElement.prototype, "src");
  if (imgSrc?.set) {
    Object.defineProperty(HTMLImageElement.prototype, "src", {
      ...imgSrc,
      set(v) { checkCard(v, ""); return imgSrc.set.call(this, v); }
    });
  }
  if (window.WebSocket) {
    const _wsSend = WebSocket.prototype.send;
    WebSocket.prototype.send = function (data) { checkCard(this.url, data); return _wsSend.apply(this, arguments); };
  }
})();
