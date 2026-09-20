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

  const _fetch = window.fetch;
  window.fetch = function (input, init = {}) {
    try {
      const url = typeof input === "string" ? input : (input?.url || "");
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
})();
