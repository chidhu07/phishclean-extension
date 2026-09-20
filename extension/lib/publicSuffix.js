/* PhishClean shared public-suffix / registrable-domain logic.
   Single source of truth used by the service worker (importScripts) and the
   content-script world (loaded before riskEngine.js). Attaches to globalThis
   so it works in both the worker (`self`) and page-isolated (`window`) contexts.

   NOTE: networkHook.js runs in the *page* context (a web_accessible_resource)
   and cannot see this global, so it keeps an inline copy — keep MULTI_TLDS in
   sync with the list below if you edit it.
*/
(function (root) {
  /* Multi-part public suffixes where the registrable domain is the third label
     from the right (e.g. amazon.co.uk, not co.uk). Not exhaustive, but covers
     the suffixes real users hit — divergence here causes third-party
     false-positives/negatives. */
  const MULTI_TLDS = new Set([
    /* United Kingdom */
    "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk", "ac.uk", "gov.uk", "nhs.uk",
    /* Australia / NZ */
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz", "school.nz",
    /* India */
    "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in", "gov.in", "ac.in", "edu.in", "res.in", "nic.in",
    /* Japan / Korea */
    "co.jp", "ne.jp", "or.jp", "go.jp", "ac.jp", "ad.jp", "ed.jp", "gr.jp", "lg.jp",
    "co.kr", "ne.kr", "or.kr", "go.kr", "re.kr", "pe.kr",
    /* Brazil / Mexico / other LatAm */
    "com.br", "net.br", "org.br", "gov.br", "edu.br",
    "com.mx", "org.mx", "gob.mx", "edu.mx",
    "com.ar", "net.ar", "org.ar", "gob.ar", "edu.ar",
    /* East / SE Asia */
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
    "com.hk", "org.hk", "net.hk", "gov.hk", "edu.hk", "idv.hk",
    "com.tw", "org.tw", "net.tw", "gov.tw", "edu.tw",
    "com.sg", "net.sg", "org.sg", "gov.sg", "edu.sg",
    "com.my", "net.my", "org.my", "gov.my", "edu.my",
    "co.id", "or.id", "ac.id", "go.id", "web.id",
    "co.th", "in.th", "ac.th", "go.th",
    "com.ph", "net.ph", "org.ph", "gov.ph",
    "com.vn", "net.vn", "org.vn", "gov.vn", "edu.vn",
    /* Middle East / Africa */
    "co.za", "org.za", "net.za", "gov.za", "ac.za",
    "co.il", "org.il", "net.il", "gov.il", "ac.il",
    "com.tr", "net.tr", "org.tr", "gov.tr", "edu.tr",
    "com.sa", "net.sa", "org.sa", "gov.sa", "edu.sa",
    "com.eg", "net.eg", "org.eg", "gov.eg", "edu.eg",
    "co.ke", "or.ke", "ac.ke", "go.ke",
    "com.ng", "org.ng", "net.ng", "gov.ng", "edu.ng",
    /* Europe (multi-part) */
    "co.rs", "org.rs", "in.ua", "com.ua", "co.ua"
  ]);

  function registrable(host) {
    const p = (host || "").toLowerCase().split(".").filter(Boolean);
    if (p.length < 2) return (host || "").toLowerCase();
    const last2 = `${p[p.length - 2]}.${p[p.length - 1]}`;
    if (p.length >= 3 && MULTI_TLDS.has(last2)) {
      return `${p[p.length - 3]}.${last2}`;
    }
    return last2;
  }

  function isThirdParty(fromHost, toHost) {
    return registrable(fromHost) !== registrable(toHost);
  }

  root.PhishCleanPSL = { MULTI_TLDS, registrable, isThirdParty };
})(typeof globalThis !== "undefined" ? globalThis : self);
