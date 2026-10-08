/* PhishClean reported-phishing feed.
   A list of ~380k hosts reported as phishing (Phishing.Database, filtered and
   hashed by scripts/build-phish-feed.mjs) is downloaded whole from
   phishclean.com and matched here, on the device. The request carries nothing
   about the user or the pages they visit, the same as the breach list.

   The file holds 6-byte SHA-256 prefixes, not hostnames: "*host" for a
   registrable domain (its subdomains belong to the same owner and match too)
   and "=host" for a single host (a customer subdomain on a hosting platform,
   where the parent is someone else's). Loaded by the service worker
   (importScripts) and listed in Firefox's background.scripts. */
(function (root) {
  const FEED_URL = "https://www.phishclean.com/feeds/phish-v1.bin";
  const MAX_AGE_MS = 12 * 60 * 60 * 1000;
  const PREFIX = 6;
  const META_KEY = "phishclean_feed_meta";
  const DB_NAME = "phishclean";
  const STORE = "feeds";
  const RECORD = "phish-v1";

  /* ── IndexedDB: the file is ~2 MB of binary, which storage.local would hold
     only as base64 and would count against its quota. ── */
  function withStore(mode, fn) {
    return new Promise((resolve, reject) => {
      const open = indexedDB.open(DB_NAME, 1);
      open.onupgradeneeded = () => open.result.createObjectStore(STORE);
      open.onerror = () => reject(open.error);
      open.onsuccess = () => {
        const db = open.result;
        const tx = db.transaction(STORE, mode);
        const req = fn(tx.objectStore(STORE));
        tx.oncomplete = () => { db.close(); resolve(req?.result); };
        tx.onerror = tx.onabort = () => { db.close(); reject(tx.error); };
      };
    });
  }

  function parse(buffer) {
    if (!buffer || buffer.byteLength < 16) return null;
    const bytes = new Uint8Array(buffer);
    if (String.fromCharCode(bytes[0], bytes[1], bytes[2], bytes[3]) !== "PCF1") return null;
    const view = new DataView(buffer);
    const count = view.getUint32(4);
    if (buffer.byteLength !== 16 + count * PREFIX) return null;
    return { count, generated_at: view.getUint32(8) * 1000, prefixes: bytes.subarray(16) };
  }

  function contains(feed, prefix) {
    let lo = 0, hi = feed.count - 1;
    const p = feed.prefixes;
    while (lo <= hi) {
      const mid = (lo + hi) >>> 1;
      const at = mid * PREFIX;
      let cmp = 0;
      for (let i = 0; i < PREFIX && cmp === 0; i++) cmp = p[at + i] - prefix[i];
      if (cmp === 0) return true;
      if (cmp < 0) lo = mid + 1; else hi = mid - 1;
    }
    return false;
  }

  /* The host itself, exactly, plus every parent with at least two labels as
     a wildcard. Normalised the same way the build script normalises. */
  function candidates(hostname) {
    const host = String(hostname || "").toLowerCase().replace(/\.$/, "").replace(/^www\./, "");
    if (!host || !host.includes(".")) return [];
    const labels = host.split(".");
    const out = [`=${host}`];
    for (let i = 0; i <= labels.length - 2; i++) out.push(`*${labels.slice(i).join(".")}`);
    return out;
  }

  async function prefixOf(text) {
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
    return new Uint8Array(digest, 0, PREFIX);
  }

  let feed = null;      /* parsed feed, kept for the life of the worker */
  let loading = null;
  let refreshing = null;

  function load() {
    if (feed) return Promise.resolve(feed);
    if (!loading) {
      loading = withStore("readonly", (s) => s.get(RECORD))
        .then((rec) => { feed = parse(rec?.buffer); return feed; })
        .catch(() => null)
        .finally(() => { loading = null; });
    }
    return loading;
  }

  /* Download when the copy is older than MAX_AGE_MS. The ETag makes an
     unchanged file a 304 instead of another 2 MB. Any failure keeps the copy
     already stored. */
  function refresh(force = false) {
    if (refreshing) return refreshing;
    refreshing = (async () => {
      const meta = (await chrome.storage.local.get(META_KEY))[META_KEY] || null;
      if (!force && meta && Date.now() - meta.fetched_at < MAX_AGE_MS && (await load())) return meta;
      const headers = meta?.etag && (await load()) ? { "If-None-Match": meta.etag } : {};
      const r = await fetch(FEED_URL, { headers, cache: "no-cache" });
      if (r.status === 304) {
        const next = { ...meta, fetched_at: Date.now() };
        await chrome.storage.local.set({ [META_KEY]: next });
        return next;
      }
      if (!r.ok) throw new Error(`feed ${r.status}`);
      const buffer = await r.arrayBuffer();
      const parsed = parse(buffer);
      if (!parsed || parsed.count === 0) throw new Error("feed malformed");
      feed = parsed;
      /* IndexedDB can be unavailable (Firefox set to never remember history).
         The copy in memory still protects until the worker stops, and the
         next start downloads again because load() comes back empty. */
      await withStore("readwrite", (s) => s.put({ buffer }, RECORD)).catch(() => {});
      const next = {
        fetched_at: Date.now(),
        generated_at: parsed.generated_at,
        count: parsed.count,
        etag: r.headers.get("ETag") || null
      };
      await chrome.storage.local.set({ [META_KEY]: next });
      return next;
    })().catch(async () => (await chrome.storage.local.get(META_KEY))[META_KEY] || null)
      .finally(() => { refreshing = null; });
    return refreshing;
  }

  async function isListed(hostname) {
    const list = await load();
    if (!list) return false;
    for (const c of candidates(hostname)) {
      if (contains(list, await prefixOf(c))) return true;
    }
    return false;
  }

  root.PhishCleanFeed = { refresh, isListed, parse, contains, candidates, META_KEY };
})(typeof globalThis !== "undefined" ? globalThis : self);
