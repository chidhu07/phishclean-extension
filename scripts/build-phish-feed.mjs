/* Build the reported-phishing feed the extension matches against locally.

   Source: Phishing.Database (MIT, github.com/Phishing-Database/Phishing.Database),
   the "ACTIVE" domain list — hosts that were reported as phishing and still
   resolve. About 390k entries.

   The raw list cannot be used as is. It contains real sites (sites.google.com,
   gravatar.com, pastebin.com, telegra.ph, mercadolibre.*): someone reported a
   phishing page hosted on them and the whole host went on the list. Blocking
   those would block every Google Sites page. So:

   - Popular domains are dropped: anything whose registrable domain is in the
     Tranco top 1M. Exception: hosting platforms where every subdomain is a
     different customer (x.weebly.com, y.000webhostapp.com). Their listed
     subdomains are kept, exact-match only, and the platform root never is.
   - Every kept entry is either WILDCARD (it is a registrable domain, so its
     subdomains are the same owner and match too) or EXACT (that host only).

   Output: public/feeds/phish-v1.bin
     bytes 0..3   "PCF1"
     bytes 4..7   entry count, uint32 BE
     bytes 8..11  generated at, unix seconds, uint32 BE
     bytes 12..15 reserved (0)
     then count × 6-byte prefixes of SHA-256("*" + host) for wildcard entries
     and SHA-256("=" + host) for exact ones, sorted ascending, deduplicated.
   Hostnames never ship in the clear, so the file is not a ready-made list of
   live phishing hosts, and 48 bits keep a false match below one in a billion
   page loads.

   Runs as part of the Vercel build. It must never fail the deploy: if a source
   is unreachable it reuses the copy currently live on www.phishclean.com, and
   if that is unreachable too it writes nothing (the extension keeps the copy
   it already has).

   Run: node scripts/build-phish-feed.mjs            (writes public/feeds/)
        node scripts/build-phish-feed.mjs --stats    (prints what the filter drops)
*/
import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const OUT = resolve(ROOT, "public/feeds/phish-v1.bin");
const LIVE_URL = "https://www.phishclean.com/feeds/phish-v1.bin";
const SOURCE_URL = "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt";
const PSL_URL = "https://publicsuffix.org/list/public_suffix_list.dat";
const TRANCO_ID_URL = "https://tranco-list.eu/top-1m-id";
const TRANCO_TOP = 1000000;
const PREFIX_BYTES = 6;
const MIN_ENTRIES = 50000; /* a list far smaller than usual means a broken download */

/* Platforms that give each customer a subdomain but are not in the Public
   Suffix List's private section, so PSL alone would treat x.weebly.com as part
   of weebly.com. Their roots are always dropped; listed customer subdomains
   are kept as exact matches. */
export const HOSTING_PLATFORMS = new Set([
  "000webhostapp.com", "weebly.com", "wixsite.com", "wix.com", "webflow.io",
  "godaddysites.com", "square.site", "squarespace.com", "jimdosite.com",
  "jimdofree.com", "yolasite.com", "site123.me", "strikingly.com",
  "mystrikingly.com", "webnode.page", "ukit.me", "tilda.ws", "carrd.co",
  "glitch.me", "replit.app", "repl.co", "gitbook.io", "notion.site",
  "framer.website", "framer.app", "mobirisesite.com", "wordpress.com",
  "blogspot.com", "firebaseapp.com", "web.app", "netlify.app", "vercel.app",
  "pages.dev", "workers.dev", "r2.dev", "herokuapp.com", "azurewebsites.net",
  "github.io", "gitlab.io", "surge.sh", "onrender.com", "fly.dev",
  "translate.goog", "ipfs.dweb.link", "myshopify.com", "typedream.app",
  "beehiiv.com", "substack.com", "linktr.ee", "start.page", "wixstudio.io",
  "editorx.io", "duckdns.org", "ngrok.io", "ngrok-free.app", "trycloudflare.com",
  /* From --stats: the platforms whose customers the top-1M filter dropped most. */
  "weeblysite.com", "xsph.ru", "swtest.ru", "webcindario.com", "tw1.ru",
  "tmweb.ru", "usrfiles.com", "atwebpages.com", "mybluehost.me", "crabdance.com",
  "temp-site.link", "temporary.link", "temporary.site", "beget.tech", "serv00.net",
  "liveblog365.com", "rf.gd", "myportfolio.com", "ydns.eu", "moonfruit.com",
  "zzux.com", "zyns.com", "otzo.com", "work.gd", "wikaba.com", "selcdn.ru",
  "infura-ipfs.io", "appdomain.cloud", "filesusr.com", "fleek.co", "ic0.app",
  "brizy.site", "codeanyapp.com", "easywp.com", "webwave.dev", "ubpages.com",
  "preview-domain.com", "zya.me", "wcomhost.com", "justns.ru", "webspace.re",
]);
/* blogspot.<country> (blogspot.fi, blogspot.com.br, …): one blog per subdomain. */
const BLOGSPOT_RE = /\.blogspot\.[a-z]{2,3}(\.[a-z]{2})?$/;

const HOST_RE = /^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/;

export function normalizeHost(raw) {
  let h = String(raw || "").trim().toLowerCase();
  if (!h || h.startsWith("#")) return "";
  h = h.replace(/\.$/, "").replace(/^www\./, "");
  return HOST_RE.test(h) ? h : "";
}

/* Minimal Public Suffix List matcher: normal, wildcard and exception rules. */
export function parsePsl(text) {
  const rules = new Set(), wild = new Set(), except = new Set();
  for (const line of text.split("\n")) {
    const r = line.trim().toLowerCase();
    if (!r || r.startsWith("//")) continue;
    if (r.startsWith("!")) except.add(r.slice(1));
    else if (r.startsWith("*.")) wild.add(r.slice(2));
    else rules.add(r);
  }
  return function registrable(host) {
    const labels = host.split(".");
    let suffixLen = 1;
    for (let i = 0; i < labels.length; i++) {
      const s = labels.slice(i).join(".");
      if (except.has(s)) { suffixLen = labels.length - i - 1; break; }
      if (rules.has(s)) { suffixLen = labels.length - i; break; }
      if (i + 1 < labels.length && wild.has(labels.slice(i + 1).join("."))) { suffixLen = labels.length - i; break; }
    }
    if (labels.length <= suffixLen) return null;
    return labels.slice(labels.length - suffixLen - 1).join(".");
  };
}

/* Tranco ranks pay-level domains; hosting platforms are exempt (see above). */
export function classify(host, registrable, top) {
  const reg = registrable(host);
  if (!reg || reg === "phishclean.com") return null;
  if (HOSTING_PLATFORMS.has(host) || /^blogspot\./.test(host)) return null;
  if (BLOGSPOT_RE.test(host)) return { kind: "exact", host };
  /* A registrable domain by the PSL (incl. its private section, so
     evil.github.io is one) belongs to one owner: wildcard. */
  if (host === reg && !top.has(host)) return { kind: "wildcard", host };
  for (const p of HOSTING_PLATFORMS) {
    if (host.endsWith("." + p)) return { kind: "exact", host };
  }
  if (top.has(host) || top.has(reg)) return null;
  return { kind: host === reg ? "wildcard" : "exact", host };
}

export function prefixOf(kind, host) {
  return createHash("sha256").update((kind === "wildcard" ? "*" : "=") + host).digest().subarray(0, PREFIX_BYTES);
}

export function encodeFeed(prefixes, generatedAt) {
  prefixes.sort(Buffer.compare);
  const unique = prefixes.filter((p, i) => i === 0 || !p.equals(prefixes[i - 1]));
  const out = Buffer.alloc(16 + unique.length * PREFIX_BYTES);
  out.write("PCF1", 0, "ascii");
  out.writeUInt32BE(unique.length, 4);
  out.writeUInt32BE(Math.floor(generatedAt / 1000), 8);
  unique.forEach((p, i) => p.copy(out, 16 + i * PREFIX_BYTES));
  return out;
}

async function text(url, attempts = 2) {
  try {
    const r = await fetch(url, { signal: AbortSignal.timeout(180000) });
    if (!r.ok) throw new Error(`${url} → ${r.status}`);
    return await r.text();
  } catch (err) {
    if (attempts <= 1) throw err;
    return text(url, attempts - 1);
  }
}

async function build({ stats }) {
  const [source, psl, trancoId] = await Promise.all([text(SOURCE_URL), text(PSL_URL), text(TRANCO_ID_URL)]);
  const tranco = await text(`https://tranco-list.eu/download/${trancoId.trim()}/${TRANCO_TOP}`);
  const top = new Set(tranco.split("\n").map((l) => l.split(",")[1]?.trim().toLowerCase()).filter(Boolean));
  if (top.size < TRANCO_TOP * 0.9) throw new Error(`Tranco list too short (${top.size})`);
  const registrable = parsePsl(psl);

  const kept = new Map();
  const dropped = new Map();
  let raw = 0;
  for (const line of source.split("\n")) {
    const host = normalizeHost(line);
    if (!host) continue;
    raw++;
    const c = classify(host, registrable, top);
    if (c) kept.set(host, c.kind);
    else if (stats) {
      const reg = registrable(host) || host;
      dropped.set(reg, (dropped.get(reg) || 0) + 1);
    }
  }

  const wildcards = [...kept.values()].filter((k) => k === "wildcard").length;
  console.log(`phish feed: ${raw} listed, ${kept.size} kept (${wildcards} wildcard, ${kept.size - wildcards} exact)`);
  if (stats) {
    const worst = [...dropped].sort((a, b) => b[1] - a[1]).slice(0, 40);
    console.log("dropped, by registrable domain:");
    for (const [d, n] of worst) console.log(`  ${String(n).padStart(6)}  ${d}`);
    return null;
  }
  if (kept.size < MIN_ENTRIES) throw new Error(`only ${kept.size} entries kept`);
  return encodeFeed([...kept].map(([host, kind]) => prefixOf(kind, host)), Date.now());
}

async function main() {
  const stats = process.argv.includes("--stats");
  let feed = null;
  try {
    feed = await build({ stats });
    if (stats) return;
  } catch (err) {
    if (stats) throw err;
    console.warn(`phish feed: build failed (${err.message}); reusing the live copy`);
    try {
      const r = await fetch(LIVE_URL, { signal: AbortSignal.timeout(30000) });
      const buf = Buffer.from(await r.arrayBuffer());
      if (r.ok && buf.subarray(0, 4).toString("ascii") === "PCF1") feed = buf;
    } catch { /* handled below */ }
  }
  if (!feed) {
    console.warn("phish feed: no feed written; extensions keep the copy they have");
    return;
  }
  mkdirSync(dirname(OUT), { recursive: true });
  writeFileSync(OUT, feed);
  console.log(`phish feed: wrote ${OUT} (${(feed.length / 1048576).toFixed(2)} MB, ${feed.readUInt32BE(4)} entries)`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((err) => { console.warn(`phish feed: ${err.message}`); });
}
