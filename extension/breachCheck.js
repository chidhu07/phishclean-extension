/* PhishClean breach checks — data from Have I Been Pwned (CC BY 4.0).
   Both checks wake up only when the user interacts with a password field.

   Breached site (free, every install): when a password field gets focus, the
   site's registrable domain is looked up in HIBP's public breach list. The
   background worker downloads that list whole and matches it locally, so the
   domain is never sent anywhere. Shown once per domain, ever.

   Leaked password (trial and paid): when a password field changes or its form
   is submitted, the password is SHA-1 hashed here and only the first 5 hex
   characters of the hash are sent (via the background worker) to the Pwned
   Passwords range API. The reply lists every leaked hash starting with those
   characters and the match is made here — neither the password nor its full
   hash leaves this page. Skipped on plain-HTTP pages, where crypto.subtle is
   unavailable (and where the HTTP_PASSWORD signal already warns).
*/
(() => {
  const LICENSE_KEY = "phishclean_license";
  const SEEN_KEY = "phishclean_breach_seen";
  const SEEN_MAX = 500;
  const HIBP_URL = "https://haveibeenpwned.com/";

  const TYPING_PAUSE_MS = 800;
  const TYPING_MIN_LENGTH = 6;

  const leakCounts = new Map();
  let typingTimer = 0;
  let siteChecked = false;
  let current = null; /* the notice on screen, if any */

  const isPasswordField = (el) => el instanceof HTMLInputElement && el.type === "password";
  const send = (msg) => chrome.runtime.sendMessage(msg).catch(() => null);

  async function proEnabled() {
    const license = (await chrome.storage.local.get([LICENSE_KEY]))[LICENSE_KEY];
    return !!(license?.trial_active || license?.is_paid);
  }

  /* ── wording helpers ── */
  const compact = (n) => new Intl.NumberFormat("en", { notation: "compact" }).format(n);
  const monthYear = (d) =>
    new Date(`${d}T12:00:00Z`).toLocaleDateString("en", { month: "long", year: "numeric" });

  function exposedList(dataClasses) {
    const items = dataClasses.map((c) => c.toLowerCase());
    /* Passwords first — it is the reason the notice appears on a login form. */
    items.sort((a, b) => (b === "passwords") - (a === "passwords"));
    const shown = items.slice(0, 3);
    if (items.length > 3) return `${shown.join(", ")} and more`;
    if (shown.length < 2) return shown[0] || "account data";
    return `${shown.slice(0, -1).join(", ")} and ${shown[shown.length - 1]}`;
  }

  /* ── notice card, anchored under the field ── */
  function closeNotice() {
    if (!current) return;
    current.remove();
    current = null;
    document.removeEventListener("mousedown", onOutside, true);
    document.removeEventListener("keydown", onEscape, true);
  }
  function onOutside(e) { if (current && !e.composedPath().includes(current)) closeNotice(); }
  function onEscape(e) { if (e.key === "Escape") closeNotice(); }

  function showNotice(field, { title, body, footer, action }) {
    closeNotice();
    const wrapper = document.createElement("div");
    wrapper.id = "phishclean-breach";
    const shadow = wrapper.attachShadow({ mode: "closed" });
    shadow.innerHTML = `
      <style>
        :host { all: initial; }
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        .card {
          position: absolute; z-index: 2147483647; width: min(360px, calc(100vw - 16px));
          background: #0f1117; color: #cbd5e1; border: 1px solid #1e293b; border-left: 3px solid #f59e0b;
          border-radius: 10px; padding: 14px 16px; box-shadow: 0 12px 32px rgba(0,0,0,0.35);
          font: 13px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        }
        .top { display: flex; justify-content: space-between; align-items: flex-start; gap: 8px; }
        .title { font-size: 14px; font-weight: 600; color: #f1f5f9; margin-bottom: 4px; }
        .close { background: none; border: none; color: #64748b; font-size: 18px; line-height: 1; cursor: pointer; }
        .close:hover { color: #e2e8f0; }
        .action { margin-top: 10px; background: #2563eb; color: #fff; border: none; border-radius: 6px;
                  padding: 7px 12px; font-family: inherit; font-size: 12px; font-weight: 500; cursor: pointer; }
        .action:hover { background: #1d4ed8; }
        .footer { margin-top: 10px; font-size: 11px; color: #64748b; }
        .footer a { color: #93c5fd; text-decoration: none; }
        .footer a:hover { text-decoration: underline; }
      </style>
      <div class="card" role="status">
        <div class="top">
          <div class="title"></div>
          <button class="close" aria-label="Dismiss">&times;</button>
        </div>
        <div class="body"></div>
        <button class="action" hidden></button>
        <div class="footer"><span class="note"></span> Data from <a href="${HIBP_URL}" target="_blank" rel="noopener">Have I Been Pwned</a>.</div>
      </div>`;
    shadow.querySelector(".title").textContent = title;
    shadow.querySelector(".body").textContent = body;
    shadow.querySelector(".note").textContent = footer || "";
    shadow.querySelector(".close").onclick = closeNotice;
    if (action) {
      const btn = shadow.querySelector(".action");
      btn.hidden = false;
      btn.textContent = action.label;
      btn.onclick = () => { action.run(); closeNotice(); };
    }

    document.documentElement.appendChild(wrapper);

    /* Beside the field if it fits, else above it, else below. Below is the
       last resort because that is where the submit button usually is. */
    const card = shadow.querySelector(".card");
    const r = field.getBoundingClientRect();
    const { width, height } = card.getBoundingClientRect();
    const GAP = 8;
    let left, top;
    if (r.right + GAP + width <= innerWidth - GAP) {
      left = r.right + GAP;
      top = Math.max(GAP, r.top + r.height / 2 - height / 2);
    } else {
      left = Math.max(GAP, Math.min(r.left, innerWidth - width - GAP));
      top = r.top - GAP - height >= 0 ? r.top - GAP - height : r.bottom + GAP;
    }
    card.style.left = `${left + scrollX}px`;
    card.style.top = `${top + scrollY}px`;
    current = wrapper;
    document.addEventListener("mousedown", onOutside, true);
    document.addEventListener("keydown", onEscape, true);
  }

  /* ── breached site ── */
  async function checkSite(field) {
    if (siteChecked) return;
    siteChecked = true;
    const domain = globalThis.PhishCleanPSL?.registrable(location.hostname.toLowerCase());
    if (!domain) return;
    const seen = (await chrome.storage.local.get([SEEN_KEY]))[SEEN_KEY] || [];
    if (seen.includes(domain)) return;
    const res = await send({ type: "BREACH_FOR_DOMAIN", domain });
    const breach = res?.breach;
    if (!breach) return;

    const next = [...seen, domain];
    if (next.length > SEEN_MAX) next.splice(0, next.length - SEEN_MAX);
    await chrome.storage.local.set({ [SEEN_KEY]: next });

    const pro = await proEnabled();
    const accounts = breach.count ? `${compact(breach.count)} accounts' ` : "";
    showNotice(field, {
      title: "This site has had a data breach",
      body: `${breach.title} was breached in ${monthYear(breach.date)}, exposing ${accounts}` +
            `${exposedList(breach.data)}. If you had an account then, make sure the password ` +
            `you use here isn't used anywhere else.` +
            (pro ? "" : " With full protection, PhishClean also checks whether the password you type has leaked."),
      footer: "Matched on your device.",
      action: pro ? null : { label: "Turn on full protection", run: () => send({ type: "OPEN_PAYMENT" }) }
    });
  }

  /* ── leaked password ── */
  async function sha1Hex(text) {
    const digest = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(text));
    return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
  }

  /* hash -> Promise<count>; a failed lookup is dropped so it is retried. */
  function leakCount(hash) {
    if (!leakCounts.has(hash)) {
      const lookup = send({ type: "PWNED_RANGE", prefix: hash.slice(0, 5) }).then((res) => {
        if (!res?.ok) throw new Error("lookup failed");
        const suffix = hash.slice(5);
        for (const line of res.body.split("\n")) {
          const [s, n] = line.trim().split(":");
          if (s === suffix) return parseInt(n, 10) || 0; /* padding rows carry 0 */
        }
        return 0;
      });
      lookup.catch(() => leakCounts.delete(hash));
      leakCounts.set(hash, lookup);
    }
    return leakCounts.get(hash);
  }

  async function checkPassword(field) {
    const value = field.value;
    if (!value || !crypto?.subtle) return;
    if (!(await proEnabled())) return;
    const hash = await sha1Hex(value);
    const count = await leakCount(hash);
    /* The user may have kept typing while the lookup ran. */
    if (!count || field.value !== value) return;
    if (current?.dataset.leak === hash) return; /* already on screen */

    showNotice(field, {
      title: "This password has leaked",
      body: `It has appeared ${count.toLocaleString("en")} ${count === 1 ? "time" : "times"} in data breaches, ` +
            `so attackers try it early. Choose a different one here, and change it anywhere else you use it.`,
      footer: "Checked privately: your password never left this page."
    });
    current.dataset.leak = hash;
  }

  /* ── wiring ──
     Delegated listeners in the capture phase, so fields added later by the
     page (and forms that stop propagation) are covered without a
     MutationObserver. composedPath()[0] sees through open shadow roots. */
  const target = (e) => e.composedPath?.()[0] || e.target;

  document.addEventListener("focusin", (e) => {
    const el = target(e);
    if (isPasswordField(el)) checkSite(el).catch(() => {});
  }, true);

  /* Checking only on change would be too late: clicking "Sign in" blurs the
     field and the page navigates before the warning is read. So check after a
     pause in typing too. A warning for a value that has since changed is
     taken down at once. */
  document.addEventListener("input", (e) => {
    const el = target(e);
    if (!isPasswordField(el)) return;
    if (current?.dataset.leak) closeNotice();
    clearTimeout(typingTimer);
    if (el.value.length < TYPING_MIN_LENGTH) return;
    typingTimer = setTimeout(() => checkPassword(el).catch(() => {}), TYPING_PAUSE_MS);
  }, true);

  document.addEventListener("change", (e) => {
    const el = target(e);
    if (isPasswordField(el)) checkPassword(el).catch(() => {});
  }, true);

  /* Enter-to-submit can skip the change event, so check on submit as well.
     Lookups are cached per hash, so this costs nothing when change ran. */
  document.addEventListener("submit", (e) => {
    for (const el of e.target.querySelectorAll?.('input[type="password"]') || []) {
      checkPassword(el).catch(() => {});
    }
  }, true);
})();
