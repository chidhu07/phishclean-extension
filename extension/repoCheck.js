/* PhishClean coding-test repo check
   On a GitHub, GitLab or Bitbucket repository page, reads the files where
   fake "take-home test" repos hide their malware (npm install hooks, VS Code
   tasks that run on folder open, config files that download and run code)
   and shows a card when installing or opening the repo would run something.
   The files are fetched from the code host straight into this tab and
   analysed here (lib/repoRisk.js); nothing about the repo goes to PhishClean.
   Paid check: free installs skip it.
*/
(() => {
  const risk = globalThis.PhishCleanRepoRisk;
  if (!risk) return;
  if (!/^(?:www\.)?(?:github\.com|gitlab\.com|bitbucket\.org)$/.test(location.hostname)) return;

  const LICENSE_KEY = "phishclean_license";
  const CACHE_KEY = "phishclean_repo_checks";
  const PAUSE_KEY = "phishclean_repo_check_paused_until";
  const CACHE_MS = 24 * 60 * 60 * 1000;
  const CACHE_MAX = 60;
  const HELP_URL = "https://www.phishclean.com/blog/fake-job-interview-coding-test-malware?utm_source=extension&utm_medium=repo-check";

  let currentKey = "";
  let card = null;

  const repoKey = (ref) => `${ref.host}:${ref.owner}/${ref.repo}`.toLowerCase();

  async function proEnabled() {
    const d = await chrome.storage.local.get(LICENSE_KEY);
    return !!(d[LICENSE_KEY]?.trial_active || d[LICENSE_KEY]?.is_paid);
  }

  /* One check per repo per day, shared by every tab. Dismissing a card is
     remembered with the result. */
  async function cached(key) {
    const d = await chrome.storage.local.get(CACHE_KEY);
    const hit = (d[CACHE_KEY] || {})[key];
    return hit && Date.now() - hit.at < CACHE_MS ? hit : null;
  }

  async function remember(key, entry) {
    const d = await chrome.storage.local.get(CACHE_KEY);
    const all = d[CACHE_KEY] || {};
    all[key] = { ...all[key], ...entry, at: entry.at || all[key]?.at || Date.now() };
    const keys = Object.keys(all).sort((a, b) => all[b].at - all[a].at);
    for (const k of keys.slice(CACHE_MAX)) delete all[k];
    await chrome.storage.local.set({ [CACHE_KEY]: all });
  }

  async function check() {
    const ref = risk.parseRepoUrl(location.href);
    const key = ref ? repoKey(ref) : "";
    if (key === currentKey) return;
    currentKey = key;
    removeCard();
    if (!ref || !(await proEnabled())) return;

    let entry = await cached(key);
    if (!entry) {
      const paused = (await chrome.storage.local.get(PAUSE_KEY))[PAUSE_KEY] || 0;
      if (Date.now() < paused) return;
      try {
        const result = await risk.checkRepo(ref, fetch.bind(globalThis), { skipEstablished: true });
        entry = { at: Date.now(), verdict: result.verdict, findings: result.findings.slice(0, 8), codingTest: result.codingTest, filesChecked: result.filesChecked.length };
        await remember(key, entry);
      } catch (e) {
        /* Out of anonymous API calls: GitHub allows 60 an hour per address. */
        if (e?.code === "rate-limit") await chrome.storage.local.set({ [PAUSE_KEY]: Date.now() + 60 * 60 * 1000 });
        return;
      }
    }
    if (key !== currentKey || entry.dismissed) return;
    if (entry.verdict === "danger" || entry.verdict === "warning") showCard(key, ref, entry);
  }

  function removeCard() {
    card?.remove();
    card = null;
  }

  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

  function showCard(key, ref, entry) {
    removeCard();
    const danger = entry.verdict === "danger";
    const host = { github: "GitHub", gitlab: "GitLab", bitbucket: "Bitbucket" }[ref.host];
    const title = danger ? "This repo runs hidden code when you install or open it" : "Check this repo before you run it";
    const lead = entry.codingTest
      ? "It reads like a job assessment. Fake recruiters send repos like this so the candidate installs malware on their own laptop."
      : danger
        ? "Running npm install or opening the folder in VS Code would start the code below."
        : "Something in it runs code you might not expect.";

    const wrapper = document.createElement("div");
    wrapper.id = "phishclean-repo-check";
    const shadow = wrapper.attachShadow({ mode: "closed" });
    shadow.innerHTML = `
      <style>
        :host { all: initial; }
        .card {
          position: fixed; right: 16px; bottom: 16px; z-index: 2147483646;
          width: min(400px, calc(100vw - 32px)); max-height: calc(100vh - 32px); overflow: auto;
          background: #0f1117; color: #e2e8f0; border: 1px solid ${danger ? "#7f1d1d" : "#78350f"};
          border-radius: 14px; padding: 18px; box-shadow: 0 18px 40px rgba(0,0,0,0.35);
          font: 13px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        }
        .top { display: flex; gap: 10px; align-items: flex-start; }
        .dot { flex: none; width: 10px; height: 10px; border-radius: 50%; margin-top: 6px; background: ${danger ? "#ef4444" : "#f59e0b"}; }
        h2 { margin: 0; font-size: 15px; font-weight: 600; color: #f8fafc; line-height: 1.35; }
        p { margin: 8px 0 0; color: #cbd5e1; }
        ul { list-style: none; margin: 12px 0 0; padding: 0; }
        li { background: #1e293b; border-radius: 8px; padding: 8px 10px; margin-top: 6px; color: #cbd5e1; overflow-wrap: anywhere; }
        code { font: 12px/1.4 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; color: ${danger ? "#fca5a5" : "#fcd34d"}; display: block; margin-bottom: 2px; }
        .advice { color: #e2e8f0; }
        .row { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; margin-top: 14px; }
        button { font: inherit; border: 1px solid #334155; background: #1e293b; color: #cbd5e1; border-radius: 8px; padding: 7px 12px; cursor: pointer; }
        button:hover { background: #334155; color: #f8fafc; }
        a { color: #93c5fd; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .fine { margin-top: 12px; font-size: 11px; color: #64748b; }
      </style>
      <div class="card" role="alert" aria-label="PhishClean repo check">
        <div class="top">
          <span class="dot" aria-hidden="true"></span>
          <div>
            <h2>${esc(title)}</h2>
            <p>${esc(lead)}</p>
          </div>
        </div>
        <ul>${entry.findings.slice(0, 4).map((f) => `<li><code>${esc(f.file)}</code>${esc(f.detail)}</li>`).join("")}</ul>
        <p class="advice">Don't run it on a computer with your passwords, wallets or work access. If you have to run it, use a throwaway virtual machine or a cloud dev environment, and never open it in VS Code with "Trust" on.</p>
        <div class="row">
          <a href="${HELP_URL}" target="_blank" rel="noopener">How fake coding tests work &rarr;</a>
          <span style="flex:1"></span>
          <button id="dismiss">Dismiss for this repo</button>
        </div>
        <p class="fine">PhishClean read ${entry.filesChecked} file${entry.filesChecked === 1 ? "" : "s"} from ${host} in this tab. Nothing about this repo was sent to PhishClean.</p>
      </div>`;
    shadow.getElementById("dismiss").onclick = () => {
      removeCard();
      remember(key, { dismissed: true }).catch(() => {});
    };
    document.documentElement.appendChild(wrapper);
    card = wrapper;
  }

  /* GitHub, GitLab and Bitbucket all change pages without a full load. */
  const tick = () => { check().catch(() => {}); };
  tick();
  setInterval(() => {
    const ref = risk.parseRepoUrl(location.href);
    if ((ref ? repoKey(ref) : "") !== currentKey) tick();
  }, 1500);
})();
