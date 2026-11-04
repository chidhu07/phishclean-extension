/* PhishClean coding-test repo check
   Fake recruiters send a repository as a "take-home test" or "bug to fix".
   Installing or opening it runs malware: an npm install hook, a VS Code task
   that runs when the folder opens, or a config file that downloads code and
   runs it. This reads the files those tricks live in and reports what each
   one would do, without running anything.

   Shared by the extension (repoCheck.js) and the free checker at
   phishclean.com/tools/coding-test-checker, which gets a copy at build time.
   No DOM, no state: analysis functions plus a small fetch layer for GitHub,
   GitLab and Bitbucket.
*/
(() => {
  const MAX_FILES = 20;
  const MAX_BYTES = 400000;

  /* ── Rules ── */

  /* npm runs these by itself during `npm install`. */
  const INSTALL_HOOKS = new Set(["preinstall", "install", "postinstall", "prepare", "preprepare", "postprepare", "prepublish"]);
  const DOWNLOAD_CMD_RE = /\b(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod|bitsadmin|certutil|start-bitstransfer)\b/i;
  const SHELL_PIPE_RE = /\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b|\|\s*iex\b|\|\s*python[0-9.]*\b|\bpowershell(?:\.exe)?\b[^|&;]*\s-(?:e|en|enc|encodedcommand)\b/i;
  const INLINE_CODE_RE = /\bnode\s+(?:-e|--eval|-p|--print)\b|\beval\b|\bbase64\b|\bpython[0-9.]*\s+-c\b|\bperl\s+-e\b/i;
  /* `node something.woff2`: a font or image file run as a program. */
  const DISGUISED_EXT = String.raw`woff2?|ttf|otf|eot|png|jpe?g|gif|ico|svg|bmp|webp|txt|md|log|dat|bin|css|map|lock|csv`;
  const DISGUISED_RUN_RE = new RegExp(String.raw`\b(?:node|nodemon|ts-node|bun|deno run|python[0-9.]*)\s+(?:--?[\w-]+\s+)*["']?((?:\.{0,2}/)?(?:[\w@.-]+/)*[\w@-][\w@.-]*\.(?:${DISGUISED_EXT}))(?![\w/.-])`, "i");
  /* Local files a script runs, so they get read too. */
  const RUN_FILE_RE = /\b(?:node|nodemon|ts-node|bun|python[0-9.]*|sh|bash)\s+(?:--?[\w-]+\s+)*["']?((?:\.{0,2}\/)?[\w@./-]+\.[a-z0-9]{1,6})\b/gi;

  const DYNAMIC_EXEC_RE = /\beval\s*\(|\bnew\s+Function\s*\(|Function\s*\.\s*constructor|\(\s*Function\s*\)\s*\(|\bFunction\s*\(\s*["'`]|\bvm\s*\.\s*run(?:InThisContext|InNewContext|InContext)\s*\(|\bnew\s+vm\s*\.\s*Script\s*\(/;
  const NETWORK_RE = /\baxios\s*(?:\.\s*(?:get|post|request)\s*)?\(|\bfetch\s*\(|\bXMLHttpRequest\b|\b(?:require\s*\(|from)\s*["'](?:axios|node-fetch|got|request|needle|superagent|https?|undici)["']|\bhttps?\s*\.\s*(?:get|request)\s*\(|\brequests\s*\.\s*(?:get|post)\s*\(|\burllib\.request\b|\burlopen\s*\(/;
  const DECODE_RE = /\batob\s*\(|Buffer\s*\.\s*from\s*\([^)]{0,200}["'](?:base64|hex)["']|String\s*\.\s*fromCharCode\s*\(|\bb64decode\b|\bzlib\s*\.\s*decompress\b|\bmarshal\s*\.\s*loads\b|\bcodecs\s*\.\s*decode\b/;
  const CHILD_PROCESS_RE = /\bchild_process\b|\bexecSync\s*\(|\bspawnSync?\s*\(|\bsubprocess\s*\.\s*(?:run|call|Popen|check_output)\b|\bos\s*\.\s*system\s*\(/;
  /* `new Function("require", code)` hands the downloaded code require(). */
  const PASSES_REQUIRE_RE = /Function[^;]{0,120}["'`]require["'`]/;
  /* A line with code, then a long run of spaces, then more code: the second
     part sits far off-screen to the right in an editor or GitHub's viewer. */
  const HIDDEN_CODE_RE = /\S[ \t]{150,}\S/;
  const OBFUSCATOR_RE = /\b_0x[0-9a-f]{4,6}\b/g;
  const LONG_BLOB_RE = /(?<![A-Za-z0-9+/]|base64,)[A-Za-z0-9+/]{1500,}={0,2}/;
  /* Paste and JSON-hosting sites these loaders fetch their next stage from. */
  const DEAD_DROP_RE = /\b(?:api\.npoint\.io|npoint\.io|jsonkeeper\.com|jsonsilo\.com|api\.jsonbin\.io|jsonbin\.io|pastebin\.com\/raw|paste\.ee\/r|rentry\.co|hastebin\.com\/raw|ipfs\.io\/ipfs)\b/i;

  const BINARY_RE = /\.(?:exe|dll|scr|msi|lnk|hta|vbs|vbe|jse|wsf|dmg|pkg|app|deb|rpm|apk)$/i;
  const SKIP_DIR_RE = /(?:^|\/)(?:node_modules|dist|build|out|vendor|coverage|\.next|\.nuxt|\.git)\//i;
  /* Test fixtures of big projects carry sample installers on purpose. */
  const TEST_DIR_RE = /(?:^|\/)(?:tests?|__tests__|fixtures?|spec|testdata|test-data)\//i;
  const CODE_RE = /\.(?:c?js|mjs|ts|cts|mts|jsx|tsx|py)$/i;
  const CONFIG_RE = /(?:^|\/)(?:[\w.-]+\.config\.(?:c|m)?[jt]s|\.eslintrc\.c?js|\.babelrc\.c?js|babel\.config\.json|gulpfile\.c?js|gruntfile\.c?js|hardhat\.config\.[jt]s|truffle-config\.js)$/i;
  const ENTRY_RE = /^(?:index|app|server|main|setup)\.(?:c?js|mjs|ts|py)$/i;
  const SERVER_DIR_RE = /(?:^|\/)(?:server|backend|api|config|configs|routes|controllers?|middlewares?|utils?|helpers?|lib|services?|scripts?|models?)\//i;

  const CODING_TEST_RE = /\b(?:take[- ]home|coding (?:test|challenge|assignment|exercise|task)|technical (?:test|assessment|interview|task|challenge)|assessment|interview (?:task|project|test|assignment)|candidate|hiring|recruit(?:er|ment|ing)|test task|trial task|skill test)\b/i;
  const RUN_IT_RE = /\b(?:npm|yarn|pnpm|bun)\s+(?:i|install|run|start|dev)\b|\bnode\s+[\w./-]+|\bpython[0-9.]*\s+[\w./-]+\.py|\bpip\s+install\b|\bdocker[- ]compose\s+up\b/i;

  const finding = (severity, rule, file, detail) => ({ severity, rule, file, detail });

  function stripJsonComments(text) {
    return (text || "").replace(/("(?:\\.|[^"\\])*")|\/\*[\s\S]*?\*\/|\/\/[^\n]*/g, (m, str) => str || "").replace(/,(\s*[}\]])/g, "$1");
  }

  function dirOf(path) {
    const i = path.lastIndexOf("/");
    return i < 0 ? "" : path.slice(0, i + 1);
  }

  function resolvePath(base, rel) {
    const parts = (dirOf(base) + rel.replace(/^\.\//, "")).split("/");
    const out = [];
    for (const p of parts) {
      if (p === "..") out.pop();
      else if (p && p !== ".") out.push(p);
    }
    return out.join("/");
  }

  function runFiles(cmd, from) {
    const files = [];
    for (const m of (cmd || "").matchAll(RUN_FILE_RE)) {
      if (/^https?:/i.test(m[1])) continue;
      files.push(resolvePath(from, m[1]));
    }
    return files;
  }

  const clip = (s, n = 140) => (s.length > n ? s.slice(0, n - 1) + "…" : s);

  /**
   * npm scripts and dependencies.
   * @returns {{ findings: object[], follow: string[] }}
   */
  function analyzePackageJson(path, text) {
    const findings = [], follow = [];
    let pkg;
    try { pkg = JSON.parse(text); } catch { return { findings, follow }; }
    if (!pkg || typeof pkg !== "object") return { findings, follow };

    for (const [name, raw] of Object.entries(pkg.scripts || {})) {
      if (typeof raw !== "string") continue;
      const cmd = raw.trim();
      const hook = INSTALL_HOOKS.has(name);
      const disguised = cmd.match(DISGUISED_RUN_RE);
      if (disguised) {
        findings.push(finding("high", "disguised-file", path,
          `The "${name}" script runs ${disguised[1]} as a program. That is a ${disguised[1].split(".").pop()} file name on code, a way to hide malware from a quick look.`));
      } else if (hook && (DOWNLOAD_CMD_RE.test(cmd) || SHELL_PIPE_RE.test(cmd) || INLINE_CODE_RE.test(cmd))) {
        findings.push(finding("high", "install-hook", path,
          `npm runs the "${name}" script by itself during npm install, and it downloads or runs hidden code: ${clip(cmd)}`));
      } else if (SHELL_PIPE_RE.test(cmd)) {
        findings.push(finding("high", "shell-pipe", path,
          `The "${name}" script pipes a download straight into a shell: ${clip(cmd)}`));
      } else if (hook && /https?:\/\//i.test(cmd)) {
        findings.push(finding("medium", "install-hook-url", path,
          `npm runs the "${name}" script by itself during npm install, and it contacts a web address: ${clip(cmd)}`));
      }
      for (const f of runFiles(cmd, path)) if (!follow.includes(f)) follow.push(f);
    }

    const deps = { ...pkg.dependencies, ...pkg.devDependencies, ...pkg.optionalDependencies };
    for (const [name, spec] of Object.entries(deps)) {
      if (typeof spec !== "string") continue;
      const m = spec.match(/^(?:https?:\/\/|git\+https?:\/\/)([^/]+)/i);
      if (m && !/(?:^|\.)(?:github\.com|gitlab\.com|bitbucket\.org|registry\.npmjs\.org|codeload\.github\.com)$/i.test(m[1])) {
        findings.push(finding("medium", "remote-dependency", path,
          `The dependency "${name}" is downloaded from ${m[1]} instead of the npm registry.`));
      }
    }
    return { findings, follow };
  }

  /**
   * VS Code tasks that run as soon as the folder is opened.
   * @returns {{ findings: object[], follow: string[] }}
   */
  function analyzeVscodeTasks(path, text) {
    const findings = [], follow = [];
    let tasks = [];
    try { tasks = JSON.parse(stripJsonComments(text)).tasks || []; } catch { /* unreadable, fall through to text */ }
    const autoRun = tasks.filter((t) => t && t.runOptions && t.runOptions.runOn === "folderOpen");
    if (!autoRun.length && !/"runOn"\s*:\s*"folderOpen"/.test(text || "")) return { findings, follow };

    const commands = autoRun.length
      ? autoRun.map((t) => [t.command, ...(t.args || []), t.windows?.command, t.osx?.command, t.linux?.command].filter((c) => typeof c === "string").join(" "))
      : [text];
    for (const cmd of commands) {
      const disguised = cmd.match(DISGUISED_RUN_RE);
      const bad = disguised || DOWNLOAD_CMD_RE.test(cmd) || SHELL_PIPE_RE.test(cmd) || INLINE_CODE_RE.test(cmd) || /https?:\/\//i.test(cmd);
      findings.push(bad
        ? finding("high", "vscode-autorun", path,
          disguised
            ? `VS Code runs ${disguised[1]} as a program the moment you open this folder (runOn: folderOpen). That file name hides code.`
            : `VS Code runs this the moment you open the folder (runOn: folderOpen), and it downloads or runs hidden code: ${clip(cmd.trim())}`)
        : finding("medium", "vscode-autorun", path,
          `VS Code runs a task the moment you open this folder (runOn: folderOpen): ${clip(cmd.trim()) || "(no command shown)"}`));
      for (const f of runFiles(cmd, "")) if (!follow.includes(f)) follow.push(f);
    }
    return { findings, follow };
  }

  /** JavaScript, TypeScript or Python source. */
  function analyzeSource(path, text) {
    const findings = [];
    const t = (text || "").slice(0, MAX_BYTES);
    if (!t) return findings;

    /* In Python exec() runs code; in JavaScript it is child_process, below. */
    const exec = DYNAMIC_EXEC_RE.test(t) || (/\.py$/i.test(path) && /\bexec\s*\(/.test(t));
    if (HIDDEN_CODE_RE.test(t)) {
      findings.push(finding("high", "hidden-code", path,
        "A line continues after more than 150 spaces, which pushes code off the right edge of the screen where a reviewer won't see it."));
    }
    if ((t.match(OBFUSCATOR_RE) || []).length >= 25) {
      findings.push(finding("high", "obfuscated", path,
        "The code is run through an obfuscator (_0x… names everywhere). A coding test has no reason to hide what its code does."));
    }
    if (exec && NETWORK_RE.test(t)) {
      findings.push(finding("high", "remote-exec", path,
        PASSES_REQUIRE_RE.test(t)
          ? "Downloads code from a server and runs it with full access to your computer (new Function with require)."
          : "Downloads something from a server and runs it as code (eval or new Function)."));
    } else if (exec && DECODE_RE.test(t)) {
      findings.push(finding("high", "decode-exec", path,
        "Decodes hidden text (Base64, hex or character codes) and runs it as code."));
    }
    if (CHILD_PROCESS_RE.test(t) && (DOWNLOAD_CMD_RE.test(t) || SHELL_PIPE_RE.test(t))) {
      findings.push(finding("high", "download-run", path,
        "Starts a shell command that downloads and runs a program."));
    }
    const drop = t.match(DEAD_DROP_RE);
    if (drop) {
      findings.push(finding(exec ? "high" : "medium", "dead-drop", path,
        `Fetches data from ${drop[0]}, a paste site that malware in fake coding tests uses to hide its next stage.`));
    }
    if (!findings.length && LONG_BLOB_RE.test(t)) {
      findings.push(finding("medium", "encoded-blob", path,
        "Contains a long encoded blob (1,500+ characters of Base64-like text)."));
    }
    return findings;
  }

  /** Files that should not be in a source repo, from the file list alone. */
  function analyzeTree(paths) {
    const bins = paths.filter((p) => BINARY_RE.test(p) && !SKIP_DIR_RE.test(p) && !TEST_DIR_RE.test(p));
    return bins.length
      ? [finding("medium", "binaries", bins[0],
        `The repo carries ${bins.length === 1 ? "a program file" : `${bins.length} program files`} (${bins.slice(0, 3).join(", ")}${bins.length > 3 ? ", …" : ""}). A coding test never needs you to run one.`)]
      : [];
  }

  /** Does the README read like a job assessment that tells you to run it? */
  function isCodingTest(readme) {
    return CODING_TEST_RE.test(readme || "") && RUN_IT_RE.test(readme || "");
  }

  /**
   * Which files to read, most telling first.
   * @param {{path: string, size?: number}[]} tree
   * @returns {string[]}
   */
  function pickFiles(tree) {
    const ok = tree.filter((f) => !SKIP_DIR_RE.test(f.path) && !(f.size > MAX_BYTES) && !/\.min\.js$/i.test(f.path));
    const depth = (p) => p.split("/").length;
    const picked = [];
    const add = (p) => { if (!picked.includes(p)) picked.push(p); };
    ok.filter((f) => /(?:^|\/)package\.json$/.test(f.path) && depth(f.path) <= 3)
      .sort((a, b) => depth(a.path) - depth(b.path)).forEach((f) => add(f.path));
    ok.filter((f) => /(?:^|\/)\.vscode\/tasks\.json$/.test(f.path)).forEach((f) => add(f.path));
    ok.filter((f) => CONFIG_RE.test(f.path) && depth(f.path) <= 3).forEach((f) => add(f.path));
    ok.filter((f) => ENTRY_RE.test(f.path) || /^(?:src|server|backend)\/(?:index|app|server|main)\.[cm]?[jt]s$/i.test(f.path)).forEach((f) => add(f.path));
    ok.filter((f) => CODE_RE.test(f.path) && SERVER_DIR_RE.test(f.path))
      .sort((a, b) => depth(a.path) - depth(b.path) || a.path.length - b.path.length)
      .forEach((f) => add(f.path));
    return picked;
  }

  const SEVERITY_ORDER = { high: 0, medium: 1, info: 2 };

  function verdictOf(findings) {
    if (findings.some((f) => f.severity === "high")) return "danger";
    if (findings.some((f) => f.severity === "medium")) return "warning";
    return "clean";
  }

  /* ── Fetching ── */

  /**
   * github.com/o/r, gitlab.com/group/sub/r, bitbucket.org/o/r, with or
   * without https:// and with any /tree/… or /blob/… tail.
   * @returns {{ host: "github"|"gitlab"|"bitbucket", owner: string, repo: string } | null}
   */
  const RESERVED_GITHUB = new Set(["orgs", "settings", "marketplace", "topics", "features", "explore",
    "notifications", "pulls", "issues", "sponsors", "login", "join", "about", "pricing", "enterprise",
    "collections", "trending", "codespaces", "search", "apps", "organizations", "users", "new", "site",
    "security", "customer-stories", "readme", "team", "contact", "events", "github-copilot", "resources",
    "solutions", "dashboard", "account", "gist", "copilot", "models", "mcp"]);

  function parseRepoUrl(input) {
    let u;
    try { u = new URL(/^https?:\/\//i.test(input) ? input : `https://${String(input).trim()}`); } catch { return null; }
    const h = u.hostname.toLowerCase().replace(/^www\./, "");
    const parts = u.pathname.split("/").filter(Boolean);
    if (h === "github.com") {
      if (parts.length < 2 || RESERVED_GITHUB.has(parts[0].toLowerCase())) return null;
      return { host: "github", owner: parts[0], repo: parts[1].replace(/\.git$/, "") };
    }
    if (h === "bitbucket.org") {
      if (parts.length < 2 || ["account", "dashboard", "product", "repo", "workspace"].includes(parts[0])) return null;
      return { host: "bitbucket", owner: parts[0], repo: parts[1].replace(/\.git$/, "") };
    }
    if (h === "gitlab.com") {
      const end = parts.indexOf("-");
      const path = (end < 0 ? parts : parts.slice(0, end));
      if (path.length < 2 || ["users", "explore", "dashboard", "help", "admin", "groups", "search"].includes(path[0])) return null;
      return { host: "gitlab", owner: path.slice(0, -1).join("/"), repo: path[path.length - 1].replace(/\.git$/, "") };
    }
    return null;
  }

  class RepoCheckError extends Error {
    constructor(code, message) { super(message); this.code = code; }
  }

  async function getJson(fetchFn, url) {
    const r = await fetchFn(url, { credentials: "omit" });
    if (r.status === 404) throw new RepoCheckError("not-found", "Repository not found, or it is private.");
    if (r.status === 403 || r.status === 429) throw new RepoCheckError("rate-limit", "The code host is rate-limiting checks from this address. Try again in an hour.");
    if (!r.ok) throw new RepoCheckError("http", `The code host answered ${r.status}.`);
    return r.json();
  }

  async function getText(fetchFn, url) {
    try {
      const r = await fetchFn(url, { credentials: "omit" });
      if (!r.ok) return null;
      const text = await r.text();
      return text.length > MAX_BYTES ? text.slice(0, MAX_BYTES) : text;
    } catch { return null; }
  }

  const encPath = (p) => p.split("/").map(encodeURIComponent).join("/");

  /* Each host: read the repo's details (one request), then its file list and
     a raw-file URL builder. Split in two so a caller can stop after the
     details, before the costlier file list. */
  const PROVIDERS = {
    github: {
      async meta(f, { owner, repo }) {
        const m = await getJson(f, `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`);
        return { createdAt: m.created_at, pushedAt: m.pushed_at, stars: m.stargazers_count, fork: !!m.fork, url: m.html_url, branch: m.default_branch || "main" };
      },
      async files(f, { owner, repo }, { branch }) {
        const o = encodeURIComponent(owner), r = encodeURIComponent(repo), b = encodeURIComponent(branch);
        const tree = await getJson(f, `https://api.github.com/repos/${o}/${r}/git/trees/${b}?recursive=1`);
        return {
          files: (tree.tree || []).filter((n) => n.type === "blob").map((n) => ({ path: n.path, size: n.size })),
          raw: (p) => `https://raw.githubusercontent.com/${o}/${r}/${b}/${encPath(p)}`
        };
      }
    },
    gitlab: {
      async meta(f, { owner, repo }) {
        const m = await getJson(f, `https://gitlab.com/api/v4/projects/${encodeURIComponent(`${owner}/${repo}`)}`);
        return { createdAt: m.created_at, pushedAt: m.last_activity_at, stars: m.star_count, fork: !!m.forked_from_project, url: m.web_url, branch: m.default_branch || "main" };
      },
      async files(f, { owner, repo }, { branch }) {
        const base = `https://gitlab.com/api/v4/projects/${encodeURIComponent(`${owner}/${repo}`)}`;
        const files = [];
        for (let page = 1; page <= 5; page++) {
          const items = await getJson(f, `${base}/repository/tree?recursive=true&per_page=100&page=${page}&ref=${encodeURIComponent(branch)}`);
          for (const n of items) if (n.type === "blob") files.push({ path: n.path });
          if (items.length < 100) break;
        }
        return { files, raw: (p) => `${base}/repository/files/${encodeURIComponent(p)}/raw?ref=${encodeURIComponent(branch)}` };
      }
    },
    bitbucket: {
      async meta(f, { owner, repo }) {
        const m = await getJson(f, `https://api.bitbucket.org/2.0/repositories/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`);
        return { createdAt: m.created_on, pushedAt: m.updated_on, stars: null, fork: !!m.parent, url: m.links?.html?.href, branch: m.mainbranch?.name || "main" };
      },
      async files(f, { owner, repo }, { branch }) {
        const base = `https://api.bitbucket.org/2.0/repositories/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/src/${encodeURIComponent(branch)}`;
        const files = [];
        let next = `${base}/?max_depth=6&pagelen=100`;
        for (let i = 0; next && i < 5; i++) {
          const page = await getJson(f, next);
          for (const n of page.values || []) if (n.type === "commit_file") files.push({ path: n.path, size: n.size });
          next = page.next;
        }
        return { files, raw: (p) => `${base}/${encPath(p)}` };
      }
    }
  };

  /* Well-known projects with years of history are not fake coding tests. */
  function isEstablished(meta) {
    const ageDays = (Date.now() - Date.parse(meta.createdAt || "")) / 86400000;
    return !meta.fork && meta.stars >= 500 && ageDays > 365;
  }

  /**
   * Read a repository and report what installing or opening it would run.
   * @param {{host: string, owner: string, repo: string}} ref  from parseRepoUrl
   * @param {typeof fetch} fetchFn
   * @param {{ skipEstablished?: boolean }} [opts]  stop after the repo
   *        details when it is a long-standing popular project
   * @returns {Promise<{ verdict, findings, codingTest, meta, filesChecked, fileCount }>}
   *          verdict is "danger", "warning", "clean" or "skipped"
   */
  async function checkRepo(ref, fetchFn = globalThis.fetch.bind(globalThis), opts = {}) {
    const provider = PROVIDERS[ref?.host];
    if (!provider) throw new RepoCheckError("unsupported", "Only GitHub, GitLab and Bitbucket repositories can be checked.");
    const meta = await provider.meta(fetchFn, ref);
    if (opts.skipEstablished && isEstablished(meta)) {
      return { verdict: "skipped", findings: [], codingTest: false, meta, filesChecked: [], fileCount: 0 };
    }
    const { files, raw } = await provider.files(fetchFn, ref, meta);
    const paths = files.map((f) => f.path);
    const have = new Set(paths);
    const findings = analyzeTree(paths);
    const checked = [];
    const queue = pickFiles(files);
    const readme = paths.find((p) => /^readme(?:\.md|\.txt|\.rst)?$/i.test(p));
    const readmeText = readme ? await getText(fetchFn, raw(readme)) : null;

    /* Files a script or task runs jump the queue: that is where the payload is. */
    for (let i = 0; i < queue.length && checked.length < MAX_FILES; i++) {
      const path = queue[i];
      checked.push(path);
      const text = await getText(fetchFn, raw(path));
      if (text == null) continue;
      let result = null;
      if (/(?:^|\/)package\.json$/.test(path)) result = analyzePackageJson(path, text);
      else if (/\.vscode\/tasks\.json$/.test(path)) result = analyzeVscodeTasks(path, text);
      else findings.push(...analyzeSource(path, text));
      if (result) {
        findings.push(...result.findings);
        const next = result.follow.filter((p) => have.has(p) && !checked.includes(p));
        for (const p of next) {
          const at = queue.indexOf(p);
          if (at > i) queue.splice(at, 1);
        }
        queue.splice(i + 1, 0, ...next);
      }
    }

    findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
    return {
      verdict: verdictOf(findings),
      findings,
      codingTest: isCodingTest(readmeText),
      meta,
      filesChecked: checked,
      fileCount: files.length
    };
  }

  globalThis.PhishCleanRepoRisk = {
    parseRepoUrl, checkRepo, RepoCheckError,
    analyzePackageJson, analyzeVscodeTasks, analyzeSource, analyzeTree,
    isCodingTest, pickFiles, verdictOf, isEstablished
  };
})();
