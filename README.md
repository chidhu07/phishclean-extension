# PhishClean — extension source

This is the source of the [PhishClean](https://www.phishclean.com) browser extension, published so that the privacy claims on the website can be checked rather than trusted. It is version 1.10.0. [Which store build this matches](#which-store-build-this-is) is set out below.

PhishClean runs 27 phishing, scam and leak checks locally in the browser, 5 of them free. The claim is: **nothing about the pages you visit is ever sent to PhishClean.** One paid feature does ask a third party about the page you are on: the coding-test repo check asks the code host about the repository you opened. It is in the table below with everything else.

## Which store build this is

Checked on 4 November 2026 by downloading the live package from each store and comparing every file. All three stores call their build 1.10.0, but they were not uploaded at the same time.

| Store | How it compares with `extension/` here |
|---|---|
| Chrome Web Store | Identical, apart from line endings and the `update_url` Chrome adds to the manifest |
| Edge Add-ons | Identical, apart from line endings and a reformatted manifest |
| Firefox Add-ons | An earlier upload. It has the older icons and branding, and it does not have the digit-swap and subdomain lookalike rules in [`riskEngine.js`](extension/riskEngine.js). Its network requests are the same. The store copy of the manifest is also reformatted |

To check it yourself, unzip a store package and compare it, ignoring line endings because the packages are built on Windows:

```sh
diff -r --strip-trailing-cr unzipped-store-package extension
```

## Verify the privacy claim in five minutes

Every outbound network request the extension can make is listed here. There are no others.

| Where | What it sends | To |
|---|---|---|
| [`extension/background.js`](extension/background.js) — `registerInstall()` | a random UUID (`install_id`) and the extension version, plus the organisation key if your company's admin set one by policy | `https://www.phishclean.com/api/register` |
| [`extension/background.js`](extension/background.js) — `refreshStatus()` | the same `install_id` (plus a bearer token if you chose to sign in, and the organisation key if one was set by policy) | `https://www.phishclean.com/api/status` |
| [`extension/background.js`](extension/background.js) — `authenticateExtensionAccount()` / logout | email + password **only if you create an account**, which is optional | `https://www.phishclean.com/api/extension-auth` |
| [`extension/background.js`](extension/background.js) — `OPEN_PORTAL` | `install_id` | `https://www.phishclean.com/api/portal` |
| [`extension/background.js`](extension/background.js) — `setUninstallPing()` | `install_id`, once, when you uninstall | `https://www.phishclean.com/api/status?event=uninstall` |
| [`extension/lib/phishFeed.js`](extension/lib/phishFeed.js) — `refresh()` | nothing: a plain download of the same file for every user, about twice a day (`If-None-Match` when a copy is already stored). No install ID, no URL. Each page's hostname is hashed and looked up in that file **on the device** | `https://www.phishclean.com/feeds/phish-v1.bin` |
| [`extension/background.js`](extension/background.js) — `refreshBreaches()` | nothing: a download of Have I Been Pwned's full public list of breached sites, every few days; the site you are on is matched locally | `https://haveibeenpwned.com/api/v3/breaches` |
| [`extension/background.js`](extension/background.js) — `pwnedRange()` (trial and paid only) | the first **5 hex characters** of the SHA-1 hash of a password you are typing (k-anonymity, padded response); the password and its full hash never leave the page | `https://api.pwnedpasswords.com/range/` |
| [`extension/lib/repoRisk.js`](extension/lib/repoRisk.js), called from [`extension/repoCheck.js`](extension/repoCheck.js) (trial and paid only) | when you open a repository page on GitHub, GitLab or Bitbucket: that repository's owner and name, then the paths of the files it reads, to that same company's public API. Sent with `credentials: "omit"`, so without your login cookies. The code host sees your IP address and which repository was checked. Nothing goes to PhishClean, and the result is kept on the device. Repositories with 500 or more stars that are over a year old stop after the first request | `https://api.github.com/repos/`, `https://raw.githubusercontent.com/`, `https://gitlab.com/api/v4/projects/`, `https://api.bitbucket.org/2.0/repositories/` |
| [`extension/secretScanner.js`](extension/secretScanner.js) | nothing — it *reads* a page's own same-origin script files (credentials omitted) to scan them for leaked keys, the same request the page already made | the site you are on |

Things you will **not** find, and can grep for yourself:

```sh
grep -rnE "fetch(Fn)?\(|XMLHttpRequest|sendBeacon|WebSocket|setUninstallURL" extension --include=*.js | grep -v jspdf
```

- No page URL, title, DOM content, form value, or password is ever sent to PhishClean. The content scripts ([`contentScript.js`](extension/contentScript.js), [`riskEngine.js`](extension/riskEngine.js), [`secretScanner.js`](extension/secretScanner.js), [`guards.js`](extension/guards.js), [`linkTooltip.js`](extension/linkTooltip.js), [`breachCheck.js`](extension/breachCheck.js), [`searchBadges.js`](extension/searchBadges.js), [`repoCheck.js`](extension/repoCheck.js), [`clipboardHook.js`](extension/clipboardHook.js), [`networkHook.js`](extension/networkHook.js)) contain no network calls to PhishClean at all — they talk only to the background worker via `chrome.runtime.sendMessage`.
- That grep also matches two things that send nothing of their own. [`networkHook.js`](extension/networkHook.js) wraps the page's own requests to spot card numbers heading somewhere unexpected, and [`repoRisk.js`](extension/lib/repoRisk.js) has a pattern that looks for network calls in the code of the repository it is reading.
- No analytics or telemetry library. The only third-party code is [jsPDF 2.5.2](extension/lib/jspdf.umd.min.js), unmodified, used to build the optional local PDF report.
- The threat log, stats, trusted-domain list and settings live in `chrome.storage.local` and never leave the browser.

The `<all_urls>` host permission exists because the content scripts must run on every page to inspect it; it is not used to send anything.

## Run it from source

1. Clone this repository.
2. Chrome / Edge / Brave: open `chrome://extensions`, enable *Developer mode*, *Load unpacked*, choose the `extension/` folder.
3. Firefox: `about:debugging#/runtime/this-firefox` → *Load Temporary Add-on* → pick `extension/manifest.firefox.json`.

The trial and licence behaviour is identical to the store build, because it *is* the store build.

## Run the tests

```sh
npm install
npx playwright install chromium
npm test
```

One fixture is deliberately absent: the secret-scanner demo page that contains fake `sk_live_…`, `AKIA…` and `ghp_…` strings. GitHub push protection rejects it, because the patterns [`secretScanner.js`](extension/secretScanner.js) looks for are the same ones GitHub looks for — which is rather the point. Make your own with any string matching those regexes.

The `*.test.mjs` files test the detection rules directly in Node. The `*-verify.mjs` files load the unpacked extension into a real Chromium window and drive the pages in `tests/`: [`browser-verify`](tests/browser-verify.mjs) checks which signals fire under trial, expired and paid licences, [`interview-verify`](tests/interview-verify.mjs) covers the repo check and the fake interview warnings, and the others cover the Have I Been Pwned checks, the reported-phishing list, search badges, paste and download warnings, and hacked-site checks. They need port 8080 free.

## How the reported-phishing list is built

[`scripts/build-phish-feed.mjs`](scripts/build-phish-feed.mjs) runs on every deploy of phishclean.com, so this copy can be newer than the extension. It takes the "ACTIVE" domain list from [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database) (MIT), which stopped updating on 2 October 2026, and adds [PhishTank](https://phishtank.org/)'s list of verified phishing sites that are still online (CC BY-SA 2.5, so the feed file is CC BY-SA 2.5 too). It removes anything whose registrable domain is in the [Tranco](https://tranco-list.eu/) top 1M (the raw list contains real sites such as `sites.google.com` and `gravatar.com`), keeps customer subdomains of hosting platforms as exact matches only, and writes 6-byte SHA-256 prefixes. The extension never sees or sends the hostnames themselves.

## Build the store packages

```sh
bash build.sh
```

Produces `dist/phishclean-{chrome,edge,firefox}-v<version>.zip` from `extension/` with no transformation — no bundler, no minifier.

## What this repository is not

The backend (licensing API, payment webhook, account service) is not here; it holds nothing about your browsing because nothing about your browsing is ever sent to it. The website source is not here either.

## Related

The [phishclean-mcp](https://github.com/chidhu07/phishclean-mcp) server (MIT, `npx phishclean-mcp`) exposes PhishClean's URL, email, JWT and secret checks to Claude Desktop, Claude Code and Cursor. It is a separate, API-backed product; the extension itself never uses it.

## License

Source-available under the [PolyForm Noncommercial License 1.0.0](LICENSE.md). You may read, run, modify and share it for noncommercial purposes. You may not sell it, offer it as a service, or republish it to an extension store. If you want to use it commercially, write to <support@phishclean.com>.

Security issues: <https://www.phishclean.com/.well-known/security.txt>.
