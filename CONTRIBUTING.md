# Contributing

This repository mirrors the PhishClean extension as it ships to the browser stores. It is published so anyone can check what the extension does, under the PolyForm Noncommercial License (see `LICENSE.md`).

## Reporting problems

- **Security problems:** follow [SECURITY.md](SECURITY.md). Please do not open a public issue.
- **Bugs and missed or wrong warnings:** open an issue with the extension version, the browser, and the page or steps that show the problem. For a phishing page PhishClean missed, the address is enough.
- **Ideas:** open an issue describing the scam or attack you want caught.

## Code changes

Pull requests are welcome for bug fixes and new detection rules. The mirror is updated from the main repository at each store release, so an accepted change is applied there and reaches this repository with the next release. Your commit is credited in the release notes.

## Tests

Every detection rule has unit tests in `tests/*.test.mjs`, and a change to a rule needs a test that fails without it. New checks also get a browser test (`tests/*-verify.mjs`) with a test page in `tests/test-*.html`.

```sh
node --test tests/*.test.mjs   # unit tests, no browser needed
npm install && npx playwright install chromium
npm test                       # unit + browser tests
```

The unit tests run on every push and pull request in GitHub Actions.

## Code style

Plain JavaScript (ES modules, so strict mode) with no build step and no runtime dependencies. The extension must not load remote code or send anything not listed in the README's network table.
