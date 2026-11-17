# Security policy

## Reporting a vulnerability

Please report security problems privately, not in a public issue:

- **GitHub:** use [Report a vulnerability](https://github.com/chidhu07/phishclean-extension/security/advisories/new) on this repository's Security tab, or
- **Email:** support@phishclean.com with "Security" in the subject.

Useful things to include: the extension version and browser, steps to reproduce, and what an attacker could do with it. A proof-of-concept page is welcome.

We aim to reply within 7 days and to tell you when a fix is submitted to the stores. Fixes reach users through the Chrome, Edge and Firefox stores, so a fix is live only after each store's review. We will credit you in the release notes unless you would rather not be named.

## What counts

In scope:

- Anything that lets a web page read, change or turn off PhishClean's settings, trusted sites or licence.
- A web page making PhishClean send data anywhere not listed in the README's network table.
- Script injection through PhishClean's warnings, popup or options page.
- A way for a phishing page to hide from a check that should catch it, when the miss comes from a bug rather than a known limit of the rule.

Not in scope: missed phishing pages in general (report those at https://www.phishclean.com/contact so the rules can improve), and bugs in the browsers themselves.

## Supported versions

Only the latest version on each store gets fixes. The stores update installs automatically.

The full disclosure policy is at https://www.phishclean.com/security.
