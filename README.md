# phish-sentinel

[![npm version](https://img.shields.io/npm/v/phish-sentinel.svg)](https://www.npmjs.com/package/phish-sentinel) [![CI](https://github.com/MrLouisWright/phish-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/MrLouisWright/phish-sentinel/actions/workflows/ci.yml) [![Node](https://img.shields.io/node/v/phish-sentinel.svg)](https://nodejs.org) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE) [![provenance](https://img.shields.io/badge/npm-provenance-blue)](https://docs.npmjs.com/generating-provenance-statements)

> Offline phishing URL heuristics with an explainable score: lookalike and homograph domains, brand impersonation, IP hosts, `user@host` tricks, risky TLDs, shorteners, free hosting and redirect chains.

`phish-sentinel` scores URLs from 0 to 100 and tells you exactly why. Give it URLs, or files (emails, `.eml`, HTML, logs, URL lists) and it extracts the URLs itself, refanging `hxxp://` and `[.]` and decoding quoted-printable mail. **Nothing is fetched or resolved**, so it is safe to run on live phishing samples and works in air-gapped triage. Pass your own domains with `--brand` to catch typosquats and homographs of *your* brand. CLI, library and GitHub Action. Node.js 18+, **zero runtime dependencies**.

```
$ phish-sentinel suspicious-mail.eml -f table --brand acme-corp.com
 80  likely-phishing https://paypal-account-verify.top/webscr?cmd=login
 60  suspicious      https://acme-c0rp.com/sso
  0  clean           https://www.acme-corp.com/
```

## How scoring works

Each signal adds a weight; the total is capped at 100. A score of **70+** adds a `phishing-likely` (critical) finding and **40–69** adds `phishing-suspicious` (high). Signals are also reported on their own, so you can tune them with `severity` or `allow`.

Weights: `brand-lookalike` 60, `homograph` 70, `brand-impersonation` 45, `userinfo-trick` 50, `dangerous-scheme` 60, `ip-host` 30, `punycode` 15, `risky-tld` 15, `free-hosting` 20, `shortener` 15, `open-redirect` 20, `credential-lure` 20, `risky-download` 25, `deep-subdomain` 10, `hyphenated-domain` 10, `random-domain` 10, `encoded-url` 10, `non-standard-port` 10, `plain-http` 5, `long-url` 5.

- **Lookalikes**: Damerau-Levenshtein distance to ~60 commonly phished brands (PayPal, Microsoft, Apple, banks, couriers, crypto exchanges…) and your `--brand` domains, after folding confusables (`rn`→`m`, `0`→`o`, `1`→`l`, Cyrillic/Greek letters). For your brands, the same name on a different suffix (`acme-corp.net`) also counts.
- **Homographs**: `xn--` domains whose Unicode form renders like a brand, or that mix Latin with Cyrillic/Greek.
- **Impersonation**: a brand name in the subdomains (`paypal.com.secure-login.xyz`), in the domain (`micros0ft-support.com`), or in the path together with another signal.
- Plus `user@host` tricks, raw/hex/decimal IP hosts, abused TLDs, shorteners, free hosting and tunnels (Weebly, Firebase, `pages.dev`, ngrok, `trycloudflare.com`…), redirect parameters to other domains, credential lure words, executable downloads, deep subdomains, hyphen-heavy or random-looking domains, heavy encoding, odd ports and plain HTTP.

Heuristics produce false positives and miss things; use the score for triage, not as a final verdict.

## Rules

| Rule | Default | Meaning |
|---|---|---|
| `phishing-likely` | critical | Combined score says this URL is very likely phishing |
| `phishing-suspicious` | high | Combined score says this URL is suspicious |
| `brand-lookalike` | high | Domain is a typo/lookalike of a protected brand domain |
| `homograph` | high | IDN homograph: mixed scripts or confusable characters spell a known domain |
| `brand-impersonation` | high | Brand name in the subdomain or path of an unrelated domain |
| `userinfo-trick` | high | user@host form hides the real host (https://bank.com@evil.io) |
| `dangerous-scheme` | high | javascript:, data: or vbscript: URL |
| `ip-host` | medium | Host is a raw or obfuscated IP address |
| `punycode` | medium | Internationalised (xn--) domain |
| `risky-tld` | medium | TLD heavily abused for phishing (.zip, .top, .tk…) |
| `free-hosting` | medium | Hosted on a free site builder, tunnel or storage service |
| `shortener` | medium | URL shortener hides the destination |
| `open-redirect` | medium | Query parameter carries another URL (redirect chain) |
| `credential-lure` | medium | Login/verify/account keywords on an unrelated domain |
| `risky-download` | medium | Path ends in an executable or script extension |
| `deep-subdomain` | low | Unusually many subdomain levels |
| `hyphenated-domain` | low | Many hyphens in the registered domain |
| `random-domain` | low | Domain label looks random (high entropy, many digits) |
| `encoded-url` | low | Heavy percent-encoding or encoded host characters |
| `non-standard-port` | low | Explicit non-standard port |
| `plain-http` | low | http:// URL asking for interaction |
| `long-url` | info | Very long URL |
| `invalid-url` | low | Could not be parsed as a URL |

## Install and run

```bash
npx phish-sentinel 'https://www.paypal.com.secure-login.xyz/verify'
npx phish-sentinel reported/*.eml --brand acme-corp.com --brand acme.io -f table
cat proxy.log | npx phish-sentinel - --trust acme-corp.com --format json > urls.json
```

## Library

```js
import { analyzeUrl, brandTable } from 'phish-sentinel';
const r = analyzeUrl('https://acme-c0rp.com/sso', { brands: brandTable(['acme-corp.com']) });
// { score: 60, verdict: 'suspicious', signals: [{ rule: 'brand-lookalike', ... }] }
```

## Configuration

Put a `.phish-sentinel.json` in the working directory (or pass `--config <file>`). Every key is optional; CLI flags override the file.

```json
{
  "failOn": "high",
  "severity": { "shortener": "high" },
  "allow": [
    { "rule": "shortener", "match": "*bit.ly*", "reason": "Accepted risk, ticket SEC-123", "expires": "2027-03-31" }
  ]
}
```

- **`severity`** changes the severity of any rule, or turns it `off`.
- **`allow`** suppresses findings. Each entry needs a `rule` (globs such as `shortener-*` work) and a `reason`, and can be narrowed with `target` and `match` (a glob tested against the target, location and value). Suppressed findings are listed in the JSON report. When `expires` (YYYY-MM-DD) has passed, the finding comes back together with an `allow-expired` finding, so exceptions can't be forgotten. Entries that match nothing are reported as `allow-unused` (info).

## Output and exit codes

- `--format text|json|sarif|markdown` for stdout, plus `--json`, `--sarif` and `--markdown <file>` to write extra copies in one run. SARIF 2.1.0 works with GitHub code scanning.
- `--fail-on critical|high|medium|low|info|none` (default `high`).
- Exit code **0**: passed. **1**: at least one finding at or above `--fail-on`. **2**: usage or config error, or a target could not be checked.
- `--list-rules` prints every rule with its default severity.

## GitHub Action

```yaml
permissions:
  contents: read
  security-events: write   # only for the SARIF upload
steps:
  - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
    with: { persist-credentials: false }
  - uses: MrLouisWright/phish-sentinel@v1
    with:
      targets: 'urls.txt'
      fail-on: high
      sarif: phish-sentinel.sarif
  - uses: github/codeql-action/upload-sarif@v3
    if: always()
    with: { sarif_file: phish-sentinel.sarif }
```

Inputs: `targets`, `fail-on`, `config`, `sarif`, `json`, `job-summary` (Markdown report in the job summary, default `true`), `args` (extra CLI flags), `brands`. Outputs: `markdown-file`, `exit-code`.

## Requirements

Node.js 18 or newer. No runtime dependencies.

## Support

If this project is useful to you, you can support its development with a donation: [Buy me a coffee](https://donate.stripe.com/aFa00lek3cvX4Ds2Fk9EI0b). It helps keep these tools maintained, documented and free for everyone.

## Credit (optional)

Free to use under MIT, no attribution required. If phish-sentinel helps you, a link back is appreciated:

```html
<a href="https://louiswright.co.uk">Built with phish-sentinel by Louis Wright</a>
```

```markdown
[![Built with phish-sentinel by Louis Wright](https://img.shields.io/badge/built%20with-phish--sentinel-blue)](https://louiswright.co.uk)
```

## Lookalike monitoring

```sh
npx phish-sentinel lookalikes example.com -f table           # list candidates (offline)
npx phish-sentinel lookalikes example.com --check --rdap     # which are registered (DNS + RDAP)
```

Run it on a schedule. Each registered typosquat is reported as a `lookalike-registered` finding, with its registration date and registrar when RDAP returns them.

## Phishing feeds (optional, offline cache)

```sh
npx phish-sentinel update-feeds --feeds .phish-cache                      # OpenPhish community feed
PHISHTANK_KEY=... npx phish-sentinel update-feeds --feeds .phish-cache --source openphish,phishtank
npx phish-sentinel urls.txt --feeds .phish-cache
```

Scoring never touches the network. Feeds are only downloaded when you run `update-feeds`. Please follow each feed's terms of use.

## Plugins and image fuzzy hashes

```js
import { checkAsync, imageHashPlugin } from 'phish-sentinel';
const visual = imageHashPlugin({ references: { MyBank: ['f0e1d2c3b4a59687'] }, hashUrl: async (url) => myScreenshotDHash(url) });
const report = await checkAsync(urls, { protect: ['mybank.com'], plugins: [visual] });
```

A plugin is `{ name, analyze(url, ctx) }` and returns signals of the form `{ rule, message, weight }`. phish-sentinel doesn't fetch or render pages itself. Your `hashUrl` decides how to get the image.

Only external URLs are scored. Links to your own `--brand`/`--own` domains are skipped.

## Module formats and types

Ships ESM (`import`) and a bundled CommonJS build (`require`), with TypeScript declarations generated from the source:

```js
import * as lib from 'phish-sentinel';      // ESM
const lib = require('phish-sentinel');      // CommonJS
```

Tests live in [`test/`](test) and run on Node 18, 20 and 22 in [GitHub Actions](https://github.com/MrLouisWright/phish-sentinel/actions/workflows/ci.yml), including a require+import check. Releases are published with `npm publish --provenance`.

## License

MIT © Louis Wright ([Louis Wright](https://github.com/MrLouisWright))
