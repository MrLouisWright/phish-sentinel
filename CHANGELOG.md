# Changelog

## 1.0.0 - 2026-10-14

### Added before first publish

- `lookalikes <domain>` subcommand plus `generateLookalikes()`, which covers omission, repetition, transposition, keyboard replacement and insertion, homoglyph, vowel swap, bitsquat, hyphenation, subdomain split and TLD swap. With `--check` (DNS NS/A) and `--rdap`, `checkRegistrations()` reports registered typosquats as `lookalike-registered`.
- Optional offline phishing feeds: `update-feeds --feeds <dir>` caches OpenPhish (and PhishTank with `--phishtank-key`). `--feeds` matches by URL or host and raises `known-phishing`, which is critical and adds 100 points. If a refresh fails, the previous cache is kept.
- Plugin hook (`plugins`, `--plugin <module>`, `checkAsync()`), plus `imageHashPlugin()`, which compares your perceptual hashes and raises `visual-lookalike`. Signals from rules the tool doesn't know are reported as `plugin-signal`.
- Only external URLs are scored. URLs on `--brand`/`--own` domains are skipped (counted in `skippedOwn`); `--include-own` scores them too.

### Packaging

- Dual ESM + CommonJS: `import` loads `src/`, `require` loads a bundled `dist/index.cjs`, via package.json `exports`.
- TypeScript declarations are generated from the source (`dist/types`) instead of hand-written.
- CI runs build, tests and a require+import check on Node 18/20/22; releases use `npm publish --provenance`.

- First release: offline phishing URL scoring with 23 rules (lookalike, homograph, brand impersonation, userinfo, IP host, risky TLD, shortener, free hosting, open redirect and more), a brand watchlist (`--brand`), trusted domains, and URL extraction from emails and text with refanging.
- Text, JSON, SARIF, Markdown and table output; allowlist with expiry; per-rule severity; `--fail-on`; composite GitHub Action.
