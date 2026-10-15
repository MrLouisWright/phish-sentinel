#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { runCli, list, UsageError } from '../src/cli-core.js';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { check, checkAsync, extractUrls, formatTable, lookalikeReport, updateFeeds, TOOL } from '../src/index.js';

const HELP = `phish-sentinel {VERSION} — offline phishing heuristics for URLs, with an explainable score

Usage: phish-sentinel <url|file|-> [...] [options]
       phish-sentinel lookalikes <your-domain> [--check] [--rdap] [--limit n] [--ascii]
       phish-sentinel update-feeds --feeds <dir> [--source openphish,phishtank] [--phishtank-key k]

Files (text, HTML, .eml, URL lists) and stdin ("-") are scanned for URLs; hxxp:// and [.] are refanged.
Only external URLs are scored: URLs on your --brand/--own domains are skipped (--include-own to score them).
Scoring never fetches or resolves anything; only "lookalikes --check" (DNS, plus RDAP with --rdap) and
"update-feeds" use the network.

      --own <domain>         First-party domain to skip (repeatable or comma-separated)
      --include-own          Also score URLs on your own domains
      --feeds <dir|file>     Match against feeds cached by update-feeds (or a plain URL list)
      --plugin <module>      Load a plugin module (default export: plugin object or array); repeatable

      --brand <domain>       Protect your own domain: flag typos, homographs and impersonation of it
                             (repeatable or comma-separated)
      --trust <domain>       Never flag URLs on this registered domain (repeatable or comma-separated)
      --no-builtin-brands    Only use --brand domains, not the built-in list of commonly phished brands
  -f table                   One line per URL: score, verdict, URL
{COMMON}`;

process.exitCode = await runCli(TOOL, {
  help: HELP,
  formats: ['table'],
  options: { brand: { type: 'string', multiple: true }, trust: { type: 'string', multiple: true }, 'no-builtin-brands': { type: 'boolean' }, own: { type: 'string', multiple: true }, 'include-own': { type: 'boolean' }, feeds: { type: 'string' }, plugin: { type: 'string', multiple: true }, check: { type: 'boolean' }, rdap: { type: 'boolean' }, limit: { type: 'string' }, ascii: { type: 'boolean' }, source: { type: 'string', multiple: true }, 'phishtank-key': { type: 'string' } },
  async run(o, pos, cfg, ctx) {
    if (pos[0] === 'lookalikes') {
      if (!pos[1]) throw new UsageError('lookalikes needs a domain');
      const report = await lookalikeReport(pos[1], { check: o.check, rdap: o.rdap, limit: o.limit ? +o.limit : undefined, ascii: o.ascii, allow: cfg.allow, severity: cfg.severity });
      return ctx.format === 'table' ? { report, output: (report.targets[0].summary.list || report.targets[0].findings.map((f) => f.message)).join('\n') + '\n' } : report;
    }
    if (pos[0] === 'update-feeds') {
      const dir = o.feeds || cfg.feeds; if (!dir) throw new UsageError('update-feeds needs --feeds <dir>');
      const r = await updateFeeds(dir, { sources: list(o.source).length ? list(o.source) : undefined, phishtankKey: o['phishtank-key'] || process.env.PHISHTANK_KEY });
      return { output: `${Object.entries(r.counts).map(([k, v]) => `${k}: ${v} URLs`).join('\n')}${r.errors.length ? '\n' + r.errors.join('\n') : ''}\ncache: ${r.file}\n`, exit: r.errors.length && !Object.keys(r.counts).length ? 2 : 0 };
    }
    const plugins = [];
    for (const m of [...list(o.plugin), ...(cfg.plugins || [])]) { const mod = await import(/^[./]/.test(m) ? pathToFileURL(resolve(m)).href : m); plugins.push(...[].concat(mod.default ?? mod.plugin ?? [])); }
    let inputs = [...pos];
    if (inputs.includes('-')) { inputs = inputs.filter((x) => x !== '-'); inputs.push(...extractUrls(readFileSync(0, 'utf8'))); }
    if (!inputs.length) throw new UsageError('No URL or file given');
    const report = await checkAsync(inputs, { plugins, own: [...(cfg.own || []), ...list(o.own)], includeOwn: o['include-own'] ?? cfg.includeOwn, feeds: o.feeds || cfg.feeds, protect: [...(cfg.brands || []), ...list(o.brand)], trusted: [...(cfg.trusted || []), ...list(o.trust)], builtinBrands: !(o['no-builtin-brands'] ?? cfg.noBuiltinBrands), allow: cfg.allow, severity: cfg.severity });
    return ctx.format === 'table' ? { report, output: formatTable(report) } : report;
  },
});
