#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { runCli, list, UsageError } from '../src/cli-core.js';
import { check, extractUrls, formatTable, TOOL } from '../src/index.js';

const HELP = `phish-sentinel {VERSION} — offline phishing heuristics for URLs, with an explainable score

Usage: phish-sentinel <url|file|-> [...] [options]

Files (text, HTML, .eml, URL lists) and stdin ("-") are scanned for URLs; hxxp:// and [.] are refanged.
No URL is ever fetched or resolved.

      --brand <domain>       Protect your own domain: flag typos, homographs and impersonation of it
                             (repeatable or comma-separated)
      --trust <domain>       Never flag URLs on this registered domain (repeatable or comma-separated)
      --no-builtin-brands    Only use --brand domains, not the built-in list of commonly phished brands
  -f table                   One line per URL: score, verdict, URL
{COMMON}`;

process.exitCode = await runCli(TOOL, {
  help: HELP,
  formats: ['table'],
  options: { brand: { type: 'string', multiple: true }, trust: { type: 'string', multiple: true }, 'no-builtin-brands': { type: 'boolean' } },
  run(o, pos, cfg, ctx) {
    let inputs = [...pos];
    if (inputs.includes('-')) { inputs = inputs.filter((x) => x !== '-'); inputs.push(...extractUrls(readFileSync(0, 'utf8'))); }
    if (!inputs.length) throw new UsageError('No URL or file given');
    const report = check(inputs, { protect: [...(cfg.brands || []), ...list(o.brand)], trusted: [...(cfg.trusted || []), ...list(o.trust)], builtinBrands: !(o['no-builtin-brands'] ?? cfg.noBuiltinBrands), allow: cfg.allow, severity: cfg.severity });
    return ctx.format === 'table' ? { report, output: formatTable(report) } : report;
  },
});
