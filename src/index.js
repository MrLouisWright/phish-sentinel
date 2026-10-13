import { readFileSync, existsSync, statSync } from 'node:fs';
import { buildReport, exceeds, exitCode, formatText, formatJson, formatSarif, formatMarkdown, SEVERITIES, ConfigError, validateConfig } from './core.js';
import { RULES } from './rules.js';
import { analyzeUrl, extractUrls, registrableDomain, skeleton, distance, brandTable, WEIGHTS } from './analyze.js';
import { BRANDS } from './data.js';

export { analyzeUrl, extractUrls, registrableDomain, skeleton, distance, brandTable, WEIGHTS, BRANDS, RULES, exceeds, exitCode, formatText, formatJson, formatSarif, formatMarkdown, SEVERITIES, ConfigError };
export const VERSION = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;
export const TOOL = { name: 'phish-sentinel', version: VERSION, rules: RULES, title: 'phish-sentinel', emoji: '🎣', defaultFailOn: 'high' };

/** Expand inputs: URLs stay, files (text, HTML, .eml, lists) are scanned for URLs. */
export function collectUrls(inputs) {
  const urls = []; const errors = [];
  for (const i of inputs) {
    if (existsSync(i) && statSync(i).isFile()) { const found = extractUrls(readFileSync(i, 'utf8')); urls.push(...found.map((u) => ({ url: u, source: i }))); if (!found.length) errors.push({ source: i, error: 'no URLs found' }); }
    else urls.push({ url: i });
  }
  const seen = new Set(); return { urls: urls.filter((u) => !seen.has(u.url) && seen.add(u.url)), errors };
}

/** Score URLs offline. Options: protect (your domains, for lookalike detection), trusted (skip these domains), builtinBrands (default true), allow, severity. */
export function check(inputs, opts = {}) {
  validateConfig({ allow: opts.allow, severity: opts.severity });
  const brands = brandTable(opts.protect || [], { builtin: opts.builtinBrands !== false });
  const { urls, errors } = collectUrls(inputs);
  const results = errors.map((e) => ({ target: e.source, raw: [], errors: [`${e.source}: ${e.error}`] }));
  for (const { url, source } of urls) {
    const r = analyzeUrl(url, { brands, trusted: opts.trusted });
    const loc = source ? `${source}: ${url}` : url;
    if (r.invalid) { results.push({ target: url, raw: [{ rule: 'invalid-url', location: loc, message: `Not a valid http(s) URL: ${url.slice(0, 100)}` }] }); continue; }
    const raw = r.signals.map((s) => ({ rule: s.rule, location: loc, message: s.message, evidence: s.evidence, score: s.weight }));
    if (r.verdict === 'likely-phishing' || r.verdict === 'suspicious') raw.unshift({ rule: r.verdict === 'likely-phishing' ? 'phishing-likely' : 'phishing-suspicious', location: loc, message: `Score ${r.score}/100 (${r.signals.map((s) => s.rule).join(', ')})`, evidence: r.domain, score: r.score });
    results.push({ target: url, summary: { domain: r.domain, ...(r.unicodeHost ? { unicodeHost: r.unicodeHost } : {}), score: r.score, verdict: r.verdict, ...(source ? { source } : {}) }, raw });
  }
  return buildReport(TOOL, results, opts);
}

export function formatTable(report) {
  return report.targets.map((t) => `${String(t.summary?.score ?? '-').padStart(3)}  ${(t.summary?.verdict || (t.errors.length ? 'error' : 'invalid')).padEnd(15)} ${t.target}`).join('\n') + '\n';
}
