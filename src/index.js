import { readFileSync, existsSync, statSync } from 'node:fs';
import { buildReport, exceeds, exitCode, formatText, formatJson, formatSarif, formatMarkdown, SEVERITIES, ConfigError, validateConfig } from './core.js';
import { RULES } from './rules.js';
import { analyzeUrl, extractUrls, registrableDomain, skeleton, distance, brandTable, WEIGHTS } from './analyze.js';
import { BRANDS } from './data.js';
import { generateLookalikes, checkRegistrations } from './lookalike.js';
import { updateFeeds, loadFeeds, matchFeeds, FEED_SOURCES } from './feeds.js';
import { imageHashPlugin, hammingHex } from './plugins.js';
export { generateLookalikes, checkRegistrations, updateFeeds, loadFeeds, matchFeeds, FEED_SOURCES, imageHashPlugin, hammingHex };

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

const verdictOf = (score) => (score >= 70 ? 'likely-phishing' : score >= 40 ? 'suspicious' : score > 0 ? 'low-risk' : 'clean');

function prepare(inputs, opts) {
  validateConfig({ allow: opts.allow, severity: opts.severity });
  const brands = brandTable(opts.protect || [], { builtin: opts.builtinBrands !== false });
  const own = new Set([...(opts.protect || []), ...(opts.own || [])].map((d) => registrableDomain(String(d).toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, ''))));
  const feeds = opts.feeds ? (typeof opts.feeds === 'string' ? loadFeeds(opts.feeds) : opts.feeds) : null;
  const { urls, errors } = collectUrls(inputs);
  const results = errors.map((e) => ({ target: e.source, raw: [], errors: [`${e.source}: ${e.error}`] }));
  return { brands, own, feeds, urls, results, skipped: [] };
}

function score(url, source, ctx, opts) {
  const r = analyzeUrl(url, { brands: ctx.brands, trusted: opts.trusted });
  if (r.invalid) return { invalid: true, r };
  // only external URLs are scored: links to your own (protected) domains are skipped unless includeOwn is set
  if (!opts.includeOwn && r.domain && ctx.own.has(r.domain)) return { own: true, r };
  const hit = matchFeeds(url, ctx.feeds);
  if (hit) r.signals.unshift({ rule: 'known-phishing', message: `Listed in the ${hit.feed} feed (${hit.match} match)`, evidence: hit.feed, weight: 100 });
  return { r };
}

function finalize(url, source, r, extra = []) {
  for (const x of extra) { const known = RULES[x.rule] && !['phishing-likely', 'phishing-suspicious'].includes(x.rule); r.signals.push({ rule: known ? x.rule : 'plugin-signal', message: known ? x.message : `${x.rule}: ${x.message}`, evidence: x.evidence, weight: Number(x.weight) || 0 }); }
  r.score = Math.min(100, r.signals.reduce((a, x) => a + x.weight, 0)); r.verdict = verdictOf(r.score);
  const loc = source ? `${source}: ${url}` : url;
  const raw = r.signals.map((s) => ({ rule: s.rule, location: loc, message: s.message, evidence: s.evidence, score: s.weight }));
  if (r.verdict === 'likely-phishing' || r.verdict === 'suspicious') raw.unshift({ rule: r.verdict === 'likely-phishing' ? 'phishing-likely' : 'phishing-suspicious', location: loc, message: `Score ${r.score}/100 (${r.signals.map((s) => s.rule).join(', ')})`, evidence: r.domain, score: r.score });
  return { target: url, summary: { domain: r.domain, ...(r.unicodeHost ? { unicodeHost: r.unicodeHost } : {}), score: r.score, verdict: r.verdict, ...(source ? { source } : {}) }, raw };
}

const invalidResult = (url, source) => ({ target: url, raw: [{ rule: 'invalid-url', location: source ? `${source}: ${url}` : url, message: `Not a valid http(s) URL: ${url.slice(0, 100)}` }] });

/**
 * Score external URLs offline. Options: protect (your domains: lookalike detection, and their own URLs are skipped),
 * own (more first-party domains to skip), includeOwn, trusted (skip these domains), builtinBrands (default true),
 * feeds (cache dir/file from updateFeeds, or loadFeeds() result), plugins (sync analyze only; use checkAsync for async), allow, severity.
 */
export function check(inputs, opts = {}) {
  const ctx = prepare(inputs, opts);
  for (const { url, source } of ctx.urls) {
    const s = score(url, source, ctx, opts);
    if (s.invalid) { ctx.results.push(invalidResult(url, source)); continue; }
    if (s.own) { ctx.skipped.push(url); continue; }
    const extra = [];
    for (const p of opts.plugins || []) { const v = p.analyze(url, { domain: s.r.domain, source }); if (v && typeof v.then === 'function') throw new TypeError(`plugin ${p.name || '?'} is async; use checkAsync()`); extra.push(...(v || [])); }
    ctx.results.push(finalize(url, source, s.r, extra));
  }
  const rep = buildReport(TOOL, ctx.results, opts); if (ctx.skipped.length) rep.skippedOwn = ctx.skipped.length; return rep;
}

/** Like check(), but awaits async plugins (e.g. imageHashPlugin). */
export async function checkAsync(inputs, opts = {}) {
  const ctx = prepare(inputs, opts);
  for (const { url, source } of ctx.urls) {
    const s = score(url, source, ctx, opts);
    if (s.invalid) { ctx.results.push(invalidResult(url, source)); continue; }
    if (s.own) { ctx.skipped.push(url); continue; }
    const extra = [];
    for (const p of opts.plugins || []) { try { extra.push(...((await p.analyze(url, { domain: s.r.domain, source })) || [])); } catch {} }
    ctx.results.push(finalize(url, source, s.r, extra));
  }
  const rep = buildReport(TOOL, ctx.results, opts); if (ctx.skipped.length) rep.skippedOwn = ctx.skipped.length; return rep;
}

/** Generate lookalikes of your domain and (optionally) check which are registered. opts: { check, rdap, resolver, fetch, limit, ascii, tlds } */
export async function lookalikeReport(domain, opts = {}) {
  const cands = generateLookalikes(domain, opts);
  const results = [];
  if (!opts.check) {
    results.push({ target: domain, summary: { candidates: cands.length, list: cands.map((c) => c.domain) }, raw: [] });
    return buildReport(TOOL, results, opts);
  }
  const checked = await checkRegistrations(cands, opts);
  const reg = checked.filter((c) => c.registered);
  results.push({ target: domain, summary: { candidates: cands.length, registered: reg.length, unknown: checked.filter((c) => c.registered === null).length },
    raw: reg.map((c) => ({ rule: 'lookalike-registered', location: c.domain, message: `${c.domain} (${c.kind}) is registered${c.rdap?.events?.registration ? ` since ${c.rdap.events.registration.slice(0, 10)}` : ''}${c.rdap?.registrar ? ` via ${c.rdap.registrar}` : ''}${c.dns.a?.length ? `, resolves to ${c.dns.a.slice(0, 2).join(', ')}` : ''}`, evidence: c.kind })) });
  return buildReport(TOOL, results, opts);
}

export function formatTable(report) {
  return report.targets.map((t) => `${String(t.summary?.score ?? '-').padStart(3)}  ${(t.summary?.verdict || (t.errors.length ? 'error' : 'invalid')).padEnd(15)} ${t.target}`).join('\n') + '\n';
}
