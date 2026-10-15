import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { check, checkAsync, generateLookalikes, checkRegistrations, lookalikeReport, updateFeeds, loadFeeds, matchFeeds, imageHashPlugin, hammingHex } from '../src/index.js';

const bin = new URL('../bin/phish-sentinel.js', import.meta.url).pathname;

test('generateLookalikes covers the main typo kinds', () => {
  const l = generateLookalikes('example.com');
  const by = (k) => l.filter((x) => x.kind === k).map((x) => x.domain);
  assert.ok(by('omission').includes('exmple.com'));
  assert.ok(by('transposition').includes('exmaple.com'));
  assert.ok(by('repetition').includes('exammple.com'));
  assert.ok(by('tld-swap').includes('example.net'));
  assert.ok(by('homoglyph').includes('examp1e.com'));
  assert.ok(!l.some((x) => x.domain === 'example.com'));
  assert.ok(generateLookalikes('shop.example.co.uk', { ascii: true }).every((x) => /^[\x00-\x7f]+$/.test(x.domain) && x.domain !== 'example.co.uk'));
  assert.equal(generateLookalikes('example.com', { limit: 5 }).length, 5);
});

test('checkRegistrations uses DNS and RDAP', async () => {
  const resolver = { resolveNs: async (h) => { if (h === 'exmple.com') return ['ns1.x']; const e = new Error('x'); e.code = 'ENOTFOUND'; throw e; }, resolve4: async (h) => { if (h === 'exmple.com') return ['1.2.3.4']; const e = new Error('x'); e.code = 'ENODATA'; throw e; } };
  const fetch = async (u) => u.endsWith('/exmple.com') ? new Response(JSON.stringify({ events: [{ eventAction: 'registration', eventDate: '2026-09-01T00:00:00Z' }] }), { status: 200 }) : new Response('', { status: 404 });
  const r = await checkRegistrations(['exmple.com', 'exampel.com'], { resolver, rdap: true, fetch });
  assert.equal(r[0].registered, true); assert.equal(r[0].rdap.events.registration, '2026-09-01T00:00:00Z');
  assert.equal(r[1].registered, false);
  const rep = await lookalikeReport('example.com', { check: true, resolver, limit: 50, ascii: true });
  const f = rep.targets[0].findings;
  assert.equal(f.length, 1); assert.equal(f[0].rule, 'lookalike-registered'); assert.match(f[0].message, /1\.2\.3\.4/);
});

test('feeds: update, cache, match (offline)', async () => {
  const d = mkdtempSync(join(tmpdir(), 'ps-'));
  const fetch = async (u) => u.includes('openphish') ? new Response('https://evil.example.net/login\nhttps://bad.test/x/\n') : new Response(JSON.stringify([{ url: 'http://pt.test/a' }]));
  const u = await updateFeeds(d, { sources: ['openphish', 'phishtank', 'nope'], fetch });
  assert.deepEqual(u.counts, { openphish: 2, phishtank: 1 }); assert.equal(u.errors.length, 1);
  const feeds = loadFeeds(d);
  assert.deepEqual(matchFeeds('https://bad.test/x', feeds), { feed: 'openphish', match: 'url' });
  assert.equal(matchFeeds('https://evil.example.net/other', feeds).match, 'host');
  assert.equal(matchFeeds('https://fine.test/', feeds), null);
  const rep = check(['https://pt.test/a'], { feeds: d });
  assert.equal(rep.targets[0].summary.verdict, 'likely-phishing');
  assert.ok(rep.targets[0].findings.some((f) => f.rule === 'known-phishing'));
  // failed refresh keeps the previous cache
  await updateFeeds(d, { sources: ['openphish'], fetch: async () => new Response('', { status: 503 }) });
  assert.ok(loadFeeds(d).urls.size >= 3);
});

test('only external URLs are scored', () => {
  const r = check(['https://login.mysite.test/verify-account', 'https://mysite-login.top/verify'], { protect: ['mysite.test'] });
  assert.equal(r.targets.length, 1); assert.equal(r.skippedOwn, 1);
  assert.equal(check(['https://login.mysite.test/'], { own: ['mysite.test'], includeOwn: true }).targets.length, 1);
});

test('image hash plugin and plugin hook', async () => {
  assert.equal(hammingHex('ff00', 'ff01'), 1); assert.equal(hammingHex('ab', 'abc'), Infinity);
  const plugin = imageHashPlugin({ references: { MyBank: ['f0f0f0f0f0f0f0f0'] }, hashUrl: async (u) => (u.includes('fake') ? 'f0f0f0f0f0f0f0f1' : '0000000000000000') });
  const r = await checkAsync(['https://fake-portal.test/', 'https://other.test/'], { plugins: [plugin, { name: 'x', analyze: () => [{ rule: 'custom', message: 'hi', weight: 5 }] }] });
  const [a, b] = r.targets;
  assert.ok(a.findings.some((f) => f.rule === 'visual-lookalike'));
  assert.ok(b.findings.some((f) => f.rule === 'plugin-signal' && /custom: hi/.test(f.message)));
  assert.throws(() => check(['https://a.test/'], { plugins: [plugin] }), /checkAsync/);
});

test('CLI lookalikes lists candidates offline', () => {
  const r = spawnSync(process.execPath, [bin, 'lookalikes', 'example.com', '--limit', '3', '-f', 'table'], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr); assert.equal(r.stdout.trim().split('\n').length, 3);
});
