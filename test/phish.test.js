import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { analyzeUrl, extractUrls, registrableDomain, skeleton, distance, check, exitCode, brandTable } from '../src/index.js';
const F = new URL('./fixtures/', import.meta.url).pathname;
const R = (u, o) => analyzeUrl(u, o).signals.map((s) => s.rule);

test('registrableDomain handles multi-label suffixes', () => {
  assert.equal(registrableDomain('a.b.example.co.uk'), 'example.co.uk');
  assert.equal(registrableDomain('www.paypal.com.evil.xyz'), 'evil.xyz');
});
test('skeleton and distance', () => { assert.equal(skeleton('rnicros0ft'), 'microsoft'); assert.equal(skeleton('аррӏе'), 'apple'); assert.equal(distance('paypal', 'paypla'), 1); assert.equal(distance('abc', 'abc'), 0); });
test('legitimate URLs are clean', () => {
  for (const u of ['https://paypal.com/signin', 'https://www.amazon.co.uk/gp/cart', 'https://login.microsoftonline.com/common', 'https://github.com/a/b', 'https://en.wikipedia.org/wiki/Apple_Inc.', 'https://www.bbc.co.uk/news', 'https://news.ycombinator.com', 'https://www.nytimes.com/2026/google-antitrust.html'])
    assert.equal(analyzeUrl(u).score, 0, u);
});
test('lookalikes and homographs', () => {
  assert.ok(R('https://paypa1.com/login').includes('brand-lookalike'));
  assert.ok(R('https://arnazon.com').includes('brand-lookalike'));
  assert.ok(R('https://xn--pple-43d.com/').includes('homograph'));
  assert.equal(analyzeUrl('https://xn--pple-43d.com/').unicodeHost, 'аpple.com');
});
test('impersonation, userinfo, IP, TLD, shortener, redirect, free hosting', () => {
  assert.ok(R('https://www.paypal.com.secure-login.xyz/verify').includes('brand-impersonation'));
  assert.ok(R('https://www.paypal.com.secure-login.xyz/verify').includes('risky-tld'));
  assert.ok(R('https://micros0ft-support.com').includes('brand-impersonation'));
  assert.deepEqual(R('https://bank.com@203.0.113.9/').slice(0, 2), ['userinfo-trick', 'ip-host']);
  assert.ok(R('http://0xC0A80105/').includes('ip-host'));
  assert.ok(R('https://bit.ly/x').includes('shortener'));
  assert.ok(R('https://example.com/?next=https://evil.io').includes('open-redirect'));
  assert.ok(!R('https://example.com/?next=https://www.example.com/a').includes('open-redirect'));
  assert.ok(R('https://site.weebly.com/office365-login').includes('free-hosting'));
  assert.ok(R('https://example.org/files/invoice.pdf.exe').includes('risky-download'));
  assert.ok(R('javascript:alert(1)').includes('dangerous-scheme'));
});
test('verdicts', () => {
  assert.equal(analyzeUrl('https://www.paypal.com.secure-login.xyz/verify').verdict, 'likely-phishing');
  assert.equal(analyzeUrl('https://bit.ly/x').verdict, 'low-risk');
  assert.equal(analyzeUrl('https://example.com').verdict, 'clean');
});
test('protected brands: typo, TLD swap, trusted', () => {
  const brands = brandTable(['acme-corp.com']);
  assert.ok(R('https://acme-c0rp.com/sso', { brands }).includes('brand-lookalike'));
  assert.ok(R('https://acme-corp.net/', { brands }).includes('brand-lookalike'));
  assert.equal(analyzeUrl('https://sso.acme-corp.com/', { brands }).score, 0);
  assert.equal(analyzeUrl('https://bit.ly/x', { trusted: ['bit.ly'] }).score, 0);
});
test('extractUrls refangs and decodes quoted-printable', () => {
  assert.deepEqual(extractUrls('go to hxxps://evil[.]com/x, now'), ['https://evil.com/x']);
  assert.deepEqual(extractUrls('<a href=3D"https://a.top/x?b=3D1">'), ['https://a.top/x?b=1']);
});
test('check report and exit code', () => {
  const r = check([F + 'urls.txt', F + 'mail.eml'], { protect: ['acme-corp.com'] });
  assert.ok(r.findings.some((f) => f.rule === 'phishing-likely'));
  assert.equal(exitCode(r, 'high'), 1);
  assert.equal(exitCode(check(['https://example.com']), 'high'), 0);
  const inv = check(['http://[bad']); assert.equal(inv.findings[0].rule, 'invalid-url');
});
test('CLI', () => {
  const bin = new URL('../bin/phish-sentinel.js', import.meta.url).pathname;
  for (const f of ['json', 'sarif', 'markdown', 'text', 'table']) { const p = spawnSync('node', [bin, F + 'urls.txt', '-f', f]); assert.equal(p.status, 1, f); assert.ok(p.stdout.length); }
  const p = spawnSync('node', [bin, '-', '-f', 'table'], { input: 'mail from hxxp://paypa1[.]com/login' }); assert.match(p.stdout.toString(), /paypa1\.com/);
  assert.equal(spawnSync('node', [bin, 'https://example.com']).status, 0);
  assert.equal(spawnSync('node', [bin]).status, 2);
});
