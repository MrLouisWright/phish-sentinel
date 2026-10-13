import { domainToUnicode } from 'node:url';
import { MULTI_SUFFIX, BRANDS, RISKY_TLDS, SHORTENERS, FREE_HOSTS, LURE_WORDS, RISKY_EXT, CONFUSABLES } from './data.js';

export const WEIGHTS = { 'brand-lookalike': 60, homograph: 70, 'brand-impersonation': 45, 'userinfo-trick': 50, 'dangerous-scheme': 60, 'ip-host': 30, punycode: 15, 'risky-tld': 15, 'free-hosting': 20, shortener: 15, 'open-redirect': 20, 'credential-lure': 20, 'risky-download': 25, 'deep-subdomain': 10, 'hyphenated-domain': 10, 'random-domain': 10, 'encoded-url': 10, 'non-standard-port': 10, 'plain-http': 5, 'long-url': 5 };

export function registrableDomain(host) {
  const labels = host.toLowerCase().replace(/\.$/, '').split('.');
  if (labels.length <= 2) return labels.join('.');
  const last2 = labels.slice(-2).join('.');
  return MULTI_SUFFIX.has(last2) ? labels.slice(-3).join('.') : last2;
}
const suffixOf = (rd) => { const l = rd.split('.'); return MULTI_SUFFIX.has(l.slice(-2).join('.')) && l.length > 2 ? l.slice(-2).join('.') : l.slice(-1)[0]; };
const labelOf = (rd) => rd.slice(0, rd.length - suffixOf(rd).length - 1);

export function skeleton(s) {
  let out = ''; for (const ch of s.normalize('NFC').toLowerCase()) out += CONFUSABLES[ch] ?? ch;
  return out.replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/0/g, 'o').replace(/[1|]/g, 'l').replace(/3/g, 'e').replace(/5/g, 's').replace(/\$/g, 's').replace(/4/g, 'a').replace(/7/g, 't').replace(/8/g, 'b');
}
export function distance(a, b) { // Damerau-Levenshtein (optimal string alignment)
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]); for (let j = 1; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) for (let j = 1; j <= b.length; j++) {
    d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
  }
  return d[a.length][b.length];
}
const entropy = (s) => { const c = {}; for (const ch of s) c[ch] = (c[ch] || 0) + 1; return -Object.values(c).reduce((e, n) => e + (n / s.length) * Math.log2(n / s.length), 0); };
const scripts = (s) => { const out = new Set(); for (const ch of s) { if (/[a-z]/i.test(ch)) out.add('Latin'); else if (/\p{Script=Cyrillic}/u.test(ch)) out.add('Cyrillic'); else if (/\p{Script=Greek}/u.test(ch)) out.add('Greek'); else if (/\p{Script=Armenian}/u.test(ch)) out.add('Armenian'); else if (/\p{L}/u.test(ch)) out.add('Other'); } return out; };

function ipHost(h) {
  if (/^\[.*\]$/.test(h)) return 'IPv6';
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) return 'IPv4';
  if (/^(0x[0-9a-f]+|\d{8,10})$/i.test(h) || /^(0x[0-9a-f]+|0\d+|\d+)(\.(0x[0-9a-f]+|0\d+|\d+)){1,3}$/i.test(h)) return 'obfuscated IP';
  return null;
}

/** Build the brand table: built-ins plus protected domains (name derived from the label). */
export function brandTable(extra = [], { builtin = true } = {}) {
  const t = builtin ? Object.fromEntries(Object.entries(BRANDS).map(([k, v]) => [k, [...v]])) : {};
  const protectedLabels = new Set();
  for (const d of extra) { const rd = registrableDomain(String(d).replace(/^https?:\/\//, '').split('/')[0]); const l = labelOf(rd); protectedLabels.add(l); (t[l] ||= []).push(rd); const n = l.replace(/[^a-z0-9]/g, ''); if (n !== l) (t[n] ||= []).push(rd); }
  Object.defineProperty(t, '_protected', { value: protectedLabels });
  return t;
}

/** Analyse one URL. Returns { url, host, domain, score, verdict, signals:[{rule, message, evidence, weight}] } */
export function analyzeUrl(input, opts = {}) {
  const brands = opts.brands || brandTable(opts.protect || []);
  const own = new Set(Object.values(brands).flat());
  const trusted = new Set((opts.trusted || []).map((d) => d.toLowerCase()));
  const sig = []; const add = (rule, message, evidence) => sig.push({ rule, message, evidence, weight: WEIGHTS[rule] ?? 0 });
  const raw = String(input).trim();
  if (/^\s*(javascript|data|vbscript):/i.test(raw)) { add('dangerous-scheme', `${raw.split(':')[0].toLowerCase()}: URL`, raw.slice(0, 60)); return finish({ url: raw, host: null, domain: null, signals: sig }); }
  let u; try { u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `http://${raw}`); } catch { return { url: raw, invalid: true, score: 0, verdict: 'invalid', signals: [] }; }
  if (!/^(https?|ftp):$/.test(u.protocol)) return { url: raw, invalid: true, score: 0, verdict: 'invalid', signals: [] };
  const host = u.hostname.toLowerCase(); const uhost = domainToUnicode(host) || host; const ip = ipHost(host);
  const domain = ip ? host : registrableDomain(host); const isOwn = own.has(domain) || trusted.has(domain);
  const res = { url: raw, host, unicodeHost: uhost !== host ? uhost : undefined, domain };
  if (trusted.has(domain)) return finish({ ...res, signals: [] });
  if (u.username || /@/.test(raw.split('/').slice(0, 3).join('/'))) add('userinfo-trick', `Real host is ${host}; "${decodeURIComponent(u.username)}${u.password ? ':…' : ''}@" before it is decoration`, u.username);
  if (ip) add('ip-host', `Host is ${ip === 'IPv4' || ip === 'IPv6' ? `an ${ip} address` : 'an obfuscated IP address'} (${host})`, host);
  if (!ip) {
    const labels = host.split('.'); const tld = labels[labels.length - 1]; const dl = labelOf(domain);
    const udl = labelOf(registrableDomain(uhost));
    if (host.includes('xn--')) {
      add('punycode', `Internationalised domain ${uhost}`, host);
      const sc = scripts(udl);
      const sk = skeleton(udl);
      const hit = Object.entries(brands).find(([, ds]) => ds.some((d) => labelOf(d) === sk));
      if (hit) add('homograph', `${uhost} renders like ${hit[1][0]}`, uhost);
      else if (sc.size > 1 && sc.has('Latin')) add('homograph', `${uhost} mixes ${[...sc].join(' and ')} characters`, uhost);
    }
    if (RISKY_TLDS.has(tld) || RISKY_TLDS.has(labels.slice(-2).join('.'))) add('risky-tld', `.${tld} is heavily abused for phishing`, tld);
    if (SHORTENERS.has(domain) || SHORTENERS.has(host)) add('shortener', `${host} is a URL shortener; the destination is hidden`, host);
    const fh = FREE_HOSTS.find((f) => host === f || host.endsWith('.' + f) || (f.includes('/') && (host + u.pathname).startsWith(f)));
    if (fh && !isOwn) add('free-hosting', `Hosted on ${fh} (anyone can publish there)`, fh);
    else if (fh && /^(sites|docs)\.google\.com$/.test(fh)) add('free-hosting', `Hosted on ${fh} (anyone can publish there)`, fh);
    if (!isOwn && !host.includes('xn--')) {
      const sk = skeleton(dl);
      for (const [name, ds] of Object.entries(brands)) {
        for (const bd of ds) {
          const bl = labelOf(bd);
          if (dl === bl && brands._protected?.has(bl)) { add('brand-lookalike', `${domain} uses your brand name ${bl} on a different suffix than ${bd}`, domain); break; }
          if (bl.length < 4 || dl === bl) continue;
          const dist = distance(dl, bl);
          if (sk === bl || (bl.length >= 5 && dist === 1) || (bl.length >= 8 && dist === 2)) { add('brand-lookalike', `${domain} looks like ${bd}`, domain); break; }
        }
        if (sig.some((s) => s.rule === 'brand-lookalike')) break;
      }
    }
    if (!isOwn && !sig.some((s) => s.rule === 'brand-lookalike' || s.rule === 'homograph')) {
      const tokens = new Set([...labels.slice(0, -1).flatMap((l) => l.split(/[^a-z0-9]+/)), ...decodeURIComponent(u.pathname + ' ' + u.search).toLowerCase().split(/[^a-z0-9]+/)].filter(Boolean));
      const hay = labels.slice(0, -1).join('.'); const skHay = skeleton(hay);
      for (const [name, ds] of Object.entries(brands)) {
        if (ds.includes(domain)) continue;
        const inHost = name.length >= 5 ? (hay.includes(name) || skHay.includes(name)) : tokens.has(name) && labels.slice(0, -1).some((l) => l.split(/[^a-z0-9]+/).includes(name));
        const inPath = !inHost && name.length >= 5 && tokens.has(name) && (sig.length > 0 || LURE_WORDS.test(u.pathname));
        if (inHost || inPath) { add('brand-impersonation', `"${name}" appears in the ${inHost ? 'host name' : 'path'} but the site is ${domain}, not ${ds[0]}`, name); break; }
      }
    }
    const sub = labels.length - domain.split('.').length;
    if (sub >= 4) add('deep-subdomain', `${sub} subdomain levels (${host})`, host);
    const hy = dl.startsWith('xn--') ? 0 : (dl.match(/-/g) || []).length; if (hy >= 3) add('hyphenated-domain', `${hy} hyphens in ${domain}`, domain);
    const digits = (dl.match(/\d/g) || []).length;
    if (dl.length >= 12 && (entropy(dl) > 3.8 || digits / dl.length > 0.3) || /^[bcdfghjklmnpqrstvwxz]{6,}$/.test(dl)) add('random-domain', `${domain} looks machine-generated`, domain);
  }
  const lure = LURE_WORDS.exec(host + u.pathname);
  if (lure && !isOwn && sig.length) add('credential-lure', `"${lure[0]}" on ${domain}`, lure[0]);
  for (const [k, v] of u.searchParams) if (/^(https?:)?\/\/|^https?%3a/i.test(v) || /^(https?:)?\/\//i.test(decodeURIComponent(v))) { try { const t = new URL(v.startsWith('//') ? 'https:' + v : v); if (registrableDomain(t.hostname) !== domain) { add('open-redirect', `Parameter ${k} points to ${t.hostname}`, k); break; } } catch {} }
  if (RISKY_EXT.test(u.pathname) && !/\.com$/i.test(u.pathname.split('/').pop() || '') ) add('risky-download', `Downloads ${u.pathname.split('/').pop()}`, u.pathname.split('/').pop());
  const pct = (raw.match(/%[0-9a-f]{2}/gi) || []).length;
  if (pct >= 10 || /%[0-9a-f]{2}/i.test(raw.split('/')[2] || '')) add('encoded-url', `${pct} percent-encoded characters`, String(pct));
  if (u.port && !['80', '443', '8080', '8443'].includes(u.port)) add('non-standard-port', `Port ${u.port}`, u.port);
  if (u.protocol === 'http:' && sig.length) add('plain-http', 'Plain http://', 'http');
  if (raw.length > 150) add('long-url', `${raw.length} characters long`, String(raw.length));
  return finish({ ...res, signals: sig });
}

function finish(r) {
  const s = r.signals.reduce((a, x) => a + x.weight, 0);
  r.score = Math.min(100, s);
  r.verdict = r.score >= 70 ? 'likely-phishing' : r.score >= 40 ? 'suspicious' : r.score > 0 ? 'low-risk' : 'clean';
  return r;
}

const URL_RE = /\b(?:https?|ftp|hxxps?):\/\/[^\s"'<>()[\]{}`]+|\bwww\.[a-z0-9-]+(?:\.[a-z0-9-]+)+[^\s"'<>()[\]{}`]*/gi;
/** Pull URLs out of free text (also refangs hxxp and [.]). */
export function extractUrls(text) {
  let t0 = String(text);
  if (/=3D|=\r?\n/i.test(t0)) t0 = t0.replace(/=\r?\n/g, '').replace(/=([0-9A-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
  const t = t0.replace(/hxxp/gi, 'http').replace(/\[\.\]|\(\.\)|\{\.\}/g, '.').replace(/\[:\]/g, ':')
;
  const out = new Set(); for (const m of t.matchAll(URL_RE)) out.add(m[0].replace(/[.,;:!?]+$/, '')); return [...out];
}
