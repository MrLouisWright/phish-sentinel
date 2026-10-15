// Lookalike (typosquat) domain generation and registration checks via DNS and RDAP.
import { promises as dns } from 'node:dns';
import { registrableDomain } from './analyze.js';

const KEYS = ['1234567890-', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm'];
const ADJ = {};
KEYS.forEach((row, r) => [...row].forEach((c, i) => { ADJ[c] = [row[i - 1], row[i + 1], KEYS[r - 1]?.[i], KEYS[r + 1]?.[i]].filter(Boolean).join(''); }));
const GLYPHS = { a: ['4', 'à', 'á', 'а'], b: ['d', 'lb'], c: ['e', 'с'], d: ['b', 'cl'], e: ['3', 'é', 'е'], g: ['q', '9'], h: ['lh'], i: ['1', 'l', 'í', 'і'], k: ['lk'], l: ['1', 'i', 'I'], m: ['rn', 'nn'], n: ['m', 'r'], o: ['0', 'ο', 'о'], p: ['р'], q: ['g'], s: ['5', 'ѕ'], u: ['v', 'ü'], v: ['u'], w: ['vv'], x: ['х'], y: ['у'], z: ['2'] };
const TLDS = ['com', 'net', 'org', 'co', 'io', 'app', 'info', 'biz', 'xyz', 'top', 'online', 'site', 'shop', 'co.uk', 'us', 'cc'];
const valid = (l) => /^(?!-)[a-z0-9-]{1,63}(?<!-)$/.test(l) || /[^\x00-\x7f]/.test(l);

/** Typosquat candidates for a domain, each { domain, kind }. kinds: omission, repetition, transposition, replacement, insertion, homoglyph, hyphenation, vowel-swap, bitsquat, tld-swap, subdomain-split. */
export function generateLookalikes(domain, opts = {}) {
  const d = String(domain).toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  const reg = registrableDomain(d);
  const dot = reg.indexOf('.'); const name = reg.slice(0, dot); const tld = reg.slice(dot + 1);
  const out = new Map(); const add = (n, kind, t = tld) => { if (!n || n === name && t === tld || !valid(n)) return; const x = `${n}.${t}`; if (!out.has(x)) out.set(x, { domain: x, kind }); };
  for (let i = 0; i < name.length; i++) {
    const c = name[i]; const pre = name.slice(0, i); const post = name.slice(i + 1);
    add(pre + post, 'omission');
    add(pre + c + c + post, 'repetition');
    if (i < name.length - 1) add(pre + name[i + 1] + c + name.slice(i + 2), 'transposition');
    for (const k of ADJ[c] || '') { add(pre + k + post, 'replacement'); add(pre + k + c + post, 'insertion'); add(pre + c + k + post, 'insertion'); }
    for (const g of GLYPHS[c] || []) add(pre + g + post, 'homoglyph');
    if ('aeiou'.includes(c)) for (const v of 'aeiou') if (v !== c) add(pre + v + post, 'vowel-swap');
    for (let b = 0; b < 7; b++) { const f = String.fromCharCode(c.charCodeAt(0) ^ (1 << b)); if (/[a-z0-9-]/.test(f)) add(pre + f + post, 'bitsquat'); }
    if (i > 0) { add(pre + '-' + c + post, 'hyphenation'); add(pre, 'subdomain-split', `${c + post}.${tld}`); }
  }
  for (const t of opts.tlds || TLDS) if (t !== tld) add(name, 'tld-swap', t);
  let list = [...out.values()].filter((x) => x.domain !== reg && !(x.kind === 'subdomain-split' && x.domain.split('.')[0].length < 2));
  if (opts.ascii) list = list.filter((x) => !/[^\x00-\x7f]/.test(x.domain));
  return opts.limit ? list.slice(0, opts.limit) : list;
}

async function pool(items, n, fn) { const out = new Array(items.length); let i = 0; await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => { while (i < items.length) { const k = i++; out[k] = await fn(items[k], k); } })); return out; }

/**
 * Check which candidates exist. opts: { resolver: { resolveNs, resolve4 } (default node:dns), rdap: false|true, fetch, rdapBase = 'https://rdap.org/domain/', concurrency = 8, timeout = 8000 }
 * Returns [{ domain, kind, registered: bool|null, dns: { ns, a }, rdap?: { status, registered, events } }]
 */
export async function checkRegistrations(candidates, opts = {}) {
  const r = opts.resolver || dns; const f = opts.fetch || globalThis.fetch; const base = opts.rdapBase || 'https://rdap.org/domain/';
  const ascii = (d) => { try { return new URL(`http://${d}`).hostname; } catch { return d; } };
  return pool(candidates.map((c) => (typeof c === 'string' ? { domain: c } : c)), opts.concurrency ?? 8, async (c) => {
    const host = ascii(c.domain); const res = { ...c, registered: null, dns: {} };
    const q = async (fn) => { try { return await fn(host); } catch (e) { return e.code === 'ENOTFOUND' || e.code === 'ENODATA' ? [] : null; } };
    res.dns.ns = await q((h) => r.resolveNs(h)); res.dns.a = await q((h) => r.resolve4(h));
    if (res.dns.ns?.length || res.dns.a?.length) res.registered = true; else if (res.dns.ns && res.dns.a) res.registered = false;
    if (opts.rdap) {
      try {
        const ac = new AbortController(); const t = setTimeout(() => ac.abort(), opts.timeout ?? 8000);
        const rr = await f(base + host, { signal: ac.signal, headers: { accept: 'application/rdap+json' } }); clearTimeout(t);
        if (rr.status === 404) res.rdap = { status: 404, registered: false };
        else if (rr.ok) { const j = await rr.json(); res.rdap = { status: rr.status, registered: true, events: Object.fromEntries((j.events || []).map((e) => [e.eventAction, e.eventDate])), registrar: (j.entities || []).find((e) => (e.roles || []).includes('registrar'))?.vcardArray?.[1]?.find((v) => v[0] === 'fn')?.[3] };
          res.registered = true; }
        else res.rdap = { status: rr.status, registered: null };
        if (res.rdap.registered === false && res.registered === null) res.registered = false;
      } catch (e) { res.rdap = { error: e.name === 'AbortError' ? 'timeout' : e.message }; }
    }
    return res;
  });
}
