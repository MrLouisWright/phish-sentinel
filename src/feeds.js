// Optional, offline-cached phishing feeds (OpenPhish community feed, PhishTank). Never fetched unless you call updateFeeds().
import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

export const FEED_SOURCES = {
  openphish: { url: 'https://openphish.com/feed.txt', parse: (t) => t.split(/\r?\n/).map((x) => x.trim()).filter((x) => /^https?:\/\//i.test(x)) },
  phishtank: { url: (key) => `https://data.phishtank.com/data/${key ? encodeURIComponent(key) + '/' : ''}online-valid.json`, parse: (t) => JSON.parse(t).map((e) => e.url).filter(Boolean) },
};
const CACHE = 'phish-feeds.json';
export const normUrl = (u) => { try { const x = new URL(u); x.hash = ''; return (x.hostname + x.pathname.replace(/\/+$/, '') + x.search).toLowerCase(); } catch { return String(u).toLowerCase(); } };
const hostOf = (u) => { try { return new URL(u).hostname.toLowerCase(); } catch { return null; } };

/** Download feeds into cacheDir/phish-feeds.json. opts: { sources = ['openphish'], phishtankKey, fetch, now }. Returns { counts, errors, file }. */
export async function updateFeeds(cacheDir, opts = {}) {
  const f = opts.fetch || globalThis.fetch; const counts = {}; const errors = []; const feeds = {};
  const prev = existsSync(join(cacheDir, CACHE)) ? JSON.parse(readFileSync(join(cacheDir, CACHE), 'utf8')) : { feeds: {} };
  for (const s of opts.sources || ['openphish']) {
    const src = FEED_SOURCES[s]; if (!src) { errors.push(`${s}: unknown feed`); continue; }
    const url = typeof src.url === 'function' ? src.url(opts.phishtankKey) : src.url;
    try { const r = await f(url, { headers: { 'user-agent': 'phish-sentinel' } }); if (!r.ok) throw new Error(`HTTP ${r.status}`); const urls = src.parse(await r.text()); feeds[s] = { fetched: new Date(opts.now || Date.now()).toISOString(), urls }; counts[s] = urls.length; }
    catch (e) { errors.push(`${s}: ${e.message}`); if (prev.feeds?.[s]) feeds[s] = prev.feeds[s]; }
  }
  mkdirSync(cacheDir, { recursive: true });
  const file = join(cacheDir, CACHE); writeFileSync(file, JSON.stringify({ version: 1, feeds: { ...prev.feeds, ...feeds } }));
  return { counts, errors, file };
}

/** Load the cache (or a plain text list of URLs). Returns { urls: Map(norm -> feed), hosts: Map(host -> feed), age: { feed: iso } } */
export function loadFeeds(pathOrDir) {
  const file = existsSync(join(pathOrDir, CACHE)) ? join(pathOrDir, CACHE) : pathOrDir;
  const text = readFileSync(file, 'utf8'); const urls = new Map(); const hosts = new Map(); const age = {};
  let data; try { data = JSON.parse(text); } catch { data = { feeds: { list: { urls: FEED_SOURCES.openphish.parse(text) } } }; }
  for (const [name, f] of Object.entries(data.feeds || {})) { age[name] = f.fetched; for (const u of f.urls || []) { urls.set(normUrl(u), name); const h = hostOf(u); if (h && !hosts.has(h)) hosts.set(h, name); } }
  return { urls, hosts, age };
}

/** Match a URL against loaded feeds: exact URL first, then host. */
export function matchFeeds(url, feeds) {
  if (!feeds) return null;
  const n = normUrl(url); if (feeds.urls.has(n)) return { feed: feeds.urls.get(n), match: 'url' };
  const h = hostOf(url); if (h && feeds.hosts.has(h)) return { feed: feeds.hosts.get(h), match: 'host' };
  return null;
}
