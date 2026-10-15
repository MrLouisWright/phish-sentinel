// Plugin hook: extra signals per URL. A plugin is { name, analyze(url, ctx) => signals | Promise<signals> },
// where a signal is { rule, message, evidence?, weight }. Use checkAsync() for async plugins.

/** Hamming distance between two equal-length hex perceptual hashes (aHash/dHash/pHash). */
export function hammingHex(a, b) {
  if (!a || !b || a.length !== b.length) return Infinity;
  let d = 0; for (let i = 0; i < a.length; i++) { let x = parseInt(a[i], 16) ^ parseInt(b[i], 16); while (x) { d += x & 1; x >>= 1; } } return d;
}

/**
 * Image fuzzy-hash plugin. You supply how to get a hash for a URL (screenshot, favicon, logo) and reference hashes of your brand;
 * phish-sentinel only compares. opts: { references: { brandName: [hexHash, ...] }, hashUrl: async (url, ctx) => hexHash|null, threshold = 10, weight = 50 }
 */
export function imageHashPlugin(opts = {}) {
  const threshold = opts.threshold ?? 10; const weight = opts.weight ?? 50;
  if (typeof opts.hashUrl !== 'function') throw new TypeError('imageHashPlugin needs hashUrl(url) returning a hex hash');
  return {
    name: 'image-hash',
    async analyze(url, ctx) {
      let h; try { h = await opts.hashUrl(url, ctx); } catch { return []; }
      if (!h) return [];
      let best = null;
      for (const [brand, refs] of Object.entries(opts.references || {})) for (const r of [].concat(refs)) { const d = hammingHex(String(h).toLowerCase(), String(r).toLowerCase()); if (d <= threshold && (!best || d < best.d)) best = { brand, d }; }
      return best ? [{ rule: 'visual-lookalike', message: `Page image matches ${best.brand} (hash distance ${best.d})`, evidence: h, weight }] : [];
    },
  };
}
