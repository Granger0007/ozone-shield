/* OZONE Shield website Worker.
 *
 * The site is static files; this Worker only answers /api/* (see
 * run_worker_first in wrangler.jsonc). Everything else goes straight to the
 * files in ./public.
 *
 * GET /api/threats returns a small JSON snapshot for the Threat Watch page.
 * Visitors never trigger calls to outside services: a scheduled job refreshes
 * the snapshot every 30 minutes and keeps it in Workers KV, and requests only
 * read it. So a visitor's IP address is never sent to CISA, GitHub or the
 * Cloudflare Radar API, and nobody can use this endpoint to hammer them.
 *
 * Sources
 *   CISA Known Exploited Vulnerabilities, from CISA's own GitHub mirror
 *   (github.com/cisagov/kev-data). Newest entries come first in the file, so
 *   only the first 48 KB is fetched and read: parsing the full 1.8 MB file
 *   would use most of the free plan's 10 ms of CPU.
 *   Cloudflare Radar layer 7 attack data, CC BY-NC 4.0, attributed on the
 *   page. Needs the RADAR_TOKEN secret (a read-only Radar API token); without
 *   it the snapshot simply has no attack data.
 *
 * Every value from outside is checked against a strict pattern before it is
 * stored, and the page only ever writes it with textContent.
 */

// CISA's own feed first; its official GitHub mirror if that fails (GitHub's
// raw host rate-limits busy shared addresses, which Workers use).
const KEV_URLS = [
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
  'https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json',
];
const KEV_BYTES = 48 * 1024;
const KEV_LATEST = 12;
const RADAR = 'https://api.cloudflare.com/client/v4/radar/attacks/layer7/top';
const RADAR_RANGE = '7d';
const KEY = 'threats';
const LOCK = 'threats:refreshing';

const JSON_HEADERS = {
  'Content-Type': 'application/json; charset=utf-8',
  'X-Content-Type-Options': 'nosniff',
  'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Referrer-Policy': 'no-referrer',
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains',
};

function json(body, status, extra) {
  return new Response(JSON.stringify(body), { status, headers: { ...JSON_HEADERS, ...extra } });
}

/* ---------- checking outside values ---------- */
const text = (v, max) => (typeof v === 'string' ? v.replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, max) : '');
const cc = (v) => (typeof v === 'string' && /^[A-Z]{2}$/.test(v) ? v : null);
const day = (v) => (typeof v === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(v) ? v : null);
const pct = (v) => { const n = Number(v); return Number.isFinite(n) && n >= 0 && n <= 100 ? Math.round(n * 100) / 100 : null; };

/* ---------- CISA KEV: read the newest entries from the start of the file ---------- */

// Returns the complete JSON objects inside the "vulnerabilities" array that
// fit in `src`, skipping the last one if it was cut off.
export function kevObjects(src, max) {
  const out = [];
  let i = src.indexOf('"vulnerabilities"');
  if (i < 0) return out;
  i = src.indexOf('[', i);
  if (i < 0) return out;
  let depth = 0, start = -1, inStr = false, esc = false;
  for (i += 1; i < src.length && out.length < max; i++) {
    const ch = src[i];
    if (inStr) {
      if (esc) esc = false;
      else if (ch === '\\') esc = true;
      else if (ch === '"') inStr = false;
      continue;
    }
    if (ch === '"') inStr = true;
    else if (ch === '{') { if (depth === 0) start = i; depth++; }
    else if (ch === '}') {
      depth--;
      if (depth === 0 && start >= 0) {
        try { out.push(JSON.parse(src.slice(start, i + 1))); } catch { /* skip a bad entry */ }
        start = -1;
      }
    } else if (ch === ']' && depth === 0) break;
  }
  return out;
}

export function kevFromText(src) {
  const head = (re) => { const m = src.slice(0, 600).match(re); return m ? m[1] : null; };
  const latest = kevObjects(src, KEV_LATEST).map((v) => ({
    cve: typeof v.cveID === 'string' && /^CVE-\d{4}-\d{4,7}$/.test(v.cveID) ? v.cveID : null,
    vendor: text(v.vendorProject, 60),
    product: text(v.product, 80),
    name: text(v.vulnerabilityName, 160),
    added: day(v.dateAdded),
    ransomware: v.knownRansomwareCampaignUse === 'Known',
  })).filter((v) => v.cve && v.added);
  const count = Number(head(/"count":\s*(\d{1,6})/));
  return {
    version: head(/"catalogVersion":\s*"(\d{4}\.\d{2}\.\d{2})"/),
    released: head(/"dateReleased":\s*"([0-9T:.\-]{10,30}Z)"/),
    count: Number.isFinite(count) && count > 0 ? count : null,
    latest,
  };
}

async function fetchKev() {
  const failures = [];
  for (const url of KEV_URLS) {
    try { return await fetchKevFrom(url); }
    catch (e) { failures.push(new URL(url).hostname + ': ' + String(e && e.message || e).slice(0, 80)); }
  }
  throw new Error(failures.join('; '));
}

async function fetchKevFrom(url) {
  const res = await fetch(url, { headers: { Range: `bytes=0-${KEV_BYTES - 1}`, 'User-Agent': 'ozone-shield-threat-watch' } });
  if (!res.ok) throw new Error('HTTP ' + res.status);
  let src;
  if (res.status === 206) src = await res.text();
  else {
    // Server ignored the range: read only as much as we need, then stop.
    const reader = res.body.getReader();
    const dec = new TextDecoder();
    src = '';
    while (src.length < KEV_BYTES) {
      const { done, value } = await reader.read();
      if (done) break;
      src += dec.decode(value, { stream: true });
    }
    reader.cancel().catch(() => {});
  }
  const kev = kevFromText(src);
  if (!kev.latest.length) throw new Error('no entries read');
  return kev;
}

/* ---------- Cloudflare Radar: layer 7 attacks, last 7 days ---------- */
async function radarGet(path, token) {
  const res = await fetch(`${RADAR}/${path}`, { headers: { Authorization: `Bearer ${token}` } });
  if (!res.ok) throw new Error(`Radar ${path} HTTP ${res.status}`);
  const body = await res.json();
  if (!body || body.success !== true || !body.result) throw new Error(`Radar ${path}: unexpected reply`);
  return body.result;
}

export function radarFrom(pairs, origins, targets) {
  const meta = pairs.meta || {};
  const range = Array.isArray(meta.dateRange) && meta.dateRange[0] ? meta.dateRange[0] : {};
  const list = (rows, map) => (Array.isArray(rows) ? rows : []).map(map).filter(Boolean).slice(0, 12);
  return {
    from: text(range.startTime, 30) || null,
    to: text(range.endTime, 30) || null,
    updated: text(meta.lastUpdated, 30) || null,
    pairs: list(pairs.top_0, (r) => {
      const a = cc(r.originCountryAlpha2), b = cc(r.targetCountryAlpha2), v = pct(r.value);
      return a && b && v !== null ? { from: a, fromName: text(r.originCountryName, 60), to: b, toName: text(r.targetCountryName, 60), pct: v } : null;
    }),
    origins: list(origins.top_0, (r) => {
      const a = cc(r.originCountryAlpha2), v = pct(r.value);
      return a && v !== null ? { cc: a, name: text(r.originCountryName, 60), pct: v } : null;
    }),
    targets: list(targets.top_0, (r) => {
      const a = cc(r.targetCountryAlpha2), v = pct(r.value);
      return a && v !== null ? { cc: a, name: text(r.targetCountryName, 60), pct: v } : null;
    }),
  };
}

async function fetchRadar(token) {
  const q = `dateRange=${RADAR_RANGE}&format=json`;
  const [pairs, origins, targets] = await Promise.all([
    radarGet(`attacks?${q}&limit=12`, token),
    radarGet(`locations/origin?${q}&limit=8`, token),
    radarGet(`locations/target?${q}&limit=8`, token),
  ]);
  return radarFrom(pairs, origins, targets);
}

/* ---------- refresh: keep the last good data if a source fails ---------- */
export async function refresh(env) {
  const old = (await env.THREATS.get(KEY, 'json')) || {};
  const snap = { generated: new Date().toISOString(), kev: old.kev || null, kevAt: old.kevAt || null, radar: old.radar || null, radarAt: old.radarAt || null, problems: {} };
  // A short reason for any source that failed, so the snapshot explains itself
  // (no secrets: just the host and HTTP status or error name).
  const note = (name) => (e) => {
    const why = String(e && e.message || e).replace(/Bearer\s+\S+/gi, 'Bearer ***').slice(0, 200);
    snap.problems[name] = why;
    console.log('threats refresh ' + name + ':', why);
  };
  const jobs = [fetchKev().then((k) => { snap.kev = k; snap.kevAt = snap.generated; }, note('kev'))];
  if (env.RADAR_TOKEN) jobs.push(fetchRadar(env.RADAR_TOKEN).then((r) => { snap.radar = r; snap.radarAt = snap.generated; }, note('radar')));
  else snap.problems.radar = 'not connected (no RADAR_TOKEN)';
  await Promise.all(jobs);
  await env.THREATS.put(KEY, JSON.stringify(snap));
  return snap;
}

/* ---------- the API ---------- */
async function threats(request, env, ctx) {
  if (request.method !== 'GET' && request.method !== 'HEAD') return json({ error: 'Method not allowed' }, 405, { Allow: 'GET, HEAD' });
  const body = await env.THREATS.get(KEY);
  if (body) {
    return new Response(request.method === 'HEAD' ? null : body, { status: 200, headers: { ...JSON_HEADERS, 'Cache-Control': 'public, max-age=300' } });
  }
  // First run after deploy: start one refresh (at most one a minute), say so.
  if (!(await env.THREATS.get(LOCK))) {
    await env.THREATS.put(LOCK, '1', { expirationTtl: 60 });
    ctx.waitUntil(refresh(env).catch(() => {}));
  }
  return json({ status: 'warming' }, 503, { 'Retry-After': '30', 'Cache-Control': 'no-store' });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === '/api/threats') return threats(request, env, ctx);
    if (url.pathname.startsWith('/api/')) return json({ error: 'Not found' }, 404);
    return env.ASSETS.fetch(request);
  },
  async scheduled(event, env, ctx) {
    ctx.waitUntil(refresh(env));
  },
};
