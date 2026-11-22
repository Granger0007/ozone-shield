// Run with: node --test worker/test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import worker, { kevObjects, kevFromText, radarFrom, refresh } from '../index.js';

// The first 48 KB of the real CISA KEV file (catalogue 2026.11.20), cut mid-entry.
const head = readFileSync(new URL('./kev-head.json', import.meta.url), 'utf8');

test('reads the newest KEV entries from a cut-off file', () => {
  const kev = kevFromText(head);
  assert.equal(kev.version, '2026.11.20');
  assert.equal(kev.count, 1790);
  assert.equal(kev.latest.length, 12);
  assert.equal(kev.latest[0].cve, 'CVE-2026-129448');
  assert.equal(kev.latest[0].vendor, 'Apache');
  assert.match(kev.latest[0].added, /^\d{4}-\d{2}-\d{2}$/);
});

test('skips the entry that was cut off and copes with braces inside strings', () => {
  const src = '{"vulnerabilities": [{"cveID":"CVE-2026-0001","dateAdded":"2026-01-01","notes":"a } b { c \\" d"},{"cveID":"CVE-2026-0002","date';
  const objs = kevObjects(src, 10);
  assert.equal(objs.length, 1);
  assert.equal(objs[0].notes, 'a } b { c " d');
});

test('drops entries with a malformed CVE ID or date, and trims long text', () => {
  const src = JSON.stringify({ count: 3, vulnerabilities: [
    { cveID: '<script>alert(1)</script>', dateAdded: '2026-01-01' },
    { cveID: 'CVE-2026-1234', dateAdded: 'yesterday' },
    { cveID: 'CVE-2026-5678', dateAdded: '2026-02-02', vendorProject: 'x'.repeat(500), knownRansomwareCampaignUse: 'Known' },
  ] });
  const kev = kevFromText(src);
  assert.equal(kev.latest.length, 1);
  assert.equal(kev.latest[0].vendor.length, 60);
  assert.equal(kev.latest[0].ransomware, true);
});

test('keeps only valid Radar rows', () => {
  const meta = { dateRange: [{ startTime: '2026-11-15T00:00:00Z', endTime: '2026-11-22T00:00:00Z' }], lastUpdated: '2026-11-22T01:00:00Z' };
  const r = radarFrom(
    { meta, top_0: [
      { originCountryAlpha2: 'US', originCountryName: 'United States', targetCountryAlpha2: 'GB', targetCountryName: 'United Kingdom', value: '4.5' },
      { originCountryAlpha2: 'u<s', targetCountryAlpha2: 'GB', value: '1' },
      { originCountryAlpha2: 'DE', targetCountryAlpha2: 'FR', value: '900' },
    ] },
    { top_0: [{ originCountryAlpha2: 'US', originCountryName: 'United States', value: '20.123' }] },
    { top_0: [{ targetCountryAlpha2: 'GB', targetCountryName: 'United Kingdom', value: 'NaN' }] },
  );
  assert.deepEqual(r.pairs, [{ from: 'US', fromName: 'United States', to: 'GB', toName: 'United Kingdom', pct: 4.5 }]);
  assert.deepEqual(r.origins, [{ cc: 'US', name: 'United States', pct: 20.12 }]);
  assert.deepEqual(r.targets, []);
  assert.equal(r.updated, '2026-11-22T01:00:00Z');
});

function memKV() {
  const m = new Map();
  return { m, async get(k, t) { const v = m.get(k); return v == null ? null : t === 'json' ? JSON.parse(v) : v; }, async put(k, v) { m.set(k, v); } };
}

test('refresh keeps the last good data when a source fails', async () => {
  const env = { THREATS: memKV() };
  const real = globalThis.fetch;
  try {
    globalThis.fetch = async () => new Response(head, { status: 206 });
    const first = await refresh(env);
    assert.equal(first.kev.latest[0].cve, 'CVE-2026-129448');
    assert.equal(first.radar, null); // no token, no attack data
    globalThis.fetch = async () => new Response('down', { status: 503 });
    const second = await refresh(env);
    assert.equal(second.kev.latest[0].cve, 'CVE-2026-129448');
    assert.equal(second.kevAt, first.kevAt);
    assert.match(second.problems.kev, /www\.cisa\.gov: HTTP 503; raw\.githubusercontent\.com: HTTP 503/);
    assert.equal(second.problems.radar, 'not connected (no RADAR_TOKEN)');
  } finally { globalThis.fetch = real; }
});

test('API: serves the snapshot, refuses writes, 404s other paths', async () => {
  const env = { THREATS: memKV(), ASSETS: { fetch: () => new Response('asset') } };
  const ctx = { waitUntil() {} };
  await env.THREATS.put('threats', '{"generated":"x"}');
  let res = await worker.fetch(new Request('https://s/api/threats'), env, ctx);
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('X-Content-Type-Options'), 'nosniff');
  assert.equal(await res.text(), '{"generated":"x"}');
  res = await worker.fetch(new Request('https://s/api/threats', { method: 'POST' }), env, ctx);
  assert.equal(res.status, 405);
  res = await worker.fetch(new Request('https://s/api/other'), env, ctx);
  assert.equal(res.status, 404);
});

test('API: before the first refresh it says "warming" and starts only one refresh', async () => {
  const env = { THREATS: memKV() };
  let started = 0;
  const ctx = { waitUntil(p) { started++; p.catch(() => {}); } };
  const real = globalThis.fetch;
  globalThis.fetch = async () => new Response('down', { status: 503 });
  try {
    const a = await worker.fetch(new Request('https://s/api/threats'), env, ctx);
    const b = await worker.fetch(new Request('https://s/api/threats'), env, ctx);
    assert.equal(a.status, 503);
    assert.equal(b.status, 503);
    assert.equal(started, 1);
  } finally { globalThis.fetch = real; }
});

test('falls back to the GitHub mirror when cisa.gov refuses', async () => {
  const env = { THREATS: memKV() };
  const real = globalThis.fetch; const asked = [];
  globalThis.fetch = async (url) => { asked.push(new URL(url).hostname); return new URL(url).hostname === 'www.cisa.gov' ? new Response('no', { status: 403 }) : new Response(head, { status: 206 }); };
  try {
    const snap = await refresh(env);
    assert.deepEqual(asked, ['www.cisa.gov', 'raw.githubusercontent.com']);
    assert.equal(snap.kev.latest.length, 12);
    assert.equal(snap.problems.kev, undefined);
  } finally { globalThis.fetch = real; }
});

test('reads a compressed download as a stream, and keeps what arrived before a broken stream', async () => {
  const env = { THREATS: memKV() };
  const real = globalThis.fetch; const sent = [];
  // Real-world failure: the body breaks part-way, as a cut gzip stream does.
  globalThis.fetch = async (url, init) => {
    sent.push(init.headers);
    const bytes = new TextEncoder().encode(head); let i = 0;
    const body = new ReadableStream({ pull(c) { if (i < bytes.length) { c.enqueue(bytes.slice(i, i + 4096)); i += 4096; } else c.error(new Error('Gzip compressed stream ended prematurely.')); } });
    return new Response(body, { status: 200 });
  };
  try {
    const snap = await refresh(env);
    assert.equal(snap.kev.latest.length, 12);
    assert.equal(snap.problems.kev, undefined);
    assert.equal(sent[0].Range, undefined); // no byte range: it breaks compressed replies
  } finally { globalThis.fetch = real; }
});
