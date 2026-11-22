// Run with: node --test worker/test/news.test.mjs
// Feeds here are made up, so no publisher's articles are copied into the repo.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseFeed, rankNews, NEWS_SOURCES } from '../news.js';
import { refreshNews } from '../index.js';

const src = (id) => NEWS_SOURCES.find((s) => s.id === id);
const NOW = Date.parse('2026-11-22T12:00:00Z');
const ago = (h) => new Date(NOW - h * 3600e3).toUTCString();
const rss = (items) => '<?xml version="1.0"?><rss><channel>' + items.map((i) =>
  `<item><title><![CDATA[${i.t}]]></title><link>${i.l}</link><pubDate>${i.d}</pubDate><description><![CDATA[${i.x || ''}]]></description></item>`).join('') + '</channel></rss>';

test('reads title, link, date and CVEs; decodes entities', () => {
  const items = parseFeed(rss([{ t: 'Attackers&#8217; exploit CVE-2026-1111 &amp; more', l: 'https://www.bleepingcomputer.com/news/a', d: ago(1), x: 'Also CVE-2026-2222.' }]), src('bleeping'));
  assert.equal(items.length, 1);
  assert.equal(items[0].title, 'Attackers’ exploit CVE-2026-1111 & more');
  assert.deepEqual(items[0].cves, ['CVE-2026-1111', 'CVE-2026-2222']);
  assert.equal(items[0].exploited, true);
});

test('drops links that leave the outlet, non-https links and script in titles', () => {
  const items = parseFeed(rss([
    { t: 'Fine', l: 'https://www.bleepingcomputer.com/news/ok', d: ago(1) },
    { t: 'Elsewhere', l: 'https://evil.example/news', d: ago(1) },
    { t: 'Plain http', l: 'http://www.bleepingcomputer.com/news/x', d: ago(1) },
    { t: 'javascript', l: 'javascript:alert(1)', d: ago(1) },
    { t: '<script>alert(1)</script>Tagged', l: 'https://www.bleepingcomputer.com/news/t', d: ago(1) },
  ]), src('bleeping'));
  // Tags are stripped; what's left is plain text, and the page only ever writes it with textContent.
  assert.deepEqual(items.map((i) => i.title), ['Fine', 'alert(1) Tagged']);
});

test('the same story from several outlets is one story, and ranks first', () => {
  const b = parseFeed(rss([
    { t: 'Acme VPN zero-day exploited to breach corporate networks', l: 'https://www.bleepingcomputer.com/news/acme', d: ago(5) },
    { t: 'Small blog redesign announced', l: 'https://www.bleepingcomputer.com/news/blog', d: ago(1) },
  ]), src('bleeping'));
  const r = parseFeed(rss([{ t: 'Acme VPN zero-day under active exploitation, networks breached', l: 'https://therecord.media/acme', d: ago(3) }]), src('record'));
  const s = parseFeed(rss([{ t: 'Hackers exploit Acme VPN zero-day to breach networks', l: 'https://www.securityweek.com/acme', d: ago(2) }]), src('secweek'));
  const top = rankNews([...b, ...r, ...s], [], NOW);
  assert.equal(top[0].outlets.length, 3);
  assert.equal(top[0].title, 'Acme VPN zero-day exploited to breach corporate networks'); // first report leads
  assert.equal(top[0].exploited, true);
});

test('a CVE in the CISA exploited list and an official source lift a story', () => {
  const a = parseFeed(rss([{ t: 'Patch now: Foo Server flaw CVE-2026-5555', l: 'https://www.bleepingcomputer.com/news/foo', d: ago(10) }]), src('bleeping'));
  const n = parseFeed(rss([{ t: 'NCSC guidance for schools', l: 'https://www.ncsc.gov.uk/news/schools', d: ago(20) }]), src('ncsc'));
  const o = parseFeed(rss([{ t: 'Ordinary industry funding round', l: 'https://therecord.media/funding', d: ago(1) }]), src('record'));
  const top = rankNews([...a, ...n, ...o], ['CVE-2026-5555'], NOW);
  assert.deepEqual(top[0].inKev, ['CVE-2026-5555']);
  assert.equal(top[1].official, true);
  assert.equal(top[2].title, 'Ordinary industry funding round');
});

test('keeps to the last 72 hours when there is enough news, and ignores future dates', () => {
  const items = parseFeed(rss([
    ...[1, 2, 3, 4, 5].map((h) => ({ t: 'Recent story number ' + h + ' alpha', l: 'https://therecord.media/r' + h, d: ago(h * 5) })),
    { t: 'Very old story', l: 'https://therecord.media/old', d: ago(200) },
    { t: 'From the future', l: 'https://therecord.media/future', d: ago(-48) },
  ]), src('record'));
  const top = rankNews(items, [], NOW);
  assert.equal(top.length, 5);
  assert.ok(top.every((s) => s.title.startsWith('Recent story')));
});

function memKV() {
  const m = new Map();
  return { async get(k, t) { const v = m.get(k); return v == null ? null : t === 'json' ? JSON.parse(v) : v; }, async put(k, v) { m.set(k, v); } };
}

test('news refresh: one outlet down is noted, the rest still show', async () => {
  const env = { THREATS: memKV() };
  await env.THREATS.put('threats', JSON.stringify({ generated: 'x', kev: { latest: [{ cve: 'CVE-2026-5555' }] }, problems: {} }));
  const real = globalThis.fetch;
  globalThis.fetch = async (url) => {
    const host = new URL(url).hostname;
    if (host === 'krebsonsecurity.com') return new Response('blocked', { status: 403 });
    const s = NEWS_SOURCES.find((x) => new URL(x.url).hostname === host);
    return new Response(rss([{ t: s.name + ' story about CVE-2026-5555 exploited', l: 'https://' + s.hosts[0] + '/a', d: new Date().toUTCString() }]), { status: 200 });
  };
  try {
    const snap = await refreshNews(env);
    assert.ok(snap.news.top.length >= 1);
    assert.ok(snap.news.top[0].inKev.includes('CVE-2026-5555'));
    assert.match(snap.problems.news, /Krebs on Security: HTTP 403/);
    assert.equal(snap.news.sources.find((s) => s.id === 'krebs').ok, false);
    assert.equal(snap.kev.latest[0].cve, 'CVE-2026-5555'); // the rest of the snapshot is kept
  } finally { globalThis.fetch = real; }
});
