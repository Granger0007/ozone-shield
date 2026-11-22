/* Threat Watch news: the top 5 security stories for an analyst.
 *
 * Headlines come from the RSS feeds of trusted outlets. We never rewrite a
 * headline or copy article text: each story is its original headline and a
 * link to the publisher.
 *
 * "Top" is worked out from signals anyone can check, not from our opinion:
 *   - corroboration: how many independent outlets report the same story
 *   - an official source (the UK's NCSC)
 *   - a CVE that's in the CISA Known Exploited Vulnerabilities catalogue
 *   - words that mean active harm (exploited, zero-day, ransomware, breach)
 *   - freshness, over the last 72 hours
 *
 * Feeds are read like the KEV file: stream the first 40 KB (newest items
 * come first) and stop, so the refresh stays within the free plan's CPU.
 * Links are only kept if they point at the outlet's own website.
 */

export const NEWS_SOURCES = [
  { id: 'ncsc', name: 'NCSC', url: 'https://www.ncsc.gov.uk/api/1/services/v1/news-rss-feed.xml', hosts: ['www.ncsc.gov.uk'], official: true },
  { id: 'bleeping', name: 'BleepingComputer', url: 'https://www.bleepingcomputer.com/feed/', hosts: ['www.bleepingcomputer.com'] },
  { id: 'record', name: 'The Record', url: 'https://therecord.media/feed', hosts: ['therecord.media'] },
  { id: 'thn', name: 'The Hacker News', url: 'https://feeds.feedburner.com/TheHackersNews', hosts: ['thehackernews.com'] },
  { id: 'secweek', name: 'SecurityWeek', url: 'https://www.securityweek.com/feed/', hosts: ['www.securityweek.com'] },
  { id: 'krebs', name: 'Krebs on Security', url: 'https://krebsonsecurity.com/feed/', hosts: ['krebsonsecurity.com'] },
];

const FEED_BYTES = 28 * 1024;
const PER_SOURCE = 10;
const WINDOW_H = 72;

/* ---------- reading a feed ---------- */
const ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', '#8216': '‘', '#8217': '’', '#8220': '“', '#8221': '”', '#8211': '–', '#8212': '—', '#038': '&', '#039': "'", '#8230': '…' };
function clean(s, max) {
  if (typeof s !== 'string') return '';
  s = s.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
    .replace(/<[^>]*>/g, ' ')
    .replace(/&(#x?[0-9a-f]+|[a-z]+);/gi, (m, e) => {
      const k = e.toLowerCase();
      if (ENTITIES[k] !== undefined) return ENTITIES[k];
      const n = k[0] === '#' ? (k[1] === 'x' ? parseInt(k.slice(2), 16) : parseInt(k.slice(1), 10)) : NaN;
      return Number.isFinite(n) && n > 31 && n < 0x10ffff ? String.fromCodePoint(n) : ' ';
    })
    .replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim();
  return max ? s.slice(0, max) : s;
}
const TAGS = {};
['title', 'link', 'pubDate', 'description'].forEach((n) => { TAGS[n] = new RegExp('<' + n + '(?:\\s[^>]*)?>([\\s\\S]*?)</' + n + '>', 'i'); });
const tag = (item, name) => { const m = TAGS[name].exec(item); return m ? m[1] : ''; };

export function parseFeed(xml, source) {
  const out = [];
  const re = /<item\b[\s\S]*?<\/item>/gi;
  let m;
  while ((m = re.exec(xml)) && out.length < PER_SOURCE) {
    const it = m[0];
    const title = clean(tag(it, 'title'), 180);
    const link = clean(tag(it, 'link'), 400);
    const when = new Date(clean(tag(it, 'pubDate'), 60));
    let url;
    try { url = new URL(link); } catch { continue; }
    if (url.protocol !== 'https:' || !source.hosts.includes(url.hostname)) continue; // only the outlet's own site
    if (!title || isNaN(when)) continue;
    const text = title + ' ' + tag(it, 'description').slice(0, 800); // raw is fine for these checks
    out.push({
      title, link: url.href, date: when.toISOString(), source: source.id,
      cves: [...new Set((text.match(/CVE-\d{4}-\d{4,7}/gi) || []).map((c) => c.toUpperCase()))].slice(0, 5),
      exploited: /\b(exploit(ed|ing|ation)?|zero-day|0-day|actively|in the wild)\b/i.test(text),
      harm: /\b(ransomware|breach|hack(ed|ers)?|stolen|leak(ed)?|attack)\b/i.test(text),
    });
  }
  return out;
}

export async function fetchFeed(source) {
  const res = await fetch(source.url, { headers: { 'User-Agent': 'ozone-shield-threat-watch', Accept: 'application/rss+xml, application/xml, text/xml' } });
  if (!res.ok) throw new Error('HTTP ' + res.status);
  const reader = res.body.getReader();
  const dec = new TextDecoder();
  let xml = '';
  try {
    while (xml.length < FEED_BYTES) {
      const { done, value } = await reader.read();
      if (done) break;
      xml += dec.decode(value, { stream: true });
    }
  } catch (e) { if (!xml) throw e; }
  reader.cancel().catch(() => {});
  return parseFeed(xml, source);
}

/* ---------- same story, different outlets ---------- */
const STOP = new Set('about after again against also amid among another back been before being between both could does down during each even every first from have here into just like look made make many more most much must news next only other over says same says should since some still such than that their them then there these they this those through under until very what when where which while will with within without would your year years week weeks report reports new news hackers hacker security cyber attack attacks flaw flaws vulnerability vulnerabilities users user data'.split(' '));
function words(title) {
  return new Set((title.toLowerCase().match(/[a-z0-9][a-z0-9.-]{2,}/g) || []).filter((w) => w.length >= 4 && !STOP.has(w)));
}
function sameStory(a, b) {
  if (a.cves.some((c) => b.cves.includes(c))) return true;
  let shared = 0;
  a.words.forEach((w) => { if (b.words.has(w)) shared++; });
  const union = a.words.size + b.words.size - shared;
  return shared >= 3 || (union > 0 && shared / union >= 0.34);
}

export function rankNews(items, kevCves, now) {
  const t = now || Date.now();
  items.forEach((i) => { i.ts = Date.parse(i.date); });
  const recent = items.filter((i) => t - i.ts <= WINDOW_H * 3600e3 && i.ts <= t + 3600e3);
  const pool = recent.length >= 5 ? recent : items.filter((i) => t - i.ts <= 7 * 24 * 3600e3 && i.ts <= t + 3600e3);
  pool.forEach((i) => { i.words = words(i.title); });
  pool.sort((a, b) => a.ts - b.ts); // oldest first: the first report leads its story
  const stories = [];
  for (const it of pool) {
    const home = stories.find((s) => s.items.some((x) => x.source !== it.source && sameStory(x, it)));
    if (home) { if (!home.items.some((x) => x.source === it.source)) home.items.push(it); }
    else stories.push({ items: [it] });
  }
  const kev = new Set(kevCves || []);
  const scored = stories.map((s) => {
    const srcs = new Set(s.items.map((i) => i.source));
    const official = s.items.some((i) => NEWS_SOURCES.find((x) => x.id === i.source && x.official));
    const cves = [...new Set(s.items.flatMap((i) => i.cves))];
    const inKev = cves.filter((c) => kev.has(c));
    const exploited = s.items.some((i) => i.exploited);
    const harm = s.items.some((i) => i.harm);
    const newest = Math.max(...s.items.map((i) => i.ts));
    const fresh = Math.max(0, 1 - (t - newest) / (WINDOW_H * 3600e3));
    const score = 3 * (srcs.size - 1) + (official ? 3 : 0) + (inKev.length ? 3 : 0) + (exploited ? 2 : 0) + (harm ? 1 : 0) + 2 * fresh;
    const lead = s.items.find((i) => NEWS_SOURCES.find((x) => x.id === i.source && x.official)) || s.items[0];
    return {
      score: Math.round(score * 100) / 100,
      title: lead.title, link: lead.link, source: lead.source, date: lead.date, latest: new Date(newest).toISOString(),
      outlets: s.items.map((i) => ({ source: i.source, link: i.link })),
      official: !!official, exploited, cves: cves.slice(0, 4), inKev,
    };
  });
  scored.sort((a, b) => b.score - a.score || (b.latest < a.latest ? -1 : b.latest > a.latest ? 1 : 0));
  return scored.slice(0, 5);
}

/* ---------- fetch every source, keep going if some fail ---------- */
export async function fetchNews(kevCves) {
  const results = await Promise.allSettled(NEWS_SOURCES.map(fetchFeed));
  const items = [], failed = [];
  results.forEach((r, i) => {
    if (r.status === 'fulfilled') items.push(...r.value);
    else failed.push(NEWS_SOURCES[i].name + ': ' + String(r.reason && r.reason.message || r.reason).slice(0, 60));
  });
  if (!items.length) throw new Error(failed.join('; ') || 'no stories read');
  return {
    top: rankNews(items, kevCves),
    sources: NEWS_SOURCES.map((s) => ({ id: s.id, name: s.name, ok: !failed.some((f) => f.startsWith(s.name + ':')) })),
    failed,
  };
}
