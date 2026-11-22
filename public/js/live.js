/* OZONE Shield: Threat Watch. Loads the snapshot our own server keeps
   (/api/threats, refreshed every 30 minutes from Cloudflare Radar and the
   CISA catalogue), draws the attack arcs on the globe and fills the lists.
   Every value is written with textContent, never as HTML. */
(function () {
  'use strict';
  var $ = function (id) { return document.getElementById(id); };
  var status = $('twStatus');
  var places = window.OzoneCountries || {};
  var fmtDay = new Intl.DateTimeFormat('en-GB', { day: 'numeric', month: 'short', year: 'numeric' });
  var fmtTime = new Intl.DateTimeFormat('en-GB', { hour: '2-digit', minute: '2-digit', timeZone: 'Europe/London', timeZoneName: 'short' });

  function el(tag, cls, txt) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (txt != null) n.textContent = txt;
    return n;
  }
  function when(iso) {
    var d = new Date(iso);
    return isNaN(d) ? '' : fmtTime.format(d) + ', ' + fmtDay.format(d);
  }
  function flag(code) { // two regional-indicator letters show as a flag on most systems
    return /^[A-Z]{2}$/.test(code) ? String.fromCodePoint(0x1F1E6 + code.charCodeAt(0) - 65, 0x1F1E6 + code.charCodeAt(1) - 65) : '';
  }

  function bars(list, rows) {
    list.textContent = '';
    if (!rows || !rows.length) { list.appendChild(el('li', 'tw-empty', 'Not available yet')); return; }
    var top = rows[0].pct || 1;
    rows.slice(0, 6).forEach(function (r) {
      var li = el('li');
      var label = el('span', 'tw-bar-label');
      label.appendChild(el('span', 'tw-flag', flag(r.cc))).setAttribute('aria-hidden', 'true');
      label.appendChild(document.createTextNode(r.name || r.cc));
      li.appendChild(label);
      li.appendChild(el('b', null, r.pct.toLocaleString('en-GB', { maximumFractionDigits: 1 }) + '%'));
      var bar = el('span', 'tw-bar'), fill = el('i');
      fill.style.setProperty('--w', String(Math.max(0.03, r.pct / top)));
      bar.appendChild(fill); li.appendChild(bar);
      list.appendChild(li);
    });
  }

  function attacks(radar) {
    if (!radar || !radar.pairs || !radar.pairs.length) {
      bars($('twOrigins'), null); bars($('twTargets'), null);
      return false;
    }
    bars($('twOrigins'), radar.origins);
    bars($('twTargets'), radar.targets);
    var max = radar.pairs[0].pct || 1;
    var arcs = radar.pairs.map(function (p) {
      var a = places[p.from], b = places[p.to];
      return a && b && p.from !== p.to ? { from: a, to: b, weight: p.pct / max } : null;
    }).filter(Boolean);
    if (window.OzoneGlobe) window.OzoneGlobe.setArcs(arcs);
    return true;
  }

  function kev(k) {
    var list = $('kevList');
    list.textContent = '';
    if (!k || !k.latest || !k.latest.length) { list.appendChild(el('li', 'tw-empty', 'Not available yet')); return false; }
    if (k.count) $('kevTotal').textContent = k.count.toLocaleString('en-GB') + ' flaws are in the catalogue so far.';
    k.latest.forEach(function (v) {
      var li = el('li', 'kev-item' + (v.ransomware ? ' is-ransom' : ''));
      var top = el('p', 'kev-top');
      var a = el('a', 'kev-cve', v.cve);
      a.href = 'https://nvd.nist.gov/vuln/detail/' + encodeURIComponent(v.cve);
      a.target = '_blank'; a.rel = 'noopener';
      top.appendChild(a);
      var d = new Date(v.added + 'T00:00:00Z');
      top.appendChild(el('span', 'kev-date', 'Added ' + (isNaN(d) ? v.added : fmtDay.format(d))));
      li.appendChild(top);
      li.appendChild(el('p', 'kev-what', [v.vendor, v.product].filter(Boolean).join(' · ')));
      li.appendChild(el('p', 'kev-name', v.name));
      if (v.ransomware) li.appendChild(el('span', 'kev-tag', 'Used by ransomware gangs'));
      list.appendChild(li);
    });
    return true;
  }

  var OUTLETS = { ncsc: 'NCSC', bleeping: 'BleepingComputer', record: 'The Record', thn: 'The Hacker News', secweek: 'SecurityWeek', krebs: 'Krebs on Security' };
  function ago(iso) {
    var m = Math.round((Date.now() - Date.parse(iso)) / 60000);
    if (!(m >= 0)) return '';
    if (m < 60) return m <= 1 ? 'just now' : m + ' minutes ago';
    var h = Math.round(m / 60);
    if (h < 24) return h === 1 ? '1 hour ago' : h + ' hours ago';
    var d = Math.round(h / 24);
    return d === 1 ? 'yesterday' : d + ' days ago';
  }
  function safeLink(href) { // only https links to the outlets we read
    try { var u = new URL(href); return u.protocol === 'https:' ? u.href : null; } catch (e) { return null; }
  }
  function news(n, at) {
    var list = $('newsList');
    list.textContent = '';
    if (!n || !n.top || !n.top.length) {
      list.appendChild(el('li', 'tw-empty', 'Stories will appear after the next refresh.'));
      $('newsMeta').textContent = '';
      return false;
    }
    var ok = (n.sources || []).filter(function (s) { return s.ok; }).map(function (s) { return s.name; });
    $('newsMeta').textContent = 'Ranked from ' + ok.length + ' trusted sources' + (at ? ', last checked ' + when(at) : '') + '. Each headline links to the original.';
    n.top.forEach(function (s, i) {
      var li = el('li', 'news-item' + (i === 0 ? ' is-lead' : ''));
      li.appendChild(el('span', 'news-rank', String(i + 1))).setAttribute('aria-hidden', 'true');
      var body = el('div', 'news-body');
      var h = el('h3', 'news-title');
      var href = safeLink(s.link);
      if (href) { var a = el('a', null, s.title); a.href = href; a.target = '_blank'; a.rel = 'noopener'; h.appendChild(a); }
      else h.textContent = s.title;
      body.appendChild(h);
      var meta = el('p', 'news-meta');
      meta.appendChild(el('span', null, (OUTLETS[s.source] || s.source) + ' · ' + ago(s.date)));
      body.appendChild(meta);
      var tags = el('p', 'news-tags');
      if (s.outlets && s.outlets.length > 1) tags.appendChild(el('span', 'tag tag-corr', 'Reported by ' + s.outlets.length + ' outlets'));
      if (s.official) tags.appendChild(el('span', 'tag tag-off', 'Official: NCSC'));
      (s.inKev || []).forEach(function (c) { tags.appendChild(el('span', 'tag tag-kev', c + ' · actively exploited (CISA)')); });
      if (s.exploited && !(s.inKev || []).length) tags.appendChild(el('span', 'tag tag-exp', 'Exploitation reported'));
      (s.cves || []).filter(function (c) { return (s.inKev || []).indexOf(c) === -1; }).slice(0, 2).forEach(function (c) { tags.appendChild(el('span', 'tag', c)); });
      if (tags.childNodes.length) body.appendChild(tags);
      if (s.outlets && s.outlets.length > 1) {
        var also = el('p', 'news-also');
        also.appendChild(document.createTextNode('Read it at: '));
        s.outlets.forEach(function (o, k) {
          var u = safeLink(o.link);
          if (!u) return;
          if (k) also.appendChild(document.createTextNode(' · '));
          var a2 = el('a', null, OUTLETS[o.source] || o.source); a2.href = u; a2.target = '_blank'; a2.rel = 'noopener';
          also.appendChild(a2);
        });
        body.appendChild(also);
      }
      li.appendChild(body);
      list.appendChild(li);
    });
    return true;
  }

  function show(snap) {
    news(snap.news, snap.newsAt);
    var hasA = attacks(snap.radar), hasK = kev(snap.kev);
    var parts = [];
    if (snap.generated) parts.push('Updated ' + when(snap.generated));
    if (!hasA) parts.push('attack data not connected yet');
    if (!hasK) parts.push('vulnerability data unavailable');
    status.textContent = parts.join(' · ');
    status.classList.add('is-ready');
  }

  function load(tries) {
    var ctl = 'AbortController' in window ? new AbortController() : null;
    var timer = setTimeout(function () { if (ctl) ctl.abort(); }, 10000);
    fetch('/api/threats', { headers: { Accept: 'application/json' }, signal: ctl ? ctl.signal : undefined })
      .then(function (res) {
        clearTimeout(timer);
        if (res.status === 503 && tries < 2) {
          status.textContent = 'Fetching the first data. This takes a few seconds…';
          setTimeout(function () { load(tries + 1); }, 15000);
          return null;
        }
        if (!res.ok) throw new Error('HTTP ' + res.status);
        return res.json();
      })
      .then(function (snap) { if (snap) show(snap); })
      .catch(function () {
        clearTimeout(timer);
        status.textContent = "Couldn't load the latest data. Try again in a few minutes.";
        bars($('twOrigins'), null); bars($('twTargets'), null); kev(null); news(null);
      });
  }
  load(0);
})();
