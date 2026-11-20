/* OZONE Shield: Scam map. Twelve scams from the Spot the Scam game sit on a
   ring; lines join scams that use the same trick. Picking a trick lights up
   every scam that uses it. Built with DOM APIs only (no innerHTML), so it runs
   under the site's strict Content Security Policy. */
(function () {
  'use strict';

  var root = document.getElementById('scamMap');
  if (!root) return;

  var SCAMS = [
    { id: 'parcel', name: 'Parcel fee' },
    { id: 'tax', name: 'Tax refund' },
    { id: 'bank', name: 'Safe account' },
    { id: 'family', name: 'Hi Mum' },
    { id: 'invest', name: 'Investment' },
    { id: 'job', name: 'Job offer' },
    { id: 'account', name: 'Account locked' },
    { id: 'vehicle', name: 'Vehicle tax' },
    { id: 'energy', name: 'Energy rebate' },
    { id: 'prize', name: 'Prize draw' },
    { id: 'courier', name: 'Courier' },
    { id: 'romance', name: 'Romance' }
  ];

  // Examples are lines from the made-up training messages in the game.
  var TRICKS = [
    { id: 'impersonate', name: 'Pretends to be someone you trust',
      scams: ['parcel', 'tax', 'bank', 'family', 'account', 'vehicle', 'energy', 'courier'],
      spot: 'Contact the organisation yourself, using a number or website you already know. Never use the details in the message.',
      examples: ['“HMRC: You are due a tax refund…”', '“This is your bank’s fraud team.”'] },
    { id: 'rush', name: 'Rushes or scares you',
      scams: ['parcel', 'tax', 'bank', 'invest', 'account', 'vehicle', 'prize', 'courier', 'romance'],
      spot: 'Real organisations give you time. A deadline or a threat is a reason to slow down.',
      examples: ['“Pay within 24 hours”', '“Only 5 places left today.”'] },
    { id: 'link', name: 'Sends you to a link',
      scams: ['parcel', 'tax', 'account', 'vehicle', 'energy'],
      spot: 'Type the website yourself or use the official app. HMRC and the DVLA are on gov.uk.',
      examples: ['“amaz0n-secure-login.com”', '“dvla-vehicle-renew.co”'] },
    { id: 'fee', name: 'Small fee to unlock something',
      scams: ['parcel', 'prize', 'job'],
      spot: 'A small fee to release a parcel, a prize or a job is a way to get your card details.',
      examples: ['“an unpaid fee of £1.99”', '“pay a £50 registration fee.”'] },
    { id: 'bait', name: 'Too good to be true',
      scams: ['tax', 'invest', 'job', 'energy', 'prize'],
      spot: 'Free money, guaranteed returns and easy pay are bait. You can’t win a draw you never entered.',
      examples: ['“Guaranteed 30% returns every week.”', '“Earn £300 a day just liking videos.”'] },
    { id: 'money', name: 'Asks for money another way',
      scams: ['bank', 'family', 'invest', 'courier', 'romance'],
      spot: 'Banks never ask you to move money to a “safe account”. Gift cards, new numbers and couriers collecting cards are classic scam signs.',
      examples: ['“Move your money to a safe account”', '“Could you send £600 in gift cards?”'] },
    { id: 'secret', name: 'Stops you checking',
      scams: ['bank', 'family'],
      spot: 'Asking for secrecy, or making excuses not to talk, is there to stop you checking. Check another way.',
      examples: ['“Don’t tell branch staff”', '“Can’t call, the mic is broken”'] }
  ];

  var NS = 'http://www.w3.org/2000/svg';
  var R = 165, LABEL_R = 182;
  var reduceMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  function el(tag, attrs, text) {
    var n = document.createElementNS(NS, tag);
    for (var k in attrs) n.setAttribute(k, attrs[k]);
    if (text) n.textContent = text;
    return n;
  }
  function pos(i, r) {
    var a = (i / SCAMS.length) * Math.PI * 2 - Math.PI / 2;
    return { x: Math.cos(a) * r, y: Math.sin(a) * r, a: a };
  }

  // Pairs of scams and the tricks they share.
  var index = {};
  SCAMS.forEach(function (s, i) { index[s.id] = i; });
  var pairs = {};
  TRICKS.forEach(function (t) {
    for (var i = 0; i < t.scams.length; i++) {
      for (var j = i + 1; j < t.scams.length; j++) {
        var a = index[t.scams[i]], b = index[t.scams[j]];
        var key = Math.min(a, b) + '-' + Math.max(a, b);
        (pairs[key] = pairs[key] || []).push(t.id);
      }
    }
  });

  /* ---------- draw ---------- */
  var svg = root.querySelector('svg');
  var chordLayer = el('g', { 'class': 'sm-chords' });
  var nodeLayer = el('g', { 'class': 'sm-nodes' });
  svg.appendChild(el('circle', { 'class': 'sm-ring', cx: 0, cy: 0, r: R }));
  svg.appendChild(chordLayer);
  svg.appendChild(nodeLayer);

  var chordEls = [];
  Object.keys(pairs).forEach(function (key) {
    var ab = key.split('-').map(Number), p = pos(ab[0], R), q = pos(ab[1], R);
    var path = el('path', { d: 'M' + p.x.toFixed(1) + ' ' + p.y.toFixed(1) + ' Q0 0 ' + q.x.toFixed(1) + ' ' + q.y.toFixed(1), 'class': 'sm-chord' });
    path.style.setProperty('--w', String(0.8 + pairs[key].length * 0.7));
    chordLayer.appendChild(path);
    chordEls.push({ el: path, tricks: pairs[key] });
  });

  var nodeEls = SCAMS.map(function (s, i) {
    var p = pos(i, R), l = pos(i, LABEL_R);
    var g = el('g', { 'class': 'sm-node' });
    g.appendChild(el('circle', { cx: p.x.toFixed(1), cy: p.y.toFixed(1), r: 7 }));
    var anchor = Math.abs(l.x) < 4 ? 'middle' : (l.x > 0 ? 'start' : 'end');
    var dy = l.y > 4 ? 12 : (l.y < -4 ? -4 : 4);
    g.appendChild(el('text', { x: l.x.toFixed(1), y: (l.y + dy).toFixed(1), 'text-anchor': anchor }, s.name));
    nodeLayer.appendChild(g);
    return g;
  });

  /* ---------- trick picker ---------- */
  var picker = root.querySelector('.sm-tricks');
  var detail = root.querySelector('.sm-detail');
  var buttons = TRICKS.map(function (t) {
    var b = document.createElement('button');
    b.type = 'button';
    b.className = 'sm-trick';
    b.textContent = t.name;
    b.setAttribute('aria-pressed', 'false');
    b.addEventListener('click', function () { select(t.id); });
    var li = document.createElement('li');
    li.appendChild(b);
    picker.appendChild(li);
    return b;
  });

  function select(id) {
    var t = TRICKS.filter(function (x) { return x.id === id; })[0];
    buttons.forEach(function (b, i) { b.setAttribute('aria-pressed', String(TRICKS[i].id === id)); });
    chordEls.forEach(function (c) { c.el.classList.toggle('on', c.tricks.indexOf(id) !== -1); });
    nodeEls.forEach(function (n, i) { n.classList.toggle('on', t.scams.indexOf(SCAMS[i].id) !== -1); });
    root.classList.add('has-pick');

    detail.textContent = '';
    var h = document.createElement('h3'); h.textContent = t.name;
    var count = document.createElement('p'); count.className = 'sm-count';
    count.textContent = 'Used by ' + t.scams.length + ' of the ' + SCAMS.length + ' scams in the game';
    var spot = document.createElement('p'); spot.className = 'sm-spot'; spot.textContent = t.spot;
    var ex = document.createElement('ul'); ex.className = 'sm-examples'; ex.setAttribute('aria-label', 'Examples');
    t.examples.forEach(function (e) { var li = document.createElement('li'); li.textContent = e; ex.appendChild(li); });
    detail.appendChild(h); detail.appendChild(count); detail.appendChild(spot); detail.appendChild(ex);
    if (!reduceMotion) { detail.classList.remove('swap'); void detail.offsetWidth; detail.classList.add('swap'); }
  }

  root.classList.add('sm-ready');
  select('impersonate');
})();
