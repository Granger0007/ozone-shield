/* OZONE Shield: the scanner instrument. A ring in verdict colours, fine ticks
   and a living waveform. It stays pinned while the story scrolls, changes with
   each chapter, and reacts to the message checker: listening while you type,
   scanning while it checks, then showing the verdict. Only transforms and
   classes change per frame; it pauses when off screen, and draws a still
   frame for people who prefer reduced motion. No innerHTML, so it runs under
   the site's strict Content Security Policy. */
(function () {
  'use strict';

  var inst = document.getElementById('inst');
  if (!inst) return;
  var svg = inst.querySelector('svg');
  var readout = document.getElementById('instReadout');
  var NS = 'http://www.w3.org/2000/svg';
  var reduceMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  function el(tag, attrs, parent) {
    var n = document.createElementNS(NS, tag);
    for (var k in attrs) n.setAttribute(k, attrs[k]);
    (parent || svg).appendChild(n);
    return n;
  }
  function arc(r, a0, a1) {
    var p0 = [Math.cos(a0) * r, Math.sin(a0) * r], p1 = [Math.cos(a1) * r, Math.sin(a1) * r];
    return 'M' + p0[0].toFixed(1) + ' ' + p0[1].toFixed(1) + ' A' + r + ' ' + r + ' 0 ' + (a1 - a0 > Math.PI ? 1 : 0) + ' 1 ' + p1[0].toFixed(1) + ' ' + p1[1].toFixed(1);
  }

  /* ---------- build ---------- */
  var SEGS = 8, GAP = 0.05;
  var glow = el('g', { 'class': 'inst-glow' });
  var ring = el('g', { 'class': 'inst-ring' });
  for (var i = 0; i < SEGS; i++) {
    var a0 = (i / SEGS) * Math.PI * 2 - Math.PI / 2 + GAP / 2, a1 = a0 + (Math.PI * 2) / SEGS - GAP;
    el('path', { d: arc(272, a0, a1), 'class': 'seg s' + i }, glow);
    el('path', { d: arc(272, a0, a1), 'class': 'seg s' + i }, ring);
  }
  var ticks = el('g', { 'class': 'inst-ticks' });
  for (var t = 0; t < 144; t++) {
    var a = (t / 144) * Math.PI * 2, long = t % 4 === 0, r0 = long ? 236 : 241;
    el('line', { x1: (Math.cos(a) * r0).toFixed(1), y1: (Math.sin(a) * r0).toFixed(1), x2: (Math.cos(a) * 250).toFixed(1), y2: (Math.sin(a) * 250).toFixed(1), 'class': long ? 'tick long' : 'tick' }, ticks);
  }
  el('circle', { cx: 0, cy: 0, r: 224, 'class': 'inst-inner' });
  var spinA = el('g', { 'class': 'spin spin-a' }); el('path', { d: arc(212, -2.6, -1.2), 'class': 'sweep' }, spinA);
  var spinB = el('g', { 'class': 'spin spin-b' }); el('path', { d: arc(200, 0.5, 1.7), 'class': 'sweep thin' }, spinB);

  var LINES = 41, wave = el('g', { 'class': 'inst-wave' }), bars = [];
  for (var l = 0; l < LINES; l++) {
    var y = (l - (LINES - 1) / 2) * 7.2;
    bars.push(el('line', { x1: -170, y1: y.toFixed(1), x2: 170, y2: y.toFixed(1), 'class': 'bar' }, wave));
  }
  /* The opening lock: closed on arrival, then it opens to welcome you. */
  var lock = el('g', { 'class': 'inst-lock' });
  var shackle = el('g', { 'class': 'lock-shackle' }, lock);
  el('path', { d: 'M-38 -6 V-48 A38 38 0 0 1 38 -48 V-6', 'class': 'lock-arc' }, shackle);
  el('rect', { x: -66, y: -10, width: 132, height: 112, rx: 18, 'class': 'lock-body' }, lock);
  el('circle', { cx: 0, cy: 34, r: 11, 'class': 'lock-hole' }, lock);
  el('rect', { x: -4.5, y: 38, width: 9, height: 30, rx: 4.5, 'class': 'lock-hole' }, lock);

  var DOTS = 26, trail = el('g', { 'class': 'inst-dots' }), dots = [];
  for (var d = 0; d < DOTS; d++) dots.push(el('circle', { cx: 0, cy: 0, r: 5.2, 'class': 'dot' }, trail));

  /* ---------- modes ---------- */
  var LABELS = {
    lock: 'Locked', welcome: 'Welcome', idle: 'Standing by', listen: 'Listening', scan: 'Scanning…', rush: 'Pressure detected',
    mask: 'Impersonation detected', money: 'Payment request detected', safe: 'Check first',
    'v-safe': 'Verdict: no scam signs found', 'v-caution': 'Verdict: be careful', 'v-scam': 'Verdict: scam'
  };
  var mode = 'lock', chapterMode = 'lock', chars = 0, override = null, unlocked = false;

  function setMode(m) {
    if (m === mode) return;
    mode = m;
    inst.setAttribute('data-mode', m);
    var label = LABELS[m] || '';
    if (m === 'listen') label = chars ? 'Listening · ' + chars.toLocaleString('en-GB') + ' characters' : 'Listening';
    readout.textContent = label;
    if (reduceMotion) draw(performance.now());
  }
  function refresh() {
    var m = override || chapterMode;
    if (m === 'lock' && unlocked) m = 'welcome';
    setMode(m);
  }

  /* Waveform shape per mode: half-width of each bar (0..1) at time t. */
  function width(i, t) {
    var u = i / (LINES - 1) * 2 - 1;               // -1 (top) .. 1 (bottom)
    var env = Math.max(0, 1 - u * u);              // lens shape
    switch (mode) {
      case 'listen': {
        var amp = 0.25 + Math.min(1, chars / 400) * 0.7;
        return env * amp * (0.75 + 0.25 * Math.sin(t * 3 + i * 0.6));
      }
      case 'scan': {
        var pos = Math.sin(t * 2.4) * 1.1;             // a band sweeps up and down
        return 0.15 + 0.85 * Math.exp(-Math.pow((u - pos) * 3.2, 2));
      }
      case 'rush': return env * (0.45 + 0.55 * Math.abs(Math.sin(t * 7 + i * 1.3)));
      case 'mask': {                                   // two lobes, like two faces
        var lobe = Math.exp(-Math.pow((u + 0.45) * 3, 2)) + Math.exp(-Math.pow((u - 0.45) * 3, 2));
        return Math.min(1, lobe * (0.8 + 0.2 * Math.sin(t * 1.6)));
      }
      case 'money': return Math.max(0.05, 1 - Math.abs(u) * 1.15) * (0.85 + 0.15 * Math.sin(t * 4));
      case 'v-scam': return Math.max(0.05, 1 - Math.abs(u) * 1.1);
      case 'v-caution': return env * 0.6;
      case 'v-safe': case 'safe': return 0.08 + env * 0.12 * (1 + Math.sin(t * 1.2));
      default: {                                       // idle: slow breathing diamond
        var wv = Math.sin(t * 1.1 + u * 3) * 0.12;
        return Math.max(0.04, (1 - Math.abs(u)) * 0.85 + wv);
      }
    }
  }
  function dotPos(k, t) {
    var f = k / (DOTS - 1), x = -200 + f * 400, y;
    switch (mode) {
      case 'scan': y = Math.sin(f * 9 - t * 6) * 70; break;
      case 'rush': y = Math.sin(f * 14 - t * 9) * 40 + Math.sin(t * 13 + k) * 6; break;
      case 'mask': y = Math.sin(f * Math.PI * 2 + t) * 90; break;
      case 'money': y = 120 - f * f * 240; break;
      case 'v-scam': case 'v-caution': y = 120 - f * f * 240; break;
      case 'v-safe': case 'safe': y = 110; break;
      case 'listen': y = 100 + Math.sin(f * 6 + t * 2) * 12 * (0.3 + Math.min(1, chars / 400)); break;
      default: y = 110 - Math.pow(Math.sin(f * Math.PI), 2) * 60 * (0.6 + 0.4 * Math.sin(t * 0.9));
    }
    return [x, y];
  }

  function draw(now) {
    var t = now / 1000;
    for (var i = 0; i < LINES; i++) bars[i].setAttribute('transform', 'scale(' + width(i, t).toFixed(3) + ' 1)');
    for (var k = 0; k < DOTS; k++) { var p = dotPos(k, t); dots[k].setAttribute('transform', 'translate(' + p[0].toFixed(1) + ' ' + p[1].toFixed(1) + ')'); }
  }

  /* ---------- run only while visible ---------- */
  var running = false, visible = false;
  function loop(now) { if (!running) return; draw(now); requestAnimationFrame(loop); }
  function update() {
    var should = visible && !reduceMotion && document.visibilityState === 'visible';
    if (should && !running) { running = true; requestAnimationFrame(loop); }
    if (!should) running = false;
  }
  if ('IntersectionObserver' in window) {
    new IntersectionObserver(function (es) { visible = es[0].isIntersecting; update(); }).observe(inst);
  } else { visible = true; }
  document.addEventListener('visibilitychange', update);
  draw(performance.now());
  update();

  /* Unlock once, shortly after arrival: the shackle lifts, the ring lights
     up segment by segment, and the readout says welcome. */
  function unlock() {
    if (unlocked) return;
    unlocked = true;
    inst.classList.add('is-open');
    refresh();
  }
  inst.classList.add('is-booting');
  if (reduceMotion) { inst.classList.remove('is-booting'); unlock(); }
  else {
    setTimeout(function () { inst.classList.remove('is-booting'); }, 150);
    setTimeout(unlock, 1300);
  }

  /* ---------- chapters drive the mode ---------- */
  var chapters = Array.prototype.slice.call(document.querySelectorAll('.chapter[data-mode]'));
  if ('IntersectionObserver' in window && chapters.length) {
    var cio = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) {
        if (!en.isIntersecting) return;
        chapters.forEach(function (c) { c.classList.toggle('is-active', c === en.target); });
        chapterMode = en.target.getAttribute('data-mode');
        if (en.target.id !== 'checker') override = null;   // leaving the checker resets its verdict
        refresh();
      });
    }, { rootMargin: '-45% 0px -45% 0px' });
    chapters.forEach(function (c) { cio.observe(c); });
  }

  /* ---------- the checker drives it too ---------- */
  var input = document.getElementById('messageInput');
  var card = document.getElementById('checkerCard');
  var result = document.getElementById('resultCard');
  if (input) input.addEventListener('input', function () {
    chars = input.value.length;
    if (mode === 'listen') { mode = ''; refresh(); }
  });
  function fromChecker() {
    if (card && card.getAttribute('data-state') === 'checking') override = 'scan';
    else if (result && !result.hidden) {
      override = result.classList.contains('v-scam') ? 'v-scam' : result.classList.contains('v-safe') ? 'v-safe' : 'v-caution';
    } else override = null;
    refresh();
  }
  if ('MutationObserver' in window && card && result) {
    var mo = new MutationObserver(fromChecker);
    mo.observe(card, { attributes: true, attributeFilter: ['data-state'] });
    mo.observe(result, { attributes: true, attributeFilter: ['hidden', 'class'] });
  }
})();
