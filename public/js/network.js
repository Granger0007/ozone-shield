/* OZONE Shield: How the internet works. Each scene keeps its diagram in
   place while its steps scroll past; this script sets data-step (0-3) on
   the scene from the step crossing the middle of the screen, and CSS moves
   the diagram. It also types the simulated packet capture and counts the
   route figures. Every address and time is an example: nothing is measured
   and nothing about the visitor is collected. */
(function () {
  'use strict';
  var reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  var scenes = Array.prototype.slice.call(document.querySelectorAll('.nj'));
  if (!scenes.length) return;

  /* ---------- simulated tcpdump (RFC 1918 and RFC 5737 example addresses) ---------- */
  var TERM = [
    [], // step 0: the capture is waiting
    [['k', '12:00:00.000 IP 192.168.1.23.52344 > 198.51.100.24.443: Flags [S], seq 0, win 64240, length 0'],
     ['r', '12:00:00.012 IP 198.51.100.24.443 > 192.168.1.23.52344: Flags [S.], seq 0, ack 1, win 65535, length 0'],
     ['k', '12:00:00.012 IP 192.168.1.23.52344 > 198.51.100.24.443: Flags [.], ack 1, win 502, length 0']],
    [['k', '12:00:00.013 IP 192.168.1.23.52344 > 198.51.100.24.443: Flags [P.], seq 1:518, ack 1, length 517']],
    [['r', '12:00:00.025 IP 198.51.100.24.443 > 192.168.1.23.52344: Flags [.], ack 518, length 0']]
  ];
  var PROMPT = '$ sudo tcpdump -n -i en0 port 443\nlistening on en0, link-type EN10MB (Ethernet)\n';
  var term = document.getElementById('term');
  var shownStep = -1, typing = null;

  function linesUpTo(step) {
    var out = [];
    for (var s = 0; s <= step; s++) out = out.concat(TERM[s]);
    return out;
  }
  function paint(lines, partial) {
    term.textContent = '';
    var p = document.createElement('span'); p.className = 'p'; p.textContent = PROMPT; term.appendChild(p);
    lines.forEach(function (l, i) {
      var sp = document.createElement('span'); sp.className = l[0];
      var last = i === lines.length - 1 && partial != null;
      sp.textContent = (last ? l[1].slice(0, partial) + '█' : l[1]) + '\n';
      term.appendChild(sp);
    });
  }
  function termTo(step) {
    if (!term || step === shownStep) return;
    var forward = step === shownStep + 1;
    var before = linesUpTo(shownStep < 0 ? 0 : shownStep);
    shownStep = step;
    if (typing) { cancelAnimationFrame(typing); typing = null; }
    var all = linesUpTo(step);
    if (reduce || !forward || all.length === before.length) { paint(all); return; }
    // Type the new lines at about 160 characters a second.
    var idx = before.length, chars = 0, last = 0;
    function frame(ts) {
      if (!last) last = ts;
      chars += (ts - last) * 0.16; last = ts;
      var line = all[idx][1];
      if (chars >= line.length) { idx++; chars = 0; }
      if (idx >= all.length) { paint(all); typing = null; return; }
      paint(all.slice(0, idx + 1), Math.floor(chars));
      typing = requestAnimationFrame(frame);
    }
    typing = requestAnimationFrame(frame);
  }

  /* ---------- route figures (5 routers before the server, so TTL arrives as 59) ---------- */
  var ROUTE = [{ hops: 1, ms: 1, ttl: 63 }, { hops: 2, ms: 2, ttl: 62 }, { hops: 3, ms: 8, ttl: 61 }, { hops: 6, ms: 24, ttl: 59 }];
  var rH = document.getElementById('rHops'), rM = document.getElementById('rMs'), rT = document.getElementById('rTtl');
  var cur = { hops: 1, ms: 1, ttl: 63 }, anim = null;
  function routeTo(step) {
    var to = ROUTE[step], from = { hops: cur.hops, ms: cur.ms, ttl: cur.ttl }, t0 = 0;
    function out(v) { rH.textContent = String(Math.round(v.hops)); rM.textContent = Math.round(v.ms) + ' ms'; rT.textContent = String(Math.round(v.ttl)); }
    if (anim) cancelAnimationFrame(anim);
    if (reduce) { cur = to; out(to); return; }
    function frame(ts) {
      if (!t0) t0 = ts;
      var k = Math.min(1, (ts - t0) / 700), e = 1 - Math.pow(1 - k, 3);
      cur = { hops: from.hops + (to.hops - from.hops) * e, ms: from.ms + (to.ms - from.ms) * e, ttl: from.ttl + (to.ttl - from.ttl) * e };
      out(cur);
      anim = k < 1 ? requestAnimationFrame(frame) : null;
    }
    anim = requestAnimationFrame(frame);
  }

  /* ---------- which step is in the middle of the screen ---------- */
  scenes.forEach(function (s) { s.classList.add('is-live'); s._steps = Array.prototype.slice.call(s.querySelectorAll('.nj-step')); s._step = -1; });
  function setStep(s, i) {
    if (i === s._step) return;
    s._step = i;
    s.setAttribute('data-step', String(i));
    s._steps.forEach(function (li, n) { li.classList.toggle('is-active', n === i); });
    if (s.classList.contains('nj-layers')) termTo(i);
    if (s.classList.contains('nj-route') && rH) routeTo(i);
  }
  var ticking = false;
  function measure() {
    ticking = false;
    // On phones the diagram fills the top half, so a step counts once it is in the lower part.
    var line = window.innerHeight * (window.innerWidth < 960 ? 0.78 : 0.55);
    scenes.forEach(function (s) {
      var pick = 0;
      for (var n = 0; n < s._steps.length; n++) if (s._steps[n].getBoundingClientRect().top <= line) pick = n;
      setStep(s, pick);
    });
  }
  window.addEventListener('scroll', function () { if (!ticking) { ticking = true; requestAnimationFrame(measure); } }, { passive: true });
  window.addEventListener('resize', measure, { passive: true });
  paint([]);
  measure();
})();
