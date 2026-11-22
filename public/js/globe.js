/* OZONE Shield: live globe. A dotted Earth (Natural Earth land, public domain)
   that turns slowly and can be dragged. Daylight is real: the sun's position
   is worked out from the current time, so the lit side matches the world
   right now. London is marked, with its live time. Canvas only, no network
   requests, so it runs under the site's strict Content Security Policy. */
(function () {
  'use strict';

  var canvas = document.getElementById('globe');
  var land = window.OzoneLand;
  if (!canvas || !land || !canvas.getContext) return;
  var ctx = canvas.getContext('2d');
  var reduceMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  var RAD = Math.PI / 180;

  /* Land dots as unit vectors. */
  var pts = [];
  land.rows.forEach(function (row) {
    var lat = row[0] * RAD, n = row[1], hex = row[2];
    for (var k = 0; k < n; k++) {
      var nib = parseInt(hex[k >> 2], 16);
      if (!(nib & (8 >> (k & 3)))) continue;
      var lon = (-180 + (k + 0.5) * 360 / n) * RAD;
      pts.push([Math.cos(lat) * Math.cos(lon), Math.cos(lat) * Math.sin(lon), Math.sin(lat)]);
    }
  });

  /* Where the sun is overhead right now (accurate to well under a degree). */
  function subsolar(date) {
    var d = date.getTime() / 86400000 + 2440587.5 - 2451545.0;
    var g = (357.529 + 0.98560028 * d) * RAD;
    var q = 280.459 + 0.98564736 * d;
    var L = (q + 1.915 * Math.sin(g) + 0.020 * Math.sin(2 * g)) * RAD;
    var e = (23.439 - 0.00000036 * d) * RAD;
    var ra = Math.atan2(Math.cos(e) * Math.sin(L), Math.cos(L));
    var dec = Math.asin(Math.sin(e) * Math.sin(L));
    var gmst = (280.46061837 + 360.98564736629 * d) * RAD;
    var lon = Math.atan2(Math.sin(ra - gmst), Math.cos(ra - gmst));
    return [Math.cos(dec) * Math.cos(lon), Math.cos(dec) * Math.sin(lon), Math.sin(dec)];
  }

  var LONDON = { lat: 51.5074 * RAD, lon: -0.1278 * RAD };
  var LV = [Math.cos(LONDON.lat) * Math.cos(LONDON.lon), Math.cos(LONDON.lat) * Math.sin(LONDON.lon), Math.sin(LONDON.lat)];
  var sun = subsolar(new Date());

  /* Optional attack arcs (Threat Watch): great circles lifted off the surface,
     with a light travelling from origin to target. Set by live.js. */
  var arcs = [];
  function unit(lat, lon) { lat *= RAD; lon *= RAD; return [Math.cos(lat) * Math.cos(lon), Math.cos(lat) * Math.sin(lon), Math.sin(lat)]; }
  function arcPath(a, b) {
    var dot = Math.max(-1, Math.min(1, a[0] * b[0] + a[1] * b[1] + a[2] * b[2]));
    var ang = Math.acos(dot), s = Math.sin(ang) || 1e-6, out = [], N = 56;
    for (var k = 0; k <= N; k++) {
      var t = k / N, wa = Math.sin((1 - t) * ang) / s, wb = Math.sin(t * ang) / s;
      var lift = 1 + Math.sin(Math.PI * t) * (0.06 + ang * 0.12);
      out.push([(a[0] * wa + b[0] * wb) * lift, (a[1] * wa + b[1] * wb) * lift, (a[2] * wa + b[2] * wb) * lift]);
    }
    return out;
  }
  window.OzoneGlobe = {
    setArcs: function (list) {
      arcs = (list || []).map(function (x, i) {
        var a = unit(x.from[0], x.from[1]), b = unit(x.to[0], x.to[1]);
        return { path: arcPath(a, b), a: a, b: b, w: Math.max(0.25, Math.min(1, x.weight || 0.5)), phase: i * 0.137 };
      });
      draw(performance.now());
    },
    focus: function (lat, lon) { lat0 = lat * RAD; lon0 = lon * RAD; draw(performance.now()); }
  };

  /* View: centre longitude turns; the tilt keeps the UK in view. */
  var lon0 = -20 * RAD, lat0 = 28 * RAD, dragging = false, lastX = 0, lastY = 0, idleAt = 0;
  var css = getComputedStyle(document.documentElement);
  var C = {
    day: css.getPropertyValue('--ink').trim() || '#f6f3ef',
    night: '#7f93ad',
    accent: '#7cc4ff', sun: '#f7b84b', attack: '#ff7a6e', line: css.getPropertyValue('--line').trim() || '#3e3b38'
  };

  var W = 0, H = 0, R = 0, dpr = 1;
  function size() {
    var r = canvas.getBoundingClientRect();
    dpr = Math.min(2, window.devicePixelRatio || 1);
    W = Math.round(r.width); H = Math.round(r.height);
    canvas.width = W * dpr; canvas.height = H * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    R = Math.min(W, H) / 2 - 8;
  }

  function project(v) {
    // Rotate the world so (lat0, lon0) faces the viewer, then drop depth.
    var cl = Math.cos(-lon0), sl = Math.sin(-lon0);
    var x = v[0] * cl - v[1] * sl, y = v[0] * sl + v[1] * cl, z = v[2];
    var cp = Math.cos(lat0), sp = Math.sin(lat0);
    var depth = x * cp + z * sp;          // towards the viewer
    var up = -x * sp + z * cp;
    return [W / 2 + y * R, H / 2 - up * R, depth];
  }

  function draw(now) {
    ctx.clearRect(0, 0, W, H);
    // Atmosphere and disc
    var g = ctx.createRadialGradient(W / 2, H / 2, R * 0.85, W / 2, H / 2, R * 1.12);
    g.addColorStop(0, 'rgba(124,196,255,0.10)'); g.addColorStop(1, 'rgba(124,196,255,0)');
    ctx.fillStyle = g; ctx.beginPath(); ctx.arc(W / 2, H / 2, R * 1.12, 0, Math.PI * 2); ctx.fill();
    ctx.strokeStyle = C.line; ctx.lineWidth = 1; ctx.beginPath(); ctx.arc(W / 2, H / 2, R, 0, Math.PI * 2); ctx.stroke();

    var dot = Math.max(1.1, R / 170);
    for (var i = 0; i < pts.length; i++) {
      var p = project(pts[i]);
      if (p[2] <= 0) continue;
      var lit = pts[i][0] * sun[0] + pts[i][1] * sun[1] + pts[i][2] * sun[2];
      var limb = 0.35 + 0.65 * p[2];
      if (lit > 0.05) { ctx.globalAlpha = limb; ctx.fillStyle = C.day; }
      else if (lit > -0.08) { ctx.globalAlpha = limb * 0.75; ctx.fillStyle = C.sun; }   // dawn and dusk
      else { ctx.globalAlpha = limb * 0.7; ctx.fillStyle = C.night; }
      ctx.fillRect(p[0] - dot / 2, p[1] - dot / 2, dot, dot);
    }
    ctx.globalAlpha = 1;

    // Attack arcs: the line, then a light running from origin to target
    for (var j = 0; j < arcs.length; j++) {
      var A = arcs[j], P = A.path, prev = null;
      ctx.lineWidth = 0.8 + A.w * 1.6;
      for (var m = 0; m < P.length; m++) {
        var q = project(P[m]);
        var dx = q[0] - W / 2, dy = q[1] - H / 2;
        var seen = q[2] > 0 || dx * dx + dy * dy > R * R;   // in front, or lifted past the edge
        if (prev && seen && prev.seen) {
          ctx.strokeStyle = C.attack; ctx.globalAlpha = 0.18 + A.w * 0.35;
          ctx.beginPath(); ctx.moveTo(prev.x, prev.y); ctx.lineTo(q[0], q[1]); ctx.stroke();
        }
        prev = { x: q[0], y: q[1], seen: seen };
      }
      var tt = reduceMotion ? 0.7 : ((now / 2600 + A.phase) % 1);
      var hi = Math.round(tt * (P.length - 1));
      for (var tail = 0; tail < 9; tail++) {
        var idx = hi - tail; if (idx < 0) break;
        var h = project(P[idx]), hx = h[0] - W / 2, hy = h[1] - H / 2;
        if (!(h[2] > 0 || hx * hx + hy * hy > R * R)) continue;
        ctx.globalAlpha = (1 - tail / 9) * 0.95; ctx.fillStyle = C.attack;
        ctx.beginPath(); ctx.arc(h[0], h[1], (2.6 - tail * 0.22) * (0.7 + A.w * 0.5), 0, Math.PI * 2); ctx.fill();
      }
      var o = project(A.a);
      if (o[2] > 0) { ctx.globalAlpha = 0.9; ctx.fillStyle = C.attack; ctx.beginPath(); ctx.arc(o[0], o[1], 2.5 + A.w * 2, 0, Math.PI * 2); ctx.fill(); }
      var tg = project(A.b);
      if (tg[2] > 0) { ctx.globalAlpha = 0.9; ctx.strokeStyle = C.attack; ctx.lineWidth = 1.5; ctx.beginPath(); ctx.arc(tg[0], tg[1], 4 + A.w * 2.5, 0, Math.PI * 2); ctx.stroke(); }
    }
    ctx.globalAlpha = 1;

    // London, with a slow pulse
    var lp = project(LV);
    if (lp[2] > 0) {
      var t = reduceMotion ? 0.4 : ((now / 1600) % 1);
      ctx.strokeStyle = C.accent; ctx.globalAlpha = 1 - t; ctx.lineWidth = 2;
      ctx.beginPath(); ctx.arc(lp[0], lp[1], 6 + t * 18, 0, Math.PI * 2); ctx.stroke();
      ctx.globalAlpha = 1; ctx.fillStyle = C.accent;
      ctx.beginPath(); ctx.arc(lp[0], lp[1], 4.5, 0, Math.PI * 2); ctx.fill();
    }
  }

  /* Live readouts */
  var timeEl = document.getElementById('londonTime'), sunEl = document.getElementById('londonSun'), youEl = document.getElementById('yourTime');
  var fmtLondon = new Intl.DateTimeFormat('en-GB', { timeZone: 'Europe/London', hour: '2-digit', minute: '2-digit' });
  var fmtYou = new Intl.DateTimeFormat('en-GB', { hour: '2-digit', minute: '2-digit' });
  function readouts() {
    var now = new Date();
    sun = subsolar(now);
    var lit = LV[0] * sun[0] + LV[1] * sun[1] + LV[2] * sun[2];
    if (timeEl) timeEl.textContent = fmtLondon.format(now);
    if (sunEl) sunEl.textContent = lit > 0.05 ? 'Daylight' : lit > -0.08 ? 'Twilight' : 'Night-time';
    if (youEl) youEl.textContent = fmtYou.format(now);
  }
  readouts();
  setInterval(readouts, 30000);

  /* Turn slowly; drag to explore; pause when off screen. */
  var running = false, visible = false, last = 0;
  function loop(now) {
    if (!running) return;
    var dt = last ? Math.min(64, now - last) : 16; last = now;
    if (!dragging && now > idleAt) lon0 -= dt * 0.00007;   // west to east, like the real Earth
    draw(now);
    requestAnimationFrame(loop);
  }
  function update() {
    var should = visible && !reduceMotion && document.visibilityState === 'visible';
    if (should && !running) { running = true; last = 0; requestAnimationFrame(loop); }
    if (!should) running = false;
  }
  canvas.addEventListener('pointerdown', function (e) { dragging = true; lastX = e.clientX; lastY = e.clientY; canvas.setPointerCapture(e.pointerId); });
  canvas.addEventListener('pointermove', function (e) {
    if (!dragging) return;
    lon0 -= (e.clientX - lastX) / R; lat0 = Math.max(-1.2, Math.min(1.2, lat0 + (e.clientY - lastY) / R));
    lastX = e.clientX; lastY = e.clientY;
    if (!running) draw(performance.now());
  });
  function release() { dragging = false; idleAt = performance.now() + 1800; }
  canvas.addEventListener('pointerup', release);
  canvas.addEventListener('pointercancel', release);
  canvas.addEventListener('keydown', function (e) {
    var step = 0.12;
    if (e.key === 'ArrowLeft') lon0 += step; else if (e.key === 'ArrowRight') lon0 -= step;
    else if (e.key === 'ArrowUp') lat0 = Math.min(1.2, lat0 + step); else if (e.key === 'ArrowDown') lat0 = Math.max(-1.2, lat0 - step);
    else return;
    e.preventDefault(); idleAt = performance.now() + 3000;
    if (!running) draw(performance.now());
  });

  size(); draw(performance.now());
  window.addEventListener('resize', function () { size(); draw(performance.now()); });
  if ('IntersectionObserver' in window) new IntersectionObserver(function (es) { visible = es[0].isIntersecting; update(); }).observe(canvas);
  else { visible = true; update(); }
  document.addEventListener('visibilitychange', update);
})();
