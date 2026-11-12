/* OZONE Shield: page logic. Loaded as a file (no inline script) so the site
   can run under a strict Content Security Policy. */
(function () {
  'use strict';

  var API_URL = 'https://ozone-analyse.bbaranda055.workers.dev';
  var COOLDOWN_MS = 10000;
  // The site key is public by design. The secret key lives only on the backend.
  var TURNSTILE_SITE_KEY = '0x4AAAAAADfi29voJT_jNWHf';

  var $ = function (id) { return document.getElementById(id); };
  var input = $('messageInput');
  var checker = $('checkerCard');
  var btn = $('analyseBtn');
  var btnText = $('btnText');
  var statusText = $('statusText');
  var errorBox = $('errorBox');
  var errorText = $('errorText');
  var card = $('resultCard');
  var reduceMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  var cooldownActive = false;
  var busy = false;

  /* ---------- character counter ---------- */
  function updateCount() { $('charCount').textContent = input.value.length.toLocaleString('en-GB'); }
  input.addEventListener('input', updateCount);
  input.addEventListener('paste', function () { setTimeout(updateCount, 0); });

  /* ---------- contact address (kept out of the HTML source) ---------- */
  $('contact-email').textContent = 'bbaranda055' + '@' + 'gmail.com';

  /* ---------- Cloudflare Turnstile ---------- */
  var turnstileWidgetId = null;
  var turnstileToken = '';

  window.onTurnstileLoad = function () {
    turnstileWidgetId = window.turnstile.render('#turnstileBox', {
      sitekey: TURNSTILE_SITE_KEY,
      theme: 'auto',
      appearance: 'interaction-only',
      callback: function (token) { turnstileToken = token; },
      'expired-callback': function () { turnstileToken = ''; window.turnstile.reset(turnstileWidgetId); },
      'error-callback': function () { turnstileToken = ''; }
    });
  };

  // If someone clicks before the invisible check finishes, wait briefly for it.
  function waitForTurnstileToken(maxMs) {
    var start = Date.now();
    return new Promise(function (resolve) {
      (function poll() {
        if (turnstileToken || !window.turnstile || Date.now() - start >= maxMs) return resolve(turnstileToken);
        setTimeout(poll, 100);
      })();
    });
  }

  // Each token can be used once, so get a fresh one after every request.
  function refreshTurnstile() {
    turnstileToken = '';
    if (window.turnstile && turnstileWidgetId !== null) window.turnstile.reset(turnstileWidgetId);
  }

  /* ---------- UI helpers ---------- */
  function showError(msg) {
    errorText.textContent = msg;
    errorBox.hidden = false;
  }
  function clearError() { errorBox.hidden = true; errorText.textContent = ''; }

  function setChecking(on) {
    busy = on;
    checker.setAttribute('data-state', on ? 'checking' : 'idle');
    btn.disabled = on;
    btnText.textContent = on ? 'Checking…' : 'Check this message';
    statusText.textContent = on ? 'Checking your message for scam signs…' : '';
  }

  function startCooldown() {
    cooldownActive = true;
    var track = $('cooldownTrack');
    var fill = $('cooldownFill');
    track.classList.add('active');
    fill.style.transition = 'none';
    fill.style.width = '0';
    void fill.offsetWidth; // restart the transition
    fill.style.transition = 'width ' + COOLDOWN_MS + 'ms linear';
    fill.style.width = '100%';
    setTimeout(function () {
      cooldownActive = false;
      track.classList.remove('active');
      fill.style.transition = 'none';
      fill.style.width = '0';
    }, COOLDOWN_MS);
  }

  // Scroll so the element sits just below the sticky header. Computed by hand
  // because smooth scrollIntoView ignores scroll-padding in some browsers and
  // left the verdict hidden under the header.
  function scrollBelowHeader(el) {
    var y = 0;
    for (var n = el; n; n = n.offsetParent) y += n.offsetTop; // offsetTop ignores the entrance transform
    var header = document.querySelector('.site-header');
    var top = Math.max(0, y - (header ? header.offsetHeight : 0) - 16);
    window.scrollTo({ top: top, behavior: reduceMotion ? 'auto' : 'smooth' });
  }

  /* ---------- verdict rendering ---------- */
  // A wrong "safe" answer can cost someone money, so SAFE is never shown as a promise.
  var VERDICTS = {
    SAFE: {
      cls: 'v-safe',
      title: 'No scam signs found',
      sub: "That doesn't prove it's genuine. If it asks for money or personal details, contact the company using a number you already trust."
    },
    SUSPICIOUS: {
      cls: 'v-caution',
      title: 'Be careful',
      sub: "There are warning signs. Don't click links, call numbers or pay until you've checked independently."
    },
    SCAM: {
      cls: 'v-scam',
      title: 'This looks like a scam',
      sub: "Strong scam signs. Don't reply, click links, call back or send money."
    },
    INVALID: {
      cls: 'v-caution',
      title: "We couldn't check that",
      sub: 'Paste the full text of a message you received, then try again.'
    }
  };

  function render(r) {
    var v = VERDICTS[r.VERDICT] || VERDICTS.SUSPICIOUS;
    card.className = 'card result ' + v.cls;
    $('verdictTitle').textContent = v.title;
    $('verdictSub').textContent = v.sub;

    var pct = Number(r.CONFIDENCE_PERCENT);
    pct = isFinite(pct) ? Math.max(0, Math.min(100, Math.round(pct))) : null;
    $('confidencePct').textContent = pct === null ? '—' : pct + '%';
    $('severityText').textContent = typeof r.SEVERITY === 'string' && r.SEVERITY ? r.SEVERITY : '—';

    var list = $('reasonsList');
    list.textContent = '';
    (Array.isArray(r.REASONS) ? r.REASONS : []).slice(0, 3).forEach(function (reason) {
      var li = document.createElement('li');
      var span = document.createElement('span');
      span.textContent = String(reason);
      li.appendChild(span);
      list.appendChild(li);
    });
    $('actionBox').textContent = typeof r.WHAT_TO_DO === 'string' ? r.WHAT_TO_DO : '';
    $('reportBox').hidden = !(r.VERDICT === 'SCAM' || r.VERDICT === 'SUSPICIOUS');

    card.hidden = false;
    setDial(pct);
    if (pct !== null && !reduceMotion) countUp($('confidencePct'), 0, pct, 0, '', '%', 900);
    if (!reduceMotion) {
      card.classList.remove('is-entering');
      void card.offsetWidth;
      card.classList.add('is-entering');
    }
    $('verdictTitle').focus({ preventScroll: true });
    scrollBelowHeader(card);
  }

  /* ---------- main action ---------- */
  function analyse() {
    if (busy) return;
    var message = input.value.trim();
    clearError();

    if (!message) { showError('Please paste a message to check.'); input.focus(); return; }
    if (cooldownActive) { showError('Please wait a few seconds before checking another message.'); return; }

    setChecking(true);
    card.hidden = true;

    waitForTurnstileToken(5000)
      .then(function () {
        return fetch(API_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ message: message, turnstileToken: turnstileToken })
        });
      })
      .then(function (res) {
        if (!res.ok) {
          return res.json().catch(function () { return {}; }).then(function (e) {
            throw new Error(e.error || 'Something went wrong (error ' + res.status + '). Please try again.');
          });
        }
        return res.text();
      })
      .then(function (raw) {
        var parsed = JSON.parse(raw.replace(/```json|```/g, '').trim());
        // Finish the layout change above the card before measuring and scrolling to it.
        setChecking(false);
        render(parsed);
        startCooldown();
      })
      .catch(function (err) {
        setChecking(false);
        var msg = err && err.message ? err.message : '';
        if (!msg || /Failed to fetch|NetworkError|Load failed/i.test(msg)) {
          msg = "We couldn't reach the checker. Check your connection and try again.";
        } else if (/JSON|Unexpected token/i.test(msg)) {
          msg = 'We got an unreadable answer. Please try again.';
        }
        showError(msg);
      })
      .then(function () {
        refreshTurnstile();
      });
  }

  btn.addEventListener('click', analyse);
  document.addEventListener('keydown', function (e) {
    if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') { e.preventDefault(); analyse(); }
  });

  $('againBtn').addEventListener('click', function () {
    card.hidden = true;
    clearError();
    input.value = '';
    updateCount();
    input.focus();
    scrollBelowHeader($('checker'));
  });

  /* ---------- scroll progress + header state (one write per frame) ---------- */
  var fill = $('progressFill');
  var header = $('siteHeader');

  /* ---------- decoder: scroll dissects a scam, one red flag at a time ---------- */
  var decoder = $('decoder');
  var dcFlags = decoder ? decoder.querySelectorAll('.dc-flag') : [];
  var dcNotes = decoder ? decoder.querySelectorAll('.dc-note') : [];
  var dcStamp = decoder ? decoder.querySelector('.dc-stamp') : null;
  var dcStep = -1;
  if (decoder && !reduceMotion) document.documentElement.classList.add('dc-live');
  function updateDecoder() {
    if (!decoder || reduceMotion) return;
    var r = decoder.getBoundingClientRect();
    var span = r.height - window.innerHeight;
    var p = span > 0 ? Math.min(1, Math.max(0, -r.top / span)) : 1;
    var step = Math.min(5, Math.floor(p * 6));          // 0 = clean, 1-4 = flags, 5 = verdict
    if (step === dcStep) return;
    dcStep = step;
    Array.prototype.forEach.call(dcFlags, function (el, i) { el.classList.toggle('on', i < step); });
    Array.prototype.forEach.call(dcNotes, function (el, i) {
      el.classList.toggle('on', i < step);
      el.classList.toggle('current', i === Math.min(step, 4) - 1);
    });
    if (dcStamp) dcStamp.classList.toggle('on', step >= 5);
    var count = $('dcCount'); if (count) count.textContent = String(Math.min(step, 4));
  }
  var ticking = false;
  var pendingReveals = [];
  function reveal(el) {
    el.classList.add('reveal-in');
    el.classList.remove('reveal-pending');
    Array.prototype.forEach.call(el.querySelectorAll('.count'), runCounter);
  }
  function updateProgress() {
    ticking = false;
    // Also reveal anything already scrolled past (e.g. after jumping to a link),
    // so no section can stay invisible.
    if (pendingReveals.length) {
      var limit = window.innerHeight * 0.95;
      pendingReveals = pendingReveals.filter(function (el) {
        if (el.classList.contains('reveal-in')) return false;
        if (el.getBoundingClientRect().top < limit) { reveal(el); return false; }
        return true;
      });
    }
    var max = document.documentElement.scrollHeight - window.innerHeight;
    var p = max > 0 ? Math.min(1, Math.max(0, window.scrollY / max)) : 0;
    if (fill) fill.style.setProperty('--progress', p.toFixed(4));
    if (header) header.classList.toggle('is-scrolled', window.scrollY > 8);
    updateDecoder();
  }
  window.addEventListener('scroll', function () {
    if (!ticking) { ticking = true; requestAnimationFrame(updateProgress); }
  }, { passive: true });
  updateProgress();

  /* ---------- count-up numbers ---------- */
  function easeOutCubic(t) { return 1 - Math.pow(1 - t, 3); }
  function formatNum(v, decimals) {
    return v.toLocaleString('en-GB', { minimumFractionDigits: decimals, maximumFractionDigits: decimals });
  }
  function countUp(el, from, to, decimals, prefix, suffix, ms) {
    var start = null;
    function frame(ts) {
      if (start === null) start = ts;
      var t = Math.min(1, (ts - start) / ms);
      el.textContent = prefix + formatNum(from + (to - from) * easeOutCubic(t), decimals) + suffix;
      if (t < 1) requestAnimationFrame(frame);
    }
    requestAnimationFrame(frame);
  }
  function runCounter(el) {
    if (el.dataset.counted) return;
    el.dataset.counted = '1';
    if (reduceMotion) return; // the final value is already in the HTML
    countUp(el, 0, parseFloat(el.dataset.to), parseInt(el.dataset.decimals || '0', 10),
      el.dataset.prefix || '', el.dataset.suffix || '', 1300);
  }

  /* ---------- confidence dial ---------- */
  var DIAL_C = 2 * Math.PI * 24;
  function setDial(pct) {
    var arc = $('dialArc');
    if (!arc) return;
    arc.style.strokeDashoffset = String(DIAL_C);
    void arc.getBoundingClientRect(); // restart the sweep each time
    arc.style.strokeDashoffset = String(pct === null ? DIAL_C : DIAL_C * (1 - pct / 100));
  }

  /* ---------- soft glow that follows the pointer in the hero ---------- */
  var heroArt = document.querySelector('.hero-art');
  var heroEl = document.querySelector('.hero');
  if (heroArt && heroEl && !reduceMotion && window.matchMedia && window.matchMedia('(hover: hover) and (pointer: fine)').matches) {
    var glowQueued = false, gx = 0, gy = 0;
    heroEl.addEventListener('pointermove', function (e) {
      var r = heroEl.getBoundingClientRect(); gx = e.clientX - r.left; gy = e.clientY - r.top;
      if (glowQueued) return; glowQueued = true;
      requestAnimationFrame(function () {
        glowQueued = false;
        heroArt.style.setProperty('--gx', gx.toFixed(0) + 'px');
        heroArt.style.setProperty('--gy', gy.toFixed(0) + 'px');
        heroArt.style.setProperty('--glow', '1');
      });
    }, { passive: true });
    heroEl.addEventListener('pointerleave', function () { heroArt.style.setProperty('--glow', '0'); });
  }

  /* ---------- cursor spotlight on cards ---------- */
  if (!reduceMotion && window.matchMedia && window.matchMedia('(hover: hover) and (pointer: fine)').matches) {
    Array.prototype.forEach.call(document.querySelectorAll('.spot'), function (el) {
      el.addEventListener('pointermove', function (e) {
        var r = el.getBoundingClientRect();
        el.style.setProperty('--mx', (e.clientX - r.left).toFixed(0) + 'px');
        el.style.setProperty('--my', (e.clientY - r.top).toFixed(0) + 'px');
      }, { passive: true });
    });
  }

  /* ---------- scroll reveals with a stagger ---------- */
  var revealEls = Array.prototype.slice.call(document.querySelectorAll('[data-reveal]'));
  if ('IntersectionObserver' in window && !reduceMotion) {
    var vh = window.innerHeight;
    revealEls.forEach(function (el) {
      var sibs = Array.prototype.filter.call(el.parentNode.children, function (c) { return c.hasAttribute('data-reveal'); });
      el.style.setProperty('--i', String(Math.min(sibs.indexOf(el), 6)));
      // Only hide what starts below the fold: the page is complete without JS
      // and nothing already on screen flickers.
      if (el.getBoundingClientRect().top > vh * 0.9) { el.classList.add('reveal-pending'); pendingReveals.push(el); }
    });
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) {
        if (!en.isIntersecting) return;
        reveal(en.target);
        io.unobserve(en.target);
      });
    }, { rootMargin: '0px 0px -12% 0px', threshold: 0.12 });
    revealEls.forEach(function (el) { io.observe(el); });
  }
})();
