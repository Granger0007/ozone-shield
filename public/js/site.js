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
    statusText.textContent = on ? 'Checking your message. This usually takes about 6 seconds.' : '';
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
    $('confidencePct').textContent = isFinite(pct) ? Math.max(0, Math.min(100, Math.round(pct))) + '%' : '—';
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
})();
