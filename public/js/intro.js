/* OZONE Shield: the opening door. Runs in <head> so the door is closed before
   the first paint. The doors, dial and lock are pure CSS (pseudo-elements on
   <html> and <body>); this script only decides whether to play and moves the
   sequence on: lock turns and opens, the doors part, the visitor is welcomed.
   Plays once per visit, any key or tap skips it, never with reduced motion,
   and CSS opens the doors on its own if this script stops for any reason. */
(function () {
  'use strict';
  var root = document.documentElement;
  var reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  var seen = false;
  try { seen = sessionStorage.getItem('ozone.intro') === '1'; sessionStorage.setItem('ozone.intro', '1'); } catch (e) { seen = true; }
  if (reduce || seen) return;

  window.ozoneIntroPlaying = true;
  root.classList.add('intro');
  var timers = [], finished = false;

  function welcome() { window.dispatchEvent(new Event('ozone:welcome')); }
  function finish() {
    if (finished) return;
    finished = true;
    timers.forEach(clearTimeout);
    root.classList.remove('intro', 'intro-unlock', 'intro-open', 'intro-fast');
    window.ozoneIntroPlaying = false;
    ['keydown', 'pointerdown', 'wheel', 'touchstart'].forEach(function (t) { window.removeEventListener(t, skip, true); });
  }
  function open(fast) {
    if (root.classList.contains('intro-open')) return;
    root.classList.add('intro-unlock', 'intro-open');
    if (fast) root.classList.add('intro-fast');
    welcome();
    timers.push(setTimeout(finish, fast ? 450 : 1100));
  }
  function skip() { if (!finished) open(true); }

  timers.push(setTimeout(function () { root.classList.add('intro-unlock'); }, 450));
  timers.push(setTimeout(function () { open(false); }, 1250));
  ['keydown', 'pointerdown', 'wheel', 'touchstart'].forEach(function (t) { window.addEventListener(t, skip, { capture: true, passive: true }); });
})();
