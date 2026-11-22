/* OZONE Shield: "How a scam works". One invented scam text sits on a phone
   that stays in place while five short beats scroll past it. This script only
   reports where the reader is: data-beat (0-4) says which beat is in the
   middle of the screen and --p (0-1) how far through the section they are.
   CSS does all the drawing, using transforms and opacity so it stays smooth.
   Without this script the message and every beat's words still show. */
(function () {
  'use strict';
  var section = document.getElementById('anatomy');
  if (!section) return;
  var phone = section.querySelector('.phone');
  var beats = Array.prototype.slice.call(section.querySelectorAll('.beat'));
  var checkSection = document.getElementById('checkSection');
  var reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  section.classList.add('is-live');

  var current = -1, target = 0.5, shown = 0.5, ticking = false, arrived = false;

  function setBeat(i) {
    if (i === current) return;
    current = i;
    section.setAttribute('data-beat', String(i));
    beats.forEach(function (b, n) { b.classList.toggle('is-active', n === i); });
  }

  function measure() {
    ticking = false;
    var vh = window.innerHeight;
    var rect = section.getBoundingClientRect();

    // Which beat crosses the line just below the middle of the screen?
    var line = vh * 0.55, pick = 0;
    for (var n = 0; n < beats.length; n++) {
      if (beats[n].getBoundingClientRect().top <= line) pick = n;
    }
    setBeat(pick);

    // The first time the section comes into view, the message arrives.
    if (!arrived && rect.top < vh * 0.6 && rect.bottom > 0) {
      arrived = true;
      if (!reduce && rect.top > -vh * 0.3) section.classList.add('is-arriving');
    }

    target = Math.min(1, Math.max(0, (vh - rect.top) / (rect.height + vh)));
    if (!reduce) glide();
  }

  // Ease the phone's tilt towards the scroll position instead of jumping.
  var gliding = false;
  function glide() {
    if (gliding) return;
    gliding = true;
    requestAnimationFrame(function step() {
      shown += (target - shown) * 0.12;
      if (Math.abs(target - shown) < 0.0005) shown = target;
      phone.style.setProperty('--p', shown.toFixed(4));
      if (shown !== target) requestAnimationFrame(step);
      else gliding = false;
    });
  }

  function onScroll() {
    if (!ticking) { ticking = true; requestAnimationFrame(measure); }
  }
  window.addEventListener('scroll', onScroll, { passive: true });
  window.addEventListener('resize', onScroll, { passive: true });
  measure();

  // As the story hands over, the checker lights up to take the question.
  if (checkSection && 'IntersectionObserver' in window) {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) {
        if (en.isIntersecting) { checkSection.classList.add('is-near'); io.disconnect(); }
      });
    }, { threshold: 0.35 });
    io.observe(checkSection);
  }
})();
