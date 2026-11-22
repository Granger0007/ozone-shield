/* Spot the Scam: game logic. Progress lives only in this browser (localStorage). */
(function () {
  'use strict';

  var DATA = window.OzoneGameData || [];
  var HARD = window.OzoneGameHard || [];
  var TIME_LIMIT = 30; // seconds per message in Expert
  var MODES = { classic: 'Classic', hard: 'Hard', expert: 'Expert' };
  var STORE_KEY = 'ozone.spotTheScam.v1';
  var ROUND_SCAMS = 7, ROUND_GENUINE = 3;
  var SHARE_URL = 'https://ozone-shield.bbaranda055.workers.dev/spot-the-scam/';
  var LEVELS = [
    { xp: 0, name: 'Rookie' }, { xp: 300, name: 'Spotter' }, { xp: 800, name: 'Investigator' },
    { xp: 1500, name: 'Defender' }, { xp: 2500, name: 'Guardian' }, { xp: 4000, name: 'Shield Master' }
  ];
  var BADGES = {
    'first-catch': { name: 'First catch', desc: 'Caught your first scam', icon: '1' },
    'not-fooled': { name: 'Not fooled', desc: 'Trusted a genuine message', icon: '✓' },
    'eagle-eye': { name: 'Eagle eye', desc: 'Found every red flag in a message', icon: '◎' },
    'hat-trick': { name: 'Hat-trick', desc: '3 right in a row', icon: '3' },
    'on-fire': { name: 'On fire', desc: '7 right in a row', icon: '7' },
    'perfect': { name: 'Perfect round', desc: '10 out of 10', icon: '10' },
    'parcel-pro': { name: 'Parcel pro', desc: 'Caught a delivery scam', icon: 'P' },
    'tax-wise': { name: 'Tax wise', desc: 'Caught a fake tax refund', icon: '£' },
    'family-first': { name: 'Family first', desc: 'Caught a "Hi Mum" scam', icon: 'M' },
    'bank-guard': { name: 'Bank guard', desc: 'Caught a fake bank or police message', icon: 'B' },
    'regular': { name: 'Regular', desc: 'Played 3 days in a row', icon: 'D' },
    'inspector': { name: 'Inspector', desc: 'Exposed a disguised link before answering', icon: '?' },
    'investigator': { name: 'Investigator', desc: '10 out of 10 in Hard or Expert', icon: 'H' },
    'cool-head': { name: 'Cool head', desc: '8 or more right in Expert', icon: 'E' }
  };
  var CATEGORY_BADGE = { parcel: 'parcel-pro', tax: 'tax-wise', family: 'family-first', bank: 'bank-guard' };

  var $ = function (id) { return document.getElementById(id); };
  var reduceMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  /* ---------- storage (this device only) ---------- */
  function fresh() { return { xp: 0, badges: [], best: null, lastDay: null, dayStreak: 0 }; }
  function load() {
    try {
      var s = JSON.parse(localStorage.getItem(STORE_KEY) || 'null');
      if (s && typeof s.xp === 'number' && isFinite(s.xp) && s.xp >= 0) {
        return {
          xp: Math.floor(s.xp),
          badges: Array.isArray(s.badges) ? s.badges.filter(function (b) { return BADGES[b]; }) : [],
          best: typeof s.best === 'number' ? s.best : null,
          lastDay: typeof s.lastDay === 'string' ? s.lastDay : null,
          dayStreak: typeof s.dayStreak === 'number' ? s.dayStreak : 0
        };
      }
    } catch (e) { /* storage blocked or corrupt: start fresh */ }
    return fresh();
  }
  function save() { try { localStorage.setItem(STORE_KEY, JSON.stringify(store)); } catch (e) { /* private mode */ } }
  var store = load();

  function dayString(d) {
    var p = function (n) { return (n < 10 ? '0' : '') + n; };
    return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate());
  }
  function touchDay() {
    var today = dayString(new Date());
    if (store.lastDay === today) return;
    var y = new Date(); y.setDate(y.getDate() - 1);
    store.dayStreak = store.lastDay === dayString(y) ? store.dayStreak + 1 : 1;
    store.lastDay = today;
  }

  /* ---------- HUD ---------- */
  function levelIndex(xp) { var i = 0; while (i + 1 < LEVELS.length && xp >= LEVELS[i + 1].xp) i++; return i; }
  function renderHud() {
    var i = levelIndex(store.xp);
    var cur = LEVELS[i].xp, next = LEVELS[i + 1] ? LEVELS[i + 1].xp : null;
    $('levelNum').textContent = String(i + 1);
    $('levelNumText').textContent = String(i + 1);
    $('levelName').textContent = LEVELS[i].name;
    $('xpNow').textContent = store.xp.toLocaleString('en-GB');
    $('xpNext').textContent = next === null ? 'MAX' : next.toLocaleString('en-GB');
    var frac = next === null ? 1 : (store.xp - cur) / (next - cur);
    $('xpFill').style.setProperty('--xp', Math.max(0, Math.min(1, frac)).toFixed(4));
    $('xpBar').setAttribute('aria-valuenow', String(Math.round(frac * 100)));
    $('dayStreak').textContent = String(store.dayStreak);
    $('bestScore').textContent = store.best === null ? '–' : store.best.toLocaleString('en-GB');
    renderShelf();
  }

  function badgeEl(key, earned) {
    var b = BADGES[key];
    var li = document.createElement('li');
    li.className = 'badge' + (earned ? ' earned' : '');
    var ic = document.createElement('span'); ic.className = 'badge-icon'; ic.setAttribute('aria-hidden', 'true'); ic.textContent = b.icon;
    var tx = document.createElement('span'); tx.className = 'badge-text';
    var n = document.createElement('b'); n.textContent = b.name;
    var d = document.createElement('span'); d.textContent = earned ? b.desc : 'Locked: ' + b.desc.toLowerCase();
    tx.appendChild(n); tx.appendChild(d);
    li.appendChild(ic); li.appendChild(tx);
    return li;
  }
  function renderShelf() {
    var shelf = $('badgeShelf'); shelf.textContent = '';
    Object.keys(BADGES).forEach(function (k) { shelf.appendChild(badgeEl(k, store.badges.indexOf(k) !== -1)); });
  }

  /* ---------- effects ---------- */
  function floatXp(amount, anchor) {
    if (reduceMotion || !anchor) return;
    var r = anchor.getBoundingClientRect();
    var f = document.createElement('span');
    f.className = 'xp-float'; f.textContent = '+' + amount;
    f.style.left = (r.left + r.width / 2) + 'px';
    f.style.top = (r.top + window.scrollY) + 'px';
    document.body.appendChild(f);
    setTimeout(function () { f.remove(); }, 1100);
  }
  function confetti(n) {
    if (reduceMotion) return;
    var box = $('confetti');
    for (var i = 0; i < n; i++) {
      var c = document.createElement('i');
      c.className = 'cf c' + (i % 4);
      c.style.setProperty('--x', (Math.random() * 100).toFixed(1) + 'vw');
      c.style.setProperty('--dx', ((Math.random() - 0.5) * 30).toFixed(1) + 'vw');
      c.style.setProperty('--r', Math.round(Math.random() * 720 - 360) + 'deg');
      c.style.setProperty('--d', (900 + Math.random() * 900).toFixed(0) + 'ms');
      box.appendChild(c);
    }
    setTimeout(function () { box.textContent = ''; }, 2000);
  }

  var newBadges = [];
  function award(key) {
    if (!BADGES[key] || store.badges.indexOf(key) !== -1) return;
    store.badges.push(key);
    newBadges.push(key);
    save();
    renderShelf();
  }

  var pendingLevelUp = null;
  function addXp(amount, anchor) {
    var before = levelIndex(store.xp);
    store.xp += amount;
    var after = levelIndex(store.xp);
    game.score += amount;
    $('scoreNow').textContent = game.score.toLocaleString('en-GB');
    floatXp(amount, anchor);
    save();
    renderHud();
    if (after > before) pendingLevelUp = after;
  }
  function showLevelUp(i, then) {
    var lv = $('levelUp');
    var back = document.activeElement;
    $('levelUpNum').textContent = String(i + 1);
    $('levelUpName').textContent = LEVELS[i].name;
    lv.hidden = false;
    confetti(48);
    $('levelUpOk').focus();
    $('levelUpOk').onclick = function () {
      lv.hidden = true;
      if (back && back.focus) back.focus();
      if (then) then();
    };
  }

  /* ---------- game flow ---------- */
  function shuffle(a) {
    for (var i = a.length - 1; i > 0; i--) { var j = Math.floor(Math.random() * (i + 1)); var t = a[i]; a[i] = a[j]; a[j] = t; }
    return a;
  }
  var game = null;

  // A red flag is any part with a reason; links without one are just links.
  function isFlag(p) { return typeof p !== 'string' && !!p.why; }
  // Note: strings have a legacy .link() method, so always check the type first.
  function isLink(p) { return !!p && typeof p === 'object' && typeof p.link === 'string'; }
  function partText(p) { return typeof p === 'string' ? p : (isLink(p) ? p.link : p.t); }

  function newGame(mode) {
    mode = MODES[mode] ? mode : 'classic';
    var rounds;
    if (mode === 'classic') {
      var scams = shuffle(DATA.filter(function (m) { return m.scam; })).slice(0, ROUND_SCAMS);
      var genuine = shuffle(DATA.filter(function (m) { return !m.scam; })).slice(0, ROUND_GENUINE);
      rounds = shuffle(scams.concat(genuine));
    } else {
      // Between 5 and 7 scams, so counting can't give the answer away.
      var nScam = 5 + Math.floor(Math.random() * 3);
      var hs = shuffle(HARD.filter(function (m) { return m.scam; })).slice(0, nScam);
      var hg = shuffle(HARD.filter(function (m) { return !m.scam; })).slice(0, 10 - nScam);
      rounds = shuffle(hs.concat(hg));
    }
    game = { mode: mode, rounds: rounds, i: 0, score: 0, correct: 0, streak: 0, bestStreak: 0, flags: 0, results: [], answered: false };
    newBadges = [];
    touchDay();
    if (store.dayStreak >= 3) award('regular');
    save(); renderHud();
    $('roundTotal').textContent = String(game.rounds.length);
    $('scoreNow').textContent = '0';
    var ticks = $('roundTicks'); ticks.textContent = '';
    game.rounds.forEach(function () { ticks.appendChild(document.createElement('li')); });
    $('timer').hidden = mode !== 'expert';
    show('roundScreen');
    showRound();
  }

  function show(id) {
    ['startScreen', 'roundScreen', 'endScreen'].forEach(function (s) { $(s).hidden = s !== id; });
  }

  function isPunct(t) { return /^[\s.,:;!?'"-]*$/.test(t); }

  function showRound() {
    var m = game.rounds[game.i];
    game.answered = false;
    game.found = 0;
    $('roundNum').textContent = String(game.i + 1);
    Array.prototype.forEach.call($('roundTicks').children, function (li, k) { li.classList.toggle('current', k === game.i); });
    $('msgChannel').textContent = m.channel;
    $('msgChannel').className = 'channel ch-' + m.channel.toLowerCase();
    $('msgSender').textContent = m.sender;
    $('phone').setAttribute('data-channel', m.channel.toLowerCase());
    $('phone').classList.toggle('is-hard', game.mode !== 'classic');
    // Hard mode: what you'd really know, the earlier messages, the full sender
    $('msgContext').hidden = !m.context;
    $('msgContextText').textContent = m.context || '';
    $('msgTime').textContent = m.time || '';
    $('msgFrom').hidden = true;
    $('msgFrom').textContent = m.from || '';
    $('msgSender').setAttribute('aria-expanded', 'false');
    $('msgSender').disabled = !m.from;
    $('msgStranger').hidden = !(m.channel === 'WhatsApp' && !m.known && /^\+/.test(m.sender));
    $('msgSubject').hidden = !m.subject;
    $('msgSubject').textContent = m.subject || '';
    var thread = $('msgThread'); thread.textContent = '';
    (m.thread || []).forEach(function (t) {
      var li = document.createElement('li');
      li.className = 'tmsg ' + (t.who === 'me' ? 'me' : 'them');
      var tx = document.createElement('span'); tx.textContent = t.text;
      var tm = document.createElement('small'); tm.textContent = t.time || '';
      li.appendChild(tx); li.appendChild(tm);
      thread.appendChild(li);
    });
    thread.hidden = !(m.thread && m.thread.length);
    $('msgPeek').hidden = true;
    $('inspectHint').hidden = game.mode === 'classic' || !(m.from || m.parts.some(isLink));

    var body = $('msgBody'); body.textContent = '';
    m.parts.forEach(function (part, k) {
      var text = partText(part);
      // Punctuation and tiny joining words (like " at ") stay plain text: as tap
      // targets they would be smaller than the 24px minimum in WCAG 2.2.
      if (typeof part === 'string' && (isPunct(text) || text.trim().length < 4)) { body.appendChild(document.createTextNode(text)); return; }
      // Inline spans (not <button>) so highlights flow inside the sentence;
      // they become keyboard-operable buttons during the red-flag hunt.
      var seg = document.createElement('span');
      seg.className = 'seg' + (isLink(part) ? ' link' : '');
      seg.textContent = text;
      if (isLink(part)) { // links can be inspected at any time, like a long-press
        seg.setAttribute('role', 'button');
        seg.setAttribute('tabindex', '0');
        seg.setAttribute('aria-label', 'Link: ' + text + '. Press to see where it really goes.');
      }
      seg.dataset.k = String(k);
      seg.addEventListener('click', onSegment);
      seg.addEventListener('keydown', function (e) {
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onSegment(e); }
      });
      body.appendChild(seg);
    });

    $('choices').hidden = false;
    $('feedback').hidden = true;
    $('flagsBox').hidden = true;
    $('flagNotes').textContent = '';
    var phone = $('phone');
    if (!reduceMotion) { phone.classList.remove('enter'); void phone.offsetWidth; phone.classList.add('enter'); }
    phone.focus({ preventScroll: true });
    startTimer();
  }

  /* ---------- inspecting, like a long-press on a real phone ---------- */
  function peek(text, warn) {
    var p = $('msgPeek');
    p.textContent = text;
    p.className = 'peek' + (warn ? ' warn' : '');
    p.hidden = false;
  }
  function inspectLink(part) {
    peek('This link opens: ' + part.url, false);
    if (part.why && !game.answered) { game.inspected = true; award('inspector'); }
  }
  function toggleFrom() {
    var f = $('msgFrom'), open = f.hidden;
    f.hidden = !open;
    $('msgSender').setAttribute('aria-expanded', open ? 'true' : 'false');
  }

  /* ---------- Expert: a clock, because scammers rush you ---------- */
  var timer = null;
  function stopTimer() { if (timer) { clearInterval(timer); timer = null; } }
  function startTimer() {
    stopTimer();
    if (game.mode !== 'expert') return;
    game.deadline = Date.now() + TIME_LIMIT * 1000;
    var fill = $('timerFill'), num = $('timerNum');
    function tick() {
      var left = Math.max(0, game.deadline - Date.now());
      fill.style.setProperty('--t', (left / (TIME_LIMIT * 1000)).toFixed(4));
      num.textContent = String(Math.ceil(left / 1000));
      $('timer').classList.toggle('low', left < 8000);
      if (left <= 0) { stopTimer(); answer(null); }
    }
    tick();
    timer = setInterval(tick, 200);
  }

  function answer(saidScam) {
    if (game.answered) return;
    game.answered = true;
    var timedOut = saidScam === null;
    var left = game.deadline ? Math.max(0, game.deadline - Date.now()) : 0;
    stopTimer();
    var m = game.rounds[game.i];
    var hard = game.mode !== 'classic';
    var right = !timedOut && saidScam === m.scam;
    var btn = saidScam ? $('ansScam') : $('ansSafe');
    game.results.push(right);
    $('roundTicks').children[game.i].classList.add(right ? 'right' : 'wrong');

    if (right) {
      game.correct++;
      game.streak++;
      game.bestStreak = Math.max(game.bestStreak, game.streak);
      addXp(hard ? 150 : 100, btn);
      if (game.streak >= 3) addXp(50, btn);
      if (game.mode === 'expert') { var bonus = Math.round(50 * left / (TIME_LIMIT * 1000)); if (bonus > 0) addXp(bonus, btn); }
      if (m.scam) { award('first-catch'); if (CATEGORY_BADGE[m.cat]) award(CATEGORY_BADGE[m.cat]); }
      else award('not-fooled');
      if (game.streak === 3) award('hat-trick');
      if (game.streak === 7) award('on-fire');
    } else {
      game.streak = 0;
      // Too much suspicion costs something too: a missed GP appointment, a real fraud alert ignored.
      if (hard && saidScam === true && !m.scam) {
        game.score -= 50;
        $('scoreNow').textContent = game.score.toLocaleString('en-GB');
      }
    }

    var fb = $('feedback');
    fb.className = 'feedback ' + (right ? 'is-right' : 'is-wrong');
    $('fbTitle').textContent = timedOut
      ? (m.scam ? "Time's up: it was a scam" : "Time's up: it was genuine")
      : right
      ? (m.scam ? "Right, it's a scam" : "Right, it's genuine")
      : (m.scam ? 'Not quite: this one is a scam' : (hard ? 'Not quite: this one is genuine (−50)' : 'Not quite: this one is genuine'));
    $('fbLesson').textContent = m.lesson;
    $('choices').hidden = true;
    fb.hidden = false;

    var total = m.parts.filter(isFlag).length;
    if (m.scam && total) {
      $('flagsTotal').textContent = String(total);
      $('flagsFound').textContent = '0';
      $('flagsBox').hidden = false;
      $('revealBtn').hidden = false;
      Array.prototype.forEach.call($('msgBody').querySelectorAll('.seg'), function (s) {
        s.setAttribute('role', 'button');
        s.setAttribute('tabindex', '0');
        s.removeAttribute('aria-label');
      });
      $('phone').classList.add('hunting');
    }
    $('nextBtn').textContent = game.i + 1 < game.rounds.length ? 'Next message' : 'See my results';
    $('fbTitle').focus({ preventScroll: true });
    fb.scrollIntoView({ behavior: reduceMotion ? 'auto' : 'smooth', block: 'nearest' });
  }

  function addNote(part, earned) {
    var li = document.createElement('li');
    li.className = earned ? 'note found' : 'note revealed';
    var q = document.createElement('b'); q.textContent = '“' + partText(part) + '”';
    var w = document.createElement('span'); w.textContent = part.why;
    li.appendChild(q); li.appendChild(w);
    $('flagNotes').appendChild(li);
  }

  function onSegment(e) {
    var seg = e.currentTarget;
    var m = game.rounds[game.i];
    var part = m.parts[Number(seg.dataset.k)];
    if (isLink(part) && (!game.answered || !$('phone').classList.contains('hunting'))) { inspectLink(part); return; }
    if (seg.getAttribute('tabindex') !== '0') return; // only during the red-flag hunt
    if (seg.classList.contains('found') || seg.classList.contains('revealed')) return;
    if (isLink(part)) inspectLink(part);
    if (!isFlag(part)) {
      seg.classList.remove('nope'); void seg.offsetWidth; seg.classList.add('nope');
      return;
    }
    seg.classList.add('found');
    seg.setAttribute('aria-label', 'Red flag found: ' + partText(part));
    game.found++; game.flags++;
    $('flagsFound').textContent = String(game.found);
    addNote(part, true);
    addXp(25, seg);
    var total = m.parts.filter(isFlag).length;
    if (game.found === total) { award('eagle-eye'); $('revealBtn').hidden = true; }
  }

  function revealRest() {
    var m = game.rounds[game.i];
    Array.prototype.forEach.call($('msgBody').querySelectorAll('.seg'), function (seg) {
      var part = m.parts[Number(seg.dataset.k)];
      if (isFlag(part) && !seg.classList.contains('found')) { seg.classList.add('revealed'); addNote(part, false); }
    });
    $('revealBtn').hidden = true;
  }

  function next() {
    $('phone').classList.remove('hunting');
    stopTimer();
    var go = function () {
      game.i++;
      if (game.i < game.rounds.length) showRound(); else finish();
    };
    if (pendingLevelUp !== null) { var lv = pendingLevelUp; pendingLevelUp = null; showLevelUp(lv, go); }
    else go();
  }

  function finish() {
    stopTimer();
    if (game.correct === game.rounds.length) award('perfect');
    if (game.mode !== 'classic' && game.correct === game.rounds.length) award('investigator');
    if (game.mode === 'expert' && game.correct >= 8) award('cool-head');
    $('endMode').textContent = MODES[game.mode] + ' mode';
    if (store.best === null || game.score > store.best) store.best = game.score;
    save(); renderHud();
    show('endScreen');
    $('endCorrect').textContent = String(game.correct);
    $('endScore').textContent = game.score.toLocaleString('en-GB');
    $('endFlags').textContent = String(game.flags);
    $('endStreak').textContent = String(game.bestStreak);
    var c = game.correct;
    $('endMsg').textContent = game.mode !== 'classic'
      ? (c === 10 ? 'Perfect. You would catch scams that fool most people.'
        : c >= 8 ? 'Excellent. These are the scams that catch careful people out.'
        : c >= 5 ? 'Solid. Hard mode is meant to be hard: check the lessons and try again.'
        : 'These scams fool experts too. Read the lessons, then play again.')
      : c === 10 ? 'Perfect. Nothing gets past you.'
      : c >= 8 ? "Excellent. You'd spot most scams."
      : c >= 5 ? 'Good start. Play again to sharpen your eye.'
      : "Scams are designed to fool people. Play again and you'll improve fast.";
    var list = $('newBadgeList'); list.textContent = '';
    newBadges.forEach(function (k) { list.appendChild(badgeEl(k, true)); });
    $('newBadges').hidden = newBadges.length === 0;
    if (c >= 8) confetti(64);
    $('end-title').focus({ preventScroll: true });
    window.scrollTo({ top: 0, behavior: reduceMotion ? 'auto' : 'smooth' });
  }

  function toast(msg) {
    var t = $('toast'); t.textContent = msg; t.classList.add('show');
    setTimeout(function () { t.classList.remove('show'); }, 3000);
  }
  function share() {
    var text = 'I got ' + game.correct + '/10 on Spot the Scam (' + MODES[game.mode] + ' mode) by OZONE Shield. Can you beat me?';
    if (navigator.share) {
      navigator.share({ title: 'Spot the Scam', text: text, url: SHARE_URL }).catch(function () { /* cancelled */ });
      return;
    }
    var full = text + ' ' + SHARE_URL;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(full).then(function () { toast('Copied. Paste it into a message to challenge a friend.'); },
        function () { toast(full); });
    } else { toast(full); }
  }

  var resetArmed = false;
  function reset() {
    var b = $('resetBtn');
    if (!resetArmed) {
      resetArmed = true; b.textContent = 'Tap again to confirm: this clears your points and badges';
      setTimeout(function () { resetArmed = false; b.textContent = 'Reset my progress'; }, 4000);
      return;
    }
    resetArmed = false;
    store = fresh();
    try { localStorage.removeItem(STORE_KEY); } catch (e) { /* ignore */ }
    b.textContent = 'Progress reset';
    renderHud();
  }

  $('startBtn').addEventListener('click', function () { newGame('classic'); });
  $('startHard').addEventListener('click', function () { newGame('hard'); });
  $('startExpert').addEventListener('click', function () { newGame('expert'); });
  $('againBtn').addEventListener('click', function () { newGame(game ? game.mode : 'classic'); });
  $('modesBtn').addEventListener('click', function () { show('startScreen'); $('startBtn').focus(); });
  $('msgSender').addEventListener('click', toggleFrom);
  $('ansScam').addEventListener('click', function () { answer(true); });
  $('ansSafe').addEventListener('click', function () { answer(false); });
  $('revealBtn').addEventListener('click', revealRest);
  $('nextBtn').addEventListener('click', next);
  $('shareBtn').addEventListener('click', share);
  $('resetBtn').addEventListener('click', reset);

  renderHud();

  // Read-only hook for automated tests.
  window.OzoneGame = { current: function () { return game && game.rounds[game.i]; }, store: function () { return store; }, mode: function () { return game && game.mode; } };
})();
