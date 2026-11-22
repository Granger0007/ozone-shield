/* OZONE Shield: the phone menu. It is a plain <details> element, so it opens
   and closes without this script; this only closes it on Escape, on a tap
   outside it, and after a link inside it is followed. */
(function () {
  'use strict';
  var menu = document.querySelector('.menu');
  if (!menu) return;
  function close() { if (menu.open) menu.open = false; }
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && menu.open) { close(); menu.querySelector('summary').focus(); }
  });
  document.addEventListener('pointerdown', function (e) { if (!menu.contains(e.target)) close(); });
  menu.addEventListener('click', function (e) { if (e.target.closest('a')) close(); });
})();
