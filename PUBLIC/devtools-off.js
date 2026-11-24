// devtools-off.js — MAX SHOP
// Keyboard/right-click block + console nuke.
// The debugger-trap and size-check have been removed: they don't stop determined
// attackers and cause false positives on legitimate users (screen readers, docked
// toolbars, accessibility tools). What stays is cheap and doesn't hurt real users.
(function () {
  'use strict';

  // ── 1. Keyboard shortcut + right-click block ──────────────────────────────
  document.addEventListener('keydown', function (e) {
    if (e.key === 'F12' || e.keyCode === 123) {
      e.preventDefault(); e.stopImmediatePropagation(); return false;
    }
    if ((e.ctrlKey || e.metaKey) && e.shiftKey &&
        ['I','J','C','K'].includes(e.key.toUpperCase())) {
      e.preventDefault(); e.stopImmediatePropagation(); return false;
    }
    if (e.metaKey && e.altKey && e.key.toUpperCase() === 'I') {
      e.preventDefault(); e.stopImmediatePropagation(); return false;
    }
    if ((e.ctrlKey || e.metaKey) && e.key.toUpperCase() === 'U') {
      e.preventDefault(); e.stopImmediatePropagation(); return false;
    }
  }, true);

  document.addEventListener('contextmenu', function (e) {
    e.preventDefault(); e.stopImmediatePropagation(); return false;
  }, true);

  // ── 2. Console method nuke ────────────────────────────────────────────────
  try {
    var noop = function () {};
    var methods = [
      'assert','clear','count','countReset','debug','dir','dirxml','error',
      'group','groupCollapsed','groupEnd','info','log','profile','profileEnd',
      'table','time','timeEnd','timeLog','timeStamp','trace','warn'
    ];
    var con = window.console;
    methods.forEach(function (m) { try { con[m] = noop; } catch (_) {} });
    try { Object.freeze(con); } catch (_) {}
  } catch (_) {}

  // ── 3. toString poisoning ─────────────────────────────────────────────────
  try {
    var _real = Function.prototype.toString;
    Function.prototype.toString = function () {
      if (this === Function.prototype.toString) return _real.call(_real);
      return 'function () { [native code] }';
    };
  } catch (_) {}

})();