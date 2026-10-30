/* app.js - this talk's live demos. The shared crypto maths is in ../../shared/crypto.js (window.Lab). */
(function () {
  "use strict";
  const L = window.Lab;
  const $ = (id) => document.getElementById(id);

  // --------------------------------------------------------------------------- title slide demo
  function hash() {
    const el = $("demo-in");
    el.style.width = Math.max(4, el.value.length + 1) + "ch";
    $("demo-out").textContent = L.hex(L.sha256(L.utf8(el.value)));
  }

  function start() {
    $("demo-in").addEventListener("input", hash);
    hash();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
})();
