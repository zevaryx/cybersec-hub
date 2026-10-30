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

  // --------------------------------------------------------------------------- easter eggs
  // Every talk hides a few. Ideas: jokes for special inputs, a console message, a reward for finishing a demo.
  function consoleHint() {
    console.log("%c" + document.title, "font: 700 24px monospace; color: #ff2e88; text-shadow: 0 0 8px #ff2e88");
    console.log("%cA hint for the curious goes here.", "font: 14px monospace; color: #00f0ff");
  }

  function start() {
    consoleHint();
    $("demo-in").addEventListener("input", hash);
    hash();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
})();
