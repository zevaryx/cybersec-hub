/* app.js - the live demos for "Cyber in the News: Black October". Shared maths: ../../shared/crypto.js (window.Lab).
   The signing demo uses real P-256 ECDSA and the hash pin uses real SHA-256. */
(function () {
  "use strict";
  const L = window.Lab;

  // --------------------------------------------------------------------------- helpers
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const sp = (cls, s) => `<span class="${cls}">${esc(s)}</span>`;
  const short = (x) => { const h = x.toString(16).padStart(64, "0"); return h.slice(0, 12) + "…" + h.slice(-6); };
  function bind(ids, fn) { for (const id of [].concat(ids)) $(id).addEventListener("input", fn); fn(); }
  function click(id, fn) { $(id).addEventListener("click", fn); }

  // --------------------------------------------------------------------------- title: bingo
  const SQUARES = ["CVSS 10.0", "Emergency patch", "Supply chain", "CA distrusted",
    "We don't even use PHP", "It was in a container", "AI found it", "They wanted your AI keys",
    "A 2Shell domain", "New all-time record", "Restart required", "Preliminary report",
    "Lookalike name", "Not enough randomness", "Rotate everything", "Known exploited"];
  const LINES = [];
  for (let i = 0; i < 4; i++) { LINES.push([0, 1, 2, 3].map((j) => i * 4 + j)); LINES.push([0, 1, 2, 3].map((j) => j * 4 + i)); }
  LINES.push([0, 5, 10, 15], [3, 6, 9, 12]);
  let bingoLines = 0;

  function bingo() {
    const box = $("bingo");
    box.innerHTML = SQUARES.map((s, i) => `<button type="button" aria-pressed="false" data-i="${i}">${esc(s)}</button>`).join("");
    box.addEventListener("click", (e) => {
      const b = e.target.closest("button");
      if (!b) return;
      b.setAttribute("aria-pressed", b.getAttribute("aria-pressed") === "true" ? "false" : "true");
      const on = [...box.children].map((x) => x.getAttribute("aria-pressed") === "true");
      const lines = LINES.filter((l) => l.every((i) => on[i])).length;
      const note = $("bingo-note");
      if (on.every(Boolean)) { note.textContent = "# FULL CARD. You have survived Black October. Go patch something."; box.classList.add("won"); }
      else if (lines > bingoLines) { note.textContent = "# BLACK OCTOBER! (shout it)"; box.classList.remove("won"); void box.offsetWidth; box.classList.add("won"); }
      else if (lines) note.textContent = `# ${lines} line${lines > 1 ? "s" : ""}. Keep going.`;
      else { note.textContent = '# tick a square when it comes up. Get a line? Shout "Black October!"'; box.classList.remove("won"); }
      bingoLines = lines;
    });
  }

  // --------------------------------------------------------------------------- Binance: sign what you're told
  let sigKey = null;
  const HIJACK = "withdraw ALL hot wallet funds to 0xA77ACKER";
  function sign(msg) {
    if (!sigKey) { const d = L.randBelow(L.P256.n - 1n) + 1n; sigKey = { d, Q: L.P256.mul(d) }; }
    const k = L.randBelow(L.P256.n - 1n) + 1n;
    return L.ecdsaSign(sigKey.d, L.hashInt(msg), k);
  }
  let lastSigned = null;
  function sigRun() {
    const msg = $("sig-msg").value;
    const sig = sign(msg);
    const ok = L.ecdsaVerify(sigKey.Q, L.hashInt(msg), sig);
    let out = `${sp("k", "wallet key")} P-256, private part stays in the signing system\n` +
      `${sp("k", "message")}    ${esc(msg)}\n${sp("k", "signature")}  r=${short(sig[0])}  s=${short(sig[1])}\n` +
      `${sp("k", "verifies?")}  ${ok ? sp("ok", "yes: the key approved exactly this message") : sp("bad", "no")}`;
    if (lastSigned && lastSigned.msg !== msg) {
      const old = L.ecdsaVerify(sigKey.Q, L.hashInt(msg), lastSigned.sig);
      out += `\n\n${sp("m", "the previous signature, checked against this message:")} ${old ? sp("bad", "verifies?!") : sp("ok", "doesn't verify")}` +
        `\n${sp("m", "signatures bind the exact message. So attackers don't change it after signing: they change it before.")}`;
    }
    const t = msg.toLowerCase();
    if (/\b(everything|all)\b/.test(t) && /\b(me|my|myself)\b/.test(t))
      out += `\n\n${sp("y", "Signed. Verified. Approved by nobody. That's the whole problem.")}`;
    $("sig-out").innerHTML = out;
    lastSigned = { msg, sig };
  }

  // --------------------------------------------------------------------------- eMudhra: randomness → guesses
  const UNIVERSE = 4.35e17;                         // the universe's age, in seconds
  function dur(s) {
    if (s < 1e-3) return "instantly";
    if (s < 60) return `${s.toPrecision(2)} seconds`;
    if (s < 3600) return `${(s / 60).toPrecision(2)} minutes`;
    if (s < 86400) return `${(s / 3600).toPrecision(2)} hours`;
    if (s < 3.15e7) return `${(s / 86400).toPrecision(2)} days`;
    if (s < UNIVERSE) return `${(s / 3.15e7).toPrecision(2)} years`;
    return `${(s / UNIVERSE).toPrecision(2)}× the age of the universe`;
  }
  function rnd() {
    const b = +$("rnd-bits").value;
    $("rnd-bits-out").textContent = b;
    const keys = Math.pow(2, b), laptop = keys / 2 / 1e9, farm = keys / 2 / 1e15;
    let out = `${sp("k", "possible keys")}    2^${b} ${b <= 32 ? "= " + keys.toLocaleString("en-US") : ""}\n` +
      `${sp("k", "laptop")}           ${dur(laptop)}  ${sp("m", "(a billion guesses a second, on average half the keys)")}\n` +
      `${sp("k", "huge GPU farm")}    ${dur(farm)}  ${sp("m", "(a million billion a second)")}\n\n`;
    if (b >= 128) out += sp("ok", "Safe: no one is guessing this, ever.");
    else if (b >= 80) out += sp("y", "Safe today against almost anyone. Not the margin you want for a CA.");
    else if (b >= 48) out += sp("bad", "Within reach of a well-funded attacker. A CA key must never be here.");
    else out += sp("bad", "Broken. Anyone with a laptop can find the key, and sign as you.");
    if (b === 4) out += `\n\n${sp("y", "16 possible keys. You could guess this one on your fingers. The 12 days of cybermas would approve.")}`;
    $("rnd-out").innerHTML = out;
  }

  // --------------------------------------------------------------------------- PHP: would the scan catch it?
  function scanQuiz() {
    const cards = [...$("scan-quiz").querySelectorAll("details")];
    const upd = () => {
      const n = cards.filter((d) => d.open).length;
      $("scan-score").textContent = n === cards.length ? "# 3 out of 3 missed. That's the myth of the month, early." : n ? `# ${n} of 3 revealed` : "";
    };
    cards.forEach((d) => d.addEventListener("toggle", upd));
  }

  // --------------------------------------------------------------------------- GitLab and Ruby: a pattern is code
  const ISSUES = ["Release v1.2 notes", "Typo in the v1x2 tag", "Upgrade to v1.20", "Roll back v1-2 hotfix", "Docs for v2.1"];
  const rxEscape = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  function rx() {
    const raw = $("rx-in").value.slice(0, 40);
    let asPattern, err = "";
    try { const r = new RegExp(raw, "i"); asPattern = ISSUES.filter((t) => r.test(t)); } catch (e) { asPattern = null; err = e.message; }
    const lit = new RegExp(rxEscape(raw), "i"), asText = ISSUES.filter((t) => lit.test(t));
    const list = (a) => (a.length ? a.map((t) => "  " + esc(t)).join("\n") : sp("m", "  (no matches)"));
    let out = `${sp("k", "as a pattern")} ${sp("m", "(the input is compiled: code)")}\n` +
      (asPattern ? list(asPattern) : sp("bad", "  the compiler rejected it: " + err) + `\n  ${sp("m", "compiling user input is exactly where Ruby's bugs lived")}`) +
      `\n\n${sp("k", "as text")} ${sp("m", "(escaped first: data)")}\n${list(asText)}`;
    if (asPattern && asPattern.length === ISSUES.length && raw.length && asText.length < ISSUES.length)
      out += `\n\n${sp("y", "A pattern that matches everything. Users writing code: what could go wrong?")}`;
    $("rx-out").innerHTML = out;
  }

  // --------------------------------------------------------------------------- Brotli: name your own bug
  function nick() {
    const w = $("nick-in").value.trim().replace(/[^\p{L}\p{N}-]/gu, "").slice(0, 24);
    if (!w) { $("nick-out").innerHTML = sp("m", "type a word"); return; }
    const name = w[0].toUpperCase() + w.slice(1).toLowerCase() + "2Shell";
    let out = `${sp("k", "bug name")}   ${sp("y", name)}\n${sp("k", "domain")}     ${esc(w.toLowerCase())}2shell.com\n` +
      `${sp("k", "logo")}       pending\n${sp("k", "CVE")}        still the real name`;
    if (w.toLowerCase() === "broccoli")
      out += `\n\n${sp("ok", "Taken. \"Node2Shell is a terrible name. I'm calling it Broccoli.\" (Juliano Rizzo)")}`;
    else if (w.toLowerCase() === "node" || w.toLowerCase() === "http" || w.toLowerCase() === "php")
      out += `\n\n${sp("bad", "Taken this month. Try a vegetable.")}`;
    $("nick-out").innerHTML = out;
  }

  // --------------------------------------------------------------------------- LiteLLM: lookalike and hash pin
  function lookalike() {
    $("look").addEventListener("click", (e) => {
      const b = e.target.closest("button");
      if (!b) return;
      for (const x of $("look").children) x.classList.remove("right", "wrong");
      const real = b.dataset.real === "1";
      b.classList.add(real ? "right" : "wrong");
      $("look-out").textContent = real
        ? "# Right: BerriAI. The attacker's fork was Berri-AI. One hyphen."
        : "# That's the lookalike. One hyphen was enough to fool a release workflow.";
    });
  }
  const PIN_TEXT = "litellm-1.106.2: the release you tested";
  let pinHash = null;
  function pin() {
    if (!pinHash) pinHash = L.sha256(L.utf8(PIN_TEXT));
    const got = L.sha256(L.utf8($("pin-in").value)), same = L.equalBytes(got, pinHash);
    let out = `${sp("k", "lock file")}   sha256:${L.hex(pinHash).slice(0, 32)}…\n${sp("k", "downloaded")}  sha256:${L.hex(got).slice(0, 32)}…\n\n`;
    out += same
      ? sp("ok", "pip: hashes match, installing")
      : `${sp("bad", "pip: ERROR: THESE PACKAGES DO NOT MATCH THE HASHES FROM THE REQUIREMENTS FILE")}\n${sp("m", `${L.bitDiff(got, pinHash)} of 256 bits differ. Install stopped.`)}`;
    if (/1\.107\.0/.test($("pin-in").value)) out += `\n\n${sp("y", "1.107.0, refused at the door. This is the good ending.")}`;
    $("pin-out").innerHTML = out;
  }

  // --------------------------------------------------------------------------- easter eggs
  function consoleHint() {
    console.log("%cBlack October", "font: 700 24px monospace; color: #ff2e88; text-shadow: 0 0 8px #ff2e88");
    console.log("%cYou opened the console. Check your sources too: every story slide lists them at the bottom.", "font: 14px monospace; color: #00f0ff");
    console.log("%cTry: the 4-bit key, \"broccoli\", and signing \"send everything to me\".", "font: 12px monospace; color: #f6e94b");
  }

  function start() {
    consoleHint();
    bingo();
    click("sig-go", sigRun);
    click("sig-evil", () => { $("sig-msg").value = HIJACK; sigRun(); });
    sigRun();
    bind("rnd-bits", rnd);
    scanQuiz();
    bind("rx-in", rx);
    bind("nick-in", nick);
    lookalike();
    bind("pin-in", pin);
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
})();
