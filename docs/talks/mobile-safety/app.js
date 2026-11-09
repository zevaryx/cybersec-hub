/* app.js - the live demos for "Your Phone, Safely".
   Everything here is a simulation in your browser: no passcode is stored or sent, and nothing you type leaves the page. */
(function () {
  "use strict";

  // --------------------------------------------------------------------------- helpers
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const sp = (cls, s) => `<span class="${cls}">${esc(s)}</span>`;
  function click(id, fn) { $(id).addEventListener("click", fn); }
  function store(key, val) {
    try { if (val === undefined) return localStorage.getItem(key); localStorage.setItem(key, val); } catch (e) {}
    return null;
  }
  function press(group, attr, value) {
    for (const b of group.querySelectorAll("button")) b.setAttribute("aria-pressed", String(b.getAttribute(attr) === value));
  }

  // --------------------------------------------------------------------------- passcode analysis (shared by the title terminal and the estimator)
  // Top 20 four-digit codes from DataGenetics' 2012 analysis of ~3.4 million leaked four-digit passwords.
  const TOP20 = ["1234", "1111", "0000", "1212", "7777", "1004", "2000", "4444", "2222", "6969",
    "9999", "3333", "5555", "6666", "1122", "1313", "8888", "4321", "2001", "1010"];
  const WORDS = ["password", "passw0rd", "qwerty", "qwertyuiop", "letmein", "iloveyou", "abc123", "abcdef", "admin", "welcome", "monkey", "dragon", "123abc"];
  // Guesses before the phone stops accepting more (see the slide's sources).
  const LIMITS = { ios: { n: 10, name: "iPhone", after: "After 10 wrong guesses it locks and needs a computer, or erases itself if Erase Data is on." },
    android: { n: 20, name: "Android 16 QPR2+", after: "After 20 it accepts no more guesses; other Android phones vary by maker." } };
  const TRY_SECONDS = 0.08; // Apple tunes each on-device passcode attempt to take about 80 ms

  function pattern(s) {
    if (/^(.)\1+$/.test(s)) return "the same character repeated";
    if (/^\d+$/.test(s)) {
      let up = true, down = true;
      for (let i = 1; i < s.length; i++) {
        if ((+s[i - 1] + 1) % 10 !== +s[i]) up = false;
        if ((+s[i - 1] + 9) % 10 !== +s[i]) down = false;
      }
      if (s.length >= 4 && (up || down)) return "a straight run of digits";
      if (s.length === 4 && /^(19|20)\d\d$/.test(s)) return "a year (birth years are a favourite guess)";
      if (/^(\d\d)\1+$/.test(s) || /^(\d\d\d)\1+$/.test(s)) return "a repeating pattern";
      if (/^(\d)\1(\d)\2(\d)\3$/.test(s)) return "pairs of repeated digits";
    }
    if (WORDS.includes(s.toLowerCase())) return "one of the most common passwords";
    return "";
  }

  function analyze(code) {
    const s = String(code);
    const len = [...s].length;
    let pool = 0;
    if (/\d/.test(s)) pool += 10;
    if (/[a-z]/.test(s)) pool += 26;
    if (/[A-Z]/.test(s)) pool += 26;
    if (/[^a-zA-Z0-9]/.test(s)) pool += 33;
    const log10 = len && pool ? len * Math.log10(pool) : 0;
    const rank = TOP20.indexOf(s);
    const pat = rank >= 0 ? "" : pattern(s);
    return { s, len, pool, log10, rank, pat, popular: rank >= 0 || !!pat, digits: /^\d+$/.test(s) };
  }

  function fmtBig(log10) {
    if (log10 < 15) return Math.round(10 ** log10).toLocaleString("en-US");
    const e = Math.floor(log10), m = 10 ** (log10 - e);
    return `${m.toFixed(1)} × 10^${e}`;
  }
  function fmtTime(sec) {
    if (!isFinite(sec) || sec > 4.4e17) return "longer than the age of the universe";
    const units = [["year", 31557600], ["day", 86400], ["hour", 3600], ["minute", 60], ["second", 1]];
    for (const [u, n] of units) if (sec >= n) {
      const v = sec / n;
      const t = v >= 1e6 ? fmtBig(Math.log10(v)) : v >= 100 ? Math.round(v).toLocaleString("en-US") : v.toFixed(v < 10 ? 1 : 0);
      return `${t} ${u}${t === "1" || t === "1.0" ? "" : "s"}`;
    }
    return "under a second";
  }
  // chance that a guesser trying codes in a sensible order gets in within the allowed guesses
  function chance(a, n) {
    if (a.rank >= 0 && a.rank < n) return { text: "very high", bad: true, why: `it's #${a.rank + 1} on the most-used list` };
    if (a.popular) return { text: "high", bad: true, why: `it's ${a.pat}` };
    const lg = Math.log10(n) - a.log10;
    if (lg >= 0) return { text: "certain", bad: true, why: "there are fewer codes than allowed guesses" };
    const oneIn = 10 ** -lg;
    return { text: oneIn < 1e15 ? "1 in " + Math.round(oneIn).toLocaleString("en-US") : "1 in " + fmtBig(-lg), bad: oneIn < 1000, why: "a random code: every guess is a long shot" };
  }

  // --------------------------------------------------------------------------- title: how guessable?
  function hero() {
    const el = $("hero-in"), v = el.value;
    el.style.width = Math.max(6, [...v].length + 1) + "ch";
    const out = $("hero-out"), note = $("hero-note");
    const t = v.trim().toLowerCase();
    if (!v) {
      out.innerHTML = `${sp("k", "possible codes:")} ${sp("bad", "1 (no passcode)")}`;
      note.textContent = "# no passcode, no lock worth the name. Setting one is what switches on the phone's data protection.";
      return;
    }
    if (t === "*#06#") { out.innerHTML = `${sp("k", "type:")} ${sp("ok", "dial code")}`; note.textContent = "# not a passcode: dial it to show your phone's IMEI. Worth writing down somewhere safe, before you need it."; return; }
    if (t === "911" || t === "112" || t === "999") { out.innerHTML = `${sp("k", "type:")} ${sp("ok", "emergency number")}`; note.textContent = "# emergency calls work from a locked phone, no passcode needed. That one's a feature."; return; }
    const a = analyze(v), c = chance(a, LIMITS.ios.n);
    out.innerHTML = `${sp("k", "possible codes:")} ${sp("y", fmtBig(a.log10))}<br>${sp("k", "popular or patterned:")} ${a.popular ? sp("bad", a.rank >= 0 ? "yes, #" + (a.rank + 1) : "yes") : sp("ok", "no")}<br>${sp("k", "odds in 10 guesses:")} ${c.bad ? sp("bad", c.text) : sp("ok", c.text)}`;
    let n = a.popular ? `# ${c.why}. A guesser tries these first.` : a.len < 6 && a.digits ? "# not on the popular list. Six random digits or more is better." : "# a guesser with ten tries is out of luck.";
    if (t === "8068") n = "# the rarest code in the 2012 study: 25 times in 3.4 million. A little less rare now that a whole room has seen it.";
    else if (t === "correct horse battery staple") n = "# a famous passphrase. Long is great; famous, less so. Pick four words of your own.";
    else if (t === "1234") n = "# the most popular four-digit code in a 2012 study: almost 11% of them. The first guess, every time.";
    note.textContent = n;
  }

  // --------------------------------------------------------------------------- the estimator slide
  let phone = "ios";
  function randomCode(kind) {
    const sets = { "6d": ["0123456789", 6], "6a": ["abcdefghijklmnopqrstuvwxyz0123456789", 6], "10A": ["abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789", 10] };
    const [chars, n] = sets[kind];
    const r = new Uint32Array(n); crypto.getRandomValues(r);
    return Array.from(r, (x) => chars[x % chars.length]).join("");
  }
  function estimate() {
    const v = $("pc-in").value, lim = LIMITS[phone];
    const stats = $("pc-stats"), note = $("pc-note");
    if (!v) { stats.innerHTML = ""; note.textContent = "# type a made-up code. No passcode at all means anyone can open it."; return; }
    const a = analyze(v), c = chance(a, lim.n);
    stats.innerHTML =
      `<div class="stat"><b>${esc(fmtBig(a.log10))}</b><span>possible codes (${a.pool} characters, ${a.len} long)</span></div>` +
      `<div class="stat"><b>${lim.n}</b><span>guesses allowed on ${esc(lim.name)}</span></div>` +
      `<div class="stat${c.bad ? " stat-bad" : " stat-ok"}"><b>${esc(c.text)}</b><span>chance a guesser gets in</span></div>`;
    note.textContent = `# ${c.why[0].toUpperCase() + c.why.slice(1)}. ${lim.after} If someone could skip the limits entirely, trying every code at ~80 ms each would take ${fmtTime(10 ** a.log10 * TRY_SECONDS)}.`;
  }

  // --------------------------------------------------------------------------- before first unlock
  const FILES = 12;
  const OPEN = { off: 1, locked: 9, open: 12 };
  function bfu(state) {
    press($("bfu-pick"), "data-s", state);
    const grid = $("bfu-files");
    grid.innerHTML = Array.from({ length: FILES }, (_, i) => `<i class="${i < OPEN[state] ? "open" : ""}" title="${i < OPEN[state] ? "readable" : "encrypted"}"></i>`).join("");
    for (const d of document.querySelectorAll("#bfu .bfu-state")) d.classList.toggle("on", d.dataset.s === state);
    $("bfu-cap").textContent = state === "off" ? "Almost everything is locked away until the passcode is typed."
      : state === "locked" ? "Most keys stay in memory so the phone keeps working; the most sensitive data is locked again."
      : "Everything is readable to whoever is holding it.";
  }

  // --------------------------------------------------------------------------- lock-screen previews
  const PREVIEW = { "ls-code": "Your code is 482 913. Don't share it.", "ls-mail": "Door code for Friday is 4471#", "ls-cal": "Hospital appointment, 3 pm" };
  function previews() {
    const b = $("ls-toggle"), on = b.getAttribute("aria-pressed") !== "true";
    b.setAttribute("aria-pressed", String(on));
    b.textContent = on ? "Show previews again" : "Hide previews when locked";
    for (const [id, txt] of Object.entries(PREVIEW)) { $(id).textContent = on ? "Notification" : txt; $(id).classList.toggle("hidden-prev", on); }
  }

  // --------------------------------------------------------------------------- permission audit
  const PERMS = [
    { k: "light", name: "Turn on the flashlight", need: true, why: "That's the whole job." },
    { k: "loc", name: "Precise location, always", need: false, why: "A torch doesn't care where you are. Advertisers do." },
    { k: "contacts", name: "All your contacts", need: false, why: "Nothing to do with light, and it's other people's data too." },
    { k: "mic", name: "Microphone", need: false, why: "Even a \"clap to switch on\" trick isn't worth a listening torch." },
    { k: "camera", name: "Camera", need: false, why: "Lighting up isn't taking pictures. Android, for one, lets apps turn on the torch without opening the camera." },
    { k: "photos", name: "All your photos", need: false, why: "Nothing a torch does involves your photo library." },
    { k: "track", name: "Track you across other apps and sites", need: false, why: "An advertising request, not a torch feature." },
    { k: "notify", name: "Send notifications", need: null, why: "Harmless, but a torch rarely has anything to say except ads." },
  ];
  const choice = {};
  function auditDraw(checked) {
    $("pa-list").innerHTML = PERMS.map((p) => {
      const c = choice[p.k];
      const state = c === undefined ? "?" : c ? "Allow" : "Deny";
      let mark = "";
      if (checked && c !== undefined && p.need !== null) mark = (c === p.need) ? " ok" : " bad";
      return `<li><button type="button" class="perm${c === true ? " allow" : c === false ? " deny" : ""}${mark}" data-k="${p.k}" aria-pressed="${c === true}"><span>${esc(p.name)}</span><b>${state}</b></button></li>`;
    }).join("");
    const why = $("pa-why");
    why.hidden = !checked;
    why.innerHTML = checked ? PERMS.map((p) => `<li class="${p.need === null ? "meh" : p.need ? "ok" : "bad"}"><b>${p.need === null ? "Optional" : p.need ? "Needs it" : "Deny"}</b><span>${esc(p.why)}</span></li>`).join("") : "";
  }
  function auditToggle(k) {
    choice[k] = choice[k] === undefined ? true : !choice[k];
    auditDraw(false);
    $("pa-note").textContent = "Tap each permission to allow or deny it, then check your answers.";
  }
  function auditCheck() {
    const scored = PERMS.filter((p) => p.need !== null);
    const answered = PERMS.filter((p) => choice[p.k] !== undefined).length;
    const right = scored.filter((p) => choice[p.k] === p.need).length;
    const all = PERMS.every((p) => choice[p.k] === true), none = PERMS.every((p) => choice[p.k] === false);
    auditDraw(true);
    let n;
    if (answered === 0) n = "# nothing chosen yet. Tap a permission to allow or deny it.";
    else if (all) n = "# you allowed everything. The torch now knows where you are, who you know and what you sound like. It still can't find your keys.";
    else if (none) n = "# you denied everything, including the light. Very private, very dark.";
    else if (right === scored.length) n = `# ${right} of ${scored.length}: the only thing a torch needs is the light. Perfect.`;
    else n = `# ${right} of ${scored.length}. The test is always the same: does it need this to do the job I installed it for?`;
    $("pa-note").textContent = n;
  }
  function builtin() {
    for (const p of PERMS) delete choice[p.k];
    auditDraw(false);
    $("pa-note").textContent = "# the best torch app is the one already in Control Center or Quick Settings: no permissions to give, and no ads.";
  }

  // --------------------------------------------------------------------------- update prompt
  let snoozes = 0;
  function later() {
    snoozes++;
    $("upd-note").textContent = snoozes === 1 ? "# reminder set for tomorrow."
      : snoozes === 2 ? "# tomorrow it is. Again."
      : "# tomorrow is a very popular day for updates. Attackers are fans of it too.";
  }
  function now() {
    $("upd-note").textContent = snoozes >= 3 ? "# there it is. It installs tonight while the phone charges, and your future self says thanks."
      : "# scheduled for tonight while it charges. You won't even notice.";
    $("upd-note").classList.add("ok");
  }

  // --------------------------------------------------------------------------- real risk or myth?
  const MYTHS = [
    { c: "Anyone on café Wi-Fi can read my online banking.", a: "myth", v: "Mostly myth today",
      why: "Banking apps and almost all websites encrypt the connection, so others on the network see scrambled data. The US FTC now calls public Wi-Fi \"usually safe\". The real risk is a fake Wi-Fi sign-in page that asks for your email or social media password." },
    { c: "A public USB charging port could attack my phone.", a: "real", v: "Real, but rare",
      why: "Researchers showed it in 2025 (\"ChoiceJacking\"), and Apple and Google added stronger checks. Documented real-world attacks are hard to find. The easy fix: your own plug or power bank." },
    { c: "A website pop-up says my phone has a virus, so I should install its cleaner app.", a: "myth", v: "Myth, and a scam",
      why: "A web page can't scan your phone. Those pop-ups are ads or scams. Close the tab, and don't install anything it suggests." },
    { c: "Someone can read my messages from the lock screen without unlocking the phone.", a: "real", v: "Real, on many phones",
      why: "Message previews often show on the lock screen by default. Set them to show only when unlocked (part 1)." },
  ];
  let mi = 0, mscore = 0, mdone = false;
  function mythShow() {
    const m = MYTHS[mi];
    $("mq-count").textContent = `Claim ${mi + 1} of ${MYTHS.length}`;
    $("mq-claim").textContent = m.c;
    $("mq-verdict").hidden = true; $("mq-next").hidden = true; $("mq-why").textContent = "";
    for (const b of $("mq-btns").querySelectorAll("[data-a]")) { b.disabled = false; b.hidden = false; }
    mdone = false;
  }
  function mythAnswer(a) {
    if (mdone) return; mdone = true;
    const m = MYTHS[mi], ok = a === m.a;
    if (ok) mscore++;
    for (const b of $("mq-btns").querySelectorAll("[data-a]")) b.disabled = true;
    const v = $("mq-verdict"); v.hidden = false;
    v.className = "verdict " + (ok ? "ok" : "bad");
    v.textContent = (ok ? "Right: " : "Not quite: ") + m.v + ".";
    $("mq-why").textContent = m.why;
    $("mq-score").textContent = `Score: ${mscore} / ${mi + 1}`;
    $("mq-next").hidden = false;
    $("mq-next").textContent = mi === MYTHS.length - 1 ? "See score" : "Next ›";
  }
  function mythNext() {
    if (mi < MYTHS.length - 1) { mi++; mythShow(); return; }
    const n = MYTHS.length;
    let s = `Final score: ${mscore} / ${n}.`;
    if (mscore === n) s += " # all four. You could give this slide yourself.";
    else if (mscore === 0) s += " # zero, which means the scary headlines did their job. Now you know which ones to drop.";
    else s += " # the pattern: yesterday's scary stories fade, and fake pages and fake alerts are today's everyday risk.";
    $("mq-score").textContent = s;
    $("mq-claim").textContent = "That's all four.";
    $("mq-count").textContent = ""; $("mq-verdict").hidden = true; $("mq-why").textContent = "";
    for (const b of $("mq-btns").querySelectorAll("[data-a]")) b.hidden = true;
    $("mq-next").textContent = "Play again";
    $("mq-next").onclick = () => { mi = 0; mscore = 0; $("mq-next").onclick = null; $("mq-score").textContent = ""; mythShow(); };
  }

  // --------------------------------------------------------------------------- lost-phone checklist (kept in this browser only)
  const LP_KEY = "mobile-safety-lost-phone";
  function checklist() {
    const boxes = Array.from(document.querySelectorAll("#lp-plan input[type=checkbox]"));
    let saved = {};
    try { saved = JSON.parse(store(LP_KEY) || "{}"); } catch (e) {}
    boxes.forEach((b) => { b.checked = !!saved[b.dataset.k]; });
    const update = () => {
      const done = boxes.filter((b) => b.checked).length;
      store(LP_KEY, JSON.stringify(Object.fromEntries(boxes.map((b) => [b.dataset.k, b.checked]))));
      const note = $("lp-note"); note.className = "comment";
      if (done === boxes.length) { note.textContent = "# all twelve. Your future self, patting an empty pocket in a taxi queue, says thank you."; note.classList.add("ok"); }
      else if (done === 0) note.textContent = "# tick them off on your own phone as we go. They're saved in this browser only.";
      else note.textContent = `# ${done} of ${boxes.length} done. Anything left is your homework for tonight.`;
    };
    boxes.forEach((b) => b.addEventListener("change", update));
    update();
  }

  // --------------------------------------------------------------------------- console hint
  function consoleHint() {
    console.log("%cYour Phone, Safely", "font: 700 24px monospace; color: #ff2e88; text-shadow: 0 0 8px #ff2e88");
    console.log("%cYou opened the developer console on a talk about phones. Bonus tip: dial *#06# on your phone and write down the number it shows. Then try *#06# in the title terminal.", "font: 14px monospace; color: #00f0ff");
  }

  function start() {
    consoleHint();
    $("hero-in").addEventListener("input", hero); hero();
    $("pc-in").addEventListener("input", estimate);
    for (const b of $("pc-presets").querySelectorAll("button")) b.addEventListener("click", () => { $("pc-in").value = b.dataset.v || randomCode(b.dataset.rand); estimate(); });
    for (const b of $("pc-phone").querySelectorAll("button")) b.addEventListener("click", () => { phone = b.dataset.p; press($("pc-phone"), "data-p", phone); estimate(); });
    estimate();
    for (const b of $("bfu-pick").querySelectorAll("button")) b.addEventListener("click", () => bfu(b.dataset.s));
    bfu("off");
    click("ls-toggle", previews);
    $("pa-list").addEventListener("click", (e) => { const b = e.target.closest("[data-k]"); if (b) auditToggle(b.dataset.k); });
    click("pa-check", auditCheck); click("pa-builtin", builtin);
    click("pa-reveal", () => { $("pa-real").hidden = false; $("pa-reveal").hidden = true; });
    auditDraw(false);
    click("upd-later", later); click("upd-now", now);
    for (const b of $("mq-btns").querySelectorAll("[data-a]")) b.addEventListener("click", () => mythAnswer(b.dataset.a));
    $("mq-next").addEventListener("click", () => { if (!$("mq-next").onclick) mythNext(); });
    mythShow();
    checklist();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
})();
