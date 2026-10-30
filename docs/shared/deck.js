/* deck.js - turns the page into a slide deck: one slide at a time, arrows, notes, overview,
   a synced presenter window, and a scroll view for phones. Shared by every talk in the hub.

   Each talk describes itself in a JSON block in its page:
   <script type="application/json" id="deck-config">
     { "id": "crypto-101", "title": "Crypto 101", "footer": "CRYPTOGRAPHY", "subtitle": "A BEGINNER'S GUIDE",
       "parts": [{ "name": "Foundations", "minutes": 25 }, ...] }
   </script>
   Slides use data-part="N" (0 = intro/outro, 1.. = the parts above) and data-num for the footer number. */
(function () {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const root = document.documentElement;
  const slides = [...document.querySelectorAll(".slide")];
  const STAGE_W = 1440, STAGE_H = 810;
  const CFG = (() => { try { return JSON.parse($("deck-config").textContent); } catch (e) { return {}; } })();
  const PARTS = ["Introduction"].concat((CFG.parts || []).map((p) => p.name));
  const PART_MIN = [0].concat((CFG.parts || []).map((p) => p.minutes || 0));
  const TALK_ID = CFG.id || "talk", TALK_TITLE = CFG.title || document.title;
  const store = {
    get(k) { try { return localStorage.getItem(k); } catch (e) { return null; } },
    set(k, v) { try { localStorage.setItem(k, v); } catch (e) { /* storage blocked: fine */ } },
  };
  const chan = "BroadcastChannel" in window ? new BroadcastChannel(`deck-${TALK_ID}`) : null;
  let cur = 0;

  const mode = () => (root.classList.contains("mode-presenter") ? "presenter" : root.classList.contains("mode-scroll") ? "scroll" : "slides");
  const indexOf = (id) => Math.max(0, slides.findIndex((s) => s.id === id));
  const titleOf = (s) => (s.querySelector("h2, h1") || {}).textContent || s.id;
  const skip = (s) => (s && s.dataset.skip ? " · SKIPPABLE" : "");
  const notesOf = (s) => (s.querySelector(".notes") || {}).innerHTML || "<p>No notes for this slide.</p>";   // our own static markup

  // ---------------------------------------------------------------------------- slide furniture
  slides.forEach((s, i) => {
    const part = +s.dataset.part;
    s.setAttribute("aria-roledescription", "slide");
    s.setAttribute("aria-label", `${i + 1} of ${slides.length}: ${titleOf(s).trim()}`);
    const foot = document.createElement("footer");
    foot.className = "slide-foot";
    foot.innerHTML = `<b>${s.dataset.num}</b><span>${CFG.footer || ""}</span><span>${part ? `PART ${part} · ${PARTS[part].toUpperCase()}` : s.dataset.label || CFG.subtitle || ""}</span>`;
    s.append(foot);
  });

  // ---------------------------------------------------------------------------- layout
  function fit() {
    const s = Math.min(innerWidth / STAGE_W, innerHeight / STAGE_H);
    root.style.setProperty("--scale", s.toFixed(4));
  }
  function setMode(m, save) {
    root.classList.remove("mode-slides", "mode-scroll");
    root.classList.add("mode-" + m);
    if (save) store.set("deck-mode", m);
    if (m === "slides") { fit(); show(cur, false); }
    else { cpFollow(slides[cur]); requestAnimationFrame(() => slides[cur].scrollIntoView({ block: "start" })); }
  }

  // ---------------------------------------------------------------------------- checkpoint timers
  // Each checkpoint slide has a 5-minute countdown. In slide mode it starts when the slide appears
  // and resets when you leave; clicking it pauses or resumes (or starts it, in scroll view).
  const CP_SECONDS = 300, CP_LOW = 30, RING = 2 * Math.PI * 54;
  const timers = [...document.querySelectorAll(".cp-timer")].map((el) => ({ el, left: CP_SECONDS * 1000, end: 0, tick: 0 }));
  const mmss = (secs) => `${String(Math.floor(secs / 60)).padStart(2, "0")}:${String(secs % 60).padStart(2, "0")}`;
  const cpHere = () => timers.find((t) => slides[cur].contains(t.el));
  const cpState = (t) => (t.el.classList.contains("done") ? "done" : t.tick ? "running" : t.el.classList.contains("paused") ? "paused" : "idle");
  function cpBroadcast() {                             // mirror the current slide's timer in a presenter window
    if (!chan || mode() === "presenter") return;
    const t = cpHere();
    chan.postMessage(t ? { type: "cp", left: t.left, state: cpState(t) } : { type: "cp", state: "off" });
  }
  function cpDraw(t) {
    const secs = Math.ceil(t.left / 1000);
    t.el.querySelector("output").textContent = mmss(secs);
    t.el.querySelector(".bar").style.strokeDashoffset = (RING * (1 - t.left / (CP_SECONDS * 1000))).toFixed(2);
    t.el.classList.toggle("low", secs <= CP_LOW && secs > 0);
    if (t === cpHere()) cpBroadcast();
  }
  function cpTick(t) {
    t.left = Math.max(0, t.end - Date.now());
    cpDraw(t);
    if (t.left === 0) {
      clearInterval(t.tick); t.tick = 0;
      t.el.classList.remove("running");
      t.el.classList.add("done");
      t.el.querySelector("small").textContent = "time's up";
      t.el.closest(".slide").classList.add("cp-flash");
      cpBroadcast();
    }
  }
  function cpStart(t) {
    if (t.tick || t.left === 0) return;
    t.end = Date.now() + t.left;
    t.el.classList.add("running"); t.el.classList.remove("paused");
    t.tick = setInterval(() => cpTick(t), 250);
    cpBroadcast();
  }
  function cpPause(t) {
    if (!t.tick) return;
    clearInterval(t.tick); t.tick = 0;
    t.left = Math.max(0, t.end - Date.now());
    t.el.classList.remove("running"); t.el.classList.add("paused");
    cpBroadcast();
  }
  function cpReset(t) {
    clearInterval(t.tick); t.tick = 0;
    t.left = CP_SECONDS * 1000;
    t.el.classList.remove("running", "paused", "done", "low");
    t.el.querySelector("small").textContent = "discussion";
    t.el.closest(".slide").classList.remove("cp-flash");
    cpDraw(t);
  }
  timers.forEach((t) => {
    t.el.querySelector(".bar").style.strokeDasharray = RING.toFixed(2);
    cpDraw(t);
    t.el.addEventListener("click", () => (t.tick ? cpPause(t) : t.left === 0 ? (cpReset(t), cpStart(t)) : cpStart(t)));
  });
  function cpFollow(s) {                               // called on every slide change
    timers.forEach((t) => {
      const here = mode() === "slides" && s.contains(t.el);
      if (!here) { if (t.tick || t.left !== CP_SECONDS * 1000) cpReset(t); }
      else if (!t.tick && !t.el.classList.contains("paused") && !t.el.classList.contains("done")) cpStart(t);
    });
    cpBroadcast();
  }

  // ---------------------------------------------------------------------------- navigation
  function show(i, broadcast = true) {
    cur = Math.max(0, Math.min(slides.length - 1, i));
    const s = slides[cur];
    slides.forEach((el, j) => el.classList.toggle("current", j === cur));
    if (document.activeElement && document.activeElement !== document.body && !s.contains(document.activeElement)) document.activeElement.blur();
    if (location.hash !== "#" + s.id) history.replaceState(null, "", "#" + s.id);
    $("ui-count").textContent = `${cur + 1} / ${slides.length}`;
    $("progress-bar").style.width = `${((cur + 1) / slides.length) * 100}%`;
    $("notes-title").textContent = `${s.dataset.num} · ${titleOf(s)}${skip(s)}`;
    $("notes-text").innerHTML = notesOf(s);
    document.querySelectorAll(".scroll-parts a").forEach((a) => a.classList.toggle("active", +a.dataset.part === +s.dataset.part));
    if (mode() === "presenter") presenterDraw();
    cpFollow(s);
    document.dispatchEvent(new CustomEvent("deck:slide", { detail: s }));   // lets demos redraw at the right size
    if (broadcast && chan) chan.postMessage({ type: "go", id: s.id });
  }
  const next = () => show(cur + 1);
  const prev = () => show(cur - 1);

  const el = (t) => (t instanceof Element ? t : document.body);      // events can target the document itself
  function typingIn(t) {
    return el(t).closest("input, textarea, select, [contenteditable]") !== null;
  }
  document.addEventListener("keydown", (e) => {
    if (e.ctrlKey || e.metaKey || e.altKey || typingIn(e.target)) return;
    const k = e.key, letter = k.length === 1 ? k.toLowerCase() : "", t = el(e.target);
    if (letter && t.closest("#en-keys")) return;                      // the Enigma keyboard is typing
    if (k === "Escape") { closeOverlays(); return; }
    if (mode() === "scroll") return;
    if (["ArrowRight", "PageDown"].includes(k) || (k === " " && !t.closest("button, summary, a"))) { e.preventDefault(); next(); }
    else if (["ArrowLeft", "PageUp"].includes(k)) { e.preventDefault(); prev(); }
    else if (k === "Home") { e.preventDefault(); show(0); }
    else if (k === "End") { e.preventDefault(); show(slides.length - 1); }
    else if (mode() === "presenter") return;
    else if (letter === "n") toggleNotes();
    else if (letter === "o") toggleOverview();
    else if (letter === "p") openPresenter();
    else if (letter === "f") fullscreen();
  });
  window.addEventListener("hashchange", () => { if (mode() !== "scroll") show(indexOf(location.hash.slice(1))); });
  window.addEventListener("resize", () => { if (mode() === "slides") fit(); });

  // simple swipe for tablets in slide mode
  let touchX = null;
  document.addEventListener("touchstart", (e) => { touchX = e.touches.length === 1 ? e.touches[0].clientX : null; }, { passive: true });
  document.addEventListener("touchend", (e) => {
    if (touchX === null || mode() !== "slides" || typingIn(e.target)) return;
    const dx = e.changedTouches[0].clientX - touchX;
    if (Math.abs(dx) > 60 && !el(e.target).closest("input, canvas, .keys")) (dx < 0 ? next : prev)();
    touchX = null;
  }, { passive: true });

  // ---------------------------------------------------------------------------- controls, notes, overview
  let idleTimer;
  function wake() {
    root.classList.remove("ui-idle");
    clearTimeout(idleTimer);
    idleTimer = setTimeout(() => root.classList.add("ui-idle"), 2500);
  }
  document.addEventListener("mousemove", wake);
  wake();

  function toggleNotes() { $("notes-panel").hidden = !$("notes-panel").hidden; }
  function toggleOverview() {
    const o = $("overview");
    if (o.hidden) {
      $("overview-list").innerHTML = slides.map((s, i) =>
        `<li class="${i === cur ? "here" : ""}"><button type="button" data-i="${i}"><small>${i + 1} · ${s.querySelector(".eyebrow") ? s.querySelector(".eyebrow").textContent : ""}</small>${titleOf(s)}${s.dataset.skip ? '<em class="skip">skippable</em>' : ""}</button></li>`).join("");
      o.hidden = false;
      const here = o.querySelector(".here button");
      if (here) here.focus();
    } else o.hidden = true;
  }
  function closeOverlays() { $("overview").hidden = true; $("notes-panel").hidden = true; }
  $("overview-list").addEventListener("click", (e) => { const b = e.target.closest("button[data-i]"); if (b) { show(+b.dataset.i); $("overview").hidden = true; } });
  $("overview-close").addEventListener("click", () => ($("overview").hidden = true));
  $("overview").addEventListener("click", (e) => { if (e.target.id === "overview") $("overview").hidden = true; });

  function fullscreen() {
    const d = document;
    if (d.fullscreenElement) d.exitFullscreen().catch(() => {});
    else if (root.requestFullscreen) root.requestFullscreen().catch(() => {});
  }
  function openPresenter() {
    const url = location.pathname + "?presenter#" + slides[cur].id;
    const w = window.open(url, `${TALK_ID}-presenter`, "width=1100,height=720");
    if (!w) { $("notes-panel").hidden = false; }                  // pop-up blocked: fall back to the notes panel
  }

  $("ui-prev").addEventListener("click", prev);
  $("ui-next").addEventListener("click", next);
  $("ui-overview").addEventListener("click", toggleOverview);
  $("ui-notes").addEventListener("click", toggleNotes);
  $("ui-presenter").addEventListener("click", openPresenter);
  $("ui-full").addEventListener("click", fullscreen);
  $("ui-print").addEventListener("click", () => window.print());     // print styles lay out one slide per page
  document.querySelectorAll("[data-mode]").forEach((b) => b.addEventListener("click", () => setMode(b.dataset.mode, true)));
  // links to other slides (e.g. the roadmap) jump inside the deck
  document.addEventListener("click", (e) => {
    const a = e.target.closest('a[href^="#"]');
    if (!a || mode() === "scroll") return;
    e.preventDefault();
    show(indexOf(a.getAttribute("href").slice(1)));
  });

  // scroll view: keep "current" in step with what is on screen, for the part highlight and mode switching
  if ("IntersectionObserver" in window) {
    const io = new IntersectionObserver((entries) => {
      if (mode() !== "scroll") return;
      for (const en of entries) if (en.isIntersecting) {
        cur = slides.indexOf(en.target);
        document.querySelectorAll(".scroll-parts a").forEach((a) => a.classList.toggle("active", +a.dataset.part === +en.target.dataset.part));
      }
    }, { rootMargin: "-45% 0px -50% 0px" });
    slides.forEach((s) => io.observe(s));
  }

  // ---------------------------------------------------------------------------- presenter window
  let t0 = null, pausedFor = 0, tick;
  const fmtClock = (s) => `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`;
  function clock() { $("pr-clock").textContent = fmtClock(Math.floor((pausedFor + (t0 ? Date.now() - t0 : 0)) / 1000)); }
  function presenterBuild() {
    const p = $("presenter");
    p.hidden = false;
    p.innerHTML = `
      <header><b>PRESENTER</b><span id="pr-count"></span>
        <button type="button" class="pr-cp" id="pr-cp" hidden title="The checkpoint timer on the main screen. Click to pause or resume it."><small>CHECKPOINT</small><output>05:00</output></button>
        <span class="pr-timer"><output id="pr-clock">00:00</output>
        <button type="button" class="btn btn-sm" id="pr-start">Start timer</button><button type="button" class="btn btn-ghost btn-sm" id="pr-reset">Reset</button></span></header>
      <section class="pr-now"><small id="pr-eyebrow"></small><h2 id="pr-title"></h2><div id="pr-notes" class="cue"></div></section>
      <aside class="pr-side"><small>NEXT</small><p id="pr-next"></p><small>PLAN</small><ol id="pr-plan"></ol></aside>
      <footer><button type="button" class="btn btn-ghost" id="pr-prev">‹ Previous</button><button type="button" class="btn" id="pr-nextbtn">Next ›</button></footer>`;
    let end = 0;                                       // part lengths include their 5-minute checkpoint (120 min total)
    $("pr-plan").innerHTML = PART_MIN.map((m, i) => (i ? `<li data-part="${i}">${PARTS[i]}<span>${m} min · done by minute ${(end += m)}</span></li>` : "")).join("");
    $("pr-prev").addEventListener("click", prev);
    $("pr-nextbtn").addEventListener("click", next);
    $("pr-start").addEventListener("click", () => {
      if (t0 === null) { t0 = Date.now(); tick = setInterval(clock, 1000); $("pr-start").textContent = "Pause"; }
      else { clearInterval(tick); pausedFor += Date.now() - t0; t0 = null; $("pr-start").textContent = "Resume"; }
    });
    $("pr-reset").addEventListener("click", () => { clearInterval(tick); t0 = null; pausedFor = 0; clock(); $("pr-start").textContent = "Start timer"; });
    $("pr-cp").addEventListener("click", () => chan && chan.postMessage({ type: "cp-toggle" }));
    document.title = `Presenter · ${TALK_TITLE}`;
  }
  function presenterCp(m) {                            // the main window's checkpoint timer, mirrored
    const b = $("pr-cp");
    b.hidden = m.state === "off";
    if (b.hidden) return;
    const secs = Math.ceil(m.left / 1000);
    b.querySelector("output").textContent = m.state === "done" ? "TIME'S UP" : mmss(secs);
    b.className = `pr-cp ${m.state}${m.state === "running" && secs <= CP_LOW ? " low" : ""}`;
  }
  function presenterDraw() {
    const s = slides[cur], n = slides[cur + 1];
    $("pr-count").textContent = `Slide ${cur + 1} of ${slides.length} · deck slide ${s.dataset.num}`;
    $("pr-eyebrow").textContent = ((s.querySelector(".eyebrow") || {}).textContent || "") + skip(s);
    $("pr-title").textContent = titleOf(s);
    $("pr-notes").innerHTML = notesOf(s);
    $("pr-next").textContent = n ? `${n.dataset.num} · ${titleOf(n)}${skip(n) ? " (skippable)" : ""}` : "End of the deck";
    document.querySelectorAll("#pr-plan li").forEach((li) => li.classList.toggle("here", +li.dataset.part === +s.dataset.part));
  }

  if (chan) chan.onmessage = (e) => {
    const m = e.data || {};
    if (m.type === "go") show(indexOf(m.id), false);
    else if (m.type === "hello" && mode() !== "presenter") { chan.postMessage({ type: "go", id: slides[cur].id }); cpBroadcast(); }
    else if (m.type === "cp" && mode() === "presenter") presenterCp(m);
    else if (m.type === "cp-toggle" && mode() !== "presenter") { const t = cpHere(); if (t) t.el.click(); }
  };

  // ---------------------------------------------------------------------------- start
  cur = indexOf(location.hash.slice(1));
  if (mode() === "presenter") { presenterBuild(); show(cur, false); if (chan) chan.postMessage({ type: "hello" }); }
  else if (mode() === "slides") { fit(); show(cur, false); }
  else { show(cur, false); if (location.hash) requestAnimationFrame(() => slides[cur].scrollIntoView({ block: "start" })); }
})();
