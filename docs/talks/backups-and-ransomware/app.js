/* app.js - the live demos for "Backups and Ransomware".
   Everything here is a simulation in your browser: nothing real is encrypted, locked, deleted or sent.
   Files are only ever marked "locked" on screen. Ticks and your plan are kept in this browser's
   localStorage and nowhere else. Random picks use crypto.getRandomValues. */
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
    for (const b of group.querySelectorAll("button")) b.setAttribute("aria-pressed", String(b.getAttribute(attr) === String(value)));
  }
  function rint(n) { // an unbiased random whole number from 0 to n-1
    const lim = Math.floor(4294967296 / n) * n, a = new Uint32Array(1);
    do { crypto.getRandomValues(a); } while (a[0] >= lim);
    return a[0] % n;
  }
  const plural = (n, w) => `${n} ${w}${n === 1 ? "" : "s"}`;

  // --------------------------------------------------------------------------- title: survives
  // A toy: it reads the places you type, guesses what kind each is, and counts. It is not a product.
  const KINDS = [
    { k: "internal", re: /\b(laptop|pc|computer|desktop|phone|mac|macbook|tablet|notebook)\b/ },
    { k: "cloudbackup", re: /(backblaze|crashplan|carbonite|idrive|spideroak|cloud backup|online backup)/ },
    { k: "sync", re: /(onedrive|dropbox|google drive|gdrive|icloud|\bbox\b|sync|the cloud|cloud folder|cloud storage)/ },
    { k: "external", re: /(external|usb|hard drive|hard disk|hdd|ssd|time machine|file history|\bnas\b|synology|qnap|raid|mirror|backup drive|\bdrive\b|tape|disk|stick|thumb drive|flash drive)/ },
  ];
  const OFFSITE_RE = /(off-?site|parents|\bmum\b|\bmom\b|friend|relative|work desk|at work|safe deposit|bank|another (house|building)|elsewhere)/;
  const OFFLINE_RE = /(unplugged|offline|drawer|\bsafe\b|shelf|cupboard|\btape\b|air-?gap|locked copy|immutable|object lock|stored away|in a box)/;
  function classify(p) {
    const t = p.toLowerCase();
    let kind = "other";
    for (const o of KINDS) if (o.re.test(t)) { kind = o.k; break; }
    const cloud = kind === "sync" || kind === "cloudbackup";
    const medium = kind === "internal" ? "internal" : cloud ? "cloud" : kind === "external" ? "external" : "other";
    const offline = !cloud && kind !== "internal" && OFFLINE_RE.test(t);
    const offsite = cloud || (kind !== "internal" && OFFSITE_RE.test(t));
    return { t, kind, medium, offline, offsite };
  }
  function analyze(v) {
    const places = v.split(/[,;+\n]|\band\b|\bplus\b/i).map((s) => s.trim()).filter(Boolean).map(classify);
    const media = new Set(places.map((p) => p.medium));
    return {
      places,
      copies: places.length,
      kinds: media.size,
      offsite: places.some((p) => p.offsite),
      offline: places.some((p) => p.offline),
      syncOnly: places.some((p) => p.kind === "sync") && !places.some((p) => p.kind === "cloudbackup" || p.kind === "external"),
    };
  }
  function hero() {
    const el = $("hero-in"), v = el.value, t = v.trim().toLowerCase();
    el.style.width = Math.max(10, [...v].length + 1) + "ch";
    const out = $("hero-out"), note = $("hero-note");
    const a = analyze(v);
    const yn = (b) => (b ? sp("ok", "yes") : sp("bad", "no"));
    out.innerHTML =
      `${sp("k", "copies:")} ${sp(a.copies >= 3 ? "ok" : "bad", String(a.copies))} ${sp("k", "(3-2-1 asks for 3)")}<br>` +
      `${sp("k", "kinds of storage:")} ${sp(a.kinds >= 2 ? "ok" : "bad", String(a.kinds))} ${sp("k", "(asks for 2)")}<br>` +
      `${sp("k", "a copy somewhere else:")} ${yn(a.offsite)}<br>` +
      `${sp("k", "a copy ransomware can't reach:")} ${yn(a.offline)}`;
    const plan = a.copies >= 3 && a.kinds >= 2 && a.offsite && a.offline;
    let n;
    if (!t || /^(nothing|nowhere|none|no copies|zero)$/.test(t)) n = "# nothing listed: no copies at all. Today is a fine day to make the first one.";
    else if (/\bmy head\b|\bmemory\b|\bbrain\b/.test(t)) n = "# memory is a fine place for a poem and a poor place for a tax return. Try a drive.";
    else if (/\b(paper|printed|printout|printouts)\b/.test(t)) n = "# paper survives ransomware very well. It struggles with forty thousand photos.";
    else if (/\bfloppy|floppies\b/.test(t)) n = "# 1.44 MB per disk: smaller than most photos from a modern phone. Admirable, and very offline.";
    else if (plan) n = "# 3-2-1-1: a plan to be proud of. Now restore one file from it, to find out for sure.";
    else if (/\btape\b/.test(t)) n = "# tape: still used for offline copies, and while it's on a shelf nothing can lock it.";
    else if (/\b(raid|mirror)\b/.test(t)) n = "# RAID keeps going when a disk dies, and it faithfully mirrors a deleted file too. Useful, but not a backup.";
    else if (/^(the )?cloud$/.test(t)) n = "# the cloud is somebody else's computer. The useful question: does it sync (follow your changes) or back up (keep old versions)?";
    else if (/\bdrawer\b/.test(t)) n = "# a drive in a drawer is the oldest offline copy there is. Check once in a while that it still turns on.";
    else if (a.syncOnly) n = "# a synced copy follows the laptop, so it's closer to one copy than two. The next slides show why.";
    else if (!a.offline) n = "# nothing here is out of ransomware's reach: add a copy that's unplugged or locked.";
    else if (!a.offsite) n = "# good: a copy that can't be reached. Add one kept somewhere else, away from a fire or a burglary.";
    else n = "# on the right track. The 3-2-1 builder gets to the rest.";
    note.textContent = n;
  }

  // --------------------------------------------------------------------------- hopeless: key sizes
  const AGE_UNIVERSE_YEARS = 13.8e9; // about 13.8 billion years
  function fmtBig(log10) {
    if (log10 < 6) return Math.round(10 ** log10).toLocaleString("en-US");
    const e = Math.floor(log10), m = 10 ** (log10 - e);
    return `${m.toFixed(1)} × 10^${e}`;
  }
  function fmtSpan(log10sec) {
    const sec = 10 ** log10sec;
    if (sec < 1) return "under a second";
    if (sec < 60) return plural(Math.round(sec), "second");
    if (sec < 3600) return plural(Math.round(sec / 60), "minute");
    if (sec < 86400) return plural(Math.round(sec / 3600), "hour");
    const years = sec / 31557600;
    if (years < 1) return plural(Math.round(sec / 86400), "day");
    if (years < 1e6) return plural(Math.round(years), "year");
    return `${fmtBig(Math.log10(years))} years`;
  }
  let hlBits = 128, hlExp = 18;
  function hopeless() {
    press($("hl-bits"), "data-v", hlBits); press($("hl-rate"), "data-v", hlExp);
    const logKeys = hlBits * Math.log10(2);
    const logSec = logKeys - hlExp, years = 10 ** (logSec - Math.log10(31557600));
    const ratio = years / AGE_UNIVERSE_YEARS;
    let cmp;
    if (ratio >= 10) cmp = `${fmtBig(Math.log10(ratio))} times the age of the universe`;
    else if (ratio >= 0.01) cmp = `about ${Math.round(ratio * 100)}% of the age of the universe`;
    else cmp = "far less than a human lifetime" ;
    const short = 10 ** logSec < 86400 * 365 * 100;
    $("hl-out").innerHTML =
      `<div class="stat"><b>${esc(fmtBig(logKeys))}</b><span>possible keys (2^${hlBits})</span></div>` +
      `<div class="stat ${short ? "stat-bad" : "stat-ok"}"><b>${esc(fmtSpan(logSec))}</b><span>to try every one at 10^${hlExp} a second</span></div>` +
      `<div class="stat"><b>${short ? "tiny" : esc(ratio >= 10 ? fmtBig(Math.log10(ratio)) : "~" + Math.round(ratio * 100) + "%")}</b><span>${short ? "next to the age of the universe" : ratio >= 10 ? "times the age of the universe (about 13.8 billion years)" : "of the age of the universe (about 13.8 billion years)"}</span></div>`;
    let n;
    if (hlBits === 56) n = "# 56 bits is the old DES key size: within reach of a big enough pile of computers. Modern ciphers use 128 bits or more.";
    else if (ratio >= 10) n = `# trying every key would take ${cmp}, at speeds nobody has. Finding it on average takes half that, which doesn't help. Not a plan.`;
    else n = `# trying every key would take ${cmp}, at a speed no real attacker has: 10^${hlExp} keys a second is absurdly generous. Not a plan.`;
    $("hl-note").textContent = n;
  }

  // --------------------------------------------------------------------------- sync is not backup
  const SS_FILES = ["taxes.pdf", "photos", "essay.doc", "recipes"];
  const SS_STORES = [
    { k: "laptop", name: "Laptop", sub: "the original" },
    { k: "sync", name: "Sync folder", sub: "follows the laptop" },
    { k: "ver", name: "Versioned backup", sub: "keeps old versions" },
    { k: "off", name: "Unplugged copy", sub: "updated 2 weeks ago" },
  ];
  const SS_WINDOW = { sync: 30, ver: 90 };
  let ss = { ev: null, restored: false };
  function ssFile(store, i) {
    if (ss.ev === "delete" && i === 0) return store === "ver" || store === "off" ? "ok" : "gone";
    if (ss.ev === "lock") return store === "off" ? "ok" : "lock";
    return "ok";
  }
  function ssStatus(store, n) {
    if (ss.restored) {
      if (store === "laptop") return { cls: "bad", t: "nothing to restore from" };
      if (store === "off") return { cls: "good", t: "back, as of two weeks ago" };
      const w = SS_WINDOW[store];
      return n <= w ? { cls: "good", t: "restored from history" } : { cls: "bad", t: `history ended after ${w} days` };
    }
    if (!ss.ev) return { cls: "", t: "in step" };
    const del = ss.ev === "delete";
    if (store === "laptop") return { cls: "bad", t: del ? "1 file gone" : "all files locked" };
    if (store === "sync") return { cls: "bad", t: del ? "deleted here too, moments later" : "locked files synced" };
    if (store === "ver") return { cls: "warn", t: del ? "old copy kept" : "locked saved as newest; old versions kept" };
    return { cls: "good", t: "can't be reached: untouched" };
  }
  function syncDraw() {
    const n = +$("ss-days").value;
    $("ss-days-out").textContent = plural(n, "day");
    $("ss-grid").innerHTML = SS_STORES.map((s) => {
      const st = ssStatus(s.k, n);
      return `<div class="store ${st.cls}"><b>${esc(s.name)}</b><small>${esc(s.sub)}</small>` +
        `<ul class="files">${SS_FILES.map((f, i) => `<li class="f ${ssFile(s.k, i)}">${esc(f)}</li>`).join("")}</ul>` +
        `<p class="st">${esc(st.t)}</p></div>`;
    }).join("");
    const note = $("ss-note");
    if (!ss.ev) { note.textContent = "# press one of the first two buttons to make something go wrong."; return; }
    if (!ss.restored) { note.textContent = ss.ev === "delete" ? "# one file deleted: the sync folder deleted it too. Now slide the bar and try to restore." : "# every file locked, and the sync folder uploaded the locked ones. Now slide the bar and try to restore."; return; }
    let t;
    if (n <= 30) t = "# noticed in time: the sync history and the backup both go back far enough. The unplugged copy works too, but it's two weeks behind.";
    else if (n <= 90) t = "# the sync service's history has ended (30 days here). The versioned backup and the unplugged copy still have your files.";
    else t = "# past every window except one: only the unplugged copy still has your files, as of two weeks ago. That's why it earns its place.";
    if (n >= 120 && ss.ev === "lock") t += " Four months on, the locked files have long since replaced the good ones everywhere that could be reached.";
    note.textContent = t;
  }
  function syncEvent(ev) { ss = { ev, restored: false }; syncDraw(); }

  // --------------------------------------------------------------------------- 3-2-1 builder
  // history = days of old versions kept (an assumption, shown on the slide's notes); provider A = your sync login
  const COPIES = [
    { k: "sync", label: "Cloud sync folder", sub: "OneDrive, Dropbox, Google Drive, iCloud Drive", medium: "cloud", offsite: true, history: 30, provider: "A" },
    { k: "plugged", label: "External drive, always plugged in", sub: "with File History or Time Machine on", medium: "external", history: 90 },
    { k: "nas", label: "A NAS at home, always on", sub: "with snapshots", medium: "external", history: 60 },
    { k: "unplugged", label: "External drive kept unplugged at home", sub: "plugged in only to update it", medium: "external", offline: true },
    { k: "offsitedrive", label: "External drive kept somewhere else", sub: "a desk at work, a relative's home", medium: "external", offsite: true, offline: true },
    { k: "cloudbackup", label: "Cloud backup service with version history", sub: "separate from your sync folder", medium: "cloud", offsite: true, history: 180, provider: "B" },
    { k: "locked", label: "Cloud storage with locked (immutable) copies", sub: "mostly for small teams", medium: "cloud", offsite: true, immutable: true, history: 365, provider: "C" },
  ];
  const PRESETS = { laptop: [], sync: ["sync"], plugged: ["plugged"], good: ["cloudbackup", "unplugged"], team: ["sync", "nas", "offsitedrive", "locked"] };
  const BD_KEY = "backups-plan";
  let bd = { sel: ["sync"], tested: false };
  function bdLoad() {
    try { const s = JSON.parse(store(BD_KEY) || "null"); if (s && Array.isArray(s.sel)) bd = { sel: s.sel.filter((k) => COPIES.some((c) => c.k === k)), tested: !!s.tested }; } catch (e) {}
  }
  function bdSave() { store(BD_KEY, JSON.stringify(bd)); }
  const DISASTERS = [
    ["Fire, flood or burglary at home", (o) => (o.some((c) => c.offsite) ? { s: "ok", why: "A copy is kept somewhere else." } : { s: "bad", why: "Every copy is in the same building." })],
    ["The laptop dies or is stolen", (o) => (o.length ? { s: "ok", why: "Another copy exists." } : { s: "bad", why: "The only copy is gone." })],
    ["A file deleted by mistake, noticed after two months", (o) => (o.some((c) => (c.history || 0) >= 60 || c.offline || c.immutable) ? { s: "ok", why: "A copy remembers further back than that." } : { s: "bad", why: "Nothing goes back two months." })],
    ["Ransomware locks the laptop", (o) => {
      if (o.some((c) => c.offline || c.immutable)) return { s: "ok", why: "A copy it can't reach." };
      if (o.some((c) => c.history)) return { s: "maybe", why: "Only if you notice in time and the old versions and your login are untouched." };
      return { s: "bad", why: "Everything is reachable and none keeps old versions." };
    }],
    ["The laptop dies and your cloud login is locked", (o) => (o.some((c) => c.provider !== "A") ? { s: "ok", why: "A copy doesn't depend on that login." } : { s: "bad", why: "Everything hangs on one login, or on the laptop." })],
  ];
  const SCORE = { ok: "Survives", maybe: "Maybe", bad: "Lost" };
  function bdDraw() {
    const chosen = COPIES.filter((c) => bd.sel.includes(c.k));
    $("bd-opts").innerHTML =
      `<label class="bd-opt locked"><input type="checkbox" checked disabled><span><b>The laptop itself</b><small>the original: always copy number 1</small></span></label>` +
      COPIES.map((c) => `<label class="bd-opt"><input type="checkbox" data-k="${c.k}"${bd.sel.includes(c.k) ? " checked" : ""}><span><b>${esc(c.label)}</b><small>${esc(c.sub)}</small></span></label>`).join("");
    $("bd-tested").checked = bd.tested;
    for (const b of $("bd-presets").querySelectorAll("button")) {
      const p = PRESETS[b.dataset.p];
      b.setAttribute("aria-pressed", String(p.length === bd.sel.length && p.every((k) => bd.sel.includes(k))));
    }
    const copies = chosen.length + 1;
    const kinds = new Set(["internal", ...chosen.map((c) => c.medium)]).size;
    const offsite = chosen.some((c) => c.offsite), offline = chosen.some((c) => c.offline || c.immutable);
    const chips = [
      [copies >= 3, `3 copies: you have ${copies}`], [kinds >= 2, `2 kinds of storage: ${kinds}`],
      [offsite, `1 off-site: ${offsite ? "yes" : "no"}`], [offline, `1 offline or locked: ${offline ? "yes" : "no"}`],
      [bd.tested, `0 errors: ${bd.tested ? "tested" : "not tested"}`],
    ];
    $("bd-chips").innerHTML = chips.map(([ok, t]) => `<span class="chip ${ok ? "ok" : "bad"}">${esc(t)}</span>`).join("");
    $("bd-rows").innerHTML = DISASTERS.map(([name, fn]) => {
      const r = fn(chosen);
      return `<tr class="${r.s}"><th>${esc(name)}</th><td><b>${SCORE[r.s]}</b><small>${esc(r.why)}</small></td></tr>`;
    }).join("");
    let n;
    if (!chosen.length) n = "# one copy, the original. Everyone starts here; the next copy is the biggest step.";
    else if (chosen.length === COPIES.length && bd.tested) n = "# everything, tested: heroic. A plan you'll actually keep up beats a grand one you won't.";
    else if (chips.every((c) => c[0])) n = "# 3-2-1-1-0. The textbook plan, and it's yours. Put the next test in the calendar.";
    else if (!offsite) n = "# nothing is kept somewhere else: a fire or a burglary takes all of it.";
    else if (!offline) n = "# nothing here is out of ransomware's reach: add a copy that's unplugged or locked.";
    else if (!bd.tested) n = "# the last 0: restore a file from it, so you know it works.";
    else if (copies < 3) n = "# one more copy and the 3 in 3-2-1 is met.";
    else n = "# close: check the red chips above.";
    $("bd-note").textContent = n;
  }
  function bdSet(sel) { bd.sel = sel.slice(); bdSave(); bdDraw(); }

  // --------------------------------------------------------------------------- versioning: how far back
  const VR = [
    ["Trash: Google Drive, OneDrive (personal), iCloud Drive", "30 days", 30],
    ["Google Drive: older versions of a file", "30 days or 100 versions", 30],
    ["OneDrive: Restore your OneDrive (Microsoft 365)", "30 days", 30],
    ["Dropbox: Basic, Plus, Family", "30 days", 30],
    ["OneDrive, work or school: recycle bin", "93 days", 93],
    ["Dropbox: Professional, Essentials, Business, Standard", "180 days", 180],
    ["Dropbox: Business Plus, Advanced, Enterprise", "365 days", 365],
    ["A copy you keep yourself (an unplugged drive)", "as long as you keep it", Infinity],
  ];
  function vrSpan(n) {
    if (n < 60) return plural(n, "day");
    if (n < 330) return `${n} days (about ${Math.round(n / 30.4)} months)`;
    return `${n} days (about ${(n / 365).toFixed(1).replace(/\.0$/, "")} year${n >= 548 ? "s" : ""})`;
  }
  function versions() {
    const n = +$("vr-days").value;
    $("vr-out").textContent = vrSpan(n);
    press($("vr-presets"), "data-d", n);
    $("vr-rows").innerHTML = VR.map(([where, back, w]) => {
      const ok = n <= w;
      const res = w === Infinity ? "Yes, as last updated" : ok ? "Yes" : "No: too late";
      return `<tr class="${ok ? "ok" : "bad"}"><th>${esc(where)}</th><td>${esc(back)}</td><td><b>${esc(res)}</b></td></tr>`;
    }).join("");
    let t;
    if (n <= 30) t = "# inside 30 days, almost everything on this list can still help.";
    else if (n <= 93) t = "# past 30 days most free sync plans can't help. A work account, a paid plan or your own copy may.";
    else if (n <= 365) t = "# only the longer paid plans and a copy you keep yourself remain.";
    else t = "# over a year: only a copy you kept yourself goes back that far.";
    $("vr-note").textContent = t;
  }

  // --------------------------------------------------------------------------- where does the key live
  const KEYS = [
    { t: "Only in my head", good: false, why: "If you forget it, the backup is gone: Apple says an encrypted backup can't be restored without its password." },
    { t: "In a text file on the laptop I'm backing up", good: false, why: "If the laptop dies, the key goes with it, just when you need it." },
    { t: "In my password manager", good: true, why: "It's stored apart from the laptop and has its own recovery steps. Set those up too." },
    { t: "Printed, kept somewhere safe away from the laptop", good: true, why: "Paper can't be locked by ransomware and doesn't depend on any device." },
    { t: "On a sticky note on the backup drive", good: false, why: "Anyone who finds the drive has the key, which cancels the point of encrypting." },
    { t: "In a sealed envelope with someone I trust", good: true, why: "A second place, away from you. Choose carefully, and tell them what it is." },
  ];
  let kyPick = KEYS.map(() => null), kyChecked = false;
  function keysDraw() {
    $("ky-list").innerHTML = KEYS.map((k, i) => {
      const cls = kyChecked ? (kyPick[i] === (k.good ? "good" : "bad") ? "ok" : "bad") : "";
      return `<li class="so-row ${cls}"><span>${esc(k.t)}</span><span class="seg-pick">` +
        `<button type="button" data-i="${i}" data-z="good" aria-pressed="${kyPick[i] === "good"}">Good place</button>` +
        `<button type="button" data-i="${i}" data-z="bad" aria-pressed="${kyPick[i] === "bad"}">Bad place</button></span></li>`;
    }).join("");
    $("ky-help").hidden = kyChecked; $("ky-why").hidden = !kyChecked;
    if (kyChecked) $("ky-why").innerHTML = KEYS.map((k, i) => {
      const right = kyPick[i] === (k.good ? "good" : "bad");
      return `<li class="${right ? "ok" : "bad"}"><b>${right ? "yes" : "no"}</b><span>${esc(k.t)}: ${esc(k.why)}</span></li>`;
    }).join("");
  }
  function keysCheck() {
    if (kyPick.some((p) => p === null)) { $("ky-note").textContent = "# mark all six first."; return; }
    kyChecked = true; keysDraw();
    const score = KEYS.filter((k, i) => kyPick[i] === (k.good ? "good" : "bad")).length;
    let t = `${score} of ${KEYS.length} right. `;
    if (score === KEYS.length) t += "# all six. The key is in more than one safe place, and never next to what it protects.";
    else if (score === 0) t += "# zero: the obvious places are the risky ones. Now you know which.";
    else t += "# the rule: keep the key somewhere that survives whatever kills the backup, and where a thief of the backup wouldn't look.";
    $("ky-note").textContent = t;
  }
  function keysReset() { kyPick = KEYS.map(() => null); kyChecked = false; $("ky-note").textContent = ""; keysDraw(); }

  // --------------------------------------------------------------------------- the restore test checklist
  const RT_KEY = "backups-restore-test";
  function restoreTest() {
    const boxes = Array.from(document.querySelectorAll("#rt-plan input[type=checkbox]"));
    let saved = {};
    try { saved = JSON.parse(store(RT_KEY) || "{}"); } catch (e) {}
    boxes.forEach((b) => { b.checked = !!saved[b.dataset.k]; });
    const update = () => {
      const done = boxes.filter((b) => b.checked).length;
      store(RT_KEY, JSON.stringify(Object.fromEntries(boxes.map((b) => [b.dataset.k, b.checked]))));
      const note = $("rt-note"); note.className = "comment";
      if (done === boxes.length) { note.textContent = "# all six. A backup you've restored is a plan; yours is now one."; note.classList.add("ok"); }
      else if (done === 0) note.textContent = "# tick what you've already done. Ticks are saved in this browser only.";
      else note.textContent = `# ${done} of ${boxes.length} done. Start with the first three: they tell you the most.`;
    };
    boxes.forEach((b) => b.addEventListener("change", update));
    update();
  }

  // --------------------------------------------------------------------------- how long will a restore take
  let rsSize = 1000, rsRate = 100, rsName = "a drive plugged in by USB";
  function fmtDur(sec) {
    if (sec < 90) return plural(Math.max(1, Math.round(sec)), "second");
    if (sec < 5400) return plural(Math.round(sec / 60), "minute");
    if (sec < 86400 * 1.5) return `${(sec / 3600).toFixed(1).replace(/\.0$/, "")} hours`;
    return `${(sec / 86400).toFixed(1).replace(/\.0$/, "")} days`;
  }
  function restoreTime() {
    press($("rs-size"), "data-v", rsSize);
    for (const b of $("rs-link").querySelectorAll("button")) b.setAttribute("aria-pressed", String(+b.dataset.v === rsRate));
    const sec = (rsSize * 1000) / rsRate; // GB -> MB, then MB/s
    const sizeTxt = rsSize >= 1000 ? `${rsSize / 1000} TB` : `${rsSize} GB`;
    const long = sec >= 86400;
    $("rs-out").innerHTML =
      `<div class="stat ${long ? "stat-bad" : "stat-ok"}"><b>~${esc(fmtDur(sec))}</b><span>to copy ${esc(sizeTxt)} back, best case</span></div>` +
      `<div class="stat"><b>${rsRate >= 100 ? rsRate + " MB/s" : (rsRate * 8) + " Mbit/s"}</b><span>from ${esc(rsName)}</span></div>` +
      `<div class="stat"><b>${sec < 4 * 3600 ? "an afternoon" : sec < 86400 ? "about a day" : "days"}</b><span>roughly how long you're without the files</span></div>`;
    let t;
    if (rsSize === 4000 && rsRate === 2.5) t = "# about 18 days. This is why a local copy matters as well as an off-site one.";
    else if (rsSize === 50 && rsRate === 100) t = "# 50 GB over USB: about eight minutes. Lovely, and a good reason to keep a local copy.";
    else if (long) t = "# days, even in the best case. Plan for it, and restore the important things first.";
    else if (rsRate >= 100) t = "# a local copy is the fast way back, if it survived.";
    else t = "# a cloud restore is limited by your connection. Fine for a few documents, slow for everything.";
    $("rs-note").textContent = t;
  }

  // --------------------------------------------------------------------------- a ransomware morning
  let bySetup = 1, byDays = 1;
  function badDay() {
    press($("bdy-setup"), "data-v", bySetup); press($("bdy-when"), "data-v", byDays);
    const steps = ["<b>03:12</b> Ransomware starts locking files on the laptop."];
    if (bySetup >= 1) steps.push("<b>03:13</b> The sync folder uploads the locked files as the newest versions.");
    if (bySetup >= 2) steps.push("<b>03:20</b> The plugged-in drive is reachable, so its copies are locked or deleted too.");
    if (bySetup >= 3) steps.push("<b>03:20</b> The unplugged copy sits in a drawer. Nothing can reach it.");
    steps.push(byDays === 1 ? "<b>08:00</b> You see the ransom note." : `<b>Day ${byDays}</b> You open a folder you rarely use and find it locked (in this made-up case the damage was quiet).`);
    $("bdy-tl").innerHTML = steps.map((s) => `<li>${s}</li>`).join("");
    let cls, head, note;
    if (bySetup === 3) {
      cls = "ok"; head = "You get everything back, as it was two weeks ago.";
      note = byDays === 45 ? "# six weeks later, the drawer still came through. You lose two weeks of changes, and you keep your files." : "# the unplugged copy didn't care what day you noticed. It's two weeks old, but it's yours.";
    } else if (bySetup === 0) {
      cls = "bad"; head = "Nothing to restore from.";
      note = "# nothing to restore from: this is the day the free-decryptor list matters. Check it, report it, and start the second copy tomorrow.";
    } else if (byDays <= 30) {
      cls = "maybe"; head = "Probably most of it, from the sync history.";
      note = bySetup === 2 ? "# the plugged-in drive was locked too, so the sync service's old versions are all you have, and they take time to restore file by file." : "# the old versions are still there for now, and it works only if your account is untouched. One copy of the history is a thin thread.";
    } else {
      cls = "bad"; head = "The history has ended: nothing to restore from.";
      note = "# the sync service's 30-day history is gone, and the plugged-in drive was reachable too. This is the day an unplugged copy pays for itself.";
    }
    const v = $("bdy-verdict"); v.className = "verdict " + cls; v.textContent = head;
    $("bdy-note").textContent = note;
  }

  // --------------------------------------------------------------------------- tabletop scenarios
  const SCENARIOS = [
    { w: "Monday, 8:10.", t: "Every file on the shared drive has a strange new ending, and a text file on the desktop asks for payment.",
      q: ["Who do we call first, and what's their phone number?", "Which machines do we disconnect, and who decides?", "Where's the offline backup, and who can restore from it?"] },
    { w: "Friday, 5:05 pm.", t: "The accountant's laptop shows a ransom note. She says she opened an invoice an hour ago.",
      q: ["What do we do with her laptop right now?", "How do we check the other machines and the backup drive?", "What do we tell staff, and how, if email might not be safe?"] },
    { w: "Saturday, 11 pm.", t: "The office storage box shows a message saying your files are locked. The office is empty.",
      q: ["Who can get in, and who has the IT provider's number?", "Can we reach the backup password without the locked machines?", "What can wait until Monday, and what can't?"] },
    { w: "Tuesday, 9:30.", t: "A supplier emails: they've been hit by ransomware, and your login to their portal may be affected.",
      q: ["Which accounts share that supplier login, and do we change them from a clean device?", "Does every one of those accounts have a second step?", "Who tells our customers, and what do we say?"] },
    { w: "Wednesday.", t: "A customer says their details appeared on a website. Every one of your files opens fine.",
      q: ["What data could it be, and who needs to be told?", "Who helps us find out how it got out?", "Would a backup have helped here? What would?"] },
    { w: "Thursday.", t: "The restore you started is crawling: two terabytes will take days over the office connection.",
      q: ["What do we restore first, and who decides?", "Is there a local copy that's faster than the cloud?", "How do we keep doing business in the meantime?"] },
  ];
  let ttSeen = new Set(), ttLast = -1;
  function tabletop() {
    const i = rint(SCENARIOS.length), s = SCENARIOS[i];
    $("tt-out").innerHTML = `<p class="tt-sc"><b>${esc(s.w)}</b> ${esc(s.t)}</p><ol class="tt-q">${s.q.map((q) => `<li>${esc(q)}</li>`).join("")}</ol>`;
    ttSeen.add(i);
    let t = "";
    if (ttSeen.size === SCENARIOS.length) t = "# all six drawn. Write your own next: the best scenarios are the ones that nearly happened.";
    else if (i === ttLast) t = "# the same scenario again. Run it anyway: the second time round is usually faster.";
    ttLast = i;
    $("tt-note").textContent = t;
  }

  // --------------------------------------------------------------------------- console hint
  function consoleHint() {
    console.log("%cBackups and Ransomware", "font: 700 24px monospace; color: #ff2e88; text-shadow: 0 0 8px #ff2e88");
    console.log("%cYou opened the developer console on a talk about backups. Bonus tip: this week, pick one file, restore it from your backup into a different folder, and open it. That ten-minute test is worth more than another backup.", "font: 14px monospace; color: #00f0ff");
  }

  function start() {
    consoleHint();
    $("hero-in").addEventListener("input", hero); hero();

    for (const b of $("hl-bits").querySelectorAll("button")) b.addEventListener("click", () => { hlBits = +b.dataset.v; hopeless(); });
    for (const b of $("hl-rate").querySelectorAll("button")) b.addEventListener("click", () => { hlExp = +b.dataset.v; hopeless(); });
    hopeless();

    click("ss-del", () => syncEvent("delete")); click("ss-lock", () => syncEvent("lock"));
    click("ss-reset", () => { ss = { ev: null, restored: false }; $("ss-days").value = 3; syncDraw(); });
    click("ss-restore", () => {
      if (!ss.ev) { $("ss-note").textContent = "# nothing has gone wrong yet: press one of the first two buttons."; return; }
      ss.restored = true; syncDraw();
    });
    $("ss-days").addEventListener("input", syncDraw);
    syncDraw();

    bdLoad();
    $("bd-opts").addEventListener("change", (e) => {
      const b = e.target.closest("[data-k]"); if (!b) return;
      const s = new Set(bd.sel), k = b.dataset.k; if (b.checked) s.add(k); else s.delete(k);
      bdSet(COPIES.map((c) => c.k).filter((x) => s.has(x)));
      const nb = $("bd-opts").querySelector(`[data-k="${k}"]`); if (nb) nb.focus(); // keep keyboard focus after the redraw
    });
    for (const b of $("bd-presets").querySelectorAll("button")) b.addEventListener("click", () => bdSet(PRESETS[b.dataset.p]));
    $("bd-tested").addEventListener("change", (e) => { bd.tested = e.target.checked; bdSave(); bdDraw(); });
    bdDraw();

    $("vr-days").addEventListener("input", versions);
    for (const b of $("vr-presets").querySelectorAll("button")) b.addEventListener("click", () => { $("vr-days").value = b.dataset.d; versions(); });
    versions();

    $("ky-list").addEventListener("click", (e) => {
      const b = e.target.closest("[data-z]");
      if (b) { kyPick[+b.dataset.i] = b.dataset.z; kyChecked = false; $("ky-note").textContent = ""; keysDraw(); }
    });
    click("ky-check", keysCheck); click("ky-reset", keysReset);
    keysDraw();

    restoreTest();

    for (const b of $("rs-size").querySelectorAll("button")) b.addEventListener("click", () => { rsSize = +b.dataset.v; restoreTime(); });
    for (const b of $("rs-link").querySelectorAll("button")) b.addEventListener("click", () => { rsRate = +b.dataset.v; rsName = b.dataset.n; restoreTime(); });
    restoreTime();

    for (const b of $("bdy-setup").querySelectorAll("button")) b.addEventListener("click", () => { bySetup = +b.dataset.v; badDay(); });
    for (const b of $("bdy-when").querySelectorAll("button")) b.addEventListener("click", () => { byDays = +b.dataset.v; badDay(); });
    badDay();

    click("tt-draw", tabletop);
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
})();
