/* app.js - the live demos for "Logging, Monitoring and Incident Response".
   Everything here is a simulation in your browser: the logs, accounts, addresses and incidents are made up, and nothing you type is sent anywhere.
   The logic and data are in logs.js (window.Logs); the hash chain uses the real SHA-256 and HMAC-SHA-256 from ../../shared/crypto.js (teaching code only). */
(function () {
  "use strict";
  const L = window.Lab, G = window.Logs;

  // --------------------------------------------------------------------------- helpers
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const sp = (cls, s) => `<span class="${cls}">${esc(s)}</span>`;
  const click = (id, fn) => $(id).addEventListener("click", fn);
  const fmtGB = (n) => (n >= 1000 ? (n / 1000).toFixed(n >= 10000 ? 0 : 1) + " TB" : n >= 100 ? Math.round(n) + " GB" : n >= 10 ? n.toFixed(0) + " GB" : n.toFixed(1) + " GB");
  function store(key, val) {
    try { if (val === undefined) return localStorage.getItem(key); localStorage.setItem(key, val); } catch (e) {}
    return null;
  }
  function segPick(id, fn) {
    const g = $(id), btns = [...g.querySelectorAll("button")];
    let val = (btns.find((b) => b.getAttribute("aria-pressed") === "true") || btns[0]).dataset.v;
    const set = (v) => { val = v; for (const b of btns) b.setAttribute("aria-pressed", String(b.dataset.v === v)); };
    set(val);
    g.addEventListener("click", (e) => { const b = e.target.closest("button"); if (!b) return; set(b.dataset.v); fn(); });
    return { get: () => val, set };
  }
  const randFloat = () => crypto.getRandomValues(new Uint32Array(1))[0] / 4294967296;
  const checkGlyph = { ok: "✓", part: "~", bad: "✗" };
  const checkCls = { ok: "ok", part: "y", bad: "bad" };
  let eggs = {};                                   // which eggs have been shown (so a note doesn't flicker)

  // --------------------------------------------------------------------------- title: the log linter
  function lintHtml(r) {
    const rows = r.checks.map((c) => `<span class="lr"><b class="${checkCls[c.state]}">${checkGlyph[c.state]}</b><span class="k">${esc(c.label)}</span><span class="m">${esc(c.note)}</span></span>`).join("");
    const secret = r.secret ? `<span class="lr"><b class="bad">⚠</b><span class="k">secret</span><span class="bad">looks like ${esc(r.secret)}: log the event, not the secret</span></span>` : "";
    const cls = r.score >= 4 ? "ok" : r.score >= 2 ? "y" : "bad";
    return rows + secret + `<span class="lr lr-total">${sp(cls, r.score + " of 5 questions answered")}</span>`;
  }
  function epochNote(n) { return new Date(n * 1000).toISOString().replace(".000Z", "Z"); }
  function hero() {
    const el = $("hero-in"), raw = el.value, t = raw.trim();
    el.style.width = Math.max(12, Math.min(34, el.value.length + 1)) + "ch";
    const r = G.lint(raw);
    $("hero-out").innerHTML = lintHtml(r);
    let note = "# try a line from your own system, or fix this one.";
    if (t === "") note = "# nothing typed, nothing answered: 0 of 5. Honest, at least.";
    else if (/^(event\s*(id)?\s*)?1102$/i.test(t)) note = "# Windows event 1102: \"The audit log was cleared.\" Clearing the log writes a note that it happened, and Microsoft's list ranks it Medium to High.";
    else if (/^(event\s*(id)?\s*)?4624$/i.test(t)) note = "# 4624 is \"An account was successfully logged on\"; 4625 is the failure. The pair you'll meet first in Windows logs.";
    else if (/^(event\s*(id)?\s*)?4625$/i.test(t)) note = "# 4625 is \"An account failed to log on\"; 4624 is the success. A long run of the first, then the second, is a story.";
    else if (t === "0") note = `# Unix time 0 is ${epochNote(0)}, the epoch. A log stamped 1970 usually means a clock that never got set.`;
    else if (t === "1700000000") note = `# Unix time 1,700,000,000 is ${epochNote(1700000000)}. Epoch seconds are always UTC, which makes them an easy timestamp to get right.`;
    else if (t === "2147483647") note = `# 2,147,483,647 is ${epochNote(2147483647)}: where signed 32-bit Unix time runs out.`;
    else if (/^(big yellow )?taxi$/i.test(t)) note = "# \"Big Yellow Taxi\" was the name State's SOC gave a custom alert, per the CSRB report. It's also a Joni Mitchell song about not knowing what you've got until it's gone, which is also true of logs.";
    else if (r.secret) note = "# a secret in a log line: anyone who can read the log can use it. Record that a login failed, not what was typed.";
    else if (r.score === 5) note = "# 5 of 5: your 3 a.m. self thanks you.";
    else if (r.score === 0) note = "# 0 of 5: a fine message, but not yet a log line. Who did what, when, from where, and did it work?";
    else if (r.score >= 4) note = "# nearly there. Check which question is still unanswered.";
    $("hero-note").textContent = note;
  }

  // --------------------------------------------------------------------------- slide 4: five questions
  function qSamples() {
    for (const box of document.querySelectorAll("#q-samples .sample")) {
      const line = box.dataset.line, r = G.lint(line);
      box.querySelector("pre").textContent = line;
      const sc = box.querySelector(".score");
      sc.textContent = r.score + " of 5";
      sc.className = "score " + (r.score >= 4 ? "ok" : r.score >= 2 ? "y" : "bad");
    }
  }
  function qOwn() {
    const r = G.lint($("q-in").value);
    $("q-chips").innerHTML = r.checks.map((c) => `<span class="chip chip-${checkCls[c.state]}" title="${esc(c.note)}">${checkGlyph[c.state]} ${esc(c.label)}</span>`).join("") + (r.secret ? `<span class="chip chip-bad">⚠ ${esc(r.secret)}</span>` : "") + `<span class="chip-score">${r.score} of 5</span>`;
  }

  // --------------------------------------------------------------------------- slide 5: what to log first
  const WL_DEFAULT = ["idp", "cloud", "endpoint"];
  function wlBuild() {
    $("wl-body").innerHTML = G.SOURCES.map((s) => `<tr><td><input type="checkbox" id="wl-${s.id}" data-id="${s.id}" ${WL_DEFAULT.includes(s.id) ? "checked" : ""} aria-label="${esc(s.name)}"></td><td><label for="wl-${s.id}">${esc(s.name)}</label></td><td class="q">${esc(s.q)}</td><td class="num">${s.gb}</td></tr>`).join("");
    $("wl-body").addEventListener("change", wlUpdate);
    for (const id of ["wl-staff", "wl-hot", "wl-total"]) $(id).addEventListener("input", wlUpdate);
  }
  function wlUpdate() {
    const sel = [...document.querySelectorAll("#wl-body input:checked")].map((i) => i.dataset.id);
    let staff = Number($("wl-staff").value); if (!Number.isFinite(staff) || staff < 1) staff = 500;
    let hot = Number($("wl-hot").value), total = Number($("wl-total").value);
    if (total < hot) { total = hot; $("wl-total").value = String(total); }
    $("wl-hot-o").textContent = hot; $("wl-total-o").textContent = total;
    const b = G.budget(sel, staff, hot, total);
    $("wl-day").textContent = fmtGB(b.perDay);
    $("wl-hotgb").textContent = fmtGB(b.hot);
    $("wl-totalgb").textContent = fmtGB(b.total);
    $("wl-steps").innerHTML = G.STEPS.map((st) => { const seen = st.by.some((x) => sel.includes(x)); return `<span class="st ${seen ? "seen" : "dark"}"><b>${seen ? "✓" : "✗"}</b>${esc(st.name)}</span>`; }).join("");
    let note;
    if (!sel.length) note = "# nothing selected: you could reconstruct none of the six steps. Quiet, and blind.";
    else if (b.blind.length) note = `# dark: ${b.blind.join(", ")}. Which source would light ${b.blind.length > 1 ? "them" : "it"} up?`;
    else note = "# all six steps can be reconstructed. Now check the retention, and that the sources really are sending.";
    $("wl-note").textContent = note;
  }

  // --------------------------------------------------------------------------- slide 6: clocks
  let ckSeen = new Set();
  function ckRender(mode) {
    ckSeen.add(mode);
    const { rows, isTrue } = G.orderEvents(mode);
    $("ck-list").innerHTML = rows.map((r, i) => {
      const trueIdx = G.TIME_EVENTS.findIndex((e) => e.id === r.ev.id) + 1;
      const moved = trueIdx !== i + 1;
      return `<li class="ck-row${moved ? " off" : ""}"><span class="n">${i + 1}</span><span class="w">${esc(r.ev.written)}</span><span class="h">${esc(r.ev.host)}</span><span class="t">${esc(r.ev.text)}</span><span class="b">${moved ? `<i>was ${trueIdx}</i>` : ""}</span></li>`;
    }).join("");
    const v = $("ck-verdict");
    if (mode === "raw") { v.className = "verdict bad"; v.textContent = "As written: a file is read and copied before dana signs in, and the VPN session starts five hours earlier than anything else. A timeline built on this tells the wrong story."; }
    else if (mode === "zone") { v.className = "verdict y"; v.textContent = "Better: the VPN session now lines up. But the file server's clock is seven minutes slow, so its events still appear before the sign-in."; }
    else { v.className = "verdict ok"; v.textContent = isTrue ? "True order: VPN session, sign-in, file read, new account, logging off, bulk copy. Nothing changed but the clocks." : ""; }
    if (ckSeen.size === 3 && mode === "drift") v.textContent += " # The same six events, three different stories. Fix the clocks first.";
  }

  // --------------------------------------------------------------------------- slide 7: log explorer
  const lx = { q: "", flags: new Set() };
  function lxRender() {
    const rows = G.search(G.LOG, lx.q);
    $("lx-rows").innerHTML = rows.map((e) => {
      const flagged = lx.flags.has(e.id);
      return `<tr data-id="${e.id}" class="${flagged ? "flag" : ""}${e.outcome === "failure" ? " fail" : ""}"><td><button type="button" class="fl" aria-pressed="${flagged}" aria-label="Flag row ${e.id}">${flagged ? "●" : "○"}</button></td><td class="mono">${esc(e.t.slice(5, 19).replace("T", " "))}</td><td>${esc(e.host)}</td><td>${esc(e.user)}</td><td>${esc(e.action)}</td><td class="o-${esc(e.outcome)}">${esc(e.outcome)}</td><td class="mono">${esc(e.src)}</td><td class="d" title="${esc(e.detail)}">${esc(e.detail)}</td></tr>`;
    }).join("");
    let c = `${rows.length} of ${G.LOG.length} events shown`;
    const q = lx.q.trim().toLowerCase();
    if (/\btaxi\b/.test(q)) c += ` # "Big Yellow Taxi" was State's custom alert name in the CSRB report. It matches nothing here: you'd search your own logs for your own rule names.`;
    else if (/1\s*=\s*1/.test(q)) c += " # not SQL: this search is plain substring matching, so there's nothing to inject.";
    $("lx-count").textContent = c;
    $("lx-flags").textContent = lx.flags.size + " flagged";
    if (lx.flags.size >= 30 && !eggs.flagAll) { eggs.flagAll = 1; $("lx-result").innerHTML = `<p class="comment"># flagged ${lx.flags.size} rows: that's what an alert that fires on everything looks like. Narrow it down.</p>`; }
  }
  function lxCheck() {
    const r = G.checkCase([...lx.flags]);
    if (!lx.flags.size) { $("lx-result").innerHTML = `<p class="comment">Flag some rows first.</p>`; return; }
    const found = r.found.map((n) => `<li class="ok" title="${esc(G.STORY[n].why)}"><b>✓</b> ${esc(G.STORY[n].title)}</li>`).join("");
    const missed = r.missed.map((n) => `<li class="m"><b>?</b> ${esc(G.STORY[n].hint)}</li>`).join("");
    const why = r.found.length ? `<details class="lx-why"><summary>Why each step matters</summary><ul>${r.found.map((n) => `<li><b>${esc(G.STORY[n].title)}.</b> ${esc(G.STORY[n].why)}</li>`).join("")}</ul></details>` : "";
    let head = `<p class="verdict ${r.found.length === 8 ? "ok" : "y"}">${r.found.length} of 8 steps found` + (r.falseFlags ? `, ${r.falseFlags} flag${r.falseFlags === 1 ? "" : "s"} on ordinary activity` : ", no false flags") + `</p>`;
    let egg = "";
    if (r.found.length === 8 && !r.falseFlags) egg = `<p class="comment"># eight of eight, no false flags: a clean timeline. Now write the rule that would have woken someone at 01:41.</p>`;
    $("lx-result").innerHTML = head + `<ul class="lx-story">${found}${missed}</ul>` + why + egg;
  }
  function lxInit() {
    $("lx-q").addEventListener("input", () => { lx.q = $("lx-q").value; lxRender(); });
    $("lx-chips").addEventListener("click", (e) => { const b = e.target.closest(".chip"); if (!b) return; $("lx-q").value = b.dataset.q; lx.q = b.dataset.q; lxRender(); });
    click("lx-clear", () => { $("lx-q").value = ""; lx.q = ""; lx.flags.clear(); eggs.flagAll = 0; $("lx-result").innerHTML = ""; lxRender(); });
    $("lx-rows").addEventListener("click", (e) => { const tr = e.target.closest("tr"); if (!tr) return; const id = Number(tr.dataset.id); if (lx.flags.has(id)) lx.flags.delete(id); else lx.flags.add(id); lxRender(); });
    click("lx-check", lxCheck);
    lxRender();
  }

  // --------------------------------------------------------------------------- slide 8: tamper-evident chain (real SHA-256 / HMAC-SHA-256)
  const ch = { kind: "plain", key: null, orig: [], cur: [], anchor: "", last: "reset", anchorOn: true };
  const CH_EDIT = "03:15:20Z audit logging reviewed by=dana";
  function chBuild() {
    ch.key = ch.kind === "hmac" ? ch.key || L.randBytes(16) : null;
    ch.orig = G.chainBuild(G.CHAIN_TEXTS, ch.key);
    ch.anchor = ch.orig[ch.orig.length - 1].hash;
  }
  function chApply() {
    const o = ch.orig;
    ch.cur = ch.last === "edit" ? G.attack.editText(o, 2, CH_EDIT)
      : ch.last === "fix" ? G.attack.editFixHash(o, 2, CH_EDIT)
      : ch.last === "rewrite" ? G.attack.rewriteAll(o, 2, CH_EDIT)
      : ch.last === "delete" ? G.attack.deleteEntry(o, 2)
      : ch.last === "cut" ? G.attack.truncate(o, 4)
      : o.map((e) => ({ ...e }));
  }
  function chRender() {
    const v = G.chainVerify(ch.cur, ch.key, ch.anchorOn ? ch.anchor : null);
    $("ch-rows").innerHTML = ch.cur.map((e, i) => {
      const r = v.rows[i], tampered = ch.last !== "reset" && (e.text !== (ch.orig[i] || {}).text || e.hash !== (ch.orig[i] || {}).hash);
      return `<tr class="${r.ok ? "" : "bad"}"><td>${i + 1}</td><td class="mono">${esc(e.text)}</td><td class="mono">${e.prev.slice(0, 8)}</td><td class="mono ${tampered ? "tam" : ""}">${e.hash.slice(0, 8)}</td><td class="ch-st">${r.ok ? `<b class="ok">✓</b>` : `<b class="bad">✗</b><small>${esc(r.why)}</small>`}</td></tr>`;
    }).join("");
    const vd = $("ch-verdict"), bad = v.rows.findIndex((r) => !r.ok);
    let egg = "";
    const WHY = { "link broken": "its link to the entry before is broken", "hash mismatch": "its hash doesn't match its text" };
    if (bad >= 0) { vd.className = "verdict bad"; vd.textContent = `Tampering detected at entry ${ch.cur[bad].n}: ${WHY[v.rows[bad].why] || v.rows[bad].why}.`; }
    else if (v.headOk === false) { vd.className = "verdict bad"; vd.textContent = "Every link checks out, but the latest hash no longer matches the copy kept elsewhere: something was rewritten or cut off."; }
    else if (v.headOk === true) { vd.className = "verdict ok"; vd.textContent = ch.last === "reset" ? "All six entries verify, and the latest hash matches the saved copy." : "All entries verify."; }
    else { vd.className = "verdict y"; vd.textContent = ch.last === "reset" ? "All six entries verify." : "Every link checks out. Without a copy of the latest hash kept elsewhere, a rewrite or a cut-off end would look exactly like this."; }
    if (ch.last === "rewrite" && ch.kind === "plain" && ch.anchorOn && v.internallyOk && v.headOk === false) egg = "# internally consistent, and still caught: the saved head doesn't match. The anchor is what makes it work.";
    else if (ch.last === "rewrite" && ch.kind === "hmac") egg = "# the keyed chain: without the key, the attacker's recomputed hashes don't verify.";
    else if (ch.last === "cut" && !ch.anchorOn) egg = "# cut off the end and the chain still checks out: only the saved head tells you something's missing.";
    else if (ch.last === "rewrite" && ch.kind === "plain" && !ch.anchorOn) egg = "# a perfect-looking chain, and a rewritten one. This is why the plain chain needs an anchor.";
    $("ch-egg") && ($("ch-egg").textContent = egg);
  }
  function chInit() {
    chBuild(); chApply(); chRender();
    segPick("ch-kind", () => { ch.kind = $("ch-kind").querySelector("[aria-pressed=true]").dataset.v; ch.key = null; chBuild(); chApply(); chRender(); });
    $("ch-anchor").addEventListener("change", () => { ch.anchorOn = $("ch-anchor").checked; chRender(); });
    $("ch-acts").addEventListener("click", (e) => { const b = e.target.closest("button"); if (!b) return; ch.last = b.dataset.act; chApply(); chRender(); });
  }

  // --------------------------------------------------------------------------- slide 9: spot the leak
  const lkAns = []; let lkLast = -1;
  function lkRender() {
    $("lk-list").innerHTML = G.LEAKS.map((l, i) => {
      const a = lkAns[i], shown = esc(l.line).replace(/\\n/g, `<i class="nl">⏎</i>\n`);
      const badge = a === undefined ? "" : `<span class="lk-badge ${a === l.leak ? "ok" : "bad"}">${a === l.leak ? "✓ right" : "✗ " + (l.leak ? "it leaks" : "it's fine")}</span>`;
      return `<div class="lk-item${a !== undefined ? " done" : ""}${i === lkLast ? " cur" : ""}" data-i="${i}"><pre class="term">${shown}</pre><div class="lk-btns">${a === undefined ? `<button type="button" class="btn btn-ghost btn-sm" data-i="${i}" data-a="0">Fine</button><button type="button" class="btn btn-ghost btn-sm" data-i="${i}" data-a="1">Leaks or forged</button>` : badge}</div></div>`;
    }).join("");
    const cur = lkLast >= 0 ? G.LEAKS[lkLast] : null;
    $("lk-panel").innerHTML = cur ? `<b class="${lkAns[lkLast] === cur.leak ? "ok" : "bad"}">${lkAns[lkLast] === cur.leak ? "✓" : "✗"} ${cur.leak ? "It leaks or can be forged." : "That one's fine."}</b> ${esc(cur.why)}${cur.fix ? `<pre class="term lk-fix">${esc(cur.fix)}</pre>` : ""}` : `<span class="m">Call each line, then the reason appears here. Click an answered line to read it again.</span>`;
    const n = lkAns.filter((a) => a !== undefined).length, right = G.LEAKS.filter((l, i) => lkAns[i] === l.leak).length, v = $("lk-score");
    if (n < G.LEAKS.length) { v.className = "verdict"; v.textContent = n ? `${right} right so far, ${G.LEAKS.length - n} to go.` : "Call each line before you reveal it."; }
    else { v.className = "verdict " + (right === G.LEAKS.length ? "ok" : "y"); v.textContent = `${right} of ${G.LEAKS.length}.` + (right === G.LEAKS.length ? " # six of six: log the event, never the secret." : " The ones that surprise people are usually the failed login and the newline."); }
  }
  function lkInit() {
    $("lk-list").addEventListener("click", (e) => {
      const b = e.target.closest("button[data-i]");
      if (b) { lkAns[Number(b.dataset.i)] = b.dataset.a === "1"; lkLast = Number(b.dataset.i); lkRender(); return; }
      const it = e.target.closest(".lk-item.done"); if (it) { lkLast = Number(it.dataset.i); lkRender(); }
    });
    lkRender();
  }

  // --------------------------------------------------------------------------- slide 12: good first alerts
  const ALERTS = [
    { id: "spray", name: "Password spray", when: "queue, page if one succeeds", catches: "One address failing against many accounts, a few tries each.", needs: "Identity provider sign-in logs, with the source address.", fp: "Shared kiosks, guest Wi-Fi, office NAT, a vulnerability scanner.", first: "Did any account succeed from that address afterwards? If so, treat it as compromised: revoke its sessions, reset it, and review what it did.", att: [["T1110.003", "Password Spraying"]] },
    { id: "travel", name: "Impossible or unusual sign-in", when: "queue, page for admins", catches: "One account in two places no person could travel between in the time, or an admin signing in from somewhere it never has. (ACSC's definition of impossible travel.)", needs: "Identity logs with a location for each sign-in.", fp: "VPNs and mobile carriers, a traveller (check for a travel notice), a shared account.", first: "Ask the person through another channel (not email from the same account). If you can't reach them, revoke sessions and require a fresh MFA sign-in.", att: [["T1078", "Valid Accounts"]] },
    { id: "admin", name: "New admin account or privilege", when: "page, unless there's a ticket", catches: "An account created, added to an admin group or role, or a dormant account re-enabled, especially with administrator rights.", needs: "Directory and identity change logs; cloud IAM change events. On Windows, events 4720 (account created) and 4728 or 4732 (added to a group).", fp: "Planned joiners and projects: look for the change ticket.", first: "Find the ticket. No ticket, or the requester denies it: disable the account (don't delete it), preserve the logs, and widen the search to what its creator did.", att: [["T1136", "Create Account"]] },
    { id: "logging", name: "Logging switched off, cleared, or silent", when: "page", catches: "A cloud trail stopped or deleted, a Windows audit log cleared, audit policy changed, a security tool's configuration changed, or a source that simply stops sending.", needs: "Cloud audit logs; endpoint logs (Windows event 1102 for a cleared log, 4719 for a policy change); a heartbeat per source so silence is visible.", fp: "Planned maintenance, a rebuilt server: check the ticket.", first: "Treat it as an incident until explained. Who did it, from where, and what else did that account do around then? Restore logging and copy what you have.", att: [["T1685.002", "Disable or Modify Cloud Log"], ["T1685.005", "Clear Windows Event Logs"]] },
    { id: "mass", name: "Mass file changes or a bulk export", when: "page if it's growing", catches: "Thousands of files renamed or changed in minutes (ransomware's signature), a bulk read, a large download or outbound transfer.", needs: "File server or endpoint file events, cloud storage logs, network flow or proxy logs.", fp: "Backups, migrations, antivirus scans: baseline them by account and time of day.", first: "Isolate the host (don't power it off), identify the account, and check that your backups are intact before anything else.", att: [["T1486", "Data Encrypted for Impact"]] },
  ];
  let faSel = 0;
  function faRender() {
    $("fa-list").innerHTML = ALERTS.map((a, i) => `<button type="button" class="fa-btn" data-i="${i}" aria-pressed="${i === faSel}"><b>${esc(a.name)}</b><small>${esc(a.when)}</small></button>`).join("");
    const a = ALERTS[faSel];
    $("fa-detail").innerHTML = `<h3>${esc(a.name)}</h3>
      <div class="fa-row"><b>Catches</b><span>${esc(a.catches)}</span></div>
      <div class="fa-row"><b>Needs</b><span>${esc(a.needs)}</span></div>
      <div class="fa-row"><b>Often a false alarm when</b><span>${esc(a.fp)}</span></div>
      <div class="fa-row"><b>First look</b><span>${esc(a.first)}</span></div>
      <div class="fa-row"><b>ATT&amp;CK</b><span>${a.att.map((t) => `<code>${t[0]}</code> ${esc(t[1])}`).join(" · ")}</span></div>`;
  }
  function faInit() {
    $("fa-list").addEventListener("click", (e) => { const b = e.target.closest(".fa-btn"); if (!b) return; faSel = Number(b.dataset.i); faRender(); });
    faRender();
  }

  // --------------------------------------------------------------------------- slide 13: the tuning lab
  const TU_PRESETS = [
    { name: "Lockout: 5 in 10 min", rule: "account", n: 5, w: 10 },
    { name: "Raise it: 15 in 10 min", rule: "account", n: 15, w: 10 },
    { name: "Spray: 10 in 15 min", rule: "source", n: 10, w: 15 },
    { name: "Spray: 10 in 3 h", rule: "source", n: 10, w: 180 },
    { name: "Both: 10 in 3 h", rule: "both", n: 10, w: 180 },
    { name: "Every failure pages", rule: "account", n: 1, w: 1 },
  ];
  const tu = { sim: null, rule: null };
  const DAYN = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
  function tuRender() {
    const rule = tu.rule.get(), n = Number($("tu-n").value), w = Number($("tu-w").value);
    $("tu-n-l").innerHTML = rule === "account" ? `Alert at <output id="tu-n-o">${n}</output> failures` : `Alert at <output id="tu-n-o">${n}</output> different accounts from one address`;
    $("tu-w-o").textContent = w >= 60 ? (w % 60 === 0 ? w / 60 + " hour" + (w === 60 ? "" : "s") : (w / 60).toFixed(1) + " hours") : w + " minute" + (w === 1 ? "" : "s");
    const r = rule === "both" ? G.runBoth(tu.sim, n, w) : G.runRule(tu.sim, rule, n, w), names = r.caught.map((i) => tu.sim.attacks[i].name);
    $("tu-rule-note").textContent = rule === "both" ? "Both: the per-address rule below, plus 15 failures on one account in 10 minutes." : "";
    $("tu-caught").textContent = r.caught.length + " of 3";
    $("tu-caught-l").textContent = r.caught.length ? "caught: " + names.map((x) => x.replace(/ \(.*$/, "")).join(", ") : "real attacks caught";
    $("tu-false").textContent = r.falseAlerts.toLocaleString("en-US");
    $("tu-hours").textContent = (Math.round(r.falseAlerts * 10 / 6) / 10).toLocaleString("en-US") + " h";
    const max = Math.max(1, ...r.days.map((d) => d.f + d.t));
    $("tu-days").innerHTML = r.days.map((d, i) => `<div class="day"><span class="bar"><i class="f" style="height:${(d.f / max) * 100}%"></i><i class="t" style="height:${(d.t / max) * 100}%"></i></span><b>${d.f + d.t}</b><small>${DAYN[i]}</small></div>`).join("");
    const fat = G.fatigue(r.perDay), missed = [1, 2, 3].filter((i) => !r.caught.includes(i)).map((i) => tu.sim.attacks[i].name.replace(/ \(.*$/, ""));
    const v = $("tu-verdict");
    let text;
    if (r.caught.length === 3 && r.falseAlerts <= 2) { text = `All three caught, with ${r.falseAlerts} false alert${r.falseAlerts === 1 ? "" : "s"} all week: ${fat.label}.`; v.className = "verdict ok"; }
    else if (!r.caught.length) { text = `Blind to all three attacks. False alerts: ${r.falseAlerts}.`; v.className = "verdict bad"; }
    else { text = `Catches ${names.map((x) => x.replace(/ \(.*$/, "")).join(" and ")}; misses ${missed.join(" and ")}. ${fat.label}.`; v.className = "verdict " + (fat.level >= 2 ? "bad" : "y"); }
    v.textContent = text;
    let note = "";
    if (rule === "account" && n === 1 && w === 1) note = "# every single failed login pages someone. Congratulations: you've invented alert fatigue.";
    else if (r.caught.length === 3 && r.falseAlerts <= 2) note = "# all three attacks, and a quiet week. That's a rule people will read.";
    else if (rule === "source" && n <= 2 && r.falseAlerts > 20) note = "# two accounts from one address is just a shared computer. Raise the number, or add context.";
    $("tu-note").textContent = note;
  }
  function tuInit() {
    tu.sim = G.authSim(2026);
    tu.rule = segPick("tu-rule", () => { tuRender(); });
    $("tu-presets").innerHTML = TU_PRESETS.map((p, i) => `<button type="button" class="chip" data-i="${i}">${esc(p.name)}</button>`).join("");
    $("tu-presets").addEventListener("click", (e) => { const b = e.target.closest(".chip"); if (!b) return; const p = TU_PRESETS[Number(b.dataset.i)]; tu.rule.set(p.rule); $("tu-n").value = p.n; $("tu-w").value = p.w; tuRender(); });
    $("tu-n").addEventListener("input", tuRender); $("tu-w").addEventListener("input", tuRender);
    tuRender();
  }

  // --------------------------------------------------------------------------- slide 14: coverage map
  function cvBuild() {
    $("cv-src").innerHTML = G.SOURCES.map((s) => `<label class="check"><input type="checkbox" data-id="${s.id}" ${WL_DEFAULT.includes(s.id) ? "checked" : ""}> ${esc(s.name.replace(/ \(.*\)/, ""))}</label>`).join("");
    $("cv-src").addEventListener("change", cvUpdate);
  }
  function cvUpdate() {
    const sel = [...document.querySelectorAll("#cv-src input:checked")].map((i) => i.dataset.id), cv = G.coverage(sel);
    $("cv-grid").innerHTML = cv.map((t) => `<div class="tile ${t.level}"><small>${t.id}</small><b>${esc(t.name)}</b><span>${t.level === "good" ? "good view" : t.level === "some" ? "some view" : "dark"}</span></div>`).join("");
    const g = cv.filter((t) => t.level === "good").length, s = cv.filter((t) => t.level === "some").length, d = cv.filter((t) => t.level === "dark").length;
    let note = `${g} tactics with a good view, ${s} with some, ${d} dark.`;
    if (!sel.length) note = "# no logs: every tactic dark. (Also a very quiet week.)";
    else if (sel.length === G.SOURCES.length) note = "# seven sources, and Reconnaissance and Resource Development are still dark: most of that happens before an attacker touches your systems.";
    $("cv-note").textContent = note;
  }

  // --------------------------------------------------------------------------- slide 16: lifecycle
  const PHASES = [
    { n: "Prepare", what: "Agree roles and contacts, collect the right logs, write a short runbook, and practise (that's tonight's tabletop). Set up a way to talk that doesn't depend on the systems that might be compromised.", logs: "Central, time-synced logs kept long enough, and an asset list so you know what a host is.", mistake: "Finding out mid-incident that nobody is allowed to isolate a server at 3 a.m." },
    { n: "Detect", what: "Turn signals into a decision: is this an incident? Triage it, scope it, and name an incident lead.", logs: "Alerts with context, identity and cloud logs, endpoint telemetry, and a person who looks.", mistake: "Calling an alert a false positive because it's late. (An approved MFA prompt isn't proof of anything.)" },
    { n: "Contain", what: "Stop the harm spreading with the smallest action that works: isolate, disable, revoke sessions, block. Preserve evidence as you go.", logs: "Copy the logs first, capture what's volatile, and record every action with a UTC time.", mistake: "Powering things off and losing memory, or containing so widely the business stops." },
    { n: "Eradicate", what: "Remove the attacker's way in and every foothold: patch, rebuild, remove persistence, rotate every secret they could have seen.", logs: "Search every system for what you've learned, not only the one you found.", mistake: "Declaring victory after removing one foothold." },
    { n: "Recover", what: "Restore service from known-good, in a deliberate order, and watch closely for a return.", logs: "Extra monitoring on what you've restored, and confirmation that logging works again.", mistake: "Restoring onto a machine the attacker can still get into." },
    { n: "Learn", what: "A blameless review: timeline, decisions, what helped, what hurt, and changes with owners and dates. Share lessons as they appear.", logs: "The scribe's timeline, and a list of the logs you wished you'd had.", mistake: "Writing a report nobody acts on." },
  ];
  let lcSel = 0;
  function lcRender() {
    $("lc-steps").innerHTML = PHASES.map((p, i) => `<button type="button" class="lc-btn" data-i="${i}" aria-pressed="${i === lcSel}"><small>${i + 1}</small><b>${p.n}</b></button>`).join("");
    const p = PHASES[lcSel];
    $("lc-detail").innerHTML = `<h3>${p.n}</h3><div class="fa-row"><b>What happens</b><span>${esc(p.what)}</span></div><div class="fa-row"><b>Logs and evidence</b><span>${esc(p.logs)}</span></div><div class="fa-row"><b>A common mistake</b><span>${esc(p.mistake)}</span></div>`;
  }
  function lcInit() { $("lc-steps").addEventListener("click", (e) => { const b = e.target.closest(".lc-btn"); if (!b) return; lcSel = Number(b.dataset.i); lcRender(); }); lcRender(); }

  // --------------------------------------------------------------------------- slide 17: whose job?
  const ROLES = ["Lead", "Technical", "Comms", "Scribe"], ROLE_FULL = ["incident lead", "technical lead", "communications lead", "scribe"];
  const TASKS = [
    { t: "Decide whether to isolate the file server.", a: 0, why: "A decision with a business cost. The lead decides, with the technical lead's advice." },
    { t: "Pull the last 24 hours of VPN logs.", a: 1, why: "Hands-on investigation: the technical lead, or someone they direct." },
    { t: "Tell staff what is happening.", a: 2, why: "One clear voice to the organisation: the communications lead." },
    { t: "Log: 03:41 UTC, Dana's account disabled.", a: 3, why: "The timeline is the scribe's job: UTC time, what, who. It's what makes a handover possible." },
    { t: "Ask counsel who outside must be told.", a: 0, why: "A leadership call: the lead brings in counsel. Comms drafts afterwards." },
    { t: "Capture a laptop's memory before isolating it.", a: 1, why: "Evidence collection is technical work, done before anything changes the machine." },
  ];
  const rl = []; let rlLast = -1;
  function rlRender() {
    $("rl-tasks").innerHTML = TASKS.map((k, i) => {
      const a = rl[i];
      return `<div class="rl-task${a !== undefined ? " done" : ""}${i === rlLast ? " cur" : ""}" data-i="${i}"><p>${esc(k.t)}</p><div class="rl-btns">${ROLES.map((r, j) => `<button type="button" class="btn btn-ghost btn-sm${a === j ? (j === k.a ? " good" : " wrong") : a !== undefined && j === k.a ? " good" : ""}" data-i="${i}" data-j="${j}" ${a !== undefined ? "disabled" : ""}>${r}</button>`).join("")}</div></div>`;
    }).join("");
    const cur = rlLast >= 0 ? TASKS[rlLast] : null;
    $("rl-note").innerHTML = cur ? `<b class="${rl[rlLast] === cur.a ? "ok" : "bad"}">${rl[rlLast] === cur.a ? "✓ Yes." : "✗ Usually the " + ROLE_FULL[cur.a] + "."}</b> ${esc(cur.why)}` : `<span class="m">Pick a role for each task; the reason appears here. Click an answered task to read it again.</span>`;
    const n = rl.filter((x) => x !== undefined).length, right = TASKS.filter((k, i) => rl[i] === k.a).length, v = $("rl-score");
    v.className = "verdict" + (n === TASKS.length ? (right === TASKS.length ? " ok" : " y") : "");
    v.textContent = n < TASKS.length ? "Pick the usual owner of each task." : `${right} of ${TASKS.length}.` + (right === TASKS.length ? " # Four hats, and nobody doing everything." : " Several of these have more than one reasonable owner: that's a good thing to discuss.");
  }
  function rlInit() {
    $("rl-tasks").addEventListener("click", (e) => {
      const b = e.target.closest("button[data-i]");
      if (b) { rl[Number(b.dataset.i)] = Number(b.dataset.j); rlLast = Number(b.dataset.i); rlRender(); return; }
      const t = e.target.closest(".rl-task.done"); if (t) { rlLast = Number(t.dataset.i); rlRender(); }
    });
    rlRender();
  }

  // --------------------------------------------------------------------------- slide 18: containment choices
  const CONTAIN = [
    { a: "Disable the account", s: 2, e: 3, t: 2, b: 1, note: "Stops new sign-ins, not sessions and tokens that already exist: revoke those too. Disable, don't delete: the account is evidence." },
    { a: "Revoke sessions and tokens, reset credentials", s: 3, e: 3, t: 2, b: 1, note: "Cuts off access that's already in use. The person is signed out everywhere, which is a small price. Do it for every account you think was touched." },
    { a: "Isolate the host from the network", s: 3, e: 3, t: 2, b: 2, note: "Using endpoint-security network containment or a switch port keeps memory and disk intact. Usually the best first move for a compromised machine." },
    { a: "Block their address or domain", s: 1, e: 3, t: 3, b: 0, note: "Quick and cheap, and attackers move to another address. A good extra layer, rarely enough on its own." },
    { a: "Power it off", s: 3, e: 1, t: 3, b: 2, note: "Stops everything and loses what's in memory, which may hold how they got in. Reserve it for when damage is actively spreading and you can't isolate." },
    { a: "Watch and wait", s: 0, e: 3, t: 1, b: 0, note: "Lets you learn what they're after, and lets them keep going. CISA's playbook describes monitoring an actor in a sandbox as limited to advanced SOCs with mature capabilities." },
  ];
  let ctSel = 0;
  const dots = (n, good) => `<span class="dots3 ${good ? "g" : "b"}" aria-label="${n} of 3">${"●".repeat(n)}${"○".repeat(3 - n)}</span>`;
  function ctRender() {
    $("ct-rows").innerHTML = CONTAIN.map((c, i) => `<tr data-i="${i}" class="${i === ctSel ? "sel" : ""}" tabindex="0"><td>${esc(c.a)}</td><td>${dots(c.s, true)}</td><td>${dots(c.e, true)}</td><td>${dots(c.t, false)}</td><td>${dots(c.b, false)}</td></tr>`).join("");
    $("ct-note").innerHTML = `<b>${esc(CONTAIN[ctSel].a)}.</b> ${esc(CONTAIN[ctSel].note)}`;
  }
  function ctInit() {
    const pick = (e) => { const tr = e.target.closest("tr[data-i]"); if (!tr) return; ctSel = Number(tr.dataset.i); ctRender(); };
    $("ct-rows").addEventListener("click", pick);
    $("ct-rows").addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); pick(e); } });
    ctRender();
  }

  // --------------------------------------------------------------------------- slides 22-23: the tabletop
  const tt = { scenario: "admin", game: null, shown: 0, picked: null, resultHtml: "", summary: false, timer: null, left: 180, running: false };
  function ttFmt(s) { return Math.floor(s / 60) + ":" + String(s % 60).padStart(2, "0"); }
  function ttTimerReset() { clearInterval(tt.timer); tt.running = false; tt.left = 180; $("tt-timer").textContent = "Discuss: " + ttFmt(tt.left); $("tt-timer").classList.remove("hot"); }
  function ttTimerToggle() {
    if (tt.running) { clearInterval(tt.timer); tt.running = false; return; }
    if (tt.left <= 0) ttTimerReset();
    tt.running = true;
    tt.timer = setInterval(() => {
      tt.left -= 1; $("tt-timer").textContent = tt.left > 0 ? "Discuss: " + ttFmt(tt.left) : "Time! Decide.";
      $("tt-timer").classList.toggle("hot", tt.left <= 30);
      if (tt.left <= 0) { clearInterval(tt.timer); tt.running = false; }
    }, 1000);
  }
  function ttDeal() {
    tt.game = G.ttNew(tt.scenario, G.drawInjects(2, randFloat));
    tt.shown = 0; tt.picked = null; tt.resultHtml = ""; tt.summary = false;
    ttTimerReset(); ttRender();
  }
  const fxName = { spread: "Attacker's reach", evidence: "Evidence kept", disruption: "Disruption", clarity: "Clarity" };
  function ttMeters() {
    const m = tt.game.meters, w = G.ttSummary(tt.game).words;
    $("tt-meters").innerHTML = G.METERS.map((x) => { const v = m[x.id], good = x.good === "high" ? v >= 60 : v <= 35, mid = x.good === "high" ? v >= 40 : v <= 60; return `<div class="meter"><span>${esc(x.name)}</span><b>${esc(w[x.id])}</b><i class="${good ? "g" : mid ? "m" : "b"}" style="width:${v}%"></i></div>`; }).join("");
  }
  function ttRender() {
    const g = tt.game, sc = G.SCENARIOS[g.scenario], opts = $("tt-opts");
    $("tt-eyebrow").textContent = "// TABLETOP EXERCISE 02 · " + sc.title.toUpperCase();
    $("tt-title").textContent = sc.title;
    ttMeters();
    $("tt-log").innerHTML = `<h3>Decisions so far</h3>` + (g.log.length ? `<ol>${g.log.map((l) => `<li><small>${esc(l.time)}${l.kind === "inject" ? " · surprise" : ""}</small> ${esc(l.choice)}</li>`).join("")}</ol>` : `<p class="fine">None yet. The scribe writes each one down with its time.</p>`);
    if (tt.summary) {
      const sm = G.ttSummary(g), m = sm.meters, tidy = m.spread <= 20 && m.evidence >= 80 && m.disruption <= 25 && m.clarity >= 60;
      $("tt-head").textContent = "Exercise over";
      $("tt-text").textContent = sc.title + ": the night is over. Here's how it went.";
      opts.innerHTML = "";
      $("tt-result").innerHTML = `<p class="verdict ${tidy ? "ok" : "y"}">The attacker's reach: ${esc(sm.words.spread)}. Evidence: ${esc(sm.words.evidence)}. Disruption: ${esc(sm.words.disruption)}. Clarity: ${esc(sm.words.clarity)}.</p>` + (tidy ? `<p class="comment"># contained, preserved, calm and clear: the textbook night. Real ones are messier, which is why you practise.</p>` : `<p class="comment">Scores are a prompt for discussion, not a grade. Which decision would you change, and what would you have needed to know?</p>`);
      $("tt-next").hidden = true; $("tt-again").hidden = false; return;
    }
    const st = g.steps[tt.shown];
    $("tt-head").textContent = st.kind === "round" ? `Round ${st.round + 1} of 3 · ${st.time} UTC · ${st.title}` : `Surprise in round ${st.round + 1} · ${st.title}`;
    $("tt-text").textContent = (tt.shown === 0 ? sc.intro + " " : "") + st.text;
    opts.innerHTML = st.options.map((o, i) => `<button type="button" class="tt-opt${tt.picked === i ? " picked" : ""}" data-i="${i}" ${tt.picked !== null ? "disabled" : ""}><b>${"ABCD"[i]}</b><span>${esc(o.t)}</span></button>`).join("");
    $("tt-result").innerHTML = tt.picked !== null ? tt.resultHtml : "";
    $("tt-next").hidden = tt.picked === null; $("tt-next").textContent = g.done ? "Finish ›" : "Next ›"; $("tt-again").hidden = true;
  }
  function ttChoose(i) {
    const g = tt.game, opt = g.steps[tt.shown].options[i];
    clearInterval(tt.timer); tt.running = false;
    const fx = Object.keys(opt.fx).map((k) => { const d = opt.fx[k], goodUp = k === "evidence" || k === "clarity", better = goodUp ? d > 0 : d < 0; return `<span class="fx ${better ? "ok" : "bad"}">${esc(fxName[k])} ${d > 0 ? "+" : "−"}${Math.abs(d)}</span>`; }).join(" ");
    tt.picked = i;
    tt.resultHtml = `<p><b>What happens.</b> ${esc(opt.why)}</p><p class="fxrow">${fx}</p>`;
    tt.game = G.ttChoose(g, i);
    ttRender();
  }
  function ttNext() {
    tt.picked = null; tt.resultHtml = "";
    if (tt.game.done) tt.summary = true; else tt.shown = tt.game.step;
    ttTimerReset(); ttRender();
  }
  function ttInit() {
    $("tt-pick").innerHTML = Object.values(G.SCENARIOS).map((s) => `<button type="button" class="tt-sc" data-id="${s.id}" aria-pressed="${s.id === tt.scenario}"><b>${esc(s.title)}</b><span>${esc(s.intro)}</span></button>`).join("");
    const PRACTISE = { admin: "Containing an administrator account without losing evidence, getting logging back on, and what to tell the CEO when you don't know yet.", ransom: "Isolating a machine without powering it off, restoring from backup without reinfecting, and finding out which notification clocks apply." };
    const intro = () => { $("tt-intro").innerHTML = `<b>What you'll practise</b><span>${esc(PRACTISE[tt.scenario])} Three rounds and two random surprises.</span>`; };
    intro();
    $("tt-pick").addEventListener("click", (e) => { const b = e.target.closest(".tt-sc"); if (!b) return; tt.scenario = b.dataset.id; for (const x of $("tt-pick").children) x.setAttribute("aria-pressed", String(x === b)); intro(); ttDeal(); });
    click("tt-start", () => { ttDeal(); location.hash = "tabletop"; });
    $("tt-opts").addEventListener("click", (e) => { const b = e.target.closest(".tt-opt"); if (!b || tt.picked !== null || tt.summary) return; ttChoose(Number(b.dataset.i)); });
    click("tt-next", ttNext);
    click("tt-again", ttDeal);
    click("tt-timer", ttTimerToggle);
    ttDeal();
  }

  // --------------------------------------------------------------------------- slide 24: first-hour checklist
  const FH = [
    ["scribe", "Start an incident log, in UTC, and name a scribe"],
    ["lead", "Name an incident lead and a technical lead"],
    ["oob", "Move coordination off systems that may be compromised"],
    ["preserve", "Preserve first: copy the relevant logs somewhere safe, and image or snapshot affected systems"],
    ["contain", "Contain the smallest thing that stops the harm"],
    ["logging", "Check that logging is still on, and extend retention for the affected systems"],
    ["creds", "Revoke sessions and rotate credentials for the accounts involved"],
    ["known", "Write down what's known, what's unknown, and what you're assuming"],
    ["tell", "Tell the people who must know: leadership, counsel, your insurer"],
    ["clocks", "Note the time you became aware, and check each notification clock with counsel"],
    ["next", "Set the time of the next update, and keep it"],
    ["rest", "Plan shifts and handovers: tired people make mistakes"],
  ];
  function fhInit() {
    let saved = []; try { saved = JSON.parse(store("ir-first-hour") || "[]"); } catch (e) {}
    $("fh-plan").innerHTML = FH.map(([k, t]) => `<label><input type="checkbox" data-k="${k}" ${saved.includes(k) ? "checked" : ""}> ${esc(t)}</label>`).join("");
    const upd = () => {
      const on = [...document.querySelectorAll("#fh-plan input:checked")].map((i) => i.dataset.k);
      store("ir-first-hour", JSON.stringify(on));
      const v = $("fh-note");
      v.className = "verdict" + (on.length === FH.length ? " ok" : "");
      v.textContent = on.length === FH.length ? "12 of 12. # Hour one, handled. Hour two is a different checklist." : `${on.length} of ${FH.length} ticked.`;
    };
    $("fh-plan").addEventListener("change", upd); upd();
  }

  // --------------------------------------------------------------------------- the console
  function consoleHint() {
    console.log("%cLogging, Monitoring and Incident Response", "font: 700 24px monospace; color: #ff2e88; text-shadow: 0 0 8px #ff2e88");
    console.log("%cThe logic behind the demos is in window.Logs. Try Logs.lint('your own log line'), or build a hash chain with Logs.chainBuild(Logs.CHAIN_TEXTS) and tamper with it.", "font: 14px monospace; color: #00f0ff");
  }

  function start() {
    consoleHint();
    $("hero-in").addEventListener("input", hero); hero();
    qSamples(); $("q-in").addEventListener("input", qOwn); qOwn();
    wlBuild(); wlUpdate();
    segPick("ck-mode", () => ckRender($("ck-mode").querySelector("[aria-pressed=true]").dataset.v)); ckRender("raw");
    lxInit(); chInit(); lkInit(); faInit(); tuInit(); cvBuild(); cvUpdate();
    lcInit(); rlInit(); ctInit(); ttInit(); fhInit();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
})();
