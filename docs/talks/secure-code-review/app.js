/* app.js - the live demos for "Secure Code Review Workshop".
   Every code sample is invented and deliberately flawed. The line checker and the source-to-sink tracer are small text matchers: nothing is
   executed, parsed by a real engine, fetched or sent anywhere. The logic lives in review.js (tested in Node). */
(function () {
  "use strict";
  const R = window.ReviewLab;

  // --------------------------------------------------------------------------- helpers
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  function store(key, val) {
    try { if (val === undefined) return localStorage.getItem(key); localStorage.setItem(key, val); } catch (e) {}
    return null;
  }
  const verdict = (el, cls, text) => { el.className = "verdict " + cls; el.textContent = text; };
  const MARK = { ok: "✓", bad: "✗", y: "!", m: "·" };

  // a short message at the bottom of the screen (eggs and the Eagle Eye badge)
  let toastTimer = 0;
  function toast(title, text) {
    let el = $("toast");
    if (!el) { el = document.createElement("div"); el.id = "toast"; el.className = "toast"; el.setAttribute("role", "status"); document.body.appendChild(el); }
    el.innerHTML = "<b>" + esc(title) + "</b>" + esc(text);
    el.hidden = false; clearTimeout(toastTimer); toastTimer = setTimeout(() => { el.hidden = true; }, 6000);
  }
  // sad trombone, only ever played because someone pressed a button; four falling notes
  function trombone() {
    try {
      const AC = window.AudioContext || window.webkitAudioContext; if (!AC) return;
      const ctx = new AC(), t0 = ctx.currentTime + 0.02;
      [[233, 0.0, 0.32], [220, 0.36, 0.32], [208, 0.72, 0.32], [196, 1.08, 0.9]].forEach(([f, at, len], i) => {
        const o = ctx.createOscillator(), g = ctx.createGain(), lp = ctx.createBiquadFilter();
        o.type = "sawtooth"; lp.type = "lowpass"; lp.frequency.value = 900;
        o.frequency.setValueAtTime(f, t0 + at);
        if (i === 3) { for (let k = 0; k < 6; k++) o.frequency.linearRampToValueAtTime(f * (k % 2 ? 1.02 : 0.97), t0 + at + 0.12 * (k + 1)); }
        g.gain.setValueAtTime(0.0001, t0 + at); g.gain.exponentialRampToValueAtTime(0.12, t0 + at + 0.05); g.gain.exponentialRampToValueAtTime(0.0001, t0 + at + len);
        o.connect(lp); lp.connect(g); g.connect(ctx.destination); o.start(t0 + at); o.stop(t0 + at + len + 0.05);
      });
      setTimeout(() => { try { ctx.close(); } catch (e) {} }, 2600);
    } catch (e) {}
  }

  // --------------------------------------------------------------------------- title: the toy line checker
  function hero() {
    const el = $("hero-in"), v = el.value;
    el.style.width = Math.min(40, Math.max(12, v.length + 1)) + "ch";
    const r = R.scanLine(v), t = v.trim().toLowerCase();
    $("hero-out").innerHTML = `<span class="k">result:</span> ${esc(r.label)}<br><span class="k">why:   </span> ${esc(r.why)}${r.fix ? `<br><span class="k">fix:   </span> ${esc(r.fix)}` : ""}`;
    let n;
    if (r.id === "empty") n = "# nothing to review. The safest change is the one you don't make.";
    else if (t === "lgtm") n = "# LGTM: Let's Go To Monitoring. (Also: Looks Good To Me, if you've actually read it.)";
    else if (/goto\s+fail/.test(t)) n = "# goto fail; goto fail; : two lines, one famous bug (Apple, 2014). A pattern matcher shrugs at it. A reviewer asks what the second line skips.";
    else if (/hunter2/.test(t)) n = "# hunter2: the old IRC joke. A secret in a line is a secret in Git history, too.";
    else if (r.id === "todo") n = "# Found it! The easiest finding in history: the author already knew.";
    else if (r.id === "none") n = "# a pattern matcher can't tell who owns the data, whether a token expires, or what's missing. That's your job.";
    else n = "# a pattern matcher spotted that. It can't tell if this particular use is safe: you decide.";
    $("hero-note").textContent = n;
  }

  // --------------------------------------------------------------------------- the source-to-sink tracer
  const TR_NOTES = {
    term: "# one source, two sinks: a placeholder fixes the query, escaping fixes the page.",
    page: "# a number is safe to hand to a query. Cleaning at the source is the whole idea.",
    sort: "# a placeholder can't bind a column name. Allow-list the values instead.",
    like: "# copied and decorated, still the same data. Cleaning has to happen before this line.",
    sql: "# the finished string. Fixing it here is too late: build it with placeholders instead.",
    rows: "# not from the request, but it lands in HTML. Ask where it came from and who could have written it."
  };
  function trInit() {
    const lines = R.TRACE_EXAMPLE, vars = R.traceVars(lines);
    let sel = "term";
    const box = $("tr-vars");
    box.innerHTML = vars.map((v) => `<button type="button" data-v="${esc(v)}" aria-pressed="${v === sel}">${esc(v)}</button>`).join("");
    function draw() {
      const t = R.trace(lines, sel);
      const useSet = new Set(t.uses.map((u) => u.line)), sinkSet = new Set(t.sinks.map((s) => s.line));
      $("tr-code").innerHTML = lines.map((l, i) => {
        const n = i + 1, cls = n === t.line ? "origin" : sinkSet.has(n) ? "sink" : useSet.has(n) ? "use" : "";
        return `<span class="cl ${cls}"><i>${n}</i>${esc(l) || " "}</span>`;
      }).join("");
      let origin;
      if (t.direct) origin = `<b>${esc(sel)}</b> is set on line ${t.line} straight from the request: a source.`;
      else if (t.from.length) origin = `<b>${esc(sel)}</b> (line ${t.line}) is built from ${t.from.map((f) => `<b>${esc(f)}</b>`).join(", ")}${t.dirty ? ", so it carries request data too" : ""}.`;
      else origin = `<b>${esc(sel)}</b> (line ${t.line}) is the result of a call that is itself a sink: data from that system, not from the request.`;
      if (t.cleaned) origin += " It's passed through <b>Number()</b> on the way, which cleans it.";
      $("tr-origin").innerHTML = origin;
      $("tr-uses").innerHTML = t.uses.length ? "Lines " + t.uses.map((u) => u.line).join(", ") + (t.derived.length ? ` (and through ${t.derived.map((d) => `<b>${esc(d)}</b>`).join(", ")})` : "") + "." : "None.";
      $("tr-sinks").innerHTML = t.sinks.length ? t.sinks.map((s) => `<li><b>${esc(s.kind)}</b><span>line ${s.line}, via ${s.via.map(esc).join(", ")}</span></li>`).join("") : `<li class="m"><b>none</b><span>no sink on any line that uses it</span></li>`;
      const v = $("tr-verdict");
      if (t.dirty && t.sinks.length) verdict(v, "bad", `Request data reaches ${t.sinks.length} sink${t.sinks.length === 1 ? "" : "s"} and nothing cleans it.`);
      else if (t.cleaned && t.sinks.length) verdict(v, "ok", "Cleaned before it gets there: a number can't carry a query.");
      else if (t.dirty) verdict(v, "y", "Carries request data, but no sink here. Follow what it's built into.");
      else verdict(v, "y", "Not request data, but follow it: stored data can have come from someone.");
      $("tr-note").textContent = TR_NOTES[sel] || "";
    }
    box.addEventListener("click", (e) => {
      const b = e.target.closest("button[data-v]"); if (!b) return;
      sel = b.dataset.v;
      for (const x of box.querySelectorAll("button")) x.setAttribute("aria-pressed", String(x === b));
      draw();
    });
    draw();
  }

  // --------------------------------------------------------------------------- empty, huge or hostile
  function pbInit() {
    const kinds = Object.keys(R.PROBES), box = $("pb-kind");
    let sel = "id";
    box.innerHTML = kinds.map((k) => `<button type="button" data-k="${k}" aria-pressed="${k === sel}">${esc(R.PROBES[k].label)}</button>`).join("");
    const draw = () => {
      const p = R.PROBES[sel];
      $("pb-vals").innerHTML = p.values.map((v) => `<li><code>${esc(v)}</code></li>`).join("");
      $("pb-ask").textContent = p.ask;
    };
    box.addEventListener("click", (e) => {
      const b = e.target.closest("button[data-k]"); if (!b) return;
      sel = b.dataset.k;
      for (const x of box.querySelectorAll("button")) x.setAttribute("aria-pressed", String(x === b));
      draw();
    });
    draw();
  }

  // --------------------------------------------------------------------------- the exercises (diff viewer)
  const RES = {};            // snippet id -> { found, total } for the diffs a pair has checked
  const STATE = {};          // snippet id -> { flags:Set, graded, revealed, sel, lastGrade }
  let lgtmClean = false, eagleSaid = false;
  const stOf = (s) => STATE[s.id] || (STATE[s.id] = { flags: new Set(), graded: false, revealed: false, sel: null, last: null });

  function record(s, g) {
    if (s.findings.some((f) => !f.bonus)) RES[s.id] = { found: g.found.length, total: g.total };
    sbDraw();
    const sb = R.scoreboard(RES);
    if (sb.eagleEye && !eagleSaid) { eagleSaid = true; toast("★ Eagle Eye unlocked", "Every planted flaw in all nine buggy diffs found. See the scoreboard."); }
  }

  function exInit(root) {
    const round = +root.dataset.round, snips = R.SNIPPETS.filter((s) => s.round === round);
    let cur = snips[0];
    root.innerHTML = `
      <div class="seg-pick ex-tabs" role="group" aria-label="Diffs in this round">${snips.map((s, i) => `<button type="button" data-id="${s.id}" aria-pressed="${i === 0}">${esc(s.tab)}${i === 2 ? " ★" : ""}</button>`).join("")}</div>
      <div class="ex-grid">
        <div class="ex-left">
          <div class="ex-diff"><div class="ex-file"><b class="ex-fname"></b><span class="ex-lang"></span></div><div class="ex-lines" role="group" aria-label="Lines of the diff: select the ones you would comment on"></div></div>
          <div class="ex-find" hidden><div class="ex-chips seg-pick" role="group" aria-label="Findings"></div><div class="ex-detail" aria-live="polite"></div></div>
        </div>
        <div class="ex-side">
          <p class="ex-pr"></p>
          <div class="ex-actions">
            <button type="button" class="btn btn-sm ex-check">Check my flags</button>
            <button type="button" class="btn btn-ghost btn-sm ex-reveal">Show answers</button>
            <button type="button" class="btn btn-ghost btn-sm ex-lgtm">Looks good to me</button>
            <button type="button" class="btn btn-ghost btn-sm ex-reset">Reset</button>
          </div>
          <p class="verdict ex-verdict"></p>
          <ul class="ex-out"></ul>
          <div class="ex-two" hidden></div>
          <p class="ex-score"></p>
        </div>
      </div>`;
    const q = (c) => root.querySelector(c);
    const linesBox = q(".ex-lines"), out = q(".ex-out"), find = q(".ex-find"), chips = q(".ex-chips"), detail = q(".ex-detail"), two = q(".ex-two"), vd = q(".ex-verdict");

    function scoreLine() {
      const sn = snips.filter((s) => s.findings.length);
      let f = 0, t = 0;
      for (const s of sn) if (RES[s.id]) { f += RES[s.id].found; t += R.required(s).length; }
      const all = sn.reduce((a, s) => a + R.required(s).length, 0);
      q(".ex-score").textContent = t ? `Round ${round} so far: ${f} of ${t} findings in the diffs you've checked (${all} planted in this round).` : `Round ${round}: ${all} findings planted across ${sn.length} ${sn.length === 1 ? "diff" : "diffs"}${snips.some((s) => s.clean) ? ", plus a clean one" : ""}.`;
    }

    function drawLines() {
      const st = stOf(cur), g = st.last;
      const hit = new Set(), noise = new Set(), miss = new Set(), fine = new Set();
      if (g || st.revealed) {
        for (const f of cur.findings) if (f.lines.some((m) => st.flags.has(m))) for (const n of f.lines) hit.add(n);
        const covered = new Set(cur.findings.flatMap((f) => f.lines));
        for (const n of st.flags) if (!covered.has(n)) noise.add(n);
      }
      if (st.revealed) {
        for (const f of cur.findings) if (!f.bonus && !f.lines.some((m) => st.flags.has(m))) for (const n of f.lines) miss.add(n);
        for (const d of cur.decoys) fine.add(d.line);
      }
      linesBox.innerHTML = cur.code.map((text, i) => {
        const n = i + 1, on = st.flags.has(n);
        const cls = [on ? "flag" : "", on && hit.has(n) ? "hit" : "", on && noise.has(n) ? "noise" : "", miss.has(n) ? "miss" : "", st.revealed && fine.has(n) && !hit.has(n) ? "fine" : "", st.sel && st.selLines && st.selLines.includes(n) ? "sel" : ""].filter(Boolean).join(" ");
        return `<button type="button" class="ln ${cls}" data-n="${n}" aria-pressed="${on}" aria-label="Line ${n}${on ? ", flagged" : ""}"><i>${n}</i><b>+</b><code>${esc(text) || " "}</code></button>`;
      }).join("");
    }
    function drawOut() {
      const st = stOf(cur), g = st.last;
      if (!g || st.revealed) { out.innerHTML = ""; return; }
      const rows = [];
      for (const id of g.found) rows.push(`<li class="ok"><b>${MARK.ok}</b><span>Found: ${esc(cur.findings.find((f) => f.id === id).title)}</span></li>`);
      for (const id of g.bonus) rows.push(`<li class="y"><b>★</b><span><b>Found it!</b> The easiest finding in history. (Bonus: it doesn't count towards the score.)</span></li>`);
      if (g.missed.length) rows.push(`<li class="m"><b>${MARK.m}</b><span>${g.missed.length} ${g.missed.length === 1 ? "finding is" : "findings are"} still hiding.</span></li>`);
      if (g.falseFlags.length > 3) rows.push(`<li class="y"><b>${MARK.y}</b><span>${g.falseFlags.length} flagged lines have no finding. Some are decoys; "Show answers" says why each is fine.</span></li>`);
      else for (const fl of g.falseFlags) rows.push(`<li class="y"><b>${MARK.y}</b><span>Line ${fl.line}: ${fl.why ? esc(fl.why) : "nothing planted here. A good instinct to ask, but not a finding."}</span></li>`);
      out.innerHTML = rows.join("");
    }
    function drawFind() {
      const st = stOf(cur);
      find.hidden = !st.revealed; two.hidden = true;
      if (!st.revealed) return;
      if (cur.clean) { chips.innerHTML = ""; detail.innerHTML = `<p class="ex-why"><b>No findings.</b> ${esc(cur.verdict)}</p><ul class="ex-fine">${cur.decoys.map((d) => `<li><b>line ${d.line}</b> ${esc(d.why)}</li>`).join("")}</ul>`; return; }
      chips.innerHTML = cur.findings.map((f) => {
        const got = f.lines.some((n) => st.flags.has(n));
        return `<button type="button" data-f="${f.id}" aria-pressed="${st.sel === f.id}" class="${f.bonus ? "bonus" : got ? "got" : "missed"}">${got || f.bonus ? MARK.ok : MARK.bad} ${esc(f.title.length > 30 ? f.title.slice(0, 28) + "…" : f.title)}</button>`;
      }).join("");
      if (st.selDecoy) { detail.innerHTML = `<p class="ex-why"><b>Line ${st.selDecoy.line} is fine.</b> ${esc(st.selDecoy.why)}</p>`; return; }
      const f = cur.findings.find((x) => x.id === st.sel) || cur.findings[0];
      st.sel = f.id; st.selLines = f.lines;
      detail.innerHTML = `<p class="ex-why"><span class="tag ${f.sev === "Blocking" ? "tag-bad" : f.sev === "Found it!" ? "tag-ok" : "tag-y"}">${esc(f.sev)}</span> <b>${esc(f.title)}</b>${f.cwe ? ` <small>${esc(f.cwe)}</small>` : ""}<br>${esc(f.why)}</p>`;
      two.hidden = false;
      two.innerHTML = `<div><small class="lr-label">A fix</small><pre class="term">${esc(f.fix.join("\n"))}</pre></div><div><small class="lr-label">A model review comment</small><pre class="term cmt">${esc(f.comment)}</pre></div>`;
      for (const b of chips.querySelectorAll("button")) b.setAttribute("aria-pressed", String(b.dataset.f === st.sel));
    }
    function draw() {
      q(".ex-fname").textContent = cur.file; q(".ex-lang").textContent = cur.lang;
      q(".ex-pr").innerHTML = `<b>${esc(cur.title)}.</b> ${esc(cur.desc)}`;
      drawLines(); drawOut(); drawFind(); scoreLine();
      q(".ex-lgtm").textContent = cur.clean ? "Approve (LGTM)" : "Looks good to me";
      for (const b of root.querySelectorAll(".ex-tabs button")) b.setAttribute("aria-pressed", String(b.dataset.id === cur.id));
    }
    function grade() {
      const st = stOf(cur), g = R.grade(cur, st.flags);
      st.last = g; st.graded = true; record(cur, g);
      return g;
    }
    function check() {
      const st = stOf(cur), g = grade();
      let msg, cls;
      if (cur.clean) {
        if (!st.flags.size) { cls = "ok"; msg = "Nothing flagged. For this diff that's the right call: press Approve."; }
        else { cls = "y"; msg = `${g.falseFlags.length} ${g.falseFlags.length === 1 ? "flag" : "flags"}, and this diff is clean. Read why each line is fine below, then decide.`; }
      } else if (!st.flags.size) { cls = "y"; msg = "Nothing flagged yet. Click the lines you'd comment on first."; }
      else if (g.perfect) { cls = "ok"; msg = `All ${g.total} found. Show the answers to compare your comment wording with a model one.`; }
      else { cls = g.found.length ? "y" : "bad"; msg = `Found ${g.found.length} of ${g.total}.`; }
      if (cur.code.length > 3 && st.flags.size === cur.code.length) msg += " You flagged every line. Flagging everything is the same as flagging nothing: aim.";
      verdict(vd, cls, msg);
      draw();
    }
    function reveal() {
      const st = stOf(cur);
      if (!st.graded) grade();
      st.revealed = true;
      st.selDecoy = null;
      if (!cur.clean) { const first = cur.findings.find((f) => !f.bonus) || cur.findings[0]; st.sel = first.id; st.selLines = first.lines; }
      if (!vd.textContent) verdict(vd, "y", `Answers shown. Compare each finding's fix and comment with yours.`);
      draw();
    }
    function lgtm() {
      const st = stOf(cur);
      if (cur.clean) { lgtmClean = true; verdict(vd, "ok", cur.verdict); sbDraw(); if (!st.revealed) reveal(); return; }
      if (st.revealed) { verdict(vd, "y", "Approve once the fixes land and the tests for the not-allowed case exist."); return; }
      trombone();
      verdict(vd, "bad", `LGTM: Let's Go To Monitoring. There ${R.required(cur).length === 1 ? "is 1 finding" : "are " + R.required(cur).length + " findings"} in this diff. Flag lines and check again.`);
    }
    function reset() {
      STATE[cur.id] = null; delete STATE[cur.id]; delete RES[cur.id];
      vd.className = "verdict ex-verdict"; vd.textContent = ""; sbDraw(); draw();
    }

    linesBox.addEventListener("click", (e) => {
      const b = e.target.closest("button.ln"); if (!b) return;
      const st = stOf(cur), n = +b.dataset.n;
      if (st.revealed) {
        const f = cur.findings.find((x) => x.lines.includes(n)), d = cur.decoys.find((x) => x.line === n);
        if (f) { st.sel = f.id; st.selLines = f.lines; st.selDecoy = null; } else if (d) { st.selDecoy = d; st.selLines = [n]; st.sel = null; } else { st.selDecoy = { line: n, why: "No comment needed here." }; st.selLines = [n]; st.sel = null; }
        draw(); return;
      }
      if (st.flags.has(n)) st.flags.delete(n); else st.flags.add(n);
      st.graded = false; st.last = null;
      verdict(vd, "", ""); vd.textContent = ""; vd.className = "verdict ex-verdict";
      draw();
    });
    root.querySelector(".ex-tabs").addEventListener("click", (e) => {
      const b = e.target.closest("button[data-id]"); if (!b) return;
      cur = R.byId(b.dataset.id); vd.className = "verdict ex-verdict"; vd.textContent = ""; draw();
    });
    chips.addEventListener("click", (e) => {
      const b = e.target.closest("button[data-f]"); if (!b) return;
      const st = stOf(cur), f = cur.findings.find((x) => x.id === b.dataset.f);
      st.sel = f.id; st.selLines = f.lines; st.selDecoy = null; draw();
    });
    q(".ex-check").addEventListener("click", check);
    q(".ex-reveal").addEventListener("click", reveal);
    q(".ex-lgtm").addEventListener("click", lgtm);
    q(".ex-reset").addEventListener("click", reset);
    document.addEventListener("cr:redraw", scoreLine);
    draw();
  }

  // --------------------------------------------------------------------------- the scoreboard
  function sbDraw() {
    const el = $("sb-table"); if (!el) return;
    const sb = R.scoreboard(RES);
    el.innerHTML = `<table class="sb"><thead><tr><th>Round</th><th>Found</th><th>Diffs checked</th></tr></thead><tbody>` +
      sb.rounds.map((r) => `<tr><td>${r.round} · ${esc(r.name)}</td><td class="${r.checked && r.found === r.total ? "ok" : ""}">${r.found} / ${r.total}</td><td>${r.checked} of ${r.snippets}</td></tr>`).join("") +
      `<tr class="sb-clean"><td>Knew when to approve</td><td class="${lgtmClean ? "ok" : ""}">${lgtmClean ? "✓" : "·"}</td><td>the clean diff</td></tr>` +
      `<tr class="sb-total"><td>All rounds</td><td>${sb.found} / ${sb.total}</td><td>${Object.keys(RES).length} of ${R.SNIPPETS.filter((s) => s.findings.length).length}</td></tr></tbody></table>`;
    const v = $("sb-verdict"), n = $("sb-note");
    if (!Object.keys(RES).length) { verdict(v, "y", "Nothing checked yet. Flag lines on the round slides and press Check my flags."); n.textContent = "# the board fills in as pairs work through the diffs."; }
    else if (sb.eagleEye) { verdict(v, "ok", `${sb.found} of ${sb.total}: every planted flaw found.`); n.textContent = "# that's every flaw. Now try the comment builder: finding it is half the job."; }
    else { verdict(v, "y", `${sb.found} of ${sb.total} planted flaws found so far.`); n.textContent = sb.allChecked ? "# all diffs checked. Look at what the misses had in common: usually something absent, not something wrong." : "# unchecked diffs count as zero until someone checks them."; }
    const eg = $("sb-eagle");
    eg.className = "eagle" + (sb.eagleEye ? " on" : "");
    eg.innerHTML = sb.eagleEye ? `<b>★ EAGLE EYE</b><span>Every planted flaw in all nine buggy diffs. Nothing got past you.</span>` : `<b>☆ Eagle Eye (locked)</b><span>Find every planted flaw in all nine buggy diffs. The clean one doesn't count, and neither does the TODO.</span>`;
    document.dispatchEvent(new Event("cr:redraw"));
  }

  // --------------------------------------------------------------------------- writing the comment
  function cmInit() {
    const boxes = Array.from(document.querySelectorAll("#cm-parts input"));
    let tone = "code";
    const draw = () => {
      const o = { label: $("cm-label").value, aboutPerson: tone === "person" };
      for (const b of boxes) o[b.dataset.k] = b.checked;
      const c = R.composeComment(o);
      $("cm-out").textContent = c.text;
      const v = $("cm-verdict");
      if (c.kind === "personal") verdict(v, "bad", `${c.score} of ${c.max} · Even if every word is true, this lands as blame. Aim it at the code.`);
      else if (c.kind === "great") verdict(v, "ok", `${c.score} of ${c.max} · Review comment of the week.`);
      else if (c.kind === "good") verdict(v, "ok", `${c.score} of ${c.max} · The author can act on this without a follow-up question.`);
      else verdict(v, "y", `${c.score} of ${c.max} · The author would have to ask you what you meant.`);
      $("cm-missing").innerHTML = c.missing.map((m) => `<li><b>+</b><span>${esc(m)}</span></li>`).join("");
    };
    boxes.forEach((b) => b.addEventListener("change", draw));
    $("cm-label").addEventListener("change", draw);
    $("cm-tone").addEventListener("click", (e) => {
      const b = e.target.closest("button[data-t]"); if (!b) return;
      tone = b.dataset.t;
      for (const x of $("cm-tone").querySelectorAll("button")) x.setAttribute("aria-pressed", String(x === b));
      draw();
    });
    draw();
  }

  // --------------------------------------------------------------------------- machine or human?
  function auInit() {
    const ans = {}, list = $("au-list");
    const LABEL = { machine: "Machine first", human: "Person first", both: "Both" };
    list.innerHTML = R.AUTO_ITEMS.map((it) => `<li data-id="${it.id}"><span class="au-t">${esc(it.text)}</span><span class="seg-pick au-b" role="group" aria-label="Who should catch it first">${R.AUTO_CHOICES.map((c) => `<button type="button" data-c="${c}" aria-pressed="false">${LABEL[c]}</button>`).join("")}</span></li>`).join("") + `<li class="au-detail-row"><p class="au-why" id="au-why" aria-live="polite">Pick an answer for any row to see why.</p></li>`;
    list.addEventListener("click", (e) => {
      const b = e.target.closest("button[data-c]"); if (!b) return;
      const li = b.closest("li[data-id]"), it = R.AUTO_ITEMS.find((x) => x.id === li.dataset.id);
      ans[it.id] = b.dataset.c;
      for (const x of li.querySelectorAll("button")) x.setAttribute("aria-pressed", String(x === b));
      const ok = ans[it.id] === it.best;
      li.className = ok ? "ok" : "bad";
      const w = $("au-why");
      w.innerHTML = `<b>${ok ? MARK.ok : MARK.bad} ${esc(it.text)}: ${ok ? "yes" : "best answer is " + LABEL[it.best].toLowerCase()}.</b> ${esc(it.why)}`;
      const s = R.autoScore(ans), v = $("au-verdict");
      if (s.answered === s.total) verdict(v, s.right === s.total ? "ok" : "y", `${s.right} of ${s.total}. ${s.right === s.total ? "Machines for the repeatable, people for the contextual." : "The pattern: machines for what's repeatable, people for what depends on context."}`);
      else verdict(v, "y", `${s.answered} of ${s.total} answered.`);
    });
  }

  // --------------------------------------------------------------------------- team checklist
  const RV_KEY = "code-review-checklist";
  function review() {
    const list = $("rv-list");
    list.innerHTML = R.CHECKLIST.map((c) => `<label><input type="checkbox" data-k="${c.k}"> ${esc(c.t)}</label>`).join("");
    const boxes = Array.from(list.querySelectorAll("input"));
    let saved = {};
    try { saved = JSON.parse(store(RV_KEY) || "{}"); } catch (e) {}
    boxes.forEach((b) => { b.checked = !!saved[b.dataset.k]; });
    const update = () => {
      const done = boxes.filter((b) => b.checked).length;
      store(RV_KEY, JSON.stringify(Object.fromEntries(boxes.map((b) => [b.dataset.k, b.checked]))));
      const n = $("rv-note"); n.className = "comment";
      if (done === boxes.length) { n.textContent = "# ten of ten. Now ask a teammate which one they'd drop, and put the list where the next pull request will see it."; n.classList.add("ok"); }
      else if (!done) n.textContent = "# tick what your team asks today. Each gap is something to try on the next three pull requests. Saved in this browser only.";
      else n.textContent = `# ${done} of ${boxes.length}. Pick the unticked box that would have caught your last bug, and start there.`;
    };
    boxes.forEach((b) => b.addEventListener("change", update));
    update();
  }

  // --------------------------------------------------------------------------- easter eggs
  function consoleHint() {
    console.log("%cSecure Code Review Workshop", "font: 700 24px monospace; color: #ff2e88; text-shadow: 0 0 8px #ff2e88");
    console.log("%cYou're reading source in a console. That's a code review. Found anything? Start with the question: who can call this?", "font: 14px monospace; color: #00f0ff");
  }

  function start() {
    consoleHint();
    $("hero-in").addEventListener("input", hero); hero();
    trInit(); pbInit();
    document.querySelectorAll(".ex[data-round]").forEach(exInit);
    sbDraw(); cmInit(); auInit(); review();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
})();
