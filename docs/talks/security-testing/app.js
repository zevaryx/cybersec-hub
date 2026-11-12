/* app.js - the live demos for "Security Testing in Your Workflow".
   Every demo is a simulation in this page, built on the small models in tests.js: a tool-coverage table, a toy static scanner,
   a mock invoice API with a test suite, filename cleaners, a pipeline planner, a suppression linter, invented findings and
   a findings simulation. Nothing is fetched or sent anywhere. */
(function () {
  "use strict";
  const T = window.TestLab;

  // --------------------------------------------------------------------------- helpers
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const click = (id, fn) => $(id).addEventListener("click", fn);
  function store(key, val) {
    try { if (val === undefined) return localStorage.getItem(key); localStorage.setItem(key, val); } catch (e) {}
    return null;
  }
  const setPressed = (id, attr, val) => { for (const b of $(id).querySelectorAll("button")) b.setAttribute("aria-pressed", String(b.getAttribute(attr) === String(val))); };
  const verdict = (id, cls, text) => { const el = $(id); el.className = "verdict" + (cls ? " " + cls : ""); el.textContent = text; };
  const note = (id, text, cls) => { const el = $(id); el.className = "comment" + (cls ? " " + cls : ""); el.textContent = text; };
  const visible = (s, max) => {
    let out = "";
    for (const ch of String(s)) {
      const c = ch.codePointAt(0);
      out += (c < 32 || (c >= 127 && c < 160) || (c >= 0x200b && c <= 0x200f) || (c >= 0x202a && c <= 0x202e) || (c >= 0x2066 && c <= 0x2069)) ? "\\u" + c.toString(16).padStart(4, "0") : ch;
    }
    return out.length > max ? out.slice(0, max) + "… (" + String(s).length + " chars)" : out;
  };

  // --------------------------------------------------------------------------- title: lint a test name
  function hero() {
    const el = $("hero-in"), v = el.value;
    el.style.width = Math.min(34, Math.max(10, v.length + 1)) + "ch";
    const r = T.lintTestName(v);
    const mark = r.level === "ok" ? "✓ reads well" : r.level === "bad" ? "✗ " + (v.trim() || "(empty)") : "! could say more";
    const out = $("hero-out");
    out.className = "hashout " + r.level;
    out.textContent = mark;
    note("hero-note", r.text.charAt(0) === "#" ? r.text : "# " + r.text);
  }

  // --------------------------------------------------------------------------- tool map
  const seenBugs = new Set();
  function toolMap() {
    const pick = $("tm-pick");
    pick.innerHTML = T.BUGS.map((b) => `<button type="button" data-b="${b.id}" aria-pressed="false">${esc(b.label)}</button>`).join("");
    pick.addEventListener("click", (e) => {
      const b = e.target.closest("button[data-b]"); if (!b) return;
      show(b.dataset.b);
    });
    function show(id) {
      setPressed("tm-pick", "data-b", id);
      const r = T.toolsFor(id);
      $("tm-grid").innerHTML = T.TOOLS.map((t, i) => {
        const v = r.bug.r[i];
        return `<li class="r${v}"><span>${esc(t.label)}</span><span class="tm-pips">${"●".repeat(v + 1)}${"○".repeat(2 - v)}<small>${T.RATING[v]}</small></span></li>`;
      }).join("");
      $("tm-lesson").textContent = r.bug.lesson;
      seenBugs.add(id);
      if (seenBugs.size === T.BUGS.length) note("tm-note", "# you've seen them all: no single tool covers the whole map. That's the point. (Dots are a rule of thumb, not a measurement.)", "ok");
      else note("tm-note", `# ${seenBugs.size} of ${T.BUGS.length} bugs looked at. Dots are a rule of thumb, not a measurement.`);
    }
    show(T.BUGS[0].id);
  }

  // --------------------------------------------------------------------------- toy static scanner
  let saIdx = 0, saMode = "pattern";
  function sast() {
    $("sa-pick").innerHTML = T.SNIPPETS.map((s, i) => `<button type="button" data-i="${i}" aria-pressed="${i === 0}">${esc(s.label)}</button>`).join("");
    $("sa-pick").addEventListener("click", (e) => { const b = e.target.closest("button[data-i]"); if (b) { saIdx = +b.dataset.i; setPressed("sa-pick", "data-i", saIdx); render(); } });
    $("sa-mode").addEventListener("click", (e) => { const b = e.target.closest("button[data-sm]"); if (b) { saMode = b.dataset.sm; setPressed("sa-mode", "data-sm", saMode); render(); } });
    function render() {
      const s = T.SNIPPETS[saIdx], f = T.scan(s.src, saMode), flagged = new Set(f.map((x) => x.line));
      $("sa-code").innerHTML = s.src.split("\n").map((l, i) => `<span class="ln${flagged.has(i + 1) ? " flag" : ""}">${esc(l) || " "}</span>`).join("");
      const j = T.judge(s, f);
      const cls = j === "caught" || j.indexOf("quiet") === 0 ? "ok" : j === "missed" ? "bad" : "y";
      verdict("sa-verdict", cls, f.length ? `Flagged: ${f.map((x) => x.text).join("; ")} (line ${f.map((x) => x.line).join(", ")}). Truth: ${s.truth}. → ${j}` : `No findings. Truth: ${s.truth}. → ${j}`);
      const id = s.id;
      let n;
      if (id === "direct") n = f.length ? "# found: the query text is built by joining strings" + (saMode === "taint" ? ", and the data comes straight from the request." : ".") : "";
      else if (id === "helper") n = "# the dangerous string-building lives in repo.py, so this file looks fine. Many real products follow data across files; this toy reads one.";
      else if (id === "param") n = "# quiet, correctly: the query and the data travel separately.";
      else if (id === "allow") n = f.length ? "# a false alarm: the table name is checked against an allowlist first. Switch to 'follow the data' and it goes quiet." : "# quiet, correctly: the value no longer comes from the request, so nothing can reach the query.";
      else n = "# nothing is wrong with the code that's here. Something is missing, and no scanner flags an absence.";
      note("sa-note", n, id === "authz" ? "bad" : "");
      const rows = T.SNIPPETS.map((x, i) => {
        const a = T.judge(x, T.scan(x.src, "pattern")), b = T.judge(x, T.scan(x.src, "taint"));
        const c = (j2) => `<td class="${j2 === "caught" ? "caught" : j2 === "missed" ? "missed" : j2 === "false alarm" ? "alarm" : "quiet"}">${esc(j2)}</td>`;
        return `<tr class="${i === saIdx ? "cur" : ""}"><th>${esc(x.label.split(":")[0])}</th><td>${esc(x.truth)}</td>${c(a)}${c(b)}</tr>`;
      }).join("");
      $("sa-table").innerHTML = `<thead><tr><th></th><th>Truth</th><th>Pattern</th><th>Data flow</th></tr></thead><tbody>${rows}</tbody>`;
    }
    render();
  }

  // --------------------------------------------------------------------------- authorization tests
  let azBug = "none", azSel = null; const azOn = new Set(T.TESTS.map((t) => t.id));
  function authz() {
    $("az-bug").innerHTML = T.BUG_OPTIONS.map((b) => `<option value="${b.id}">${esc(b.label)}</option>`).join("");
    $("az-bug").addEventListener("change", () => { azBug = $("az-bug").value; azSel = null; run(); });
    $("az-tests").addEventListener("click", (e) => {
      const li = e.target.closest("li[data-t]"); if (!li) return;
      if (e.target.tagName === "INPUT") { if (e.target.checked) azOn.add(li.dataset.t); else azOn.delete(li.dataset.t); }
      else azSel = li.dataset.t;
      run();
    });
    function run() {
      const res = T.runSuite(azBug, azOn);
      const failing = res.filter((r) => r.status === "fail"), skipped = res.filter((r) => r.status === "skipped").length;
      const selId = azSel && res.some((r) => r.id === azSel) ? azSel : (failing[0] || res[0]).id;
      $("az-tests").innerHTML = res.map((r) => `<li data-t="${r.id}" class="${r.status}${r.id === selId ? " sel" : ""}"><input type="checkbox" ${azOn.has(r.id) ? "checked" : ""} aria-label="Include ${esc(r.name)}"><span class="st">${r.status === "pass" ? "PASS" : r.status === "fail" ? "FAIL" : "skip"}</span><span class="nm">${esc(r.name)}</span></li>`).join("");
      const sel = T.TESTS.find((t) => t.id === selId);
      $("az-src-title").textContent = failing.some((r) => r.id === selId) ? "The test that went red" : "The selected test";
      $("az-src").textContent = `def ${sel.name}(api):\n    ` + sel.src.split("\n").join("\n    ");
      const ran = res.length - skipped;
      const bugInfo = T.BUG_OPTIONS.find((b) => b.id === azBug);
      note("az-about", "# " + bugInfo.about);
      if (failing.length) verdict("az-verdict", "bad", `${ran} run, ${failing.length} failed: ${failing.map((r) => r.name).join(", ")}`);
      else if (azBug !== "none") verdict("az-verdict", "y", `${ran} run, 0 failed. All tests passed. Suspicious.`);
      else verdict("az-verdict", "ok", `${ran} run, all passed.` + (skipped ? ` (${skipped} skipped)` : ""));
      if (azBug !== "none" && !failing.length) note("az-note", "# the bug is still there, and nothing noticed. A suite can only protect the rules it states.", "bad");
      else if (failing.length) note("az-note", "# the name of the red test says which rule broke. Untick it (the box beside it) to see what the rest of the suite thinks.");
      else note("az-note", "# now switch a bug on. Exactly one test should go red.");
    }
    run();
  }

  // --------------------------------------------------------------------------- input tests
  let inVer = "v1";
  function input() {
    $("in-pick").innerHTML = Object.keys(T.SANITIZERS_FN).map((k, i) => `<button type="button" data-v="${k}" aria-pressed="${i === 0}">${esc(T.SANITIZERS_FN[k].label)}</button>`).join("");
    $("in-pick").addEventListener("click", (e) => { const b = e.target.closest("button[data-v]"); if (b) { inVer = b.dataset.v; setPressed("in-pick", "data-v", inVer); render(); } });
    $("in-own").addEventListener("input", own);
    function render() {
      const rows = T.runBattery(inVer);
      $("in-table").innerHTML = `<thead><tr><th>Input</th><th>Cleaned to</th><th>First problem</th></tr></thead><tbody>` + rows.map((r) =>
        `<tr><td title="${esc(visible(r.input, 60))}">${esc(r.label)}</td><td class="out" title="${esc(visible(r.out, 120))}">${esc(visible(r.out, 18))}</td><td class="rs ${r.ok ? "good" : "badc"}" title="${esc(r.problems.join("; "))}">${r.ok ? "✓" : "✗ " + esc(r.problems[0])}</td></tr>`).join("") + "</tbody>";
      const pass = rows.filter((r) => r.ok).length;
      verdict("in-verdict", pass === rows.length ? "ok" : pass < rows.length / 2 ? "bad" : "y", `${pass} of ${rows.length} cases pass every property`);
      own();
    }
    function own() {
      const v = $("in-own").value, out = $("in-own-out");
      if (!v) { out.textContent = ""; note("in-note", "# try a path, an emoji, a very long line, or paste something strange."); return; }
      const cleaned = T.SANITIZERS_FN[inVer].fn(v), p = T.problems(cleaned);
      out.textContent = visible(cleaned, 120) + "\n" + (p.length ? "✗ " + p.join("; ") : "✓ passes every property");
      if (/drop\s+table/i.test(v)) note("in-note", "# hello, Bobby Tables. It's only a string here: this cleaner never builds a query. (For the query you'd use parameters.) xkcd #327, and a good reminder that one function rarely covers every sink.", "y");
      else note("in-note", p.length ? "# that input makes this version unsafe. Add it to your battery, then fix the function." : "# safe by these properties. A test is only as good as its list: add what surprises you.");
    }
    render();
  }

  // --------------------------------------------------------------------------- pipeline planner
  let plan = {};
  function pipeline() {
    const setAll = (fn) => { T.PIPE_TOOLS.forEach((t) => { plan[t.id] = fn(t); }); };
    setAll(() => "pr");
    const opts = T.STAGES.map((s) => `<option value="${s.id}">${esc(s.label)}</option>`).join("");
    $("pl-list").innerHTML = T.PIPE_TOOLS.map((t) => `<li data-t="${t.id}"><span class="t"><b>${esc(t.label)}</b> <small>${T.fmt(t.secs)}</small></span><select aria-label="When to run: ${esc(t.label)}">${opts}</select></li>`).join("");
    for (const li of $("pl-list").children) li.querySelector("select").value = plan[li.dataset.t];
    $("pl-list").addEventListener("change", (e) => { const li = e.target.closest("li[data-t]"); if (li) { plan[li.dataset.t] = e.target.value; render(); } });
    $("pl-presets").addEventListener("click", (e) => {
      const b = e.target.closest("button[data-p]"); if (!b) return;
      if (b.dataset.p === "all") setAll(() => "pr"); else setAll((t) => T.SUGGESTED[t.id]);
      for (const li of $("pl-list").children) li.querySelector("select").value = plan[li.dataset.t];
      render();
      note("pl-note", b.dataset.p === "all" ? "# looks thorough, and it's the layout that teaches a team to wait, then to skip." : "# fast and precise before the commit, your tests and quick scans on the pull request, slow and noisy ones later. Fewer warnings, and nobody waits 90 minutes.", b.dataset.p === "all" ? "" : "ok");
    });
    function render() {
      const r = T.checkPlan(plan), slowIds = new Set(r.warns.filter((w) => w.kind === "slow").map((w) => w.tool));
      for (const li of $("pl-list").children) li.classList.toggle("slow", slowIds.has(li.dataset.t));
      $("pl-totals").innerHTML = T.STAGES.map((s) => `<li><span>${esc(s.label)}</span><b>${r.totals[s.id].tools} check${r.totals[s.id].tools === 1 ? "" : "s"}</b><span>limit ${T.fmt(s.budget)}</span></li>`).join("");
      $("pl-warns").innerHTML = r.warns.map((w) => `<li class="${w.kind}">${esc(w.text)}</li>`).join("");
      verdict("pl-verdict", r.warns.length ? "y" : "ok", r.warns.length ? `${r.warns.length} warning${r.warns.length === 1 ? "" : "s"}` : "No warnings: each check runs where its speed fits.");
      if (T.PIPE_TOOLS.every((t) => plan[t.id] === "pre")) note("pl-note", "# every check before every commit: commits now take about six hours, and people will find a way around it.", "y");
    }
    note("pl-note", "# change a check's stage and watch the warnings. Times are teaching numbers, not measurements.");
    render();
  }

  // --------------------------------------------------------------------------- suppression linter
  const SLOPPY = [
    "py/sql-injection reports/legacy.py | Only reachable from the admin CLI, which takes no web input. Revisit when the CLI is removed. | dana | 2027-02-01",
    "dep/EXAMPLE-ID-1 package-lock.json | false positive | |",
    "js/xss web/legacy.js | todo | sam | 2026-09-01",
    "js/open-redirect web/login.js | Redirect target is checked against an allowlist in redirect.js | ari | 2029-01-01",
    "secret/aws-key docs/setup.md | AWS's documented example key, not a credential | lee | 2027-05-01",
  ].join("\n");
  const GOOD = [
    "py/sql-injection reports/legacy.py | Only reachable from the admin CLI, which takes no web input. Revisit when the CLI is removed. | dana | 2027-02-01",
    "dep/EXAMPLE-ID-1 package-lock.json | Library's TIFF decoder is never called: we accept PNG and JPEG only. Upgrade in the next routine update. | jo | 2027-01-15",
    "js/xss web/legacy.js | Output is escaped by the template engine; the finding is a pattern match on a helper. Rewrite the helper in Q1. | sam | 2027-03-01",
    "js/open-redirect web/login.js | Redirect target is checked against an allowlist in redirect.js | ari | 2027-04-01",
    "secret/aws-key docs/setup.md | AWS's documented example key, not a credential | lee | 2027-05-01",
  ].join("\n");
  function suppress() {
    $("sp-today").textContent = T.TODAY;
    const ta = $("sp-text"); ta.value = SLOPPY;
    ta.addEventListener("input", render);
    $("sp-presets").addEventListener("click", (e) => { const b = e.target.closest("button[data-p]"); if (b) { ta.value = b.dataset.p === "good" ? GOOD : SLOPPY; render(); } });
    function render() {
      const r = T.lintSuppressions(ta.value, T.TODAY);
      $("sp-results").innerHTML = r.map((x) => `<li class="${x.ok ? "ok" : "bad"}"><code>${esc(x.head)}</code>${x.ok ? " ✓ reason, owner and expiry" : x.issues.map((i) => `<span class="issue">✗ ${esc(i)}</span>`).join("")}</li>`).join("");
      const bad = r.filter((x) => !x.ok).length;
      if (r.length && !bad) note("sp-note", "# every suppression has a reason, an owner and an expiry. That's one a future teammate will thank you for.", "ok");
      else if (!r.length) note("sp-note", "# no suppressions. If that's because nothing is suppressed, wonderful. If it's because nothing is scanned, less so.");
      else note("sp-note", `# ${bad} of ${r.length} need work. Edit the file, or press "Fix them all".`);
    }
    render();
  }

  // --------------------------------------------------------------------------- triage game
  const tg = { i: 0, answers: [], answered: false };
  function triage() {
    $("tg-buttons").addEventListener("click", (e) => { const b = e.target.closest("button[data-a]"); if (b && !tg.answered) answer(b.dataset.a); });
    $("tg-next").addEventListener("click", () => { if (tg.i >= T.FINDINGS.length) { tg.i = 0; tg.answers = []; } else if (tg.answered) tg.i++; tg.answered = false; render(); });
    function render() {
      const f = T.FINDINGS[tg.i];
      if (!f) return finish();
      $("tg-count").textContent = `Finding ${tg.i + 1} of ${T.FINDINGS.length} · from: ${f.tool}`;
      $("tg-title").textContent = f.title; $("tg-where").textContent = f.where; $("tg-code").textContent = f.code;
      for (const b of $("tg-buttons").children) { b.disabled = false; b.hidden = false; }
      verdict("tg-verdict", "", ""); $("tg-why").textContent = ""; $("tg-prio").textContent = "";
      $("tg-next").hidden = true; note("tg-note", "# call it before you click: is this a real problem here, or noise?");
    }
    function answer(a) {
      const f = T.FINDINGS[tg.i]; tg.answered = true; tg.answers.push(a);
      for (const b of $("tg-buttons").children) b.disabled = true;
      const right = a === f.truth;
      verdict("tg-verdict", right ? "ok" : "bad", right ? `Yes: ${f.truth}.` : `Not quite: this one is ${f.truth}.`);
      $("tg-why").textContent = f.why; $("tg-prio").textContent = f.priority;
      $("tg-next").hidden = false; $("tg-next").textContent = tg.i === T.FINDINGS.length - 1 ? "See the result" : "Next finding";
      note("tg-note", "");
    }
    function finish() {
      const right = tg.answers.filter((a, i) => a === T.FINDINGS[i].truth).length, n = T.FINDINGS.length;
      $("tg-count").textContent = "Result";
      $("tg-title").textContent = `${right} of ${n} right`; $("tg-where").textContent = ""; $("tg-code").textContent = "";
      for (const b of $("tg-buttons").children) b.hidden = true;
      verdict("tg-verdict", right === n ? "ok" : right >= 3 ? "y" : "bad", right === n ? "A perfect triage." : `${right} of ${n}.`);
      let why = "Reading the evidence beats reading the label: severity words describe a type of bug, not your risk.";
      if (tg.answers.every((a) => a === "noise")) why = "";
      $("tg-why").textContent = why; $("tg-prio").textContent = "";
      const nn = $("tg-note");
      if (tg.answers.every((a) => a === "noise")) { nn.className = "comment y"; nn.innerHTML = `<span class="badge">THE OPTIMIST</span> Everything was noise! Two of them weren't, and one of those was a live token. Marking things noise is the easy way to feel done.`; }
      else if (right === n) { nn.className = "comment ok"; nn.innerHTML = `<span class="badge">SHARP EYES</span> Evidence over labels.`; }
      else nn.textContent = "# a quick rule: if you can't explain why it's safe, it isn't noise yet. It's unknown.";
      $("tg-next").hidden = false; $("tg-next").textContent = "Play again";
    }
    render();
  }

  // --------------------------------------------------------------------------- measuring
  const ms = { scanner: false, hide: false };
  function measure() {
    $("ms-buttons").addEventListener("click", (e) => {
      const b = e.target.closest("button[data-t]"); if (!b) return;
      ms[b.dataset.t] = !ms[b.dataset.t]; b.setAttribute("aria-pressed", String(ms[b.dataset.t])); render();
    });
    function render() {
      const base = T.metrics(), m = T.metrics(ms);
      const cell = (label, val, baseVal, unit) => `<div class="${val !== baseVal ? "hl" : ""}"><b>${val}${unit || ""}</b><span>${label}</span></div>`;
      $("ms-stats").innerHTML = cell("found so far", m.found, base.found) + cell("open now", m.open, base.open) + cell("fixed", m.fixed, base.fixed)
        + cell("median days to fix", m.medianDaysToFix, base.medianDaysToFix) + cell("oldest open (days)", m.oldestOpenDays, base.oldestOpenDays)
        + cell("dismissed or suppressed", m.dismissed + m.suppressed, base.dismissed + base.suppressed);
      let n = "# the baseline: 24 findings, most fixed within a couple of weeks, and a few that have been open a long time.";
      if (ms.scanner && !ms.hide) n = "# the count jumped, the dashboard looks worse, and the median time to fix hardly moved. The team is fine. The tools got better.";
      else if (!ms.scanner && ms.hide) n = "# the open count fell, and nothing was fixed. The median didn't move. Hiding old findings made the number better and the code no safer.";
      else if (ms.scanner && ms.hide) n = "# both at once: a bigger count of findings and a smaller count of open ones, and the same median. Counts are easy to move; fixes are not.";
      note("ms-note", n, ms.hide ? "y" : "");
    }
    render();
  }

  // --------------------------------------------------------------------------- checklist
  const RV_KEY = "security-testing-checklist";
  function checklist() {
    const boxes = Array.from(document.querySelectorAll("#rv-list input[type=checkbox]"));
    let saved = {};
    try { saved = JSON.parse(store(RV_KEY) || "{}"); } catch (e) {}
    boxes.forEach((b) => { b.checked = !!saved[b.dataset.k]; });
    const update = () => {
      const done = boxes.filter((b) => b.checked).length;
      store(RV_KEY, JSON.stringify(Object.fromEntries(boxes.map((b) => [b.dataset.k, b.checked]))));
      const n = $("rv-note"); n.className = "comment";
      if (done === boxes.length) { n.textContent = "# 10 of 10. All tests passed. Suspicious: go and break one on purpose, and see which test notices."; n.classList.add("ok"); }
      else if (!done) n.textContent = "# tick what's true for your team today. Each gap is a ticket, not a failure. Saved in this browser only.";
      else n.textContent = `# ${done} of ${boxes.length}. Pick the unticked box that's cheapest to fix this week.`;
    };
    boxes.forEach((b) => b.addEventListener("change", update));
    update();
  }

  // --------------------------------------------------------------------------- easter egg: console
  function consoleHint() {
    console.log("%c" + document.title, "font: 700 24px monospace; color: #ff2e88; text-shadow: 0 0 8px #ff2e88");
    console.log("%cAll tests passed. Suspicious.", "font: 14px monospace; color: #00f0ff");
  }

  function start() {
    consoleHint();
    $("hero-in").addEventListener("input", hero); hero();
    toolMap(); sast(); authz(); input(); pipeline(); suppress(); triage(); measure(); checklist();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
})();
