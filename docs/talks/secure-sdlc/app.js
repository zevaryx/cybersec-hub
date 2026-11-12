/* app.js - the live demos for "Security in Your Development Process", built on the models in sdlc.js.
   Every team, finding, service and number is invented, and nothing is fetched or sent anywhere. */
(function () {
  "use strict";
  const L = window.SdlcLab;

  const $ = (id) => document.getElementById(id);
  const esc = L.escapeHtml;
  function store(key, val) {
    try { if (val === undefined) return localStorage.getItem(key); localStorage.setItem(key, val); } catch (e) {}
    return null;
  }
  const verdict = (id, cls, text) => { const el = $(id); el.className = "verdict" + (cls ? " " + cls : ""); el.textContent = text; };
  const note = (id, text, cls) => { const el = $(id); el.className = "comment" + (cls ? " " + cls : ""); el.textContent = text; };
  const stat = (b, span, cls) => `<div class="stat ${cls || ""}"><b>${b}</b><span>${span}</span></div>`;
  const pick = (id, attr, val) => { for (const b of $(id).querySelectorAll("button")) b.setAttribute("aria-pressed", String(b.getAttribute(attr) === String(val))); };
  const talkLink = (slug, title) => `<a href="../${slug}/">${esc(title)}</a>`;

  // --------------------------------------------------------------------------- title: security.txt checker
  function hero() {
    const r = L.lintSecurityTxt($("hero-in").value);
    const out = $("hero-out");
    const lines = [];
    r.errors.forEach((e) => lines.push("✗ " + e));
    r.warnings.forEach((e) => lines.push("! " + e));
    if (r.ok) lines.unshift("✓ valid: Contact and Expires are present and well formed");
    out.className = "hashout " + (r.ok ? (r.warnings.length ? "y" : "ok") : "bad");
    out.style.whiteSpace = "pre-wrap";
    out.textContent = lines.join("\n") || "(nothing to report)";
    note("hero-note", "# " + (r.egg || (r.ok ? "RFC 9116 needs only two fields. Everything else is a kindness." : "two fields are required: Contact and Expires. Fix the first line and see.")));
  }

  // --------------------------------------------------------------------------- lifecycle board
  function lifecycle() {
    const seen = new Set();
    $("lc-stages").innerHTML = L.STAGES.map((s) => `<button type="button" data-s="${s.id}" aria-pressed="false">${esc(s.name)}</button>`).join("");
    function show(id) {
      const s = L.STAGES.find((x) => x.id === id); if (!s) return;
      seen.add(id); pick("lc-stages", "data-s", id);
      $("lc-detail").innerHTML = `<b>${esc(s.name)}</b>
        <span><i class="k">THE LIGHT STEP</i> ${esc(s.step)}</span>
        <span><i class="k">COSTS</i> ${esc(s.time)}</span>
        <span><i class="k">CATCHES</i> ${esc(s.catches)}</span>
        <span><i class="k">IF YOU FIND IT LATER</i> ${esc(s.later)}</span>
        <span class="lc-talks"><i class="k">LEARN IT</i> ${s.talks.map((t) => talkLink(t[0], t[1])).join(" · ")}</span>`;
      if (seen.size === L.STAGES.length) note("lc-note", "# all six stages opened. Notice that none of them is a gate at the end: the steps are small and spread out. That's what keeps them from being skipped.", "ok");
      else note("lc-note", `# ${seen.size} of ${L.STAGES.length} stages seen. Start at the stage where your last real bug got through.`);
    }
    $("lc-stages").addEventListener("click", (e) => { const b = e.target.closest("button[data-s]"); if (b) show(b.dataset.s); });
    show("req"); seen.clear(); seen.add("req");
    note("lc-note", "# 1 of 6 stages seen. Start at the stage where your last real bug got through.");
  }

  // --------------------------------------------------------------------------- requirements
  function reqs() {
    $("rq-pick").innerHTML = L.REQ_FEATURES.map((f) => `<button type="button" data-f="${f.id}" aria-pressed="false">${esc(f.name)}</button>`).join("");
    let cur = L.REQ_FEATURES[0];
    function render() {
      pick("rq-pick", "data-f", cur.id);
      const withTests = $("rq-tests").checked;
      $("rq-title").textContent = `"${cur.name}" · security acceptance criteria`;
      $("rq-list").innerHTML = cur.criteria.map((c) => `<li><span>${esc(c[0])}</span>${withTests ? `<code>${esc(c[1])}</code>` : ""}</li>`).join("");
      $("rq-talk").innerHTML = `Where to learn the detail: ${talkLink(cur.talk[0], cur.talk[1])}. All criteria here are examples.`;
      note("rq-note", withTests ? "# every criterion became a test name. If you can't name the test, the criterion is probably too vague." : "# these are statements a developer can build and a reviewer can hold someone to. Tick the box to see them as tests.");
    }
    $("rq-pick").addEventListener("click", (e) => { const b = e.target.closest("button[data-f]"); if (!b) return; cur = L.REQ_FEATURES.find((f) => f.id === b.dataset.f); render(); });
    $("rq-tests").addEventListener("change", render);
    render();
  }

  // --------------------------------------------------------------------------- frameworks
  function frameworks() {
    const seen = new Set();
    $("fw-pick").innerHTML = L.FRAMEWORKS.map((f) => `<button type="button" data-f="${f.id}" aria-pressed="false">${esc(f.name)}</button>`).join("");
    $("fw-map").innerHTML = `<thead><tr><th>Stage</th><th>OWASP SAMM</th><th>NIST SSDF</th></tr></thead><tbody>${L.FW_MAP.map((r) => `<tr><td>${esc(r[0])}</td><td>${esc(r[1].replace("SAMM: ", ""))}</td><td>${esc(r[2].replace("SSDF: ", ""))}</td></tr>`).join("")}</tbody>`;
    function show(id) {
      const f = L.FRAMEWORKS.find((x) => x.id === id); seen.add(id); pick("fw-pick", "data-f", id);
      $("fw-detail").innerHTML = `<b>${esc(f.name)} <small>${esc(f.kind)}</small></b>
        <span><i class="k">STATUS</i> ${esc(f.status)}</span>
        <span><i class="k">WHAT IT IS</i> ${esc(f.what)}</span>
        <span><i class="k">USE IT TO</i> ${esc(f.use)}</span>
        <span><i class="k">DON'T</i> ${esc(f.avoid)}</span>`;
      if (seen.size === L.FRAMEWORKS.length) note("fw-note", "# all five read. The common advice: pick one to score yourself against, borrow vocabulary from the others, and stop comparing.", "ok");
      else note("fw-note", `# ${seen.size} of ${L.FRAMEWORKS.length} read. They overlap on purpose: you need one of them, not all.`);
    }
    $("fw-pick").addEventListener("click", (e) => { const b = e.target.closest("button[data-f]"); if (b) show(b.dataset.f); });
    show("samm"); seen.clear(); seen.add("samm");
    note("fw-note", "# 1 of 5 read. They overlap on purpose: you need one of them, not all.");
  }

  // --------------------------------------------------------------------------- champions
  function champions() {
    $("ch-support").innerHTML = L.CHAMPION_SUPPORT.map((s, i) => `<label class="chk"><input type="checkbox" data-k="${s[0]}"${i < 3 ? " checked" : ""}> ${esc(s[1])}</label>`).join("");
    const ids = ["devs", "teams", "ratio", "hours"];
    function render() {
      const v = {}; ids.forEach((k) => { v[k] = +$("ch-" + k).value; $("ch-" + k + "-out").textContent = v[k]; });
      const support = Array.from($("ch-support").querySelectorAll("input:checked")).map((i) => i.dataset.k);
      const p = L.championPlan({ devs: v.devs, teams: v.teams, ratio: v.ratio, hours: v.hours, support });
      $("ch-stats").innerHTML = stat(p.champions, "champions", "") + stat(p.coverage + "%", `of ${p.teams} teams covered`, p.coverage === 100 ? "slow" : "fast") + stat(p.totalHours + " h", "per week in total") + stat(p.fte, "full-time equivalents");
      $("ch-warn").innerHTML = p.warnings.length ? p.warnings.map((w) => `<li>${esc(w)}</li>`).join("") : "<li class=\"good\">Looks workable: protected time, support and every team covered.</li>";
      note("ch-note", p.verdict === "ok" ? "# every team has a champion, with time and support. The next risk is a champion who leaves: rotate and back up." : p.verdict === "bad" ? "# red flags: time or support is too thin for the role to change anything." : "# close. Read the warnings and adjust one slider at a time.", p.verdict === "ok" ? "ok" : p.verdict === "bad" ? "bad" : "y");
    }
    for (const k of ids) $("ch-" + k).addEventListener("input", render);
    $("ch-support").addEventListener("change", render);
    render();
  }

  // --------------------------------------------------------------------------- paved roads
  function paved() {
    $("pr-pick").innerHTML = L.ROADS.map((r) => `<button type="button" data-r="${r.id}" aria-pressed="false">${esc(r.task)}</button>`).join("");
    function pickRoad(id) {
      const r = L.ROADS.find((x) => x.id === id); pick("pr-pick", "data-r", id);
      $("pr-paved").value = r.paved; $("pr-diy").value = r.diy;
      $("pr-detail").innerHTML = `<b>${esc(r.task)}</b><span>${esc(r.what)}</span><span class="fine">Without it: ${esc(r.risk)}</span>`;
      render();
    }
    function render() {
      const paved = +$("pr-paved").value, diy = +$("pr-diy").value, fit = +$("pr-fit").value;
      $("pr-paved-out").textContent = paved + " min"; $("pr-diy-out").textContent = diy + " min"; $("pr-fit-out").textContent = fit + "%";
      const a = L.adoption({ paved, diy, fit, mandate: $("pr-mandate").checked });
      $("pr-stats").innerHTML = stat(a.rate + "%", "of cases take the paved road", a.verdict === "ok" ? "slow" : "fast") + stat(a.easier + "%", "how much easier it is (50% = same)") + stat(fit + "%", "of real cases it covers");
      verdict("pr-verdict", a.verdict, a.advice);
      note("pr-note", a.note ? "# " + a.note : "# adoption = coverage × how much easier the road is. No mandate needed when both are high.");
    }
    $("pr-pick").addEventListener("click", (e) => { const b = e.target.closest("button[data-r]"); if (b) pickRoad(b.dataset.r); });
    for (const id of ["pr-paved", "pr-diy", "pr-fit"]) $(id).addEventListener("input", render);
    $("pr-mandate").addEventListener("change", render);
    pickRoad("http");
  }

  // --------------------------------------------------------------------------- security.txt builder
  function disclosure() {
    const val = () => ({ contact: $("st-contact").value, days: $("st-days").value, languages: $("st-lang").value, policy: $("st-policy").value.trim(), ack: $("st-ack").value.trim(), encryption: $("st-enc").value.trim(), canonical: $("st-canon").value.trim() });
    function render() {
      const text = L.buildSecurityTxt(val());
      $("st-out").textContent = text;
      const r = L.lintSecurityTxt(text);
      const items = [];
      r.errors.forEach((e) => items.push(`<li class="bad">✗ ${esc(e)}</li>`));
      r.warnings.forEach((e) => items.push(`<li class="y">! ${esc(e)}</li>`));
      r.infos.forEach((e) => items.push(`<li>· ${esc(e)}</li>`));
      if (r.ok) items.unshift(`<li class="good">✓ passes the checker: Contact and Expires present and well formed</li>`);
      $("st-lint").innerHTML = items.join("");
      note("st-note", /hacker cat approves/.test(text) ? "# hacker cat approves. (Comments start with #, and researchers' tools ignore them.)" : "# serve it at /.well-known/security.txt as text/plain over https, and put a reminder in the calendar to renew Expires.");
    }
    for (const id of ["st-contact", "st-days", "st-lang", "st-policy", "st-ack", "st-enc", "st-canon"]) $(id).addEventListener("input", render);
    $("st-copy").addEventListener("click", () => {
      const t = $("st-out").textContent;
      const done = () => note("st-note", "# copied. Now put it on the web server, not just in the repository.");
      try { navigator.clipboard.writeText(t).then(done, () => note("st-note", "# the browser blocked copying: select the text and copy it yourself.")); }
      catch (e) { note("st-note", "# the browser blocked copying: select the text and copy it yourself."); }
    });
    render();
  }

  // --------------------------------------------------------------------------- the report clock
  function clock() {
    function render() {
      const received = Date.parse($("rc-date").value + "T09:00:00Z");
      if (isNaN(received)) { $("rc-list").innerHTML = ""; note("rc-note", "# pick a date."); return; }
      const exploited = $("rc-exploited").checked, eu = $("rc-eu").checked, severity = $("rc-sev").value;
      const k = L.reportClock({ received, severity, exploited, euProduct: eu });
      $("rc-list").innerHTML = k.items.map((i) => { const w = L.fmtWhen(i.at, received); return `<li class="${/^cra/.test(i.key) ? "cra" : i.who === "researcher" ? "res" : ""}"><span class="rc-when"><b>${w.rel}</b><small>${w.day}</small></span><span class="rc-what"><b>${esc(i.label)}</b><small>${esc(i.basis)}</small></span><span class="rc-who">${esc(i.who)}</span></li>`; }).join("");
      if (severity === "critical" && exploited && eu) note("rc-note", "# three clocks at once: yours, the researcher's and the EU's. This is why you rehearse the first day before you need it.", "bad");
      else if (exploited && eu) note("rc-note", "# the EU early warning is the first thing due, and it's due before you've fixed anything. Decide who files it.", "y");
      else if (exploited) note("rc-note", "# exploited bugs shorten your own fix target and the researcher's 90 days to 7.", "y");
      else note("rc-note", "# the dates above are examples: set targets you can keep, and publish them.");
    }
    for (const id of ["rc-date", "rc-sev", "rc-exploited", "rc-eu"]) $(id).addEventListener("input", render);
    $(("rc-exploited")).addEventListener("change", render); $("rc-eu").addEventListener("change", render);
    render();
  }

  // --------------------------------------------------------------------------- bug bounty readiness
  function bounty() {
    $("bb-list").innerHTML = L.BOUNTY_CHECKS.map((c) => `<label class="chk"><input type="checkbox" data-k="${c[0]}"> ${esc(c[1])}</label>`).join("");
    function render() {
      const done = Array.from($("bb-list").querySelectorAll("input:checked")).map((i) => i.dataset.k);
      const r = L.bountyReadiness(done);
      $("bb-stats").innerHTML = stat(`${r.n} / ${r.total}`, "ready", r.level === "ok" ? "slow" : "fast") + stat(r.core ? "yes" : "no", "the four basics are in place", r.core ? "slow" : "fast");
      verdict("bb-verdict", r.level, r.text);
    }
    $("bb-list").addEventListener("change", render);
    render();
  }

  // --------------------------------------------------------------------------- blameless
  function blameless() {
    const flipped = new Set();
    $("bl-list").innerHTML = L.BLAME.map((b, i) => `<button type="button" class="bl-item" data-i="${i}" aria-pressed="false"><span class="bl-tag">WHO?</span><span class="bl-text">${esc(b.blame)}</span></button>`).join("");
    $("bl-list").addEventListener("click", (e) => {
      const btn = e.target.closest("button[data-i]"); if (!btn) return;
      const i = +btn.dataset.i, b = L.BLAME[i];
      if (flipped.has(i)) { flipped.delete(i); btn.setAttribute("aria-pressed", "false"); btn.innerHTML = `<span class="bl-tag">WHO?</span><span class="bl-text">${esc(b.blame)}</span>`; }
      else { flipped.add(i); btn.setAttribute("aria-pressed", "true"); btn.innerHTML = `<span class="bl-tag ok">WHAT LET THIS HAPPEN?</span><span class="bl-text">${esc(b.better)}<small>Change: ${esc(b.fix)}</small></span>`; }
      if (flipped.size === L.BLAME.length) note("bl-note", "# every sentence rewritten, and every one points at a change you can make. A name points at nothing.", "ok");
      else note("bl-note", `# ${flipped.size} of ${L.BLAME.length} rewritten. Blameless doesn't mean nobody is accountable: it means the first question is about the conditions.`);
    });
    note("bl-note", "# 0 of 6 rewritten. Blameless doesn't mean nobody is accountable: it means the first question is about the conditions.");
  }

  // --------------------------------------------------------------------------- useful metrics
  function metrics() {
    let q = 1;
    function render() {
      pick("mt-pick", "data-q", q);
      const m = L.usefulMetrics(q);
      const rows = Object.keys(L.SEV).map((s) => { const t = m.ttf[s]; return `<tr><td>${L.SEV[s].name}</td><td>${t.median == null ? "–" : t.median + " d"}</td><td>${t.n}</td><td>${t.openNow}</td></tr>`; }).join("");
      $("mt-ttf").innerHTML = `<thead><tr><th>Severity</th><th>Median to fix</th><th>Fixed</th><th>Still open</th></tr></thead><tbody>${rows}</tbody>`;
      $("mt-stats").innerHTML = stat(`${m.paved} / ${m.services}`, "services on the paved road", q === 2 ? "slow" : "") + stat(m.total, "findings this quarter") + stat(m.repeat.length, "bug classes seen last quarter too", m.repeat.length ? "fast" : "");
      $("mt-repeat").textContent = m.repeat.length ? `${m.repeat.join(", ")}. Most common first.${q === 2 ? " Authorization came back three times: the answer is a paved road and a test, not another reminder." : ""}` : "None yet: this is the first quarter, so there's nothing to compare.";
      note("mt-note", q === 1 ? "# quarter 1: criticals took a median of two weeks. That's the baseline to beat." : "# quarter 2: criticals down to four days and paved-road coverage doubled, yet every class came back. Faster fixes alone don't stop repeats.", q === 2 ? "ok" : "");
    }
    $("mt-pick").addEventListener("click", (e) => { const b = e.target.closest("button[data-q]"); if (b) { q = +b.dataset.q; render(); } });
    render();
  }

  // --------------------------------------------------------------------------- metrics that get gamed
  function gaming() {
    $("gm-pick").innerHTML = L.GOODHART.map((g) => `<button type="button" data-g="${g.id}" aria-pressed="false">${esc(g.name)}</button>`).join("");
    function show(id) {
      const g = L.GOODHART.find((x) => x.id === id); pick("gm-pick", "data-g", id);
      const word = g.rating === "bad" ? "AVOID" : g.rating === "y" ? "GUARD IT" : "KEEP";
      $("gm-detail").innerHTML = `<b>${esc(g.name)} <small class="${g.rating}">${word}</small></b>
        <span><i class="k">REWARDS</i> ${esc(g.rewards)}</span>
        <span><i class="k">GAMED BY</i> ${esc(g.gamed)}</span>
        <span><i class="k">INSTEAD</i> ${esc(g.better)}</span>`;
    }
    function table() {
      const cap = +$("gm-cap").value; $("gm-cap-out").textContent = cap;
      const easy = L.closureGame(cap, "easy"), worst = L.closureGame(cap, "worst");
      const row = (name, g) => `<tr><td>${name}</td><td>${g.closed}</td><td class="${g.criticalLeft ? "bad" : "ok"}">${g.criticalLeft}</td><td class="${g.highLeft ? "y" : "ok"}">${g.highLeft}</td></tr>`;
      $("gm-table").innerHTML = `<thead><tr><th>Strategy</th><th>Closed</th><th>Critical open</th><th>High open</th></tr></thead><tbody>${row("Easiest first", easy)}${row("Worst first", worst)}</tbody>`;
      if (easy.closed === worst.closed && easy.criticalLeft > 0) note("gm-note", `# same count on the dashboard (${easy.closed}), very different risk: ${easy.criticalLeft} critical and ${easy.highLeft} high still open.`, "bad");
      else if (easy.criticalLeft === 0) note("gm-note", "# with this much capacity even the easy-first team reaches the criticals. The count still says nothing about speed.", "y");
      else note("gm-note", "# raise or lower the capacity and watch which risks stay open.");
    }
    $("gm-pick").addEventListener("click", (e) => { const b = e.target.closest("button[data-g]"); if (b) show(b.dataset.g); });
    $("gm-cap").addEventListener("input", table);
    show("found"); table();
  }

  // --------------------------------------------------------------------------- maturity self-check
  const MU_KEY = "secure-sdlc-maturity";
  function maturity() {
    let ans = {};
    try { ans = JSON.parse(store(MU_KEY) || "{}"); } catch (e) {}
    $("mu-list").innerHTML = L.AREAS.map((a) => `<fieldset class="mu-area"><legend>${esc(a.name)}</legend>${a.qs.map((q, i) => `<div class="mu-q"><p>${esc(q[0])}</p><div class="mu-opts" role="radiogroup" aria-label="${esc(a.name)} question ${i + 1}">${L.ANSWERS.map((o) => `<label><input type="radio" name="mu-${a.id}-${i}" value="${o[1]}" data-k="${a.id}.${i}"> ${o[0]}</label>`).join("")}</div></div>`).join("")}</fieldset>`).join("");
    for (const r of $("mu-list").querySelectorAll("input[type=radio]")) r.checked = ans[r.dataset.k] === +r.value;
    function render() {
      const m = L.maturity(ans);
      $("mu-stats").innerHTML = stat(m.pct + "%", "overall", m.perfect ? "slow" : "") + stat(`${m.answered} / ${m.total}`, "questions answered");
      $("mu-areas").innerHTML = m.areas.map((a) => `<li><span>${esc(a.name)}</span><i class="bar"><b style="width:${a.pct}%"></b></i><em>${a.answered === a.total ? a.pct + "%" : "–"}</em></li>`).join("");
      if (m.perfect) { verdict("mu-next", "y", "Nothing to improve: every question answered Yes."); note("mu-note", "# suspiciously perfect. Your auditor would like a word.", "y"); }
      else if (m.weakest) {
        const w = m.areas.find((a) => a.id === m.weakest.id);
        verdict("mu-next", m.weakest.pct < 50 ? "bad" : "y", `Weakest area: ${w.name} (${w.pct}%). Next step: ${w.next || "all answered Yes here."}`);
        note("mu-note", m.complete ? "# a score is a conversation starter, not a grade. Compare answers with a colleague: the disagreements are the useful part." : `# ${m.total - m.answered} questions still to answer.`);
      } else { verdict("mu-next", "", ""); note("mu-note", "# answer both questions in an area to see its score and a next step. Saved in this browser only."); }
    }
    $("mu-list").addEventListener("change", (e) => {
      const r = e.target.closest("input[type=radio]"); if (!r) return;
      ans[r.dataset.k] = +r.value; store(MU_KEY, JSON.stringify(ans)); render();
    });
    $("mu-reset").addEventListener("click", () => { ans = {}; store(MU_KEY, "{}"); for (const r of $("mu-list").querySelectorAll("input[type=radio]")) r.checked = false; render(); });
    render();
  }

  // --------------------------------------------------------------------------- the whole track
  function trackmap() {
    const pills = [["all", "Every talk"]].concat(L.STAGES.map((s) => [s.id, s.name]));
    $("tk-pick").innerHTML = pills.map((p) => `<button type="button" data-s="${p[0]}" aria-pressed="false">${esc(p[1])}</button>`).join("");
    const stageName = (id) => (L.STAGES.find((s) => s.id === id) || {}).name || id;
    $("tk-grid").innerHTML = L.TRACK.map((t, i) => `<a class="tk-item" href="../${t[0]}/" data-st="${t[2].join(" ")}"><b>${String(i + 1).padStart(2, "0")}</b><span>${esc(t[1])}</span><small>${esc(t[2].map(stageName).join(", "))}</small></a>`).join("");
    function show(id) {
      pick("tk-pick", "data-s", id);
      let n = 0;
      for (const a of $("tk-grid").querySelectorAll(".tk-item")) { const on = id === "all" || a.dataset.st.split(" ").includes(id); a.classList.toggle("dim", !on); if (on) n++; }
      note("tk-note", id === "all" ? "# eighteen talks, six stages. Pick a stage to see which ones teach it." : `# ${n} talks teach the ${stageName(id).toLowerCase()} stage. Several cover more than one.`);
    }
    $("tk-pick").addEventListener("click", (e) => { const b = e.target.closest("button[data-s]"); if (b) show(b.dataset.s); });
    show("all");
  }

  // --------------------------------------------------------------------------- checklist
  const SD_KEY = "secure-sdlc-checklist";
  function checklist() {
    const boxes = Array.from(document.querySelectorAll("#sd-list input[type=checkbox]"));
    let saved = {};
    try { saved = JSON.parse(store(SD_KEY) || "{}"); } catch (e) {}
    boxes.forEach((b) => { b.checked = !!saved[b.dataset.k]; });
    const update = () => {
      const done = boxes.filter((b) => b.checked).length;
      store(SD_KEY, JSON.stringify(Object.fromEntries(boxes.map((b) => [b.dataset.k, b.checked]))));
      const n = $("sd-note"); n.className = "comment";
      if (done === boxes.length) { n.textContent = "# 10 of 10. Now check that the ticks are real: pick one and ask the person who owns it to show you."; n.classList.add("ok"); }
      else if (!done) n.textContent = "# tick what's true for your team today. Each gap is a ticket, not a failure. Saved in this browser only.";
      else n.textContent = `# ${done} of ${boxes.length}. Pick the unticked box that's cheapest to fix this month. Don't try for all of them at once.`;
    };
    boxes.forEach((b) => b.addEventListener("change", update));
    update();
  }

  function consoleHint() {
    console.log("%c" + document.title, "font: 700 24px monospace; color: #ff2e88; text-shadow: 0 0 8px #ff2e88");
    console.log("%cDoes this hub have a security.txt? Not yet. That's today's homework.", "font: 14px monospace; color: #00f0ff");
  }

  function start() {
    consoleHint();
    $("hero-in").addEventListener("input", hero); hero();
    lifecycle(); reqs(); frameworks(); champions(); paved(); disclosure(); clock(); bounty(); blameless(); metrics(); gaming(); maturity(); trackmap(); checklist();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
})();
