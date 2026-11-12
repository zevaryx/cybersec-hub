/* app.js - the live demos for "Threat Modeling in Practice".
   Everything is a simulation in this page: a data-flow diagram builder, STRIDE prompts, a threat log you rank, answer and turn
   into tickets, and a toy attack tree. The logic lives in tm.js (window.TMLab). The systems, threats and numbers are invented;
   nothing is fetched or sent anywhere, and nothing is kept once the tab is closed (except the habit checklist, in this browser). */
(function () {
  "use strict";
  const T = window.TMLab;

  // --------------------------------------------------------------------------- helpers
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const sp = (cls, s) => `<span class="${cls}">${esc(s)}</span>`;
  const click = (id, fn) => $(id).addEventListener("click", fn);
  function store(key, val) {
    try { if (val === undefined) return localStorage.getItem(key); localStorage.setItem(key, val); } catch (e) {}
    return null;
  }
  const segPick = (id, attr, fn) => {
    const box = $(id);
    box.addEventListener("click", (e) => {
      const b = e.target.closest("button[" + attr + "]"); if (!b) return;
      for (const x of box.querySelectorAll("button")) x.setAttribute("aria-pressed", String(x === b));
      fn(b.getAttribute(attr));
    });
  };
  const verdict = (id, cls, text) => { const el = $(id); el.className = "verdict " + cls; el.textContent = text; };
  const chip = (k) => `<i class="ch ch-${k}" title="${esc(T.catName(k))}">${esc(k)}</i>`;
  const today = () => new Date().toISOString().slice(0, 10);
  const inDays = (n) => new Date(Date.now() + n * 864e5).toISOString().slice(0, 10);

  // state shared by the slides: the model drawn in exercise 1, and the log from exercise 2 that parts 4 reads
  const state = { model: T.createModel(), log: T.createLog() };
  const refModel = T.SAMPLES.photo.build();
  const activeModel = () => (state.model.nodes.length >= 3 ? state.model : refModel);

  // --------------------------------------------------------------------------- title: what kind of thing is it?
  function hero() {
    const el = $("hero-in"), v = el.value;
    el.style.width = Math.min(26, Math.max(8, v.length + 1)) + "ch";
    const c = T.classify(v), t = v.trim().toLowerCase();
    let out;
    if (c.type) {
      const letters = T.perElement(c.type, c.log);
      out = `${sp("k", "kind:   ")} ${esc(T.TYPE_LABEL[c.type])}${c.log ? " (holds logs)" : ""}<br>${sp("k", "letters:")} ${esc(letters.join(" · "))}<br>${sp("k", "ask:    ")} ${esc(letters.map((k) => T.strideByKey(k).name).join(", "))}`;
    } else out = `${sp("k", "kind:   ")} can't tell yet<br>${sp("k", "letters:")} ?<br>${sp("k", "ask:    ")} is it outside, running, resting or moving?`;
    $("hero-out").innerHTML = out;
    let note;
    if (!t) note = "# nothing to model. The easiest system to secure is the one that doesn't exist, and the hardest to ship.";
    else if (/^(the )?attackers?$/.test(t)) note = "# attackers aren't a box on the diagram: they're what the letters ask each box about.";
    else if (t === "everything") note = "# 'everything' isn't an element, it's a mood. Pick one box or one arrow.";
    else if (/^(the )?internet$/.test(t)) note = "# not a box: it's the space between the zones. Draw a boundary, not a cloud.";
    else if (t === "stride") note = "# the acronym itself! Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege.";
    else if (/^coffee machine$/.test(t)) note = "# a coffee machine on the office network is a fine thing to ask about. It's just not in this keyword guess.";
    else if (c.log) note = "# a log earns an extra letter, Repudiation: logs are where 'who did that?' gets answered.";
    else if (c.type === "entity") note = "# outside our control: we decide what to believe from it.";
    else if (c.type === "process") note = "# it runs our code, so all six letters apply.";
    else if (c.type === "store") note = "# where data rests: tampering, disclosure and denial of service.";
    else if (c.type === "flow") note = "# data in motion: ask at every boundary it crosses.";
    else note = "# a keyword guess, not intelligence. Is it something outside, something that runs, somewhere data rests, or data moving?";
    $("hero-note").textContent = note;
  }

  // --------------------------------------------------------------------------- the four questions, on a password reset
  const FQ = [
    ["What are we working on?", "A password reset. The user asks for a link, we email it, they set a new password.", "# a sentence and a sketch. If you can't say it simply, you aren't ready to model it."],
    ["What can go wrong?", "Someone guesses or intercepts the link. The link works twice. The email goes to the wrong address. The page tells a stranger which emails have accounts.", "# four threats from one sentence: prompts beat inspiration."],
    ["What are we going to do about it?", "A long random link that works once and expires in 30 minutes. The same message whether or not the account exists. A notice to the old address when the password changes.", "# each answer is a decision someone can own."],
    ["Did we do a good enough job?", "Test it: reuse the link, try an expired one, compare responses for a known and an unknown email. Look again when we add SMS reset.", "# the fourth question has a date in it. That's what makes it a habit."],
  ];
  function fq(i) {
    const q = FQ[Number(i)];
    $("fq-out").innerHTML = `<b>${esc(q[0])}</b><span>${esc(q[1])}</span>`;
    $("fq-note").textContent = q[2];
  }

  // --------------------------------------------------------------------------- how big should this threat model be?
  const wfFlags = {};
  const WF_NOTES = { "Let admins impersonate users": "# one trigger, but a big one: the count is a starting point, and judgement overrides it." };
  function wf(note) {
    const a = T.advise(wfFlags);
    $("wf-out").innerHTML = `<b>${esc(a.name)}${a.key === "skip" ? "" : " · " + esc(a.mins) + " min"}</b><span><em>Who:</em> ${esc(a.who)}</span><span><em>What:</em> ${esc(a.what)}</span>`;
    $("wf-out").className = "card wf-out wf-" + a.key;
    let n = note;
    if (!n) n = a.key === "deep" && a.count === 4 ? "# all four triggers: this is the one to put on the calendar today."
      : a.key === "skip" ? "# no triggers: a one-line note in the pull request is a perfectly good threat model."
      : "# " + a.count + " of 4 triggers. Tick what's true for the change you're working on.";
    $("wf-note").textContent = n;
  }
  function wfInit() {
    $("wf-flags").innerHTML = T.TRIGGERS.map((t) => `<label><input type="checkbox" data-k="${t.k}"> ${esc(t.label)}</label>`).join("");
    $("wf-flags").addEventListener("change", (e) => {
      const b = e.target.closest("input[data-k]"); if (!b) return;
      wfFlags[b.dataset.k] = b.checked;
      for (const x of $("wf-presets").querySelectorAll("button")) x.setAttribute("aria-pressed", "false");
      wf();
    });
    $("wf-presets").innerHTML = T.PRESETS.map((p, i) => `<button type="button" data-p="${i}" aria-pressed="false">${esc(p.label)}</button>`).join("");
    segPick("wf-presets", "data-p", (i) => {
      const p = T.PRESETS[Number(i)];
      for (const t of T.TRIGGERS) { wfFlags[t.k] = !!p.flags[t.k]; $("wf-flags").querySelector(`[data-k="${t.k}"]`).checked = !!p.flags[t.k]; }
      wf(WF_NOTES[p.label]);
    });
    wf();
  }

  // --------------------------------------------------------------------------- the four kinds of element
  const DE = {
    entity: { what: "Something outside your control that sends or receives data: a user, a partner, another company's service.", ask: "What do we believe about it, and what if that's wrong?" },
    process: { what: "Code that runs and acts on data: an app, an API, a worker, a function.", ask: "What does it trust, and what can it do if someone lies to it?" },
    store: { what: "Anywhere data rests: a database, a bucket, a queue, a log file.", ask: "Who can read it, change it, or fill it up?" },
    flow: { what: "Data moving between a process and something else, labelled with what moves.", ask: "What happens to it on the way, and at each boundary it crosses?" },
  };
  function shapeSvg(type) {
    const body = {
      entity: '<rect x="30" y="14" width="160" height="46" class="dn-shape dn-entity"/><text x="110" y="42" text-anchor="middle">Payment provider</text>',
      process: '<rect x="30" y="14" width="160" height="46" rx="23" class="dn-shape dn-process"/><text x="110" y="42" text-anchor="middle">API</text>',
      store: '<line x1="30" y1="14" x2="190" y2="14" class="dn-store"/><line x1="30" y1="60" x2="190" y2="60" class="dn-store"/><text x="110" y="42" text-anchor="middle">Photo storage</text>',
      flow: '<path d="M20 37H186" class="df-line"/><path d="M190 37l-14-7v14z" class="df-head"/><text x="105" y="26" text-anchor="middle">photos</text>',
    }[type];
    return `<svg viewBox="0 0 220 74" class="de-svg" aria-hidden="true">${body}</svg>`;
  }
  function de(type) {
    const log = type === "store" && $("de-log").checked;
    $("de-logrow").hidden = type !== "store";
    const letters = T.perElement(type, log), d = DE[type];
    $("de-shape").innerHTML = shapeSvg(type);
    $("de-out").innerHTML = `<b>${esc(T.TYPE_LABEL[type])}</b><span>${esc(d.what)}</span><span><em>Ask:</em> ${esc(d.ask)}</span>
      <span class="de-letters">${letters.map((k) => `${chip(k)} ${esc(T.strideByKey(k).name)}`).join(" · ")}</span>`;
    $("de-note").textContent = log ? "# logs earn Repudiation: they're where 'who did that?' is answered." : type === "entity" ? "# only two letters: we can't tamper with their systems, only choose what to believe from them." : type === "process" ? "# all six: this is where our own decisions run." : "";
  }
  let deType = "entity";

  // --------------------------------------------------------------------------- the diagram renderer
  const NW = 160, NH = 40, ROW = 64, TOP = 40, BAND = 300, W = 900;
  const clip = (cx, cy, tx, ty) => {
    const dx = tx - cx, dy = ty - cy; if (!dx && !dy) return [cx, cy];
    const t = Math.min(dx ? NW / 2 / Math.abs(dx) : Infinity, dy ? NH / 2 / Math.abs(dy) : Infinity, 1);
    return [cx + dx * t, cy + dy * t];
  };
  const trunc = (s, n) => (s.length > n ? s.slice(0, n - 1) + "…" : s);
  function layout(m) {
    const bands = T.ZONES.map(() => []), pos = {};
    for (const n of m.nodes) { const b = T.ZONES.findIndex((z) => z.id === n.zone); pos[n.id] = { b, i: bands[b].length }; bands[b].push(n); }
    const rows = Math.max(3, ...bands.map((b) => b.length));
    for (const n of m.nodes) { const p = pos[n.id]; p.x = p.b * BAND + BAND / 2; p.y = TOP + 14 + NH / 2 + p.i * ROW; }
    return { pos, H: TOP + 24 + rows * ROW };
  }
  function drawModel(svg, m, o) {
    o = o || {};
    const { pos, H } = layout(m), id = svg.id || "dfd";
    const parts = [`<defs><marker id="${id}-ar" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" class="df-head"/></marker><marker id="${id}-arx" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" class="df-head cross"/></marker></defs>`];
    if (o.bounds !== false) {
      T.ZONES.forEach((z, i) => {
        parts.push(`<rect x="${i * BAND}" y="0" width="${BAND}" height="${H}" class="zone zone-${i}"/>`);
        parts.push(`<text x="${i * BAND + BAND / 2}" y="24" text-anchor="middle" class="zone-label">${esc(z.name.toUpperCase())}</text>`);
        if (i) parts.push(`<line x1="${i * BAND}" y1="6" x2="${i * BAND}" y2="${H - 6}" class="zone-line"/>`);
      });
    }
    if (!m.nodes.length) parts.push(`<text x="${W / 2}" y="${H / 2}" text-anchor="middle" class="dfd-empty">Add an element to begin</text>`);
    // flows first, so nodes sit on top
    const seen = {};
    for (const f of m.flows) {
      const a = pos[f.from], b = pos[f.to];
      const cross = o.crossings !== false && T.crosses(m, f), key = [f.from, f.to].sort().join("|");
      const rev = m.flows.some((g) => g.from === f.to && g.to === f.from), side = rev ? (f.from < f.to ? 1 : -1) : 0;
      seen[key] = (seen[key] || 0) + 1;
      let d, lx, ly, anchor = "start";
      if (a.b === b.b) {
        const diff = Math.abs(a.i - b.i), up = b.i < a.i, off = side * 9;
        const y1 = a.y + (up ? -NH / 2 : NH / 2), y2 = b.y + (up ? NH / 2 : -NH / 2);
        if (diff === 1) { d = `M${a.x + off} ${y1} L${b.x + off} ${y2}`; lx = a.x + off + (side < 0 ? -8 : 8); ly = (y1 + y2) / 2 + 3; anchor = side < 0 ? "end" : "start"; }
        else { const B = 100 + 36 * diff; d = `M${a.x} ${y1} Q${a.x + B} ${(y1 + y2) / 2} ${b.x} ${y2}`; lx = a.x + B / 2 + 6; ly = (y1 + y2) / 2 + 3; }
      } else if (Math.abs(a.b - b.b) > 1) {
        const [x1, y1] = clip(a.x, a.y, b.x, b.y - 40), [x2, y2] = clip(b.x, b.y, a.x, a.y - 40), cy = Math.max(8, Math.min(a.y, b.y) - 62);
        d = `M${x1} ${y1 - NH / 2 + 4} Q${(x1 + x2) / 2} ${cy} ${x2} ${y2 - NH / 2 + 4}`; lx = (x1 + x2) / 2; ly = cy + 26; anchor = "middle";
      } else {
        const dx = b.x - a.x, dy = b.y - a.y, len = Math.hypot(dx, dy) || 1, ox = (-dy / len) * side * 8, oy = (dx / len) * side * 8;
        const [x1, y1] = clip(a.x, a.y, b.x, b.y), [x2, y2] = clip(b.x, b.y, a.x, a.y);
        d = `M${x1 + ox} ${y1 + oy} L${x2 + ox} ${y2 + oy}`; lx = (x1 + x2) / 2 + ox; ly = (y1 + y2) / 2 + oy + (side < 0 ? 15 : -6); anchor = "middle";
      }
      const sel = o.selected === f.id ? " sel" : "";
      parts.push(`<g class="df${cross ? " crossing" : ""}${sel}" data-id="${f.id}" data-kind="flow" tabindex="0" role="button" aria-label="Flow: ${esc(T.flowKey(m, f))}, ${esc(f.label)}${cross ? ", crosses a trust boundary" : ""}"><path d="${d}" class="df-hit"/><path d="${d}" class="df-line" marker-end="url(#${id}-${cross ? "arx" : "ar"})"/><text x="${lx}" y="${ly}" text-anchor="${anchor}" class="df-label">${esc(trunc(f.label, 14))}</text></g>`);
    }
    for (const n of m.nodes) {
      const p = pos[n.id], x = p.x - NW / 2, y = p.y - NH / 2, sel = o.selected === n.id ? " sel" : "";
      let shape;
      if (n.type === "entity") shape = `<rect x="${x}" y="${y}" width="${NW}" height="${NH}" class="dn-shape dn-entity"/>`;
      else if (n.type === "process") shape = `<rect x="${x}" y="${y}" width="${NW}" height="${NH}" rx="${NH / 2}" class="dn-shape dn-process"/>`;
      else shape = `<rect x="${x}" y="${y}" width="${NW}" height="${NH}" class="dn-hit"/><line x1="${x}" y1="${y}" x2="${x + NW}" y2="${y}" class="dn-store"/><line x1="${x}" y1="${y + NH}" x2="${x + NW}" y2="${y + NH}" class="dn-store"/>`;
      parts.push(`<g class="dn${sel}" data-id="${n.id}" data-kind="node" tabindex="0" role="button" aria-label="${esc(T.TYPE_LABEL[n.type])}: ${esc(n.name)}${n.log ? ", holds logs" : ""}">${shape}<text x="${p.x}" y="${p.y + 5}" text-anchor="middle" class="dn-text">${esc(trunc(n.name, 17))}</text>${n.log ? `<text x="${x + NW - 6}" y="${y + 13}" text-anchor="end" class="dn-tag">LOG</text>` : ""}</g>`);
    }
    svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
    svg.innerHTML = parts.join("");
    if (o.onSelect) {
      const act = (g) => o.onSelect(g.dataset.id, g.dataset.kind);
      svg.onclick = (e) => { const g = e.target.closest("g[data-id]"); if (g) act(g); };
      svg.onkeydown = (e) => { if (e.key !== "Enter" && e.key !== " ") return; const g = e.target.closest && e.target.closest("g[data-id]"); if (g) { e.preventDefault(); act(g); } };
    } else { svg.onclick = null; svg.onkeydown = null; }
  }

  // --------------------------------------------------------------------------- trust boundaries
  const tbPhoto = T.SAMPLES.photo.build();
  function tb() {
    drawModel($("tb-svg"), tbPhoto, { bounds: $("tb-bounds").checked, crossings: $("tb-cross").checked });
    $("tb-list").innerHTML = T.crossings(tbPhoto).map((f) => {
      const a = T.nodeById(tbPhoto, f.from), b = T.nodeById(tbPhoto, f.to);
      return `<li><b>${esc(a.name)} → ${esc(b.name)}</b><span>${esc(f.label)} · ${esc(T.zoneById(a.zone).short)} to ${esc(T.zoneById(b.zone).short)}</span></li>`;
    }).join("");
  }

  // --------------------------------------------------------------------------- exercise 1: the diagram builder
  let typeTouched = false;
  const modelNames = () => state.model.nodes;
  function fillSelects() {
    const keep = (id) => $(id).value, opts = modelNames().map((n) => `<option value="${n.id}">${esc(n.name)}</option>`).join("");
    const f = keep("f-from"), t = keep("f-to");
    $("f-from").innerHTML = opts; $("f-to").innerHTML = opts;
    if (f && state.model.nodes.some((n) => n.id === f)) $("f-from").value = f;
    if (t && state.model.nodes.some((n) => n.id === t)) $("f-to").value = t; else if (state.model.nodes.length > 1) $("f-to").selectedIndex = 1;
  }
  function builderRender(msg) {
    const m = state.model;
    drawModel($("b-svg"), m, { onSelect: () => {} });
    fillSelects();
    $("b-stats").innerHTML = `<div><b>${m.nodes.length}</b><span>elements</span></div><div><b>${m.flows.length}</b><span>flows (${T.crossings(m).length} cross a boundary)</span></div><div><b>${T.promptCount(m)}</b><span>STRIDE prompts to answer</span></div>`;
    $("b-lint").innerHTML = T.lint(m).map((s) => `<li class="m">${esc(s)}</li>`).join("") || `<li class="ok">No drawing mistakes spotted. Now argue about where the lines go.</li>`;
    if (msg) verdict("b-msg", msg[0], msg[1]);
    refreshTargets();
  }
  function bAdd() {
    const name = $("b-name").value;
    const r = T.addNode(state.model, { name, type: $("b-type").value, zone: $("b-zone").value, log: $("b-log").checked });
    if (!r.ok) { builderRender(["bad", r.error]); return; }
    $("b-name").value = ""; typeTouched = false; $("b-log").checked = false;
    const t = name.trim().toLowerCase();
    let msg = ["ok", `Added ${r.node.name}.`];
    if (/^(the )?cloud$/.test(t)) msg = ["y", "# 'The Cloud' isn't a process. Whose machine, in which account, run by whom? Name that."];
    else if (/^(the )?attackers?$/.test(t)) msg = ["y", "# attackers aren't boxes: they're what STRIDE asks each box about. Delete it and keep going."];
    else if (/^(the )?internet$/.test(t)) msg = ["y", "# the internet is the space between zones, not an element. A boundary will do."];
    if (msg[0] === "ok" && state.model.nodes.length >= 3 && /one zone/.test(T.lint(state.model).join(" "))) msg = ["y", "# everything in one zone: a flat network is a trust boundary on its day off."];
    builderRender(msg);
  }
  function fAdd() {
    const r = T.addFlow(state.model, { from: $("f-from").value, to: $("f-to").value, label: $("f-label").value });
    if (!r.ok) { builderRender(["bad", r.error + (/skips the code/.test(r.error) ? " No teleporting." : "")]); return; }
    $("f-label").value = "";
    const m = state.model, fl = r.flow;
    let msg = ["ok", `Added ${T.flowKey(m, fl)}${T.crosses(m, fl) ? ": it crosses a boundary, so it's a place to start." : "."}`];
    if (m.nodes.length >= 3 && /one zone/.test(T.lint(m).join(" "))) msg = ["y", "# everything in one zone: a flat network is a trust boundary on its day off."];
    builderRender(msg);
  }
  function builderInit() {
    $("b-zone").innerHTML = T.ZONES.map((z) => `<option value="${z.id}">${esc(z.name)}</option>`).join("");
    $("b-zone").value = "cloud";
    $("b-type").addEventListener("change", () => { typeTouched = true; });
    $("b-name").addEventListener("input", () => {
      if (typeTouched) return;
      const c = T.classify($("b-name").value);
      if (c.type && c.type !== "flow") { $("b-type").value = c.type; $("b-log").checked = c.log; }
    });
    $("b-name").addEventListener("keydown", (e) => { if (e.key === "Enter") bAdd(); });
    $("f-label").addEventListener("keydown", (e) => { if (e.key === "Enter") fAdd(); });
    click("b-add", bAdd); click("f-add", fAdd);
    click("b-photo", () => { state.model = T.SAMPLES.photo.build(); builderRender(["ok", "Loaded the reference answer: 8 elements, 9 flows. Compare it with yours: where do the lines differ, and why?"]); });
    click("b-clear", () => { state.model = T.createModel(); builderRender(["ok", "Cleared."]); });
    builderRender();
    $("b-msg").className = "verdict";
  }

  // --------------------------------------------------------------------------- STRIDE
  function strideInit() {
    $("st-pick").innerHTML = T.STRIDE.map((s, i) => `<button type="button" data-k="${s.k}" aria-pressed="${i === 0}">${s.k} · ${esc(s.name)}</button>`).join("");
    segPick("st-pick", "data-k", stride);
    const rows = [["entity", "SR"], ["process", "STRIDE"], ["store", "TID"], ["flow", "TID"]];
    $("st-chart").innerHTML = `<div class="sc-head"><span></span>${T.STRIDE.map((s) => `<span>${s.k}</span>`).join("")}</div>` +
      rows.map(([t, ls]) => `<div class="sc-row" data-t="${t}"><b>${esc(T.TYPE_LABEL[t])}</b>${T.STRIDE_KEYS.map((k) => `<span data-k="${k}" class="${ls.includes(k) ? "yes" : ""}">${ls.includes(k) ? "●" : ""}${t === "store" && k === "R" ? '<small title="Only for a store that holds logs">log</small>' : ""}</span>`).join("")}</div>`).join("");
    stride("S");
  }
  function stride(k) {
    const s = T.strideByKey(k);
    $("st-out").innerHTML = `<b>${esc(s.k)} · ${esc(s.name)}</b><span><em>Breaks:</em> ${esc(s.prop)}</span><span><em>Ask:</em> ${esc(s.ask)}</span><span><em>For example:</em> ${esc(s.ex)}</span><span><em>Defended by:</em> ${esc(s.defence)}</span>`;
    for (const c of $("st-chart").querySelectorAll("[data-k]")) c.classList.toggle("col", c.dataset.k === k);
  }

  // --------------------------------------------------------------------------- the walk: reference answers
  const wkModels = { website: T.SAMPLES.website.build(), photo: T.SAMPLES.photo.build() };
  let wkSample = "website", wkSel = null; const wkSeen = {};
  const wkDefault = { website: "Browser→Web server", photo: "Mobile app→API" };
  function wkTargetOf(m, id, kind) {
    if (kind === "flow") { const f = m.flows.find((x) => x.id === id); return { key: T.flowKey(m, f), type: "flow", label: T.flowKey(m, f) + " (" + f.label + ")", cross: T.crosses(m, f), letters: T.perElement("flow") }; }
    const n = T.nodeById(m, id); return { key: n.name, type: n.type, label: n.name, cross: false, letters: T.perElement(n.type, n.log) };
  }
  function wk(sample, selId, selKind) {
    const m = wkModels[sample]; wkSample = sample;
    if (!selId) { const f = m.flows.find((x) => T.flowKey(m, x) === wkDefault[sample]); selId = f.id; selKind = "flow"; }
    wkSel = selId;
    (wkSeen[sample] = wkSeen[sample] || new Set()).add(selId);
    drawModel($("wk-svg"), m, { selected: selId, onSelect: (id, kind) => wk(wkSample, id, kind) });
    const t = wkTargetOf(m, selId, selKind), refs = T.REFERENCE[sample].filter((r) => r.target === t.key);
    $("wk-out").innerHTML = `<b>${esc(t.label)}</b><span>${esc(T.TYPE_LABEL[t.type])}${t.cross ? " · crosses a trust boundary" : ""} · earns ${t.letters.map(chip).join(" ")}</span>` +
      (refs.length ? `<ul class="wk-threats">${refs.map((r) => `<li>${chip(r.cat)} <span>${esc(r.text)}</span><em>Response: ${esc(r.fix)}</em></li>`).join("")}</ul>`
        : `<span class="wk-none">No threat in the reference list for this one. It still earns its letters: draw a card and ask them.</span>`);
    const total = m.nodes.length + m.flows.length;
    $("wk-note").textContent = wkSeen[sample].size >= total ? "# every box and arrow visited: that's what 'per element' means." : `# ${wkSeen[sample].size} of ${total} visited. Click an element or an arrow.`;
  }

  // --------------------------------------------------------------------------- threat cards
  let cdSuit = "all", cdDeck = [], cdSeen = new Set(), cdDrawn = 0;
  function shuffle(a) { for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; } return a; }
  const cdPool = () => T.CARDS.filter((c) => cdSuit === "all" || c.suit === cdSuit);
  function cdShow(c) {
    const s = T.strideByKey(c.suit);
    $("cd-card").innerHTML = c ? `<small>${chip(c.suit)} ${esc(s.name)}</small><p>${esc(c.text)}</p><em>Pick an element or flow on your diagram, and answer it for that thing.</em>` : "";
  }
  function cdDrawOne() {
    if (!cdDeck.length) cdDeck = shuffle(cdPool().slice());
    const c = cdDeck.pop(); cdSeen.add(c.id); cdDrawn++; cdShow(c);
    $("cd-count").textContent = `${cdSeen.size} of ${T.CARDS.length} cards seen`;
    $("cd-note").textContent = cdSeen.size === T.CARDS.length ? "# every card drawn. A deck you've read right through has done its job: the questions are in your head now."
      : cdDrawn === 1 ? "# no threat? Say why not, in one line. That's a result too." : "";
  }
  function cdGrid() {
    $("cd-grid").innerHTML = T.CARDS.filter((c) => cdSuit === "all" || c.suit === cdSuit).map((c) => `<div class="cd-mini">${chip(c.suit)}<span>${esc(c.text)}</span></div>`).join("");
  }
  function cardsInit() {
    $("cd-pick").innerHTML = `<button type="button" data-s="all" aria-pressed="true">All 24</button>` + T.STRIDE.map((s) => `<button type="button" data-s="${s.k}" aria-pressed="false">${s.k} · ${esc(s.name)}</button>`).join("");
    segPick("cd-pick", "data-s", (s) => { cdSuit = s; cdDeck = []; cdGrid(); });
    click("cd-draw", cdDrawOne);
    click("cd-all", () => { const b = $("cd-all"), on = b.getAttribute("aria-pressed") !== "true"; b.setAttribute("aria-pressed", String(on)); b.textContent = on ? "Hide the grid" : "Show all 24"; $("cd-grid").hidden = !on; $("cd-card").hidden = on; cdGrid(); });
    $("cd-card").innerHTML = `<small>Press "Draw a card"</small><p>Each card is a prompt for one STRIDE letter.</p>`;
    cdGrid();
  }

  // --------------------------------------------------------------------------- LINDDUN and abuse cases
  function privacyInit() {
    $("pv-pick").innerHTML = T.LINDDUN.map((l, i) => `<button type="button" data-k="${l.k}" aria-pressed="${i === 0}">${esc(l.name)}</button>`).join("");
    segPick("pv-pick", "data-k", (k) => { const l = T.LINDDUN.find((x) => x.k === k); $("pv-out").innerHTML = `<b>${esc(l.name)}</b><span><em>Ask:</em> ${esc(l.ask)}</span><span><em>For example:</em> ${esc(l.ex)}</span>`; });
    const l = T.LINDDUN[0]; $("pv-out").innerHTML = `<b>${esc(l.name)}</b><span><em>Ask:</em> ${esc(l.ask)}</span><span><em>For example:</em> ${esc(l.ex)}</span>`;
    $("pv-abuse").innerHTML = T.ABUSE.map((a) => `<li>${esc(a)}</li>`).join("");
  }

  // --------------------------------------------------------------------------- attack tree
  const tree = T.photoTree(), blocked = new Set();
  const leafById = {}; for (const l of T.treeLeaves(tree)) leafById[l.id] = l;
  function atRender() {
    const r = T.evalTree(tree, blocked), onPath = new Set(r.path);
    $("at-root").innerHTML = `<small>GOAL · ANY ONE OF THESE (OR)</small><b>${esc(tree.label)}</b>`;
    $("at-grid").innerHTML = tree.children.map((br) => {
      const br2 = T.evalTree(br, blocked);
      return `<div class="at-br${br2.possible ? "" : " dead"}"><div class="at-head"><span class="at-op ${br.type}">${br.type.toUpperCase()}</span><b>${esc(br.label)}</b><small>${br2.possible ? "cheapest: " + br2.cost : "no path"}</small></div>` +
        br.children.map((l) => `<button type="button" class="at-leaf${blocked.has(l.id) ? " off" : ""}${onPath.has(l.id) ? " on" : ""}" data-id="${l.id}" aria-pressed="${blocked.has(l.id)}"><span>${esc(l.label)}</span><i>effort ${l.cost}</i><em>${blocked.has(l.id) ? "Defended: " + esc(l.fix) : "Click to add a defence"}</em></button>`).join("") + `</div>`;
    }).join("");
    if (r.possible) {
      const names = r.path.map((id) => leafById[id].label.replace(/^(.)/, (c) => c.toLowerCase()));
      verdict("at-out", r.cost <= 10 ? "bad" : r.cost <= 35 ? "y" : "ok", `Cheapest path costs ${r.cost}: ${names.join(", then ")}.`);
    } else verdict("at-out", "ok", "No path left in this tree.");
    $("at-note").textContent = !r.possible ? "# no path left. Which means no path we drew: what's missing from the tree?"
      : blocked.size ? "# defend the cheapest step and the next-cheapest becomes the new weakest point. Aim for balance, not a perfect wall." : "# defend the cheapest step and watch the next one take its place.";
  }
  function treeInit() {
    $("at-grid").addEventListener("click", (e) => {
      const b = e.target.closest(".at-leaf"); if (!b) return;
      const id = b.dataset.id; if (blocked.has(id)) blocked.delete(id); else blocked.add(id);
      atRender();
      const nb = $("at-grid").querySelector(`[data-id="${id}"]`); if (nb) nb.focus();
    });
    atRender();
  }

  // --------------------------------------------------------------------------- exercise 2: the threat log
  function targets() {
    const m = activeModel(), flows = T.crossings(m).concat(m.flows.filter((f) => !T.crosses(m, f)));
    return { m, flows, nodes: m.nodes };
  }
  function refreshTargets() {
    if (!$("t-target")) return;
    const { m, flows, nodes } = targets(), cur = $("t-target").value;
    $("t-target").innerHTML = `<optgroup label="Flows (boundary crossings first)">${flows.map((f) => `<option value="${esc(T.flowKey(m, f))}">${esc(T.flowKey(m, f))}${T.crosses(m, f) ? " ·" : ""}</option>`).join("")}</optgroup><optgroup label="Elements">${nodes.map((n) => `<option value="${esc(n.name)}">${esc(n.name)}</option>`).join("")}</optgroup>`;
    if (cur && Array.from($("t-target").options).some((o) => o.value === cur)) $("t-target").value = cur;
    tHint();
  }
  function tHint() {
    const { m } = targets(), v = $("t-target").value, nd = T.nodeByName(m, v);
    const letters = nd ? T.perElement(nd.type, nd.log) : T.perElement("flow"), type = nd ? T.TYPE_LABEL[nd.type] : "Data flow";
    $("t-hint").textContent = `${type} earns ${letters.join(" ")}. A guide, not a rule: log what you find.`;
  }
  function coverageRender() {
    const c = T.coverage(state.log);
    $("t-cov").innerHTML = T.STRIDE.map((s) => `<div class="cv${c.counts[s.k] >= c.goal ? " ok" : ""}" title="${esc(s.name)}"><b>${s.k}</b><span>${c.counts[s.k]} / ${c.goal}</span></div>`).join("");
    return c;
  }
  function logRender() {
    const c = coverageRender();
    $("t-list").innerHTML = state.log.items.map((t) => `<li>${chip(t.cat)}<span><b>${esc(t.target || "(anywhere)")}</b> ${esc(t.text)}</span><button type="button" class="btn btn-ghost btn-sm" data-rm="${t.id}" aria-label="Remove this threat">×</button></li>`).join("") || `<li class="m">No threats yet. Quantity first: ranking comes later.</li>`;
    $("t-note").textContent = c.done ? "# two for every letter. Quantity first; the next slides rank and answer them."
      : state.log.items.length ? `# missing: ${c.missing.map((k) => T.strideByKey(k).name).join(", ")}.` : "";
  }
  function tAdd() {
    const text = $("t-text").value;
    const r = T.addThreat(state.log, { target: $("t-target").value, cat: $("t-cat").value, text, l: 2, i: 2 });
    if (!r.ok) { verdict("t-msg", "bad", r.error); return; }
    $("t-text").value = "";
    verdict("t-msg", /meteor/i.test(text) ? "y" : "ok", /meteor/i.test(text) ? "# logged. Likelihood: low. Impact: high. Response: see the responses slide; 'hope' isn't on it." : "Logged.");
    refreshLogViews();
  }
  function loadRef() {
    const have = new Set(state.log.items.map((t) => t.text));
    let n = 0;
    for (const r of T.REFERENCE.photo) if (!have.has(r.text)) { T.addThreat(state.log, r); n++; }
    return n;
  }
  function logInit() {
    $("t-cat").innerHTML = T.CATS.map((c) => `<option value="${c.k}">${c.k} · ${esc(c.name)}</option>`).join("");
    $("t-target").addEventListener("change", tHint);
    $("t-text").addEventListener("keydown", (e) => { if (e.key === "Enter") tAdd(); });
    click("t-add", tAdd);
    click("t-ref", () => { const n = loadRef(); verdict("t-msg", "ok", n ? `Added ${n} reference threats. Compare them with yours.` : "The reference threats are already in the log."); refreshLogViews(); });
    click("t-clear", () => { state.log = T.createLog(); verdict("t-msg", "ok", "Cleared."); refreshLogViews(); });
    $("t-list").addEventListener("click", (e) => { const b = e.target.closest("[data-rm]"); if (!b) return; T.removeThreat(state.log, b.dataset.rm); refreshLogViews(); });
    refreshTargets(); $("t-msg").className = "verdict";
  }

  // --------------------------------------------------------------------------- ranking
  function rkRender() {
    const items = T.ranked(state.log);
    $("rk-count").textContent = items.length ? `${items.length} threats` : "";
    const opt = (v) => [1, 2, 3].map((n) => `<option value="${n}"${n === v ? " selected" : ""}>${T.LEVELS[n]}</option>`).join("");
    $("rk-list").innerHTML = items.map((t) => { const s = T.score(t); return `<li class="rk ${T.band(s)}"><b class="rk-score" title="Likelihood × impact">${s}</b>${chip(t.cat)}<span class="rk-text"><b>${esc(t.target || "(anywhere)")}</b> ${esc(t.text)}</span><span class="rk-sel"><label>L <select data-id="${t.id}" data-f="l" aria-label="Likelihood">${opt(t.l)}</select></label><label>I <select data-id="${t.id}" data-f="i" aria-label="Impact">${opt(t.i)}</select></label></span></li>`; }).join("") ||
      `<li class="m">No threats to rank yet. Log some in exercise 2, or load the reference threats.</li>`;
    const cells = {}; for (const t of items) cells[t.l + "" + t.i] = (cells[t.l + "" + t.i] || 0) + 1;
    let g = `<span class="g-corner"></span>` + [1, 2, 3].map((l) => `<span class="g-h">${T.LEVELS[l]}</span>`).join("");
    for (const i of [3, 2, 1]) { g += `<span class="g-h g-r">${T.LEVELS[i]}</span>`; for (const l of [1, 2, 3]) { const n = cells[l + "" + i] || 0; g += `<span class="g-c ${T.band(l * i)}${n ? " has" : ""}" title="Likelihood ${T.LEVELS[l]}, impact ${T.LEVELS[i]}">${n || ""}</span>`; } }
    $("rk-grid").innerHTML = g + `<span class="g-axis">Likelihood →</span>`;
    $("rk-note").textContent = items.length >= 4 && items.every((t) => t.l === 3 && t.i === 3) ? "# when everything is a 9, nothing is. Re-rate them against each other."
      : items.length ? "# change a rating and watch the order move. Argue high vs low, not 6 vs 7." : "";
  }
  function rkInit() {
    $("rk-list").addEventListener("change", (e) => {
      const s = e.target.closest("select[data-id]"); if (!s) return;
      const t = state.log.items.find((x) => x.id === s.dataset.id); if (!t) return;
      t[s.dataset.f] = Number(s.value);
      const id = s.dataset.id, f = s.dataset.f;
      refreshLogViews("rank");
      rkRender();
      const ns = $("rk-list").querySelector(`select[data-id="${id}"][data-f="${f}"]`); if (ns) ns.focus();
    });
    click("rk-load", () => { loadRef(); refreshLogViews(); });
  }

  // --------------------------------------------------------------------------- responses
  const topN = (n) => T.ranked(state.log).slice(0, n);
  function rsMsg(row, t) {
    const errs = T.validResponse(t, today()), el = row.querySelector(".rs-msg");
    el.className = "rs-msg " + (errs.length ? "bad" : "ok");
    el.textContent = errs.length ? errs[0] : "Done: " + T.RESPONSES[t.response].split(":")[0] + ", owned by " + t.owner + (t.response === "accept" ? ", revisit " + t.review : "") + ".";
    row.querySelector(".rs-date").hidden = t.response !== "accept";
    return errs;
  }
  function rsRender() {
    const items = topN(3);
    $("rs-count").textContent = items.length ? `top ${items.length} by rank` : "";
    $("rs-list").innerHTML = items.map((t) => `<div class="rs-row" data-id="${t.id}"><div class="rs-head"><b class="rk-score ${T.band(T.score(t))}">${T.score(t)}</b>${chip(t.cat)}<span><b>${esc(t.target || "(anywhere)")}</b> ${esc(t.text)}</span></div>
      <div class="rs-ctl"><label><span class="lr-label">Response</span><select data-f="response" aria-label="Response"><option value="">Choose…</option>${Object.keys(T.RESPONSES).map((k) => `<option value="${k}"${t.response === k ? " selected" : ""}>${k[0].toUpperCase() + k.slice(1)}</option>`).join("")}</select></label>
      <label><span class="lr-label">Owner</span><input data-f="owner" maxlength="32" value="${esc(t.owner)}" placeholder="a person" autocomplete="off"></label>
      <label class="grow"><span class="lr-label">What exactly?</span><input data-f="fix" maxlength="160" value="${esc(t.fix)}" placeholder="the control, the change, or why it's accepted" autocomplete="off"></label>
      <label class="rs-date"${t.response === "accept" ? "" : " hidden"}><span class="lr-label">Revisit on</span><input data-f="review" maxlength="10" value="${esc(t.review)}" placeholder="YYYY-MM-DD" autocomplete="off"></label></div><p class="rs-msg"></p></div>`).join("") ||
      `<p class="note">No threats yet. Load the reference threats, or log some in exercise 2.</p>`;
    for (const row of $("rs-list").querySelectorAll(".rs-row")) { const t = state.log.items.find((x) => x.id === row.dataset.id); if (t.response) rsMsg(row, t); else row.querySelector(".rs-msg").textContent = "Pick a response."; }
  }
  function rsInit() {
    const on = (e) => {
      const el = e.target.closest("[data-f]"), row = e.target.closest(".rs-row"); if (!el || !row) return;
      const t = state.log.items.find((x) => x.id === row.dataset.id); if (!t) return;
      t[el.dataset.f] = el.value;
      if (el.dataset.f === "response" && el.value === "accept" && !t.review) { t.review = inDays(90); row.querySelector('[data-f="review"]').value = t.review; }
      rsMsg(row, t);
      if (t.response === "accept" && !t.owner && !t.review) $("rs-note").textContent = "# 'Accepted. Owner: nobody. Review: never.' isn't a response, it's a shrug with paperwork.";
      else $("rs-note").textContent = T.validResponse(t, today()).length ? "# not done until it has an owner (and a date, if you're accepting it)." : "# a decision someone can be asked about later. That's the whole point.";
      refreshLogViews("responses");
    };
    $("rs-list").addEventListener("change", on);
    $("rs-list").addEventListener("input", (e) => { if (e.target.matches("input")) on(e); });
    click("rs-load", () => { loadRef(); refreshLogViews(); });
  }

  // --------------------------------------------------------------------------- tickets
  function ticketItems() {
    if (state.log.items.length) return T.ranked(state.log);
    const tmp = T.createLog(); for (const r of T.REFERENCE.photo) T.addThreat(tmp, r); return T.ranked(tmp);
  }
  function copyText(text, msgId) {
    const done = (ok) => { $(msgId).textContent = ok ? "Copied." : "Couldn't copy: select the text and copy it."; };
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(() => done(true), () => done(false));
    else { const ta = document.createElement("textarea"); ta.value = text; document.body.appendChild(ta); ta.select(); let ok = false; try { ok = document.execCommand("copy"); } catch (e) {} document.body.removeChild(ta); done(ok); }
  }
  let tkItems = [];
  function tkRender(keepId) {
    tkItems = ticketItems();
    const cur = keepId || $("tk-pick").value;
    $("tk-pick").innerHTML = tkItems.map((t) => `<option value="${t.id}">${T.score(t)} · ${esc(t.target || "(anywhere)")}: ${esc(t.text.length > 60 ? t.text.slice(0, 59) + "…" : t.text)}</option>`).join("");
    if (cur && tkItems.some((t) => t.id === cur)) $("tk-pick").value = cur;
    const t = tkItems.find((x) => x.id === $("tk-pick").value) || tkItems[0];
    const k = T.ticket(t);
    $("tk-out").textContent = k.title + "\n\n" + k.body.replace(/\*\*/g, "");
    $("tk-note").textContent = state.log.items.length ? "# built from your threat log. Edit the 'Done when' line for your real system." : "# showing the reference threats: log your own in exercise 2.";
  }
  function tkInit() {
    $("tk-pick").addEventListener("change", () => tkRender());
    click("tk-copy", () => { const t = tkItems.find((x) => x.id === $("tk-pick").value) || tkItems[0]; const k = T.ticket(t); copyText(k.title + "\n\n" + k.body, "tk-msg"); });
  }
  function x3Render() {
    const items = topN(3);
    $("x3-list").innerHTML = items.map((t, i) => {
      const k = T.ticket(t), warn = [];
      if (!t.response) warn.push("no response chosen yet"); if (!t.owner) warn.push("no owner"); if (t.response === "accept" && !t.review) warn.push("no review date");
      return `<article class="x3"><header><b>${i + 1}</b><h3>${esc(k.title)}</h3></header><pre class="term">${esc(k.body.replace(/\*\*/g, ""))}</pre>${warn.length ? `<p class="verdict bad">Missing: ${esc(warn.join(", "))}.</p>` : `<p class="verdict ok">Ready for the backlog.</p>`}</article>`;
    }).join("") || `<p class="note">No threats yet: log some in exercise 2, or load the reference threats above.</p>`;
  }
  function x3Init() {
    click("x3-copy", () => { const items = topN(3); if (!items.length) { $("x3-msg").textContent = "Nothing to copy yet."; return; } copyText(items.map((t) => { const k = T.ticket(t); return k.title + "\n\n" + k.body; }).join("\n\n---\n\n"), "x3-msg"); });
    click("x3-load", () => { loadRef(); refreshLogViews(); });
  }

  // one place to refresh every view of the log, optionally leaving the view being edited alone
  function refreshLogViews(skip) {
    logRender();
    if (skip !== "rank") rkRender();
    if (skip !== "responses") rsRender();
    tkRender(); x3Render();
  }

  // --------------------------------------------------------------------------- the habit checklist
  const RV_KEY = "threat-modeling-habit";
  function review() {
    const boxes = Array.from(document.querySelectorAll("#rv-list input[type=checkbox]"));
    let saved = {};
    try { saved = JSON.parse(store(RV_KEY) || "{}"); } catch (e) {}
    boxes.forEach((b) => { b.checked = !!saved[b.dataset.k]; });
    const update = () => {
      const done = boxes.filter((b) => b.checked).length;
      store(RV_KEY, JSON.stringify(Object.fromEntries(boxes.map((b) => [b.dataset.k, b.checked]))));
      const n = $("rv-note"); n.className = "comment";
      if (done === boxes.length) { n.textContent = "# ten of ten. Now go and draw something small this week, and put the date in the calendar."; n.classList.add("ok"); }
      else if (!done) n.textContent = "# tick what your team does today. Each gap is something to try next sprint, not a failure. Saved in this browser only.";
      else n.textContent = `# ${done} of ${boxes.length}. Pick the unticked box that would improve your next design review the most.`;
    };
    boxes.forEach((b) => b.addEventListener("change", update));
    update();
  }

  // --------------------------------------------------------------------------- easter egg: console
  function consoleHint() {
    console.log("%cThreat Modeling in Practice", "font: 700 24px monospace; color: #ff2e88; text-shadow: 0 0 8px #ff2e88");
    console.log("%cYou found the console. What can go wrong here? Open DevTools on any page you build and ask the four questions about it. (The meteor is not on the diagram.)", "font: 14px monospace; color: #00f0ff");
  }

  function start() {
    consoleHint();
    $("hero-in").addEventListener("input", hero); hero();
    segPick("fq-pick", "data-q", fq); fq(0);
    wfInit();
    segPick("de-pick", "data-t", (t) => { deType = t; de(t); }); $("de-log").addEventListener("change", () => de(deType)); de("entity");
    $("tb-bounds").addEventListener("change", tb); $("tb-cross").addEventListener("change", tb); tb();
    builderInit();
    strideInit();
    segPick("wk-pick", "data-s", (s) => wk(s)); wk("website");
    cardsInit();
    privacyInit();
    treeInit();
    logInit();
    rkInit(); rsInit(); tkInit(); x3Init();
    refreshLogViews();
    review();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
})();
