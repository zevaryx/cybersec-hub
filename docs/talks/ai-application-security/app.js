/* app.js - the live demos for "Securing AI and LLM Applications".
   Every demo is a simulation in this page, built on the small models in ai.js. There is no language model anywhere,
   and nothing is fetched or sent. The "attacks" are harmless sentences aimed at a made-up address. */
(function () {
  "use strict";
  const A = window.AILab;

  // --------------------------------------------------------------------------- helpers
  const $ = (id) => document.getElementById(id);
  const esc = A.escapeHtml;
  function store(key, val) {
    try { if (val === undefined) return localStorage.getItem(key); localStorage.setItem(key, val); } catch (e) {}
    return null;
  }
  const setPressed = (id, attr, val) => { for (const b of $(id).querySelectorAll("button")) b.setAttribute("aria-pressed", String(b.getAttribute(attr) === String(val))); };
  const verdict = (id, cls, text) => { const el = $(id); el.className = "verdict" + (cls ? " " + cls : ""); el.textContent = text; };
  const note = (id, text, cls) => { const el = $(id); el.className = "comment" + (cls ? " " + cls : ""); el.textContent = text; };
  const plural = (n, one, many) => n + " " + (n === 1 ? one : many);

  // --------------------------------------------------------------------------- title terminal
  function hero() {
    const el = $("hero-in"), v = el.value;
    const r = A.lintHero(v);
    const out = $("hero-out");
    out.className = "hashout " + (r.flagged ? "bad" : "ok");
    out.textContent = r.flagged
      ? "! " + plural(r.flagged, "sentence reads", "sentences read") + " like an order" + (r.forged ? " · " + plural(r.forged, "forged marker", "forged markers") : "")
      : "✓ nothing here reads like an order (it is still one stream)";
    note("hero-note", "# " + (r.egg || "one stream: your system prompt, your request, and this email. Whose sentence is whose? The model can't be sure."));
  }

  // --------------------------------------------------------------------------- one channel
  const ch = { view: "who", last: "" };
  function channel() {
    const input = $("ch-in");
    input.value = A.SAMPLE_EMAIL;
    const add = (line, which) => { input.value = input.value.replace(/\s+$/, "") + "\n" + line; ch.last = which; render(); };
    $("ch-note").addEventListener("click", () => add(A.NOTE_LINE, "note"));
    $("ch-forge").addEventListener("click", () => add(A.FORGED_LINE, "forge"));
    $("ch-reset").addEventListener("click", () => { input.value = A.SAMPLE_EMAIL; ch.last = ""; render(); });
    input.addEventListener("input", () => { ch.last = ""; render(); });
    $("ch-view").addEventListener("click", (e) => {
      const b = e.target.closest("button[data-v]"); if (!b) return;
      ch.view = b.dataset.v; setPressed("ch-view", "data-v", ch.view); render();
    });
    function highlight(text, flagged) {
      let html = esc(text);
      for (const s of flagged) html = html.replace(esc(s), "<mark>" + esc(s) + "</mark>");
      return html;
    }
    function render() {
      const a = A.assemble({ retrieved: input.value });
      const out = $("ch-out");
      if (ch.view === "who") {
        out.innerHTML =
          `<div class="ch-seg ch-sys"><small>SYSTEM PROMPT · written by you · trusted</small><pre>${esc(a.segments[0].text)}</pre></div>` +
          `<div class="ch-seg ch-user"><small>REQUEST · from your user · trusted</small><pre>${esc(a.segments[1].text)}</pre></div>` +
          `<div class="ch-seg ch-out-src"><small>EMAIL · written by an outsider · untrusted</small><pre>${highlight(a.segments[2].text, a.flagged)}</pre></div>`;
      } else {
        out.innerHTML = `<div class="ch-seg ch-flat"><small>WHAT THE MODEL RECEIVES · one stream, no colours, no authors</small><pre>${esc(a.stream)}</pre></div>`;
      }
      if (a.forged.length) verdict("ch-verdict", "bad", `${plural(a.forged.length, "forged marker", "forged markers")} in the email (${a.forged.map((x) => x.replace(/\n/g, " ")).join(" ")}). In the stream they look just like yours.`);
      else if (a.flagged.length) verdict("ch-verdict", "y", `${plural(a.flagged.length, "sentence", "sentences")} in the email read like an instruction. Is it data, or an order? The model has to guess.`);
      else verdict("ch-verdict", "ok", "Nothing here reads like an order. It's still one channel: the next email might.");
      let c = "";
      if (ch.last === "forge") c = "# a closing tag is just more text. The model sees characters, not walls.";
      else if (ch.last === "note") c = "# that sentence is both data and an instruction. Only the model's training decides which it treats it as.";
      else c = "# the email is outside text. Add something to it, then flip to 'what the model receives'.";
      note("ch-comment", c);
    }
    render();
  }

  // --------------------------------------------------------------------------- direct vs indirect
  function inject() {
    const pick = $("in-pick");
    pick.innerHTML = A.SOURCES.map((s) => `<button type="button" data-s="${s.id}" aria-pressed="false">${esc(s.label)}</button>`).join("");
    pick.addEventListener("click", (e) => { const b = e.target.closest("button[data-s]"); if (b) show(b.dataset.s); });
    function show(id) {
      const s = A.SOURCES.find((x) => x.id === id);
      setPressed("in-pick", "data-s", id);
      $("in-task").textContent = s.task;
      $("in-visible").textContent = s.visible;
      $("in-model").innerHTML = esc(s.visible) + "\n<mark>" + esc(s.hidden) + "</mark>";
      note("in-how", "# " + s.how);
    }
    show("email");
  }

  // --------------------------------------------------------------------------- the phrase filter
  function filterDemo() {
    let list = A.BLOCKLIST.slice();
    $("fl-learn").addEventListener("click", () => { const r = A.learnNext(list); list = r.list; render(r.added); });
    $("fl-reset").addEventListener("click", () => { list = A.BLOCKLIST.slice(); render(null, true); });
    function render(added, reset) {
      const rep = A.filterReport(list);
      $("fl-table").innerHTML = "<tr><th>Same request, worded…</th><th>The filter sees</th><th></th></tr>" + rep.rows.map((r, i) => {
        const p = A.PHRASINGS[i];
        return `<tr class="${r.caught ? "caught" : "missed"}"><td>${esc(r.label)}</td><td class="fl-text" title="${esc(p.meaning || r.text)}">${esc(r.text)}</td><td>${r.caught ? "caught" : "missed"}</td></tr>`;
      }).join("");
      $("fl-list").innerHTML = list.map((b) => `<li><code>${esc(b)}</code></li>`).join("");
      $("fl-stats").textContent = `Caught ${rep.caught} of ${rep.total}. The blocklist has ${list.length} phrases.`;
      $("fl-variants").textContent = `The template behind these eight makes ${A.variantCount().toLocaleString("en-US")} variants (6 openers × 6 verbs × 6 objects × 4 languages × 5 disguises). A list can't keep up.`;
      const lastTime = !rep.missed;
      $("fl-learn").disabled = lastTime;
      if (reset) note("fl-note", "# back to the starting list: two of eight.");
      else if (lastTime) note("fl-note", "# eight of eight. That's the whack-a-mole: you've caught what you've seen, and the generator has thousands left.", "ok");
      else if (added) note("fl-note", `# learned “${added}”. The next rewording isn't on the list.`);
      else note("fl-note", "# two of eight caught. Teach it the rest, one at a time.");
    }
    render();
  }

  // --------------------------------------------------------------------------- the Rule of Two
  function trifecta() {
    const pick = $("tf-pick");
    pick.innerHTML = A.SYSTEMS.map((s) => `<button type="button" data-s="${s.id}" aria-pressed="false">${esc(s.label)}</button>`).join("");
    const boxes = { A: $("tf-a"), B: $("tf-b"), C: $("tf-c") };
    let viaSystem = false;
    function flags() { return { A: boxes.A.checked, B: boxes.B.checked, C: boxes.C.checked }; }
    function render() {
      const r = A.ruleOfTwo(flags());
      verdict("tf-verdict", r.count === 3 ? "bad" : r.count === 2 ? "y" : "ok", r.verdict);
      $("tf-fixes").innerHTML = r.fixes.map((f) => `<li>${esc(f)}</li>`).join("");
      $("tf-props").className = "tf-props n" + r.count;
    }
    pick.addEventListener("click", (e) => {
      const b = e.target.closest("button[data-s]"); if (!b) return;
      const s = A.SYSTEMS.find((x) => x.id === b.dataset.s);
      setPressed("tf-pick", "data-s", s.id);
      boxes.A.checked = s.A; boxes.B.checked = s.B; boxes.C.checked = s.C;
      viaSystem = true; note("tf-note", "# " + s.note); render();
    });
    for (const k of Object.keys(boxes)) boxes[k].addEventListener("change", () => {
      setPressed("tf-pick", "data-s", "");
      const f = flags();
      if (f.A && f.B && f.C) note("tf-note", "# all three: the shape of the stories on slide 3. Cut one leg, and an injected sentence has nothing to chain.", "y");
      else note("tf-note", "# your own combination. Pick one of the examples above, or keep toggling.");
      viaSystem = false; render();
    });
    pick.querySelector("button").click();
  }

  // --------------------------------------------------------------------------- the permission switchboard
  function tools() {
    const ST = { variant: 0 };
    $("tw-presets").innerHTML = Object.keys(A.PRESETS).map((k) => `<button type="button" data-p="${k}" aria-pressed="false">${esc(A.PRESETS[k].label)}</button>`).join("");
    $("tw-task").innerHTML = Object.keys(A.TASKS).map((k) => `<option value="${k}">${esc(A.TASKS[k].label)}</option>`).join("");
    $("tw-tools").innerHTML = A.TOOLS.map((t) => {
      const gate = (t.write || t.outbound) ? `<select data-ap="${t.id}" aria-label="Approval for ${esc(t.label)}"><option value="">no approval</option><option value="vague">vague prompt</option><option value="specific">specific prompt</option></select>` : `<span class="tw-na">reads only</span>`;
      return `<li><label><input type="checkbox" data-t="${t.id}" checked> ${esc(t.label)}</label>${gate}</li>`;
    }).join("");
    $("tw-var").innerHTML = A.ATTACKS[0].variants.map((v, i) => `<button type="button" data-v="${i}" aria-pressed="${i === 0}">${esc(v.style)}</button>`).join("");
    function readCfg() {
      const cfg = { tools: [], approvals: {}, task: $("tw-task").value, scope: $("tw-scope").checked ? "narrow" : "broad", egress: $("tw-egress").checked, plan: $("tw-plan").checked, filter: $("tw-filter").checked };
      for (const c of $("tw-tools").querySelectorAll("input[data-t]")) if (c.checked) cfg.tools.push(c.dataset.t);
      for (const s of $("tw-tools").querySelectorAll("select[data-ap]")) if (s.value) cfg.approvals[s.dataset.ap] = s.value;
      return cfg;
    }
    function apply(cfg) {
      const c = A.defaultConfig(cfg);
      for (const b of $("tw-tools").querySelectorAll("input[data-t]")) b.checked = c.tools.indexOf(b.dataset.t) >= 0;
      for (const s of $("tw-tools").querySelectorAll("select[data-ap]")) s.value = c.approvals[s.dataset.ap] || "";
      $("tw-task").value = c.task; $("tw-scope").checked = c.scope === "narrow"; $("tw-egress").checked = !!c.egress; $("tw-plan").checked = !!c.plan; $("tw-filter").checked = !!c.filter;
    }
    const BADGE = { harm: ["HAPPENS", "oc-harm"], limited: ["LIMITED", "oc-limited"], asks: ["ASKS YOU", "oc-asks"], blocked: ["BLOCKED", "oc-blocked"], impossible: ["NO TOOL", "oc-impossible"] };
    function render() {
      const cfg = readCfg();
      const res = A.evaluateAll(cfg, ST.variant);
      $("tw-results").innerHTML = res.rows.map((r) => {
        const b = BADGE[r.outcome];
        const first = r.why.split(/(?<=[.?!]['"]?)\s/)[0];
        return `<li class="${b[1]}" title="${esc(r.why)}"><span class="tw-badge">${b[0]}${r.outcome === "blocked" ? " · " + r.by : ""}</span><b>${esc(r.label)}</b><small>${esc(first)}</small></li>`;
      }).join("");
      if (res.harm === 0 && res.limited === 0) verdict("tw-verdict", "ok", "None of the five gets through.");
      else verdict("tw-verdict", res.harm ? "bad" : "y", `${res.harm} of 5 happen` + (res.limited ? `, ${res.limited} limited` : "") + ".");
      const anyVague = Object.values(cfg.approvals).indexOf("vague") >= 0;
      let n = "# try the presets: 'everything on', then 'least privilege'. Then switch the wording.";
      if (!cfg.tools.length) n = "# no tools at all: safe, and useless. Most assistants could still lose a tool or two and nobody would notice.";
      else if (anyVague && res.rows.some((r) => r.by === "approval" && r.outcome === "harm")) n = "# it asked, and it still happened: a prompt nobody can judge is not a control.";
      else if (cfg.filter && ST.variant === 0 && res.harm === 0 && res.limited === 0) n = "# the filter caught the classic wording. Switch to 'polite wording' above.";
      note("tw-note", n);
    }
    $("tw-presets").addEventListener("click", (e) => {
      const b = e.target.closest("button[data-p]"); if (!b) return;
      apply(A.PRESETS[b.dataset.p].cfg); setPressed("tw-presets", "data-p", b.dataset.p); render();
    });
    $("tw-var").addEventListener("click", (e) => { const b = e.target.closest("button[data-v]"); if (!b) return; ST.variant = +b.dataset.v; setPressed("tw-var", "data-v", ST.variant); render(); });
    for (const el of document.querySelectorAll("#tools input, #tools select")) el.addEventListener("change", () => { setPressed("tw-presets", "data-p", ""); render(); });
    apply(A.PRESETS.open.cfg); setPressed("tw-presets", "data-p", "open"); render();
  }

  // --------------------------------------------------------------------------- approval gates
  function gates() {
    const st = { dlg: "vague" };
    const boxes = Array.from($("gt-rules").querySelectorAll("input"));
    function rules() { const r = {}; for (const b of boxes) r[b.dataset.r] = b.checked; return r; }
    function render() {
      const r = A.gateReport(rules());
      $("gt-table").innerHTML = "<tr><th>Action</th><th>Per day</th><th>Risky?</th><th>Asked?</th></tr>" + A.ACTIONS.map((a) => {
        const asked = r.asked.indexOf(a.id) >= 0, risky = A.isRisky(a);
        return `<tr class="${risky && !asked ? "slip" : ""}"><td>${esc(a.label)}</td><td>${a.perDay}</td><td>${risky ? "yes" : "no"}</td><td>${asked ? "asks" : "·"}</td></tr>`;
      }).join("");
      $("gt-stats").innerHTML = `<div><b>${r.asks}</b><span>prompts a day</span></div><div><b>${r.attention}%</b><span>careful reads (invented curve)</span></div><div class="${r.slipping.length ? "hl" : ""}"><b>${r.slipping.length}</b><span>risky actions unasked</span></div>`;
      if (boxes.find((b) => b.dataset.r === "everything").checked) verdict("gt-verdict", "bad", `About ${r.asks} prompts a day. By the afternoon, "Allow" is a reflex, including for the one that matters.`);
      else if (!r.asks) verdict("gt-verdict", "bad", `No approvals: ${plural(r.slipping.length, "risky action runs", "risky actions run")} unseen.`);
      else if (r.slipping.length) verdict("gt-verdict", "y", `${plural(r.slipping.length, "risky action is", "risky actions are")} still unasked: ${r.slipping.map((a) => a.label.toLowerCase()).join(", ")}.`);
      else verdict("gt-verdict", "ok", `Every risky action is covered with ${r.asks} prompts a day: few enough to read.`);
      note("gt-note", st.dlg === "vague"
        ? "# nothing here a person can judge. Allow, allow, allow."
        : "# built by your code from the real action. The newsletter origin is what gives it away. The model must not write this text.");
      $("gt-dialog").textContent = A.DIALOGS[st.dlg].title + "\n\n" + A.DIALOGS[st.dlg].body + "\n\n[ " + A.DIALOGS[st.dlg].buttons + " ]";
    }
    for (const b of boxes) b.addEventListener("change", render);
    $("gt-dlg").addEventListener("click", (e) => { const b = e.target.closest("button[data-d]"); if (!b) return; st.dlg = b.dataset.d; setPressed("gt-dlg", "data-d", st.dlg); render(); });
    render();
  }

  // --------------------------------------------------------------------------- plan first, quarantine the reader
  function plan() {
    $("pl-mode").innerHTML = Object.keys(A.MODES).map((k) => `<button type="button" data-m="${k}" aria-pressed="false">${esc(A.MODES[k].label)}</button>`).join("");
    $("pl-inbox").innerHTML = A.INBOX.map((m) => `<li class="${m.outside ? "out" : ""}"><b>${esc(m.from)}</b>${m.outside ? '<span class="pl-tag">outside</span>' : ""}<small>${esc(m.body)}</small></li>`).join("");
    function show(mode) {
      setPressed("pl-mode", "data-m", mode);
      const r = A.runAgent(mode);
      $("pl-steps").innerHTML = r.steps.map((s) => `<li class="${s.bad ? "bad" : ""}"><b>${esc(s.who)}</b> ${esc(s.did)}${s.note ? `<small>${esc(s.note)}</small>` : ""}</li>`).join("");
      verdict("pl-verdict", r.outcome === "harm" ? "bad" : "ok", r.summary);
      note("pl-note", mode === "loop" ? "# same inbox, same request. Only the design changes. Try the other two." : mode === "plan" ? "# the plan was written before the newsletter was read." : "# the reader returned fields, not sentences.");
    }
    $("pl-mode").addEventListener("click", (e) => { const b = e.target.closest("button[data-m]"); if (b) show(b.dataset.m); });
    show("loop");
  }

  // --------------------------------------------------------------------------- output handling
  function output() {
    const st = { s: "html", h: "raw", seen: new Set() };
    $("ou-pick").innerHTML = A.OUTPUTS.map((o) => `<button type="button" data-s="${o.id}" aria-pressed="false">${esc(o.label)}</button>`).join("");
    function result(o, h) {
      const t = o.text;
      switch (o.id) {
        case "html": return h === "raw" ? "bubble.innerHTML = answer\n→ the page parses the tag, tries to load image 'x', and runs the onerror handler: as your site, with your user's session." : h === "escape" ? "bubble.textContent = answer\n→ shown as plain characters, exactly as written:\n  " + t : "sanitise(answer) → \"Here is your summary.\"\n(the img tag is not on the allowed list, so it's dropped)";
        case "image": return h === "allow" ? A.stripUntrustedImages(t).text + "\n→ host not on the allowlist: no request is made." : "render(answer)\n→ the reader's app requests:\n  GET " + t.replace(/^!\[[^\]]*\]\(|\)$/g, "") + "\nno click needed, and nothing visible on screen.";
        case "sql": return h === "raw" ? "SELECT * FROM orders WHERE customer = '" + t + "'\n→ the quote ends the value; the rest runs as SQL." : h === "escape" ? "SELECT * FROM orders WHERE customer = ?\n   -- parameter: " + JSON.stringify(t) + "\n→ stored and compared as text. Never read as SQL." : (/^[A-Za-z .'-]{1,60}$/.test(t) ? "accepted" : "rejected: names here may only hold letters, spaces, dots, hyphens and apostrophes.");
        case "shell": return h === "raw" ? "sh -c \"convert " + t + " out.png\"\n→ the semicolon ends one command and starts another." : h === "escape" ? "run([\"convert\", " + JSON.stringify(t) + ", \"out.png\"])   # no shell\n→ one odd argument: a file that doesn't exist." : (A.shellWord(t) ? "accepted" : "rejected: file names here may only hold letters, digits, dots, dashes and underscores.");
        default: { // json
          if (h === "allow") { const v = A.validateRefund(JSON.parse(t)); return "schema: only { refund: number, 0 to 25 }\n" + (v.dropped.length ? "dropped unknown fields: " + v.dropped.join(", ") + "\n" : "") + (v.problems.length ? "needs a person: " + v.problems.join("; ") : "accepted: " + JSON.stringify(v.value)); }
          return "api.update(JSON.parse(answer))\n→ refund 500 issued, and the field 'admin' is set to true.";
        }
      }
    }
    function render() {
      const o = A.OUTPUTS.find((x) => x.id === st.s);
      setPressed("ou-pick", "data-s", st.s); setPressed("ou-handler", "data-h", st.h);
      $("ou-text").textContent = o.text; $("ou-ctx").textContent = "Used in: " + o.context + ".";
      $("ou-result").textContent = result(o, st.h);
      const e = A.evaluateOutput(o.id, st.h);
      verdict("ou-verdict", e.verdict === "ok" ? "ok" : "bad", e.verdict === "ok" ? "Safe." : "Not safe.");
      st.seen.add(o.id);
      let c = "# " + e.why;
      if (o.id === "image" && st.h === "allow") c = "# " + e.why + " A quiet leak needs a quiet fix: the app has to decide what's allowed to load.";
      note("ou-note", c);
    }
    $("ou-pick").addEventListener("click", (e) => { const b = e.target.closest("button[data-s]"); if (b) { st.s = b.dataset.s; render(); } });
    $("ou-handler").addEventListener("click", (e) => { const b = e.target.closest("button[data-h]"); if (b) { st.h = b.dataset.h; render(); } });
    render();
  }

  // --------------------------------------------------------------------------- what goes into prompts
  const DT_SAMPLE = "Can you debug this? Our script calls the API with key AKIAIOSFODNN7EXAMPLE and logs in to db1.prod.internal, password: hunter2. The customer is jo@example.com (ID 123-45-6789) and the session token is ghp_abcdefghijklmnopqrstuvwxyz0123456789.";
  function data() {
    const input = $("dt-in"); input.value = DT_SAMPLE;
    const st = { map: null, redacted: "" };
    function findings() {
      const f = A.lintPrompt(input.value);
      $("dt-findings").innerHTML = f.length ? f.map((x) => `<li><b>${x.count > 1 ? x.count + "× " : ""}${esc(x.label)}</b><small>${esc(x.advice)}</small></li>`).join("") : "<li><b>Nothing found by this short list of patterns</b><small>That isn't the same as nothing sensitive. A name, a project codename or a customer's story isn't a pattern.</small></li>";
      let c = f.length ? `# ${plural(f.length, "kind", "kinds")} of secret or personal data found. Strip them before the prompt leaves, and put them back afterwards.` : "# looks clean to the patterns. Read it once yourself anyway.";
      if (/AKIAIOSFODNN7EXAMPLE/.test(input.value)) c = "# that key is AWS's own documentation example. It has never opened anything. A real one belongs in a vault, not a prompt.";
      else if (/hunter2/i.test(input.value)) c = "# hunter2: the oldest joke on IRC. Please still don't paste it.";
      note("dt-note", c);
    }
    $("dt-redact").addEventListener("click", () => { const r = A.redact(input.value); st.map = r.map; st.redacted = r.text; $("dt-out").textContent = r.text; note("dt-note", "# the model works on placeholders. The table that maps them back stays on your side."); });
    $("dt-restore").addEventListener("click", () => { if (!st.map) { note("dt-note", "# redact first, then restore."); return; } $("dt-out").textContent = A.restore("The fix is to rotate [KEY_1] and move it out of the script. (Answer, restored for you.)\n" + st.redacted, st.map); note("dt-note", "# restored after the answer, in your code, not the model's."); });
    $("dt-reset").addEventListener("click", () => { input.value = DT_SAMPLE; st.map = null; $("dt-out").textContent = ""; findings(); });
    input.addEventListener("input", () => { st.map = null; $("dt-out").textContent = ""; findings(); });
    findings();
  }

  // --------------------------------------------------------------------------- threat model an AI feature
  function threat() {
    const seen = new Set();
    $("th-pick").innerHTML = A.FEATURES.map((f) => `<button type="button" data-f="${f.id}" aria-pressed="false">${esc(f.label)}</button>`).join("");
    function show(id) {
      const f = A.FEATURES.find((x) => x.id === id); seen.add(id);
      setPressed("th-pick", "data-f", id);
      $("th-q").innerHTML = `<tr><th>Who writes text it reads?</th><td>${esc(f.who)}</td></tr><tr><th>What can it do?</th><td>${esc(f.can)}</td></tr><tr><th>What data is in reach?</th><td>${esc(f.data)}</td></tr><tr><th>What does it act as, and change?</th><td>${esc(f.acts)}</td></tr>`;
      $("th-risks").innerHTML = f.risks.map((r) => `<li>${esc(r)}</li>`).join("");
      $("th-control").textContent = f.control;
      note("th-note", seen.size === A.FEATURES.length ? "# all four: the shapes differ, the questions don't." : "# " + seen.size + " of " + A.FEATURES.length + " features looked at. Same four questions each time.", seen.size === A.FEATURES.length ? "ok" : "");
    }
    $("th-pick").addEventListener("click", (e) => { const b = e.target.closest("button[data-f]"); if (b) show(b.dataset.f); });
    show("mail");
  }

  // --------------------------------------------------------------------------- a test set of attacks
  function tests() {
    $("ts-pick").innerHTML = Object.keys(A.PRESETS).map((k) => `<button type="button" data-p="${k}" aria-pressed="false">${esc(A.PRESETS[k].label)}</button>`).join("");
    function show(k) {
      setPressed("ts-pick", "data-p", k);
      const r = A.runSuite(A.PRESETS[k].cfg);
      const styles = A.ATTACKS[0].variants.map((v) => v.style);
      let html = "<tr><th>Injected request</th>" + styles.map((s) => `<th>${esc(s)}</th>`).join("") + "</tr>";
      for (const a of A.ATTACKS) {
        html += `<tr><td>${esc(a.label)}</td>` + styles.map((s) => {
          const c = r.cases.find((x) => x.attack === a.id && x.style === s);
          return `<td class="${c.pass ? "pass" : "fail"}">${c.pass ? "pass" : "FAIL"}</td>`;
        }).join("") + "</tr>";
      }
      $("ts-grid").innerHTML = html;
      $("ts-stats").innerHTML = `<div><b>${r.total}</b><span>cases</span></div><div><b>${r.passed}</b><span>passed</span></div><div class="${r.failed ? "hl" : ""}"><b>${r.failed}</b><span>failed</span></div>`;
      verdict("ts-verdict", r.failed === 0 ? "ok" : r.failed === r.total ? "bad" : "y", r.failed === 0 ? "All pass: and they'd still pass with new wording, because the design doesn't read the wording." : `${r.failed} of ${r.total} fail.`);
      const n = { open: "# everything fails. A good first run: it proves the test set can fail.", promptOnly: "# only the classic wording passes. The suite just measured your filter, not your safety.", least: "# nothing to attack. The cheapest way to pass a security test is to not have the feature.", layered: "# passes in every wording. That's the point of asserting on actions." }[k];
      note("ts-note", n);
    }
    $("ts-pick").addEventListener("click", (e) => { const b = e.target.closest("button[data-p]"); if (b) show(b.dataset.p); });
    show("open");
  }

  // --------------------------------------------------------------------------- logs and alerts
  function monitor() {
    const log = A.buildLog();
    const boxes = Array.from($("mo-rules").querySelectorAll("input"));
    function render() {
      const rules = {}; for (const b of boxes) rules[b.dataset.r] = b.checked;
      const alerts = A.analyzeLog(log, rules);
      const hot = new Set(alerts.map((a) => a.n));
      $("mo-log").innerHTML = "<tr><th>#</th><th>Time</th><th>Tool</th><th>Target</th><th></th></tr>" + log.map((e) =>
        `<tr class="${hot.has(e.n) ? "hot" : ""}${e.ok ? "" : " denied"}"><td>${e.n}</td><td>${e.time}</td><td>${esc(e.tool)}</td><td>${esc(e.target)}</td><td>${e.ok ? "ok" : "blocked"}</td></tr>`).join("");
      $("mo-alerts").innerHTML = alerts.length ? alerts.map((a) => `<li><b>#${a.n}</b> ${esc(a.text)}</li>`).join("") : "<li class=\"none\">No alerts.</li>";
      const rl = A.rateLimit(log);
      $("mo-rate").textContent = `Rate limit: ${rl.limit} sends per session. This session sent ${rl.sends}: ${rl.over ? "over" : "within"} the limit. (Two more were blocked.)`;
      const on = boxes.filter((b) => b.checked).length;
      if (!on) note("mo-note", "# quiet logs: 24 calls, no alerts. The story is in the data; you have to ask for it.");
      else if (on === boxes.length) note("mo-note", `# ${alerts.length} alerts, and each one points at the same ten entries. The blocked calls are the best signal: your controls worked, and somebody tried.`, "ok");
      else note("mo-note", `# ${plural(alerts.length, "alert", "alerts")} from ${plural(on, "rule", "rules")}. Add another and watch the story fill in.`);
    }
    for (const b of boxes) b.addEventListener("change", render);
    render();
  }

  // --------------------------------------------------------------------------- tool servers and pinned descriptions
  function supply() {
    $("su-table").innerHTML = "<tr><th>Tool server</th><th>Publisher</th><th>Flags</th><th></th></tr>" + A.SERVERS.map((s) => {
      const v = A.vetServer(s);
      return `<tr data-s="${s.id}" tabindex="0" class="su-${v.verdict}"><td>${esc(s.label)}</td><td>${esc(s.publisher)}</td><td>${v.flags.length}</td><td>${v.verdict === "ok" ? "approve" : v.verdict === "review" ? "review" : "don't"}</td></tr>`;
    }).join("");
    function showServer(id) {
      const s = A.SERVERS.find((x) => x.id === id), v = A.vetServer(s);
      for (const r of $("su-table").querySelectorAll("tr[data-s]")) r.classList.toggle("sel", r.dataset.s === id);
      note("su-note", v.flags.length ? "# " + s.label + ": " + v.flags.join("; ") + "." : "# " + s.label + ": nothing to flag on this list. It asks for " + s.scopes + ".");
    }
    $("su-table").addEventListener("click", (e) => { const r = e.target.closest("tr[data-s]"); if (r) showServer(r.dataset.s); });
    $("su-table").addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { const r = e.target.closest("tr[data-s]"); if (r) { e.preventDefault(); showServer(r.dataset.s); } } });
    showServer("mailer");
    let pin = ""; const desc = $("su-desc");
    async function render(changedByClick) {
      const now = await A.digestHex(desc.value);
      if (!pin) pin = now;
      $("su-hash").textContent = "pinned: " + pin.slice(0, 16) + "…   now: " + now.slice(0, 16) + "…";
      if (now === pin) verdict("su-verdict", "ok", "Unchanged: still the description you approved.");
      else verdict("su-verdict", "bad", "Changed since approval: stop, show the difference to a person, and ask again.");
      if (changedByClick) note("su-note", "# one added sentence, a completely different fingerprint. That's the whole point of pinning.");
    }
    $("su-update").addEventListener("click", () => { desc.value = A.TOOL_DESC_CHANGED; render(true); });
    $("su-reset").addEventListener("click", () => { desc.value = A.TOOL_DESC; render(false); showServer("mailer"); });
    desc.value = A.TOOL_DESC; render(false);
  }

  // --------------------------------------------------------------------------- OWASP map
  function owasp() {
    const seen = new Set();
    const slideNo = {};
    document.querySelectorAll(".slide").forEach((s) => { slideNo[s.id] = s.querySelector("h2") ? s.querySelector("h2").textContent : s.id; });
    $("ow-grid").innerHTML = A.OWASP.slice().sort((x, y) => x.id25.localeCompare(y.id25)).map((o) => `<button type="button" data-o="${o.id}" aria-pressed="false"><small>${o.id25}</small>${esc(o.area)}</button>`).join("");
    function show(id) {
      const o = A.OWASP.find((x) => x.id === id); seen.add(id);
      setPressed("ow-grid", "data-o", id);
      $("ow-title").textContent = o.id25 + " · " + o.area;
      $("ow-control").textContent = o.control;
      $("ow-where").innerHTML = `In this talk: <a href="#${o.slide}">${esc(slideNo[o.slide] || o.slide)}</a>`;
      note("ow-note", seen.size === A.OWASP.length ? "# ten of ten: now say where each one lives in your own design." : `# ${seen.size} of ${A.OWASP.length} looked at.`, seen.size === A.OWASP.length ? "ok" : "");
    }
    $("ow-grid").addEventListener("click", (e) => { const b = e.target.closest("button[data-o]"); if (b) show(b.dataset.o); });
    show("pi");
  }

  // --------------------------------------------------------------------------- checklist
  const RV_KEY = "ai-application-security-checklist";
  function checklist() {
    const boxes = Array.from(document.querySelectorAll("#rv-list input[type=checkbox]"));
    let saved = {};
    try { saved = JSON.parse(store(RV_KEY) || "{}"); } catch (e) {}
    boxes.forEach((b) => { b.checked = !!saved[b.dataset.k]; });
    const update = () => {
      const done = boxes.filter((b) => b.checked).length;
      store(RV_KEY, JSON.stringify(Object.fromEntries(boxes.map((b) => [b.dataset.k, b.checked]))));
      const n = $("rv-note"); n.className = "comment";
      if (done === boxes.length) { n.textContent = "# 10 of 10. Now go and try to break it on purpose, with the test set from earlier, and see which control notices."; n.classList.add("ok"); }
      else if (!done) n.textContent = "# tick what's true for the feature you're working on. Each gap is a ticket, not a failure. Saved in this browser only.";
      else n.textContent = `# ${done} of ${boxes.length}. Pick the unticked box that's cheapest to fix this week.`;
    };
    boxes.forEach((b) => b.addEventListener("change", update));
    update();
  }

  // --------------------------------------------------------------------------- easter egg: console
  function consoleHint() {
    console.log("%c" + document.title, "font: 700 24px monospace; color: #ff2e88; text-shadow: 0 0 8px #ff2e88");
    console.log("%cThe model can't tell whose sentence it is. Your code can.", "font: 14px monospace; color: #00f0ff");
  }

  function start() {
    consoleHint();
    $("hero-in").addEventListener("input", hero); hero();
    channel(); inject(); filterDemo(); trifecta(); tools(); gates(); plan(); output(); data(); threat(); tests(); monitor(); supply(); owasp(); checklist();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
})();
