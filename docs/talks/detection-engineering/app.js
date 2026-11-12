/* app.js - the live demos for "Detection Engineering".
   Everything here is a simulation in your browser: the events, hosts, accounts, products and the threat report are made up, and nothing you type is sent anywhere.
   The rule engine is in rules.js (window.Rules) and the made-up data and scoring are in scenario.js (window.Scen). The engine is a toy that reads a subset of Sigma. */
(function () {
  "use strict";
  const R = window.Rules, S = window.Scen;

  // --------------------------------------------------------------------------- helpers
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const click = (id, fn) => $(id).addEventListener("click", fn);
  const num = (n) => Number(n).toLocaleString("en-US");
  const baseName = (p) => String(p || "").split("\\").pop();
  function store(key, val) {
    try { if (val === undefined) return localStorage.getItem(key); localStorage.setItem(key, val); } catch (e) {}
    return null;
  }
  function seg(id, items, initial, fn) {
    const g = $(id);
    g.innerHTML = items.map((it) => `<button type="button" data-v="${esc(it.v)}" aria-pressed="false">${esc(it.label)}</button>`).join("");
    const btns = [...g.querySelectorAll("button")];
    let val = initial;
    const set = (v, quiet) => { val = v; for (const b of btns) b.setAttribute("aria-pressed", String(b.dataset.v === v)); if (!quiet) fn(v); };
    g.addEventListener("click", (e) => { const b = e.target.closest("button"); if (b) set(b.dataset.v); });
    set(initial, true);
    return { get: () => val, set };
  }
  const RUNG_COLOUR = { hash: "#47ffa3", ip: "#8ff07f", domain: "#c9ef5c", artifact: "#f6e94b", tool: "#ffb347", ttp: "#ff5b3a" };
  const rungChip = (id, text) => `<span class="chip" style="color:${RUNG_COLOUR[id]};border-color:${RUNG_COLOUR[id]}">${esc(text || S.RUNGS.find((r) => r.id === id).name)}</span>`;
  const techLabel = (id) => id + " " + (S.TECH[id] || "");

  // --------------------------------------------------------------------------- title: which rung of the pyramid?
  function heroNote(t, low, c) {
    if (t === "") return "# nothing to classify. Try a hash, an address, a file name, a tool or a behaviour.";
    if (/^e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855$/i.test(t)) return "# the SHA-256 of nothing at all. A hash names exactly one file, and this one is the empty one.";
    if (/^(127\.0\.0\.1|localhost|::1)$/.test(low)) return "# that's your own computer: the one address an attacker can never ask you to block.";
    if (/^203\.0\.113\.\d{1,3}$/.test(t)) return "# 203.0.113.0/24 is reserved for documentation (RFC 5737), so every address in this talk is safe to type.";
    if (/(^|\.)(example\.com|example\.net|example\.org)$/.test(low) || /\.(test|example|invalid)$/.test(low)) return "# reserved for documentation and testing (RFC 2606): safe to type, and never anyone's real server.";
    if (/^pyramid( of pain)?$/.test(low)) return "# David Bianco's Pyramid of Pain, from a blog post of 1 March 2013. The higher the rung, the more it hurts the attacker when you take it away.";
    if (/^ttps?$/.test(low)) return "# tactics, techniques and procedures: the top of the pyramid. How they work, not what they carry.";
    if (low === "sigma") return "# Sigma: a portable rule format. This talk's playground reads real Sigma rules, version 2.1.0 of the spec.";
    if (/^t1562(\.\d{3})?$/.test(low)) return "# T1562 (Impair Defenses) was revoked in ATT&CK v19 in favour of T1685, Disable or Modify Tools. Rules tagged with an old ID need a look.";
    if (c.kind === "technique") return "# " + c.id + (c.name ? ": " + c.name + ", in ATT&CK v20.1" : ", an ATT&CK technique") + ". Behaviour sits at the top of the pyramid.";
    if (c.kind === "unknown") return "# can't place it. Is it a value (a hash, address or name) or a behaviour? Try 203.0.113.50, T1059.001, mimikatz.";
    return "# a rung is a guess from the shape of what you typed. The question to ask is always: what does the attacker have to do if I take this away?";
  }
  function hero() {
    const el = $("hero-in");
    el.style.width = Math.max(14, Math.min(34, el.value.length + 1)) + "ch";
    const t = el.value.trim(), low = t.toLowerCase(), c = S.classify(el.value);
    let html = "";
    if (c.rung) {
      const r = S.RUNGS.find((x) => x.id === c.rung);
      const bar = `<span class="painbar" aria-label="pain ${r.pain} of 6">${[1, 2, 3, 4, 5, 6].map((i) => `<i class="${i <= r.pain ? "on" : ""}"></i>`).join("")}</span>`;
      let what = r.name;
      if (c.kind === "hash") what += c.len === 256 ? " (a 256-bit SHA-256)" : c.len === 160 ? " (a 160-bit SHA-1)" : " (a 128-bit MD5)";
      if (c.kind === "technique") what = "TTP: " + (c.name || "an ATT&CK technique");
      const cls = r.pain >= 5 ? "ok" : r.pain >= 4 ? "y" : "bad";
      const verdict = r.pain >= 5 ? "build a detection on this" : r.pain >= 4 ? "useful, and cheap for them to change" : "keep as cheap enrichment, not as your defence";
      html = `<span class="lr"><b class="${cls}">▲</b><span class="k">rung</span><span class="m">${esc(what)} ${bar}</span></span>` +
        `<span class="lr"><b class="${cls}">!</b><span class="k">they</span><span class="m">${esc(r.change)}</span></span>` +
        `<span class="lr"><b class="${cls}">+</b><span class="k">you get</span><span class="m">${esc(r.get)}</span></span>` +
        `<span class="lr lr-total"><span class="${cls}">${esc(verdict)}</span></span>`;
    } else if (c.kind !== "empty") {
      html = `<span class="lr"><b class="y">?</b><span class="k">rung</span><span class="m">can't place that</span></span>`;
    }
    $("hero-out").innerHTML = html;
    $("hero-note").textContent = heroNote(t, low, c);
  }

  // --------------------------------------------------------------------------- slide 4: lifecycle
  function lifecycleInit() {
    const g = $("lc-steps");
    g.innerHTML = S.LIFECYCLE.map((s, i) => `<button type="button" class="lc-btn" data-i="${i}" aria-pressed="false"><small>${String(i + 1).padStart(2, "0")}</small><b>${esc(s.name)}</b></button>`).join("");
    const show = (i) => {
      [...g.children].forEach((b, k) => b.setAttribute("aria-pressed", String(k === i)));
      const s = S.LIFECYCLE[i];
      $("lc-detail").innerHTML = `<h3>${i + 1}. ${esc(s.name)}</h3>` +
        `<div class="fa-row"><b>You make</b><span>${esc(s.make)}</span></div><div class="fa-row"><b>What goes wrong</b><span>${esc(s.wrong)}</span></div><div class="fa-row"><b>Ask</b><span>${esc(s.ask)}</span></div>`;
    };
    g.addEventListener("click", (e) => { const b = e.target.closest("button"); if (b) show(Number(b.dataset.i)); });
    show(0);
  }

  // --------------------------------------------------------------------------- slide 5: pyramid
  function pyramidInit() {
    const widths = { ttp: 34, tool: 46, artifact: 58, domain: 72, ip: 86, hash: 100 };
    const order = ["ttp", "tool", "artifact", "domain", "ip", "hash"];
    const g = $("py-rungs");
    g.innerHTML = order.map((id) => { const r = S.RUNGS.find((x) => x.id === id); return `<button type="button" class="py-rung" data-r="${id}" style="--w:${widths[id]}%" aria-pressed="false">${esc(r.name)}<small>pain ${r.pain} of 6</small></button>`; }).join("");
    const show = (id) => {
      [...g.children].forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.r === id)));
      const r = S.RUNGS.find((x) => x.id === id);
      $("py-detail").innerHTML = `<h3>${esc(r.name)}</h3><p class="quote">"${esc(r.quote)}"<cite>Bianco, 2013</cite></p>` +
        `<div class="fa-row"><b>What it is</b><span>${esc(r.what)}</span></div><div class="fa-row"><b>Example</b><span><code>${esc(r.example)}</code></span></div>` +
        `<div class="fa-row"><b>They respond</b><span>${esc(r.change)}</span></div><div class="fa-row"><b>You get</b><span>${esc(r.get)}</span></div><div class="fa-row"><b>STP level, loosely</b><span>${esc(r.stp)}</span></div>`;
    };
    g.addEventListener("click", (e) => { const b = e.target.closest("button"); if (b) show(b.dataset.r); });
    show("hash");
  }

  // --------------------------------------------------------------------------- slide 6: the report
  function reportInit() {
    const list = $("rp-list");
    list.innerHTML = S.REPORT.map((s) => `<label class="rp-item" data-id="${s.id}"><input type="checkbox" value="${s.id}"><span>${esc(s.text)}</span></label>`).join("");
    const update = () => {
      const picked = S.REPORT.filter((s) => list.querySelector(`input[value="${s.id}"]`).checked);
      for (const s of S.REPORT) list.querySelector(`[data-id="${s.id}"]`).classList.toggle("picked", picked.includes(s));
      const beh = picked.filter((s) => s.rung === "ttp"), ind = picked.filter((s) => s.rung !== "ttp");
      $("rp-n").textContent = picked.length; $("rp-b").textContent = beh.length; $("rp-i").textContent = ind.length;
      $("rp-out").innerHTML = picked.map((s) => {
        const extra = s.attack ? ` <b>${esc(techLabel(s.attack))}</b>. Needs: ${esc(s.data)}.` : "";
        return `<div class="row">${rungChip(s.rung)}<span>${esc(s.why)}${extra}</span></div>`;
      }).join("") + (() => {
        const miss = S.REPORT.filter((s) => s.rung === "ttp" && !picked.includes(s));
        return picked.length && miss.length ? `<div class="rp-miss"><b>Not chosen yet:</b> ${miss.map((m) => esc(techLabel(m.attack))).join(", ")}. These are the behaviours in the report.</div>` : "";
      })();
      const v = $("rp-verdict");
      v.className = "verdict";
      let msg = "";
      if (picked.length === 12) { msg = "# every statement chosen: that's an inventory, not a plan. Twelve rules is a lot to maintain, and eight of them expire."; v.classList.add("y"); }
      else if (picked.length === 1 && picked[0].id === "s3") { msg = "# one hash: a rule that matches exactly one file, forever. Perfect precision, and nothing else."; v.classList.add("y"); }
      else if (picked.length && !beh.length) { msg = "All indicators: good for searching last month's logs, and cheap for the attacker to change. Add at least one behaviour."; v.classList.add("bad"); }
      else if (beh.length === 4 && !ind.length) { msg = "Four behaviours: the detections to maintain. Put the values (hashes, addresses, domains) into your searches and blocklists as enrichment."; v.classList.add("ok"); }
      else if (beh.length === 4) { msg = "All four behaviours, plus " + ind.length + " indicator" + (ind.length > 1 ? "s" : "") + ". Keep the indicators as enrichment, and give each behaviour a test."; v.classList.add("ok"); }
      else if (beh.length) { msg = beh.length + " of 4 behaviours chosen."; v.classList.add("y"); }
      v.textContent = msg;
    };
    list.addEventListener("change", update);
    click("rp-model", () => { for (const s of S.REPORT) list.querySelector(`input[value="${s.id}"]`).checked = s.rung === "ttp"; update(); });
    click("rp-clear", () => { for (const s of S.REPORT) list.querySelector(`input[value="${s.id}"]`).checked = false; update(); });
    update();
  }

  // --------------------------------------------------------------------------- slide 7: ATT&CK mapping
  function mapInit() {
    $("aq-list").innerHTML = S.ATTACK_QUIZ.map((q) => `<div class="aq-row" data-id="${q.id}"><span>${esc(q.text)}</span><select aria-label="Technique for: ${esc(q.text)}"><option value="">choose…</option>${S.ATTACK_OPTIONS.map((o) => `<option value="${o}">${esc(techLabel(o))}</option>`).join("")}</select><b class="g"></b></div>`).join("");
    const reset = () => { for (const r of $("aq-list").children) { r.className = "aq-row"; r.querySelector("select").value = ""; r.querySelector(".g").textContent = ""; } $("aq-score").textContent = ""; $("aq-out").textContent = "Choose a technique for each line, then check."; };
    click("aq-check", () => {
      let ok = 0, wrong = [], blank = 0;
      for (const q of S.ATTACK_QUIZ) {
        const row = $("aq-list").querySelector(`[data-id="${q.id}"]`), v = row.querySelector("select").value;
        if (!v) { blank++; row.className = "aq-row"; row.querySelector(".g").textContent = ""; continue; }
        const good = v === q.answer;
        row.className = "aq-row " + (good ? "ok" : "bad"); row.querySelector(".g").textContent = good ? "✓" : "✗";
        if (good) ok++; else wrong.push(q);
      }
      $("aq-score").textContent = ok + " of " + S.ATTACK_QUIZ.length + " right" + (blank ? " (" + blank + " not answered)" : "");
      const out = $("aq-out");
      if (ok === S.ATTACK_QUIZ.length) out.innerHTML = "<b>6 of 6.</b> # six for six. The map is yours.";
      else if (wrong.length) out.innerHTML = wrong.map((q) => `<b>${esc(techLabel(q.answer))}</b> fits "${esc(q.text.replace(/\.$/, ""))}".`).join("<br>");
      else out.textContent = "Keep going: " + blank + " not answered.";
    });
    click("aq-reset", reset);
  }

  // --------------------------------------------------------------------------- slide 9: telemetry
  const TS_RULES = [{ v: "office", label: "Office app starts a shell" }, { v: "certutil", label: "certutil download" }, { v: "task", label: "Scheduled task, user folder" }, { v: "vss", label: "Shadow copies deleted" }];
  function telemetryInit() {
    const prof = seg("ts-profile", [{ v: "sysmon", label: "Sysmon" }, { v: "sec4688", label: "Security 4688, command line on" }, { v: "sec4688off", label: "Security 4688, default" }, { v: "edr", label: "An EDR (made up)" }], "sysmon", run);
    const rule = seg("ts-rule", TS_RULES, "office", run);
    function run() {
      const p = S.TELEMETRY.find((t) => t.id === prof.get()), rid = rule.get();
      const c = R.compile(S.PRESETS[rid]);
      const rows = R.evaluate(c, S.degrade(S.ALL_EVENTS, p.id));
      const mine = rows.filter((r) => r.event._beh === rid);
      const caught = mine.filter((r) => r.fired).length;
      const fp = rows.filter((r) => r.fired && r.event._label !== "attack").length;
      const miss = S.missingFields(c.fields, p.id);
      $("ts-caught").textContent = caught + " of " + mine.length; $("ts-fp").textContent = fp; $("ts-miss").textContent = miss.length;
      $("ts-fields").innerHTML = c.fields.map((f) => `<span class="fld ${miss.includes(f) ? "miss" : "use"}">${esc(f)}</span>`).join("");
      $("ts-note").textContent = p.note;
      const v = $("ts-verdict");
      if (caught < mine.length) { v.className = "verdict bad"; v.textContent = "Silent: " + (mine.length - caught) + " of " + mine.length + " attack events missed, and the rule reported no error." + (miss.length ? " It reads " + miss.join(", ") + ", which this source doesn't give it." : ""); }
      else if (miss.length || fp) { v.className = "verdict y"; v.textContent = miss.length ? "Still catches them, but reads " + miss.join(", ") + ", which this source doesn't have." + (fp ? " And a filter has stopped working: " + fp + " false alarm." : "") : fp + " false alarm. Check what the filters read."; }
      else { v.className = "verdict ok"; v.textContent = "Works with this source: every field the rule reads is there."; }
    }
    run();
  }

  // --------------------------------------------------------------------------- slide 10: Sigma anatomy
  const SG = [
    { lines: ["title: Download With certutil", "id: 71c3a9e5-2d48-4b06-8f1a-6e5d0b9c3a17"], name: "title and id",
      body: "title is mandatory (up to 256 characters) and says what the rule detects. id is optional in the spec, and recommended: a random UUIDv4. Give a rule a new id when its logic changes in a major way, and link the old one with related." },
    { lines: ["status: experimental", "description: certutil fetching a file by URL", "author: Detection Engineering demo", "date: 2026-11-09"], name: "status and description",
      body: "status is one of stable, test, experimental, deprecated or unsupported: how far to trust the rule. date and modified are ISO dates. description says what fires it and why anyone should care." },
    { lines: ["tags:", "    - attack.command-and-control", "    - attack.t1105"], name: "tags",
      body: "Tags are namespaced with dots. attack.t1105 is ATT&CK technique T1105, Ingress Tool Transfer, and the tactic tag sits beside it. The tags appendix also defines namespaces such as stp (a Summiting the Pyramid rating), car, cve, d3fend, detection and tlp." },
    { lines: ["logsource:", "    category: process_creation", "    product: windows"], name: "logsource",
      body: "Where the data comes from, in lower case. This is deliberately abstract: process_creation on Windows means any telemetry that records new processes. A converter maps it to Sysmon event 1, Security 4688 or your EDR. It can't invent a field the source doesn't have." },
    { lines: ["detection:", "    selection_img:", "        - Image|endswith: '\\certutil.exe'", "        - OriginalFileName: 'CertUtil.exe'"], name: "selection_img",
      body: "A list of maps is an OR: the image path ends with certutil.exe, or the program's original file name is CertUtil.exe. The second line survives a copy under another name. Matching is case-insensitive by default." },
    { lines: ["    selection_flags:", "        CommandLine|windash|contains:", "            - '-urlcache '", "            - '-verifyctl '"], name: "selection_flags",
      body: "Modifiers chain after a pipe and apply in order. contains puts wildcards around the value; windash lets - and / (and the Unicode dashes) stand in for each other in flags. A list of values for one field is an OR." },
    { lines: ["    selection_http:", "        CommandLine|contains: 'http'"], name: "selection_http",
      body: "The command line also has to contain a web address. Without this, certutil -urlcache * delete, which only clears its cache, would match." },
    { lines: ["    condition: all of selection_*"], name: "condition",
      body: "Combines the search identifiers. all of selection_* means every identifier whose name starts with selection_, ANDed. The operators are and, or, not, 1 of and all of, and brackets; from least to most binding: or, and, not, x of, ( ). A map ANDs its fields, so each identifier is small enough to read." },
    { lines: ["falsepositives:", "    - Administrators fetching revocation lists", "level: medium"], name: "falsepositives and level",
      body: "falsepositives lists the benign causes you expect. It is optional in the spec: write it anyway. level is informational, low, medium, high or critical. The spec reserves critical for \"cases in which probability borders certainty\"." },
  ];
  function hl(line) {
    const m = /^(\s*)(- )?([A-Za-z_][\w|.-]*):(.*)$/.exec(line);
    if (!m) return esc(line).replace(/^(\s*- )(.*)$/, (a, b, c) => b + '<span class="s">' + c + "</span>");
    const val = m[4] ? " " + `<span class="s">${esc(m[4].trim())}</span>` : "";
    return esc(m[1] + (m[2] || "")) + `<span class="k">${esc(m[3])}:</span>` + val;
  }
  function sigmaInit() {
    const text = SG.map((s) => s.lines.join("\n")).join("\n");
    try { R.compile(text); } catch (e) { console.warn("Sigma anatomy rule doesn't compile:", e.message); }
    const g = $("sg-code");
    g.innerHTML = SG.map((s, i) => `<button type="button" class="sg-sec" data-i="${i}" aria-pressed="false" title="${esc(s.name)}">${s.lines.map(hl).join("\n")}</button>`).join("");
    const show = (i) => {
      [...g.children].forEach((b, k) => b.setAttribute("aria-pressed", String(k === i)));
      $("sg-detail").innerHTML = `<h3>${esc(SG[i].name)}</h3><p class="ads-body">${esc(SG[i].body)}</p>`;
    };
    g.addEventListener("click", (e) => { const b = e.target.closest("button"); if (b) show(Number(b.dataset.i)); });
    show(7);
  }

  // --------------------------------------------------------------------------- slide 11: playground
  function playgroundInit() {
    const known = new Set();
    S.PLAY_EVENTS.forEach((e) => Object.keys(e).forEach((k) => known.add(k)));
    const chips = $("pg-presets");
    chips.innerHTML = S.PRESET_LABELS.map(([id, label]) => `<button type="button" class="chip" data-p="${id}" aria-pressed="false">${esc(label)}</button>`).join("");
    const ta = $("pg-rule");
    const tbody = $("pg-rows");
    tbody.innerHTML = S.PLAY_EVENTS.map((e, i) => `<tr data-i="${i}"><td class="f"></td><td>${esc(e.UtcTime.slice(11, 16))}</td><td>${esc(e.Computer)}</td><td>${esc(e.User.replace("NT AUTHORITY\\", ""))}</td><td title="${esc(e.CommandLine)}"></td></tr>`).join("");
    const trs = [...tbody.children];
    trs.forEach((tr, i) => {
      const e = S.PLAY_EVENTS[i];
      tr.children[4].innerHTML = (e._label === "attack" ? '<span class="atk">ATTACK</span>' : "") + `<span class="par">${esc(baseName(e.ParentImage))} → </span>${esc(e.CommandLine)}`;
    });
    let cur = -1;
    const note = (i) => {
      cur = i; trs.forEach((t, k) => t.classList.toggle("cur", k === i));
      const e = S.PLAY_EVENTS[i];
      $("pg-note").textContent = (e._note || (e._label === "attack" ? "An attack event." : "Ordinary activity.")) + "  [" + e.Computer + " · " + e.User + " · " + baseName(e.Image) + "]";
    };
    tbody.addEventListener("click", (ev) => { const tr = ev.target.closest("tr"); if (tr) note(Number(tr.dataset.i)); });
    let timer = 0;
    function run() {
      const st = $("pg-status"), w = $("pg-warn"), v = $("pg-verdict");
      let c;
      try { c = R.compile(ta.value); }
      catch (e) {
        ta.classList.add("err"); st.className = "pg-status bad"; st.textContent = "✗ " + (e.plain && e.line ? "line " + e.line + ": " + e.plain : e.message);
        w.innerHTML = ""; trs.forEach((tr) => { tr.classList.remove("fired"); tr.children[0].textContent = ""; tr.children[0].className = "f"; });
        ["pg-tp", "pg-fn", "pg-fp"].forEach((id) => ($(id).textContent = "–")); $("pg-n").textContent = S.PLAY_EVENTS.length;
        v.className = "verdict"; v.textContent = ""; return;
      }
      ta.classList.remove("err");
      const warnings = c.warnings.slice();
      for (const f of c.fields) if (!known.has(f)) warnings.push("the field '" + f + "' never appears in this log, so anything that needs it can't match: check the spelling");
      w.innerHTML = warnings.map((x) => `<li>${esc(x)}</li>`).join("");
      st.className = "pg-status " + (warnings.length ? "y" : "ok");
      st.textContent = "✓ compiled: " + (c.rule.title || "(untitled)") + (warnings.length ? " (" + warnings.length + " warning" + (warnings.length > 1 ? "s" : "") + ")" : "");
      const rows = R.evaluate(c, S.PLAY_EVENTS);
      rows.forEach((r, i) => {
        const a = r.event._label === "attack";
        const cell = trs[i].children[0];
        trs[i].classList.toggle("fired", r.fired);
        cell.textContent = r.fired ? (a ? "✓" : "!") : a ? "–" : "";
        cell.className = "f " + (r.fired ? (a ? "tp" : "fp") : a ? "fn" : "");
      });
      const sc = R.score(rows);
      $("pg-tp").textContent = sc.tp; $("pg-fn").textContent = sc.fn; $("pg-fp").textContent = sc.fp; $("pg-n").textContent = rows.length;
      v.className = "verdict";
      let msg = "";
      if (sc.fired === rows.length) { msg = "# it matches every event: it catches every attack, and every morning with it."; v.classList.add("y"); }
      else if (sc.fired === 0) { msg = "# it matches nothing: zero alerts, and zero detections."; v.classList.add("y"); }
      else if (sc.fn === 0 && sc.fp === 0) { msg = "# every attack, no false alarms. Now put it in a test, so it stays that way."; v.classList.add("ok"); }
      else if (c.rule.level === "critical" && sc.fp > 0) { msg = "# level: critical, and " + sc.fp + " false alarm" + (sc.fp > 1 ? "s" : "") + ". The spec reserves critical for cases in which probability borders certainty."; v.classList.add("bad"); }
      else if (sc.fn && !sc.fp) { msg = sc.fn + " attack event" + (sc.fn > 1 ? "s" : "") + " missed. Which behaviour isn't covered yet?"; v.classList.add("y"); }
      else if (sc.fp && !sc.fn) { msg = sc.fp + " false alarm" + (sc.fp > 1 ? "s" : "") + ". What makes the harmless event different from the attack?"; v.classList.add("y"); }
      else { msg = sc.tp + " caught, " + sc.fn + " missed, " + sc.fp + " false alarm" + (sc.fp > 1 ? "s" : "") + "."; v.classList.add("y"); }
      v.textContent = msg;
    }
    const schedule = () => { clearTimeout(timer); timer = setTimeout(run, 140); };
    ta.addEventListener("input", schedule);
    chips.addEventListener("click", (e) => {
      const b = e.target.closest("button"); if (!b) return;
      ta.value = S.PRESETS[b.dataset.p]; [...chips.children].forEach((x) => x.setAttribute("aria-pressed", String(x === b))); run();
    });
    ta.value = S.PRESETS.office; chips.firstElementChild.setAttribute("aria-pressed", "true");
    run();
    window.__pgRun = run;
  }

  // --------------------------------------------------------------------------- slide 12: what survives a change
  function durableInit() {
    const ch = $("du-changes"), sel = $("du-persist");
    ch.innerHTML = S.CHAIN_CHANGES.map((c) => `<label data-id="${c.id}"><input type="checkbox" value="${c.id}"><span>${esc(c.label)}</span><span class="cost">effort ${c.cost}</span></label>`).join("");
    sel.innerHTML = S.PERSIST.map((p) => `<option value="${p.id}">${esc(p.label)}${p.cost ? " · effort " + p.cost : ""}</option>`).join("");
    const BEH = ["certutil", "task", "persist"];
    function run() {
      const changes = {};
      for (const c of S.CHAIN_CHANGES) changes[c.id] = ch.querySelector(`input[value="${c.id}"]`).checked;
      for (const c of S.CHAIN_CHANGES) ch.querySelector(`[data-id="${c.id}"]`).classList.toggle("on", !!changes[c.id]);
      const r = S.chainRun(changes, sel.value);
      $("du-rows").innerHTML = r.rows.map((x) => `<tr class="${x.fired ? "on" : "off"}"><td class="st ${x.fired ? "on" : "off"}">${x.fired ? "● fires" : "✗ silent"}</td><td>${esc(x.name)}</td><td><small>${esc(x.rung)}</small></td></tr>`).join("");
      const beh = r.rows.filter((x) => BEH.includes(x.id) && x.fired).length;
      $("du-cost").textContent = r.cost; $("du-fire").textContent = r.firing + " of " + r.total; $("du-ttp").textContent = beh + " of 3";
      const v = $("du-verdict"), any = Object.values(changes).some(Boolean) || sel.value !== "task";
      v.className = "verdict";
      const ind = r.rows.filter((x) => !BEH.includes(x.id)), indDead = ind.filter((x) => !x.fired).length;
      if (!any) { v.textContent = "Nothing has changed yet. Tick what the attacker would change."; }
      else if (r.firing === 0) { v.className = "verdict ok"; v.textContent = "Nothing fires, and it cost them effort " + r.cost + " and a new way of working. # That is what 'the attacker pays' looks like. Write the next behaviour rule."; }
      else if (beh === 3) { v.className = "verdict ok"; v.textContent = "The cheap changes killed " + indDead + " of 4 indicator rules at effort " + r.cost + ". All three behaviour rules still fire."; }
      else { v.className = "verdict y"; v.textContent = "Effort " + r.cost + ": " + (3 - beh) + " behaviour rule" + (3 - beh > 1 ? "s" : "") + " went quiet, and " + r.firing + " still fire" + (r.firing === 1 ? "s" : "") + ". Notice which one survived."; }
    }
    ch.addEventListener("change", run); sel.addEventListener("change", run);
    run();
  }

  // --------------------------------------------------------------------------- slide 13: tuning
  function tuningInit() {
    const list = $("tn-list");
    list.innerHTML = S.TUNE_FILTERS.map((f) => {
      const e = S.filterEffect(f.id);
      const eff = `<i class="good">−${num(e.removed)}</i>` + (e.hides.length ? `<i class="bad">hides ${e.hides.length} attack${e.hides.length > 1 ? "s" : ""}</i>` : `<i class="meh">hides no attack</i>`);
      return `<label class="tn-f" data-id="${f.id}"><input type="checkbox" value="${f.id}"><span>${esc(f.label)}<small>${esc(f.note)}</small></span><span class="eff">${eff}</span></label>`;
    }).join("");
    function run() {
      const on = S.TUNE_FILTERS.filter((f) => list.querySelector(`input[value="${f.id}"]`).checked).map((f) => f.id);
      for (const f of S.TUNE_FILTERS) list.querySelector(`[data-id="${f.id}"]`).classList.toggle("on", on.includes(f.id));
      const r = S.tuneRun(on);
      $("tn-alerts").textContent = num(r.alerts); $("tn-hours").textContent = Math.round(r.hours) + " h"; $("tn-caught").textContent = r.tp + " of " + r.attacks;
      $("tn-rule").textContent = r.text;
      const v = $("tn-verdict"), n = $("tn-note");
      v.className = "verdict"; n.textContent = "";
      if (r.hidden.length) {
        v.classList.add("bad"); v.textContent = "Your filters hide " + r.hidden.length + " real attack" + (r.hidden.length > 1 ? "s" : "") + ": " + r.hidden.map((a) => a.name.replace("ATTACK: ", "")).join("; ") + ".";
        n.textContent = "# that exclusion would have hidden a real attack. This is what tests are for.";
      } else if (!on.length) { v.classList.add("y"); v.textContent = "Every one of these alerts pages someone: " + num(r.alerts) + " a week."; }
      else if (r.alerts <= 60) { v.classList.add("ok"); v.textContent = "A quiet week (" + (r.perDay).toFixed(1) + " alerts a day) and all " + r.attacks + " attacks still alert. Write down why each filter is safe."; n.textContent = "# a quiet week, with every attack still alerting. The 35 left are administrators: ask them for signed scripts."; }
      else { v.classList.add("y"); v.textContent = "Still " + num(r.alerts) + " alerts a week (" + r.perDay.toFixed(0) + " a day), and nothing real is hidden. Keep going."; }
    }
    list.addEventListener("change", run);
    run();
  }

  // --------------------------------------------------------------------------- slide 14: ADS
  function adsInit() {
    const g = $("ads-list");
    g.innerHTML = S.ADS.map((a, i) => `<button type="button" class="fa-btn" data-i="${i}" aria-pressed="false"><b>${esc(a.name)}</b></button>`).join("");
    const show = (i) => {
      [...g.children].forEach((b, k) => b.setAttribute("aria-pressed", String(k === i)));
      $("ads-detail").innerHTML = `<h3>${esc(S.ADS[i].name)}</h3><p class="ads-body">${esc(S.ADS[i].text)}</p>`;
    };
    g.addEventListener("click", (e) => { const b = e.target.closest("button"); if (b) show(Number(b.dataset.i)); });
    show(4);
  }

  // --------------------------------------------------------------------------- slide 16: the test lab
  function testsInit() {
    const ta = $("tl-rule"), chips = $("tl-presets"), varBox = $("tl-var");
    const PRE = [["narrow", "Narrow: one exact command"], ["broad", "Broad: any mention of urlcache"], ["good", "Good"]];
    chips.innerHTML = PRE.map(([id, label]) => `<button type="button" class="chip" data-p="${id}" aria-pressed="false">${esc(label)}</button>`).join("");
    let timer = 0;
    function run() {
      const st = $("tl-status"), list = $("tl-list"), v = $("tl-verdict");
      let c;
      try { c = R.compile(ta.value); }
      catch (e) { ta.classList.add("err"); st.className = "pg-status bad"; st.textContent = "✗ " + (e.plain && e.line ? "line " + e.line + ": " + e.plain : e.message); list.innerHTML = ""; $("tl-sum").textContent = ""; v.textContent = ""; v.className = "verdict"; return; }
      ta.classList.remove("err");
      st.className = "pg-status " + (c.warnings.length ? "y" : "ok"); st.textContent = "✓ compiled: " + (c.rule.title || "(untitled)") + (c.warnings.length ? " (" + c.warnings.length + " warning" + (c.warnings.length > 1 ? "s" : "") + ")" : "");
      const rows = S.runTests(c, varBox.checked), sum = S.testSummary(rows);
      list.innerHTML = rows.map((r) => `<div class="tl-row ${r.pass ? "pass" : "fail"} ${r.kind === "variant" ? "var" : ""}"><b class="g">${r.pass ? "✓" : "✗"}</b><span class="t">${esc(r.kind === "variant" ? r.mutationLabel : r.name)}${r.kind === "variant" && !r.pass ? `<small>${esc(r.cmd)}</small>` : ""}${r.kind === "variant" ? "" : ""}</span><span class="k">${r.kind === "variant" ? "variant" : r.expect ? "should match" : "should not"}</span></div>`).join("");
      $("tl-sum").textContent = sum.passed + " of " + sum.total + " cases" + (varBox.checked ? " · " + sum.varPassed + " of " + sum.varTotal + " variants" : "");
      const missed = rows.filter((r) => r.kind === "positive" && !r.pass).length, extra = rows.filter((r) => r.kind === "negative" && !r.pass).length, vf = rows.filter((r) => r.kind === "variant" && !r.pass).length;
      v.className = "verdict";
      if (!missed && !extra && !vf) { v.classList.add("ok"); v.textContent = varBox.checked ? "# green on every case and every variant. Add a new case from your next false alarm." : "# all green. Now tick 'also run variants'."; }
      else { v.classList.add(missed + extra > 2 ? "bad" : "y"); v.textContent = [missed ? "Misses " + missed + " case" + (missed > 1 ? "s" : "") + " that should match" : "", extra ? "fires on " + extra + " that shouldn't" : "", vf ? vf + " variant" + (vf > 1 ? "s" : "") + " slip" + (vf > 1 ? "" : "s") + " through" : ""].filter(Boolean).join("; ") + "."; }
    }
    ta.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(run, 140); });
    varBox.addEventListener("change", run);
    chips.addEventListener("click", (e) => { const b = e.target.closest("button"); if (!b) return; ta.value = S.TEST_RULES[b.dataset.p]; [...chips.children].forEach((x) => x.setAttribute("aria-pressed", String(x === b))); run(); });
    ta.value = S.TEST_RULES.narrow; chips.firstElementChild.setAttribute("aria-pressed", "true");
    run();
    window.__tlRun = run;
  }

  // --------------------------------------------------------------------------- slide 17: purple-team results
  const PT_STATES = ["No telemetry", "Logged only", "Rule fired", "Alert reached an analyst", "Analyst knew what to do"];
  function purpleInit() {
    const items = ["T1059.001", "T1105", "T1053.005", "T1490", "T1003.001", "T1110.003"];
    const start = [3, 2, 1, 0, 2, 1];
    const g = $("pt-grid");
    g.innerHTML = items.map((id, i) => `<div class="pt-row" data-i="${i}"><span><b>${esc(id)}</b> ${esc(S.TECH[id])}</span><button type="button" data-s="${start[i]}">${PT_STATES[start[i]]}</button></div>`).join("");
    function sum() {
      const st = [...g.querySelectorAll("button")].map((b) => Number(b.dataset.s));
      const v = $("pt-verdict");
      const low = Math.min(...st), at = st.map((s, i) => [s, i]).filter(([s]) => s === low).map(([, i]) => items[i]);
      v.className = "verdict";
      if (st.every((s) => s === 4)) { v.classList.add("ok"); v.textContent = "# all six end to end. Schedule the next run: a test result has a date."; }
      else { v.classList.add(low <= 1 ? "bad" : "y"); v.textContent = st.filter((s) => s >= 3).length + " of 6 reach an analyst. Weakest: " + at.join(", ") + " (" + PT_STATES[low].toLowerCase() + "). Fix that stage first."; }
    }
    g.addEventListener("click", (e) => { const b = e.target.closest("button"); if (!b) return; const n = (Number(b.dataset.s) + 1) % PT_STATES.length; b.dataset.s = n; b.textContent = PT_STATES[n]; sum(); });
    sum();
  }

  // --------------------------------------------------------------------------- slide 18: coverage
  function coverageInit() {
    const grid = $("cv-grid");
    const BOARDS = [["painted", "Painted green"], ["tested", "Tested"], ["mixed", "Mixed"]];
    $("cv-boards").innerHTML = BOARDS.map(([id, l]) => `<button type="button" class="chip" data-b="${id}" aria-pressed="false">${l}</button>`).join("");
    let states = S.COV_BOARDS.mixed.slice();
    const paint = () => {
      grid.innerHTML = S.COV_TECHS.map((t, i) => `<button type="button" class="tile" data-i="${i}" data-s="${states[i]}" title="${esc(t.id + " " + t.name)}"><small>${esc(t.id)}</small><b>${esc(t.name)}</b><span>${esc(S.COV_STATES[states[i]].short)}</span></button>`).join("");
      const st = S.coverageStats(states);
      $("cv-bars").innerHTML = [["", "Has a rule (heatmap)", st.heat], ["h", "Tested at least once", st.testedPct], ["r", "Tested vs variants", st.robustPct]]
        .map(([cls, l, p]) => `<div class="cv-bar ${cls}"><span>${l}</span><span class="t"><i style="width:${p}%"></i></span><b>${p}%</b></div>`).join("");
      const v = $("cv-verdict"); v.className = "verdict";
      if (states.every((s) => s === 2)) { v.classList.add("y"); v.textContent = "# a very green map. Ask what each square was tested against."; }
      else if (states.every((s) => s === 4)) { v.classList.add("ok"); v.textContent = "# a heatmap that is green because it was tested is rarer than one that is green because it was painted."; }
      else if (st.heat - st.robustPct >= 40) { v.classList.add("bad"); v.textContent = "The heatmap says " + st.heat + "%. Only " + st.robustPct + "% has been tested against variants."; }
      else if (st.robustPct >= st.heat - 10 && st.heat > 0) { v.classList.add("ok"); v.textContent = "Close to the heatmap: " + st.robustPct + "% tested against variants, of " + st.heat + "% with a rule."; }
      else { v.classList.add("y"); v.textContent = st.heat + "% have a rule; " + st.testedPct + "% were ever tested; " + st.robustPct + "% against variants."; }
      [...$("cv-boards").children].forEach((b) => b.setAttribute("aria-pressed", "false"));
    };
    $("cv-boards").addEventListener("click", (e) => { const b = e.target.closest("button"); if (!b) return; states = S.COV_BOARDS[b.dataset.b].slice(); paint(); b.setAttribute("aria-pressed", "true"); });
    grid.addEventListener("click", (e) => { const b = e.target.closest("button"); if (!b) return; const i = Number(b.dataset.i); states[i] = (states[i] + 1) % S.COV_STATES.length; paint(); grid.querySelector(`[data-i="${i}"]`).focus(); });
    paint();
    $("cv-boards").children[2].setAttribute("aria-pressed", "true");
  }

  // --------------------------------------------------------------------------- slide 20: the pipeline
  function pipelineInit() {
    const ta = $("ci-rule");
    $("ci-breaks").innerHTML = S.CI_BREAKS.map((b) => `<button type="button" class="chip" data-b="${b.id}">${esc(b.label)}</button>`).join("");
    const GL = { pass: "✓", fail: "✗", warn: "!", skip: "–" };
    let timer = 0;
    function run() {
      const r = S.ciRun(ta.value);
      $("ci-log").innerHTML = r.steps.map((s) => `<div class="ci-step ${s.status}"><b>${GL[s.status]}</b><span>${esc(s.name)}<span class="d">${esc(s.detail)}</span></span></div>`).join("");
      const v = $("ci-verdict"), fails = r.steps.filter((s) => s.status === "fail").length;
      v.className = "verdict";
      if (r.pass && !r.steps.some((s) => s.status === "warn")) { v.classList.add("ok"); v.textContent = "# a green pipeline. Roll it out in stages: log only first, then low priority."; }
      else if (r.pass) { v.classList.add("y"); v.textContent = "Passes with warnings. A reviewer should read them."; }
      else if (fails >= 3) { v.classList.add("bad"); v.textContent = "# every check red: the pipeline did its job. " + fails + " steps failed."; }
      else { v.classList.add("bad"); v.textContent = "Blocked: " + fails + " step" + (fails > 1 ? "s" : "") + " failed. Nothing reaches review until they pass."; }
    }
    ta.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(run, 140); });
    $("ci-breaks").addEventListener("click", (e) => { const b = e.target.closest("button"); if (!b) return; ta.value = S.CI_BREAKS.find((x) => x.id === b.dataset.b).fn(ta.value); run(); });
    click("ci-reset", () => { ta.value = S.CI_RULE; run(); });
    ta.value = S.CI_RULE;
    run();
    window.__ciRun = run;
  }

  // --------------------------------------------------------------------------- slide 21: metrics
  function metricsInit() {
    let key = "fires", dir = -1;
    const rng = (id) => $(id);
    const label = { name: "Rule", fires: "Alerts", precision: "Real", hours: "Hours", tested: "Tested", verdict: "Verdict" };
    function run() {
      const th = { minPrecision: Number(rng("mt-prec").value), maxHours: Number(rng("mt-hours").value), staleDays: Number(rng("mt-stale").value) };
      $("mt-prec-o").textContent = th.minPrecision + "%"; $("mt-hours-o").textContent = th.maxHours; $("mt-stale-o").textContent = th.staleDays;
      const rows = S.rateRules(S.RULE_STATS, th);
      const cmp = (a, b) => { const x = a[key], y = b[key]; if (x === y) return 0; if (x === null) return 1; if (y === null) return -1; return (x > y ? 1 : -1) * dir; };
      rows.sort(cmp);
      const cls = (v) => (v.startsWith("keep") ? "keep" : v.startsWith("tune") ? "tune" : v.startsWith("retire") ? "retire" : v.startsWith("test") ? "test" : v.startsWith("assign") ? "owner" : "check");
      $("mt-rows").innerHTML = rows.map((r) => `<tr><td>${esc(r.name)}${r.why.length ? `<small>${esc(r.why.join("; "))}</small>` : ""}</td><td class="n">${num(r.fires)}</td><td class="n">${r.precision === null ? "–" : r.precision + "%"}</td><td class="n">${r.hours.toFixed(1)}</td><td class="n">${r.tested} d</td><td><span class="vd ${cls(r.verdict)}">${esc(r.verdict)}</span></td></tr>`).join("");
      const tot = rows.reduce((a, r) => ({ h: a.h + r.hours, tp: a.tp + r.tp, f: a.f + r.fires }), { h: 0, tp: 0, f: 0 });
      const counts = {}; rows.forEach((r) => (counts[r.verdict] = (counts[r.verdict] || 0) + 1));
      const v = $("mt-sum"); v.className = "verdict y";
      v.textContent = Object.entries(counts).map(([k, n]) => n + " " + k).join(" · ") + ". This week: " + num(tot.f) + " alerts, " + tot.tp + " real, " + Math.round(tot.h) + " analyst hours.";
      [...document.querySelectorAll("#metrics th[data-k]")].forEach((th) => (th.textContent = label[th.dataset.k] + (th.dataset.k === key ? (dir > 0 ? " ▲" : " ▼") : "")));
    }
    ["mt-prec", "mt-hours", "mt-stale"].forEach((id) => rng(id).addEventListener("input", run));
    document.querySelector("#metrics thead").addEventListener("click", (e) => { const th = e.target.closest("th[data-k]"); if (!th) return; if (key === th.dataset.k) dir = -dir; else { key = th.dataset.k; dir = key === "name" || key === "verdict" ? 1 : -1; } run(); });
    run();
  }

  // --------------------------------------------------------------------------- slide 22: drift
  function driftInit() {
    const pick = seg("dr-pick", S.DRIFTS.map((d) => ({ v: d.id, label: d.short })), "none", run);
    function run() {
      const d = S.DRIFTS.find((x) => x.id === pick.get());
      $("dr-desc").textContent = d.label + ". " + d.describe;
      const rows = S.driftRun(d.id);
      $("dr-rows").innerHTML = rows.map((r) => `<tr><td>${esc(r.name)}</td><td class="n ${r.caught < r.attacks ? "bad" : "good"}">${r.caught} of ${r.attacks}</td><td class="n ${r.fp ? "bad" : ""}">${r.fp}</td><td class="${r.canary ? "good" : "bad"}">${r.canary ? "✓ fires" : "✗ silent"}</td></tr>`).join("");
      const lost = rows.filter((r) => r.caught < r.attacks).length, noisy = rows.filter((r) => r.fp > 1 || (r.id === "office" && r.fp > 0)).length;
      const v = $("dr-verdict"); v.className = "verdict";
      if (d.id === "none") { v.classList.add("ok"); v.textContent = "Nothing changed, and every rule behaves. This is the baseline."; }
      else if (lost) { v.classList.add("bad"); v.textContent = lost + " of 4 rules now miss attacks, and nothing logged an error." + (noisy ? " One rule also got noisier." : "") + " The canary column is the only thing that said so."; }
      else { v.classList.add("y"); v.textContent = "Every attack is still caught, but check the false alarms: a filter may have stopped working."; }
    }
    run();
  }

  // --------------------------------------------------------------------------- slide 23: checklist
  function checklistInit() {
    const plan = $("cl-plan");
    let saved = []; try { saved = JSON.parse(store("detect-checklist") || "[]"); } catch (e) {}
    plan.innerHTML = S.CHECKLIST.map((t, i) => `<label><input type="checkbox" data-i="${i}" ${saved.includes(i) ? "checked" : ""}><span>${esc(t)}</span></label>`).join("");
    const upd = () => {
      const on = [...plan.querySelectorAll("input")].filter((x) => x.checked).map((x) => Number(x.dataset.i));
      store("detect-checklist", JSON.stringify(on));
      const v = $("cl-note"); v.className = "verdict" + (on.length === S.CHECKLIST.length ? " ok" : "");
      v.textContent = on.length === S.CHECKLIST.length ? "12 of 12. # A rule you can explain, test, tune and retire." : on.length + " of " + S.CHECKLIST.length + " ticked.";
    };
    plan.addEventListener("change", upd); upd();
  }

  // --------------------------------------------------------------------------- the console
  function consoleHint() {
    console.log("%cDetection Engineering", "font: 700 24px monospace; color: #ff2e88; text-shadow: 0 0 8px #ff2e88");
    console.log("%cThe rule engine is window.Rules and the made-up data is window.Scen. Try Rules.compile(Scen.PRESETS.all).match(Scen.PLAY_EVENTS[0]), or paste a real Sigma rule into the playground.", "font: 14px monospace; color: #00f0ff");
  }

  function start() {
    consoleHint();
    $("hero-in").addEventListener("input", hero); hero();
    lifecycleInit(); pyramidInit(); reportInit(); mapInit();
    telemetryInit(); sigmaInit(); playgroundInit(); durableInit(); tuningInit(); adsInit();
    testsInit(); purpleInit(); coverageInit();
    pipelineInit(); metricsInit(); driftInit(); checklistInit();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
})();
