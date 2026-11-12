/* app.js - the live demos for "Securing Dependencies and CI/CD".
   Every demo is a simulation in this page: an invented registry, invented packages and advisories, a toy CI system and a toy
   transparency log, plus real (but from-scratch) SHA-1, SHA-256 and ECDSA from ../../shared/crypto.js. Nothing is downloaded, installed,
   executed or sent anywhere: the "shell" in the injection demo only splits text into commands. */
(function () {
  "use strict";
  const L = window.Lab, D = window.DepsLab;

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
  const note = (id, text) => { $(id).textContent = text; };
  const row = (cls, mark, html) => `<li class="${cls}"><b>${mark}</b><span>${html}</span></li>`;
  const MARK = { ok: "✓", bad: "✗", y: "!", m: "·" };

  // --------------------------------------------------------------------------- title: look-alike names
  function hero() {
    const el = $("hero-in"), v = el.value;
    el.style.width = Math.min(30, Math.max(8, v.length + 1)) + "ch";
    const r = D.lookalike(v), t = v.trim().toLowerCase();
    let status;
    if (r.kind === "empty") status = "nothing to compare";
    else if (r.kind === "exact") status = "a well-known name";
    else if (r.kind === "close") status = "close to " + r.nearest;
    else status = "not close to any name on this short list";
    $("hero-out").innerHTML = `${sp("k", "length: ")} ${v.length}<br>${sp("k", "closest:")} ${esc(r.nearest || "-")}${r.distance ? " (" + r.distance + " edit" + (r.distance === 1 ? "" : "s") + ")" : ""}<br>${sp("k", "result: ")} ${esc(status)}`;
    let n;
    if (r.kind === "empty") n = "# nothing to install. The safest dependency is the one you never add.";
    else if (t === "left-pad") n = "# left-pad: in March 2016 its author removed his packages from npm and thousands of builds broke for about two and a half hours. A dependency can vanish.";
    else if (t === "requests") n = "# a well-known name, as far as this short list goes. Check the project's own page before you trust any name.";
    else if (t === "lodash") n = "# among the most depended-on packages there is. Popular isn't safe, but a lot of people are looking.";
    else if (t === "colors") n = "# in January 2022 its own maintainer published deliberately broken versions: trust is in people as well as code.";
    else if (t === "package-lock.json") n = "# a file, not a package. Commit it, though.";
    else if (r.kind === "exact") n = "# a well-known name (on this short list). Still copy it from the project's own page.";
    else if (r.kind === "close") n = "# close to \"" + r.nearest + "\"" + (r.tricks.length ? ": " + r.tricks.join("; ") : "") + ". A typo or a copied command is all it takes.";
    else n = "# no close match on a short list proves nothing. Check the project's page, age, maintainers and downloads.";
    note("hero-note", n);
  }

  // --------------------------------------------------------------------------- dependency tree
  const tr = { sel: "url-parse-lite", applied: new Set(), override: false };
  function treeRender() {
    const seen = new Set(), P = D.PACKAGES, vs = D.vulnState(tr.applied, tr.override);
    const direct = new Set(D.directDeps());
    const node = (name, depth) => {
      const p = P[name], again = seen.has(name);
      seen.add(name);
      const isDirect = depth === 1, cls = (isDirect ? "direct" : "") + (name === "url-parse-lite" ? " vuln" + (!vs.vulnerable ? " fixed" : "") : "");
      const ver = name === "url-parse-lite" && !vs.vulnerable ? "2.2.0" : p.v;
      const tag = (p.dev ? " dev" : "") + (again ? " ↺" : "");
      let kids = "";
      if (!again) { const c = D.PACKAGES[name].deps.concat(Array.isArray(p.dev) ? p.dev : []); if (c.length) kids = "<ul>" + c.map((k) => node(k, depth + 1)).join("") + "</ul>"; }
      return `<li class="${cls}"><button type="button" data-p="${esc(name)}" aria-pressed="${tr.sel === name}">${esc(name)}</button><small>${esc(ver)}${tag}</small>${kids}</li>`;
    };
    $("tr-list").innerHTML = `<li><button type="button" data-p="${D.ROOT}" aria-pressed="${tr.sel === D.ROOT}">${D.ROOT}</button><small>${P[D.ROOT].v} (your app)</small><ul>${D.directDeps().map((d) => node(d, 1)).join("")}</ul></li>`;
    const s = D.treeStats();
    $("tr-stats").innerHTML = `<b>${s.direct}</b> chosen by you · <b>${s.transitive}</b> that came along · <b>${s.total}</b> in all · longest chain <b>${s.maxDepth}</b> deep`;
    // detail for the selected package
    const name = tr.sel, p = P[name], paths = D.pathsTo(name);
    const parents = Object.keys(P).filter((k) => D.PACKAGES[k].deps.includes(name) || (Array.isArray(P[k].dev) && P[k].dev.includes(name)));
    let d = `<b>${esc(name)} ${esc(name === "url-parse-lite" && !vs.vulnerable ? "2.2.0" : p.v)}</b><span>${esc(p.note)}</span>`;
    d += name === D.ROOT ? "" : `<span>${direct.has(name) ? "A direct dependency." : "A transitive dependency: you didn't choose it."}${p.dev ? " Development only: it runs on build machines, not in the shipped app." : ""}</span>`;
    if (parents.length) d += `<span>Pulled in by: ${parents.map(esc).join(", ")}</span>`;
    if (p.vuln) d += `<span class="${vs.vulnerable ? "bad" : "ok"}">${esc(p.vuln.id)}: ${esc(p.vuln.sev)} in versions below ${esc(p.vuln.below)}, ${esc(p.vuln.text)}</span>`;
    $("tr-detail").innerHTML = d;
    $("tr-paths").innerHTML = name === D.ROOT ? "" : paths.map((pp) => {
      let st = "", cls = "";
      if (name === "url-parse-lite") { const x = vs.paths.find((q) => q.direct === pp[0]); st = x.fixed ? " ✓ fixed" : (x.hasFix ? " ✗ still vulnerable (a fix is available)" : " ✗ still vulnerable (no fix released)"); cls = x.fixed ? "ok" : "bad"; }
      return `<li class="${cls}"><span>${[D.ROOT].concat(pp).map(esc).join(" <i>›</i> ")}${esc(st)}</span></li>`;
    }).join("");
    if (vs.vulnerable) {
      const bad = vs.paths.filter((q) => !q.fixed).length;
      verdict("tr-verdict", "bad", `${bad} of ${vs.paths.length} chains still end in url-parse-lite 2.1.0${vs.shipped ? "" : " (build tools only)"}`);
    } else verdict("tr-verdict", "ok", "Every chain now ends in the fixed version");
    // fixes
    $("tr-fixes").innerHTML = Object.keys(D.FIXES).map((k) => `<button type="button" class="btn btn-sm" data-f="${k}" ${tr.applied.has(k) || tr.override ? "disabled" : ""}>Update ${k} → ${D.FIXES[k]}</button>`).join("")
      + `<button type="button" class="btn btn-ghost btn-sm" data-f="__o" ${tr.override ? "disabled" : ""}>Add an override</button><button type="button" class="btn btn-ghost btn-sm" data-f="__r">Reset</button>`;
    // notes (eggs)
    let n = "# click a package to see every chain that pulls it in.";
    if (tr.sel === "left-pad") n = "# left-pad: a famously tiny function. In 2016 its removal broke a lot of builds. Here it's just a leaf: but someone, somewhere, depends on it.";
    else if (tr.override) n = "# an override fixes it everywhere, and it's yours to maintain: test it, and remove it when upstream catches up.";
    else if (["forms-kit", "http-client", "build-tools"].every((k) => tr.applied.has(k))) n = "# three updates, and fast-router still carries it. Some fixes aren't yours to make: that's what overrides, forks and exit plans are for.";
    note("tr-note", n);
  }
  function treeInit() {
    $("tr-list").addEventListener("click", (e) => { const b = e.target.closest("button[data-p]"); if (!b) return; tr.sel = b.dataset.p; treeRender(); });
    $("tr-fixes").addEventListener("click", (e) => {
      const b = e.target.closest("button[data-f]"); if (!b) return;
      const f = b.dataset.f;
      if (f === "__o") tr.override = true; else if (f === "__r") { tr.applied = new Set(); tr.override = false; tr.sel = "url-parse-lite"; } else tr.applied.add(f);
      treeRender();
    });
    treeRender();
  }

  // --------------------------------------------------------------------------- typosquat spotter
  const SP = { i: 0, score: 0, answered: false, game: 0, opts: [], picked: [] };
  function spRound() {
    const r = D.ROUNDS[SP.i];
    SP.opts = D.roundOptions(r, SP.game * 7 + SP.i + 1); SP.answered = false;
    $("sp-need").innerHTML = `Round ${SP.i + 1} of ${D.ROUNDS.length}: you need <b>${esc(r.need)}</b>. Which name is the real one?`;
    $("sp-opts").innerHTML = SP.opts.map((o, k) => `<button type="button" data-k="${k}">${esc(o.name)}</button>`).join("");
    $("sp-next").hidden = true; $("sp-why").textContent = ""; $("sp-verdict").className = "verdict"; $("sp-verdict").textContent = "";
    $("sp-score").textContent = `score ${SP.score} / ${SP.i}`;
    note("sp-note", "# one is the name on the project's own page. The others are invented look-alikes.");
  }
  function spPick(k) {
    if (SP.answered) return; SP.answered = true;
    const o = SP.opts[k];
    if (o.real) SP.score++;
    $("sp-opts").querySelectorAll("button").forEach((b, j) => { b.disabled = true; if (SP.opts[j].real) b.classList.add("right"); else if (j === k) b.classList.add("wrong"); b.insertAdjacentHTML("beforeend", `<small>${esc(SP.opts[j].why)}</small>`); });
    verdict("sp-verdict", o.real ? "ok" : "bad", o.real ? "Correct: that's the real name." : "That's a look-alike.");
    $("sp-why").textContent = o.real ? "Copying from the project's page would have made this a non-question." : "The real name is " + SP.opts.find((x) => x.real).name + ".";
    $("sp-score").textContent = `score ${SP.score} / ${SP.i + 1}`;
    const last = SP.i === D.ROUNDS.length - 1;
    $("sp-next").hidden = last; if (last) spFinish();
    else $("sp-next").textContent = "Next round";
  }
  function spFinish() {
    const n = D.ROUNDS.length;
    let m = `# final score ${SP.score} of ${n}. `;
    if (SP.score === n) m += "Perfect. In real life nobody tells you which one is real, which is why the habit is to copy from the source.";
    else if (SP.score === 0) m += "Zero. Look-alikes work because they're built to be confusable. A lock file and a registry that scans are your friends.";
    else m += "Now imagine doing it at 5 p.m. from a chat message. The process matters more than eyesight.";
    note("sp-note", m);
  }
  function spInit() {
    $("sp-opts").addEventListener("click", (e) => { const b = e.target.closest("button[data-k]"); if (b) spPick(+b.dataset.k); });
    click("sp-next", () => { SP.i++; spRound(); });
    click("sp-reset", () => { SP.i = 0; SP.score = 0; SP.game++; spRound(); });
    spRound();
  }

  // --------------------------------------------------------------------------- lock files and cooldowns
  const LK = { day: 12, tampered: false, content: "date-fmt 1.2.0 package contents" };
  function lockRender() {
    const day = LK.day; $("lk-day-out").textContent = day;
    const bad = [];
    $("lk-rows").innerHTML = Object.keys(D.MODES).map((m) => {
      const tl = D.timeline(m, 20), cur = tl[day];
      if (cur.bad) bad.push(m);
      return `<div class="lk-row"><b>${esc(D.MODES[m].label)}<em>${esc(cur.v)}${cur.bad ? " (bad)" : ""}</em></b><div class="lk-cells" aria-hidden="true">${tl.map((x) => `<i class="${x.bad ? "bad" : ""}${x.day === day ? " now" : ""}"></i>`).join("")}</div></div>`;
    }).join("");
    if (bad.length) verdict("lk-verdict", "bad", `Day ${day}: ${bad.length === 1 ? "this way" : "these ways"} would give you 1.3.1: ${bad.map((m) => D.MODES[m].label.toLowerCase()).join("; ")}`);
    else verdict("lk-verdict", "ok", `Day ${day}: none of the four would give you the bad version`);
    let n = "# red = a day that way of installing hands you the bad 1.3.1.";
    if (day >= 12 && day <= 13) n = "# no lock file: the newest match is the bad one, and every image built today keeps it.";
    else if (day >= 14 && day <= 15) n = "# 1.3.1 is gone from the registry, but the bot already merged it. It stays until the fix on day 16.";
    else if (day === 16) n = "# 1.3.2 is the fix: a bot with no wait takes it now, one with a wait on day 19.";
    note("lk-note", n);
    // the lock entry and its integrity check
    const expected = D.integrity(LK.content), got = D.integrity(LK.tampered ? LK.content.replace("date-fmt", "date-fmt!") : LK.content), ok = expected === got;
    $("lk-lock").innerHTML = `${sp("k", '"date-fmt": {')}\n  "version": "1.2.0",\n  "integrity": "${esc(expected.slice(0, 22))}…"\n${sp("k", "}")}\n\n${sp("k", "downloaded:")} ${esc(got.slice(0, 22))}…\n${ok ? sp("ok", "hashes match: install continues") : sp("bad", "hash mismatch: install refused, build fails")}`;
  }
  function lockInit() {
    $("lk-day").addEventListener("input", (e) => { LK.day = +e.target.value; lockRender(); });
    click("lk-tamper", () => { LK.tampered = true; lockRender(); });
    click("lk-fix", () => { LK.tampered = false; lockRender(); });
    lockRender();
  }

  // --------------------------------------------------------------------------- reviewing an update
  function upRender(k) {
    const u = D.UPDATES[k], o = u.old, n = u.neu, lines = [];
    const kv = (label, a, b) => { if (JSON.stringify(a) === JSON.stringify(b)) lines.push(`  ${label}: ${a}`); else { lines.push(sp("del", `- ${label}: ${a}`)); lines.push(sp("add", `+ ${label}: ${b}`)); } };
    const sc = (m) => Object.keys(m.scripts || {}).map((x) => x + ": " + m.scripts[x]).join(", ") || "none";
    lines.push(sp("k", "forms-kit " + o.v + " → " + n.v));
    kv("version", o.v, n.v); kv("install scripts", sc(o), sc(n)); kv("maintainers", (o.maintainers || []).join(", "), (n.maintainers || []).join(", "));
    kv("provenance", o.provenance ? "yes" : "no", n.provenance ? "yes" : "no"); kv("dependencies", Object.keys(o.deps).join(", "), Object.keys(n.deps).join(", "));
    kv("size", o.sizeKB + " KB", n.sizeKB + " KB");
    $("up-diff").innerHTML = lines.map((l) => (l.startsWith("<") ? l : esc(l))).join("\n");
    const f = D.reviewUpdate(o, n, D.NOW);
    $("up-flags").innerHTML = f.map((x) => row(x.level, MARK[x.level], esc(x.text))).join("");
    const bad = f.filter((x) => x.level === "bad").length;
    note("up-note", bad >= 3 ? "# any one of these has an innocent explanation. Four together is a reason to stop and ask." : (k === "major" ? "# nothing suspicious, but breaking changes are still changes. Read the changelog and run the tests." : "# the version number said \"patch\". The metadata said otherwise: read the shape, not the label."));
  }
  const upInit = () => { segPick("up-pick", "data-u", upRender); upRender("patch"); };

  // --------------------------------------------------------------------------- dependency confusion
  function cfRender(k) {
    const r = D.resolveConfusion(k);
    $("cf-out").className = "cf-out" + (r.bad ? " bad" : "");
    $("cf-out").innerHTML = `<b>The build installs: ${esc(r.chosen.name)} ${esc(r.chosen.version)} from the ${esc(r.chosen.registry)}</b><span>${esc(r.why)}</span>`;
    verdict("cf-verdict", r.bad ? "bad" : "ok", r.bad ? "The wrong package is now running in your build" : "Your own package, as intended");
    note("cf-note", r.bad ? "# 99.0.0 sounds like a lot of releases. It's one, and it isn't yours." : "# the config said what to trust, so there was nothing to guess.");
  }
  function cfInit() {
    $("cf-pick").innerHTML = Object.keys(D.STRATEGIES).map((k, i) => `<button type="button" data-c="${k}" aria-pressed="${i === 0}">${esc(D.STRATEGIES[k].label)}</button>`).join("");
    segPick("cf-pick", "data-c", cfRender); cfRender("highest");
  }

  // --------------------------------------------------------------------------- SBOMs
  function sbInit() {
    const s = D.FLEET["shop-web"], c = s.components;
    const lines = ["{", '  "bomFormat": "CycloneDX",', '  "specVersion": "1.6",', '  "metadata": { "component": { "name": "shop-web" } },', '  "components": ['];
    c.slice(0, 3).forEach((x) => lines.push(`    { "name": "${x.name}", "version": "${x.version}", "purl": "${x.purl}" },`));
    lines.push(`    … ${c.length - 3} more components`, "  ]", "}");
    $("sb-json").textContent = lines.join("\n");
    click("sb-ask", () => {
      const r = D.whichApps(D.FLEET, "url-parse-lite", "2.2.0");
      $("sb-out").innerHTML = r.map((x) => x.affected ? row("bad", "✗", `<code>${esc(x.app)}</code> ships url-parse-lite ${esc(x.version)}: affected`) : (x.version ? row("ok", "✓", `<code>${esc(x.app)}</code> ships ${esc(x.version)}: already fixed`) : row("m", "·", `<code>${esc(x.app)}</code> doesn't use it`))).join("");
      const n = r.filter((x) => x.affected).length;
      note("sb-note", `# ${n} of ${r.length} apps to fix, answered in a blink. Without an inventory it's four teams and a spreadsheet.`);
    });
    note("sb-note", "# the question isn't \"do we have SBOMs?\" but \"can we answer an advisory in minutes?\"");
  }

  // --------------------------------------------------------------------------- token permissions
  const TK = { perms: new Set(D.PERMS), sec: "repo" };
  function tkRender() {
    const b = D.blast(TK.perms, TK.sec, true);
    $("tk-perms").innerHTML = D.PERMS.map((p) => `<label><input type="checkbox" data-p="${esc(p)}" ${TK.perms.has(p) ? "checked" : ""}> ${esc(p)}</label>`).join("");
    const y = ["jobs:", "  test:", "    permissions:", "      " + (TK.perms.has("contents: write") ? "contents: write" : "contents: read")];
    D.PERMS.slice(1).forEach((p) => { if (TK.perms.has(p)) y.push("      " + p); });
    y.push("    # deploy secret: " + (TK.sec === "repo" ? "a repository secret" : "an environment secret (reviewer must approve)"));
    $("tk-yaml").textContent = y.join("\n");
    $("tk-out").innerHTML = b.rows.map((r) => row(r.ok ? "bad" : "ok", r.ok ? "✗" : "✓", `${esc(r.text)}: <i>${r.ok ? "yes" : "no"}.</i> ${esc(r.why)}`)).join("");
    verdict("tk-verdict", b.count <= 1 ? "ok" : (b.count >= 5 ? "bad" : "y"), `${b.count} of ${b.rows.length} things a bad step could do${b.count <= 1 ? ": just read the code it was given" : ""}`);
    note("tk-note", TK.perms.size === D.PERMS.length && TK.sec === "repo" ? "# every key on one ring, and the ring is in the test job. That's the setup behind many a headline." : (b.count <= 1 ? "# a bad step here can read what it was handed and nothing more. That's the point." : "# every tick is something a bad step could do. Ask of each: does this job really need it?"));
  }
  function tkInit() {
    $("tk-perms").addEventListener("change", (e) => { const i = e.target.closest("input[data-p]"); if (!i) return; if (i.checked) TK.perms.add(i.dataset.p); else TK.perms.delete(i.dataset.p); tkRender(); });
    segPick("tk-sec", "data-s", (s) => { TK.sec = s; tkRender(); });
    click("tk-min", () => { TK.perms = new Set(); TK.sec = "env"; $("tk-sec").querySelectorAll("button").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.s === "env"))); tkRender(); });
    click("tk-max", () => { TK.perms = new Set(D.PERMS); TK.sec = "repo"; $("tk-sec").querySelectorAll("button").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.s === "repo"))); tkRender(); });
    tkRender();
  }

  // --------------------------------------------------------------------------- pinning
  const PN = { repo: null, ref: "tag", sha: null, moved: false };
  function pnReset() { PN.repo = D.makeActionRepo(); PN.sha = PN.repo.commits[1].id; PN.moved = false; pnRender(); }
  const sh = (id) => id.slice(0, 10) + "…";
  function pnRender() {
    const R = PN.repo;
    const tagsAt = (id) => Object.keys(R.tags).filter((t) => R.tags[t] === id).map((t) => t).concat(R.main === id ? ["main"] : []);
    $("pn-repo").innerHTML = R.commits.map((c) => `${sp("k", sh(c.id))}  ${esc(c.code[0].replace("echo ", ""))}${c.code.length > 4 ? "" : ""}${tagsAt(c.id).length ? "   " + sp("y", "← " + tagsAt(c.id).join(", ")) : ""}`).join("\n");
    const ref = PN.ref === "tag" ? "v1" : (PN.ref === "main" ? "main" : PN.sha);
    const res = D.resolveRef(R, ref);
    let out = `${sp("k", "uses:")} acme/setup-tool@${esc(PN.ref === "sha" ? PN.sha.slice(0, 10) + "…(40 chars)" : ref)}\n${sp("k", "runs commit")} ${esc(sh(res.id))}\n`;
    out += res.commit.code.map((l) => (/example\.invalid/.test(l) ? sp("bad", "  " + l) : "  " + esc(l))).join("\n");
    if (PN.ref === "sha" && R.tags.v1 !== PN.sha) {
      const nw = R.commits.find((c) => c.id === R.tags.v1), added = nw.code.filter((l) => !res.commit.code.includes(l));
      out += `\n\n${sp("k", "A bot proposes a pull request:")} ${esc(sh(PN.sha))} → ${esc(sh(nw.id))}\n` + added.map((l) => (/example\.invalid/.test(l) ? sp("bad", "+ " + l) : sp("ok", "+ " + l))).join("\n");
    }
    $("pn-run").innerHTML = out;
    if (res.bad) verdict("pn-verdict", "bad", "Tonight's build runs code you never reviewed, and it sends your environment away");
    else if (PN.ref !== "sha" && PN.moved) verdict("pn-verdict", "y", "The tag moved, and your build followed it without asking");
    else verdict("pn-verdict", "ok", PN.ref === "sha" ? "Pinned: this commit can't change under you" : "Runs the commit the tag points to today");
    let n = "# try both buttons with the tag selected, then with the hash.";
    if (res.bad) n = "# the tag moved and nobody was paged. This is the shape of the tj-actions incident: the same reference, different code.";
    else if (PN.ref === "sha" && PN.moved) n = "# the hash held. The update arrives as a diff in a pull request, where a person can read it.";
    note("pn-note", n);
  }
  function pnInit() {
    segPick("pn-ref", "data-r", (r) => { PN.ref = r; pnRender(); });
    click("pn-legit", () => { D.moveTag(PN.repo, "v1", 3); PN.moved = true; pnRender(); });
    click("pn-evil", () => { D.moveTag(PN.repo, "v1", 4); PN.repo.main = PN.repo.commits[3].id; PN.moved = true; pnRender(); });
    click("pn-reset", pnReset);
    pnReset();
  }

  // --------------------------------------------------------------------------- untrusted text in a step
  const IN = { kind: "unsafe" };
  function inRender() {
    const title = $("in-title").value, r = D.renderStep(IN.kind, title), st = D.STEPS[IN.kind];
    $("in-yaml").textContent = st.yaml.join("\n");
    $("in-script").innerHTML = (r.env ? sp("k", "env: ") + esc(r.env) + "\n" : "") + esc(r.text).replace(/\n/g, "\n");
    let seenIntended = false;
    $("in-cmds").innerHTML = r.commands.map((c) => {
      const intended = !seenIntended && c.startsWith('echo "New issue:'); if (intended) seenIntended = true;
      return row(intended ? "ok" : "bad", intended ? "✓" : "✗", `<code>${esc(c)}</code> ${intended ? "" : "<i>← not written by the workflow's author</i>"}`);
    }).join("");
    if (r.extra) verdict("in-verdict", "bad", `${r.extra} extra command${r.extra === 1 ? "" : "s"} the shell would run, chosen by whoever typed the title`);
    else verdict("in-verdict", "ok", "One command, as the author intended");
    let n = "# the text of an issue, a branch name or a commit message is written by strangers. Keep it data.";
    if (r.extra && IN.kind === "unsafe") n = "# the quote closed the string early, and the rest became code. Nothing was hacked: the template did a text replacement before the shell ever looked.";
    else if (!r.extra && IN.kind === "safe" && /["$;`]/.test(title)) n = "# same title, but now it's just a long name: the shell reads the variable's value as data and never as commands.";
    note("in-note", n);
  }
  function inInit() {
    segPick("in-kind", "data-k", (k) => { IN.kind = k; inRender(); });
    $("in-title").addEventListener("input", inRender);
    $("in-presets").addEventListener("click", (e) => { const b = e.target.closest("button[data-t]"); if (b) { $("in-title").value = b.dataset.t; inRender(); } });
    inRender();
  }

  // --------------------------------------------------------------------------- signing and the toy log
  const SG = { signer: null, other: null, log: null, ok: null, theirs: null, nolog: null, mode: "ok" };
  const RELEASE_TEXT = "shop-1.4.0.tgz\nbuilt from tag v1.4.0";
  function sgSetup() {
    SG.signer = D.newKey(); SG.other = D.newKey(); SG.log = D.makeLog();
    SG.ok = D.makeRelease(SG.signer, "shop-1.4.0.tgz", RELEASE_TEXT, SG.log, "ci@example.org (workflow)");
    SG.theirs = D.makeRelease(SG.other, "shop-1.4.0.tgz", RELEASE_TEXT, SG.log, "someone-else@example.net");
    const d = D.digestOf(L.utf8(RELEASE_TEXT)), s = D.sign(SG.signer, d);
    SG.nolog = { name: "shop-1.4.0.tgz", bytes: L.utf8(RELEASE_TEXT), digest: d, sig: s };
  }
  function sgRender() {
    let rel = SG.ok, bytes = SG.ok.bytes, mark = -1;
    if (SG.mode === "flip") { bytes = SG.ok.bytes.slice(); mark = bytes.length - 1; bytes[mark] ^= 1; }
    else if (SG.mode === "other") rel = SG.theirs;
    else if (SG.mode === "nolog") rel = SG.nolog;
    const txt = L.text ? L.text(bytes) : String.fromCharCode.apply(null, Array.from(bytes));
    $("sg-file").innerHTML = (mark >= 0 ? esc(txt.slice(0, mark)) + `<mark>${esc(txt.slice(mark))}</mark>` : esc(txt)) + `\n\n${sp("k", "sha256:")} ${esc(D.digestOf(bytes).slice(0, 32))}…\n${sp("k", "signed digest:")} ${esc(rel.digest.slice(0, 32))}…\n${sp("k", "signature:")} ${esc(D.sigHex(rel.sig))}…`;
    $("sg-log").textContent = SG.log.entries.map((e) => `#${e.index} ${e.digest.slice(0, 10)}… sig ${e.sig.slice(0, 8)}… ${e.who}\n   hash ${e.hash.slice(0, 16)}…`).join("\n") + `\nhead ${SG.log.head.slice(0, 16)}…`;
    const v = D.verifyRelease(rel, bytes, SG.signer.Q, SG.log);
    $("sg-checks").innerHTML = v.checks.map((c) => row(c.ok ? "ok" : "bad", c.ok ? "✓" : "✗", esc(c.text))).join("");
    const first = v.checks.find((c) => !c.ok);
    verdict("sg-verdict", v.ok ? "ok" : "bad", v.ok ? "All checks pass: install it" : "Refuse it: " + first.text.toLowerCase() + " failed");
    const msgs = { ok: "# the expected signer, the exact bytes, and a log entry. Each check guards against something different.", flip: "# one bit changed in the last character, and the hash is completely different. The signature still verifies for the original, which is the point.", other: "# the right file, signed by the wrong key. A signature only means something if you know whose key to expect.", nolog: "# a signature nobody can see is a signature whose owner could never notice being misused: that's what the log is for." };
    note("sg-note", msgs[SG.mode]);
  }
  function sgInit() { sgSetup(); segPick("sg-pick", "data-s", (s) => { SG.mode = s; sgRender(); }); sgRender(); }

  // --------------------------------------------------------------------------- provenance
  const PV = { builder: null, other: null, kind: "good" };
  function pvRender() {
    const x = D.provenanceScenario(PV.kind, PV.builder, PV.other), sc = D.SCENARIOS[PV.kind];
    let pretty = x.att.text; try { pretty = JSON.stringify(JSON.parse(x.att.text), null, 1); } catch (e) {}
    $("pv-stmt").textContent = pretty;
    $("pv-policy").textContent = "Policy: built by " + D.EXPECT.builders[0] + " from " + D.EXPECT.repo + " at a tag like v1.2.3";
    $("pv-checks").innerHTML = x.result.checks.map((c) => row(c.ok ? "ok" : "bad", c.ok ? "✓" : "✗", esc(c.text))).join("");
    verdict("pv-verdict", x.result.ok ? "ok" : "bad", x.result.ok ? "Policy satisfied: deploy" : "Policy failed: don't deploy");
    $("pv-why").textContent = sc.note;
    note("pv-note", PV.kind === "merged" ? "# attested is not the same as safe. Provenance tells you where it came from, so reviews, branch protection and tests still have to do their job." : "# try each scenario and read which check catches it.");
  }
  function pvInit() {
    PV.builder = D.newKey(); PV.other = D.newKey();
    $("pv-pick").innerHTML = Object.keys(D.SCENARIOS).map((k, i) => `<button type="button" data-k="${k}" aria-pressed="${i === 0}">${esc(D.SCENARIOS[k].label)}</button>`).join("");
    segPick("pv-pick", "data-k", (k) => { PV.kind = k; pvRender(); });
    pvRender();
  }

  // --------------------------------------------------------------------------- choosing a package
  function chInit() {
    const boxes = Array.from(document.querySelectorAll("#ch-list input[type=checkbox]"));
    const upd = () => {
      const n = boxes.filter((b) => b.checked).length;
      if (!n) { verdict("ch-verdict", "", ""); note("ch-note", "# a conversation starter, not a score: the aim is to ask the questions before the install, not after."); return; }
      verdict("ch-verdict", n >= 7 ? "ok" : (n >= 4 ? "y" : "bad"), `${n} of ${boxes.length}: ${n >= 7 ? "looks like a sound choice" : (n >= 4 ? "worth a closer look at the gaps" : "think hard before adding this")}`);
      note("ch-note", boxes.find((b) => b.dataset.k === "need" && !b.checked) && n >= 4 ? "# the best score is the one you get by not needing the package at all." : "# unticked boxes are the questions to ask the maintainers, or yourselves.");
    };
    boxes.forEach((b) => b.addEventListener("change", upd)); upd();
  }

  // --------------------------------------------------------------------------- review checklist
  const RV_KEY = "deps-ci-review";
  function review() {
    const boxes = Array.from(document.querySelectorAll("#rv-list input[type=checkbox]"));
    let saved = {};
    try { saved = JSON.parse(store(RV_KEY) || "{}"); } catch (e) {}
    boxes.forEach((b) => { b.checked = !!saved[b.dataset.k]; });
    const update = () => {
      const done = boxes.filter((b) => b.checked).length;
      store(RV_KEY, JSON.stringify(Object.fromEntries(boxes.map((b) => [b.dataset.k, b.checked]))));
      const n = $("rv-note"); n.className = "comment";
      if (done === boxes.length) { n.textContent = "# 12 of 12. Now ask a teammate to try to break one of them, kindly, and see which holds."; n.classList.add("ok"); }
      else if (!done) n.textContent = "# tick what your team does today. Each gap is a ticket, not a failure. Saved in this browser only.";
      else n.textContent = `# ${done} of ${boxes.length}. Pick the unticked box that would have shortened your last incident, and fix that first.`;
    };
    boxes.forEach((b) => b.addEventListener("change", update));
    update();
  }

  // --------------------------------------------------------------------------- easter eggs
  let toastTimer = 0;
  function curlEgg() {
    const re = /curl[^\n|]*\|\s*(sudo\s+)?(ba|z)?sh\b/i;
    document.addEventListener("input", (e) => {
      const t = e.target; if (!t || typeof t.value !== "string" || !re.test(t.value)) return;
      let el = $("toast");
      if (!el) { el = document.createElement("div"); el.id = "toast"; el.className = "toast"; el.setAttribute("role", "status"); document.body.appendChild(el); }
      el.innerHTML = "<b>Please don't.</b>Read the script first, pin it by hash, or use the package manager. Piping the internet into a shell is a dependency with no lock file.";
      el.hidden = false; clearTimeout(toastTimer); toastTimer = setTimeout(() => { el.hidden = true; }, 6000);
    });
  }
  function consoleHint() {
    console.log("%cSecuring Dependencies and CI/CD", "font: 700 24px monospace; color: #ff2e88; text-shadow: 0 0 8px #ff2e88");
    console.log("%cThis deck has zero runtime dependencies from the internet. Count them: crypto.js, deck.js, deps.js, app.js, two stylesheets and a few local fonts. Everything else is in your browser.", "font: 14px monospace; color: #00f0ff");
  }

  function start() {
    consoleHint(); curlEgg();
    $("hero-in").addEventListener("input", hero); hero();
    treeInit(); spInit(); lockInit(); upInit(); cfInit(); sbInit(); tkInit(); pnInit(); inInit(); sgInit(); pvInit(); chInit();
    note("hb-note", "# the safest dependency is the one you never added.");
    review();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
})();
