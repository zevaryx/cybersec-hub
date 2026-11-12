/* app.js - the live demos for "Container and Kubernetes Security".
   Every demo is a small simulation in this page: toy images, a toy registry, a toy cluster, and real SHA-256 digests and ECDSA signatures
   from ../../shared/crypto.js. Nothing talks to Docker or Kubernetes, and nothing you type is sent anywhere. */
(function () {
  "use strict";
  const L = window.Lab, C = window.ContainersLab;

  // --------------------------------------------------------------------------- helpers
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
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
  const pressed = (id, attr) => { const b = $(id).querySelector('button[aria-pressed="true"]'); return b ? b.getAttribute(attr) : null; };
  const setPressed = (id, attr, val) => { for (const b of $(id).querySelectorAll("button")) b.setAttribute("aria-pressed", String(b.getAttribute(attr) === val)); };
  const verdict = (id, cls, text) => { const el = $(id); el.className = "verdict " + cls; el.textContent = text; };
  const MARK = { ok: "✓", bad: "✗", y: "!" };

  // --------------------------------------------------------------------------- title: grade a base image
  function hero() {
    const el = $("hero-in"), v = el.value;
    el.style.width = Math.min(34, Math.max(8, v.length + 1)) + "ch";
    const g = C.gradeBase(v);
    $("hero-out").innerHTML = g.lines.map(([lv, tx]) => `<span class="${lv}">${MARK[lv] || "!"} ${esc(tx)}</span>`).join("<br>");
    $("hero-note").textContent = g.egg || (g.kind === "ok" ? "# nothing to flag. Now pin the digest and keep it fresh." : "");
  }

  // --------------------------------------------------------------------------- shared-kernel quiz
  const qz = {};
  function quiz() {
    $("qz-grid").innerHTML = C.ISOLATION.map(([name], i) => `<li class="qz-row" id="qz-${i}"><b>${esc(name)}</b><div class="seg-pick" role="group" aria-label="${esc(name)}"><button type="button" data-i="${i}" data-a="own" aria-pressed="false">Its own</button><button type="button" data-i="${i}" data-a="shared" aria-pressed="false">Shared with the host</button></div><p class="qz-ans"></p></li>`).join("");
    $("qz-grid").addEventListener("click", (e) => {
      const b = e.target.closest("button[data-i]"); if (!b) return;
      const i = +b.dataset.i, shared = C.ISOLATION[i][1], pick = b.dataset.a === "shared", row = $("qz-" + i);
      for (const x of row.querySelectorAll("button")) x.setAttribute("aria-pressed", String(x === b));
      qz[i] = pick === shared;
      row.className = "qz-row " + (qz[i] ? "right" : "wrong");
      row.querySelector(".qz-ans").textContent = (qz[i] ? "✓ " : "✗ ") + C.ISOLATION[i][2];
      const n = Object.keys(qz).length, right = Object.values(qz).filter(Boolean).length;
      $("qz-note").textContent = n < C.ISOLATION.length ? `# ${right} of ${n} right so far.` : right === n ? "# six for six. Shared kernel, separate manners." : `# ${right} of ${n}. The kernel and the hardware are the ones people forget.`;
    });
  }

  // --------------------------------------------------------------------------- base images
  function bases(id) {
    const b = C.BASES.find((x) => x.id === id);
    $("bs-ref").textContent = "FROM " + b.ref;
    const row = (k, v) => `<tr><th>${k}</th><td>${esc(v)}</td></tr>`;
    $("bs-body").innerHTML = row("Size", b.size + " " + b.sizeNote) + row("Shell", b.shell ? "yes" : "no") + row("Package manager", b.pkg) + row("C library", b.libc) + row("Tools already on the box", b.tools);
    $("bs-note").textContent = b.note;
    $("bs-egg").textContent = id === "scratch" ? "# Respect. Minimalism level: monk." : id === "distroless" ? "# no shell to land in: debugging gets harder, and so does attacking." : "";
  }

  // --------------------------------------------------------------------------- tag vs digest
  let reg, pushes;
  const showD = (d) => d.slice(0, 19) + "…";
  function digestRender(msg) {
    const t = C.resolveRef(reg, "tag"), p = C.resolveRef(reg, "digest"), moved = t !== p;
    $("dg-tag").textContent = showD(t); $("dg-pin").textContent = showD(p);
    $("dg-tagbox").className = "dg-box" + (moved ? " moved" : ""); $("dg-pinbox").className = "dg-box" + (moved ? " steady" : "");
    if (!moved) verdict("dg-verdict", "ok", "✓ Both resolve to the same image today");
    else verdict("dg-verdict", "y", "! The tag moved: an unpinned build now gets a different image. The pinned line still builds the original, and isn't getting the new version until someone moves it.");
    $("dg-note").textContent = msg || (pushes >= 3 ? "# a tag is a name badge. A digest is a fingerprint." : "");
  }
  function digestInit() {
    const fresh = () => { reg = C.makeRegistry(); pushes = 0; };
    fresh(); digestRender();
    click("dg-push", () => { C.push(reg, "shop/api:1.4"); pushes++; digestRender(); });
    click("dg-bump", () => { const was = C.resolveRef(reg, "digest") !== C.resolveRef(reg, "tag"); C.bumpPin(reg); digestRender(was ? "# the update arrives as a reviewed change you chose to take, not a surprise in tonight's build." : "# nothing to update: the pin already matches the tag."); });
    click("dg-reset", () => { fresh(); digestRender(); });
  }

  // --------------------------------------------------------------------------- multi-stage
  function multi(mode) {
    $("ms-df").textContent = C.DOCKERFILES[mode].join("\n");
    const items = C.stageContents(mode === "multi");
    $("ms-list").innerHTML = items.map(([n, why, need]) => `<li class="${need ? "need" : "extra"}"><b>${esc(n)}</b><span>${esc(why)}</span></li>`).join("");
    const extra = items.filter((i) => !i[2]).length;
    $("ms-count").className = "ms-count " + (extra ? "bad" : "ok");
    $("ms-count").textContent = `${items.length} things ship · ${extra} not needed to run`;
    $("ms-note").textContent = mode === "multi" ? "# the compiler stayed behind in the build stage." : "";
  }

  // --------------------------------------------------------------------------- what can code that got in do
  function intruder() {
    const o = { user: pressed("nr-user", "data-v"), ro: pressed("nr-fs", "data-v") === "ro", caps: pressed("nr-caps", "data-v"), nnp: pressed("nr-nnp", "data-v") === "block" };
    const rows = C.intruder(o), n = rows.filter((r) => r[1]).length;
    $("nr-cfg").textContent = ["USER " + (o.user === "root" ? "root   # no USER line" : "10001"), "readOnlyRootFilesystem: " + o.ro, "capabilities: " + (o.caps === "none" ? "drop ALL" : "runtime default"), "allowPrivilegeEscalation: " + !o.nnp].join("\n");
    $("in-body").innerHTML = rows.map(([act, allowed, why]) => `<tr><td><b class="${allowed ? "bad" : "ok"}">${allowed ? "✗ possible" : "✓ blocked"}</b><br>${esc(act)}</td><td class="why">${esc(why)}</td></tr>`).join("");
    verdict("in-verdict", n === 0 ? "ok" : n <= 2 ? "y" : "bad", `${n} of ${rows.length} things still possible`);
    $("in-note").textContent = n === 0 ? "# not nothing, but a very dull afternoon for an attacker." : "";
  }

  // --------------------------------------------------------------------------- layer explorer
  let lyMode = "rm", lyLayers = [], lyOpen = -1;
  function layers(mode) {
    lyMode = mode; lyLayers = C.layersFor(mode); lyOpen = -1;
    $("ly-stack").innerHTML = lyLayers.slice().reverse().map((l) => `<li><button type="button" data-n="${l.n}" aria-pressed="false" class="${l.secrets ? "has-secret" : ""}"><small>LAYER ${l.n}${l.secrets ? " · contains a secret" : ""}</small><code>${esc(l.cmd)}</code></button></li>`).join("");
    $("ly-title").textContent = "Pick a layer"; $("ly-pane").textContent = "";
    const found = C.secretInLayers(lyLayers);
    if (found.length) verdict("ly-verdict", "bad", `✗ Anyone who pulls the image can read the key from layer ${found[0].n}, even though the running container can't see it`);
    else verdict("ly-verdict", "ok", "✓ No layer in the shipped image contains the key");
    $("ly-note").textContent = mode === "rm" ? "# rm in a later layer is a curtain, not a wall." : mode === "mount" ? "# the secret was a guest: it left when the instruction ended." : "# the build stage's layers never ship. Clear your build caches, and still revoke.";
  }
  function layerOpen(n) {
    const l = lyLayers.find((x) => x.n === n); lyOpen = n;
    for (const b of $("ly-stack").querySelectorAll("button")) b.setAttribute("aria-pressed", String(+b.dataset.n === n));
    $("ly-title").textContent = `Layer ${l.n}: tar entries`;
    const ent = C.layerEntries(l);
    $("ly-pane").innerHTML = ent.length ? ent.map((e) => {
      if (e.kind === "whiteout") return `<span class="y">${esc(e.path)}</span>   <span class="m"># whiteout: hides ${esc(e.hides)} in the layers below. The bytes are not touched.</span>`;
      const sec = l.secrets && l.secrets[e.path];
      return `<span class="ok">+ ${esc(e.path)}</span>` + (sec ? `\n    ${esc(e.path)} contains: <mark class="bad">${esc(sec)}</mark>` : "");
    }).join("\n") : '<span class="m"># this layer adds no files (it only sets metadata)</span>';
  }
  function layersUnion() {
    $("ly-title").textContent = "What a running container sees (all layers merged)";
    $("ly-pane").innerHTML = C.unionView(lyLayers).map((p) => `<span class="ok">${esc(p)}</span>`).join("\n") + (lyMode === "rm" ? '\n\n<span class="m"># app/.env is not listed: the whiteout in layer 4 hides it.\n# Layer 2 still holds the file. Open it to see.</span>' : "");
    for (const b of $("ly-stack").querySelectorAll("button")) b.setAttribute("aria-pressed", "false");
  }

  // --------------------------------------------------------------------------- Dockerfile grader
  function grader() {
    const g = C.gradeDockerfile($("gr-in").value);
    $("gr-list").innerHTML = g.findings.map((f) => `<li class="${f.level}"><b>${MARK[f.level]}</b><span>${f.line ? `<i>line ${f.line}</i>` : ""}${esc(f.title)}</span><span class="why">${esc(f.why)}</span></li>`).join("");
    const n = (lv) => g.findings.filter((f) => f.level === lv).length;
    $("gr-tally").textContent = `${n("bad")} problems · ${n("y")} to improve · ${n("ok")} good`;
    $("gr-tally").className = "gr-tally " + (n("bad") ? "bad" : n("y") ? "y" : "ok");
    const notes = [];
    if (g.eggs.includes("scratch")) notes.push("# Respect. Minimalism level: monk.");
    if (g.eggs.includes("777")) notes.push("# 777: the number of the beast's permissions.");
    if (!notes.length && g.findings.length && !n("bad") && !n("y")) notes.push("# all green. Now go and grade the real one.");
    $("gr-note").textContent = notes.join("  ");
  }

  // --------------------------------------------------------------------------- scan triage
  function triage() {
    const f = { finalOnly: $("tr-final").checked, fixable: $("tr-fix").checked, highUp: $("tr-high").checked, rebuilt: $("tr-rebuilt").checked };
    const rows = C.triage(f), all = C.FINDINGS.length;
    $("tr-body").innerHTML = rows.map((x) => `<tr><td>${x.id}</td><td>${esc(x.pkg)}</td><td class="sev-${x.sev}">${C.SEV[x.sev]}</td><td>${x.where === "final" ? "final image" : "build stage"}</td><td>${x.fix ? "yes" : "no"}</td></tr>`).join("") || `<tr><td colspan="5" class="m">Nothing left on the list.</td></tr>`;
    $("tr-count").textContent = `${rows.length} of ${all} findings on the to-do list`;
    $("tr-note").textContent = f.finalOnly && f.fixable && f.highUp && f.rebuilt ? "# ten findings became a list short enough to finish this afternoon. Then schedule the rebuild." : "";
  }

  // --------------------------------------------------------------------------- signing and admission
  let fleet;
  function admission() {
    const pol = { registry: $("ad-reg").checked, digest: $("ad-dig").checked, signature: $("ad-sig").checked };
    let ok = 0;
    $("ad-pods").innerHTML = fleet.pods.map((p) => {
      const r = C.admit(fleet, p, pol); if (r.admit) ok++;
      const ref = p.ref.replace(/(@sha256:[0-9a-f]{8})[0-9a-f]+/, "$1…");
      const why = r.checks.length ? r.checks.map(([k, t]) => (k ? "✓ " : "✗ ") + t).join("\n") : "(no rules switched on)";
      return `<li class="${r.admit ? "yes" : "no"}"><b>${esc(p.label)}</b><code>${esc(ref)}</code><span>${esc(why).replace(/\n/g, "<br>")}</span><em>${r.admit ? "ADMITTED" : "DENIED"}</em></li>`;
    }).join("");
    $("ad-tally").textContent = `${ok} of ${fleet.pods.length} pods admitted`;
    const all = pol.registry && pol.digest && pol.signature;
    $("ad-note").textContent = !pol.registry && !pol.digest && !pol.signature ? "# with no rules, the stranger's image runs too." : all ? "# only the image CI built, signed and pinned gets in. The signature says who built it, not that it's free of bugs." : pol.signature && !pol.digest ? "# the tag-referenced image passes: its signature is valid for the digest it resolves to. Pin it anyway." : pol.registry && !pol.signature ? "# a registry rule alone lets a laptop build and a tampered image through." : "";
  }

  // --------------------------------------------------------------------------- settings that end isolation
  const thSeen = new Set();
  function thin() {
    $("th-grid").innerHTML = C.THIN.map(([t], i) => `<li><button type="button" data-i="${i}" aria-pressed="false"><small>0${i + 1}</small><b>${esc(t)}</b></button></li>`).join("");
    $("th-grid").addEventListener("click", (e) => {
      const b = e.target.closest("button[data-i]"); if (!b) return;
      const i = +b.dataset.i, [t, gives, safer] = C.THIN[i]; thSeen.add(i);
      for (const x of $("th-grid").querySelectorAll("button")) { x.setAttribute("aria-pressed", String(x === b)); if (thSeen.has(+x.dataset.i)) x.classList.add("seen"); }
      $("th-detail").innerHTML = `<b>${esc(t)}</b><span><i>What it hands over</i>${esc(gives)}</span><span><i>Instead</i>${esc(safer)}</span>`;
      $("th-count").textContent = `${thSeen.size} of ${C.THIN.length} opened`;
      $("th-note").textContent = thSeen.size === C.THIN.length ? "# six switches, and each began as someone solving a small problem." : "";
    });
  }

  // --------------------------------------------------------------------------- security context builder
  let pss = Object.assign({}, C.PSS_START);
  const PC = { priv: "privileged", hostnet: "hostNetwork", hostpid: "hostPID", hostpath: "hostPath", nonroot: "runAsNonRoot", ro: "ro" };
  function pcSync() {
    for (const [id, k] of Object.entries(PC)) $("pc-" + id).checked = !!pss[k];
    $("pc-uid").value = pss.runAsUser; $("pc-ape").value = pss.allowPE; $("pc-seccomp").value = pss.seccomp; $("pc-drop").value = pss.drop; $("pc-add").value = pss.add;
  }
  function pcRender() {
    const r = C.podSecurity(pss);
    $("pc-yaml").textContent = C.podYaml(pss);
    const lv = $("pc-level"); lv.className = "pc-level " + r.level;
    lv.textContent = r.level === "restricted" ? "Meets: restricted" : r.level === "baseline" ? "Meets: baseline, but not restricted" : "Meets only: privileged (fails baseline)";
    const items = r.baseline.map((t) => `<li class="bad"><b>✗</b><span><i>baseline</i>${esc(t)}</span></li>`).concat(r.restricted.map((t) => `<li class="y"><b>!</b><span><i>restricted</i>${esc(t)}</span></li>`));
    $("pc-why").innerHTML = items.join("") || `<li class="ok"><b>✓</b><span>passes every check this demo models</span></li>`;
    $("pc-note").textContent = r.level === "restricted" ? "# a handful of lines, and a lot of ways in just closed." : pss.privileged ? "# privileged: true. The \"I'll tighten it later\" of container settings." : "";
  }
  function pcInit() {
    pcSync(); pcRender();
    const read = () => { for (const [id, k] of Object.entries(PC)) pss[k] = $("pc-" + id).checked; pss.runAsUser = $("pc-uid").value; pss.allowPE = $("pc-ape").value; pss.seccomp = $("pc-seccomp").value; pss.drop = $("pc-drop").value; pss.add = $("pc-add").value; pcRender(); };
    $("pc-form").addEventListener("change", read);
    click("pc-reset", () => { pss = Object.assign({}, C.PSS_START); pcSync(); pcRender(); });
    click("pc-fix", () => { pss = Object.assign({}, C.PSS_RESTRICTED); pcSync(); pcRender(); });
  }

  // --------------------------------------------------------------------------- memory limits
  function leakRender(sim) {
    const bar = $("lm-bar");
    if (!sim) { bar.innerHTML = `<i class="lm-others" style="width:62.5%"></i>`; $("lm-log").textContent = "# press Run. Node: 8 GiB. Four healthy pods: 5 GiB."; verdict("lm-verdict", "", ""); $("lm-note").textContent = ""; return; }
    const last = sim.steps[sim.steps.length - 1], total = last.total, scale = Math.max(sim.node, total);
    const free = sim.node - sim.others, w = last.worker, over = Math.max(0, total - sim.node);
    bar.innerHTML = `<i class="lm-others" style="width:${sim.others / scale * 100}%"></i><i class="lm-worker" style="width:${Math.min(w, free) / scale * 100}%"></i>` + (over ? `<i class="lm-over" style="width:${over / scale * 100}%"></i>` : "");
    $("lm-log").textContent = sim.steps.map((s) => `step ${String(s.t).padStart(2)}  worker ${s.worker.toFixed(1)} GiB   node ${s.total.toFixed(1)} of ${sim.node} GiB` + (s.event ? "   << " + s.event : "")).join("\n");
    verdict("lm-verdict", sim.outcome === "limit" ? "ok" : "bad", sim.outcome === "limit" ? "✓ Only the leaky worker is killed. Its neighbours never notice." : "✗ The node ran out of memory. " + sim.victims);
  }
  function limits() {
    leakRender(null);
    click("lm-run", () => {
      const lim = +pressed("lm-pick", "data-l"), sim = C.leak(lim); leakRender(sim);
      $("lm-note").textContent = lim === 0 ? "# with no limit, somebody's neighbour is about to have a very bad afternoon." : sim.outcome === "node" ? "# a limit bigger than the free space is a polite suggestion." : "";
    });
    segPick("lm-pick", "data-l", () => leakRender(null));
  }

  // --------------------------------------------------------------------------- blast radius
  function blast() {
    const o = { net: pressed("bl-net", "data-v"), sa: pressed("bl-sa", "data-v"), pod: pressed("bl-pod", "data-v") };
    const rows = C.blast(o), n = rows.filter((r) => r[1]).length;
    $("bl-list").innerHTML = rows.map(([t, reach, why]) => `<li class="${reach ? "reach" : "safe"}"><b>${reach ? "REACHABLE" : "BLOCKED"}</b><span>${esc(t)}</span><em>${esc(why)}</em></li>`).join("");
    $("bl-tally").className = "bl-tally " + (n >= 5 ? "bad" : n >= 2 ? "y" : "ok");
    $("bl-tally").textContent = `${n} of ${rows.length} targets reachable`;
    $("bl-note").textContent = o.net === "deny" && o.sa === "none" && o.pod === "restricted" ? "# one reachable target, and it's the one it was meant to talk to. A very boring compromise." : "";
  }

  // --------------------------------------------------------------------------- Kubernetes Secrets
  function ksRender() {
    const v = $("ks-in").value, enc = C.b64(v);
    $("ks-b64").textContent = enc || "(empty)"; $("ks-back").textContent = C.unb64(enc) === null ? "?" : C.unb64(enc) || "(empty)";
    const rows = C.secretReaders({ enc: pressed("ks-enc", "data-v") === "on", rbac: pressed("ks-rbac", "data-v"), create: pressed("ks-create", "data-v") }), n = rows.filter((r) => r[1]).length;
    $("ks-list").innerHTML = rows.map(([t, can, why]) => `<li class="${can ? "reach" : "safe"}"><b>${can ? "CAN READ" : "CAN'T"}</b><span>${esc(t)}</span><em>${esc(why)}</em></li>`).join("");
    $("ks-tally").className = "bl-tally " + (n >= 5 ? "bad" : n >= 3 ? "y" : "ok");
    $("ks-tally").textContent = `${n} of ${rows.length} ways in`;
    const t = v.trim().toLowerCase();
    $("ks-note").textContent = t === "hunter2" ? "# hunter2: everyone else sees *******. Base64 shows aHVudGVyMg==, which is no better." : v === "" ? "# an empty secret is the safest kind, and the least useful." : pressed("ks-enc", "data-v") === "on" && pressed("ks-rbac", "data-v") === "broad" ? "# encryption at rest closed one row. The API rows are about who you authorise." : pressed("ks-enc", "data-v") === "on" && pressed("ks-rbac", "data-v") === "least" && pressed("ks-create", "data-v") === "few" ? "# the rows left are about process: who is authorised, and what gets committed." : "";
  }
  function ksInit() {
    $("ks-in").addEventListener("input", ksRender);
    for (const id of ["ks-enc", "ks-rbac", "ks-create"]) segPick(id, "data-v", ksRender);
    ksRender();
  }

  // --------------------------------------------------------------------------- spot the problems
  const spSel = new Set(); let spChecked = false;
  function spRender() {
    $("sp-lines").innerHTML = C.MANIFEST.map(([t, id], i) => {
      let cls = spSel.has(i) ? "" : "";
      if (spChecked) cls = id && spSel.has(i) ? "hit" : id ? "miss" : spSel.has(i) ? "false" : "";
      return `<li><button type="button" data-i="${i}" class="${cls}" aria-pressed="${spSel.has(i)}">${esc(t)}</button></li>`;
    }).join("");
  }
  function spInit() {
    spRender();
    $("sp-lines").addEventListener("click", (e) => {
      const b = e.target.closest("button[data-i]"); if (!b) return;
      const i = +b.dataset.i; spSel.has(i) ? spSel.delete(i) : spSel.add(i); spChecked = false; $("sp-why").innerHTML = ""; verdict("sp-verdict", "", ""); $("sp-note").textContent = ""; spRender();
    });
    click("sp-check", () => {
      spChecked = true; spRender();
      const risks = C.MANIFEST.map((m, i) => [m, i]).filter(([m]) => m[1]);
      const hits = risks.filter(([, i]) => spSel.has(i)).length, falses = Array.from(spSel).filter((i) => !C.MANIFEST[i][1]).length;
      verdict("sp-verdict", hits === risks.length && !falses ? "ok" : hits >= risks.length - 2 ? "y" : "bad", `Found ${hits} of ${risks.length} problem lines` + (falses ? ` · ${falses} false alarm${falses > 1 ? "s" : ""}` : ""));
      $("sp-why").innerHTML = risks.map(([m, i]) => `<li><code>${esc(m[0].trim())}</code>${spSel.has(i) ? "✓ " : "✗ missed: "}${esc(m[2])}</li>`).join("");
      $("sp-note").textContent = hits === risks.length && !falses ? "# nine for nine. You'd have caught it in review." : "";
    });
    click("sp-reset", () => { spSel.clear(); spChecked = false; $("sp-why").innerHTML = ""; verdict("sp-verdict", "", ""); $("sp-note").textContent = ""; spRender(); });
  }

  // --------------------------------------------------------------------------- checklist
  const RV_KEY = "containers-checklist";
  function review() {
    const boxes = Array.from(document.querySelectorAll("#rv-list input[type=checkbox]"));
    let saved = {};
    try { saved = JSON.parse(store(RV_KEY) || "{}"); } catch (e) {}
    boxes.forEach((b) => { b.checked = !!saved[b.dataset.k]; });
    const update = () => {
      const done = boxes.filter((b) => b.checked).length;
      store(RV_KEY, JSON.stringify(Object.fromEntries(boxes.map((b) => [b.dataset.k, b.checked]))));
      const n = $("rv-note"); n.className = "comment";
      if (done === boxes.length) { n.textContent = "# 12 of 12. Now go and run the grader on a real Dockerfile, just to be sure."; n.classList.add("ok"); }
      else if (!done) n.textContent = "# tick what your team does today. Each gap is a ticket, not a failure. Saved in this browser only.";
      else n.textContent = `# ${done} of ${boxes.length}. Pick the unticked box that would have shortened your last incident, and fix that first.`;
    };
    boxes.forEach((b) => b.addEventListener("change", update));
    update();
  }

  // --------------------------------------------------------------------------- easter egg: console
  function consoleHint() {
    console.log("%cContainer and Kubernetes Security", "font: 700 24px monospace; color: #ff2e88; text-shadow: 0 0 8px #ff2e88");
    console.log("%cIt works on my machine. Ship the machine. (Then give the machine fewer rights.) Try FROM scratch in the grader.", "font: 14px monospace; color: #00f0ff");
  }

  function start() {
    consoleHint();
    $("hero-in").addEventListener("input", hero); hero();
    quiz();
    segPick("bs-pick", "data-b", bases); bases("debian");
    digestInit();
    segPick("ms-pick", "data-m", multi); multi("single");
    for (const id of ["nr-user", "nr-fs", "nr-caps", "nr-nnp"]) segPick(id, "data-v", intruder);
    intruder();
    segPick("ly-pick", "data-m", layers); layers("rm");
    $("ly-stack").addEventListener("click", (e) => { const b = e.target.closest("button[data-n]"); if (b) layerOpen(+b.dataset.n); });
    click("ly-union", layersUnion);
    $("gr-in").value = C.DF_PRESETS.bad; grader();
    $("gr-in").addEventListener("input", grader);
    segPick("gr-pick", "data-p", (p) => { $("gr-in").value = C.DF_PRESETS[p]; grader(); });
    for (const id of ["tr-final", "tr-fix", "tr-high", "tr-rebuilt"]) $(id).addEventListener("change", triage);
    triage();
    fleet = C.makeFleet();
    for (const id of ["ad-reg", "ad-dig", "ad-sig"]) $(id).addEventListener("change", admission);
    admission();
    thin();
    pcInit();
    limits();
    for (const id of ["bl-net", "bl-sa", "bl-pod"]) segPick(id, "data-v", blast);
    blast();
    ksInit();
    spInit();
    review();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
})();
