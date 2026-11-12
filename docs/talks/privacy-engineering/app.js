/* app.js - the live demos for "Privacy Engineering", built on the models in privacy.js.
   Every person, record, log line and "database" is invented, and nothing is fetched or sent anywhere. */
(function () {
  "use strict";
  const P = window.PrivLab;

  const $ = (id) => document.getElementById(id);
  const esc = P.escapeHtml;
  function store(key, val) {
    try { if (val === undefined) return localStorage.getItem(key); localStorage.setItem(key, val); } catch (e) {}
    return null;
  }
  const verdict = (id, cls, text) => { const el = $(id); el.className = "verdict" + (cls ? " " + cls : ""); el.textContent = text; };
  const note = (id, text, cls) => { const el = $(id); el.className = "comment" + (cls ? " " + cls : ""); el.textContent = text; };
  const plural = (n, one, many) => n + " " + (n === 1 ? one : many);
  const stat = (b, span, cls) => `<div class="stat ${cls || ""}"><b>${b}</b><span>${span}</span></div>`;
  const pickInto = (id, attr, val) => { for (const b of $(id).querySelectorAll("button")) b.setAttribute("aria-pressed", String(b.getAttribute(attr) === String(val))); };
  const egg = new Set();

  // --------------------------------------------------------------------------- title: personal-data spotter
  function hero() {
    const r = P.spot($("hero-in").value);
    const out = $("hero-out");
    if (!r.found.length) { out.className = "hashout ok"; out.textContent = "✓ no personal data found (patterns only: it can miss things)"; }
    else {
      out.className = "hashout " + (r.sensitive ? "bad" : "y");
      out.textContent = r.found.map((f) => "• " + f.kind + (f.sensitive ? " (sensitive)" : "") + ": " + f.text).join("\n");
      out.style.whiteSpace = "pre-wrap";
    }
    note("hero-note", "# " + (r.egg || "a handful of patterns, so expect misses and false alarms. Real data is messier."));
  }

  // --------------------------------------------------------------------------- re-identification
  const RD_PRESETS = { full: { zip: 0, birth: 0, gender: true }, some: { zip: 1, birth: 3, gender: true }, k5: { zip: 2, birth: 3, gender: false } };
  function reid() {
    const zip = $("rd-zip"), birth = $("rd-birth"), gender = $("rd-gender");
    const cfg = () => ({ zip: +zip.value, birth: +birth.value, gender: gender.checked });
    function render() {
      const c = cfg(), a = P.anonymity(c);
      $("rd-zip-out").textContent = P.ZIP_LEVELS[c.zip];
      $("rd-birth-out").textContent = P.BIRTH_LEVELS[c.birth];
      $("rd-stats").innerHTML = stat(a.unique + " / " + a.total, "people unique in the release", a.unique ? "fast" : "slow") + stat("k = " + a.k, "smallest group") + stat(a.homogeneous, "in groups sharing one diagnosis");
      // sample of the release: first 6 people
      const rows = P.PEOPLE.slice(0, 6).map((p) => `<tr><td>${esc(P.genZip(p.zip, c.zip))}</td><td>${esc(P.genBirth(p, c.birth))}</td><td>${c.gender ? p.gender : "*"}</td><td>${esc(p.dx)}</td></tr>`).join("");
      $("rd-table").innerHTML = `<thead><tr><th>ZIP</th><th>Born</th><th>Gender</th><th>Diagnosis</th></tr></thead><tbody>${rows}</tbody>`;
      if (c.zip === 3 && c.birth === 4 && !c.gender) { note("rd-note", "# Everyone is identical. A perfectly private dataset, and perfectly useless: there's nothing left to study.", "y"); egg.add("all"); }
      else if (a.k >= 5) note("rd-note", `# k = ${a.k}: every record hides among at least ${a.k - 1} others. Now check what you can still learn from it, and whether groups share one diagnosis.`, "ok");
      else if (a.unique) note("rd-note", `# ${a.unique} of ${a.total} people are still unique. Blurring one field at a time barely helps: it's the combination that identifies.`);
      else note("rd-note", `# nobody is unique, but the smallest group has ${a.k} people. Groups that share one diagnosis still leak it.`);
      lookup();
    }
    function lookup() {
      const r = P.lookup($("rd-name").value, cfg());
      const el = $("rd-result");
      if (r.status === "empty") return verdict("rd-result", "", "");
      if (r.status === "egg") return verdict("rd-result", "ok", r.message);
      if (r.status === "unknown") return verdict("rd-result", "y", "Not in the register. Try one of the names listed above.");
      if (r.learned) return verdict("rd-result", "bad", `${r.person.name}: ${plural(r.matches, "record matches", "records match")}. The release says: ${r.learned}.`);
      verdict("rd-result", "ok", `${r.person.name}: ${r.matches} records match, with ${r.diagnoses.length} different diagnoses. Not certain.`);
    }
    for (const el of [zip, birth, gender]) el.addEventListener("input", render);
    $("rd-go").addEventListener("click", lookup);
    $("rd-name").addEventListener("input", lookup);
    $("rd-name").addEventListener("keydown", (e) => { if (e.key === "Enter") lookup(); });
    $("rd-presets").addEventListener("click", (e) => {
      const b = e.target.closest("button[data-p]"); if (!b) return;
      const p = RD_PRESETS[b.dataset.p]; zip.value = p.zip; birth.value = p.birth; gender.checked = p.gender; render();
    });
    render();
  }

  // --------------------------------------------------------------------------- minimisation
  function minimise() {
    const keep = new Set(P.FIELDS.map((f) => f.k));
    $("mn-list").innerHTML = P.FIELDS.map((f) => `<label class="mn-row"><input type="checkbox" data-k="${f.k}" checked><span><b>${esc(f.label)}</b><small>${esc(f.purpose)} · owner: ${esc(f.owner)}</small></span></label>`).join("");
    const boxes = Array.from($("mn-list").querySelectorAll("input"));
    function render() {
      keep.clear(); boxes.forEach((b) => { if (b.checked) keep.add(b.dataset.k); });
      const r = P.minimiseReport(keep);
      $("mn-stats").innerHTML = stat(r.count + " / " + P.FIELDS.length, "fields collected") + stat(r.risk + " / " + r.maxRisk, "harm if it leaks", r.risk > r.maxRisk / 2 ? "fast" : "slow") + stat(r.orphans.length, "with no owner", r.orphans.length ? "fast" : "slow");
      if (r.verdict === "min") { verdict("mn-verdict", "ok", "Minimalist unlocked. The best database is no database."); note("mn-note", "# no fields, no breach, no product. The goal isn't zero: it's every field earning its place."); egg.add("min"); }
      else if (r.verdict === "broken") { verdict("mn-verdict", "bad", "Delivery breaks: you dropped " + r.broken.join(", ") + "."); note("mn-note", "# that's a real purpose, so keep it, and keep it deletable."); }
      else if (r.verdict === "lean") { verdict("mn-verdict", "ok", "Lean: only what the delivery needs. The phone number can be asked at the order, if the courier ever needs it."); note("mn-note", "# fewer fields: less to protect, less to lose, less to delete."); }
      else { verdict("mn-verdict", "y", `${plural(r.unneeded, "field isn't", "fields aren't")} needed for delivery.` + (r.orphans.length ? ` ${r.orphans.join(", ")} ${r.orphans.length === 1 ? "has" : "have"} no owner.` : "")); note("mn-note", "# for each extra field ask: what is it for, who owns it, how does it get deleted?"); }
    }
    boxes.forEach((b) => b.addEventListener("change", render));
    $("mn-presets").addEventListener("click", (e) => {
      const b = e.target.closest("button[data-p]"); if (!b) return;
      boxes.forEach((x) => { x.checked = b.dataset.p === "all" || P.FIELDS.find((f) => f.k === x.dataset.k).needed; }); render();
    });
    render();
  }

  // --------------------------------------------------------------------------- purpose limitation
  function purpose() {
    let cur = "delivery";
    $("pu-purpose").innerHTML = P.PURPOSES.map((p) => `<button type="button" data-p="${p}" aria-pressed="${p === cur}">${p}</button>`).join("");
    function render() {
      pickInto("pu-purpose", "data-p", cur);
      const res = P.access(cur, { marketing: $("pu-marketing").checked, analytics: $("pu-analytics").checked });
      $("pu-list").innerHTML = res.map((r) => `<li class="${r.ok ? "ok" : "no"}"><b>${r.ok ? "ALLOW" : "DENY"}</b><span>${esc(r.label)}</span><small>${esc(r.why)}</small></li>`).join("");
      const allowed = res.filter((r) => r.ok).length;
      note("pu-note", allowed === res.length ? "# all five fields allowed for this purpose" : allowed === 0 ? `# the "${cur}" service gets nothing: it never had a reason to see any of this` : `# ${allowed} of ${res.length} fields allowed for "${cur}". The rest stay closed until there's a purpose, or a consent.`);
    }
    $("pu-purpose").addEventListener("click", (e) => { const b = e.target.closest("button[data-p]"); if (!b) return; cur = b.dataset.p; render(); });
    $("pu-marketing").addEventListener("change", render); $("pu-analytics").addEventListener("change", render);
    render();
  }

  // --------------------------------------------------------------------------- data map
  function datamap() {
    let cur = "email";
    $("dm-fields").innerHTML = P.MAP_FIELDS.map(([k, l]) => `<button type="button" data-f="${k}" aria-pressed="${k === cur}">${l}</button>`).join("");
    function render() {
      pickInto("dm-fields", "data-f", cur);
      const w = P.whereIs(cur);
      $("dm-list").innerHTML = P.STORES.map((s) => {
        const on = s.holds.includes(cur);
        const ret = s.retention ? s.retention + " days" : "no expiry";
        return `<li class="${on ? "on" : "off"}"><b>${esc(s.label)}</b><span>${on ? "holds it" : "—"}</span><small>${esc(s.owner)} · ${ret}</small></li>`;
      }).join("");
      $("dm-stats").innerHTML = stat(w.count + " / " + w.total, "places hold it", w.count > 4 ? "fast" : "") + stat(w.noOwner, "with no owner", w.noOwner ? "fast" : "slow") + stat(w.noExpiry, "with no expiry", w.noExpiry ? "fast" : "slow");
      note("dm-note", `# ${P.MAP_FIELDS.find((f) => f[0] === cur)[1].toLowerCase()} lives in ${w.count} of ${w.total} stores. The ones nobody owns are the logs and the vendors' tools.`);
    }
    $("dm-fields").addEventListener("click", (e) => { const b = e.target.closest("button[data-f]"); if (!b) return; cur = b.dataset.f; render(); });
    render();
  }

  // --------------------------------------------------------------------------- envelope encryption and crypto-shredding
  async function shred() {
    if (!window.crypto || !crypto.subtle) { $("sh-table").innerHTML = "<tr><td>This demo needs the Web Crypto API (a secure page).</td></tr>"; return; }
    let vault, backupHasKeys = false, hasBackup = false, shredded = false, restored = null;
    const users = [["u1", "Dana Wren", "dana.wren@example.com"], ["u2", "Sam Lee", "sam.lee@example.com"], ["u3", "Noor Ali", "noor.ali@example.com"]];
    async function init() {
      vault = await P.makeVault(); backupHasKeys = false; hasBackup = false; shredded = false; restored = null;
      for (const [id, , email] of users) await vault.enroll(id, email);
      verdict("sh-verdict", "", ""); note("sh-note", "# three customers, three data keys, one master key. Take a backup, then delete Dana's key.");
      await render();
    }
    async function render() {
      const rows = [];
      for (const [id, name] of users) {
        const live = await vault.read(id);
        const bk = hasBackup ? await vault.read(id, vault.backup) : null;
        const key = vault.keys.has(id);
        rows.push(`<tr><td>${esc(name)}</td><td class="mono-s">${esc(vault.ciphertextPreview(id))}</td><td>${key ? "yes" : "<b class='bad'>deleted</b>"}</td><td class="${live.ok ? "ok" : "bad"}">${live.ok ? esc(live.text) : esc(live.why)}</td><td>${hasBackup ? (bk.ok ? "<span class='bad'>readable</span>" : "<span class='ok'>noise</span>") : "-"}</td></tr>`);
      }
      $("sh-table").innerHTML = `<thead><tr><th>Customer</th><th>Stored (ciphertext)</th><th>Data key</th><th>Live read</th><th>Backup copy</th></tr></thead><tbody>${rows.join("")}</tbody>`;
    }
    $("sh-backup-keys").addEventListener("click", async () => { vault.snapshot(true); hasBackup = true; backupHasKeys = true; restored = null; note("sh-note", "# a backup that includes the wrapped keys: convenient, and a deletion problem."); await render(); });
    $("sh-backup-nokeys").addEventListener("click", async () => { vault.snapshot(false); hasBackup = true; backupHasKeys = false; restored = null; note("sh-note", "# a ciphertext-only backup: the keys live in the key service, with their own lifecycle."); await render(); });
    $("sh-shred").addEventListener("click", async () => {
      vault.shred("u1"); shredded = true;
      verdict("sh-verdict", "ok", "Dana's key is gone. Her row is unreadable in the live database" + (hasBackup && !backupHasKeys ? " and in the backup." : hasBackup ? ", but the backup also holds the key." : "."));
      note("sh-note", "# ciphertext without its key is just noise: nothing else had to be hunted down."); await render();
    });
    $("sh-restore").addEventListener("click", async () => {
      if (!hasBackup) return verdict("sh-verdict", "y", "Take a backup first.");
      if (backupHasKeys) { for (const [k, v] of vault.backup.keys) vault.keys.set(k, v); }
      for (const [k, v] of vault.backup.rows) vault.rows.set(k, v);
      const dana = await vault.read("u1");
      if (dana.ok && shredded) { verdict("sh-verdict", "bad", "Restored. Dana is back, because the backup kept her key."); note("sh-note", "# the key was in the backup. The data came with it.", "y"); egg.add("restore"); }
      else if (!dana.ok && shredded) verdict("sh-verdict", "ok", "Restored. Dana's row is back but unreadable: the key stayed deleted.");
      else verdict("sh-verdict", "", "Restored. Nothing was shredded yet, so nothing changed.");
      await render();
    });
    $("sh-reset").addEventListener("click", init);
    await init();
  }

  // --------------------------------------------------------------------------- pseudonyms
  function pseudo() {
    const KEY = "pseudonym-key-" + Math.random().toString(36).slice(2, 10);
    let attacked = false, leaked = false;
    function render() {
      const r = P.reverseAttack(P.TABLE_EMAILS, attacked ? P.CANDIDATES : [], KEY, leaked);
      const rows = P.TABLE_EMAILS.map((e, i) => {
        const pm = attacked && r.plainHits && P.CANDIDATES.map(P.normaliseEmail).includes(P.normaliseEmail(e));
        const km = attacked && leaked && P.CANDIDATES.map(P.normaliseEmail).includes(P.normaliseEmail(e));
        return `<tr><td class="mono-s">${r.plainTable[i].slice(0, 16)}…</td><td class="${pm ? "bad" : ""}">${pm ? esc(e) : "?"}</td><td class="mono-s">${r.keyedTable[i].slice(0, 16)}…</td><td class="${km ? "bad" : ""}">${km ? esc(e) : "?"}</td></tr>`;
      }).join("");
      $("ps-table").innerHTML = `<thead><tr><th>SHA-256(email)</th><th>Cracked?</th><th>HMAC-SHA-256(key, email)</th><th>Cracked?</th></tr></thead><tbody>${rows}</tbody>`;
      if (!attacked) verdict("ps-verdict", "", "");
      else if (leaked) verdict("ps-verdict", "bad", `With the key leaked: plain ${r.plainHits} of ${r.total}, keyed ${r.keyedHits} of ${r.total}. Same result: the key is the secret.`);
      else verdict("ps-verdict", "y", `Plain hashes: ${r.plainHits} of ${r.total} emails recovered. Keyed: ${r.keyedHits} of ${r.total}.`);
      if (leaked) egg.add("leak");
      note("ps-note", leaked ? "# keep the key in a separate system with its own access control, and plan how to rotate it." : "# the same guesses, the same table: only the keyed version resists.");
      one();
    }
    function one() {
      const e = $("ps-email").value;
      if (!e.trim()) { $("ps-one").textContent = "(type an email)"; return; }
      $("ps-one").textContent = "sha256 : " + P.plainHash(e).slice(0, 32) + "…\nhmac   : " + P.keyedPseudonym(KEY, e).slice(0, 32) + "…\n(trimmed and lower-cased first, so " + (e.trim() === e.trim().toLowerCase() ? "this" : "upper and lower case") + " matches the same person)";
    }
    $("ps-attack").addEventListener("click", () => { attacked = true; render(); });
    $("ps-leak").addEventListener("click", () => { attacked = true; leaked = true; render(); });
    $("ps-reset").addEventListener("click", () => { attacked = false; leaked = false; render(); });
    $("ps-email").addEventListener("input", one);
    render();
  }

  // --------------------------------------------------------------------------- differential privacy
  function noise() {
    const TRUE = 42, runs = [];
    const eps = () => Math.pow(10, +$("dp-eps").value);
    const fmt = (e) => (e < 1 ? e.toFixed(2) : e < 10 ? e.toFixed(1) : String(Math.round(e)));
    function render() {
      const e = eps();
      $("dp-eps-out").textContent = fmt(e);
      const n = runs.length, last = n ? runs[n - 1] : null;
      $("dp-stats").innerHTML = stat(last === null ? "-" : Math.round(last), "last answer (true: " + TRUE + ")") + stat("±" + fmt(P.expectedAbsError(e)), "typical error") + stat(n ? n * 1 + " × " + fmt(e) + " = " + fmt(n * e) : "0", "total budget spent (ε)", n > 20 ? "fast" : "");
      if (n) {
        const lo = TRUE - 30, hi = TRUE + 30, bins = 15, h = P.histogram(runs, lo, hi, bins), mx = Math.max(...h, 1);
        const lines = h.map((c, i) => String(Math.round(lo + (i + 0.5) * (hi - lo) / bins)).padStart(4) + " | " + "█".repeat(Math.round(c / mx * 26)) + (c ? " " + c : ""));
        const avg = P.mean(runs);
        $("dp-hist").textContent = lines.join("\n") + (n > 20 ? `\n\nmean of ${n} answers: ${avg.toFixed(1)}` : "");
      } else $("dp-hist").textContent = "(ask a question)";
      if (n > 20) note("dp-note", `# the average of ${n} answers is ${P.mean(runs).toFixed(1)}: close to ${TRUE}. Fresh noise on the same question averages away, which is why every answer spends budget.`, "y");
      else if (e < 0.2) note("dp-note", "# strong privacy, and the answers are mostly noise. Nobody can learn about one person from this, and nobody can use it either.", "y");
      else if (e > 20) note("dp-note", "# at this ε you are publishing the true number with extra steps.", "y");
      else note("dp-note", "# noise of about 1/ε: at ε = 1 you're typically off by one, and one person's presence can't be told from the answer.");
    }
    $("dp-eps").addEventListener("input", () => { runs.length = 0; render(); });
    $("dp-ask").addEventListener("click", () => { runs.push(P.noisyCount(TRUE, eps())); render(); });
    $("dp-100").addEventListener("click", () => { for (let i = 0; i < 200; i++) runs.push(P.noisyCount(TRUE, eps())); render(); });
    $("dp-reset").addEventListener("click", () => { runs.length = 0; render(); });
    render();
  }

  // --------------------------------------------------------------------------- redactor
  function redactor() {
    let mode = "mask";
    $("rx-in").value = P.SAMPLE_LOG;
    function render() {
      const raw = $("rx-in").value, r = P.redact(raw, { mode });
      $("rx-out").textContent = r.out;
      const kinds = {}; r.findings.forEach((f) => { kinds[f.kind] = (kinds[f.kind] || 0) + 1; });
      $("rx-stats").textContent = r.findings.length ? `${plural(r.findings.length, "value", "values")} redacted: ` + Object.entries(kinds).map(([k, n]) => `${k} ×${n}`).join(", ") : "nothing matched";
      if (raw.trim().split("\n").length === 1 && /AKIAIOSFODNN7EXAMPLE/.test(raw) && /\[cloud-key\]/.test(r.out)) note("rx-note", "# that's AWS's documentation example key: it has never opened anything. A real one would have to be rotated even after redaction, because the log line existed.", "");
      else if (mode === "pseudonym") note("rx-note", "# the same email gets the same token, so you can still count and join. The key lives elsewhere.");
      else note("rx-note", "# patterns only catch known shapes. The postal address in free text got through: log IDs, not objects.");
    }
    $("rx-in").addEventListener("input", render);
    $("rx-mode").addEventListener("click", (e) => { const b = e.target.closest("button[data-m]"); if (!b) return; mode = b.dataset.m; pickInto("rx-mode", "data-m", mode); render(); });
    render();
  }

  // --------------------------------------------------------------------------- access and audit
  function access() {
    const log = [];
    let t = 9 * 60;
    const clock = () => { t += 3 + Math.floor(Math.random() * 4); return String(Math.floor(t / 60) % 24).padStart(2, "0") + ":" + String(t % 60).padStart(2, "0"); };
    $("ac-reason").innerHTML = P.REASONS.map((r) => `<option>${esc(r)}</option>`).join("");
    const revealed = new Set();
    function render() {
      $("ac-list").innerHTML = P.RECORDS.map((r) => `<li><span class="ac-name">${esc(r.name)}${r.vip ? " ★" : ""}</span><span class="ac-mail">${revealed.has(r.id) ? esc(r.email) : "••••••@••••••.com"}</span><button type="button" class="btn btn-ghost btn-sm" data-id="${r.id}">Reveal</button></li>`).join("");
      $("ac-log").innerHTML = `<thead><tr><th>Time</th><th>Agent</th><th>Record</th><th>Reason</th></tr></thead><tbody>${log.slice(-8).map((e) => `<tr><td>${e.time}</td><td>${esc(e.agent)}</td><td>${esc(e.name)}${e.vip ? " ★" : ""}</td><td>${esc(e.reason)}</td></tr>`).join("") || "<tr><td colspan='4'>(nothing revealed yet)</td></tr>"}</tbody>`;
      const rep = P.auditReport(log);
      $("ac-alerts").innerHTML = rep.alerts.map((a) => `<li><b>ALERT</b> ${esc(a.agent)}: ${esc(a.why)}</li>`).join("");
      if (rep.alerts.some((a) => /reveals in one session/.test(a.why))) note("ac-note", "# curiosity is not a business reason. Someone has to read the alerts, or they're only evidence.", "y");
      else note("ac-note", "# masked by default, a reason to reveal, every reveal logged: and someone reads it.");
    }
    function reveal(id, agent, reason) {
      const r = P.RECORDS.find((x) => x.id === id);
      log.push({ time: clock(), agent, name: r.name, vip: r.vip, reason }); revealed.add(id);
    }
    $("ac-list").addEventListener("click", (e) => { const b = e.target.closest("button[data-id]"); if (!b) return; reveal(+b.dataset.id, $("ac-agent").value, $("ac-reason").value); render(); });
    $("ac-browse").addEventListener("click", () => { for (const r of P.RECORDS) reveal(r.id, "pat", "Other"); render(); });
    $("ac-reset").addEventListener("click", () => { log.length = 0; revealed.clear(); t = 9 * 60; render(); });
    render();
  }

  // --------------------------------------------------------------------------- retention
  function retention() {
    const policy = {}; for (const c of P.CLASSES) policy[c.k] = { days: c.days, hold: false };
    let ran = false;
    $("rt-table").innerHTML = `<thead><tr><th>Class</th><th>Keep (days)</th><th>Hold</th><th>Result</th></tr></thead><tbody>${P.CLASSES.map((c) => `<tr data-k="${c.k}"><td>${esc(c.label)}<br><small>${esc(c.why)}</small></td><td><input type="number" min="0" max="5000" class="mono rt-days" value="${c.days}" aria-label="Retention in days for ${esc(c.label)}"></td><td><input type="checkbox" class="rt-hold" aria-label="Legal hold on ${esc(c.label)}"></td><td class="rt-res"></td></tr>`).join("")}</tbody>`;
    function render() {
      const r = P.purge(policy);
      for (const row of r.rows) {
        const tr = $("rt-table").querySelector(`tr[data-k="${row.k}"] .rt-res`);
        const old = P.CLASSES.find((c) => c.k === row.k);
        tr.innerHTML = ran ? `${row.deleted} deleted · ${row.kept} kept${row.held ? " · <b>" + row.held + " on hold</b>" : ""}` : `${row.total} records`;
      }
      const stale = r.rows.reduce((n, x) => n + x.held, 0);
      $("rt-stats").innerHTML = stat(ran ? r.deleted : 0, "records purged", ran ? "slow" : "") + stat(ran ? r.kept : r.total, "kept") + stat(ran ? r.held : 0, "held (legal)");
      if (!ran) { verdict("rt-verdict", "y", "Nothing has run: every record is kept, however old."); note("rt-note", "# a policy with no job is a wish. Run the purge to see what a real retention rule removes."); }
      else if (r.kept === P.CLASSES.length && r.deleted === r.total - P.CLASSES.length) { verdict("rt-verdict", "ok", "Almost nothing kept. No data, no breach, no value."); note("rt-note", "# keep nothing is the privacy-perfect setting and an unusable product. Set periods by purpose and law.", "y"); egg.add("zero"); }
      else if (r.held) { verdict("rt-verdict", "y", `${plural(r.held, "record is", "records are")} held: the dispute stays, the rest still expires.`); note("rt-note", "# a legal hold pauses deletion for the records in a dispute, and nothing else."); }
      else { verdict("rt-verdict", "ok", `${plural(r.deleted, "record", "records")} deleted by the job, ${r.kept} kept.`); note("rt-note", "# set the period by purpose, and let a tested job enforce it."); }
    }
    $("rt-table").addEventListener("input", (e) => {
      const tr = e.target.closest("tr[data-k]"); if (!tr) return;
      policy[tr.dataset.k] = { days: Math.max(0, +tr.querySelector(".rt-days").value || 0), hold: tr.querySelector(".rt-hold").checked };
      if (ran) render();
    });
    $("rt-run").addEventListener("click", () => { ran = true; render(); });
    $("rt-off").addEventListener("click", () => { ran = false; render(); });
    $("rt-zero").addEventListener("click", () => {
      $("rt-table").querySelectorAll("tr[data-k]").forEach((tr) => { tr.querySelector(".rt-days").value = 0; tr.querySelector(".rt-hold").checked = false; policy[tr.dataset.k] = { days: 0, hold: false }; });
      ran = true; render();
    });
    $("rt-reset").addEventListener("click", () => {
      $("rt-table").querySelectorAll("tr[data-k]").forEach((tr) => { const c = P.CLASSES.find((x) => x.k === tr.dataset.k); tr.querySelector(".rt-days").value = c.days; tr.querySelector(".rt-hold").checked = false; policy[c.k] = { days: c.days, hold: false }; });
      ran = false; render();
    });
    render();
  }

  // --------------------------------------------------------------------------- deletion plan
  function deletion() {
    const choice = {};
    $("dl-list").innerHTML = P.DELSTORES.map((s) => `<label class="dl-row"><span>${esc(s.label)}</span><select data-k="${s.k}" aria-label="How ${esc(s.label)} handles deletion">${s.opts.map((o, i) => `<option value="${i}"${i === s.def ? " selected" : ""}>${esc(o[0])}</option>`).join("")}</select></label>`).join("");
    function render() {
      const r = P.deletionPlan(choice);
      const max = Math.max(35, r.worstFinite);
      $("dl-bars").textContent = r.rows.map((x) => {
        const label = x.label.replace(/ \(.*\)/, "").padEnd(28).slice(0, 28);
        if (x.day === null) return label + " NEVER  ✗ nothing removes it";
        const w = x.day === 0 ? 1 : Math.max(1, Math.round(Math.sqrt(x.day / max) * 24));
        return label + " " + String(x.day).padStart(3) + "d  " + "█".repeat(w);
      }).join("\n");
      $("dl-stats").innerHTML = stat(r.never.length, "copies with no way to delete", r.never.length ? "fast" : "slow") + stat(r.last === null ? "never" : r.last + " days", "until the last copy is gone", r.last === null || r.last > 35 ? "fast" : "slow") + stat(r.rows.filter((x) => x.day === 0).length, "gone straight away");
      if (r.never.length) verdict("dl-verdict", "bad", "Not deletable: " + r.never.join(", ") + ".");
      else if (r.last > 35) verdict("dl-verdict", "y", `Everything can be deleted, but the slowest copy takes ${r.last} days. Is that explainable to the person?`);
      else verdict("dl-verdict", "ok", `Every copy has a path, and the last is gone in ${r.last} day${r.last === 1 ? "" : "s"}.`);
      note("dl-note", "# backups can age out on a known schedule ('beyond use'); a copy that nothing ever removes is the one to fix.");
    }
    $("dl-list").addEventListener("change", (e) => { const s = e.target.closest("select[data-k]"); if (!s) return; choice[s.dataset.k] = +s.value; render(); });
    render();
  }

  // --------------------------------------------------------------------------- requests
  function dsr() {
    function render() {
      const regime = $("ds-regime").value, d = $("ds-date").value;
      if (!/^\d{4}-\d{2}-\d{2}$/.test(d)) { $("ds-stats").innerHTML = ""; note("ds-note", "# pick a date"); return; }
      const r = P.dueDates(d, regime);
      $("ds-stats").innerHTML = stat(r.base, "respond by (" + r.baseText + ")") + stat(r.ext, "latest, if extended and notified") + stat(regime === "gdpr" ? "1 + 2" : "45 + 45", regime === "gdpr" ? "months" : "days");
      const day = +d.slice(8, 10);
      if (regime === "gdpr" && day > 28) { note("ds-note", `# ${r.label}: "one month" from the ${day}th lands on ${r.base}, because a shorter month ends first. Check how your own counsel counts.`, "y"); egg.add("month"); }
      else note("ds-note", `# ${r.label}: ${r.baseText}, then ${r.extText}. Not legal advice: other laws differ.`);
    }
    $("ds-json").textContent = P.exportRecord(P.SAMPLE_USER);
    $("ds-regime").addEventListener("change", render); $("ds-date").addEventListener("input", render);
    render();
  }

  // --------------------------------------------------------------------------- LINDDUN
  function linddun() {
    const sel = $("ld-feature");
    sel.innerHTML = P.FEATURES.map((f, i) => `<option value="${i}">${esc(f.label)}</option>`).join("");
    let choice = {};
    function render() {
      const f = P.FEATURES[+sel.value];
      $("ld-table").innerHTML = `<thead><tr><th>Threat type</th><th>For this feature</th><th>Your decision</th></tr></thead><tbody>${P.LINDDUN.map((c, i) => `<tr><td><b>${esc(c.name)}</b><small>${esc(c.q)}</small></td><td>${esc(f.threats[i])}</td><td><select data-k="${c.k}" aria-label="Decision for ${esc(c.name)}">${P.MITIGATIONS.map((m, j) => `<option value="${j}"${(choice[c.k] || 0) === j ? " selected" : ""}>${esc(m)}</option>`).join("")}</select></td></tr>`).join("")}</tbody>`;
      const cov = P.linddunCoverage(choice);
      $("ld-stats").innerHTML = stat(cov.covered + " / " + cov.total, "threat types decided", cov.covered === cov.total ? "slow" : "fast") + stat(Object.values(choice).filter((v) => v === 1).length, "accepted: each needs an owner and a date") + stat(Object.values(choice).filter((v) => v === 2).length, "reduced in the design");
      if (cov.covered === cov.total) { note("ld-note", "# all seven covered. Turn each decision into a backlog item with an owner, and put the accepted risks on a calendar.", "ok"); egg.add("linddun"); }
      else note("ld-note", `# still open: ${cov.open.join(", ")}.`);
    }
    $("ld-table").addEventListener("change", (e) => { const s = e.target.closest("select[data-k]"); if (!s) return; choice[s.dataset.k] = +s.value; render(); });
    sel.addEventListener("change", () => { choice = {}; render(); });
    render();
  }

  // --------------------------------------------------------------------------- checklist
  const RV_KEY = "privacy-engineering-checklist";
  function checklist() {
    const boxes = Array.from(document.querySelectorAll("#rv-list input[type=checkbox]"));
    let saved = {};
    try { saved = JSON.parse(store(RV_KEY) || "{}"); } catch (e) {}
    boxes.forEach((b) => { b.checked = !!saved[b.dataset.k]; });
    const update = () => {
      const done = boxes.filter((b) => b.checked).length;
      store(RV_KEY, JSON.stringify(Object.fromEntries(boxes.map((b) => [b.dataset.k, b.checked]))));
      const n = $("rv-note"); n.className = "comment";
      if (done === boxes.length) { n.textContent = "# 10 of 10. Now ask the harder question: if the whole system were deleted tomorrow, what would a person actually lose?"; n.classList.add("ok"); }
      else if (!done) n.textContent = "# tick what's true for the feature you're working on. Each gap is a ticket, not a failure. Saved in this browser only.";
      else n.textContent = `# ${done} of ${boxes.length}. Pick the unticked box that's cheapest to fix this week.`;
    };
    boxes.forEach((b) => b.addEventListener("change", update));
    update();
  }

  function consoleHint() {
    console.log("%c" + document.title, "font: 700 24px monospace; color: #ff2e88; text-shadow: 0 0 8px #ff2e88");
    console.log("%cThis deck collects zero personal data. We checked. Twice.", "font: 14px monospace; color: #00f0ff");
  }

  function start() {
    consoleHint();
    $("hero-in").addEventListener("input", hero); hero();
    reid(); minimise(); purpose(); datamap(); shred(); pseudo(); noise(); redactor(); access(); retention(); deletion(); dsr(); linddun(); checklist();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
})();
