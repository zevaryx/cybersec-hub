/* app.js - the live demos for "Public Key Infrastructure in Depth".
   The signatures are real maths (ECDSA P-256, SHA-256, from ../../shared/crypto.js), but every CA, log, certificate and ACME server here
   is a simulation in your browser: nothing issues or tests a real certificate, and nothing you type is sent anywhere. */
(function () {
  "use strict";
  const L = window.Lab;

  // --------------------------------------------------------------------------- helpers
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const sp = (cls, s) => `<span class="${cls}">${esc(s)}</span>`;
  const click = (id, fn) => $(id).addEventListener("click", fn);
  const enc = (s) => L.utf8(s);
  const short = (hexs, n) => hexs.slice(0, n) + "…";
  const b64u = (b) => btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  function store(key, val) {
    try { if (val === undefined) return localStorage.getItem(key); localStorage.setItem(key, val); } catch (e) {}
    return null;
  }
  const DAY = 86400000;
  const iso = (t) => new Date(t).toISOString().slice(0, 10);
  const parseDay = (s) => Date.parse(s + "T00:00:00Z");
  const todayUtc = () => parseDay(iso(Date.now()));

  // --------------------------------------------------------------------------- real signatures: a toy certificate format on ECDSA P-256
  const P = L.P256;
  const rnd = () => L.randBelow(P.n - 1n) + 1n;
  const xhex = (pt) => L.hex(L.fromBig(pt[0], 32));
  const bodyHash = (body) => L.toBig(L.sha256(enc(JSON.stringify(body))));
  const sigCache = new Map();
  function sign(body, key, id) {
    const k = id + JSON.stringify(body);
    if (!sigCache.has(k)) sigCache.set(k, L.ecdsaSign(key, bodyHash(body), rnd()));
    return sigCache.get(k);
  }
  const verify = (body, sig, pub) => L.ecdsaVerify(pub, bodyHash(body), sig);

  // --------------------------------------------------------------------------- title: renewals a year
  function hero() {
    const el = $("hero-in"), v = el.value.trim();
    el.style.width = Math.max(4, el.value.length + 1) + "ch";
    const out = $("hero-out");
    const d = Number(v.replace(",", "."));
    if (v === "" || !Number.isFinite(d) || d < 0) { out.innerHTML = sp("m", "usage: renewals --lifetime-days <number>"); $("hero-note").textContent = "# a number of days, please. Certificates don't come in negative."; return; }
    let note;
    if (d === 0) { out.innerHTML = `${sp("bad", "error: a certificate that expires at once")}`; note = "# zero days: a certificate that expired before anyone could read it. Impressive, and unhelpful."; }
    else {
      const per = 365 / d, total = Math.round(per * 100), hours = Math.round(total * 30 / 60);
      out.innerHTML = `${sp("k", "per certificate:")} ${per >= 10 ? Math.round(per) : per.toFixed(1)} renewals a year<br>${sp("k", "100 certificates:")} ${sp(total > 400 ? "bad" : total > 150 ? "y" : "ok", total.toLocaleString("en-US"))} renewals<br>${sp("k", "at 30 min each:")} ${hours.toLocaleString("en-US")} hours of work`;
      note = d > 825 ? "# longer than any publicly trusted certificate may live today. An internal CA can choose; see part 4."
        : "# fewer days, more renewals, and a smaller window for a stolen key. That trade is the whole of part 3.";
      if (d === 47) note = "# 47 days: the limit for certificates issued from 15 March 2029.";
      else if (d === 6) note = "# 6 days: Let's Encrypt's opt-in short-lived profile (160 hours, to be exact).";
      else if (d === 200) note = "# 200 days: today's maximum, in force since 15 March 2026.";
      else if (d === 398) note = "# 398 days: the maximum from September 2020 until March 2026.";
      else if (d === 825) note = "# 825 days: the maximum before September 2020.";
      else if (d === 1) note = "# every day is fine, as long as a machine does it.";
    }
    $("hero-note").textContent = note;
  }

  // --------------------------------------------------------------------------- trust stores (pure logic; the next demo does the signatures)
  const ROOTS = { A: "Atlas Root R1", B: "Borealis Root R2 (new)", C: "Corvid Root R3", W: "Northwind Corp Root (your employer's)" };
  const PROFILES = { phone: ["A", "C"], laptop: ["A", "B", "C"], work: ["A", "B", "C", "W"] };
  const SITES = [
    { n: "shop.example", paths: [["A", "Atlas Root R1"]] },
    { n: "news.example", paths: [["B", "Borealis Root R2"], ["A", "Atlas Root R1, by a cross-sign of Borealis's issuing CA"]] },
    { n: "app.example", paths: [["B", "Borealis Root R2"]] },
    { n: "bank.example", paths: [["C", "Corvid Root R3"]] },
    { n: "intranet.corp.example", paths: [["W", "Northwind Corp Root"]] },
  ];
  let trusted = new Set(PROFILES.laptop), profile = "laptop";
  function drawTrust() {
    $("ts-roots").innerHTML = Object.entries(ROOTS).map(([k, n]) => `<label class="check"><input type="checkbox" data-r="${k}"${trusted.has(k) ? " checked" : ""}> ${esc(n)}</label>`).join("");
    for (const b of $("ts-pick").querySelectorAll("button")) b.setAttribute("aria-pressed", String(b.dataset.p === profile));
    let okCount = 0;
    $("ts-sites").innerHTML = SITES.map((s) => {
      const hit = s.paths.find(([k]) => trusted.has(k));
      if (hit) okCount++;
      return `<div class="ts-site ${hit ? "ok" : "bad"}"><b>${esc(s.n)}</b><span>${hit ? "✓ trusted via " + esc(hit[1]) : "✗ unknown issuer: no trusted root on any path"}</span></div>`;
    }).join("");
    let note = "# a root you trust can vouch for any name. That's the whole risk, and the reason for everything that follows.";
    if (!trusted.size) note = "# nothing is trusted. Perfectly safe, completely useless: not a single HTTPS page would load.";
    else if (profile === "phone" && trusted.size === 2 && trusted.has("A") && trusted.has("C")) note = "# the old phone never got Borealis, but news.example still works: its issuing CA was also signed by Atlas. app.example had no cross-sign, so it fails.";
    else if (trusted.has("W")) note = "# the work root makes the intranet work. It could also vouch for any site on this laptop, which is why it must be guarded and, if possible, name-constrained.";
    $("ts-note").textContent = note;
  }
  function trustStore() {
    $("ts-pick").addEventListener("click", (e) => { const b = e.target.closest("button[data-p]"); if (!b) return; profile = b.dataset.p; trusted = new Set(PROFILES[profile]); drawTrust(); });
    $("ts-roots").addEventListener("change", (e) => {
      const r = e.target.dataset.r; if (!r) return;
      e.target.checked ? trusted.add(r) : trusted.delete(r);
      profile = Object.entries(PROFILES).find(([, v]) => v.length === trusted.size && v.every((k) => trusted.has(k)))?.[0] || "";
      drawTrust();
    });
    drawTrust();
  }

  // --------------------------------------------------------------------------- build a chain, then try to break it
  let ck = null;
  function newKeys() { ck = { root: rnd(), inter: rnd(), leaf: rnd(), atk: rnd() }; ck.rootPub = P.mul(ck.root); ck.interPub = P.mul(ck.inter); ck.leafPub = P.mul(ck.leaf); ck.atkPub = P.mul(ck.atk); sigCache.clear(); }
  const within = (name, dom) => name === dom || name.endsWith("." + dom);
  function chain() {
    if (!ck) newKeys();
    const name = ($("bc-name").value.trim().toLowerCase() || "shop.example"), scn = $("bc-scn").value, nc = $("bc-nc").checked, rootTrusted = $("bc-root").checked;
    const target = name === "bank.example" ? "shop.example" : "bank.example";
    const today = iso(Date.now()), nb = iso(Date.now() - 30 * DAY), na = iso(Date.now() + 60 * DAY);
    const root = { subject: "Neon Root", issuer: "Neon Root", pub: xhex(ck.rootPub) };
    const inter = { subject: "Neon Issuing CA", issuer: "Neon Root", pub: xhex(ck.interPub), ...(nc ? { nameConstraint: name } : {}) };
    const rootSig = sign(root, ck.root, "r"), interSig = sign(inter, ck.root, "i");
    let leaf, leafSig, visit;
    const base = { subject: name, issuer: "Neon Issuing CA", notBefore: nb, notAfter: na, pub: xhex(ck.leafPub) };
    if (scn === "normal") { leaf = base; leafSig = sign(base, ck.inter, "l"); visit = name; }
    else if (scn === "stolen") { leaf = { ...base, subject: target, pub: xhex(ck.atkPub) }; leafSig = sign(leaf, ck.inter, "s"); visit = target; }
    else if (scn === "fake") { leaf = { ...base, subject: target, pub: xhex(ck.atkPub) }; leafSig = sign(leaf, ck.atk, "f"); visit = target; }
    else { leafSig = sign(base, ck.inter, "l"); leaf = { ...base, subject: target }; visit = target; }
    const rootOk = verify(root, rootSig, ck.rootPub), interOk = verify(inter, interSig, ck.rootPub), leafOk = verify(leaf, leafSig, ck.interPub);
    const nameOk = leaf.subject === visit, dateOk = leaf.notBefore <= today && today <= leaf.notAfter;
    const ncOk = !inter.nameConstraint || within(leaf.subject, inter.nameConstraint);
    const row = (ok, t) => `${ok ? sp("ok", "✓") : sp("bad", "✗")} ${esc(t)}`;
    const mk = (title, sub, ok) => `<div class="${ok ? "" : "bad"}"><b>${esc(title)}</b><small>${esc(sub)}</small></div>`;
    $("bc-chain").innerHTML = mk("Neon Root", rootTrusted ? "in your trust store · key " + short(root.pub, 8) : "not in your trust store", rootOk && rootTrusted) + "<i>signs ↓</i>"
      + mk("Neon Issuing CA", (inter.nameConstraint ? "limited to " + inter.nameConstraint + " · " : "") + "key " + short(inter.pub, 8), interOk && ncOk) + "<i>signs ↓</i>"
      + mk(leaf.subject, `valid ${leaf.notBefore} → ${leaf.notAfter}`, leafOk && nameOk && dateOk && ncOk);
    $("bc-checks").innerHTML = `you're visiting   ${sp("y", visit)}\n\n` + [
      row(rootOk, "the root's self-signature verifies"),
      row(rootTrusted, "the root is in the trust store"),
      row(interOk, "the root really signed the intermediate"),
      row(leafOk, "the intermediate's key really signed this certificate"),
      row(nameOk, `the certificate is for ${visit}`),
      row(dateOk, "today is inside the validity dates"),
      row(ncOk, inter.nameConstraint ? `the name is within the intermediate's limit (${inter.nameConstraint})` : "no name limit on the intermediate (it may vouch for any name)"),
    ].join("\n");
    const bad = [!rootTrusted && "Unknown issuer: the root isn't trusted.", !leafOk && "The signature doesn't verify: the certificate isn't from this CA, or was altered.",
      !nameOk && "Wrong name.", !ncOk && "The intermediate is not allowed to vouch for this name.", !(rootOk && interOk) && "A signature in the chain is broken."].filter(Boolean);
    const v = $("bc-verdict");
    v.className = "verdict " + (bad.length ? "bad" : "ok");
    v.textContent = bad.length ? "✗ Rejected. " + bad.join(" ") : "🔒 Accepted: every check passed";
    let note = "# real ECDSA signatures. Try each scenario, then the name-constrained box.";
    if (!bad.length && scn === "stolen") note = "# every check passed, for a certificate the real CA never meant to issue. A signature proves the key said yes, not that anyone meant it. Only revocation, CT and name limits can catch this.";
    else if (bad.length && scn === "stolen" && !ncOk) note = "# same stolen key, same valid signatures, but the name limit stops it. That's why internal CAs should constrain their intermediates.";
    else if (scn === "edit" && !leafOk) note = "# one changed byte, a different hash, a signature that no longer fits.";
    else if (scn === "fake") note = "# a certificate signed with the attacker's own key doesn't verify against the real intermediate's key.";
    if (name === "localhost") note = "# public CAs won't certify localhost: anyone could claim it. Internal CAs and local dev tools do, with a root you add yourself.";
    $("bc-note").textContent = note;
  }

  // --------------------------------------------------------------------------- a mini Certificate Transparency log (RFC 6962 hashing)
  const leafHash = (d) => L.sha256(L.concat(Uint8Array.of(0), d));
  const nodeHash = (l, r) => L.sha256(L.concat(Uint8Array.of(1), l, r));
  const split = (n) => 1 << (31 - Math.clz32(n - 1));                    // largest power of two below n
  function mth(h) { if (h.length === 1) return h[0]; const k = split(h.length); return nodeHash(mth(h.slice(0, k)), mth(h.slice(k))); }
  function auditPath(m, h) {
    if (h.length === 1) return [];
    const k = split(h.length);
    return m < k ? auditPath(m, h.slice(0, k)).concat([mth(h.slice(k))]) : auditPath(m - k, h.slice(k)).concat([mth(h.slice(0, k))]);
  }
  function rootFromPath(m, n, leaf, path) {                                // RFC 9162 section 2.1.3.2
    let fn = m, sn = n - 1, r = leaf;
    for (const c of path) {
      if (sn === 0) return null;
      if ((fn & 1) || fn === sn) { r = nodeHash(c, r); if (!(fn & 1)) while (!(fn & 1) && fn !== 0) { fn >>= 1; sn >>= 1; } } else r = nodeHash(r, c);
      fn >>= 1; sn >>= 1;
    }
    return sn === 0 ? r : null;
  }
  let log = null;
  const sthData = (size, root) => ({ size, root: L.hex(root) });
  function ctInit() {
    const key = rnd();
    log = { key, pub: P.mul(key), entries: [], sths: [], notes: "" };
    ["shop.example · issued by Atlas CA", "news.example · issued by Borealis CA", "bank.example · issued by Corvid CA"].forEach((t) => ctAppend(t));
    ctDraw(sp("m", "The bank's monitor watches every new entry for bank.example."));
  }
  function ctAppend(text) {
    log.entries.push({ text, bytes: enc(text), orig: text });
    const root = mth(log.entries.map((e) => leafHash(e.bytes)));
    const body = sthData(log.entries.length, root);
    log.sths.push({ ...body, sig: L.ecdsaSign(log.key, bodyHash(body), rnd()) });
  }
  const ctRoot = (n) => mth(log.entries.slice(0, n).map((e) => leafHash(e.bytes)));
  function ctAudit() {
    const bad = log.sths.filter((s) => L.hex(ctRoot(s.size)) !== s.root);
    return { bad, sigOk: log.sths.every((s) => L.ecdsaVerify(log.pub, bodyHash({ size: s.size, root: s.root }), s.sig)) };
  }
  function ctDraw(msg) {
    const a = ctAudit(), firstBad = a.bad.length ? Math.min(...a.bad.map((s) => s.size)) : Infinity;
    const tampered = log.entries.findIndex((e) => e.text !== e.orig);
    $("ct-log").innerHTML = log.entries.map((e, i) => `<li class="${/Rogue/.test(e.text) ? "rogue" : /bank\.example/.test(e.text) ? "mine" : ""}${i === tampered ? " broken" : ""}"><span>#${i + 1}</span><b>${esc(e.text)}</b><code>${L.hex(leafHash(e.bytes)).slice(0, 10)}</code></li>`).join("");
    const sel = $("ct-pick"), cur = sel.value;
    sel.innerHTML = log.entries.map((_, i) => `<option value="${i}">${i + 1}</option>`).join("");
    if (cur && +cur < log.entries.length) sel.value = cur;
    const last = log.sths[log.sths.length - 1];
    $("ct-out").innerHTML = `${sp("k", "tree size:")} ${log.entries.length}    ${sp("k", "root now:")} ${L.hex(ctRoot(log.entries.length)).slice(0, 16)}…\n${sp("k", "last signed head:")} size ${last.size}, root ${last.root.slice(0, 16)}…\n` +
      `${sp("k", "audit:")} ${a.bad.length ? sp("bad", "✗ the log's history no longer matches heads it signed (from size " + firstBad + ")") : a.sigOk ? sp("ok", "✓ every signed head matches the tree") : sp("bad", "✗ a tree-head signature is invalid")}\n\n${msg || ""}`;
    const mon = log.entries.map((e, i) => ({ e, i })).filter(({ e }) => /bank\.example/.test(e.text));
    $("ct-monitor").innerHTML = `<b>Monitor for bank.example</b>` + mon.map(({ e, i }) => {
      const ok = /Corvid CA/.test(e.text);
      return `<p class="${ok ? "ok" : "bad"}">${ok ? "✓" : "⚠"} entry #${i + 1}: ${esc(e.text)}${ok ? " (expected issuer)" : ": the bank didn't ask for this"}</p>`;
    }).join("");
  }
  function ctProof() {
    const m = +$("ct-pick").value, n = log.entries.length, hs = log.entries.map((e) => leafHash(e.bytes));
    const path = auditPath(m, hs), got = rootFromPath(m, n, hs[m], path), last = log.sths[log.sths.length - 1];
    const sigOk = L.ecdsaVerify(log.pub, bodyHash({ size: last.size, root: last.root }), last.sig);
    const match = got && L.hex(got) === last.root;
    ctDraw(`${sp("k", `inclusion proof for entry #${m + 1}`)} (${path.length} hash${path.length === 1 ? "" : "es"}):\n` + path.map((h, i) => `  ${i + 1}. ${L.hex(h).slice(0, 16)}…`).join("\n") +
      `\n${sp("k", "rebuilt root:")} ${got ? L.hex(got).slice(0, 16) + "…" : "(proof malformed)"}\n${match && sigOk ? sp("ok", "✓ the entry is in the log: it rebuilds the root the log signed") : sp("bad", "✗ the rebuilt root doesn't match the signed tree head: the log has changed since it signed")}`);
  }
  function ctNew() {
    if (log.entries.length >= 34) { ctDraw(sp("y", "# that's plenty for a toy. Real logs hold far more, and shard themselves by expiry year.")); return; }
    const name = $("ct-name").value.trim() || "blog.example";
    ctAppend(`${name} · issued by Atlas CA`);
    ctDraw(`${sp("ok", "added")} #${log.entries.length}: the root changed and the log signed a new head.` + (log.entries.length === 30 ? "\n" + sp("m", "# thirty entries, and a proof is still only a handful of hashes: it grows with the logarithm of the log's size, not the size itself.") : ""));
  }
  function ctRogue() { ctAppend("bank.example · issued by Rogue CA"); ctDraw(sp("bad", "A CA issued a certificate the bank never asked for. It's public the moment it's logged: the monitor above raises it.")); }
  function ctTamper() {
    const i = +$("ct-pick").value, e = log.entries[i];
    if (e.text !== e.orig) { ctDraw(sp("m", "That entry is already edited.")); return; }
    e.text = e.orig.replace(/ · .*/, " · issued by Nobody"); e.bytes = enc(e.text);
    ctDraw(sp("bad", `Entry #${i + 1} was edited in place. Every hash above it changed, so the log can no longer reproduce the heads it signed.`) + "\n" + sp("m", "# edit one leaf and every hash above it changes. That's the whole trick."));
  }

  // --------------------------------------------------------------------------- distrust: a cutoff date, not a cliff
  const BASE = parseDay("2026-11-16");
  const DS_CERTS = [["shop.example", -150, 90], ["api.example", -40, 90], ["mail.example", -10, 200], ["vpn.example", -300, 398], ["new.example", 6, 90], ["portal.example", 25, 90]];
  function distrust() {
    const cut = parseDay($("ds-cut").value || "2026-11-16"), off = +$("ds-today").value, now = todayUtc() + off * DAY;
    $("ds-today-l").textContent = iso(now) + (off ? ` (+${off} d)` : " (now)");
    let alive = 0, last = 0;
    $("ds-table").innerHTML = `<div class="ds-row ds-head"><span>Site</span><span>First logged</span><span>Expires</span><span>Status</span></div>` + DS_CERTS.map(([n, o, life]) => {
      const iss = BASE + o * DAY, exp = iss + life * DAY, grand = iss <= cut;
      let st, cls;
      if (!grand) { st = "refused (after cutoff)"; cls = "bad"; }
      else if (exp < now) { st = "expired"; cls = "m"; }
      else { st = "trusted until expiry"; cls = "ok"; alive++; }
      if (grand) last = Math.max(last, exp);
      return `<div class="ds-row ${cls}"><span>${esc(n)}</span><span>${iso(iss)}</span><span>${iso(exp)}</span><span>${esc(st)}</span></div>`;
    }).join("");
    const s = $("ds-sum"); s.className = "verdict " + (alive === DS_CERTS.length ? "ok" : alive ? "y" : "bad");
    s.textContent = `${alive} of ${DS_CERTS.length} still validate on ${iso(now)}. The last certificate from before the cutoff expires on ${last ? iso(last) : "(none)"}.`;
    $("ds-note").textContent = parseDay($("ds-cut").value) === todayUtc() ? "# a cutoff of today breaks nothing today. The trouble arrives at your next renewal, which is the point of grandfathering by date." : "# new certificates from this CA are refused; old ones live out their lives. Time to find another CA.";
  }

  // --------------------------------------------------------------------------- shorter certificates
  const LIVES = [[825, "825 days"], [398, "398 days"], [200, "200 days"], [100, "100 days"], [90, "90 days"], [64, "64 days"], [47, "47 days"], [45, "45 days"], [160 / 24, "6 days (160 h)"]];
  const SCHED = [["until 14 Mar 2026", 398, "2026-03-14"], ["from 15 Mar 2026", 200, "2027-03-14"], ["from 15 Mar 2027", 100, "2029-03-14"], ["from 15 Mar 2029", 47, "9999-12-31"]];
  function lifetimes() {
    const now = iso(Date.now()), cur = SCHED.findIndex(([, , until]) => now <= until);
    $("sched").innerHTML = SCHED.map(([label, d], i) => `<div class="${i === cur ? "now" : ""}"><small>${label}</small><b>${d} days</b></div>`).join("");
    const sel = $("lt-pick");
    sel.innerHTML = LIVES.map(([d, t]) => `<option value="${d}">${t}</option>`).join("");
    sel.value = "200";
    const draw = () => {
      const pick = +sel.value, max = 825;
      $("lt-bars").innerHTML = LIVES.map(([d, t]) => `<div class="bar${d === pick ? " pick" : ""}"><span>${esc(t)}</span><i style="width:${Math.max(1.5, d / max * 100)}%"></i><em>${d < 10 ? d.toFixed(1) : Math.round(d)} d</em></div>`).join("");
      $("lt-note").textContent = `# with no working revocation, a thief with a ${pick < 10 ? "6-day" : Math.round(pick) + "-day"} certificate's key can use it for up to ${pick < 10 ? "6.7" : Math.round(pick)} days, about ${pick < 10 ? "3.3" : Math.round(pick / 2)} on average.`;
    };
    sel.addEventListener("change", draw); draw();
  }

  // --------------------------------------------------------------------------- the lifetime calculator
  function calc() {
    const n = Math.max(1, +$("lc-n").value || 1), life = +$("lc-life").value, mins = Math.max(0, +$("lc-min").value || 0);
    const auto = $("lc-auto").checked, p = Math.min(1, Math.max(0, (auto ? +$("lc-pa").value : +$("lc-p").value) / 100 || 0));
    const per = n * 365 / life, hours = auto ? 0 : per * mins / 60, chance = 1 - Math.pow(1 - p, per);
    const f = (x) => x >= 100 ? Math.round(x).toLocaleString("en-US") : x >= 10 ? x.toFixed(0) : x.toFixed(1);
    $("lc-out").innerHTML = `<div class="stat"><b>${f(per)}</b><span>renewals a year${auto ? " (by machine)" : ""}</span></div><div class="stat"><b>${f(hours)}</b><span>hours of manual work</span></div><div class="stat"><b>${(chance * 100).toFixed(chance < .1 ? 1 : 0)}%</b><span>chance of at least one miss a year</span></div>`;
    const v = $("lc-verdict"); v.className = "verdict " + (chance < .05 ? "ok" : chance < .3 ? "y" : "bad");
    v.textContent = chance < .05 ? "Manageable." : chance < .3 ? "A matter of time." : "Expect an outage this year.";
    let note = "# the chance of at least one miss is 1 − (1 − p)^renewals: small risks add up fast when there are many renewals.";
    if (auto) note = "# automated: renewal is now a cron job's problem. Monitor the cron job.";
    else if (p === 0) note = "# 0% chance of a miss: either you're a robot, or you've automated. Same thing.";
    $("lc-note").textContent = note;
  }
  function calcInit() {
    $("lc-life").innerHTML = LIVES.map(([d, t]) => `<option value="${d}">${t}</option>`).join(""); $("lc-life").value = "398";
    for (const id of ["lc-n", "lc-life", "lc-min", "lc-p", "lc-pa", "lc-auto"]) $(id).addEventListener("input", calc);
    calc();
  }

  // --------------------------------------------------------------------------- ACME: proving control of a name (RFC 8555 key authorization)
  let ac = null, acPublished = null;
  function acNew() {
    const name = $("ac-name").value.trim().toLowerCase() || "shop.example", type = $("ac-type").value;
    acPublished = null;
    if (name.startsWith("*.") && type === "http") {
      ac = null; $("ac-pub").innerHTML = ""; $("ac-out").innerHTML = `${sp("bad", "CA: refused")}\n${sp("m", "# wildcards need DNS-01. A file on one web server can't prove control of a whole zone.")}`; return;
    }
    const d = rnd(), Q = P.mul(d), x = b64u(L.fromBig(Q[0], 32)), y = b64u(L.fromBig(Q[1], 32));
    const jwk = `{"crv":"P-256","kty":"EC","x":"${x}","y":"${y}"}`;
    const thumb = b64u(L.sha256(enc(jwk))), token = b64u(L.randBytes(32)), keyAuth = token + "." + thumb;
    const base = name.replace(/^\*\./, "");
    ac = { name, base, type, token, thumb, keyAuth, dns: b64u(L.sha256(enc(keyAuth))) };
    $("ac-out").innerHTML = `${sp("k", "account key:")} P-256, thumbprint ${thumb.slice(0, 16)}…\n${sp("k", "CA → you:")} order for ${esc(name)}, challenge ${type === "http" ? "http-01" : "dns-01"}, token ${token.slice(0, 16)}…\n\n${sp("m", "Now publish the answer, then ask the CA to validate.")}`;
    acDraw();
  }
  function acExpected() { return ac.type === "http" ? ac.keyAuth : ac.dns; }
  function acDraw() {
    if (!ac) return;
    const where = ac.type === "http" ? `http://${ac.base}/.well-known/acme-challenge/${ac.token}` : `_acme-challenge.${ac.base}   TXT`;
    const val = acPublished === "ok" ? acExpected() : acPublished === "other" ? (ac.type === "http" ? ac.token + "." + b64u(L.randBytes(32)) : b64u(L.randBytes(32))) : null;
    if (acPublished === "other") ac.otherVal = val;
    const shown = acPublished === "other" ? ac.otherVal : val;
    $("ac-pub").innerHTML = `${sp("k", ac.type === "http" ? "the CA will fetch:" : "the CA will look up:")}\n  ${esc(where)}\n\n${sp("k", "what you must publish:")}\n  ${esc(acExpected())}\n\n${sp("k", "what's published now:")}\n  ${shown ? sp(acPublished === "ok" ? "ok" : "bad", shown) : sp("m", "(nothing)")}`;
  }
  function acCheck() {
    if (!ac) { $("ac-out").innerHTML = sp("m", "Start an order first."); return; }
    const got = acPublished === "ok" ? acExpected() : acPublished === "other" ? ac.otherVal : null;
    const ok = got === acExpected();
    $("ac-out").innerHTML = `${sp("k", "CA → " + (ac.type === "http" ? "GET " + ac.base : "TXT lookup for _acme-challenge." + ac.base) + ":")}\n  ${got ? esc(got.slice(0, 40)) + "…" : sp("bad", ac.type === "http" ? "404 Not Found" : "NXDOMAIN")}\n\n` +
      (ok ? `${sp("ok", "✓ valid")}: you control ${esc(ac.name)}. You send a CSR (your public key, signed), the CA issues the certificate and logs it to CT.\n${sp("m", "# renew when ARI says, or about two-thirds of the way through its lifetime.")}`
        : `${sp("bad", "✗ invalid")}: ${acPublished === "other" ? "that answer was made with a different account key, so it doesn't match. A token alone can't be answered by someone else." : "nothing to match. The order stays pending."}`);
  }

  // --------------------------------------------------------------------------- internal CA checklist (kept in this browser only)
  const IC_KEY = "pki-internal-ca";
  function internalCa() {
    const boxes = Array.from(document.querySelectorAll("#ic-plan input[type=checkbox]"));
    let saved = {}; try { saved = JSON.parse(store(IC_KEY) || "{}"); } catch (e) {}
    boxes.forEach((b) => { b.checked = !!saved[b.dataset.k]; });
    const update = () => {
      const n = boxes.filter((b) => b.checked).length;
      store(IC_KEY, JSON.stringify(Object.fromEntries(boxes.map((b) => [b.dataset.k, b.checked]))));
      const note = $("ic-note"); note.className = "comment";
      if (n === boxes.length) { note.textContent = "# all eight: a boring, well-run CA. In PKI, that's the highest compliment."; note.classList.add("ok"); }
      else if (!n) note.textContent = "# tick what your organisation already does. They're saved in this browser only.";
      else note.textContent = `# ${n} of ${boxes.length}. The unticked ones are your roadmap.`;
    };
    boxes.forEach((b) => b.addEventListener("change", update)); update();
  }

  // --------------------------------------------------------------------------- inventory and expiry radar
  const INV = [["shop.example", "Web team", 12], ["api.example", "Platform", 45], ["mail.example", "Messaging", 3], ["vpn.example", "IT ops", 80], ["old-intranet", "", -4], ["payments-gateway", "Payments", 29],
    ["wifi-radius", "", 7], ["traffic-inspector", "", -120], ["partner-sftp", "IT ops", 21], ["build-cache", "Platform", 200]];
  function radar() {
    const th = +$("ex-th").value, t = todayUtc();
    $("ex-th-l").textContent = th + (th === 1 ? " day" : " days");
    let exp = 0, soon = 0, orphan = 0;
    $("ex-table").innerHTML = `<div class="ex-row ex-head"><span>Certificate</span><span>Owner</span><span>Expires</span><span>Status</span></div>` + INV.slice().sort((a, b) => a[2] - b[2]).map(([n, o, d]) => {
      let cls = "ok", st = "fine";
      if (d < 0) { cls = "bad"; st = `expired ${-d} d ago`; exp++; }
      else if (d <= th) { cls = "y"; st = th === 0 ? "expires today" : `alert: ${d} d left`; soon++; }
      if (!o) orphan++;
      return `<div class="ex-row ${cls}"><span>${esc(n)}</span><span>${o ? esc(o) : sp("bad", "no owner")}</span><span>${iso(t + d * DAY)}</span><span>${st}</span></div>`;
    }).join("");
    let note = `# ${exp} expired, ${soon} inside the alert window, ${orphan} with no owner (an alert about those goes nowhere).`;
    if (th === 0) note = "# an alert on the day it expires is just the outage report.";
    else if (th >= 90) note = "# 90 days of warning for a 90-day certificate alerts on the day it's issued. Match the alert to the lifetime.";
    $("ex-note").textContent = note;
  }

  // --------------------------------------------------------------------------- console hint
  function consoleHint() {
    console.log("%cPublic Key Infrastructure in Depth", "font: 700 24px monospace; color: #ff2e88; text-shadow: 0 0 8px #ff2e88");
    console.log("%cThe renewals command on the title slide takes any lifetime. Try the dates from the schedule: 825, 398, 200, 47, 6.", "font: 14px monospace; color: #00f0ff");
  }

  function start() {
    consoleHint();
    $("hero-in").addEventListener("input", hero); hero();
    trustStore();
    newKeys();
    for (const id of ["bc-name", "bc-scn", "bc-nc", "bc-root"]) $(id).addEventListener("input", chain);
    click("bc-new", () => { newKeys(); chain(); }); chain();
    ctInit(); click("ct-add", ctNew); click("ct-rogue", ctRogue); click("ct-proof", ctProof); click("ct-tamper", ctTamper); click("ct-reset", ctInit);
    $("ds-cut").value = "2026-11-16"; $("ds-cut").addEventListener("input", distrust); $("ds-today").addEventListener("input", distrust);
    click("ds-now", () => { $("ds-cut").value = iso(Date.now()); $("ds-today").value = "0"; distrust(); }); distrust();
    lifetimes(); calcInit();
    click("ac-new", acNew); $("ac-type").addEventListener("change", acNew);
    click("ac-ok", () => { if (ac) { acPublished = "ok"; acDraw(); } }); click("ac-other", () => { if (ac) { acPublished = "other"; acDraw(); } }); click("ac-none", () => { if (ac) { acPublished = null; acDraw(); } });
    click("ac-check", acCheck); acNew();
    internalCa();
    $("ex-th").addEventListener("input", radar); radar();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
})();
