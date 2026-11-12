/* app.js - the live demos for "Post-Quantum Migration".
   Everything here is TEACHING CODE ON INVENTED DATA. The only real cryptography is X25519 (RFC 7748) plus the SHA-256/HMAC/HKDF
   in ../../shared/crypto.js; the lattice KEM is a toy that stands in for ML-KEM and is not secure. Nothing is sent anywhere.
   The logic and the size tables are in pqc.js (window.Pqc), which also runs in Node and is tested there. */
(function () {
  "use strict";
  const L = window.Lab, P = window.Pqc;

  // --------------------------------------------------------------------------- helpers
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const num = (n) => Number(n).toLocaleString("en-US");
  const on = (id, ev, fn) => { const el = $(id); if (el) el.addEventListener(ev, fn); };
  const store = (key, val) => {
    try { if (val === undefined) return localStorage.getItem(key); localStorage.setItem(key, val); } catch (e) { /* storage can be blocked */ }
    return null;
  };
  function seg(id, items, initial, fn, cls) {
    const g = $(id);
    g.innerHTML = items.map((it) => `<button type="button" data-v="${esc(it.v)}" aria-pressed="false">${esc(it.label)}</button>`).join("");
    const btns = [...g.querySelectorAll("button")];
    let val = initial;
    const set = (v, quiet) => { val = v; for (const b of btns) b.setAttribute("aria-pressed", String(b.dataset.v === v)); if (!quiet) fn(v); };
    g.addEventListener("click", (e) => { const b = e.target.closest("button"); if (b && !b.disabled) set(b.dataset.v); });
    set(initial, true);
    return { get: () => val, set, buttons: btns };
  }
  const setVerdict = (id, text, tone) => { const el = $(id); el.textContent = text; el.className = "verdict" + (tone ? " " + tone : ""); };
  const hexs = (b, n) => L.hex(b).slice(0, n * 2);
  const plural = (n, w) => n + " " + w + (n === 1 ? "" : "s");
  const year = (y) => (Math.abs(y - Math.round(y)) < 0.05 ? String(Math.round(y)) : y.toFixed(1));
  const years = (y) => (y < 1 ? "<1" : Number.isInteger(y) ? String(y) : y.toFixed(1)) + " y";
  const ms = (x) => (x < 10 ? x.toFixed(1) : String(Math.round(x)));
  const tones = { exposed: "bad", tight: "y", safe: "ok" };

  // --------------------------------------------------------------------------- title terminal: when do we have to start?
  function hero() {
    const el = $("hero-in");
    el.style.width = Math.max(6, Math.min(24, el.value.length + 1)) + "ch";
    const r = P.heroLine(el.value);
    let out = "";
    if (r.kind === "calc") {
      out = `<span class="au-row"><b class="au-label">${esc(r.shelf)} + ${P.TERM_MIGRATION} = ${esc(r.total)} years</b><span class="au-tag">shelf life + a ${P.TERM_MIGRATION}-year migration</span></span>` +
        `<span class="au-why">Safe only if no computer that can break today's public-key crypto exists before <b>${r.year}</b>. Plan to have moved by then.</span>` +
        `<span class="au-why">${esc(r.horizon)}</span>`;
    }
    $("hero-out").innerHTML = out;
    $("hero-note").textContent = r.note;
  }

  // --------------------------------------------------------------------------- what breaks
  const brState = { id: "rsa" };
  function brDetail() {
    const x = P.PRIMS.find((p) => p.id === brState.id);
    const tag = x.verdict === "shor" ? ["bad", "Broken by Shor's algorithm"] : x.verdict === "grover" ? ["y", "Weakened by Grover's algorithm"] : ["ok", "Not a target"];
    $("br-detail").innerHTML = `<b class="d-name">${esc(x.name)}</b><span class="d-tag ${tag[0]}">${tag[1]}</span><p>${esc(x.why)}</p><p class="next">Replacement or action: ${esc(x.next)}</p>`;
    for (const b of $("br-chips").querySelectorAll("button")) b.setAttribute("aria-pressed", String(b.dataset.v === x.id));
  }
  function brInit() {
    $("br-chips").innerHTML = P.PRIMS.map((x) => `<button type="button" class="chip v-${x.verdict}" data-v="${x.id}" aria-pressed="false">${esc(x.name)}</button>`).join("");
    $("br-chips").addEventListener("click", (e) => { const b = e.target.closest("button"); if (b) { brState.id = b.dataset.v; brDetail(); } });
    brDetail();
  }

  // --------------------------------------------------------------------------- harvest now, forge later
  function hnRender() {
    const o = { crqc: +$("hn-crqc").value, kexYear: +$("hn-kex").value, sigYear: +$("hn-sig").value, resign: $("hn-resign").checked };
    $("hn-crqc-out").textContent = o.crqc; $("hn-kex-out").textContent = o.kexYear; $("hn-sig-out").textContent = o.sigYear;
    let bad = 0;
    $("hn-list").innerHTML = P.HNDL_ITEMS.map((it) => {
      const r = P.hndl(it, o); if (r.exposed) bad++;
      return `<li class="${r.exposed ? "hn-bad" : "hn-ok"}"><span class="st ${r.exposed ? "st-bad" : "st-ok"}">${r.exposed ? "exposed" : "ok"}</span><span>${esc(it.name)}<small>${esc(r.why)}</small></span></li>`;
    }).join("");
    const txt = bad === 0 ? "Nothing exposed. Key exchange and signatures both moved before the computer. That's the goal.  # a good day on the planner."
      : `${bad} of ${P.HNDL_ITEMS.length} exposed with these dates. Confidentiality is exposed by what was recorded; signatures by what is still trusted.`;
    setVerdict("hn-verdict", txt, bad === 0 ? "ok" : "bad");
  }

  // --------------------------------------------------------------------------- the estimates
  const esState = { f: "all" };
  function esRender() {
    const list = P.ESTIMATES.filter((e) => esState.f === "all" || e.target === esState.f);
    $("es-rows").innerHTML = list.map((e) => `<tr><th>${esc(e.year)}</th><td data-label="Who">${esc(e.who)} <a href="${esc(e.href)}" target="_blank" rel="noopener">[source]</a></td><td data-label="Target">${e.target === "rsa" ? "RSA-2048" : "256-bit elliptic curve"}</td><td data-label="Hardware">${esc(e.qubits)}</td><td data-label="Time">${esc(e.time)}</td><td class="small" data-label="Assumes">${esc(e.assumptions)}</td></tr>`).join("");
  }

  // --------------------------------------------------------------------------- Mosca's planner
  function moRender() {
    let early = +$("mo-early").value, late = +$("mo-late").value;
    if (late < early) { late = early; $("mo-late").value = late; }
    const mult = +$("mo-mult").value / 10;
    $("mo-early-out").textContent = early; $("mo-late-out").textContent = late; $("mo-mult-out").textContent = "×" + mult.toFixed(1);
    let badE = 0, badL = 0;
    $("mo-rows").innerHTML = P.MOSCA_CLASSES.map((c) => {
      const mig = +(c.migration * mult).toFixed(2);
      const a = P.mosca({ shelf: c.shelf, migration: mig, crqcYear: early }), b = P.mosca({ shelf: c.shelf, migration: mig, crqcYear: late });
      if (a.status === "exposed") badE++; if (b.status === "exposed") badL++;
      const start = a.startBy <= P.NOW_YEAR ? `late by ${a.lateBy.toFixed(1)} y` : year(a.startBy);
      return `<tr><th>${esc(c.name)}${c.kind === "sig" ? ' <span class="chip">signature</span>' : ""}</th><td class="num" data-label="Shelf life">${years(c.shelf)}</td><td class="num" data-label="Migration">${years(mig)}</td><td class="num" data-label="Start by">${start}</td><td data-label="Earliest"><span class="st st-${a.status === "exposed" ? "bad" : a.status === "tight" ? "tight" : "ok"}">${a.status === "exposed" ? "late" : a.status}</span></td><td data-label="Latest"><span class="st st-${b.status === "exposed" ? "bad" : b.status === "tight" ? "tight" : "ok"}">${b.status === "exposed" ? "late" : b.status}</span></td></tr>`;
    }).join("");
    const n = P.MOSCA_CLASSES.length;
    let txt = `On the earliest date, ${badE} of ${n} are already late; on the latest, ${badL}.`;
    if (badE === n) txt += "  # everything late on the early date. That's the planning problem, not a reason to panic: start with the longest lead times.";
    setVerdict("mo-summary", txt, badE === n ? "bad" : "y");
  }

  // --------------------------------------------------------------------------- deadlines
  const tlOrder = ["usfed", "usother", "uk", "eu", "nss", "free"];
  function tlRender(id) {
    const r = P.REGIMES[id], ys = [r.plan, r.kex, r.sigs, r.all].filter((y) => y != null);
    const first = Math.min(...ys), last = Math.max(...ys);
    $("tl-first").textContent = first; $("tl-last").textContent = last; $("tl-years").textContent = first - P.NOW_YEAR;
    $("tl-card").innerHTML = `<b>${esc(r.label)}</b>` + r.rows.map((x) => `<span>${esc(x)}</span>`).join("");
    $("tl-src").textContent = "Source: " + r.src + ".";
  }

  // --------------------------------------------------------------------------- the toy lattice
  const laState = { key: null, timer: 0 };
  const sv = (a) => "[" + a.join(", ") + "]";
  function laNewKey() {
    const E = +$("la-noise").value;
    laState.key = P.lweKeygen(E);
    const k = laState.key;
    let t = `secret s = ${sv(k.s)}   (hidden from everyone in real life)\nnoise bound E = ${E}\npublic equations (first 4 of ${k.m}): row · s + e = b (mod ${k.q})\n`;
    for (let i = 0; i < 4; i++) t += `  ${sv(k.A[i])} · s + (${k.e[i] >= 0 ? "+" : ""}${k.e[i]}) = ${k.b[i]}\n`;
    $("la-out").textContent = t.trimEnd();
  }
  function laStats() {
    const E = +$("la-noise").value;
    $("la-noise-out").textContent = E;
    $("la-margin").textContent = "16·E = " + 16 * E;
    $("la-eqs").textContent = P.TOY.m;
    clearTimeout(laState.timer);
    laState.timer = setTimeout(() => { $("la-fail").textContent = Math.round(P.lweFailRate(E, 300) * 300) + " / 300"; }, 30);
  }
  function laEnc() {
    if (!laState.key) laNewKey();
    const k = laState.key, bit = L.randInt(2), ct = P.lweEncrypt(k, bit), d = P.lweDecrypt(k, ct);
    $("la-out").textContent += `\n\nencrypt bit ${bit}: add a random subset of ${ct.S.length} equations\n  u = ${sv(ct.u)}  v = ${ct.v}\ndecrypt: r = v − u·s = ${d.r}   (leftover noise ${d.noise >= 0 ? "+" : ""}${d.noise}; 0 means near 0, 1 means near ${Math.floor(k.q / 2)})\n  → decrypted bit ${d.bit}  ${d.bit === bit ? "✓ correct" : "✗ WRONG: the noise was too big"}`;
  }
  function laSolve() {
    if (!laState.key) laNewKey();
    const k = laState.key, r = P.solveLinear(k);
    let t = `\n\ntry to solve for s: Gaussian elimination modulo ${k.q} on ${r.equations} equations in ${r.unknowns} unknowns\n`;
    if (r.consistent && r.s) {
      const ok = r.s.join() === k.s.join();
      t += `  consistent: yes → s = ${sv(r.s)} ${ok ? "✓ matches the secret" : ""}\n  # no noise: ordinary algebra recovers the secret. That's why the noise is there.`;
    } else {
      t += `  consistent: no. The equations contradict each other: the noise hides s from exact algebra.\n  (A real attack must search for s; at this toy size about ${(Math.pow(k.q, k.n) / 1e11).toFixed(1)} × 10^11 guesses is still easy for a computer, which is why toy parameters are only toys.)`;
    }
    $("la-out").textContent += t;
  }

  // --------------------------------------------------------------------------- KEM sizes and the toy KEM
  const kmState = { set: "mlkem768" };
  function kmRender() {
    const k = P.byId(P.KEMS, kmState.set), x = P.byId(P.KEMS, "x25519"), h = P.byId(P.KEMS, "x25519mlkem768");
    const row = (name, a) => `<tr><th>${esc(name)}</th><td class="num">${num(a.pk)}</td><td class="num">${num(a.ct)}</td><td class="num">${a.ss}</td></tr>`;
    $("km-rows").innerHTML = row(`${k.name} · category ${k.cat}`, k) + row("X25519", x) + row("X25519MLKEM768 (hybrid)", h);
  }
  function kmRun() {
    const t = P.kemKeygen(), e = P.kemEncaps(t.pk), d = P.kemDecaps(t.sk, e.ct), z = P.kemSizes();
    $("km-out").textContent = `KeyGen   public key ${z.pk} B (toy), secret key = ${t.sk.s.length} numbers\nEncaps   ciphertext ${z.ct} B (toy), shared secret ${hexs(e.ss, 12)}…\nDecaps   shared secret ${hexs(d, 12)}…\nmatch: ${L.equalBytes(e.ss, d) ? "yes ✓" : "NO"}\n\nfor comparison, real ML-KEM-768: public key 1,184 B, ciphertext 1,088 B, secret 32 B`;
  }

  // --------------------------------------------------------------------------- signatures: which for what
  function sgRender(id) {
    const u = P.SIG_USES[id];
    $("sg-rec").innerHTML = `<b>${esc(u.label)}: ${esc(u.pick)}</b><span>${esc(u.why)}</span>`;
  }

  // --------------------------------------------------------------------------- the size explorer
  const PRESETS = [
    { v: "today", label: "Today", kex: "x25519", leaf: "ecdsa256", chain: "ecdsa256" },
    { v: "hyb", label: "Hybrid keys only", kex: "x25519mlkem768", leaf: "ecdsa256", chain: "ecdsa256" },
    { v: "d44", label: "Hybrid + ML-DSA-44", kex: "x25519mlkem768", leaf: "mldsa44", chain: "mldsa44" },
    { v: "d65", label: "Hybrid + ML-DSA-65", kex: "x25519mlkem768", leaf: "mldsa65", chain: "mldsa65" },
    { v: "slh", label: "Hybrid + SLH-DSA-128s", kex: "x25519mlkem768", leaf: "slh128s", chain: "slh128s" },
  ];
  let szPreset = null;
  const logPos = (b) => Math.max(0, Math.min(1, (Math.log10(Math.max(b, 1000)) - 3) / (Math.log10(300000) - 3))) * 100;
  function szRender() {
    const o = { kex: $("sz-kex").value, leaf: $("sz-leaf").value, chain: $("sz-chain").value, certs: +$("sz-certs").value, scts: +$("sz-scts").value, link: $("sz-link").value, plainShare: $("sz-plain").checked };
    const r = P.handshake(o), base = P.handshake({ ...o, kex: "x25519", leaf: "ecdsa256", chain: "ecdsa256", plainShare: false });
    $("sz-client").textContent = num(r.clientBytes); $("sz-server").textContent = num(r.serverBytes);
    $("sz-sigs").textContent = r.sigCount + " · " + r.pkCount; $("sz-rtt").textContent = r.extraRttsTcp + " (QUIC " + r.quicExtraRtts + ")";
    $("sz-bar-fill").style.width = logPos(r.serverBytes) + "%"; $("sz-mark-iw").style.left = logPos(r.initcwnd) + "%"; $("sz-mark-base").style.left = logPos(base.serverBytes) + "%";
    const link = P.LINKS[o.link];
    let txt = `Server flight ${num(r.serverBytes)} B vs a ${num(r.initcwnd)} B initial window: ` + (r.extraRttsTcp ? `${plural(r.extraRttsTcp, "extra round trip")} on TCP (about ${ms(r.extraRttsTcp * link.rtt)} ms here). ` : "fits, no extra round trip. ") +
      (r.quicExtraRtts ? `QUIC: ${plural(r.quicExtraRtts, "extra round trip")}. ` : "QUIC: within its limit. ") + (r.clientFitsOnePacket ? "ClientHello fits one packet. " : "ClientHello splits across packets. ") +
      `About ${ms(r.timeMs)} ms on this link, against ${ms(base.timeMs)} ms today.`;
    if (r.serverBytes > 200000) txt += "  # a quarter of a megabyte of signatures before any data: nobody proposes this for TLS.";
    setVerdict("sz-verdict", txt, r.extraRttsTcp || r.quicExtraRtts ? "bad" : r.clientFitsOnePacket ? "ok" : "y");
  }
  function szInit() {
    const opt = (arr, f) => arr.map((x) => `<option value="${x.id}">${esc(x.name)}</option>`).join("");
    $("sz-kex").innerHTML = opt(P.KEMS); $("sz-leaf").innerHTML = opt(P.SIGS); $("sz-chain").innerHTML = opt(P.SIGS);
    $("sz-link").innerHTML = Object.entries(P.LINKS).map(([k, v]) => `<option value="${k}">${esc(v.name)}</option>`).join("");
    const apply = (p) => { $("sz-kex").value = p.kex; $("sz-leaf").value = p.leaf; $("sz-chain").value = p.chain; szRender(); };
    szPreset = seg("sz-preset", PRESETS.map((p) => ({ v: p.v, label: p.label })), "today", (v) => apply(PRESETS.find((p) => p.v === v)));
    apply(PRESETS[0]);
    for (const id of ["sz-kex", "sz-leaf", "sz-chain"]) on(id, "change", () => { szPreset.buttons.forEach((b) => b.setAttribute("aria-pressed", "false")); szRender(); });
    for (const id of ["sz-certs", "sz-scts", "sz-link"]) on(id, "change", szRender);
    on("sz-plain", "change", szRender);
  }

  // --------------------------------------------------------------------------- hybrid handshake
  const hyState = { run: null };
  function hyRender() {
    const el = $("hy-out");
    if (!hyState.run) { el.textContent = "Press the button to run a handshake."; setVerdict("hy-verdict", "", ""); return; }
    const r = hyState.run, z = P.kemSizes(), bx = $("hy-brokeX").checked, bk = $("hy-brokeK").checked;
    const a = P.attackerKey(r, { brokeX: bx, brokeKem: bk });
    let t = `client → server  X25519 share 32 B + toy KEM key ${z.pk} B   (real X25519MLKEM768: 1,216 B)\n` +
      `server → client  X25519 share 32 B + toy KEM ciphertext ${z.ct} B   (real: 1,120 B)\n` +
      `X25519 secret    ${hexs(r.serverSsX, 8)}…   client and server agree\n` +
      `KEM secret       ${hexs(r.serverSsK, 8)}…   client and server agree\n` +
      `session key      client ${hexs(r.keyC, 10)}…\n                 server ${hexs(r.keyS, 10)}…   ${r.agree ? "same ✓" : "DIFFERENT"}\n\n` +
      `attacker knows   X25519 secret: ${bx ? "yes (broken)" : "no"}   KEM secret: ${bk ? "yes (broken)" : "no"}\nattacker's key   ${hexs(a.guess, 10)}…   ${a.recovered ? "MATCHES the session key" : "does not match"}`;
    el.textContent = t;
    if (a.recovered) setVerdict("hy-verdict", "Both halves broken: the key falls.  # the hybrid only helps while at least one half holds.", "bad");
    else if (bx || bk) setVerdict("hy-verdict", "One half broken, and the session key is still safe. That is the point of a hybrid.", "ok");
    else setVerdict("hy-verdict", "Both halves intact. Tick a box to see what an attacker who has broken one of them can do.", "");
  }
  function hyRun() { hyState.run = P.hybridHandshake(); hyRender(); }

  // --------------------------------------------------------------------------- protocols
  const PROTOCOLS = [
    { id: "tls", name: "Web servers, CDNs and load balancers (TLS)", status: "Browsers, CDNs and OpenSSL 3.5 offer or prefer X25519MLKEM768. About 15% of the origins Cloudflare connects to use it.", check: "Upgrade the TLS library, enable the hybrid group, test old clients and the devices in the middle, and check origin connections too." },
    { id: "ssh", name: "SSH", status: "OpenSSH 10.0 (April 2025) defaults to mlkem768x25519-sha256 and sshd turns off finite-field DH.", check: "Upgrade clients and servers to 10.0 or later, and check network gear and embedded devices that ship their own SSH." },
    { id: "vpn", name: "IPsec VPNs and SASE", status: "Vendor-dependent. Cloudflare says post-quantum IPsec became generally available on 30 April 2026.", check: "Ask the vendor for a roadmap in writing. Start with site-to-site tunnels, which carry long-lived traffic." },
    { id: "chat", name: "Messaging and chat", status: "Signal and Apple iMessage use post-quantum key agreement (see Modern Messaging Protocols).", check: "Check what your enterprise chat and email vendors do for key agreement, and how stored messages are protected." },
    { id: "disk", name: "Disk, backup and database encryption", status: "AES at 128 bits or more is believed to meet NIST's lowest post-quantum category. The exposure is in how data keys are wrapped.", check: "Find where keys are wrapped with RSA or elliptic curves (KMS, backup tools, S/MIME) and plan a re-wrap." },
    { id: "sign", name: "Code signing and firmware", status: "The signatures that must last longest, and the verifiers that are hardest to change. NSA's CNSA 2.0 puts them first.", check: "List every verifier, who updates it and when. Plan a post-quantum-capable verifier for the next hardware revision." },
    { id: "pki", name: "Certificates and internal PKI", status: "Browsers don't yet trust post-quantum certificates on the public web; Chrome's quantum-resistant root store is still under a draft policy (Cloudflare, 29 Sep 2026).", check: "Inventory certificates and CAs, avoid new long-lived classical roots, and plan an internal post-quantum hierarchy." },
  ];
  function prInit() {
    let saved = []; try { saved = JSON.parse(store("pqc-protocols") || "[]"); } catch (e) { saved = []; }
    $("pr-rows").innerHTML = PROTOCOLS.map((p) => `<tr><th><label><input type="checkbox" data-id="${p.id}"${saved.includes(p.id) ? " checked" : ""}> ${esc(p.name)}</label></th><td data-label="Status">${esc(p.status)}</td><td data-label="Check">${esc(p.check)}</td></tr>`).join("");
    const draw = () => {
      const ids = [...$("pr-rows").querySelectorAll("input:checked")].map((i) => i.dataset.id);
      store("pqc-protocols", JSON.stringify(ids));
      $("pr-list").textContent = ids.length ? `Your list (${ids.length}): ` + ids.map((id) => PROTOCOLS.find((x) => x.id === id).name).join("; ") + "." : "Tick the protocols you run, and keep the checks that go with them.";
      $("pr-list").className = "verdict" + (ids.length ? " y" : "");
    };
    $("pr-rows").addEventListener("change", draw);
    draw();
  }

  // --------------------------------------------------------------------------- the certificate chain simulator
  function pkRender() {
    const alg = $("pk-alg").value, certs = +$("pk-certs").value, scts = +$("pk-scts").value;
    const r = P.handshake({ kex: "x25519", leaf: alg, chain: alg, certs, scts }), b = P.handshake({ kex: "x25519", leaf: "ecdsa256", chain: "ecdsa256", certs, scts });
    const chain = r.certBytes.reduce((a, c) => a + c, 0) + r.sctBytes, baseChain = b.certBytes.reduce((a, c) => a + c, 0) + b.sctBytes;
    $("pk-sigs").textContent = r.sigCount; $("pk-keys").textContent = r.pkCount; $("pk-bytes").textContent = num(chain);
    const ratio = chain / baseChain;
    setVerdict("pk-verdict", alg === "ecdsa256" ? "Today's chain: about " + num(baseChain) + " bytes with these settings." : `${ratio.toFixed(1)}× today's chain (${num(baseChain)} bytes), before the CertificateVerify signature.`, ratio > 8 ? "bad" : ratio > 1.5 ? "y" : "ok");
  }

  // --------------------------------------------------------------------------- long-lived signatures
  let snUpd = null;
  function snRender() {
    const life = +$("sn-life").value, ship = +$("sn-ship").value, crqc = +$("sn-crqc").value;
    $("sn-life-out").textContent = life; $("sn-ship-out").textContent = ship; $("sn-crqc-out").textContent = crqc;
    const r = P.signingPlan({ lifetime: life, ship, crqcYear: crqc, updatable: snUpd.get() });
    setVerdict("sn-verdict", r.verdict, r.level === "ok" ? "ok" : r.level);
    $("sn-advice").innerHTML = r.advice.map((a) => `<li>${esc(a)}</li>`).join("");
  }

  // --------------------------------------------------------------------------- inventory: where to look
  const PLACES = [
    { id: "code", name: "Code and dependencies", q: "Which languages, libraries and frameworks call RSA, ECDSA or ECDH, and where is the algorithm named?", how: "Search source and dependency lists (an SBOM helps), and static scanners for crypto calls.", watch: "Algorithm names built from strings, and third-party code you can't read." },
    { id: "cfg", name: "Configurations and protocols", q: "Which TLS, SSH, VPN and database settings choose groups, ciphers and signature algorithms?", how: "Read configs, scan your own endpoints' handshakes, and log the negotiated groups.", watch: "Defaults that changed with an upgrade, and devices with their own stacks." },
    { id: "keys", name: "Certificates and keys", q: "What certificates, CAs, keys and key stores exist, how long do they last, and who owns them?", how: "Certificate-lifecycle tools, certificate transparency logs for public names, KMS and HSM inventories.", watch: "Keys nobody owns, long-lived roots and RSA-wrapped data keys." },
    { id: "hw", name: "Hardware and firmware", q: "Which HSMs, smart cards, TPMs, boot ROMs and appliances verify or hold keys, and can they be updated?", how: "Asset lists, vendor datasheets, and asking the manufacturer.", watch: "Mask ROM and fixed firmware: the longest lead times." },
    { id: "vend", name: "Vendors and SaaS", q: "Who runs cryptography for you, and what is their post-quantum roadmap and date?", how: "Procurement records and a written question to each vendor.", watch: "Vendors with no answer, and contracts with no clause." },
    { id: "data", name: "Data and its shelf life", q: "Which data must stay secret or trusted for years, and where does it travel and rest?", how: "Retention schedules and data classification, tied to the systems above.", watch: "Data kept longer than anyone decided to keep it." },
  ];
  function ivRender(id) {
    const x = PLACES.find((p) => p.id === id);
    $("iv-detail").innerHTML = `<b class="d-name">${esc(x.name)}</b><p class="q">Ask: ${esc(x.q)}</p><p>How: ${esc(x.how)}</p><p class="next">Watch for: ${esc(x.watch)}</p>`;
    for (const b of $("iv-chips").querySelectorAll("button")) b.setAttribute("aria-pressed", String(b.dataset.v === id));
  }
  function ivInit() {
    $("iv-chips").innerHTML = PLACES.map((p) => `<button type="button" class="chip" data-v="${p.id}" aria-pressed="false">${esc(p.name)}</button>`).join("");
    $("iv-chips").addEventListener("click", (e) => { const b = e.target.closest("button"); if (b) ivRender(b.dataset.v); });
    ivRender("code");
  }

  // --------------------------------------------------------------------------- triage
  const trState = { order: [] };
  const shuffled = (arr) => { const a = arr.slice(); for (let i = a.length - 1; i > 0; i--) { const j = L.randInt(i + 1); [a[i], a[j]] = [a[j], a[i]]; } return a; };
  function trRender() {
    const byId = Object.fromEntries(P.ESTATE.map((s) => [s.id, s]));
    $("tr-list").innerHTML = trState.order.map((id, i) => {
      const s = byId[id];
      return `<li data-id="${id}"><span><b><span class="k-badge k-${s.kind}">${s.kind === "kex" ? "secret" : "signature"}</span>${esc(s.name)}</b><small>${years(s.life)} · ${s.exposure} · change ${s.change}/5 · ${esc(s.algs)}</small></span><span class="mv"><button type="button" data-d="-1" aria-label="Move up"${i === 0 ? " disabled" : ""}>▲</button><button type="button" data-d="1" aria-label="Move down"${i === trState.order.length - 1 ? " disabled" : ""}>▼</button></span></li>`;
    }).join("");
  }
  function trCompare() {
    const model = P.triageOrder(), d = P.orderDistance(trState.order), pos = Object.fromEntries(trState.order.map((id, i) => [id, i + 1]));
    let t = `Your order is ${d.distance} away from the model's (0 = identical; the largest possible is about ${d.max}).\n\n`;
    model.forEach((s, i) => { t += `${String(i + 1).padStart(2)}. ${s.name.slice(0, 44).padEnd(44)} score ${s.score.toFixed(1).padStart(5)}  (${s.life} + ${s.mig}) × ${s.kind === "sig" ? 0.6 : P.EXPOSURE_W[s.exposure]}   you: ${pos[s.id]}\n`; });
    if (d.same) t += "\n# identical to the model's order: a very good instinct, or a lucky shuffle.";
    $("tr-out").textContent = t.trimEnd();
  }
  function trInit() {
    trState.order = shuffled(P.ESTATE.map((s) => s.id)); trRender();
    $("tr-list").addEventListener("click", (e) => {
      const b = e.target.closest("button[data-d]"); if (!b) return;
      const id = b.closest("li").dataset.id, i = trState.order.indexOf(id), j = i + (+b.dataset.d);
      if (j < 0 || j >= trState.order.length) return;
      [trState.order[i], trState.order[j]] = [trState.order[j], trState.order[i]]; trRender();
    });
    on("tr-compare", "click", trCompare);
    on("tr-shuffle", "click", () => { trState.order = shuffled(trState.order); trRender(); $("tr-out").textContent = ""; });
    on("tr-reset", "click", () => { trState.order = P.triageOrder().map((s) => s.id); trRender(); trCompare(); });
  }

  // --------------------------------------------------------------------------- agility quiz
  const agState = { i: 0, score: 0, answered: false };
  function agShow() {
    const q = P.AGILITY[agState.i];
    $("ag-count").textContent = `Snippet ${agState.i + 1} of ${P.AGILITY.length}`;
    $("ag-snippet").textContent = q.snippet;
    $("ag-opts").innerHTML = P.AGILITY_CLASSES.map((c) => `<button type="button" data-v="${c.id}">${esc(c.label)}</button>`).join("");
    setVerdict("ag-feed", "", ""); $("ag-next").hidden = true; agState.answered = false;
    $("ag-score").textContent = agState.i ? `Score so far: ${agState.score} of ${agState.i}` : "";
  }
  function agInit() {
    $("ag-opts").addEventListener("click", (e) => {
      const b = e.target.closest("button"); if (!b || agState.answered) return;
      agState.answered = true;
      const q = P.AGILITY[agState.i], right = b.dataset.v === q.answer;
      if (right) agState.score++;
      for (const x of $("ag-opts").querySelectorAll("button")) { x.disabled = true; if (x.dataset.v === q.answer) x.classList.add("right"); else if (x === b) x.classList.add("wrong"); }
      setVerdict("ag-feed", (right ? "Yes. " : "Not quite. ") + q.why, right ? "ok" : "bad");
      const last = agState.i === P.AGILITY.length - 1;
      $("ag-score").textContent = `Score so far: ${agState.score} of ${agState.i + 1}`;
      if (last) {
        let m = `Final: ${agState.score} of ${P.AGILITY.length}.`;
        if (agState.score === P.AGILITY.length) m += "  # a perfect score: you could review the architecture yourself.";
        else if (agState.score === 0) m += "  # zero: agility problems are rarely where you look first. Now you know where to look.";
        $("ag-score").textContent = m; $("ag-next").textContent = "Start again"; $("ag-next").hidden = false;
      } else { $("ag-next").textContent = "Next snippet"; $("ag-next").hidden = false; }
    });
    on("ag-next", "click", () => {
      if (agState.i === P.AGILITY.length - 1) { agState.i = 0; agState.score = 0; } else agState.i++;
      agShow();
    });
    agShow();
  }

  // --------------------------------------------------------------------------- testing: ClientHello size
  function tsRender() {
    const base = +$("ts-base").value || 300, mtu = +$("ts-mtu").value, plain = $("ts-plain").checked;
    const size = base + 1216 + P.HS_ASSUMPTIONS.keyShareHeader + (plain ? 32 + P.HS_ASSUMPTIONS.keyShareHeader : 0), before = base + 32 + P.HS_ASSUMPTIONS.keyShareHeader, pay = mtu - 60;
    const pk = Math.ceil(size / pay), pb = Math.ceil(before / pay);
    $("ts-size").textContent = num(size); $("ts-pkts").textContent = pk; $("ts-before").textContent = num(before) + " B"; $("ts-before-note").textContent = "before hybrid: " + plural(pb, "packet");
    setVerdict("ts-verdict", pk > 1 ? `Doesn't fit one packet (about ${num(pay)} bytes fit): ${pk} packets. Anything that assumes a single-packet ClientHello can fail. Apple documents connection failures with such servers.` : "Fits one packet at this MTU. Check again with every extension you really send.", pk > 1 ? "y" : "ok");
  }

  // --------------------------------------------------------------------------- roadmap builder
  const plState = { regime: "uk", ends: {}, owners: {}, done: {}, custom: { plan: 2027, kex: 2030, sigs: 2032, all: 2035 } };
  function plLoad() {
    P.PHASES.forEach((p) => { plState.ends[p.id] = p.defaultEnd; plState.owners[p.id] = p.owner; plState.done[p.id] = false; });
    let s = null; try { s = JSON.parse(store("pqc-roadmap") || "null"); } catch (e) { s = null; }
    if (s && typeof s === "object") {
      if (s.regime && (P.REGIMES[s.regime] || s.regime === "custom")) plState.regime = s.regime;
      for (const k of ["ends", "owners", "done", "custom"]) if (s[k] && typeof s[k] === "object") Object.assign(plState[k], s[k]);
    }
  }
  const plSave = () => store("pqc-roadmap", JSON.stringify(plState));
  function plRender() {
    const res = P.roadmapCheck(plState.regime, plState.ends, plState.custom);
    const own = P.OWNERS.map((o) => `<option value="${o.id}">${esc(o.label)}</option>`).join("");
    $("pl-body").innerHTML = P.PHASES.map((p, i) => {
      const r = res[i], late = r.noLimit ? null : r.end - r.limit;
      return `<tr class="${plState.done[p.id] ? "done" : ""}" data-id="${p.id}"><td class="chk" data-label="Done"><input type="checkbox" class="pl-done" aria-label="Done: ${esc(p.name)}"${plState.done[p.id] ? " checked" : ""}></td><th>${esc(p.name)}</th><td data-label="Owner"><select class="pl-owner" aria-label="Owner">${own.replace(`value="${plState.owners[p.id]}"`, `value="${plState.owners[p.id]}" selected`)}</select></td><td data-label="Finish in"><input type="number" class="pl-end" min="2026" max="2045" value="${plState.ends[p.id]}" aria-label="Finish year"></td><td class="num" data-label="Limit">${r.noLimit ? "none stated" : r.limit}</td><td data-label="Status"><span class="st ${r.noLimit ? "st-none" : r.ok ? "st-ok" : "st-bad"}">${r.noLimit ? "no limit" : r.ok ? "meets it" : "late by " + late + " y"}</span></td></tr>`;
    }).join("");
    const meets = res.filter((r) => r.ok).length, doneN = P.PHASES.filter((p) => plState.done[p.id]).length;
    let txt = `${meets} of ${P.PHASES.length} phases meet the chosen dates; ${doneN} ticked as done.`;
    if (doneN === P.PHASES.length) txt += "  # all seven phases done. Put the next review in the calendar: the standards and the dates will have moved.";
    setVerdict("pl-sum", txt, meets === P.PHASES.length ? "ok" : "y");
    $("pl-custom").hidden = plState.regime !== "custom";
  }
  function plInit() {
    plLoad();
    const SHORT = { usfed: "US federal, high-impact", usother: "US federal, other", uk: "UK (NCSC)", eu: "EU", nss: "National security (CNSA 2.0)", free: "Private company" };
    const items = tlOrder.map((id) => ({ v: id, label: SHORT[id] })).concat([{ v: "custom", label: "My own dates" }]);
    seg("pl-regime", items, plState.regime, (v) => { plState.regime = v; plSave(); plRender(); });
    for (const [id, k] of [["cu-plan", "plan"], ["cu-kex", "kex"], ["cu-sigs", "sigs"], ["cu-all", "all"]]) { $(id).value = plState.custom[k]; on(id, "input", () => { plState.custom[k] = +$(id).value || plState.custom[k]; plSave(); plRender(); }); }
    $("pl-body").addEventListener("change", (e) => {
      const tr = e.target.closest("tr"); if (!tr) return; const id = tr.dataset.id;
      if (e.target.classList.contains("pl-done")) plState.done[id] = e.target.checked;
      else if (e.target.classList.contains("pl-owner")) plState.owners[id] = e.target.value;
      else if (e.target.classList.contains("pl-end")) plState.ends[id] = +e.target.value || plState.ends[id];
      plSave(); plRender();
    });
    plRender();
  }

  // --------------------------------------------------------------------------- hype and reality
  const clState = { i: 0, score: 0, answered: false };
  function clShow() {
    const c = P.CLAIMS[clState.i];
    $("cl-count").textContent = `Claim ${clState.i + 1} of ${P.CLAIMS.length}`; $("cl-claim").textContent = c.claim;
    $("cl-btns").innerHTML = ["true", "false", "depends"].map((v) => `<button type="button" data-v="${v}" aria-pressed="false">${v === "depends" ? "It depends" : v === "true" ? "True" : "False"}</button>`).join("");
    setVerdict("cl-feed", "", ""); $("cl-next").hidden = true; clState.answered = false;
    $("cl-score").textContent = clState.i ? `Score so far: ${clState.score} of ${clState.i}` : "";
  }
  function clInit() {
    $("cl-btns").addEventListener("click", (e) => {
      const b = e.target.closest("button"); if (!b || clState.answered) return;
      clState.answered = true;
      const c = P.CLAIMS[clState.i], right = b.dataset.v === c.verdict;
      if (right) clState.score++;
      for (const x of $("cl-btns").querySelectorAll("button")) { x.disabled = true; x.setAttribute("aria-pressed", String(x === b)); }
      setVerdict("cl-feed", `${right ? "Right." : "Not quite."} It's ${c.verdict === "depends" ? "\"it depends\"" : c.verdict}. ${c.why}`, right ? "ok" : "bad");
      const last = clState.i === P.CLAIMS.length - 1;
      $("cl-score").textContent = `Score so far: ${clState.score} of ${clState.i + 1}`;
      if (last) {
        let m = `Final: ${clState.score} of ${P.CLAIMS.length}.`;
        if (clState.score === P.CLAIMS.length) m += "  # eight for eight: you can sit through any quantum keynote now.";
        $("cl-score").textContent = m; $("cl-next").textContent = "Start again"; $("cl-next").hidden = false;
      } else { $("cl-next").textContent = "Next claim"; $("cl-next").hidden = false; }
    });
    on("cl-next", "click", () => { if (clState.i === P.CLAIMS.length - 1) { clState.i = 0; clState.score = 0; } else clState.i++; clShow(); });
    clShow();
  }

  // --------------------------------------------------------------------------- wire everything up
  function init() {
    on("hero-in", "input", hero); hero();
    brInit();
    for (const id of ["hn-crqc", "hn-kex", "hn-sig", "hn-resign"]) on(id, "input", hnRender); hnRender();
    seg("es-filter", [{ v: "all", label: "All" }, { v: "rsa", label: "RSA-2048" }, { v: "ecc", label: "Elliptic curves" }], "all", (v) => { esState.f = v; esRender(); }); esRender();
    for (const id of ["mo-early", "mo-late", "mo-mult"]) on(id, "input", moRender); moRender();
    seg("tl-pick", tlOrder.map((id) => ({ v: id, label: P.REGIMES[id].label })), "uk", tlRender); $("tl-pick").className = "seg-col"; tlRender("uk");
    laNewKey(); laStats();
    on("la-noise", "input", () => { laNewKey(); laStats(); }); on("la-key", "click", () => { laNewKey(); laStats(); }); on("la-enc", "click", laEnc); on("la-solve", "click", laSolve);
    seg("km-seg", [{ v: "mlkem512", label: "ML-KEM-512" }, { v: "mlkem768", label: "ML-KEM-768" }, { v: "mlkem1024", label: "ML-KEM-1024" }], "mlkem768", (v) => { kmState.set = v; kmRender(); }); kmRender();
    on("km-run", "click", kmRun); kmRun();
    seg("sg-use", Object.entries(P.SIG_USES).map(([k, v]) => ({ v: k, label: v.label })), "tls", sgRender); sgRender("tls");
    szInit();
    on("hy-run", "click", hyRun); on("hy-brokeX", "change", hyRender); on("hy-brokeK", "change", hyRender); hyRender();
    prInit();
    for (const id of ["pk-certs", "pk-scts"]) on(id, "change", pkRender);
    $("pk-alg").innerHTML = ["ecdsa256", "mldsa44", "mldsa65", "mldsa87", "slh128s"].map((id) => `<option value="${id}">${esc(P.byId(P.SIGS, id).name)}</option>`).join(""); on("pk-alg", "change", pkRender); pkRender();
    snUpd = seg("sn-upd", [{ v: "yes", label: "Yes" }, { v: "partly", label: "Partly" }, { v: "no", label: "No" }], "no", snRender);
    for (const id of ["sn-life", "sn-ship", "sn-crqc"]) on(id, "input", snRender); snRender();
    ivInit(); trInit(); agInit();
    for (const id of ["ts-base", "ts-mtu", "ts-plain"]) on(id, "input", tsRender); tsRender();
    plInit(); clInit();
    try { console.log("%cPost-quantum migration", "font:700 14px monospace;color:#ff2e88", "\nThe logic is in window.Pqc, and every demo runs on invented data.\nTry: Pqc.mosca({ shelf: 15, migration: 5, crqcYear: 2035 })   or   Pqc.handshake({ kex: 'x25519mlkem768', leaf: 'mldsa44', chain: 'mldsa44' })\nAnd on the title slide: type mosca, shor, or a year."); } catch (e) { /* console may be unavailable */ }
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init); else init();
})();
