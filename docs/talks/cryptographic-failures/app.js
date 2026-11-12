/* app.js - the live demos for "Case Studies in Cryptographic Failures".
   Everything here is TEACHING CODE ON INVENTED DATA: toy keys, a toy cipher, a toy compressor and an invented web page.
   Nothing is sent anywhere and nothing attacks a real system. The logic is in broken.js (window.Broken); the hashes are
   the from-scratch SHA-256 in ../../shared/crypto.js (window.Lab), which must never be used to protect real data. */
(function () {
  "use strict";
  const L = window.Lab, B = window.Broken;

  // --------------------------------------------------------------------------- helpers
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const click = (id, fn) => $(id).addEventListener("click", fn);
  const num = (n) => Number(n).toLocaleString("en-US");
  const rand = B.cryptoRand;
  function store(key, val) {
    try { if (val === undefined) return localStorage.getItem(key); localStorage.setItem(key, val); } catch (e) { /* storage can be blocked */ }
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
  const setVerdict = (id, text, tone) => { const el = $(id); el.textContent = text; el.className = "verdict" + (tone ? " " + tone : ""); };
  const iBytes = (n) => {                           // binary units, as the Sweet32 authors use for "32 GB"
    const u = ["bytes", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB"]; let i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return (n >= 100 ? Math.round(n) : +n.toFixed(n >= 10 ? 1 : 2)) + " " + u[i];
  };

  // --------------------------------------------------------------------------- title terminal: where does it stand today?
  function heroNote(t, low, e) {
    if (t === "") return "# nothing typed. Try an old name (ssl 3.0, rc4, 3des, md5, sha-1, export, wep) or a case (poodle, heartbleed).";
    if (/^(4|dice|xkcd|xkcd 221)$/.test(low)) return "# return 4; // chosen by fair dice roll. A well-known comic, and fail0verflow's 27C3 slide borrowed it to illustrate the PS3 signing bug. A constant is not random.";
    if (low === "poodle") return "# POODLE: Padding Oracle On Downgraded Legacy Encryption. A backronym, and an accurate one: SSL 3.0, advisory of September 2014, CVE-2014-3566.";
    if (low === "heartbleed") return "# Heartbleed: CVE-2014-0160, fixed in OpenSSL 1.0.1g on 7 April 2014. OpenSSL's advisory calls it a missing bounds check: not a flaw in TLS.";
    if (low === "freak") return "# FREAK: Factoring attack on RSA-EXPORT Keys, announced 3 March 2015. The 'export' is the 1990s rule that made the weak suites exist.";
    if (low === "logjam") return "# Logjam: disclosed 20 May 2015. The paper later won a Best Paper award at ACM CCS 2015.";
    if (low === "drown") return "# DROWN, March 2016: one server still speaking SSLv2 could endanger every server that shares its key.";
    if (low === "sweet32") return "# 2^32 blocks of 8 bytes is 32 GiB: the birthday bound for a 64-bit block cipher. The name has a 32 in it too.";
    if (low === "krack") return "# KRACK: Key Reinstallation Attack, disclosed 16 October 2017. The researchers say changing your Wi-Fi password doesn't help: patch the devices.";
    if (low === "roca") return "# ROCA stands for Return Of Coppersmith's Attack: the researchers extended an older attack to this prime shape. The paper's title says so.";
    if (low === "debian") return "# Debian's fix landed on 13 May 2008 (DSA-1571). The advice that mattered: regenerate every key made on an affected system.";
    if (low === "rot13") return "# rot13 isn't on the list: it was never a cipher, just a Caesar shift that undoes itself. Crypto 101's Caesar slide breaks one live.";
    if (e) return "# every entry here was once normal. Run the same check on your own servers and see which ones are still switched on.";
    return "# not in my list. Try: ssl 3.0, tls 1.0, rc4, 3des, md5, sha-1, export, static rsa, cbc, compression, wep, dual_ec, tls 1.2, tls 1.3, aes-gcm.";
  }
  function hero() {
    const el = $("hero-in");
    el.style.width = Math.max(10, Math.min(30, el.value.length + 1)) + "ch";
    const t = el.value.trim(), low = t.toLowerCase().replace(/[_\s]+/g, " ").trim();
    const e = B.audit(t);
    $("hero-out").innerHTML = e
      ? `<span class="au-row"><b class="au-label">${esc(e.label)}</b><span class="au-tag ${e.tone}">${esc(e.verdict)}</span><small>${esc(e.when)}</small></span><span class="au-why">${esc(e.why)}</span><small class="au-src">source: ${esc(e.src)}</small>`
      : "";
    $("hero-note").textContent = heroNote(t, low, e);
  }

  // --------------------------------------------------------------------------- Debian: the blocklist
  const dbg = { list: null, bits: 15, rate: 0 };
  function dbgRate() {
    const t0 = performance.now(); let n = 0;
    while (performance.now() - t0 < 25) { B.toyKey(n + 1); n++; }
    return n / (performance.now() - t0) * 1000;
  }
  function dbgScale() {
    const r = dbg.rate || dbgRate();
    $("dbg-scale").textContent = "At this device's speed (about " + num(Math.round(r)) + " keys a second): 15 bits take " + B.humanTime(2 ** 15 / r) +
      "; 32 bits, " + B.humanTime(2 ** 32 / r) + "; 64 bits, " + B.humanTime(2 ** 64 / r) + "; 128 bits, " + B.humanTime(2 ** 128 / r) + ".";
  }
  function dbgBuild() {
    const bits = +$("dbg-bits").value;
    const t0 = performance.now(), set = B.blocklist(bits), dt = Math.max(performance.now() - t0, 0.5);
    dbg.list = set; dbg.bits = bits; dbg.rate = set.size / dt * 1000;
    $("dbg-n").textContent = num(set.size);
    $("dbg-t").textContent = B.humanTime(dt / 1000);
    $("dbg-r").textContent = num(Math.round(dbg.rate));
    dbgScale();
    $("dbg-key").textContent = ""; setVerdict("dbg-verdict", bits === 18 ? "# " + num(set.size) + " keys listed: all 18 bits. Debian's real figure was 32,767 per architecture; a bigger seed only buys a bigger list, until it is too big to list." : "List built. Now make a key and check it.", bits === 18 ? "y" : "");
  }
  function dbgKey(kind) {
    let fp, label;
    if (kind === "weak") { const seed = 1 + Math.floor(rand() * (2 ** +$("dbg-bits").value - 1)); fp = B.toyKey(seed); label = "seed " + seed + " (a process ID) → key " + fp; }
    else { fp = B.goodKey(); label = "128 random bits → key " + fp; }
    $("dbg-key").textContent = label;
    if (!dbg.list) return setVerdict("dbg-verdict", "Build the list first, then check this key against it.", "y");
    if (dbg.list.has(fp)) setVerdict("dbg-verdict", "On the list. This key is one of the " + num(dbg.list.size) + " a defender can enumerate: replace it.", "bad");
    else if (kind === "weak") setVerdict("dbg-verdict", "Not on the list: this key was made with a bigger seed than the list covers. Rebuild at the slider's size.", "y");
    else setVerdict("dbg-verdict", "Not on the list. It came from 128 random bits, and nobody can list 2^128 keys.", "ok");
  }

  // --------------------------------------------------------------------------- ROCA: the public fingerprint
  const rk = { kind: "plain" };
  const shortHex = (n) => { const h = n.toString(16); return h.length > 18 ? h.slice(0, 8) + "…" + h.slice(-8) : h; };
  function tiles(f) { return '<span class="rk-tiles" aria-hidden="true">' + f.rows.map((r) => `<i class="${r.pass ? "ok" : "no"}" title="mod ${r.l}: ${r.pass ? "in" : "not in"} the group of 65537"></i>`).join("") + "</span><small>" + f.matches + " of " + f.rows.length + "</small>"; }
  function rkGen() {
    const rows = [];
    for (let i = 0; i < 5; i++) { const k = B.genKey(rand, rk.kind, 112); rows.push({ n: k.n, f: B.fingerprint(k.n) }); }
    $("rk-body").innerHTML = rows.map((r) => `<tr><td class="mono">${shortHex(r.n)}</td><td>${tiles(r.f)}</td><td>${r.f.structured ? '<span class="chip chip-bad">flagged</span>' : '<span class="chip chip-ok">not flagged</span>'}</td></tr>`).join("");
    const flagged = rows.filter((r) => r.f.structured).length;
    setVerdict("rk-out", flagged + " of 5 keys flagged. The test read only the public modulus.", flagged ? "bad" : "ok");
  }
  function rkTest() {
    const n = B.parseModulus($("rk-in").value);
    if (n === null || n < 3n) return setVerdict("rk-out", "I can't read that as a number. Paste hex or decimal digits.", "y");
    const f = B.fingerprint(n);
    setVerdict("rk-out", f.structured ? "Passes all " + f.rows.length + " tests: consistent with the structured form. A random number would do this about 1 time in " + num(Math.round(B.falsePositiveOdds().oneIn)) + "." : "Fails " + (f.rows.length - f.matches) + " of " + f.rows.length + " tests: not the structured form.", f.structured ? "bad" : "ok");
  }

  // --------------------------------------------------------------------------- the birthday bound
  function bdBits() { const v = +$("bd-bits").value; $("bd-bits-out").textContent = v; $("bd-expect").textContent = num(Math.round(B.birthdayExpected(v))); $("bd-pre").textContent = num(2 ** v); }
  function bdGo() {
    const bits = +$("bd-bits").value, btn = $("bd-go");
    btn.disabled = true; setVerdict("bd-verdict", "Searching…", "");
    setTimeout(() => {
      const salt = L.hex(L.randBytes(4)), t0 = performance.now();
      const r = B.birthday(bits, salt), dt = performance.now() - t0;
      $("bd-trials").textContent = num(r.trials);
      const hexLen = Math.ceil(bits / 4);
      $("bd-out").textContent = "message A:  " + r.a + "\nmessage B:  " + r.b + "\nSHA-256, first " + bits + " bits of both:  0x" + r.value.toString(16).padStart(hexLen, "0") + "\ntime here:  " + B.humanTime(dt / 1000);
      const ratio = r.trials / B.birthdayExpected(bits);
      setVerdict("bd-verdict", bits === 32
        ? "# 32 bits: about " + num(Math.round(B.birthdayExpected(32))) + " hashes and a few seconds here. A full SHA-256 collision would need about 2^128 of them."
        : "A collision after " + num(r.trials) + " messages: " + ratio.toFixed(2) + " × the expected number. A chosen hash would have needed about " + num(2 ** bits) + ".", "ok");
      btn.disabled = false;
    }, 30);
  }

  // --------------------------------------------------------------------------- padding oracle on a toy cipher
  const og = { demo: null, mode: "distinct" };
  function ogNew() { og.demo = B.makeCipherDemo(rand, "pin=4271"); ogRender(); }
  function ogRender() {
    const d = og.demo, target = d.blocks[0];
    $("og-ct").textContent = "toy ciphertext  IV " + L.hex(d.iv) + " · block 1 " + L.hex(d.blocks[0]) + " · block 2 " + L.hex(d.blocks[1]);
    const cells = B.oracleGrid(d.key, target, og.mode);
    $("og-grid").innerHTML = cells.map((c) => `<i class="og-c${c.ok && og.mode !== "uniform" ? " lit" : ""}" title="altered byte 0x${c.g.toString(16).padStart(2, "0")}: ${esc(c.text)}"></i>`).join("");
    const res = B.lastByteFromGrid(d.key, target, d.iv, cells, og.mode);
    if (og.mode === "uniform") setVerdict("og-out", "# every cell identical: all 256 answers read \"decryption failed\". The server tells a sender nothing, which is the defence.", "ok");
    else if (res.known) {
      const ch = res.byte >= 32 && res.byte < 127 ? '"' + String.fromCharCode(res.byte) + '"' : "(not printable)";
      setVerdict("og-out", (res.lit > 1 ? res.lit + " cells lit: the extras are longer paddings that happen to be valid, and one more question tells them apart. " : "One cell lit: ") + "altered byte 0x" + res.g.toString(16).padStart(2, "0") + " gave valid padding, which means the hidden block's last byte is 0x" + res.byte.toString(16).padStart(2, "0") + " " + ch + ".", "bad");
    } else setVerdict("og-out", "No cell lit this time.", "y");
  }

  // --------------------------------------------------------------------------- negotiation lab
  function dgChecks(id, onChange) {
    $(id).innerHTML = B.VERS.map((v) => `<label class="check"><input type="checkbox" data-v="${esc(v)}" checked> ${esc(v)}</label>`).join("");
    $(id).addEventListener("change", onChange);
  }
  const dgSet = (id) => [...$(id).querySelectorAll("input:checked")].map((i) => i.dataset.v);
  function dgRun() {
    const o = { client: dgSet("dg-client"), server: dgSet("dg-server"), attacker: $("dg-attacker").checked, dance: $("dg-dance").checked, scsv: $("dg-scsv").checked, sentinel: $("dg-sent").checked, serverExport: $("dg-export").checked };
    const r = B.negotiate(o);
    $("dg-log").innerHTML = r.steps.map((s) => `<li>${esc(s)}</li>`).join("") || "<li>Nothing happened: the client supports no version.</li>";
    const tone = { safe: "ok", weak: "bad", defended: "ok", blocked: "y", failed: "y" }[r.outcome];
    const head = { safe: "Negotiated " + r.version + ". ", weak: "Negotiated " + r.version + ": downgraded. ", defended: "Connection refused: the defence worked. ", blocked: "No connection. ", failed: "No connection. " }[r.outcome];
    const egg = o.attacker && o.scsv && o.sentinel && r.outcome === "defended" ? " # the attacker pulled every lever and got a refused connection. Failing closed is the point." : "";
    setVerdict("dg-verdict", head + r.note + egg, tone);
    $("dg-export-note").textContent = r.exportNote;
  }

  // --------------------------------------------------------------------------- Sweet32: how much data until blocks collide?
  let swBits;
  function swRun() {
    const bits = +swBits.get(), rate = +$("sw-rate").value;
    const blocks = 2 ** (bits / 2), bytes = blocks * bits / 8, secs = bytes * 8 / (rate * 1e6);
    $("sw-blocks").textContent = "2^" + bits / 2;
    $("sw-data").textContent = iBytes(bytes);
    $("sw-time").textContent = B.humanTime(secs);
    setVerdict("sw-verdict", bits === 64
      ? "Past the birthday bound after " + iBytes(bytes) + ": a long-lived connection gets there. Rekey, or stop using 64-bit blocks."
      : "Nobody sends " + iBytes(bytes) + " under one key. 128-bit blocks put the bound out of reach.", bits === 64 ? "bad" : "ok");
  }

  // --------------------------------------------------------------------------- compression leak, on an invented page
  const cx = { secret: "", known: "", mode: "none" };
  function cxPageText() {
    const page = B.pageFor(cx.secret, cx.known + "?", cx.mode, rand);
    return cx.mode === "mask"
      ? page.replace(/value="[0-9a-f]{24}"/, 'value="(24 hidden characters, a different masked value on every response)"')
      : page.replace(/value="[0-9a-f]{12}"/, 'value="(12 hidden characters)"');
  }
  function cxRender(msg, tone) {
    $("cx-page").textContent = cxPageText().replace(/(<\/form>)/, "$1\n").replace(/(<form[^>]*>)/, "$1\n");
    $("cx-known").textContent = cx.known || "(none)";
    const done = cx.known.length >= cx.secret.length;
    const rows = done ? [] : B.leakTable(cx.secret, cx.known, cx.mode, rand);
    $("cx-cands").innerHTML = rows.map((r) => `<button type="button" class="cx-c${r.best ? " min" : ""}" data-c="${r.c}" aria-label="Lock in ${r.c}: page length ${r.size}"><b>${r.c}</b><small>${r.size}</small></button>`).join("");
    if (msg) setVerdict("cx-note", msg, tone);
  }
  function cxNew() { cx.secret = B.makeSecret(rand); cx.known = ""; cxRender(cx.mode === "none" ? "Each number is the page's compressed length if that character were next. The shortest is highlighted. Click one to lock it in." : "Same page, different defence. Click a character and see if the numbers can still tell you.", ""); }
  function cxPick(c) {
    const real = cx.secret[cx.known.length];
    if (c === real) {
      cx.known += c;
      if (cx.known.length === cx.secret.length) return cxRender("# all " + cx.secret.length + " characters locked in, from lengths alone. That's why the fixes are about the page, not the cipher.", "bad");
      return cxRender("✓ Locked in " + c + ". " + (cx.secret.length - cx.known.length) + " to go.", "ok");
    }
    cxRender("✗ Not the real character. " + (cx.mode === "none" ? "Look again: the real one is the shortest." : "With this defence the lengths don't identify it: that's the point. Measure again, or pick another."), cx.mode === "none" ? "y" : "ok");
  }

  // --------------------------------------------------------------------------- how long did each flaw live?
  let lfSort;
  const yearsOf = (l) => B.years(l.from, l.to);
  function lfDraw() {
    const items = B.LIFE.slice().sort(lfSort.get() === "years" ? (a, b) => yearsOf(b) - yearsOf(a) : (a, b) => Date.parse(a.from) - Date.parse(b.from));
    const max = Math.max(...items.map(yearsOf));
    $("lf-chart").innerHTML = items.map((l) => {
      const y = yearsOf(l);
      return `<button type="button" class="lf-row" role="listitem" data-id="${l.id}"><span class="lf-name">${esc(l.name)}</span><span class="lf-bar"><i style="width:${(y / max * 100).toFixed(1)}%"></i></span><span class="lf-val">${l.approx ? "≈ " : ""}${y.toFixed(1)} yrs</span></button>`;
    }).join("");
  }
  function lfShow(id) {
    const l = B.LIFE.find((x) => x.id === id), y = yearsOf(l);
    for (const b of $("lf-chart").querySelectorAll(".lf-row")) b.classList.toggle("on", b.dataset.id === id);
    $("lf-detail").innerHTML = `<h3>${esc(l.name)}</h3><div class="lf-d"><b>From</b><span>${esc(l.fromLabel)}</span></div><div class="lf-d"><b>To</b><span>${esc(l.toLabel)}</span></div><div class="lf-d"><b>Lived</b><span>${l.approx ? "about " : ""}${y.toFixed(1)} years before it was public</span></div><div class="lf-d"><b>Found by</b><span>${esc(l.found)}</span></div>${l.approx ? '<p class="fine">An approximate start: the source gives a year or "at the latest".</p>' : ""}`;
  }

  // --------------------------------------------------------------------------- root-cause map
  const so = { picks: {}, revealed: false, focus: null };
  function soDraw() {
    $("so-list").innerHTML = B.CASES.map((c) => {
      const pick = so.picks[c.id] || "";
      const opts = '<option value="">choose…</option>' + B.CATS.map((k) => `<option value="${k.id}"${pick === k.id ? " selected" : ""}>${esc(k.name)}</option>`).join("");
      let st = "";
      if (so.revealed) {
        if (!pick) st = `<span class="so-st n" title="my category">${esc(B.catName(c.cat))}</span>`;
        else if (pick === c.cat) st = '<span class="so-st ok">✓ same</span>';
        else if (pick === c.also) st = '<span class="so-st y">≈ second choice</span>';
        else st = `<span class="so-st bad" title="my category">≠ ${esc(B.catName(c.cat))}</span>`;
      }
      return `<div class="so-row${so.focus === c.id ? " on" : ""}" role="listitem"><button type="button" class="so-name" data-case="${c.id}"><b>${esc(c.name)}</b><small>${esc(c.year)}</small></button><select data-case="${c.id}" aria-label="Category for ${esc(c.name)}">${opts}</select>${st}</div>`;
    }).join("");
    const placed = Object.keys(so.picks).length;
    $("so-done").textContent = placed + " / " + B.CASES.length;
    soDetail();
    if (!so.revealed) { $("so-match").textContent = "–"; $("so-algo").textContent = "–"; return; }
    let match = 0, close = 0;
    for (const c of B.CASES) { const p = so.picks[c.id]; if (p === c.cat) match++; else if (p && p === c.also) close++; }
    $("so-match").textContent = match; $("so-algo").textContent = close;
    const all = placed === B.CASES.length;
    setVerdict("so-verdict", all && match === B.CASES.length ? "# twelve for twelve: you could have drawn the map yourself."
      : all && match === 0 ? "# no matches: you disagree with every call, which is a fine way to start an argument."
      : placed ? match + " of your " + placed + " match my map, and " + close + " more match my second choice." : "Place a few first, or just read my map.", "ok");
  }
  function soDetail() {
    const el = $("so-detail");
    if (!so.focus) { el.innerHTML = so.revealed ? "<span>Click a case name to read my reasoning.</span>" : ""; return; }
    const c = B.CASES.find((x) => x.id === so.focus);
    el.innerHTML = so.revealed
      ? `<div><b>${esc(c.name)}: my category</b><span>${esc(B.catName(c.cat))}${c.also ? " (also fits: " + esc(B.catName(c.also)) + ")" : ""}</span></div><div><b>Was the algorithm broken?</b><span>${esc(c.algo)}</span></div><div><b>Why</b><span>${esc(c.note)}</span></div>`
      : "<span>Reveal my map to read the reasoning.</span>";
  }

  // --------------------------------------------------------------------------- which control would have helped?
  function cfShow(id) {
    const c = B.CASES.find((x) => x.id === id), k = B.CONTROLS[id];
    for (const b of $("cf-chips").querySelectorAll(".chip")) b.setAttribute("aria-pressed", String(b.dataset.id === id));
    $("cf-detail").innerHTML = `<h3>${esc(c.name)} <small>${esc(c.year)}</small></h3><p class="cf-algo">${esc(c.algo)}</p>` +
      [["Prevent", k.prevent], ["Detect", k.detect], ["Limit the damage", k.limit]].map(([a, b]) => `<div class="fa-row"><b>${a}</b><span>${esc(b)}</span></div>`).join("");
  }

  // --------------------------------------------------------------------------- audit checklist
  function auditInit() {
    let saved = []; try { saved = JSON.parse(store("crypto-failures-audit") || "[]"); } catch (e) { saved = []; }
    $("au-plan").innerHTML = B.AUDIT.map((t, i) => `<label><input type="checkbox" data-i="${i}"${saved.includes(i) ? " checked" : ""}> <span>${esc(t)}</span></label>`).join("");
    const upd = () => {
      const on = [...$("au-plan").querySelectorAll("input:checked")].map((x) => +x.dataset.i);
      store("crypto-failures-audit", JSON.stringify(on));
      setVerdict("au-note", on.length === B.AUDIT.length ? "# all twelve. Next step: pick the one you ticked fastest and check it is really true." : on.length + " of " + B.AUDIT.length + " ticked. Start with the one that would take the least time.", on.length === B.AUDIT.length ? "ok" : "");
    };
    $("au-plan").addEventListener("change", upd); upd();
  }

  // --------------------------------------------------------------------------- console hint
  function consoleHint() {
    console.log("%c" + document.title, "font: 700 24px monospace; color: #ff2e88; text-shadow: 0 0 8px #ff2e88");
    console.log("%cEverything here is teaching code on invented data. window.Broken holds the logic: try Broken.audit('rc4'), Broken.fingerprint(1234567n) or Broken.birthday(16, 'x').", "font: 14px monospace; color: #00f0ff");
  }

  // --------------------------------------------------------------------------- start
  function start() {
    consoleHint();
    $("hero-in").addEventListener("input", hero); hero();

    $("dbg-bits").addEventListener("input", () => { $("dbg-bits-out").textContent = $("dbg-bits").value; });
    click("dbg-build", dbgBuild); click("dbg-weak", () => dbgKey("weak")); click("dbg-good", () => dbgKey("good"));
    dbgScale();

    seg("rk-kind", [{ v: "plain", label: "Ordinary random primes" }, { v: "roca", label: "Structured primes (ROCA-like)" }], "plain", (v) => { rk.kind = v; rkGen(); });
    click("rk-gen", rkGen); click("rk-test", rkTest);
    $("rk-in").addEventListener("keydown", (e) => { if (e.key === "Enter") rkTest(); });
    const odds = B.falsePositiveOdds();
    $("rk-odds").textContent = "A random modulus passes all " + B.ROCA_PRIMES.length + " tests about 1 time in " + num(Math.round(odds.oneIn)) + "; the real test uses more primes (the paper's example: 2^-154 for 512-bit keys). Toy 224-bit moduli, not the real format.";
    rkGen();

    $("bd-bits").addEventListener("input", bdBits); bdBits(); click("bd-go", bdGo);

    seg("og-mode", [{ v: "distinct", label: "Distinct errors" }, { v: "uniform", label: "One uniform error" }], "distinct", (v) => { og.mode = v; ogRender(); });
    click("og-new", ogNew); ogNew();

    dgChecks("dg-client", dgRun); dgChecks("dg-server", dgRun);
    for (const id of ["dg-attacker", "dg-dance", "dg-scsv", "dg-sent", "dg-export"]) $(id).addEventListener("change", dgRun);
    dgRun();

    swBits = seg("sw-bits", [{ v: "64", label: "64-bit blocks (3DES, Blowfish)" }, { v: "128", label: "128-bit blocks (AES)" }], "64", swRun);
    $("sw-rate").addEventListener("change", swRun); swRun();

    seg("cx-mode", [{ v: "none", label: "No defence" }, { v: "mask", label: "Mask the token" }, { v: "pad", label: "Random padding" }, { v: "off", label: "Compression off" }], "none", (v) => { cx.mode = v; cxNew(); });
    click("cx-new", cxNew); click("cx-again", () => cxRender("Measured again.", ""));
    $("cx-cands").addEventListener("click", (e) => { const b = e.target.closest("button[data-c]"); if (b) cxPick(b.dataset.c); });
    cxNew();

    lfSort = seg("lf-sort", [{ v: "years", label: "Longest first" }, { v: "start", label: "Earliest start" }], "years", () => { lfDraw(); });
    lfDraw();
    $("lf-chart").addEventListener("click", (e) => { const b = e.target.closest(".lf-row"); if (b) lfShow(b.dataset.id); });
    lfShow(B.LIFE.slice().sort((a, b) => yearsOf(b) - yearsOf(a))[0].id);

    soDraw();
    $("so-list").addEventListener("change", (e) => {
      const sel = e.target.closest("select[data-case]"); if (!sel) return;
      if (sel.value) so.picks[sel.dataset.case] = sel.value; else delete so.picks[sel.dataset.case];
      so.focus = sel.dataset.case; soDraw();
      const again = $("so-list").querySelector('select[data-case="' + sel.dataset.case + '"]'); if (again) again.focus();
    });
    $("so-list").addEventListener("click", (e) => { const b = e.target.closest("button[data-case]"); if (b) { so.focus = b.dataset.case; soDraw(); } });
    click("so-reveal", () => { so.revealed = true; soDraw(); });
    click("so-reset", () => { so.picks = {}; so.revealed = false; so.focus = null; setVerdict("so-verdict", "", ""); soDraw(); });

    $("cf-chips").innerHTML = B.CASES.map((c) => `<button type="button" class="chip" data-id="${c.id}" aria-pressed="false">${esc(c.name)}</button>`).join("");
    $("cf-chips").addEventListener("click", (e) => { const b = e.target.closest("button[data-id]"); if (b) cfShow(b.dataset.id); });
    cfShow("debian");

    auditInit();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
})();
