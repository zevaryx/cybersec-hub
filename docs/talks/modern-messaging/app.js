/* app.js - the live demos for "Modern Messaging Protocols".
   The cryptography is real (X25519, HMAC-SHA-256, HKDF-SHA-256, AES-128-GCM from ../../shared/crypto.js, protocol logic in ratchet.js),
   but it is teaching code: never use it for real messages. Everything runs in your browser and nothing you type is stored or sent
   (only the checklist's ticks are kept in this browser). */
(function () {
  "use strict";

  // --------------------------------------------------------------------------- helpers
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  function click(id, fn) { $(id).addEventListener("click", fn); }
  function store(key, val) {
    try { if (val === undefined) return localStorage.getItem(key); localStorage.setItem(key, val); } catch (e) {}
    return null;
  }
  function press(group, value) {
    for (const b of group.querySelectorAll("button")) b.setAttribute("aria-pressed", String(b.getAttribute("data-v") === value));
  }
  function seg(id, fn) {
    const g = $(id);
    g.addEventListener("click", (e) => { const b = e.target.closest("button"); if (b && g.contains(b)) fn(b.getAttribute("data-v"), b); });
  }
  const L = window.Lab, M = window.Msg;
  const hx = (b, n = 5) => L.hex(b.subarray(0, n)) + (b.length > n ? "…" : "");
  const ZERO32 = new Uint8Array(32);
  const msgText = (id, fallback) => { const v = $(id).value; return v.length ? v : fallback; };
  const comment = (id, text, cls) => { const el = $(id); el.textContent = text; el.className = "comment" + (cls ? " " + cls : ""); };
  const nf = (n) => Number(n).toLocaleString("en-US");

  // --------------------------------------------------------------------------- title terminal: one chain key, a new key for every message
  const heroChain = L.randBytes(32);
  function hero() {
    const input = $("hero-in"), out = $("hero-out");
    function render() {
      const raw = input.value, t = raw.trim().toLowerCase();
      let ck = heroChain.slice(); const keys = [];
      for (let i = 0; i < 3; i++) { const r = M.kdfCK(ck); ck = r[0]; keys.push(r[1]); }
      const sealed = M.seal(keys[0], L.utf8(raw), new Uint8Array(0));
      out.innerHTML =
        `<span class="hl"><b>chain key</b>${hx(heroChain, 7)} (secret)</span>` +
        `<span class="hl"><b>key 1</b>${hx(keys[0], 7)}</span>` +
        `<span class="hl"><b>sealed</b>${hx(sealed.ct, 7)} + 16-byte tag</span>` +
        `<span class="hl del"><b>key 2</b>${hx(keys[1], 7)}</span>` +
        `<span class="hl del"><b>key 3</b>${hx(keys[2], 7)}</span>`;
      let note = "# one chain, three messages, three different keys. Each key is used once, then deleted.";
      if (!raw.length) note = "# an empty message still gets its own key and a 16-byte tag. Silence is authenticated too.";
      else if (t === "knock knock") note = "# who's there? Nobody can say: the key that opened that door was deleted after one use.";
      else if (t === "ratchet") note = "# a ratchet only turns one way, like the tool in a socket set, and so does this chain of keys.";
      else if (t === "forward secrecy") note = "# the name for what this terminal does: yesterday's keys can't be rebuilt from today's.";
      else if (t === "meet at noon") note = "# the same message as in Using Crypto Correctly in Code. There it was sealed once; here every message gets its own key.";
      else if (["alice", "bob", "eve", "mallory"].includes(t)) note = "# Alice and Bob talk, Eve listens, Mallory tampers: cryptography's cast of thought experiments. Nobody real is involved.";
      else if (["signal", "whatsapp", "imessage"].includes(t)) note = "# the same family of ideas sits behind several apps. This talk is about the ideas, not the brands.";
      comment("hero-note", note);
    }
    const fit = () => { input.style.width = Math.max(8, input.value.length + 1) + "ch"; };
    input.addEventListener("input", () => { fit(); render(); });
    fit(); render();
  }

  // --------------------------------------------------------------------------- slide 4: two people, one secret
  const ss = { step: 0, picks: 0, n: 0 };
  function ssRender() {
    const s = ss, d = "—";
    const k1 = s.step >= 1, k2 = s.step >= 2, k3 = s.step >= 3;
    const rows = [
      ["Secret key", k1 ? hx(s.a.priv) : d, "never seen", k1 ? hx(s.b.priv) : d],
      ["Public key", k1 ? hx(s.a.pub) : d, k2 ? "both public keys" : d, k1 ? hx(s.b.pub) : d],
      ["Shared secret", k2 ? hx(s.sa) : d, k2 ? "can't compute it" : d, k2 ? hx(s.sb) : d],
      ["Message key (HKDF)", k3 ? hx(s.mk) : d, k3 ? "can't compute it" : d, k3 ? hx(s.mkB) : d],
      ["The message", k3 ? esc(s.text) : d, k3 ? "ciphertext " + hx(s.ct, 8) : d, k3 ? esc(s.got) : d],
    ];
    $("ss-rows").innerHTML = rows.map((r, i) =>
      `<tr class="${i === 2 && k2 ? "match" : ""}"><th>${r[0]}</th><td class="hx">${r[1]}</td><td class="eve">${r[2]}</td><td class="hx">${r[3]}</td></tr>`).join("");
    $("ss-pick").disabled = false;
    $("ss-swap").disabled = s.step !== 1;
    $("ss-send").disabled = s.step < 2;
  }
  function ssInit() {
    click("ss-pick", () => {
      ss.picks++; ss.a = M.genKeyPair(); ss.b = M.genKeyPair(); ss.step = 1; ss.n = 0;
      ssRender();
      comment("ss-note", ss.picks === 10 ? "# ten pairs of keys, ten different shared secrets: no two conversations share one."
        : "Each side made a private key (never sent) and a public key. Nothing has crossed the network yet.");
    });
    click("ss-swap", () => {
      ss.sa = M.dh(ss.a.priv, ss.b.pub); ss.sb = M.dh(ss.b.priv, ss.a.pub); ss.step = 2;
      ssRender();
      const same = L.equalBytes(ss.sa, ss.sb);
      comment("ss-note", same ? "Both sides computed the same 32-byte secret. The listener saw both public keys and can't." : "The secrets differ: something went wrong.", same ? "ok" : "bad");
    });
    click("ss-send", () => {
      ss.text = msgText("ss-msg", "Hello"); ss.n++;
      ss.mk = M.hkdf(ZERO32, ss.sa, "demo message " + ss.n, 32);
      const sealed = M.seal(ss.mk, L.utf8(ss.text), new Uint8Array(0));
      const mkB = M.hkdf(ZERO32, ss.sb, "demo message " + ss.n, 32);
      ss.mkB = mkB; ss.ct = sealed.ct;
      ss.got = M.readable(M.open(mkB, sealed.ct, sealed.tag, new Uint8Array(0)));
      ss.step = 3; ssRender();
      comment("ss-note", "The message key came out of the shared secret through HKDF (a new one for each message sent). The listener sees only ciphertext; Bob opens it.", "ok");
    });
    click("ss-reset", () => { ss.step = 0; ss.picks = 0; ssRender(); comment("ss-note", ""); });
    ssRender();
  }

  // --------------------------------------------------------------------------- slide 5: X3DH, with Bob offline
  const px = { step: 0 };
  const pxHex = (b) => (b ? hx(b, 6) : "—");
  function pxRender() {
    const s = px, st = s.start, fin = s.fin;
    const usedOpk = st && st.ok && st.opkIndex >= 0;
    const labels = ["DH1 · Alice's identity × Bob's signed prekey", "DH2 · Alice's ephemeral × Bob's identity", "DH3 · Alice's ephemeral × Bob's signed prekey",
      usedOpk || !st || !st.ok ? "DH4 · Alice's ephemeral × a one-time prekey" : "DH4 · not used (no one-time prekey)"];
    const rows = labels.map((lab, i) => {
      const a = st && st.ok && st.dhs[i] ? hx(st.dhs[i], 6) : "—";
      const b = fin && fin.dhs[i] ? hx(fin.dhs[i], 6) : "—";
      const same = a !== "—" && a === b;
      return `<tr class="${same ? "match" : ""}"><th>${lab}</th><td class="hx">${a}</td><td class="hx">${b}</td></tr>`;
    });
    const sk = st && st.ok ? hx(st.sk, 6) : "—", skb = fin ? hx(fin.sk, 6) : "—";
    rows.push(`<tr class="${fin && sk === skb ? "match" : ""}"><th>Secret (after HKDF)</th><td class="hx">${sk}</td><td class="hx">${skb}</td></tr>`);
    $("px-rows").innerHTML = rows.join("");
    $("px-1").disabled = s.step !== 0;
    $("px-2").disabled = s.step !== 1;
    $("px-3").disabled = !(s.step === 2 && st && st.ok);
    $("px-opk").disabled = s.step !== 0;
    $("px-evil").disabled = s.step >= 2;
  }
  function pxLog(lines) { $("px-log").innerHTML = lines.join("\n"); }
  function pxInit() {
    const lines = [];
    const say = (cls, txt) => { lines.push(`<span class="${cls}">${txt}</span>`); pxLog(lines); };
    click("px-1", () => {
      px.alice = M.makeIdentity("Alice"); px.bob = M.makeIdentity("Bob");
      px.bundle = M.makeBundle(px.bob, $("px-opk").checked ? 3 : 0);
      px.step = 1; px.start = null; px.fin = null;
      say("b", `Bob: made an identity key, a signed prekey (with a signature) and ${px.bundle.pub.opks.length} one-time prekeys.`);
      say("b", "Bob → server: uploaded the public keys. Bob goes offline.");
      comment("px-note", ""); pxRender();
    });
    click("px-2", () => {
      const pub = Object.assign({}, px.bundle.pub);
      if ($("px-evil").checked) pub.spk = M.genKeyPair().pub;
      px.step = 2;
      const hadOpk = pub.opks.length > 0;
      px.start = M.x3dhStart(px.alice, pub, msgText("px-msg", "Hi Bob!"), { useOpk: hadOpk });
      if (!px.start.ok) {
        say("bad", "Alice: the signature on the signed prekey does NOT match Bob's identity key. The server tampered with it.");
        say("bad", "Alice's app refuses to start the chat.");
        comment("px-note", "# caught: the signature on the prekey doesn't match Bob's identity key. This is the check the signature is for.", "bad");
        pxRender(); return;
      }
      say("a", "Alice → server: asks for Bob's keys" + (hadOpk ? "; the server hands out one one-time prekey and deletes it." : "; no one-time prekeys are left."));
      say("a", "Alice: the signature on the signed prekey checks out against Bob's identity key.");
      say("a", `Alice: made a throwaway ephemeral key, mixed ${px.start.dhs.length} Diffie-Hellman results into a secret, encrypted the first message.`);
      say("a", `Alice → server: first message for Bob (${px.start.msg.ct.length}-byte ciphertext). Bob is still offline.`);
      comment("px-note", "Bob hasn't been online since step 1. Everything Alice used was already waiting on the server.");
      pxRender();
    });
    click("px-3", () => {
      px.fin = M.x3dhFinish(px.bob, px.bundle.secret, px.start); px.step = 3;
      const same = L.equalBytes(px.fin.sk, px.start.sk);
      say("s", "Bob: back online. He repeats the same mixes from his side and gets the same secret.");
      say(same ? "ok" : "bad", `Bob: opened the message: “${esc(px.fin.text)}”`);
      pxRender();
      comment("px-note", same
        ? (px.start.dhs.length === 3 ? "# no one-time prekeys left: three mixes instead of four, and a replayed first message could be accepted. Keeping a stock of fresh ones uploaded is the app's job."
          : "Both sides reached the same secret, and Bob read the message he was never online for.")
        : "The secrets differ.", same ? "ok" : "bad");
    });
    click("px-reset", () => { px.step = 0; px.start = null; px.fin = null; lines.length = 0; pxLog([]); comment("px-note", ""); pxRender(); });
    pxRender();
  }

  // --------------------------------------------------------------------------- slide 6: the post-quantum extra
  const pq = { mode: "classic", step: 0 };
  function pqRender() {
    const box = (cls, small, big, body) => `<div class="pq-box ${cls}"><small>${small}</small><p class="big ${cls}">${big}</p><p>${body}</p></div>`;
    let h = "";
    if (pq.step >= 1) {
      const w = pq.start.wire;
      h += box("", "Recorded today", "A recording", `The eavesdropper saves the public keys (${hx(w.ikA, 4)}, ${hx(w.ekA, 4)}) and the ${w.msg.ct.length}-byte ciphertext. ` +
        (pq.mode === "hybrid" ? "The handshake also mixed in a post-quantum secret." : "The handshake used curve secrets only."));
    } else h += box("", "Recorded today", "Not yet", "Press 1.");
    if (pq.step >= 2) {
      h += pq.res.read
        ? box("bad", "Years later", "Message read", `The attacker rebuilt all four curve secrets from the recorded public keys, derived the same key and opened it: “${esc(pq.res.text)}”.`)
        : box("ok", "Years later", "Still sealed", "The attacker rebuilt all four curve secrets, but the key also needs the post-quantum secret. The authentication tag fails, so nothing is read.");
    } else h += box("", "Years later", "—", "Press 2.");
    $("pq-out").innerHTML = h;
    $("pq-1").disabled = false;
    $("pq-2").disabled = pq.step !== 1;
  }
  function pqInit() {
    seg("pq-mode", (v) => { pq.mode = v; pq.step = 0; press($("pq-mode"), v); comment("pq-note", ""); pqRender(); });
    click("pq-1", () => {
      pq.alice = M.makeIdentity("Alice"); pq.bob = M.makeIdentity("Bob"); pq.bundle = M.makeBundle(pq.bob, 1);
      pq.start = M.x3dhStart(pq.alice, pq.bundle.pub, "Meet at the usual place", { hybrid: pq.mode === "hybrid", useOpk: true });
      pq.step = 1; comment("pq-note", ""); pqRender();
    });
    click("pq-2", () => {
      pq.res = M.quantumAttack(pq.start, pq.bob, pq.bundle.secret, pq.alice); pq.step = 2; pqRender();
      comment("pq-note", pq.res.read
        ? "# the recording from the past is readable. That's 'harvest now, decrypt later'."
        : "# a future quantum computer solves the curve part; the second lock still holds.", pq.res.read ? "bad" : "ok");
    });
    pqRender();
  }

  // --------------------------------------------------------------------------- slide 7: safety numbers
  const sf = { kase: "none" };
  function sfRender() {
    if (!sf.A) { sf.A = M.genKeyPair(); sf.B = M.genKeyPair(); sf.Mal = M.genKeyPair(); sf.B2 = M.genKeyPair(); }
    let a, b, noteA = "Chat with Bob", noteB = "Chat with Alice";
    if (sf.kase === "none") { a = M.safetyNumber(sf.A.pub, sf.B.pub); b = M.safetyNumber(sf.B.pub, sf.A.pub); }
    else if (sf.kase === "mitm") { a = M.safetyNumber(sf.A.pub, sf.Mal.pub); b = M.safetyNumber(sf.B.pub, sf.Mal.pub); noteA = "Holds Mallory's key as \"Bob\""; noteB = "Holds Mallory's key as \"Alice\""; }
    else { a = M.safetyNumber(sf.A.pub, sf.B.pub); b = M.safetyNumber(sf.A.pub, sf.B2.pub); noteA = "Still holds Bob's old key"; noteB = "New phone, new keys"; }
    const grid = (mine, other) => `<div class="sn">${mine.map((g, i) => `<span class="${g !== other[i] ? "diff" : ""}">${g}</span>`).join("")}</div>`;
    $("sf-phones").innerHTML =
      `<div class="phone"><b>Alice's phone</b><small>${noteA}</small>${grid(a, b)}</div><div class="phone"><b>Bob's phone</b><small>${noteB}</small>${grid(b, a)}</div>`;
    const same = a.join() === b.join(), v = $("sf-verdict");
    v.textContent = same ? "Numbers match: both phones hold the right keys." : "Numbers differ: one phone holds a different key from the one the other is using.";
    v.className = "verdict " + (same ? "ok" : "bad");
    comment("sf-note", sf.kase === "none" ? "# match: both phones are fingerprinting the same two keys."
      : sf.kase === "mitm" ? "# the numbers differ because each phone fingerprinted a different pair of keys. That's the whole point of comparing them."
        : "# an innocent mismatch: a new phone has new keys. Check again, ideally in person, before trusting it.", same ? "ok" : "bad");
  }
  function sfInit() { seg("sf-case", (v) => { sf.kase = v; press($("sf-case"), v); sfRender(); }); sfRender(); }

  // --------------------------------------------------------------------------- slide 9: forward secrecy and the hash chain
  const sr = { mode: "chain", msgs: [], stolen: null, ck: null, K: null };
  function srReset(n) {
    sr.msgs = []; sr.stolen = null; sr.ck = L.randBytes(32); sr.K = L.randBytes(32);
    for (const t of ["hello", "are you there?", "see you soon"].slice(0, n)) srSend(t);
  }
  function srSend(text) {
    const n = sr.msgs.length, header = { pub: new Uint8Array(32), pn: 0, n }, aad = M.headerBytes(header);
    let mk;
    if (sr.mode === "chain") { const r = M.kdfCK(sr.ck); sr.ck = r[0]; mk = r[1]; } else mk = M.staticKey(sr.K, n);
    const sealed = M.seal(mk, L.utf8(text), aad);
    sr.msgs.push({ n, text, header, aad, ct: sealed.ct, tag: sealed.tag, keyHex: hx(sr.mode === "static" ? sr.K : mk, 5) });
  }
  function srThiefRead(i) {
    const m = sr.msgs[i], st = sr.stolen;
    try {
      if (sr.mode === "static") return M.readable(M.open(M.staticKey(st.K, i), m.ct, m.tag, m.aad));
      if (i < st.at) return null;                           // the keys for these were deleted before the theft
      if (!st.t) st.t = { ck: st.ck.slice(), n: st.at };
      while (st.t.n < i) { st.t.ck = M.kdfCK(st.t.ck)[0]; st.t.n++; }
      const r = M.kdfCK(st.t.ck); st.t.ck = r[0]; st.t.n++;
      return M.readable(M.open(r[1], m.ct, m.tag, m.aad));
    } catch (e) { return null; }
  }
  function srRender() {
    const st = sr.stolen;
    if (st) st.t = null;
    $("sr-rows").innerHTML = sr.msgs.map((m, i) => {
      const key = sr.mode === "static" ? `<span class="hx">${m.keyHex} (the one key)</span>` : `<s class="hx">${m.keyHex}</s> <small class="muted">deleted</small>`;
      let after = "—", cls = "";
      if (st) {
        const got = srThiefRead(i);
        if (got !== null) { after = "READ: “" + esc(got) + "”"; cls = "bad"; } else { after = i < st.at ? "can't read: key deleted" : "can't read"; cls = "ok"; }
      }
      return `<tr class="${st && i === st.at ? "stolen" : ""}"><th>${i + 1}</th><td>${key}<br><span class="hx">“${esc(m.text)}”</span></td><td class="${cls}">${after}</td></tr>`;
    }).join("") || `<tr><td colspan="3" class="muted">No messages yet. Send a few, then steal the keys.</td></tr>`;
    const box = document.querySelector("#sr-rows").closest(".scrolly"); if (box) box.scrollTop = box.scrollHeight;
  }
  function srInit() {
    srReset(3); srRender();
    seg("sr-mode", (v) => { sr.mode = v; press($("sr-mode"), v); srReset(3); srRender(); comment("sr-note", ""); });
    click("sr-send", () => {
      srSend(msgText("sr-msg", "hello")); srRender();
      if (sr.msgs.length === 10 && !sr.stolen) comment("sr-note", "# ten keys, ten deletions. Message 11 will use a key that doesn't exist yet.");
      else if (sr.stolen) comment("sr-note", sr.mode === "static" ? "The one key still opens everything." : "A new message, and the stolen chain key follows along: the thief reads it.", "bad");
    });
    click("sr-steal", () => {
      sr.stolen = { at: sr.msgs.length, ck: sr.ck.slice(), K: sr.K.slice(), t: null }; srRender();
      comment("sr-note", sr.msgs.length === 0
        ? "# stolen before anything was sent: nothing in the past to read, and in this half of the design, everything in the future exposed."
        : sr.mode === "static" ? "The thief has the one key: every message, past and future, is open."
          : `The thief copied the chain key after message ${sr.msgs.length}. Earlier messages: their keys are gone. Send more and watch.`, "bad");
    });
    click("sr-reset", () => { srReset(0); srRender(); comment("sr-note", ""); });
  }

  // --------------------------------------------------------------------------- slide 10: the Double Ratchet, live
  const dr = {};
  function drLabel(party, pub) {
    const id = L.hex(pub);
    if (!dr.labels.has(id)) { dr.count[party] = (dr.count[party] || 0) + 1; dr.labels.set(id, party + dr.count[party]); }
    return dr.labels.get(id);
  }
  function drCard(who, s, flash) {
    const cls = who === "Bob" ? "bob" : "";
    const lab = dr.labels.get(L.hex(s.DHs.pub));
    const badge = lab ? `<span class="badge bk${(parseInt(lab.slice(1), 10) - 1) % 6}">${lab}</span>` : `<span class="badge muted">new</span>`;
    return `<div class="${cls}"><b>${who}</b><span>Ratchet key ${badge} <span class="hx">${hx(s.DHs.pub, 4)}</span>${lab ? "" : " (not used yet)"}</span>` +
      `<span>Root key <span class="hx">${s.RK ? hx(s.RK, 4) : "—"}</span></span><span>Sending chain <span class="hx">${s.CKs ? hx(s.CKs, 4) : "none yet"}</span> (${s.Ns} sent)</span>` +
      `<span>Receiving chain <span class="hx">${s.CKr ? hx(s.CKr, 4) : "none yet"}</span> (${s.Nr} read)</span>${flash ? `<span class="flash">↻ new ratchet key: a Diffie-Hellman step</span>` : ""}</div>`;
  }
  function drRender(flash) {
    $("dr-rows").innerHTML = dr.msgs.map((m) => {
      const lab = drLabel(m.from, m.header.pub), badge = `<span class="badge bk${(parseInt(lab.slice(1), 10) - 1) % 6}">${lab}</span>`;
      let th = "—", cls = "";
      if (dr.thief && m.i >= dr.stolenAt) { th = m.th.ok ? "READ “" + esc(m.th.text) + "”" : "locked"; cls = m.th.ok ? "bad" : "ok"; }
      return `<tr class="${dr.thief && m.i === dr.stolenAt ? "stolen" : ""}"><th>${m.i + 1}</th><td>${m.from === "A" ? "Alice" : "Bob"}</td><td>${badge}</td><td>${m.header.n}</td><td class="${cls}">${th}</td></tr>`;
    }).join("");
    $("dr-state").innerHTML = drCard("Alice", dr.a, flash === "A") + drCard("Bob", dr.b, flash === "B");
    const box = $("dr-rows").closest(".scrolly"); if (box) box.scrollTop = box.scrollHeight;
  }
  function drSend(who) {
    const from = who === "A" ? dr.a : dr.b, to = who === "A" ? dr.b : dr.a, text = msgText("dr-msg", "hi");
    if (!from.CKs) { comment("dr-note", "Bob can't send first: he has no sending chain until he has received Alice's first message."); return; }
    const m = from.send(text), r = to.receive({ header: m.header, ct: m.ct, tag: m.tag });
    const rec = { i: dr.msgs.length, from: who, header: m.header, ct: m.ct, tag: m.tag, text, th: { ok: false } };
    if (dr.thief) {
      rec.th = dr.thief.read(rec);
      const was = dr.lastOk; dr.lastOk = rec.th.ok;
      if (was && !rec.th.ok && !dr.healed) {
        dr.healed = true;
        comment("dr-note", "# healed: a new Diffie-Hellman secret entered the chain, and the thief wasn't there to see it.", "ok");
      } else if (rec.th.ok) comment("dr-note", "The thief copied Alice's keys and follows along: this one is read.", "bad");
      else comment("dr-note", dr.healed ? "Still locked out: every new message adds secrets the thief never saw." : "Not readable by the thief: it used a key they don't hold.", "ok");
    } else comment("dr-note", r.ratcheted ? "The receiver saw a new ratchet public key and did a Diffie-Hellman step: a new root key, new chains." : "Same ratchet key as before: just the next key in the chain.");
    dr.msgs.push(rec);
    drRender(r.ratcheted ? (who === "A" ? "B" : "A") : "");
  }
  function drReset() {
    dr.labels = new Map(); dr.count = {}; dr.msgs = []; dr.thief = null; dr.healed = false; dr.lastOk = false;
    const c = M.newConversation(); dr.a = c.a; dr.b = c.b;
    const first = dr.a.send("hi"), r = dr.b.receive({ header: first.header, ct: first.ct, tag: first.tag });
    dr.msgs.push({ i: 0, from: "A", header: first.header, ct: first.ct, tag: first.tag, text: "hi", th: { ok: false } });
    drRender(r.ratcheted ? "B" : ""); comment("dr-note", "Alice's first message is sent. Take turns, then copy Alice's keys.");
  }
  function drInit() {
    drReset();
    click("dr-a", () => drSend("A")); click("dr-b", () => drSend("B"));
    click("dr-steal", () => {
      dr.thief = new M.Thief(dr.a.clone()); dr.stolenAt = dr.msgs.length; dr.healed = false; dr.lastOk = true;
      drRender(""); comment("dr-note", `Alice's keys were copied after message ${dr.msgs.length}. Keep talking: who can the thief still read?`, "bad");
    });
    click("dr-reset", drReset);
  }

  // --------------------------------------------------------------------------- slide 11: three designs, one conversation
  const cp = {};
  function cpRender() {
    if (!cp.A) { cp.A = M.designStatic(); cp.B = M.designChain(); cp.C = M.designDouble(); }
    const k = parseInt($("cp-k").value, 10), rows = [["One key for everything", cp.A], ["Hash chain only", cp.B], ["Double Ratchet", cp.C]];
    $("cp-out").textContent = String(k + 1);
    const head = `<div class="cmp-row cmp-head"><b></b>${cp.A.msgs.map((m) => `<span><i class="${m.from === "B" ? "b" : ""}">${m.from}</i>${m.i + 1}</span>`).join("")}</div>`;
    $("cp-grid").innerHTML = head + rows.map(([name, d]) =>
      `<div class="cmp-row"><b>${name}</b>${d.leaks[k].map((r, j) => `<div class="cmp-cell ${r ? "read" : "kept"} ${j === k ? "at" : ""}" role="img" aria-label="message ${j + 1}: ${r ? "read by the thief" : "stays secret"}">${r ? "✗" : "✓"}</div>`).join("")}</div>`).join("");
    $("cp-texts").innerHTML = cp.A.msgs.map((m) => `<li class="${m.from === "B" ? "b" : ""}"><b>${m.i + 1} ${m.from === "A" ? "Alice" : "Bob"}</b> ${esc(m.text)}</li>`).join("");
    const count = (d) => d.leaks[k].filter(Boolean).length, later = (d) => d.leaks[k].filter((v, j) => v && j > k).length;
    const total = cp.A.msgs.length, after = total - k - 1;
    let note = `✗ = the thief reads it, ✓ = it stays secret. One key: ${count(cp.A)} of ${total} read. Hash chain: ${later(cp.B)} of the ${after} later messages read, none of the earlier ones. Double Ratchet: ${later(cp.C)} of the ${after} later messages read, none of the earlier ones.`;
    if (k === 0) note = "# stolen after the first message: only one message of history, so little to lose. " + note;
    else if (k === total - 1) note = "# stolen after the last message: nothing left to read in this transcript. The future is another story. " + note;
    comment("cp-note", note);
  }
  function cpInit() { $("cp-k").addEventListener("input", cpRender); cpRender(); }

  // --------------------------------------------------------------------------- slide 12: out-of-order delivery
  const oo = { limit: 4 };
  function ooReset() {
    const c = M.newConversation(); oo.a = c.a; oo.b = c.b; oo.b.maxSkip = oo.limit; oo.done = new Set(); oo.log = [];
    oo.msgs = [1, 2, 3, 4, 5, 6].map((n) => { const m = oo.a.send("message " + n); return { n, text: "message " + n, header: m.header, ct: m.ct, tag: m.tag }; });
    ooRender(); comment("oo-note", "");
  }
  function ooRender() {
    $("oo-btns").innerHTML = oo.msgs.map((m) => `<button type="button" data-n="${m.n}">${oo.done.has(m.n) ? "Replay" : "Deliver"} ${m.n}</button>`).join("");
    const skipped = Array.from(oo.b.skipped.keys()).map((k) => parseInt(k.split(":")[1], 10) + 1).sort((x, y) => x - y);
    $("oo-state").innerHTML = `<div class="bob"><b>Bob's phone</b><span>Next in the chain: message <span class="hx">${oo.b.CKr ? oo.b.Nr + 1 : 1}</span></span><span>Skipped keys saved: <span class="hx">${skipped.length ? skipped.join(", ") : "none"}</span></span></div>` +
      `<div><b>Limit</b><span>Most keys saved at once: <span class="hx">${oo.limit}</span></span><span>Delivered so far: <span class="hx">${oo.done.size ? Array.from(oo.done).sort().join(", ") : "none"}</span></span></div>`;
    $("oo-log").innerHTML = oo.log.map((l) => `<li class="${l[0]}">${l[1]}</li>`).join("");
    const lg = $("oo-log"); lg.scrollTop = lg.scrollHeight;
  }
  function ooInit() {
    ooReset();
    seg("oo-limit", (v) => { oo.limit = parseInt(v, 10); press($("oo-limit"), v); ooReset(); });
    $("oo-btns").addEventListener("click", (e) => {
      const btn = e.target.closest("button"); if (!btn) return;
      const n = parseInt(btn.getAttribute("data-n"), 10), m = oo.msgs[n - 1], replay = oo.done.has(n);
      try {
        const r = oo.b.receive({ header: m.header, ct: m.ct, tag: m.tag });
        oo.done.add(n);
        oo.log.push(["ok", `#${n} delivered: “${esc(r.text)}” ` + (r.usedSkipped ? "(opened with a saved key, now deleted)" : r.skippedNow ? `(saved ${r.skippedNow} key${r.skippedNow > 1 ? "s" : ""} for the ones it jumped over)` : "(in order)")]);
        comment("oo-note", "");
      } catch (err) {
        if (/TOO MANY SKIPPED/.test(err.message)) {
          oo.log.push(["bad", `#${n} refused: ${esc(err.message.replace("TOO MANY SKIPPED: ", "too many skipped: "))}`]);
          comment("oo-note", "# too many skipped: the app refuses rather than keep an unbounded pile of keys. The spec suggests a limit (for example 1000).", "bad");
        } else {
          oo.log.push(["mid", `#${n} rejected${replay ? " (a replay)" : ""}: its key was already used and deleted, so the authentication tag fails.`]);
          comment("oo-note", "A replayed message fails: the key that would open it no longer exists.", "ok");
        }
      }
      ooRender();
    });
    click("oo-reset", ooReset);
  }

  // --------------------------------------------------------------------------- slide 14: groups
  const GR_SIZES = [2, 3, 5, 8, 16, 50, 100, 500, 1000];
  const GR = { sel: 2 };
  function grRender() {
    const n = GR_SIZES[parseInt($("gr-n").value, 10)], c = M.groupCosts(n);
    $("gr-out").textContent = nf(n);
    $("gr-rows").innerHTML =
      `<tr><th>Pairwise copies</th><td><b>${nf(c.pairwise.message)}</b></td><td><b>${nf(c.pairwise.leave)}</b>: just stop sending to them</td><td>Signal's original 2014 design: a separate encrypted copy for each member.</td></tr>` +
      `<tr><th>Sender keys</th><td><b>${nf(c.senderKeys.message)}</b></td><td><b>${nf(c.senderKeys.leave)}</b>: everyone replaces their key and sends it on</td><td>Used by WhatsApp and present in libsignal. A hash ratchet gives forward secrecy; healing is weak.</td></tr>` +
      `<tr><th>A key tree (MLS)</th><td><b>${nf(c.tree.message)}</b></td><td><b>${nf(c.tree.leave)}</b> (about log₂ n)</td><td>IETF RFC 9420: forward secrecy and healing for groups of two to thousands. RCS encryption uses it.</td></tr>`;
    let note = "";
    if (n === 2) note = "# two people: pairwise and sender keys cost about the same, which is why one-to-one chats are the easy case.";
    else if (n === 1000) note = "# a thousand members: 999 pairwise encryptions for every message, or about 10 steps for a tree update (log₂ 1000 ≈ 10).";
    comment("gr-note", note);
  }
  function grTree() {
    const svg = $("gr-tree"), ys = [140, 95, 50, 15];
    const levels = [8, 4, 2, 1];
    const pos = (lv, i) => ({ x: lv === 0 ? 30 + i * 54 : (pos(lv - 1, i * 2).x + pos(lv - 1, i * 2 + 1).x) / 2, y: ys[lv] });
    const sel = GR.sel, path = new Set(), copath = new Set(), edges = new Set();
    for (let lv = 0; lv < 4; lv++) {
      path.add(lv + ":" + (sel >> lv));
      if (lv < 3) { copath.add(lv + ":" + ((sel >> lv) ^ 1)); edges.add(lv + ":" + (sel >> lv)); }
    }
    let h = "";
    for (let lv = 0; lv < 3; lv++) for (let i = 0; i < levels[lv]; i++) {
      const p = pos(lv, i), q = pos(lv + 1, i >> 1);
      h += `<line class="edge ${edges.has(lv + ":" + i) ? "on" : ""}" x1="${p.x}" y1="${p.y}" x2="${q.x}" y2="${q.y}"/>`;
    }
    for (let lv = 0; lv < 4; lv++) for (let i = 0; i < levels[lv]; i++) {
      const p = pos(lv, i), id = lv + ":" + i;
      const cls = path.has(id) ? "path" : copath.has(id) ? "copath" : "";
      h += `<g class="${lv === 0 ? "leaf" : ""} ${lv === 0 && i === sel ? "me" : ""}" data-i="${i}"><circle class="node ${cls}" cx="${p.x}" cy="${p.y}" r="${lv === 0 ? 14 : 10}"/>${lv === 0 ? `<text x="${p.x}" y="${p.y + 4}">M${i + 1}</text>` : ""}</g>`;
    }
    svg.innerHTML = h;
    comment("gr-tree-note", `M${sel + 1} updates its key: 4 nodes change (yellow). The new secrets are encrypted to 3 blue nodes, the siblings along the path: about log₂ 8 = 3 steps, not 7.`);
  }
  function grInit() {
    $("gr-n").value = "4"; grRender(); grTree();
    $("gr-n").addEventListener("input", grRender);
    $("gr-tree").addEventListener("click", (e) => { const g = e.target.closest("g.leaf"); if (!g) return; GR.sel = parseInt(g.getAttribute("data-i"), 10); grTree(); });
  }

  // --------------------------------------------------------------------------- slide 15: several devices
  const dv = {};
  const DV_ALICE = ["Alice's phone", "Alice's laptop", "Alice's tablet"], DV_BOB = ["Bob's phone", "Bob's tablet", "Bob's laptop"];
  function dvReset() {
    dv.alice = 2; dv.bob = 1; dv.sent = 0; dv.joined = {}; dv.ck = {}; dv.rows = [];
    dvEnsure(); dvRender(); comment("dv-note", "");
  }
  function dvEnsure() { for (const n of DV_ALICE.slice(0, dv.alice).concat(DV_BOB.slice(0, dv.bob))) if (!dv.ck[n]) dv.ck[n] = L.randBytes(32); }
  function dvRender() {
    const person = (cls, title, names, count) => `<div class="dv-person ${cls}"><b>${title}</b>${names.slice(0, count).map((n) => `<div class="dv-dev ${dv.joined[n] !== undefined ? "new" : ""}"><span>${n}</span><span>${dv.joined[n] !== undefined ? "linked later" : "original"}</span></div>`).join("")}</div>`;
    $("dv-people").innerHTML = person("", "Alice", DV_ALICE, dv.alice) + person("bob", "Bob", DV_BOB, dv.bob);
    $("dv-rows").innerHTML = dv.rows.length ? dv.rows.map((r) => `<tr><th>${r[0]}</th><td class="hx">${r[1]}</td></tr>`).join("") : `<tr><td colspan="2" class="muted">Press "Alice sends".</td></tr>`;
    $("dv-bob").disabled = dv.bob >= DV_BOB.length; $("dv-alice").disabled = dv.alice >= DV_ALICE.length;
  }
  function dvInit() {
    dvReset();
    click("dv-send", () => {
      const text = msgText("dv-msg", "hello"); dv.sent++; dvEnsure();
      const targets = DV_BOB.slice(0, dv.bob).map((n) => [n, n]).concat(DV_ALICE.slice(1, dv.alice).map((n) => [n + " (her own copy)", n]));
      dv.rows = targets.map(([label, n]) => {
        const r = M.kdfCK(dv.ck[n]); dv.ck[n] = r[0];
        const s = M.seal(r[1], L.utf8(text), L.utf8(n));
        return [label, hx(s.ct, 8) + " + tag " + hx(s.tag, 3)];
      });
      dvRender();
      comment("dv-note", `One message became ${dv.rows.length} ciphertext${dv.rows.length > 1 ? "s" : ""}: every copy is different, though the words are the same.`);
    });
    click("dv-bob", () => { const n = DV_BOB[dv.bob++]; dv.joined[n] = dv.sent; dvEnsure(); dvRender(); dvJoinNote(n); });
    click("dv-alice", () => { const n = DV_ALICE[dv.alice++]; dv.joined[n] = dv.sent; dvEnsure(); dvRender(); dvJoinNote(n); });
    click("dv-reset", dvReset);
  }
  function dvJoinNote(n) {
    const total = dv.alice + dv.bob, sent = dv.joined[n];
    if (total >= 5) comment("dv-note", "# five devices: that's a lot of places a message can be read. Worth a look at the device list now and then.");
    else comment("dv-note", sent === 0 ? `${n} is linked. It starts with no history: anything sent before it joined can't be read by it.`
      : `${n} starts empty: it joined after ${sent} message${sent === 1 ? "" : "s"} were sent, and it can read none of them. Press "Alice sends" to see its copy.`);
  }

  // --------------------------------------------------------------------------- slide 16: metadata
  function mtRender(mode) {
    const sealed = mode === "sealed";
    const rows = [
      ["What you wrote", "Hidden", "ok", "Hidden", "ok"],
      ["Who sent it", "Seen: the service knows the account", "bad", "Hidden: inside the encrypted envelope", "ok"],
      ["Who it's for", "Seen", "bad", "Seen", "bad"],
      ["When, and roughly how big", "Seen", "bad", "Seen", "bad"],
      ["The network address it came from", "Seen", "bad", "Seen", "bad"],
    ];
    $("mt-rows").innerHTML = rows.map((r) => `<tr><th>${r[0]}</th><td class="${sealed ? r[4] : r[2]}">${sealed ? r[3] : r[1]}</td></tr>`).join("");
    comment("mt-note", sealed ? "The sender row flips; the rest stays visible. Signal called this \"an incremental step\" in 2018, with timing and network-address correlation still ongoing work."
      : "The contents are hidden, but the service still has to know where to deliver the message.");
  }
  function mtInit() { seg("mt-mode", (v) => { press($("mt-mode"), v); mtRender(v); }); mtRender("e2ee"); }

  // --------------------------------------------------------------------------- slide 18: what end-to-end encryption doesn't protect
  const LM = [
    ["Your phone, unlocked", "Nothing here: the app has to show the message to you in readable form.", "Anyone holding the unlocked phone can read your chats: a thief, a partner, a child who borrows it.", "Use a strong screen lock and a short auto-lock, and keep the phone and apps updated."],
    ["The app", "The encryption is built into the app.", "A hacked or fake copy of the app can read what you can read.", "Install from the official store and keep it updated."],
    ["The network", "Contents stay encrypted from the café Wi-Fi, your provider and anyone on the path.", "Metadata: that you connect to this service, when, and how much.", "Use other tools only for what they really cover (see Privacy Tools Explained)."],
    ["The company's servers", "They can't read the message contents: that's the point.", "They still see metadata (account, recipient, timing), and can be served legal orders for what they hold.", "Prefer services that keep little, and read their transparency pages."],
    ["Their phone", "Nothing: the other person's device holds the plaintext.", "They can show, forward or photograph it. A disappearing timer doesn't stop a camera.", "Share only what you'd be comfortable with them keeping."],
    ["Backups", "Only if the backup is end-to-end encrypted with a key you hold.", "A backup the company can unlock can give your messages to it, or to a court order.", "Check each app's backup setting and where its key lives."],
    ["Lock-screen previews", "None: the notification is plain text on your screen.", "Anyone who glances at the phone can read the preview.", "Turn off message previews on the lock screen."],
    ["Linked devices", "Each is its own endpoint, with its own keys.", "A forgotten laptop can still read your new messages.", "Review the linked-device list and unlink what you don't use."],
  ];
  const lm = { seen: new Set(), cur: 0 };
  function lmRender() {
    $("lm-nodes").innerHTML = LM.map((n, i) => `<button type="button" data-v="${i}" aria-pressed="${i === lm.cur}" class="${lm.seen.has(i) ? "seen" : ""}">${n[0]}</button>`).join("");
    const n = LM[lm.cur];
    $("lm-detail").innerHTML = `<p class="t">${n[0]}</p><p class="p"><b>Encryption helps:</b> ${n[1]}</p><p class="n"><b>It doesn't cover:</b> ${n[2]}</p><p class="d"><b>What to do:</b> ${n[3]}</p>`;
    comment("lm-note", lm.seen.size === LM.length ? "# all eight places visited: the encryption covers the middle of the journey; the ends are up to you." : `${lm.seen.size} of ${LM.length} places visited.`, lm.seen.size === LM.length ? "ok" : "");
  }
  function lmInit() { lm.seen.add(0); seg("lm-nodes", (v) => { lm.cur = parseInt(v, 10); lm.seen.add(lm.cur); lmRender(); }); lmRender(); }

  // --------------------------------------------------------------------------- slide 19: a timeline
  const TL = [
    ["2004", "Off-the-Record Messaging: short-lived Diffie-Hellman keys and MACs instead of signatures (Borisov, Goldberg, Brewer).", ["ratchets"], "Research paper", ""],
    ["May 2014", "Signal's group design: a separate pairwise-encrypted copy for each member.", ["groups"], "Original design", "ok"],
    ["5 Apr 2016", "WhatsApp completes its integration of the Signal Protocol: chats, group chats, calls.", ["start", "groups"], "Shipped", "ok"],
    ["4 Nov 2016", "X3DH specification (revision 1): starting a chat with an offline recipient.", ["start"], "Specification", ""],
    ["17 Nov 2016", "Safety numbers become per-conversation: 12 groups of five digits.", ["verify"], "Shipped", "ok"],
    ["14 Apr 2017", "Sesame specification (revision 2): sessions across several devices.", ["groups"], "Specification", ""],
    ["2017–2018", "Academic analysis of group chats in Signal, WhatsApp and Threema (Rösler, Mainka, Schwenk).", ["groups"], "Research paper", ""],
    ["29 Oct 2018", "Sealed sender, a technology preview: the sender's identity goes inside the envelope.", ["meta"], "Preview", "mid"],
    ["2023", "MLS published as RFC 9420: group key agreement with forward secrecy and healing.", ["groups"], "Standard", ""],
    ["19 Sep 2023", "PQXDH: Signal adds a post-quantum secret to its handshake.", ["pq", "start"], "Shipped", "ok"],
    ["27 Oct 2023", "iMessage Contact Key Verification announced (developer previews of iOS 17.2).", ["verify"], "Announced", "mid"],
    ["21 Feb 2024", "iMessage PQ3: post-quantum keys at the start and a post-quantum ratchet. Apple said it would replace the old protocol in all supported conversations that year.", ["pq", "ratchets"], "Announced (completion not confirmed here)", "mid"],
    ["13 Aug 2024", "NIST publishes FIPS 203, the ML-KEM standard (from CRYSTALS-Kyber).", ["pq"], "Standard", ""],
    ["14 Mar 2025", "GSMA RCS Universal Profile 3.0: end-to-end encryption based on MLS.", ["groups"], "Specification", ""],
    ["2 Oct 2025", "Signal's Sparse Post-Quantum Ratchet (SPQR), the \"Triple Ratchet\": a post-quantum ratchet alongside the Double Ratchet.", ["pq", "ratchets"], "Rolling out (full enforcement not confirmed)", "mid"],
    ["4 Nov 2025", "Double Ratchet specification, revision 4.", ["ratchets"], "Specification", ""],
    ["11 May 2026", "End-to-end encrypted RCS between iPhone (iOS 26.5) and Android begins, as a beta.", ["groups"], "Beta", "mid"],
    ["11 Aug 2026", "Signal's automatic key verification: a key transparency log audited by Cloudflare and Trail of Bits.", ["verify"], "Shipped", "ok"],
  ];
  const TL_FILTERS = [["all", "All"], ["start", "Starting a chat"], ["ratchets", "Ratchets"], ["groups", "Groups and devices"], ["pq", "Post-quantum"], ["verify", "Verification"], ["meta", "Metadata"]];
  const tl = { cur: "all", seen: new Set(["all"]) };
  function tlRender() {
    $("tl-filter").innerHTML = TL_FILTERS.map(([v, t]) => `<button type="button" data-v="${v}" aria-pressed="${v === tl.cur}">${t}</button>`).join("");
    $("tl-rows").innerHTML = TL.filter((r) => tl.cur === "all" || r[2].includes(tl.cur)).map((r) => `<tr><th>${r[0]}</th><td>${esc(r[1])}</td><td class="${r[4]}">${r[3]}</td></tr>`).join("");
    comment("tl-note", tl.seen.size === TL_FILTERS.length ? "# every filter opened: 2004 to now, and none of it needed you to follow the maths." : "");
  }
  function tlInit() { seg("tl-filter", (v) => { tl.cur = v; tl.seen.add(v); tlRender(); }); tlRender(); }

  // --------------------------------------------------------------------------- slide 20: choosing and using a messenger
  const CK = [
    "End-to-end encryption is on by default for my chats, not only in a special mode.",
    "Group chats are end-to-end encrypted too.",
    "I know whether my chat backups are encrypted, and who holds the key.",
    "Message previews are off on my lock screen.",
    "The app and my phone update automatically.",
    "I have a screen lock and a recovery PIN or key I won't lose.",
    "I know how to check keys (safety numbers or key verification) for the one chat that matters.",
    "I've reviewed my linked devices and removed the ones I don't use.",
    "I know that disappearing messages rely on the other person's good faith.",
    "I know what the app's company can still see: who, when and how much.",
  ];
  function ckInit() {
    let saved = []; try { saved = JSON.parse(store("modern-messaging-checklist") || "[]"); } catch (e) {}
    $("plan").innerHTML = CK.map((t, i) => `<label><input type="checkbox" data-i="${i}" ${saved[i] ? "checked" : ""}><span>${t}</span></label>`).join("");
    const update = () => {
      const boxes = Array.from($("plan").querySelectorAll("input")), n = boxes.filter((b) => b.checked).length;
      store("modern-messaging-checklist", JSON.stringify(boxes.map((b) => b.checked)));
      comment("ck-note", n === CK.length ? "# all ten. A messenger you use carefully beats a perfect one you don't." : `${n} of ${CK.length} ticked. Saved in this browser only.`, n === CK.length ? "ok" : "");
    };
    $("plan").addEventListener("change", update); update();
  }

  // --------------------------------------------------------------------------- go
  function run(fn) { try { fn(); } catch (e) { console.error(e); } }
  [hero, ssInit, pxInit, pqInit, sfInit, srInit, drInit, cpInit, ooInit, grInit, dvInit, mtInit, lmInit, tlInit, ckInit].forEach(run);
  try {
    console.log("%cModern Messaging Protocols", "font-weight:700;color:#00f0ff", "\nEverything on these slides is real cryptography in teaching code. window.Msg holds the engine (X25519, the Double Ratchet, X3DH and the thief): poke at it, but never use it for real messages.");
  } catch (e) {}
})();
