/* ratchet.js - teaching versions of the protocols in "Modern Messaging Protocols".
   Real X25519 (RFC 7748), real HMAC-SHA-256, HKDF-SHA-256 and AES-128-GCM from ../../shared/crypto.js.
   TEACHING CODE, NEVER FOR REAL MESSAGES: no constant-time guarantees, no key storage, no real post-quantum KEM.
   Works in the browser (window.Msg) and in Node (module.exports) so it can be tested. */
(function (root) {
  "use strict";
  const L = root.Lab || (typeof require !== "undefined" ? require("../../shared/crypto.js") : null);
  const { hex, concat, utf8, randBytes, equalBytes, hmacSha256, hkdfExtract, hkdfExpand } = L;
  const ZERO32 = new Uint8Array(32);

  // --------------------------------------------------------------------------- X25519 (RFC 7748), the curve Signal's protocols use
  const P = (1n << 255n) - 19n;
  const leToBig = (b) => { let x = 0n; for (let i = b.length - 1; i >= 0; i--) x = (x << 8n) | BigInt(b[i]); return x; };
  const bigToLe = (x, n = 32) => { const o = new Uint8Array(n); for (let i = 0; i < n; i++) { o[i] = Number(x & 0xffn); x >>= 8n; } return o; };
  const mod = (a) => { const r = a % P; return r >= 0n ? r : r + P; };
  function powmod(b, e) { let r = 1n; b = mod(b); while (e > 0n) { if (e & 1n) r = (r * b) % P; b = (b * b) % P; e >>= 1n; } return r; }
  function x25519(k, u) {
    const kb = Uint8Array.from(k); kb[0] &= 248; kb[31] &= 127; kb[31] |= 64;
    const kk = leToBig(kb);
    const ub = Uint8Array.from(u); ub[31] &= 127;
    const x1 = leToBig(ub) % P;
    let x2 = 1n, z2 = 0n, x3 = x1, z3 = 1n, swap = 0n;
    for (let t = 254n; t >= 0n; t--) {
      const kt = (kk >> t) & 1n;
      swap ^= kt;
      if (swap) { [x2, x3] = [x3, x2]; [z2, z3] = [z3, z2]; }
      swap = kt;
      const A = mod(x2 + z2), AA = mod(A * A), B = mod(x2 - z2), BB = mod(B * B), E = mod(AA - BB);
      const C = mod(x3 + z3), D = mod(x3 - z3), DA = mod(D * A), CB = mod(C * B);
      x3 = mod((DA + CB) * (DA + CB)); z3 = mod(x1 * mod((DA - CB) * (DA - CB)));
      x2 = mod(AA * BB); z2 = mod(E * (AA + 121665n * E));
    }
    if (swap) { [x2, x3] = [x3, x2]; [z2, z3] = [z3, z2]; }
    return bigToLe(mod(x2 * powmod(z2, P - 2n)));
  }
  const BASE = (() => { const b = new Uint8Array(32); b[0] = 9; return b; })();
  function genKeyPair() { const priv = randBytes(32); return { priv, pub: x25519(priv, BASE) }; }
  const dh = (priv, pub) => x25519(priv, pub);

  // --------------------------------------------------------------------------- key derivation and message encryption
  const hkdf = (salt, ikm, info, len) => hkdfExpand(hkdfExtract(salt, ikm), utf8(info), len);
  // root KDF: (root key, DH output) -> (new root key, chain key)
  function kdfRK(rk, dhOut) { const o = hkdf(rk, dhOut, "MsgDemo root", 64); return [o.slice(0, 32), o.slice(32, 64)]; }
  // chain KDF per the Double Ratchet spec: HMAC(chain key, 0x01) is the message key, HMAC(chain key, 0x02) is the next chain key
  function kdfCK(ck) { return [hmacSha256(ck, Uint8Array.of(2)), hmacSha256(ck, Uint8Array.of(1))]; }
  function keyNonce(mk) { const o = hkdf(ZERO32, mk, "MsgDemo message", 28); return { key: o.slice(0, 16), nonce: o.slice(16, 28) }; }
  function seal(mk, pt, aad) { const { key, nonce } = keyNonce(mk); return L.gcmEncrypt(key, nonce, pt, aad); }
  function open(mk, ct, tag, aad) { const { key, nonce } = keyNonce(mk); return L.gcmDecrypt(key, nonce, ct, tag, aad); }
  const u32 = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n); return b; };
  const headerBytes = (h) => concat(h.pub, u32(h.pn), u32(h.n));
  const readable = (b) => { try { return new TextDecoder("utf-8", { fatal: true }).decode(b); } catch (e) { return null; } };

  // --------------------------------------------------------------------------- the Double Ratchet (after Signal's specification, revision 4)
  class Session {
    constructor(name, maxSkip = 1000) {
      Object.assign(this, { name, maxSkip, DHs: null, DHr: null, RK: null, CKs: null, CKr: null, Ns: 0, Nr: 0, PN: 0, skipped: new Map(), ad: new Uint8Array(0) });
    }
    // Alice starts after the handshake: she knows Bob's first ratchet public key (his signed prekey) and the shared secret.
    static initAlice(sk, bobPub, ad = new Uint8Array(0), maxSkip = 1000) {
      const s = new Session("Alice", maxSkip); s.ad = ad;
      s.DHs = genKeyPair(); s.DHr = bobPub;
      [s.RK, s.CKs] = kdfRK(sk, dh(s.DHs.priv, s.DHr));
      return s;
    }
    static initBob(sk, bobKeyPair, ad = new Uint8Array(0), maxSkip = 1000) {
      const s = new Session("Bob", maxSkip); s.ad = ad;
      s.DHs = bobKeyPair; s.RK = sk;
      return s;
    }
    clone() {
      const c = new Session(this.name, this.maxSkip);
      c.DHs = this.DHs && { priv: this.DHs.priv.slice(), pub: this.DHs.pub.slice() };
      c.DHr = this.DHr && this.DHr.slice();
      c.RK = this.RK && this.RK.slice(); c.CKs = this.CKs && this.CKs.slice(); c.CKr = this.CKr && this.CKr.slice();
      c.Ns = this.Ns; c.Nr = this.Nr; c.PN = this.PN; c.ad = this.ad;
      c.skipped = new Map(Array.from(this.skipped, ([k, v]) => [k, v.slice()]));
      return c;
    }
    assign(o) { for (const k of ["DHs", "DHr", "RK", "CKs", "CKr", "Ns", "Nr", "PN", "skipped"]) this[k] = o[k]; }
    send(text) {
      if (!this.CKs) throw new Error("No sending chain yet: Bob has to receive a message first");
      let mk; [this.CKs, mk] = kdfCK(this.CKs);
      const header = { pub: this.DHs.pub, pn: this.PN, n: this.Ns };
      this.Ns++;
      const { ct, tag } = seal(mk, utf8(text), concat(this.ad, headerBytes(header)));
      return { header, ct, tag, mk };
    }
    skip(until) {
      if (!this.CKr) return 0;
      if (until - this.Nr > this.maxSkip) throw new Error("TOO MANY SKIPPED: " + (until - this.Nr) + " keys would be stored (limit " + this.maxSkip + ")");
      let n = 0;
      while (this.Nr < until) {
        let mk; [this.CKr, mk] = kdfCK(this.CKr);
        this.skipped.set(hex(this.DHr) + ":" + this.Nr, mk); this.Nr++; n++;
      }
      return n;
    }
    dhRatchet(theirPub) {
      this.PN = this.Ns; this.Ns = 0; this.Nr = 0; this.DHr = theirPub;
      [this.RK, this.CKr] = kdfRK(this.RK, dh(this.DHs.priv, this.DHr));
      this.DHs = genKeyPair();
      [this.RK, this.CKs] = kdfRK(this.RK, dh(this.DHs.priv, this.DHr));
    }
    // Work on a copy and keep the new state only if the tag checks out (as the spec advises).
    receive(msg) {
      const h = msg.header, t = this.clone(), aad = concat(this.ad, headerBytes(h));
      const id = hex(h.pub) + ":" + h.n;
      if (t.skipped.has(id)) {
        const mk = t.skipped.get(id); const pt = open(mk, msg.ct, msg.tag, aad);
        t.skipped.delete(id); this.assign(t);
        return { text: readable(pt), ratcheted: false, skippedNow: 0, usedSkipped: true };
      }
      let ratcheted = false, skippedNow = 0;
      if (!t.DHr || !equalBytes(h.pub, t.DHr)) { skippedNow += t.skip(h.pn); t.dhRatchet(h.pub); ratcheted = true; }
      skippedNow += t.skip(h.n);
      let mk; [t.CKr, mk] = kdfCK(t.CKr); t.Nr++;
      const pt = open(mk, msg.ct, msg.tag, aad);
      this.assign(t);
      return { text: readable(pt), ratcheted, skippedNow, usedSkipped: false };
    }
  }

  // --------------------------------------------------------------------------- X3DH, with an optional "post-quantum" extra secret (PQXDH)
  // The signature on the signed prekey is ECDSA over P-256 from the shared crypto.js. Real Signal signs with XEdDSA using
  // the same Curve25519 identity key; this teaching code keeps a separate signing key to stay with maths the deck already has.
  function makeIdentity(name) {
    const d = L.randBelow(L.P256.n - 1n) + 1n;
    return { name, ik: genKeyPair(), signD: d, signQ: L.P256.mul(d) };
  }
  const spkHash = (spkPub) => L.hashInt("MsgDemo signed prekey " + hex(spkPub));
  function makeBundle(bob, opkCount = 3) {
    const spk = genKeyPair(), opks = [];
    for (let i = 0; i < opkCount; i++) opks.push(genKeyPair());
    const sig = L.ecdsaSign(bob.signD, spkHash(spk.pub), L.randBelow(L.P256.n - 1n) + 1n);
    return { secret: { spk, opks }, pub: { ik: bob.ik.pub, signQ: bob.signQ, spk: spk.pub, sig, opks: opks.map((k) => k.pub) } };
  }
  function bundleSigOk(pub) { return L.ecdsaVerify(pub.signQ, spkHash(pub.spk), pub.sig); }
  function x3dhKdf(dhs, ss) {
    const parts = [new Uint8Array(32).fill(0xff), ...dhs];
    if (ss) parts.push(ss);
    return hkdf(ZERO32, concat(...parts), "MsgDemo X3DH", 32);
  }
  // Alice (online) starts a conversation with a bundle fetched from the server. Returns the first message and everything the server relays.
  function x3dhStart(alice, pubBundle, text, opts = {}) {
    const steps = [];
    if (!bundleSigOk(pubBundle)) return { ok: false, reason: "BAD SIGNATURE", steps };
    steps.push("Signature on the signed prekey checks out against Bob's identity");
    const ek = genKeyPair();
    const opkIndex = opts.useOpk === false || !pubBundle.opks.length ? -1 : 0;
    const dh1 = dh(alice.ik.priv, pubBundle.spk), dh2 = dh(ek.priv, pubBundle.ik), dh3 = dh(ek.priv, pubBundle.spk);
    const dhs = [dh1, dh2, dh3];
    if (opkIndex >= 0) dhs.push(dh(ek.priv, pubBundle.opks[opkIndex]));
    const ss = opts.hybrid ? randBytes(32) : null;      // stands in for the secret a post-quantum KEM would hand to Alice (no real KEM here)
    const sk = x3dhKdf(dhs, ss);
    const ad = concat(alice.ik.pub, pubBundle.ik);
    const session = Session.initAlice(sk, pubBundle.spk, ad);
    const msg = session.send(text);
    return { ok: true, steps, session, sk, dhs, ss, ek, opkIndex, ad, msg,
      wire: { ikA: alice.ik.pub, ekA: ek.pub, opkIndex, hybrid: !!opts.hybrid, msg: { header: msg.header, ct: msg.ct, tag: msg.tag } } };
  }
  // Bob comes online later and finishes the handshake from what was left for him.
  function x3dhFinish(bob, bundleSecret, start) {
    const w = start.wire;
    const dh1 = dh(bundleSecret.spk.priv, w.ikA), dh2 = dh(bob.ik.priv, w.ekA), dh3 = dh(bundleSecret.spk.priv, w.ekA);
    const dhs = [dh1, dh2, dh3];
    if (w.opkIndex >= 0) dhs.push(dh(bundleSecret.opks[w.opkIndex].priv, w.ekA));
    const sk = x3dhKdf(dhs, w.hybrid ? start.ss : null);
    const session = Session.initBob(sk, bundleSecret.spk, start.ad);
    const got = session.receive(w.msg);
    return { sk, session, text: got.text, dhs };
  }
  // The "quantum computer" scenario: assume the attacker has turned every recorded public key into its private key
  // (the thing a large quantum computer could do to X25519) and replays the handshake from the recording.
  function quantumAttack(start, bob, bundleSecret, alice) {
    const w = start.wire;
    const dhs = [dh(alice.ik.priv, bundleSecret.spk.pub), dh(start.ek.priv, bob.ik.pub), dh(start.ek.priv, bundleSecret.spk.pub)];
    if (w.opkIndex >= 0) dhs.push(dh(start.ek.priv, bundleSecret.opks[w.opkIndex].pub));
    const sk = x3dhKdf(dhs, null);                       // no access to the KEM secret
    const s = Session.initBob(sk, bundleSecret.spk, start.ad);
    try { const g = s.receive(w.msg); return { read: true, text: g.text, sk }; } catch (e) { return { read: false, error: e.message, sk }; }
  }

  // --------------------------------------------------------------------------- safety numbers (simplified: Signal iterates SHA-512 thousands of times)
  function fingerprint(pub) {
    const h = L.sha256(concat(utf8("MsgDemo safety number"), pub));
    let out = "";
    for (let i = 0; i < 6; i++) {
      let n = 0; for (let j = 0; j < 5; j++) n = n * 256 + h[i * 5 + j];
      out += String(n % 100000).padStart(5, "0");
    }
    return out;
  }
  function safetyNumber(pubA, pubB) {
    const a = fingerprint(pubA), b = fingerprint(pubB);
    return (a < b ? a + b : b + a).match(/.{5}/g);        // 12 groups of five digits, sorted so both phones agree
  }

  // --------------------------------------------------------------------------- the same conversation under three designs, and what a stolen key reveals
  const SCRIPT = [
    ["A", "Are you home yet?"], ["A", "Dinner is at 7"], ["B", "Leaving now"], ["A", "Great, see you"], ["B", "Parking"], ["B", "Be right up"],
    ["A", "Door's open"], ["A", "Mind the cat"], ["B", "Ha, I see it"], ["A", "Pasta or rice?"], ["B", "Pasta"], ["A", "Done"],
  ];
  // Design A: one long-term key for everything. Each message gets its own nonce from its counter (so GCM is used soundly),
  // but nothing is ever forgotten: the one key opens every message, past and future.
  const staticKey = (key, n) => hmacSha256(key, u32(n));
  function designStatic(script = SCRIPT) {
    const key = randBytes(32), msgs = [];
    script.forEach(([who, text], i) => {
      const header = { pub: new Uint8Array(32), pn: 0, n: i };
      const { ct, tag } = seal(staticKey(key, i), utf8(text), headerBytes(header));
      msgs.push({ i, from: who, text, header, ct, tag });
    });
    const leaks = script.map(() => msgs.map((m) => { try { open(staticKey(key, m.i), m.ct, m.tag, headerBytes(m.header)); return true; } catch (e) { return false; } }));
    return { msgs, leaks };
  }
  // Design B: a symmetric ratchet only (hash the chain key forward, never mix in new Diffie-Hellman secrets).
  function designChain(script = SCRIPT) {
    const root = randBytes(32);
    let ck = { A: hkdf(ZERO32, root, "MsgDemo chain A", 32), B: hkdf(ZERO32, root, "MsgDemo chain B", 32) };
    const n = { A: 0, B: 0 }, msgs = [], snaps = [];
    script.forEach(([who, text], i) => {
      let mk; [ck[who], mk] = kdfCK(ck[who]);
      const header = { pub: new Uint8Array(32), pn: 0, n: n[who]++ };
      const { ct, tag } = seal(mk, utf8(text), headerBytes(header));
      msgs.push({ i, from: who, text, header, ct, tag });
      snaps.push({ ck: { A: ck.A.slice(), B: ck.B.slice() }, n: { A: n.A, B: n.B } });
    });
    const leaks = script.map((_, k) => {
      const s = { ck: { A: snaps[k].ck.A.slice(), B: snaps[k].ck.B.slice() }, n: { A: snaps[k].n.A, B: snaps[k].n.B } };
      return msgs.map((m) => {
        if (m.i <= k) return false;                      // the keys for these were deleted: nothing to derive them from
        while (s.n[m.from] < m.header.n) { s.ck[m.from] = kdfCK(s.ck[m.from])[0]; s.n[m.from]++; }
        let mk; [s.ck[m.from], mk] = kdfCK(s.ck[m.from]); s.n[m.from]++;
        try { open(mk, m.ct, m.tag, headerBytes(m.header)); return true; } catch (e) { return false; }
      });
    });
    return { msgs, leaks };
  }
  // Design C: the Double Ratchet. Alice and Bob alternate; a thief copies Alice's complete state after message k and follows along.
  function newConversation() {
    const alice = makeIdentity("Alice"), bob = makeIdentity("Bob");
    const bundle = makeBundle(bob, 1);
    const sk = randBytes(32);                            // the handshake is not the point here
    const a = Session.initAlice(sk, bundle.secret.spk.pub), b = Session.initBob(sk, bundle.secret.spk);
    return { a, b };
  }
  // A thief who copied Alice's complete state at one moment and then watches the wire (messages in both directions).
  class Thief {
    constructor(snap) {
      this.ad = snap.ad;
      this.T = { RK: snap.RK && snap.RK.slice(), DHs: snap.DHs && { priv: snap.DHs.priv.slice(), pub: snap.DHs.pub.slice() },
        DHr: snap.DHr && snap.DHr.slice(), CKs: snap.CKs && snap.CKs.slice(), CKr: snap.CKr && snap.CKr.slice(), Ns: snap.Ns, Nr: snap.Nr };
    }
    step(which, nKey, target) {
      const T = this.T;
      while (T[nKey] < target) { T[which] = kdfCK(T[which])[0]; T[nKey]++; }
      let mk; [T[which], mk] = kdfCK(T[which]); T[nKey]++; return mk;
    }
    // m: { from: "A" | "B", header, ct, tag }; returns { ok, text }
    read(m) {
      const T = this.T, aad = concat(this.ad, headerBytes(m.header));
      let mk = null;
      if (m.from === "A") {
        if (T.DHs && T.CKs && equalBytes(m.header.pub, T.DHs.pub)) mk = this.step("CKs", "Ns", m.header.n);
      } else if (T.DHr && T.CKr && equalBytes(m.header.pub, T.DHr)) {
        mk = this.step("CKr", "Nr", m.header.n);
      } else if (T.DHs && T.RK) {
        // Alice's next ratchet step starts by combining her current private key with Bob's new public key: the thief can do that half...
        const [, ckr] = kdfRK(T.RK, dh(T.DHs.priv, m.header.pub));
        T.CKr = ckr; T.DHr = m.header.pub; T.Nr = 0;
        mk = this.step("CKr", "Nr", m.header.n);
        // ...but the second half uses a fresh key pair that Alice generates after the copy was made, which the thief never sees.
        T.RK = null; T.DHs = null; T.CKs = null;
      }
      if (!mk) return { ok: false, text: null };
      try { return { ok: true, text: readable(open(mk, m.ct, m.tag, aad)) }; } catch (e) { return { ok: false, text: null }; }
    }
  }
  function thiefFollows(snap, msgs, k) {
    const t = new Thief(snap);
    return msgs.map((m) => (m.i <= k ? false : t.read(m).ok));
  }
  function designDouble(script = SCRIPT) {
    const { a, b } = newConversation();
    const msgs = [], snaps = [];
    script.forEach(([who, text], i) => {
      const from = who === "A" ? a : b, to = who === "A" ? b : a;
      // Bob cannot send before he has received once: the script always starts with Alice
      const m = from.send(text);
      to.receive({ header: m.header, ct: m.ct, tag: m.tag });
      msgs.push({ i, from: who, text, header: m.header, ct: m.ct, tag: m.tag });
      snaps.push(a.clone());
    });
    const leaks = script.map((_, k) => thiefFollows(snaps[k], msgs, k));
    return { msgs, leaks };
  }

  // --------------------------------------------------------------------------- group chats: how many encryptions does each design need? (order-of-magnitude, illustrative)
  const ceilLog2 = (n) => Math.max(1, Math.ceil(Math.log2(Math.max(2, n))));
  function groupCosts(n) {
    return {
      pairwise: { message: n - 1, setup: 0, leave: 0 },                       // one pairwise copy per other member; leaving just means no more copies
      senderKeys: { message: 1, setup: n * (n - 1), leave: (n - 1) * (n - 2) }, // everyone sends their sender key to everyone; after a leave everyone replaces theirs
      tree: { message: 1, setup: n - 1, leave: ceilLog2(n) },                  // a Welcome per new member; a leave is one commit with about log2(n) encryptions
    };
  }

  root.Msg = { x25519, genKeyPair, dh, BASE, hkdf, kdfRK, kdfCK, keyNonce, seal, open, headerBytes, readable, Session, makeIdentity, makeBundle, bundleSigOk,
    x3dhKdf, x3dhStart, x3dhFinish, quantumAttack, fingerprint, safetyNumber, SCRIPT, designStatic, designChain, designDouble, newConversation,
    Thief, thiefFollows, groupCosts, ceilLog2, staticKey, u32, hex, concat, utf8 };
  if (typeof module !== "undefined" && module.exports) module.exports = root.Msg;
})(typeof window !== "undefined" ? window : globalThis);
