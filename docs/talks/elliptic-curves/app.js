/* app.js - the live demos for "Elliptic Curves Properly".
   The maths is in ec.js (window.ECLab), built on the shared crypto.js. Everything is written to be read, not to be safe:
   real P-256, Ed25519 and X25519 arithmetic, but variable-time, unblinded, and never for protecting anything.
   Nothing is fetched or sent anywhere. */
(function () {
  "use strict";
  const E = window.ECLab, L = window.Lab;

  // --------------------------------------------------------------------------- helpers
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const sp = (cls, s) => `<span class="${cls}">${esc(s)}</span>`;
  const click = (id, fn) => $(id).addEventListener("click", fn);
  function store(key, val) {
    try { if (val === undefined) return localStorage.getItem(key); localStorage.setItem(key, val); } catch (e) {}
    return null;
  }
  const setPressed = (id, attr, val) => { for (const b of $(id).querySelectorAll("button")) b.setAttribute("aria-pressed", String(b.getAttribute(attr) === String(val))); };
  const verdict = (id, cls, text) => { const el = $(id); el.className = "verdict" + (cls ? " " + cls : ""); el.textContent = text; };
  const note = (id, text, cls) => { const el = $(id); el.className = "comment" + (cls ? " " + cls : ""); el.textContent = text; };
  const bh = (x, len = 32) => L.hex(L.fromBig(x, len));
  const sh = (s, a = 12, b = 6) => (s.length > a + b + 1 ? s.slice(0, a) + "…" + s.slice(-b) : s);
  const pt = (P) => (P === null ? "∞" : `(${P[0]}, ${P[1]})`);
  const eqB = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
  const n = E.n256;

  // --------------------------------------------------------------------------- title: k·G on the toy curve
  function hero() {
    const el = $("hero-in"), raw = el.value.trim();
    el.style.width = Math.min(18, Math.max(5, raw.length + 1)) + "ch";
    const T = E.TOY17, N = 19n;
    let sel = -1, msg = "", cls = "";
    if (/^-?\d+$/.test(raw)) {
      const k = BigInt(raw), kk = ((k % N) + N) % N;
      sel = kk === 0n ? 19 : Number(kk);
      const P = E.wMul(T, kk, T.G);
      if (k === 0n) { msg = "0·G is the point at infinity: the curve's zero, reached by adding nothing."; cls = "y"; }
      else if (kk === 0n) { msg = k + "·G = ∞: you've gone all the way round. This group has 19 points, so 19 steps is a full lap."; cls = "y"; }
      else if (k === 42n) { msg = "The answer to life, the universe and everything. Here it is 4·G = " + pt(P) + ", because 42 mod 19 = 4."; cls = "ok"; }
      else if (k === 1n) { msg = "1·G is G itself: " + pt(P) + "."; cls = "ok"; }
      else if (k < 0n) { msg = k + "·G wraps round to " + kk + "·G = " + pt(P) + ". Negating k flips the point over: same x, y turned into −y."; cls = "ok"; }
      else if (k >= N) { msg = k + " mod 19 = " + kk + ", so " + k + "·G is the same point as " + kk + "·G = " + pt(P) + ". With only 19 points the multiples repeat; real curves have about 2²⁵⁶."; cls = "ok"; }
      else { msg = k + "·G = " + pt(P) + ". Going forward is easy. Going from the point back to k is the discrete logarithm: here you could try all 19."; cls = "ok"; }
    } else if (raw === "") { msg = "Type a whole number to multiply G by."; }
    else { msg = "k has to be a whole number. This curve doesn't do words, though a hash of one would make a fine k."; cls = "y"; }
    const cells = [];
    for (let i = 1; i <= 19; i++) {
      const P = i === 19 ? null : E.wMul(T, BigInt(i), T.G);
      cells.push(`<div class="hc${i === sel ? " k-on" : ""}${i === 19 ? " k-inf" : ""}"><b>${i}</b><small>${i === 19 ? "∞" : P[0] + "," + P[1]}</small></div>`);
    }
    $("hero-cells").innerHTML = cells.join("");
    note("hero-note", msg, cls);
  }

  // --------------------------------------------------------------------------- groups: order, generator, cofactor
  let grC = "17", grSel = 0;
  function groups() {
    const T = grC === "17" ? E.TOY17 : E.TOY37, pts = grC === "17" ? E.wPoints(T) : T.points;
    $("gr-pts").innerHTML = pts.map((P, i) => `<button type="button" data-i="${i}" aria-pressed="${i === grSel}">${P === null ? "∞" : P[0] + "," + P[1]}</button>`).join("");
    const N = pts.length;
    $("gr-facts").innerHTML = `<div class="stat"><b>${N}</b><span>points (the group order)</span></div><div class="stat"><b>${T.n}</b><span>n: order of the generator G</span></div><div class="stat"><b>${T.h}</b><span>cofactor h = ${N} ÷ ${T.n}</span></div>`;
    const P = pts[grSel], ord = E.wOrder(T, P), inSub = E.wMul(T, T.n, P) === null;
    const isG = P !== null && P[0] === T.G[0] && P[1] === T.G[1];
    verdict("gr-sel", inSub ? "ok" : "y", (P === null ? "∞" : "P = " + pt(P)) + ": order " + ord + (inSub ? ", in the prime-order subgroup" : ", NOT in the prime-order subgroup"));
    const parts = []; let R = null;
    for (let i = 1; i <= Math.min(ord, 14); i++) { R = E.wAdd(T, R, P); parts.push(i === ord ? i + "P = " + sp("ok", "∞") : sp("m", i + "P ") + esc(pt(R))); }
    if (ord > 14) parts.push("… " + ord + "P = " + sp("ok", "∞"));
    let seq = parts.join("   ");
    if (P === null) seq = "∞ + ∞ = ∞: the identity, order 1.";
    $("gr-seq").innerHTML = seq;
    let msg = "";
    if (P === null) msg = "# the point at infinity is the group's zero: adding it changes nothing.";
    else if (grC === "17") msg = "# 19 is prime, so every point except ∞ has order 19: any of them could be the generator." + (isG ? " This is the Crypto 101 curve's G." : "");
    else if (ord === 11) msg = "# order 11: inside the prime-order subgroup, so a valid generator" + (isG ? " (this is the generator G the protocol would use)." : ".");
    else if (ord === 44) msg = "# order 44 generates the whole group, but a protocol wants the order-11 part. Multiply by the cofactor 4 and you land in it.";
    else msg = "# order " + ord + ": a small-order component. The subgroup check (n·P = ∞) exists to catch points like this.";
    note("gr-note", msg);
  }

  // --------------------------------------------------------------------------- shapes: Montgomery and Edwards
  function shapes() {
    const G = E.TOYG, N = G.N;
    const norm = (v) => ((parseInt(v, 10) || 0) % N + N) % N;
    const i = norm($("sh-i").value), j = norm($("sh-j").value), k = (i + j) % N;
    const mP = G.mult[i], mQ = G.mult[j], eP = G.edw[i], eQ = G.edw[j];
    const mp = (P) => (P === null ? "∞" : `(${P[0]}, ${P[1]})`), ep = (P) => `(${P[0]}, ${P[1]})`;
    const add = E.mAddT(mP, mQ), eS = E.eAdd(eP, eQ);
    const agree = (add.R === null ? eS[0] === 0n && eS[1] === 1n : (() => { const t = E.mToE(add.R); return t[0] === eS[0] && t[1] === eS[1]; })()) && eS[0] === G.edw[k][0] && eS[1] === G.edw[k][1];
    $("sh-out").innerHTML =
      `${sp("m", "              " + "Montgomery (u, v)".padEnd(20) + "Edwards (x, y)")}\n${("P = " + i + "·g").padEnd(14)}${mp(mP).padEnd(20)}${ep(eP)}\n${("Q = " + j + "·g").padEnd(14)}${mp(mQ).padEnd(20)}${ep(eQ)}\n${("P+Q = " + k + "·g").padEnd(14)}${mp(add.R).padEnd(20)}${ep(eS)}\n\n` +
      (agree ? sp("ok", "✓ the two forms agree: mapping the Montgomery sum gives the Edwards sum") : sp("bad", "✗ the forms disagree"));
    const KIND = { identity: "one of the points is ∞: a special case", inverse: "P = −Q: they cancel to ∞, another special case", double: "P = Q: the tangent (doubling) formula, a different one", chord: "the ordinary chord formula" };
    verdict("sh-case", add.kind === "chord" ? "" : "y", "Montgomery form: " + KIND[add.kind] + ". Edwards form: the same formula as always.");
    note("sh-note", i === 0 || j === 0 ? "# with ∞ (0·g) the Montgomery code takes a special path; the Edwards neutral point (0, 1) goes through the normal formula." : "# the numbers differ, but the group is the same: each point has a partner in the other form.");
  }
  function shapesAll() {
    const G = E.TOYG, N = G.N, c = E.caseCounts();
    let ok = true;
    for (let i = 0; i < N && ok; i++) for (let j = 0; j < N; j++) { const s = E.eAdd(G.edw[i], G.edw[j]), t = G.edw[(i + j) % N]; if (s[0] !== t[0] || s[1] !== t[1]) { ok = false; break; } }
    const sp7 = c.counts.identity + c.counts.inverse + c.counts.double, f = (x) => x.toLocaleString("en-US");
    $("sh-tally").innerHTML = `Montgomery: ${f(c.counts.chord)} ordinary, and ${sp("y", f(sp7))} special cases (${f(c.counts.identity)} with ∞, ${f(c.counts.inverse)} opposite pairs, ${f(c.counts.double)} doublings).<br>Edwards: ${sp("ok", "0")} special cases. One formula, all ${f(c.pairs)} sums ${ok ? "correct" : "WRONG"}.`;
    note("sh-note", "# a branch that depends on which case you're in is a branch that depends on the data. In Edwards form there is nothing to branch on.", "ok");
  }

  // --------------------------------------------------------------------------- choosing curves
  const CURVE_DETAIL = {
    p256: "NIST P-256 (secp256r1, prime256v1). SafeCurves: not safe. Rigidity: \"manipulatable\": “Coefficients generated by hashing the unexplained seed c49d3608 86e70493 6a6678e1 139d26b7 819f7e90.” It also fails the ladder, completeness and indistinguishability criteria and passes twist security. That is a design argument, not a break: no practical attack on P-256 is known, and it is used almost everywhere.",
    p384: "NIST P-384. SafeCurves: not safe. Same family and same overall verdict as P-256 (Weierstrass, standard NIST generation). This deck doesn't break the verdict down. Chosen where a policy asks for more strength than P-256.",
    k1: "secp256k1, from SEC 2. SafeCurves: not safe, but \"somewhat rigid\": a Koblitz-style curve with a prime-order group and simple parameters (a = 0, b = 7). It fails the ladder and completeness criteria, and the discriminant one. Bitcoin and Ethereum use it, so you meet it whether you like it or not.",
    c25519: "Curve25519 / edwards25519. SafeCurves: safe on every criterion, \"fully rigid\": the prime 2²⁵⁵ − 19 is the one closest below a power of two among the options considered, and A = 486662 is the smallest value meeting the security requirements. Cofactor 8. X25519 uses the Montgomery form; Ed25519 the Edwards form.",
    ed448: "Curve448 / Ed448-Goldilocks. SafeCurves: safe. p = 2⁴⁴⁸ − 2²²⁴ − 1, cofactor 4. X448 and Ed448 (RFC 7748 and RFC 8032) give more margin than the 25519 pair at more cost, and are used less.",
  };
  function choosing() {
    const rows = Array.from($("cv-table").querySelectorAll("tbody tr"));
    const pick = (r) => { rows.forEach((x) => x.classList.toggle("sel", x === r)); $("cv-detail").textContent = CURVE_DETAIL[r.dataset.k]; };
    rows.forEach((r) => { r.addEventListener("click", () => pick(r)); r.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); pick(r); } }); });
  }

  // --------------------------------------------------------------------------- encoding and validation
  let enC = "p256";
  function encCurve() { return enC === "p256" ? E.P256 : E.TOY37; }
  function encPresets() {
    const c = encCurve(), G = c.G, L2 = c.bytes, out = [];
    const unc = E.encodePoint(c, G, false), comp = E.encodePoint(c, G, true);
    out.push(["Valid, uncompressed", unc], ["Valid, compressed", comp]);
    if (enC === "p256") {
      const bad = Uint8Array.from(unc); bad[bad.length - 1] ^= 1; out.push(["One digit of y changed", bad]);
      let x = 1n; while (E.sqrt(E.mod(x * x * x + c.a * x + c.b, c.p), c.p) !== null) x++;
      out.push(["Compressed: no such point", L.concat(Uint8Array.of(2), L.fromBig(x, 32))]);
      out.push(["x ≥ p", L.concat(Uint8Array.of(4), L.fromBig(c.p + 5n, 32), L.fromBig(G[1], 32))]);
    } else {
      const wrong = c.points.find((P) => P !== null && E.wMul(c, c.n, P) !== null);
      out.push(["On the curve, wrong subgroup", E.encodePoint(c, wrong, false)]);
      let ox = 0n, oy = 0n; for (let a = 0n; a < c.p; a++) { let f = false; for (let b = 0n; b < c.p; b++) if (!E.wOn(c, [a, b])) { ox = a; oy = b; f = true; break; } if (f) break; }
      out.push(["Off the curve", L.concat(Uint8Array.of(4), L.fromBig(ox, 1), L.fromBig(oy, 1))]);
      out.push(["x ≥ p", L.concat(Uint8Array.of(4), L.fromBig(c.p + 3n, 1), L.fromBig(G[1], 1))]);
    }
    out.push(["Wrong length", unc.slice(0, unc.length - 2)], ["Point at infinity", Uint8Array.of(0)]);
    return out;
  }
  function encRender() {
    const c = encCurve(), txt = $("en-hex").value.replace(/0x/gi, "").replace(/\s+/g, "");
    if (!/^([0-9a-fA-F]{2})*$/.test(txt)) { verdict("en-verdict", "bad", "That isn't valid hex (an even number of 0–9, a–f)."); $("en-checks").innerHTML = ""; note("en-info", ""); return; }
    const bytes = L.fromHex(txt), r = E.checkPoint(c, bytes);
    verdict("en-verdict", r.ok ? "ok" : "bad", r.ok ? "Accepted: a valid point in the right group." : "Rejected: do not use this point.");
    $("en-checks").innerHTML = r.checks.map((k) => `<li class="${k.ok === true ? "ok" : k.ok === false ? "bad" : "skip"}"><b>${k.ok === true ? "✓" : k.ok === false ? "✗" : "–"}</b> <span>${esc(k.name)}<small>${esc(k.msg)}</small></span></li>`).join("");
    note("en-info", r.ok ? "# decoded point: x = " + sh(r.P[0].toString(16), 10, 6) + ", y = " + sh(r.P[1].toString(16), 10, 6) + (c.h > 1n ? " (cofactor " + c.h + ")" : "") : "# " + (bytes.length ? bytes.length + " bytes, prefix " + L.hex(bytes.slice(0, 1)) : "no bytes"));
  }
  function encLoad() {
    const pre = encPresets();
    $("en-pre").innerHTML = pre.map((p, i) => `<button type="button" data-i="${i}">${esc(p[0])}</button>`).join("");
    $("en-pre").dataset.n = pre.length;
    $("en-pre")._pre = pre;
    $("en-hex").value = L.hex(pre[0][1]);
    encRender();
  }
  function encoding() {
    $("en-curve").addEventListener("click", (e) => { const b = e.target.closest("button[data-c]"); if (!b) return; enC = b.dataset.c; setPressed("en-curve", "data-c", enC); encLoad(); });
    $("en-pre").addEventListener("click", (e) => { const b = e.target.closest("button[data-i]"); if (!b) return; $("en-hex").value = L.hex($("en-pre")._pre[+b.dataset.i][1]); encRender(); });
    $("en-hex").addEventListener("input", encRender);
    encLoad();
  }

  // --------------------------------------------------------------------------- ECDSA step by step
  const ec = { d: 0n, Q: null, sigs: 0, last: null };
  function ecNewKey() { ec.d = 1n + L.randBelow(n - 1n); ec.Q = E.ecPub(ec.d); ec.sigs = 0; ec.last = null; }
  function ecShow(extra) {
    const m = $("ec-msg").value, h = E.hashInt(m), s = ec.last;
    let o = `${sp("m", "private key d")} = ${sh(bh(ec.d), 10, 4)}   ${sp("m", "(secret)")}\n${sp("m", "public key Q.x")} = ${sh(bh(ec.Q[0]), 10, 4)}\n${sp("m", "h = SHA-256(message)")} = ${sh(bh(h), 10, 4)}\n`;
    if (s) {
      o += `${sp("y", "k (fresh random)")} = ${sh(bh(s.k), 10, 4)}   ${sp("m", "← the secret nonce, never shown to anyone")}\n${sp("m", "r = (k·G).x mod n")} = ${sh(bh(s.r), 10, 4)}\n${sp("m", "s = k⁻¹(h + r·d)")} = ${sh(bh(s.s), 10, 4)}\n\n`;
      o += extra || `verify(Q, h, (r, s)) = ${E.ecVerify(ec.Q, s.h, [s.r, s.s]) ? sp("ok", "✓ valid") : sp("bad", "✗ invalid")}`;
    } else o += "\nPress Sign.";
    $("ec-out").innerHTML = o;
  }
  function ecSign() {
    const m = $("ec-msg").value, h = E.hashInt(m), k = 1n + L.randBelow(n - 1n), sig = E.ecSign(ec.d, h, k);
    ec.last = { k, r: sig[0], s: sig[1], h, m }; ec.sigs++;
    ecShow();
    if (ec.sigs >= 10) note("ec-note", "# ten signatures, ten different k. If any two had matched we'd be in the next slide's trouble.", "ok");
    else note("ec-note", ec.sigs > 1 ? "# signature #" + ec.sigs + ": r and s changed because k did, and every one of them verifies." : "# one signature. Sign again and watch r change.");
  }
  function ecTamper() {
    if (!ec.last) ecSign();
    const m = $("ec-msg").value || " ", changed = m.slice(0, -1) + String.fromCharCode(m.charCodeAt(m.length - 1) + 1), h2 = E.hashInt(changed), s = ec.last;
    ecShow(`verify with the message changed to "${esc(changed)}" = ${E.ecVerify(ec.Q, h2, [s.r, s.s]) ? sp("bad", "✓ valid (!)") : sp("ok", "✗ invalid, as it should be")}`);
    note("ec-note", "# one letter changed, a completely different h, and the signature no longer fits.");
  }
  function ecdsa() {
    ecNewKey();
    click("ec-sign", ecSign); click("ec-again", ecSign); click("ec-tamper", ecTamper);
    click("ec-newkey", () => { ecNewKey(); ecShow(); note("ec-note", "# a new key pair: every signature below is checked against the new public key."); });
    ecSign();
    note("ec-note", "# one signature. Sign again and watch r change.");
  }

  // --------------------------------------------------------------------------- the nonce
  let ncMode = "same";
  function nonceRun(sony) {
    const m1 = $("nc-m1").value, m2 = $("nc-m2").value, d = 1n + L.randBelow(n - 1n), h1 = E.hashInt(m1), h2 = E.hashInt(m2);
    let k1, k2;
    if (ncMode === "same") k1 = k2 = 1n + L.randBelow(n - 1n);
    else if (ncMode === "random") { k1 = 1n + L.randBelow(n - 1n); k2 = 1n + L.randBelow(n - 1n); }
    else { k1 = E.rfc6979(d, L.sha256(L.utf8(m1))); k2 = E.rfc6979(d, L.sha256(L.utf8(m2))); }
    const s1 = E.ecSign(d, h1, k1), s2 = E.ecSign(d, h2, k2), same = s1[0] === s2[0];
    let o = `${sp("m", "message 1")} ${esc(JSON.stringify(m1))}\n  r = ${sh(bh(s1[0]), 10, 4)}\n  s = ${sh(bh(s1[1]), 10, 4)}\n${sp("m", "message 2")} ${esc(JSON.stringify(m2))}\n  r = ${sh(bh(s2[0]), 10, 4)}\n  s = ${sh(bh(s2[1]), 10, 4)}\n\nr values equal? ${same ? sp("bad", "yes") : sp("ok", "no")}\n`;
    const rec = E.ecRecover(h1, s1, h2, s2);
    if (rec) {
      o += `\nk = (h₁ − h₂) / (s₁ − s₂)  = ${sh(bh(rec.k), 10, 4)}\nd = (s₁·k − h₁) / r        = ${sh(bh(rec.d), 10, 4)}\nreal private key           = ${sh(bh(d), 10, 4)}`;
      verdict("nc-verdict", "bad", rec.d === d ? "The private key was recovered from two public signatures." : "Recovery failed (unexpected).");
    } else if (same) {
      verdict("nc-verdict", "y", "The two signatures are identical (same message, same k), so there is nothing to subtract. Use two different messages.");
    } else verdict("nc-verdict", "ok", "The r values differ, so there is no nonce to recover and no key leaked.");
    $("nc-out").innerHTML = o;
    const MODE = {
      same: "# one k for two messages: anyone holding the two signatures and the messages can compute k, then d. Nothing about the curve was broken.",
      random: "# fresh k each time is safe only if the generator is good. The Android 2013 wallet failures were bad generators, not bad curves.",
      rfc: "# derived from the key and the message: it can't repeat across different messages, and no random source is needed at signing time.",
    };
    note("nc-note", sony ? "# a model of the 2010 PlayStation 3 failure (the sources agree on one k used every time; the real data isn't shown here)." : MODE[ncMode], sony ? "y" : "");
  }
  function nonce() {
    $("nc-mode").addEventListener("click", (e) => { const b = e.target.closest("button[data-m]"); if (!b) return; ncMode = b.dataset.m; setPressed("nc-mode", "data-m", ncMode); nonceRun(false); });
    click("nc-run", () => nonceRun(false));
    click("nc-sony", () => { ncMode = "same"; setPressed("nc-mode", "data-m", "same"); $("nc-m1").value = "Signed boot loader A"; $("nc-m2").value = "Signed boot loader B"; nonceRun(true); });
    nonceRun(false);
  }

  // --------------------------------------------------------------------------- bias
  function bias() {
    const run = () => {
      const z = +$("bi-bits").value; $("bi-n").textContent = z;
      const hist = E.topHistogram(E.biasedNonces(z, 300, 7)), mx = Math.max(...hist);
      $("bi-chart").innerHTML = hist.map((v, i) => `<div class="bi-col"><i style="height:${Math.round((v / Math.max(mx, 1)) * 100)}%" class="${v === 0 ? "z" : ""}"></i><small>${i.toString(16)}</small><b>${v}</b></div>`).join("");
      if (z === 0) note("bi-note", "# uniform: about 19 of 300 nonces in each of the 16 buckets.", "ok");
      else if (z >= 8) note("bi-note", "# 8 of 256 bits known for every signature, from every signature. Lattice territory.", "bad");
      else if (z >= 4) note("bi-note", "# every nonce in one bucket: " + z + " bits known per signature.", "bad");
      else note("bi-note", "# the top " + z + " bit" + (z > 1 ? "s are" : " is") + " always zero: " + (16 - (16 >> z)) + " of the 16 buckets are empty. One known bit per nonce is already a leak.", "y");
    };
    $("bi-bits").addEventListener("input", run); run();
  }

  // --------------------------------------------------------------------------- RFC 6979
  function rfc() {
    const d = BigInt("0x" + E.V.ec.d), run = () => {
      const m = $("rf-msg").value, h1 = L.sha256(L.utf8(m)), k = E.rfc6979(d, h1), sig = E.ecSign(d, L.toBig(h1), k), k2 = E.rfc6979(d, h1);
      $("rf-out").innerHTML = `${sp("m", "x (the RFC's example key)")} = ${sh(bh(d), 10, 4)}\n${sp("m", "h1 = SHA-256(message)")}   = ${sh(L.hex(h1), 10, 4)}\n${sp("m", "start: V = 0x01…01, K = 0x00…00")}\n${sp("m", "K = HMAC(K, V ‖ 0x00 ‖ x ‖ h1); V = HMAC(K, V)")}\n${sp("m", "K = HMAC(K, V ‖ 0x01 ‖ x ‖ h1); V = HMAC(K, V)")}\n${sp("m", "V = HMAC(K, V)  →  k")}\n\nk = ${sp("y", sh(bh(k), 12, 6))}\nsame message again → k ${k2 === k ? sp("ok", "identical") : sp("bad", "different")}\nsignature r = ${sh(bh(sig[0]), 10, 4)}`;
      verdict("rf-kat-out", "", "");
    };
    $("rf-msg").addEventListener("input", run);
    click("rf-kat", () => {
      const e = E.V.ec, h1 = L.sha256(L.utf8(e.msg)), k = E.rfc6979(d, h1), sig = E.ecSign(d, L.toBig(h1), k);
      const ok = k === BigInt("0x" + e.k) && sig[0] === BigInt("0x" + e.r) && sig[1] === BigInt("0x" + e.s);
      verdict("rf-kat-out", ok ? "ok" : "bad", ok ? "✓ message \"sample\": k, r and s all match RFC 6979 appendix A.2.5 (P-256, SHA-256)." : "✗ does not match the RFC vector");
    });
    run();
  }

  // --------------------------------------------------------------------------- Ed25519
  const ed = { seed: null, pub: null, sigs: 0, first: null };
  function edNew() { ed.seed = L.randBytes(32); ed.pub = E.edPublic(ed.seed); ed.sigs = 0; ed.first = null; }
  const PKCS8 = L.fromHex("302e020100300506032b657004220420");
  async function edWebCrypto(msg, mine) {
    const out = $("ed-wc");
    if (!(window.crypto && crypto.subtle)) { out.textContent = "Not available here: Web Crypto needs a secure context (https or localhost)."; return; }
    try {
      const key = await crypto.subtle.importKey("pkcs8", L.concat(PKCS8, ed.seed), { name: "Ed25519" }, false, ["sign"]);
      const theirs = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, key, msg));
      const valid = E.edVerify(ed.pub, msg, theirs), same = eqB(theirs, mine);
      out.innerHTML = `Your browser signed the same message with its own Ed25519. This page's code ${valid ? sp("ok", "verifies it ✓") : sp("bad", "rejects it ✗")}. Bytes identical to this page's: ${same ? sp("ok", "yes ✓") : sp("y", "no")}.${same ? "" : " (Safari randomises Ed25519 signatures; it still verifies.)"}`;
    } catch (e) { out.textContent = "This browser has no Ed25519 in Web Crypto (Chrome 137, Firefox 129 or Safari 17 and newer do), so there is nothing to compare."; }
  }
  function edSign() {
    const msg = L.utf8($("ed-msg").value), { prefix, a } = E.expand(ed.seed);
    const r = E.mod(E.leToBig(E.sha512(L.concat(prefix, msg))), E.L25), sig = E.edSign(ed.seed, msg), valid = E.edVerify(ed.pub, msg, sig);
    ed.sigs++; const hexSig = L.hex(sig);
    const same = ed.first !== null && ed.first.m === $("ed-msg").value ? hexSig === ed.first.sig : null;
    if (ed.first === null || ed.first.m !== $("ed-msg").value) ed.first = { m: $("ed-msg").value, sig: hexSig, n: 1 };
    else ed.first.n++;
    $("ed-out").innerHTML = `${sp("m", "seed (secret)")}  ${sh(L.hex(ed.seed), 12, 4)}\n${sp("m", "public key A")}   ${sh(L.hex(ed.pub), 12, 4)}\n${sp("m", "r = SHA-512(prefix ‖ M) mod L")}  ${sh(bh(r), 10, 4)}\n${sp("m", "R = r·B")}  ${sh(L.hex(sig.slice(0, 32)), 12, 4)}\n${sp("m", "S = r + H(R‖A‖M)·a mod L")}  ${sh(L.hex(sig.slice(32)), 10, 4)}\n\nsignature (64 bytes) = ${sp("y", sh(hexSig, 16, 8))}\nverify (RFC 8032 rules) = ${valid ? sp("ok", "✓ valid") : sp("bad", "✗ invalid")}` +
      (same === true ? `\nsame message again → ${sp("ok", "byte-for-byte identical")}` : "");
    note("ed-note", ed.first.n > 1 ? "# signing the same message again gives the very same 64 bytes: there's no k to vary." : "# no nonce argument anywhere. Press Sign again.");
    edWebCrypto(msg, sig);
  }
  function eddsa() {
    edNew(); click("ed-sign", edSign); click("ed-again", edSign); click("ed-new", () => { edNew(); edSign(); });
    $("ed-msg").addEventListener("input", () => { ed.first = null; });
    edSign();
  }

  // --------------------------------------------------------------------------- malleability
  let mlS = "ed";
  const mlCache = {};
  function mlResults() { for (const k of Object.keys(E.PROFILES)) if (!mlCache[k]) mlCache[k] = E.runEdgeCases(k); return mlCache; }
  function malleable() {
    const render = () => {
      const R = mlResults(), ids = mlS === "ed" ? ["ed-valid", "ed-s-plus-l"] : ["ec-valid", "ec-high-s"], cases = ids.map((id) => R.textbook.find((r) => r.id === id));
      if (mlS === "ed") {
        const sig = L.fromHex(E.V.ed[1].sig), S = E.leToBig(sig.slice(32)), S2 = S + E.L25;
        $("ml-sigs").innerHTML = `${sp("m", "original  S")}  = ${sh(bh(S), 12, 6)}\n${sp("m", "L (group order)")} = ${sh(bh(E.L25), 12, 6)}\n${sp("m", "S + L")}        = ${sh(bh(S2), 12, 6)}  ${sp("y", "still fits in 32 bytes")}\n\nsame R, same message, two different\n64-byte signatures.`;
      } else {
        const d = BigInt("0x" + E.V.ec.d), k = E.rfc6979(d, L.sha256(L.utf8("sample"))), sg = E.ecSign(d, E.hashInt("sample"), k), lo = sg[1] > n / 2n ? n - sg[1] : sg[1];
        $("ml-sigs").innerHTML = `${sp("m", "r")}        = ${sh(bh(sg[0]), 12, 6)}   ${sp("m", "(same in both)")}\n${sp("m", "s")}        = ${sh(bh(lo), 12, 6)}\n${sp("m", "n − s")}    = ${sh(bh(n - lo), 12, 6)}  ${sp("y", "also verifies")}\n\n(r, s) and (r, n − s): one message,\ntwo valid signatures.`;
      }
      note("ml-why", "# " + cases[1].why);
      const rows = cases.map((c) => `<tr><th>${esc(c.id.endsWith("valid") ? "The original signature" : mlS === "ed" ? "S replaced by S + L" : "s replaced by n − s")}</th>` + Object.keys(E.PROFILES).map((k) => { const r = R[k].find((x) => x.id === c.id); return `<td class="${r.good ? "yes" : "no"}">${r.accepted ? "accepts" : "rejects"}${r.good ? "" : " ✗"}</td>`; }).join("") + "</tr>").join("");
      $("ml-table").querySelector("tbody").innerHTML = rows;
    };
    $("ml-pick").addEventListener("click", (e) => { const b = e.target.closest("button[data-s]"); if (!b) return; mlS = b.dataset.s; setPressed("ml-pick", "data-s", mlS); render(); });
    render();
  }

  // --------------------------------------------------------------------------- validation
  let ivI = 0, ivV = "off";
  const D_SERVER = 397n;
  function validate() {
    $("iv-pick").innerHTML = E.FOREIGN.map((f, i) => `<button type="button" data-i="${i}" aria-pressed="${i === 0}">order ${f.order}</button>`).join("");
    const iv = () => {
      const F = E.FOREIGN[ivI], Q = F.Q, c = E.ICc, lhs = E.mod(Q[1] * Q[1], c.p), rhs = E.mod(Q[0] ** 3n + c.a * Q[0] + c.b, c.p);
      if (ivV === "on") {
        $("iv-out").innerHTML = `client sends Q' = ${pt(Q)}\nserver checks y² = x³ + x + 17 (mod 1009):\n  y² = ${lhs}\n  x³ + x + 17 = ${rhs}\n  ${sp("ok", "not equal → rejected")}\nno secret was used. Nothing leaked.`;
        return;
      }
      const r = E.noValidate(D_SERVER, F);
      $("iv-out").innerHTML = `client sends Q' = ${pt(Q)}   ${sp("m", "(not on the server's curve)")}\nserver: on-curve check ${sp("bad", "skipped")}\nserver returns d·Q' = ${r.S === null ? "∞" : pt(r.S)}\n\nQ' has order ${F.order}, so d·Q' can only be one of ${F.order} values.\nIt depends on d mod ${F.order} alone: ${sp("bad", "about " + r.bits.toFixed(1) + " bits of d, from one message")}.`;
    };
    $("iv-pick").addEventListener("click", (e) => { const b = e.target.closest("button[data-i]"); if (!b) return; ivI = +b.dataset.i; setPressed("iv-pick", "data-i", ivI); iv(); });
    $("iv-val").addEventListener("click", (e) => { const b = e.target.closest("button[data-v]"); if (!b) return; ivV = b.dataset.v; setPressed("iv-val", "data-v", ivV); iv(); });
    iv();
    // X25519
    let loU = "good", loC = "off";
    const aPriv = L.fromHex(E.V.x[1].k), bPub = L.fromHex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    const lo = () => {
      const u = loU === "good" ? bPub : (() => { const b = new Uint8Array(32); b[0] = loU === "0" ? 0 : 1; return b; })();
      const K = E.x25519(aPriv, u), zero = E.allZero(K);
      let o = `Bob sends u = ${sp("y", sh(L.hex(u), 12, 4))}\nAlice computes X25519(a, u) = ${zero ? sp("bad", L.hex(K).slice(0, 16) + "…  all zero") : sp("ok", sh(L.hex(K), 12, 6))}\n`;
      if (loU === "good") o += `\n${L.hex(K) === E.V.x[2].out ? sp("ok", "✓ matches the shared secret in RFC 7748 section 6.1") : ""}`;
      else if (zero && loC === "on") o += `\n${sp("ok", "Alice aborts: an all-zero result means a low-order input.")}`;
      else if (zero) o += `\n${sp("bad", "The result is zero whatever Alice's key is: anyone can compute it, and her key contributed nothing.")}`;
      $("lo-out").innerHTML = o;
    };
    $("lo-pick").addEventListener("click", (e) => { const b = e.target.closest("button[data-u]"); if (!b) return; loU = b.dataset.u; setPressed("lo-pick", "data-u", loU); lo(); });
    $("lo-chk").addEventListener("click", (e) => { const b = e.target.closest("button[data-c]"); if (!b) return; loC = b.dataset.c; setPressed("lo-chk", "data-c", loC); lo(); });
    lo();
  }

  // --------------------------------------------------------------------------- constant time: comparison
  function ctCompare() {
    const SECRET = "hunter2!";
    let mode = "early";
    const run = () => {
      const g = $("cc-guess").value, r = E.compareSteps(SECRET, g, mode), prof = E.compareProfile(SECRET, mode), mx = SECRET.length;
      $("cc-chart").innerHTML = prof.map((v, i) => `<div class="bi-col"><i style="height:${Math.round((v / mx) * 100)}%"></i><small>${i}</small><b>${v}</b></div>`).join("");
      if (g === SECRET) verdict("cc-out", "ok", "Equal. Both versions give the same answer: they differ in what they reveal on the way.");
      else verdict("cc-out", r.steps > 1 && mode === "early" ? "y" : "", "Not equal. Steps taken: " + r.steps + " of " + mx + ".");
      note("cc-note", mode === "early" ? "# the steps climb with each correct leading byte: anyone who can time this learns the secret one byte at a time." : "# always 8 steps: the work says nothing about the guess. XOR everything, test once at the end.", mode === "early" ? "y" : "ok");
    };
    $("cc-mode").addEventListener("click", (e) => { const b = e.target.closest("button[data-m]"); if (!b) return; mode = b.dataset.m; setPressed("cc-mode", "data-m", mode); run(); });
    $("cc-guess").addEventListener("input", run); run();
  }

  // --------------------------------------------------------------------------- constant time: scalar multiplication
  function ctScalar() {
    const run = () => {
      const bits = $("cs-bits").value.replace(/[^01]/g, ""), d = E.scalarOps(bits, "dbl"), l = E.scalarOps(bits, "ladder");
      const fmt = (ops, hi) => ops.match(/.{1,2}/g) ? ops.split("").map((c) => (c === "A" && hi ? sp("bad", c) : esc(c))).join(" ") : "(nothing: a one-bit key needs no operations)";
      $("cs-dbl").innerHTML = bits ? fmt(d.ops.replace(/D/g, "D"), true) : "";
      $("cs-lad").innerHTML = bits ? fmt(l.ops, false) : "";
      $("cs-dbl-n").textContent = bits ? `${d.doubles} doubles, ${d.adds} adds: each A is a 1 bit, so the key can be read off.` : "Enter some bits.";
      $("cs-lad-n").textContent = bits ? `${l.doubles} doubles, ${l.adds} adds, for every ${(d.bits || bits).length}-bit key.` : "";
      const b = d.bits || "";
      note("cs-note", !b ? "" : /^1+$/.test(b) ? "# all ones: the most additions possible, and the longest D A D A pattern." : b === "1" ? "# nothing to do." : "# change a bit and watch only the top sequence move.");
    };
    $("cs-bits").addEventListener("input", run);
    click("cs-rand", () => { const len = 8 + L.randInt(9); let s = "1"; for (let i = 1; i < len; i++) s += L.randInt(2); $("cs-bits").value = s; run(); });
    run();
  }

  // --------------------------------------------------------------------------- side channels
  const CHANNELS = [
    ["Timing", "remote, if you can send many requests", "How long an operation takes, seen through the network, a shared server or a plugin. A loop that exits early, a branch on a secret bit or a slow path for a special value all show up.", "Constant-time algorithms: no secret-dependent branches, loop counts or early returns. Test the compiled code, not just the source."],
    ["Cache", "local: code sharing the machine or CPU", "Which memory lines were touched, visible to a neighbour on the same CPU or cloud host. A table lookup indexed by a secret value draws a map of the secret.", "No lookups indexed by secrets: constant-time table selection, bit-sliced or table-free code, and hardware instructions where the CPU offers them."],
    ["Power and electromagnetic", "physical: the attacker holds the device", "The electricity a device draws or the radio it emits while computing. Relevant to smartcards, tokens, car keys and IoT. The double-and-add pattern from the last slide is exactly what shows up.", "Uniform algorithms (ladders, complete formulas), blinding or masking so intermediate values are randomised, and physical shielding."],
    ["Faults", "physical, sometimes remote", "Make the device compute something wrong (a voltage glitch, a laser pulse, a flipped memory bit) and watch the wrong answer. A faulty signature can reveal the key.", "Check your own work before releasing it: verify the signature you just made, recompute and compare, and protect the hardware."],
    ["Speculation and shared buffers", "local, through the processor itself", "Effects of a CPU running ahead speculatively or sharing internal buffers between programs (the Spectre family). Code can be correct and still leak.", "Mostly the platform's job: processor and operating-system patches, compiler mitigations and isolating secrets in separate processes or machines."],
  ];
  function sideChannels() {
    $("sc-list").innerHTML = CHANNELS.map((c, i) => `<li><button type="button" class="mi-row" data-i="${i}"><span><b>${esc(c[0])}</b></span><span class="tm-pips">${esc(c[1])}</span></button></li>`).join("");
    $("sc-list").addEventListener("click", (e) => {
      const b = e.target.closest("button[data-i]"); if (!b) return;
      for (const x of $("sc-list").querySelectorAll(".mi-row")) x.classList.toggle("sel", x === b);
      const c = CHANNELS[+b.dataset.i];
      $("sc-detail").innerHTML = `<b>${esc(c[0])}</b><br><span class="m">What leaks:</span> ${esc(c[2])}<br><span class="m">The usual defence:</span> ${esc(c[3])}`;
    });
    $("sc-list").querySelector("button").click();
  }

  // --------------------------------------------------------------------------- testing
  let tsP = "textbook";
  function testing() {
    $("ts-prof").innerHTML = Object.keys(E.PROFILES).map((k) => `<button type="button" data-p="${k}" aria-pressed="${k === tsP}">${esc(E.PROFILES[k].label)}</button>`).join("");
    $("ts-prof").addEventListener("click", (e) => { const b = e.target.closest("button[data-p]"); if (!b) return; tsP = b.dataset.p; setPressed("ts-prof", "data-p", tsP); reset(); });
    const reset = () => { verdict("ts-kat", "", ""); $("ts-table").querySelector("tbody").innerHTML = ""; note("ts-note", "# press the button to run both."); };
    click("ts-run", () => {
      const kats = E.runKATs(E.PROFILES[tsP]), pass = kats.filter((k) => k.ok).length;
      verdict("ts-kat", pass === kats.length ? "ok" : "bad", `Known-answer tests: ${pass} of ${kats.length} pass (RFC 8032 and RFC 7748 vectors, and RFC 6979's nonce and signature).`);
      const R = E.runEdgeCases(tsP), bad = R.filter((r) => !r.good).length;
      $("ts-table").querySelector("tbody").innerHTML = R.map((r) => `<tr><th>${esc(r.kind)}: ${esc(r.name)}</th><td class="${r.good ? "yes" : "no"}">${r.accepted ? "accepts" : "rejects"}${r.good ? " ✓" : " ✗ should " + (r.shouldAccept ? "accept" : "reject")}</td></tr>`).join("");
      if (bad === 0) note("ts-note", "# all " + R.length + " edge cases handled. A handful of hand-made cases; the real suites have far more.", "ok");
      else if (pass === kats.length && tsP === "textbook") note("ts-note", "# every test vector passed, and it still gets " + bad + " of " + R.length + " edge cases wrong. The vectors only ever showed it good inputs.", "bad");
      else note("ts-note", "# " + bad + " of " + R.length + " edge cases handled wrongly.", "y");
    });
    reset();
    $("ts-run").click();
  }

  // --------------------------------------------------------------------------- choosing today
  const CH = [["new", "A new system, no outside constraint"], ["webauthn", "Passkeys / WebAuthn"], ["tls", "TLS or HTTPS"], ["jwt", "Tokens (JWT)"], ["ssh", "SSH"], ["bitcoin", "Bitcoin or Ethereum"]];
  function choose() {
    let pick = "new";
    $("ch-pick").innerHTML = CH.map((c) => `<button type="button" data-i="${c[0]}" aria-pressed="${c[0] === pick}">${esc(c[1])}</button>`).join("");
    const run = () => {
      const r = E.choose({ interop: pick, fips: $("ch-fips").checked });
      $("ch-sig").textContent = r.sig; $("ch-kex").textContent = r.kex; $("ch-why").textContent = r.why.join(" ");
      note("ch-note", pick === "new" && !$("ch-fips").checked ? "# when nothing forces your hand, the simplest curve pair is also the one with the most review." : "# the outside constraint, not the maths, makes the call.");
    };
    $("ch-pick").addEventListener("click", (e) => { const b = e.target.closest("button[data-i]"); if (!b) return; pick = b.dataset.i; setPressed("ch-pick", "data-i", pick); run(); });
    $("ch-fips").addEventListener("change", run);
    run();
  }

  // --------------------------------------------------------------------------- checklist
  const RV_KEY = "elliptic-curves-checklist";
  function checklist() {
    const boxes = Array.from(document.querySelectorAll("#rv-list input[type=checkbox]"));
    let saved = {};
    try { saved = JSON.parse(store(RV_KEY) || "{}"); } catch (e) {}
    boxes.forEach((b) => { b.checked = !!saved[b.dataset.k]; });
    const update = () => {
      const done = boxes.filter((b) => b.checked).length;
      store(RV_KEY, JSON.stringify(Object.fromEntries(boxes.map((b) => [b.dataset.k, b.checked]))));
      const el = $("rv-note"); el.className = "comment";
      if (done === boxes.length) { el.textContent = "# 10 of 10. Now go and read the library's changelog: that is where the next box will come from."; el.classList.add("ok"); }
      else if (!done) el.textContent = "# tick what's true for your team today. Each gap is a ticket, not a failure. Saved in this browser only.";
      else el.textContent = `# ${done} of ${boxes.length}. Pick the unticked box that's cheapest to fix this week.`;
    };
    boxes.forEach((b) => b.addEventListener("change", update));
    update();
  }

  // --------------------------------------------------------------------------- easter egg: console
  function consoleHint() {
    console.log("%c" + document.title, "font: 700 24px monospace; color: #ff2e88; text-shadow: 0 0 8px #ff2e88");
    console.log("%cconst k = 4;  // chosen by fair dice roll. guaranteed to be random.", "font: 14px monospace; color: #00f0ff");
    console.log("%c...and that is exactly how not to pick a nonce.", "font: 14px monospace; color: #f6e94b");
  }

  function boot() {
    consoleHint();
    $("hero-in").addEventListener("input", hero); hero();
    $("gr-curve").addEventListener("click", (e) => { const b = e.target.closest("button[data-c]"); if (!b) return; grC = b.dataset.c; grSel = grC === "17" ? 1 : E.TOY37.points.findIndex((P) => P && P[0] === E.TOY37.G[0] && P[1] === E.TOY37.G[1]); setPressed("gr-curve", "data-c", grC); groups(); });
    $("gr-pts").addEventListener("click", (e) => { const b = e.target.closest("button[data-i]"); if (!b) return; grSel = +b.dataset.i; groups(); });
    grSel = 1; groups();
    $("sh-i").addEventListener("input", shapes); $("sh-j").addEventListener("input", shapes);
    click("sh-rand", () => { $("sh-i").value = L.randInt(88); $("sh-j").value = L.randInt(88); shapes(); });
    click("sh-all", shapesAll); shapes();
    choosing(); encoding(); ecdsa(); nonce(); bias(); rfc(); eddsa(); malleable(); validate(); ctCompare(); ctScalar(); sideChannels(); testing(); choose(); checklist();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot); else boot();
})();
