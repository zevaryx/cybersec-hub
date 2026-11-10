/* zk.js - teaching versions of the proofs in "Zero-Knowledge Proofs".
   Real maths: Schnorr proofs on NIST P-256 (and a tiny toy curve so you can follow the numbers), the Fiat-Shamir transform with
   SHA-256, salted SHA-256 commitments, a graph 3-colouring proof, Merkle membership and an ECDSA-signed salted-digest credential,
   all built on ../../shared/crypto.js (window.Lab).
   TEACHING CODE, NEVER FOR REAL SECRETS: no constant-time arithmetic, no side-channel care, no audited parameters beyond the curve.
   Works in the browser (window.ZK) and in Node (module.exports) so it can be tested. */
(function (root) {
  "use strict";
  const L = root.Lab || (typeof require !== "undefined" ? require("../../shared/crypto.js") : null);
  const { P256, TOY, randBelow, sha256, utf8, concat, randBytes, toBig, equalBytes, modInv } = L;
  const mod = (a, n) => ((a % n) + n) % n;

  // --------------------------------------------------------------------------- groups
  const CURVES = { toy: TOY, p256: P256 };
  const mul = (C, k, P) => C.mul(mod(BigInt(k), C.n), P === undefined ? C.G : P);   // scalar multiplication (scalars live mod n)
  const neg = (C, P) => (P === null ? null : [P[0], mod(-P[1], C.p)]);
  const eq = (P, Q) => P === Q || (P !== null && Q !== null && P[0] === Q[0] && P[1] === Q[1]);
  const ptEnc = (P) => (P === null ? "inf" : P[0].toString(16) + "." + P[1].toString(16));
  const randScalar = (C) => randBelow(C.n - 1n) + 1n;     // 1 .. n-1

  // --------------------------------------------------------------------------- Schnorr's proof of knowledge of a discrete logarithm
  // Statement: "I know x with Y = xG".  Commit R = kG, challenge c, response s = k + c*x, check sG = R + cY.
  function keygen(C) { const x = randScalar(C); return { x, Y: mul(C, x) }; }
  function commit(C) { const k = randBelow(C.n); return { k, R: mul(C, k) }; }            // k may be 0: keeps the toy curve's distribution exact
  const challenge = (C) => randBelow(C.n);
  const respond = (C, x, k, c) => mod(k + c * x, C.n);
  function verify(C, Y, R, c, s) { return eq(mul(C, s), C.add(R, mul(C, c, Y))); }
  /** Special soundness: two answers to different challenges for the SAME commitment give away the secret. */
  function extract(C, c1, s1, c2, s2) {
    if (mod(c1 - c2, C.n) === 0n) throw new Error("the two challenges must differ");
    return mod((s1 - s2) * modInv(c1 - c2, C.n), C.n);
  }
  /** Zero knowledge (honest verifier): a transcript that verifies, made WITHOUT the secret, by working backwards from c and s. */
  function simulate(C, Y, cFixed) {
    const c = cFixed === undefined ? challenge(C) : cFixed, s = randBelow(C.n);
    return { c, s, R: C.add(mul(C, s), neg(C, mul(C, c, Y))) };
  }
  /** The best a bluffer can do against an interactive verifier: guess the challenge first, then build R backwards. */
  function bluff(C, Y, guess) {
    const t = simulate(C, Y);                    // t.c is the challenge the bluffer hopes to be asked
    return { R: t.R, wanted: t.c, answer: t.s, guess };
  }

  // --------------------------------------------------------------------------- Fiat-Shamir: the challenge becomes a hash
  const DOMAIN = "ZK-demo/schnorr/v1";
  const part = (s) => s.length + ":" + s;      // length-prefix every field, so no two inputs can be glued into the same string
  /** mode "strong" hashes everything; "noR" forgets the commitment; "noY" forgets the public key. The two weak modes are the demo's bugs. */
  function fsChallenge(C, mode, Y, R, msg) {
    const f = [DOMAIN, C.name];
    if (mode === "strong") f.push(ptEnc(C.G), ptEnc(Y), ptEnc(R), msg);
    else if (mode === "noR") f.push(ptEnc(C.G), ptEnc(Y), msg);
    else if (mode === "noY") f.push(ptEnc(C.G), ptEnc(R), msg);
    else throw new Error("unknown mode " + mode);
    return toBig(sha256(utf8(f.map(part).join("")))) % C.n;
  }
  function sign(C, mode, x, msg, k) {
    const Y = mul(C, x), kk = k === undefined ? randScalar(C) : k, R = mul(C, kk), c = fsChallenge(C, mode, Y, R, msg);
    return { Y, R, c, s: respond(C, x, kk, c), k: kk };
  }
  function checkSig(C, mode, Y, msg, R, s) {
    const c = fsChallenge(C, mode, Y, R, msg);
    return eq(mul(C, s), C.add(R, mul(C, c, Y)));
  }
  /** Anyone can run this, no secret needed: it only works when the challenge ignores the commitment R ("noR"). */
  function forge(C, mode, Y, msg) {
    const c0 = fsChallenge(C, mode, Y, null, msg), s = randScalar(C);
    return { R: C.add(mul(C, s), neg(C, mul(C, c0, Y))), s };
  }
  /** Turn a valid signature for Y into one for Y + tG, without any secret: it works when the challenge ignores the public key ("noY"). */
  function transplant(C, mode, Y, msg, sig, t) {
    const cOld = fsChallenge(C, mode, Y, sig.R, msg);
    return { Y2: C.add(Y, mul(C, t)), R: sig.R, s: mod(sig.s + cOld * t, C.n) };
  }

  // --------------------------------------------------------------------------- commitments: a sealed envelope made of SHA-256
  const enc = (v) => (typeof v === "string" ? utf8(v) : v);
  function commitValue(value, salt) {
    const sl = salt === undefined ? randBytes(16) : salt;
    return { salt: sl, digest: sha256(concat(sl, enc(value))) };
  }
  const openCommit = (digest, value, salt) => equalBytes(sha256(concat(salt, enc(value))), digest);

  // --------------------------------------------------------------------------- a graph 3-colouring proof (Goldreich, Micali and Wigderson)
  const GRAPH = {
    n: 8,
    edges: [[0, 1], [1, 2], [2, 3], [3, 4], [4, 5], [5, 6], [6, 7], [7, 0], [0, 2], [1, 3], [2, 4], [3, 5], [4, 6], [5, 7]],
    colouring: [0, 1, 2, 0, 1, 2, 0, 1],        // a valid 3-colouring
    cheat: [0, 1, 2, 0, 1, 2, 0, 2],            // one slip: vertices 5 and 7 share a colour, so exactly one edge (5-7) is bad
  };
  function perm3() {
    const p = [0, 1, 2];
    for (let i = 2; i > 0; i--) { const j = Number(randBelow(BigInt(i + 1))); [p[i], p[j]] = [p[j], p[i]]; }
    return p;
  }
  /** The prover renames the three colours at random, then seals every vertex's colour in its own salted envelope. */
  function colourRound(colouring) {
    const perm = perm3(), cols = colouring.map((c) => perm[c]);
    return { perm, cols, commits: cols.map((c) => commitValue("c" + c)) };
  }
  /** Open the two ends of one edge; the verifier checks both envelopes and that the two colours differ. */
  function openEdge(round, edge) {
    const [u, v] = edge;
    return { u, v, cu: round.cols[u], cv: round.cols[v], su: round.commits[u].salt, sv: round.commits[v].salt };
  }
  function checkEdge(round, edge, o) {
    const [u, v] = edge;
    if (!openCommit(round.commits[u].digest, "c" + o.cu, o.su)) return { ok: false, why: "the envelope for vertex " + u + " doesn't match" };
    if (!openCommit(round.commits[v].digest, "c" + o.cv, o.sv)) return { ok: false, why: "the envelope for vertex " + v + " doesn't match" };
    if (![0, 1, 2].includes(o.cu) || ![0, 1, 2].includes(o.cv)) return { ok: false, why: "not one of the three colours" };
    if (o.cu === o.cv) return { ok: false, why: "both ends are the same colour" };
    return { ok: true, why: "two different colours" };
  }
  /** Rounds needed so a cheater with one bad edge among m survives with probability at most 2^-bits. */
  const roundsFor = (m, bits) => Math.ceil((bits * Math.LN2) / -Math.log(1 - 1 / m));

  // --------------------------------------------------------------------------- Merkle membership and nullifiers
  const leafHash = (data) => sha256(concat(Uint8Array.of(0), data));
  const nodeHash = (a, b) => sha256(concat(Uint8Array.of(1), a, b));
  function merkleTree(items) {                       // items: byte arrays; the count must be a power of two
    const levels = [items.map(leafHash)];
    while (levels[levels.length - 1].length > 1) {
      const lv = levels[levels.length - 1], up = [];
      for (let i = 0; i < lv.length; i += 2) up.push(nodeHash(lv[i], lv[i + 1]));
      levels.push(up);
    }
    return { levels, root: levels[levels.length - 1][0] };
  }
  function merklePath(tree, index) {
    const path = [];
    for (let l = 0, i = index; l < tree.levels.length - 1; l++, i >>= 1) path.push({ sib: tree.levels[l][i ^ 1], right: (i & 1) === 0 });
    return path;                                     // right: the sibling sits on the right
  }
  function merkleCheck(item, path, root) {
    let h = leafHash(item);
    for (const p of path) h = p.right ? nodeHash(h, p.sib) : nodeHash(p.sib, h);
    return equalBytes(h, root);
  }
  const nullifier = (secret, context) => sha256(concat(utf8("nullifier/" + context + "/"), secret));

  // --------------------------------------------------------------------------- a credential with salted digests (the idea behind SD-JWT and mdoc)
  function makeIssuer() { const d = randScalar(P256); return { d, Q: mul(P256, d, P256.G) }; }
  const digestOf = (salt, name, value) => sha256(concat(salt, utf8(name + "=" + value)));
  const listHash = (digests) => toBig(sha256(concat(...digests)));
  function issue(issuer, claims) {
    const items = Object.entries(claims).map(([name, value]) => { const salt = randBytes(16); return { name, value: String(value), salt, digest: digestOf(salt, name, String(value)) }; });
    const sig = L.ecdsaSign(issuer.d, listHash(items.map((i) => i.digest)), randScalar(P256));
    return { items, sig };
  }
  /** The holder reveals chosen claims (with their salts) plus the signed digest list. */
  function present(cred, names) {
    return { digests: cred.items.map((i) => i.digest), sig: cred.sig, revealed: cred.items.filter((i) => names.includes(i.name)).map((i) => ({ name: i.name, value: i.value, salt: i.salt })) };
  }
  function checkPresentation(issuerQ, pres) {
    const sigOk = L.ecdsaVerify(issuerQ, listHash(pres.digests), pres.sig);
    const claims = pres.revealed.map((r) => {
      const d = digestOf(r.salt, r.name, r.value);
      return { name: r.name, value: r.value, ok: pres.digests.some((x) => equalBytes(x, d)) };
    });
    return { sigOk, claims, ok: sigOk && claims.every((c) => c.ok) };
  }

  root.ZK = {
    CURVES, mul, neg, eq, ptEnc, randScalar,
    keygen, commit, challenge, respond, verify, extract, simulate, bluff,
    fsChallenge, sign, checkSig, forge, transplant,
    commitValue, openCommit,
    GRAPH, perm3, colourRound, openEdge, checkEdge, roundsFor,
    leafHash, nodeHash, merkleTree, merklePath, merkleCheck, nullifier,
    makeIssuer, issue, present, checkPresentation, digestOf,
  };
  if (typeof module !== "undefined" && module.exports) module.exports = root.ZK;
})(typeof window !== "undefined" ? window : globalThis);
