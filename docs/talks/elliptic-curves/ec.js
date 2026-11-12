/* ec.js - the maths behind the demos in "Elliptic Curves Properly".
   EDUCATIONAL ONLY. Everything here is written to be read, not to be fast or safe: BigInt arithmetic with secret-dependent
   branches, no blinding, no side-channel defences. Real code uses a vetted library (see the closing slides).
   It builds on the shared crypto.js (SHA-256, HMAC, the P-256 curve, big-number helpers) and adds a toy-curve explorer,
   point encoding and validation, ECDSA with nonce reuse and RFC 6979, Ed25519 (RFC 8032) and X25519 (RFC 7748) with their own
   SHA-512, strict versus lax verification, and simulated constant-time models.
   It runs in the browser (window.ECLab) and in Node (module.exports) so the logic can be tested. */
(function (root) {
  "use strict";
  const Lab = typeof module !== "undefined" && module.exports ? require("../../shared/crypto.js") : root.Lab;
  const { fromHex, hex, utf8, concat, sha256, hmacSha256, toBig, fromBig } = Lab;

  // --------------------------------------------------------------------------- BigInt helpers
  const mod = (a, m) => ((a % m) + m) % m;
  function pow(b, e, m) { let r = 1n; b = mod(b, m); while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; } return r; }
  function inv(a, m) {
    let [r0, r1, s0, s1] = [mod(a, m), m, 1n, 0n];
    while (r1) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [s0, s1] = [s1, s0 - q * s1]; }
    if (r0 !== 1n) throw new Error("no inverse");
    return mod(s0, m);
  }
  const isSquare = (a, p) => { a = mod(a, p); return a === 0n || pow(a, (p - 1n) / 2n, p) === 1n; };
  function sqrt(a, p) {
    a = mod(a, p);
    if (a === 0n) return 0n;
    if (!isSquare(a, p)) return null;
    if (p % 4n === 3n) return pow(a, (p + 1n) / 4n, p);
    if (p < 65536n) { for (let y = 1n; y < p; y++) if ((y * y) % p === a) return y; return null; }
    throw new Error("sqrt: unsupported prime");
  }
  const leToBig = (b) => { let x = 0n; for (let i = b.length - 1; i >= 0; i--) x = (x << 8n) | BigInt(b[i]); return x; };
  const bigToLe = (x, n) => { const o = new Uint8Array(n); for (let i = 0; i < n; i++) { o[i] = Number(x & 0xffn); x >>= 8n; } return o; };
  const eqBytes = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);

  // --------------------------------------------------------------------------- short Weierstrass curves y^2 = x^3 + ax + b (mod p)
  const wCurve = (name, p, a, b, G, n, h, bytes) => ({ name, p, a, b, G, n, h, bytes });
  /** One addition, plus which case of the formula was used: "identity", "inverse", "double" or "chord". */
  function wAddT(c, P, Q) {
    if (P === null) return { R: Q, kind: "identity" };
    if (Q === null) return { R: P, kind: "identity" };
    const p = c.p, [x1, y1] = P, [x2, y2] = Q;
    if (x1 === x2 && mod(y1 + y2, p) === 0n) return { R: null, kind: "inverse" };
    const dbl = x1 === x2 && y1 === y2;
    const m = dbl ? mod((3n * x1 * x1 + c.a) * inv(2n * y1, p), p) : mod((y2 - y1) * inv(x2 - x1, p), p);
    const x3 = mod(m * m - x1 - x2, p);
    return { R: [x3, mod(m * (x1 - x3) - y1, p)], kind: dbl ? "double" : "chord" };
  }
  const wAdd = (c, P, Q) => wAddT(c, P, Q).R;
  function wMul(c, k, P) { let R = null; k = BigInt(k); while (k > 0n) { if (k & 1n) R = wAdd(c, R, P); P = wAdd(c, P, P); k >>= 1n; } return R; }
  const wOn = (c, P) => P === null || mod(P[1] * P[1] - (P[0] * P[0] * P[0] + c.a * P[0] + c.b), c.p) === 0n;
  function wPoints(c) {
    const pts = [null];
    for (let x = 0n; x < c.p; x++) { const r = mod(x * x * x + c.a * x + c.b, c.p); for (let y = 0n; y < c.p; y++) if ((y * y) % c.p === r) pts.push([x, y]); }
    return pts;
  }
  /** Order of P by repeated addition (small curves only). Returns 0 if it takes more than `cap` steps. */
  function wOrder(c, P, cap = 6000) { if (P === null) return 1; let R = P, n = 1; while (R !== null) { R = wAdd(c, R, P); n++; if (n > cap) return 0; } return n; }
  const factor = (n) => { const f = []; for (let i = 2; i * i <= n; i++) while (n % i === 0) { f.push(i); n /= i; } if (n > 1) f.push(n); return f; };

  // the Crypto 101 toy curve (prime order 19), and a toy with cofactor 4: 44 points = 4 x 11
  const TOY17 = wCurve("y² = x³ + 2x + 2 (mod 17)", 17n, 2n, 2n, [5n, 1n], 19n, 1n, 1);
  const TOY37 = wCurve("y² = x³ + x + 7 (mod 37)", 37n, 1n, 7n, null, 11n, 4n, 1);
  {
    const pts = wPoints(TOY37);
    const g44 = pts.find((P) => P !== null && wOrder(TOY37, P) === 44);
    TOY37.G = wMul(TOY37, 4n, g44);        // a point of order 11: the generator of the prime-order subgroup
    TOY37.points = pts;
  }
  const P256 = wCurve("NIST P-256", Lab.P256.p, Lab.P256.a, Lab.P256.b, Lab.P256.G, Lab.P256.n, 1n, 32);
  const p256mul = (k, P = P256.G) => wMul(P256, k, P), p256add = (P, Q) => wAdd(P256, P, Q);

  // --------------------------------------------------------------------------- Montgomery and Edwards forms of one toy group (p = 71)
  // Montgomery: v^2 = u^3 + A u^2 + u.  Twisted Edwards: a x^2 + y^2 = 1 + d x^2 y^2 with a = A + 2, d = A - 2.
  // Here A + 2 = 25 is a square and A - 2 = 21 is not, so the Edwards addition formula has no exceptional cases.
  const MP = 71n, MA = 23n, EA = mod(MA + 2n, MP), ED = mod(MA - 2n, MP);
  function mOn(P) { return P === null || mod(P[1] * P[1] - (P[0] * P[0] * P[0] + MA * P[0] * P[0] + P[0]), MP) === 0n; }
  function mAddT(P, Q) {
    if (P === null) return { R: Q, kind: "identity" };
    if (Q === null) return { R: P, kind: "identity" };
    const [x1, y1] = P, [x2, y2] = Q;
    if (x1 === x2 && mod(y1 + y2, MP) === 0n) return { R: null, kind: "inverse" };
    const dbl = x1 === x2 && y1 === y2;
    const m = dbl ? mod((3n * x1 * x1 + 2n * MA * x1 + 1n) * inv(2n * y1, MP), MP) : mod((y2 - y1) * inv(x2 - x1, MP), MP);
    const x3 = mod(m * m - MA - x1 - x2, MP);
    return { R: [x3, mod(m * (x1 - x3) - y1, MP)], kind: dbl ? "double" : "chord" };
  }
  function eAdd(P, Q) {                      // one formula for every pair, including the doubling and the neutral point (0, 1)
    const [x1, y1] = P, [x2, y2] = Q, t = mod(ED * x1 * x2 * y1 * y2, MP);
    return [mod((x1 * y2 + y1 * x2) * inv(1n + t, MP), MP), mod((y1 * y2 - EA * x1 * x2) * inv(1n - t, MP), MP)];
  }
  const eOn = (P) => mod(EA * P[0] * P[0] + P[1] * P[1] - 1n - ED * P[0] * P[0] * P[1] * P[1], MP) === 0n;
  function mToE(P) { if (P === null) return [0n, 1n]; const [u, v] = P; if (v === 0n) return [0n, MP - 1n]; return [mod(u * inv(v, MP), MP), mod((u - 1n) * inv(u + 1n, MP), MP)]; }
  function eToM(P) {
    const [x, y] = P;
    if (y === 1n) return null;
    if (y === MP - 1n) return [0n, 0n];
    const u = mod((1n + y) * inv(1n - y, MP), MP);
    return [u, mod(u * inv(x, MP), MP)];
  }
  /** The toy group: every multiple i*g in both forms, and what happens when you add every pair. */
  function toyGroup() {
    const pts = [null];
    for (let x = 0n; x < MP; x++) { const r = mod(x * x * x + MA * x * x + x, MP); for (let y = 0n; y < MP; y++) if ((y * y) % MP === r) pts.push([x, y]); }
    const N = BigInt(pts.length);
    let g = null;
    for (const P of pts) { if (P === null) continue; let R = P, n = 1; while (R !== null) { R = mAddT(R, P).R; n++; } if (BigInt(n) === N) { g = P; break; } }
    const mult = [null], edw = [[0n, 1n]];
    for (let i = 1; i < Number(N); i++) { mult.push(mAddT(mult[i - 1], g).R); edw.push(eAdd(edw[i - 1], mToE(g))); }
    return { N: Number(N), g, gE: mToE(g), mult, edw };
  }
  const TOYG = toyGroup();
  /** Add every pair i*g + j*g in Montgomery form and count which case of the formula ran; Edwards always runs the same one. */
  function caseCounts() {
    const c = { identity: 0, inverse: 0, double: 0, chord: 0 };
    for (let i = 0; i < TOYG.N; i++) for (let j = 0; j < TOYG.N; j++) c[mAddT(TOYG.mult[i], TOYG.mult[j]).kind]++;
    return { counts: c, pairs: TOYG.N * TOYG.N };
  }

  // --------------------------------------------------------------------------- point encoding and validation
  function encodePoint(c, P, compressed) {
    if (P === null) return Uint8Array.of(0);
    const L = c.bytes;
    return compressed ? concat(Uint8Array.of(2 + Number(P[1] & 1n)), fromBig(P[0], L)) : concat(Uint8Array.of(4), fromBig(P[0], L), fromBig(P[1], L));
  }
  /** Run the checks a receiver should make, in order. Later checks are skipped once one fails. */
  function checkPoint(c, bytes, opts = {}) {
    const L = c.bytes, checks = [];
    let P = null, failed = false;
    const step = (id, name, fn) => {
      if (failed) { checks.push({ id, name, ok: null, msg: "not reached" }); return; }
      const r = fn(); checks.push({ id, name, ok: r.ok, msg: r.msg }); if (!r.ok) failed = true;
    };
    let x = null, y = null, kind = null;
    step("format", "Length and prefix match a known format", () => {
      if (bytes.length === 0) return { ok: false, msg: "empty input" };
      const t = bytes[0];
      if (t === 0 && bytes.length === 1) { kind = "inf"; return { ok: true, msg: "00: the point at infinity" }; }
      if ((t === 2 || t === 3) && bytes.length === 1 + L) { kind = "comp"; return { ok: true, msg: "0" + t + ": compressed, x only (" + (1 + L) + " bytes)" }; }
      if (t === 4 && bytes.length === 1 + 2 * L) { kind = "unc"; return { ok: true, msg: "04: uncompressed, x and y (" + (1 + 2 * L) + " bytes)" }; }
      return { ok: false, msg: "prefix " + hex(bytes.slice(0, 1)) + " with " + bytes.length + " bytes is not a valid encoding for this curve" };
    });
    step("range", "Coordinates are in 0 … p−1", () => {
      if (kind === "inf") return { ok: true, msg: "nothing to range-check" };
      x = toBig(bytes.slice(1, 1 + L)); if (kind === "unc") y = toBig(bytes.slice(1 + L));
      if (x >= c.p) return { ok: false, msg: "x ≥ p: a second spelling of the same number, so reject it" };
      if (y !== null && y >= c.p) return { ok: false, msg: "y ≥ p: a second spelling of the same number, so reject it" };
      return { ok: true, msg: "x" + (y !== null ? " and y" : "") + " are below p" };
    });
    step("curve", kind === "comp" ? "x gives a real y (decompression works)" : "The point satisfies the curve equation", () => {
      if (kind === "inf") return { ok: true, msg: "infinity is the identity, not a point with coordinates" };
      if (kind === "comp") {
        const r = mod(x * x * x + c.a * x + c.b, c.p), s = sqrt(r, c.p);
        if (s === null) return { ok: false, msg: "x³ + ax + b has no square root mod p, so no point has this x" };
        y = (s & 1n) === BigInt(bytes[0] & 1) ? s : mod(c.p - s, c.p);
        return { ok: true, msg: "y recovered from x and the sign bit" };
      }
      const lhs = mod(y * y, c.p), rhs = mod(x * x * x + c.a * x + c.b, c.p);
      return lhs === rhs ? { ok: true, msg: "y² = x³ + ax + b holds" } : { ok: false, msg: "y² ≠ x³ + ax + b: this point is not on the curve" };
    });
    step("notinf", "It is not the point at infinity", () => kind === "inf" ? { ok: false, msg: "a public key or peer point must not be the identity" } : { ok: true, msg: "a real point" });
    step("subgroup", "It lies in the prime-order subgroup", () => {
      P = [x, y];
      if (c.h === 1n) return { ok: true, msg: "cofactor 1: every point on the curve is in the subgroup" };
      const Z = wMul(c, c.n, P);
      return Z === null ? { ok: true, msg: "n·P = ∞: it is in the subgroup (cofactor " + c.h + ")" } : { ok: false, msg: "n·P ≠ ∞: it is on the curve but in a small-order part (cofactor " + c.h + ")" };
    });
    return { ok: !failed, checks, P: failed ? null : P, kind };
  }

  // --------------------------------------------------------------------------- invalid-curve illustration (toy size, no recovery code)
  const IC = { p: 1009n, a: 1n, b: 17n };       // the curve the server believes in
  const ICc = wCurve("y² = x³ + x + 17 (mod 1009)", IC.p, IC.a, IC.b, null, 0n, 1n, 2);
  /** The group order of a curve with the given b (point counting by Euler's criterion). */
  function countPoints(p, a, b) { let n = 1n; for (let x = 0n; x < p; x++) { const r = mod(x * x * x + a * x + b, p); n += r === 0n ? 1n : isSquare(r, p) ? 2n : 0n; } return n; }
  /** A point that is NOT on the server's curve but has small order r on the curve y² = x³ + ax + b' for the b' it implies. */
  function foreignPoint(r) {
    for (let bp = 0n; bp < IC.p; bp++) {
      if (bp === IC.b || mod(4n * IC.a ** 3n + 27n * bp * bp, IC.p) === 0n) continue;
      const N = countPoints(IC.p, IC.a, bp);
      if (N % BigInt(r) !== 0n) continue;
      const cb = wCurve("", IC.p, IC.a, bp, null, 0n, 1n, 2);
      for (let x = 0n; x < IC.p; x++) {
        const rhs = mod(x * x * x + IC.a * x + bp, IC.p), y = sqrt(rhs, IC.p);
        if (y === null || y === 0n) continue;
        const Q = wMul(cb, N / BigInt(r), [x, y]);
        if (Q !== null && wOrder(cb, Q) === r) return { Q, b2: bp, order: r };
      }
    }
    return null;
  }
  const FOREIGN = [3, 5, 7, 11].map(foreignPoint).filter(Boolean);
  /** What a server that skips validation hands back for d·Q. */
  function noValidate(d, F) {
    const S = wMul(ICc, d, F.Q), cb = wCurve("", IC.p, IC.a, F.b2, null, 0n, 1n, 2);
    return { S, order: F.order, residue: Number(d % BigInt(F.order)), bits: Math.log2(F.order), onServerCurve: wOn(ICc, F.Q), onItsOwnCurve: wOn(cb, F.Q) };
  }

  // --------------------------------------------------------------------------- ECDSA on P-256
  const n256 = P256.n;
  const hashInt = (s) => toBig(sha256(utf8(s)));
  const ecPub = (d) => p256mul(d);
  function ecSign(d, h, k) { const R = p256mul(k), r = mod(R[0], n256); return [r, mod(inv(k, n256) * (h + r * d), n256)]; }
  /** opts.lowS rejects s above n/2; opts.noRange skips the 0 < r, s < n check; opts.reduceR (a bug) reduces r mod n before comparing. */
  function ecVerify(Q, h, sig, opts = {}) {
    let [r, s] = sig;
    if (!opts.noRange && (r <= 0n || r >= n256 || s <= 0n || s >= n256)) return false;
    if (opts.noRange && (s === 0n || mod(s, n256) === 0n)) return false;
    if (opts.lowS && s > n256 / 2n) return false;
    const w = inv(s, n256), X = p256add(p256mul(mod(h * w, n256)), p256mul(mod(r * w, n256), Q));
    if (X === null) return false;
    return mod(X[0], n256) === (opts.reduceR ? mod(r, n256) : r);
  }
  /** Two signatures with the same r (so the same k) give up the nonce and the key. */
  function ecRecover(h1, sig1, h2, sig2) {
    const [r, s1] = sig1, [r2, s2] = sig2;
    if (r !== r2 || mod(s1 - s2, n256) === 0n) return null;
    const k = mod((h1 - h2) * inv(s1 - s2, n256), n256);
    return { k, d: mod((s1 * k - h1) * inv(r, n256), n256) };
  }
  /** RFC 6979 section 3.2 for P-256 with SHA-256: the nonce is a function of the key and the message hash. */
  function rfc6979(d, hbytes) {
    const x = fromBig(d, 32), h1 = fromBig(mod(toBig(hbytes), n256), 32);
    let V = new Uint8Array(32).fill(1), K = new Uint8Array(32);
    K = hmacSha256(K, concat(V, Uint8Array.of(0), x, h1)); V = hmacSha256(K, V);
    K = hmacSha256(K, concat(V, Uint8Array.of(1), x, h1)); V = hmacSha256(K, V);
    for (;;) {
      V = hmacSha256(K, V);
      const k = toBig(V);
      if (k >= 1n && k < n256) return k;
      K = hmacSha256(K, concat(V, Uint8Array.of(0))); V = hmacSha256(K, V);
    }
  }
  function rng(seed) {
    let a = seed >>> 0;
    return () => { a = (a + 0x6d2b79f5) >>> 0; let t = a; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
  }
  /** Nonces whose top `zeroBits` bits are always zero (a biased generator), and a histogram of their top four bits. */
  function biasedNonces(zeroBits, count, seed) {
    const r = rng(seed), out = [];
    for (let i = 0; i < count; i++) { let x = 0n; for (let j = 0; j < 8; j++) x = (x << 32n) | BigInt(Math.floor(r() * 4294967296)); out.push(x & ((1n << BigInt(256 - zeroBits)) - 1n)); }
    return out;
  }
  function topHistogram(nonces) { const h = new Array(16).fill(0); for (const k of nonces) h[Number(k >> 252n)]++; return h; }

  // --------------------------------------------------------------------------- SHA-512, built from its definition (the constants come from cube and square roots of primes)
  const M64 = (1n << 64n) - 1n;
  const rotr = (x, n) => ((x >> n) | (x << (64n - n))) & M64;
  function iroot(n, k) { if (n < 2n) return n; let x = 1n << BigInt(Math.ceil(n.toString(2).length / k)); for (;;) { const y = ((BigInt(k) - 1n) * x + n / x ** (BigInt(k) - 1n)) / BigInt(k); if (y >= x) return x; x = y; } }
  const PRIMES = []; for (let i = 2; PRIMES.length < 80; i++) if (PRIMES.every((p) => i % p)) PRIMES.push(i);
  const K512 = PRIMES.map((p) => iroot(BigInt(p) << 192n, 3) & M64);
  const H512 = PRIMES.slice(0, 8).map((p) => iroot(BigInt(p) << 128n, 2) & M64);
  function sha512(msg) {
    const len = msg.length, padLen = (((len + 17 + 127) >> 7) << 7);
    const buf = new Uint8Array(padLen); buf.set(msg); buf[len] = 0x80;
    let bl = BigInt(len) * 8n; for (let i = 0; i < 16; i++) { buf[padLen - 1 - i] = Number(bl & 0xffn); bl >>= 8n; }
    let h = H512.slice();
    for (let o = 0; o < padLen; o += 128) {
      const w = new Array(80);
      for (let t = 0; t < 16; t++) { let x = 0n; for (let j = 0; j < 8; j++) x = (x << 8n) | BigInt(buf[o + t * 8 + j]); w[t] = x; }
      for (let t = 16; t < 80; t++) {
        const s0 = rotr(w[t - 15], 1n) ^ rotr(w[t - 15], 8n) ^ (w[t - 15] >> 7n), s1 = rotr(w[t - 2], 19n) ^ rotr(w[t - 2], 61n) ^ (w[t - 2] >> 6n);
        w[t] = (w[t - 16] + s0 + w[t - 7] + s1) & M64;
      }
      let [a, b, c, d, e, f, g, hh] = h;
      for (let t = 0; t < 80; t++) {
        const S1 = rotr(e, 14n) ^ rotr(e, 18n) ^ rotr(e, 41n), ch = (e & f) ^ (~e & M64 & g), t1 = (hh + S1 + ch + K512[t] + w[t]) & M64;
        const S0 = rotr(a, 28n) ^ rotr(a, 34n) ^ rotr(a, 39n), maj = (a & b) ^ (a & c) ^ (b & c), t2 = (S0 + maj) & M64;
        hh = g; g = f; f = e; e = (d + t1) & M64; d = c; c = b; b = a; a = (t1 + t2) & M64;
      }
      h = [a, b, c, d, e, f, g, hh].map((v, i) => (h[i] + v) & M64);
    }
    const out = new Uint8Array(64); h.forEach((v, i) => out.set(fromBig(v, 8), i * 8));
    return out;
  }

  // --------------------------------------------------------------------------- Ed25519 (RFC 8032 section 5.1), extended coordinates
  const P25 = (1n << 255n) - 19n, L25 = (1n << 252n) + 27742317777372353535851937790883648493n;
  const D25 = mod(-121665n * inv(121666n, P25), P25), I25 = pow(2n, (P25 - 1n) / 4n, P25);
  function recoverX(y, sign) {
    if (y >= P25) return null;
    const x2 = mod((y * y - 1n) * inv(D25 * y * y + 1n, P25), P25);
    if (x2 === 0n) return sign ? null : 0n;
    let x = pow(x2, (P25 + 3n) / 8n, P25);
    if (mod(x * x - x2, P25) !== 0n) x = mod(x * I25, P25);
    if (mod(x * x - x2, P25) !== 0n) return null;
    if ((x & 1n) !== BigInt(sign)) x = P25 - x;
    return x;
  }
  const By = mod(4n * inv(5n, P25), P25), Bx = recoverX(By, 0), B25 = [Bx, By, 1n, mod(Bx * By, P25)], ID25 = [0n, 1n, 1n, 0n];
  function eadd(P, Q) {
    const [X1, Y1, Z1, T1] = P, [X2, Y2, Z2, T2] = Q;
    const A = mod((Y1 - X1) * (Y2 - X2), P25), B = mod((Y1 + X1) * (Y2 + X2), P25), C = mod(T1 * 2n * D25 * T2, P25), Dd = mod(Z1 * 2n * Z2, P25);
    const E = B - A, F = Dd - C, G = Dd + C, H = B + A;
    return [mod(E * F, P25), mod(G * H, P25), mod(F * G, P25), mod(E * H, P25)];
  }
  function emul(s, P) { let Q = ID25; while (s > 0n) { if (s & 1n) Q = eadd(Q, P); P = eadd(P, P); s >>= 1n; } return Q; }
  const edEq = (P, Q) => mod(P[0] * Q[2] - Q[0] * P[2], P25) === 0n && mod(P[1] * Q[2] - Q[1] * P[2], P25) === 0n;
  function compress(P) { const zi = inv(P[2], P25), x = mod(P[0] * zi, P25), y = mod(P[1] * zi, P25); return bigToLe(y | ((x & 1n) << 255n), 32); }
  /** Decode a 32-byte point. canonical = reject a y that is not below p. Returns null if it is not a point. */
  function decompress(b, canonical = true) {
    if (b.length !== 32) return null;
    const v = leToBig(b), sign = Number(v >> 255n);
    let y = v & ((1n << 255n) - 1n);
    if (y >= P25) { if (canonical) return null; y = mod(y, P25); }
    const x = recoverX(y, sign);
    return x === null ? null : [x, y, 1n, mod(x * y, P25)];
  }
  const isSmallOrder = (P) => edEq(emul(8n, P), ID25);
  function expand(seed) {
    const h = sha512(seed); let a = leToBig(h.slice(0, 32));
    a &= (1n << 254n) - 8n; a |= 1n << 254n;
    return { a, prefix: h.slice(32) };
  }
  const edPublic = (seed) => compress(emul(expand(seed).a, B25));
  const modL = (b) => mod(leToBig(b), L25);
  function edSign(seed, msg) {
    const { a, prefix } = expand(seed), A = compress(emul(a, B25));
    const r = modL(sha512(concat(prefix, msg))), R = compress(emul(r, B25));
    const k = modL(sha512(concat(R, A, msg)));
    return concat(R, bigToLe(mod(r + k * a, L25), 32));
  }
  /** Sign with a chosen r and a chosen way of writing R (used to build edge-case signatures for the testing slide). */
  function edSignWith(seed, msg, r, Rbytes) {
    const { a } = expand(seed), A = compress(emul(a, B25));
    const k = modL(sha512(concat(Rbytes, A, msg)));
    return concat(Rbytes, bigToLe(mod(r + k * a, L25), 32));
  }
  /** opts: checkS (S < L), canonical (reject y >= p), rejectSmallOrder, cofactored. RFC 8032 verification is checkS + canonical. */
  function edVerify(pub, msg, sig, opts = {}) {
    const o = Object.assign({ checkS: true, canonical: true, rejectSmallOrder: false, cofactored: false }, opts);
    if (pub.length !== 32 || sig.length !== 64) return false;
    const A = decompress(pub, o.canonical), R = decompress(sig.slice(0, 32), o.canonical);
    if (!A || !R) return false;
    const S = leToBig(sig.slice(32));
    if (o.checkS && S >= L25) return false;
    if (o.rejectSmallOrder && (isSmallOrder(A) || isSmallOrder(R))) return false;
    const k = modL(sha512(concat(sig.slice(0, 32), pub, msg)));
    let lhs = emul(S, B25), rhs = eadd(R, emul(k, A));
    if (o.cofactored) { lhs = emul(8n, lhs); rhs = emul(8n, rhs); }
    return edEq(lhs, rhs);
  }

  // --------------------------------------------------------------------------- X25519 (RFC 7748 section 5)
  function clamp(k) { const c = Uint8Array.from(k); c[0] &= 248; c[31] &= 127; c[31] |= 64; return c; }
  function x25519(kb, ub) {
    const k = leToBig(clamp(kb)), u = mod(leToBig(ub) & ((1n << 255n) - 1n), P25), a24 = 121665n;
    let x2 = 1n, z2 = 0n, x3 = u, z3 = 1n, swap = 0n;
    for (let t = 254n; t >= 0n; t--) {
      const kt = (k >> t) & 1n; swap ^= kt;
      if (swap) { [x2, x3] = [x3, x2]; [z2, z3] = [z3, z2]; }
      swap = kt;
      const A = x2 + z2, AA = mod(A * A, P25), B = x2 - z2, BB = mod(B * B, P25), E = AA - BB, C = x3 + z3, D = x3 - z3;
      const DA = mod(D * A, P25), CB = mod(C * B, P25);
      x3 = mod((DA + CB) ** 2n, P25); z3 = mod(u * mod((DA - CB) ** 2n, P25), P25);
      x2 = mod(AA * BB, P25); z2 = mod(E * (AA + a24 * E), P25);
    }
    if (swap) { [x2, x3] = [x3, x2]; [z2, z3] = [z3, z2]; }
    return bigToLe(z2 === 0n ? 0n : mod(x2 * inv(z2, P25), P25), 32);
  }
  const BASE9 = (() => { const b = new Uint8Array(32); b[0] = 9; return b; })();
  const allZero = (b) => b.reduce((acc, v) => acc | v, 0) === 0;   // the OR-everything check RFC 7748 describes

  // --------------------------------------------------------------------------- constant-time models (counted steps, not real timings)
  /** Compare a secret with a guess byte by byte. Early exit stops at the first difference; the constant-time version never stops early. */
  function compareSteps(secret, guess, mode) {
    const n = secret.length;
    if (mode === "constant") { let diff = guess.length === n ? 0 : 1; for (let i = 0; i < n; i++) diff |= secret.charCodeAt(i) ^ (guess.charCodeAt(i) || 0); return { steps: n, equal: diff === 0 }; }
    for (let i = 0; i < n; i++) if (guess[i] !== secret[i]) return { steps: i + 1, equal: false };
    return { steps: n, equal: guess.length === n };
  }
  /** Steps taken when the guess has m correct leading characters followed by a wrong one. */
  function compareProfile(secret, mode) {
    const out = [];
    for (let m = 0; m < secret.length; m++) out.push(compareSteps(secret, secret.slice(0, m) + (secret[m] === "x" ? "y" : "x") + secret.slice(m + 1), mode).steps);
    return out;
  }
  /** The sequence of point operations for a scalar's bits (MSB first). D = doubling, A = addition. */
  function scalarOps(bitString, mode) {
    const b = bitString.replace(/[^01]/g, "").replace(/^0+/, "");
    if (!b) return { ops: "", doubles: 0, adds: 0 };
    let ops = "";
    if (mode === "ladder") { for (let i = 1; i < b.length; i++) ops += "AD"; }
    else for (let i = 1; i < b.length; i++) ops += b[i] === "1" ? "DA" : "D";
    return { ops, doubles: (ops.match(/D/g) || []).length, adds: (ops.match(/A/g) || []).length, bits: b };
  }

  // --------------------------------------------------------------------------- known-answer tests and an edge-case suite
  const V = {
    ed: [
      { name: "RFC 8032 test 1 (empty message)", seed: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", pub: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", msg: "", sig: "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" + "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b" },
      { name: "RFC 8032 test 2 (one byte, 72)", seed: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", pub: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", msg: "72", sig: "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da" + "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00" },
      { name: "RFC 8032 test 3 (two bytes, af82)", seed: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7", pub: "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", msg: "af82", sig: "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac" + "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a" },
    ],
    x: [
      { name: "RFC 7748 section 5.2 vector 1", k: "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", u: "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c", out: "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552" },
      { name: "RFC 7748 section 6.1 Alice's public key", k: "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", u: "09" + "00".repeat(31), out: "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a" },
      { name: "RFC 7748 section 6.1 shared secret", k: "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", u: "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", out: "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742" },
    ],
    ec: { d: "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721", msg: "sample", k: "A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60",
      r: "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716", s: "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8" },
  };
  function runKATs(opts = {}) {
    const out = [];
    for (const t of V.ed) {
      const sig = edSign(fromHex(t.seed), fromHex(t.msg));
      out.push({ name: t.name + ": public key", ok: hex(edPublic(fromHex(t.seed))) === t.pub });
      out.push({ name: t.name + ": signature", ok: hex(sig) === t.sig });
      out.push({ name: t.name + ": verifies", ok: edVerify(fromHex(t.pub), fromHex(t.msg), fromHex(t.sig), opts.ed) });
    }
    for (const t of V.x) out.push({ name: t.name, ok: hex(x25519(fromHex(t.k), fromHex(t.u))) === t.out });
    const e = V.ec, d = BigInt("0x" + e.d), h = fromHex(hex(sha256(utf8(e.msg)))), k = rfc6979(d, h), sig = ecSign(d, toBig(h), k);
    out.push({ name: "RFC 6979 A.2.5: nonce k", ok: k === BigInt("0x" + e.k) });
    out.push({ name: "RFC 6979 A.2.5: signature (r, s)", ok: sig[0] === BigInt("0x" + e.r) && sig[1] === BigInt("0x" + e.s) });
    out.push({ name: "RFC 6979 A.2.5: verifies", ok: ecVerify(ecPub(d), toBig(h), sig, Object.assign({}, opts.ec, { lowS: false })) });   // the RFC example has a high s, so the low-s rule is left off here
    return out;
  }
  // three verifier profiles for the testing slide
  const PROFILES = {
    textbook: { label: "Textbook: just the equation", ed: { checkS: false, canonical: false, rejectSmallOrder: false }, ec: { noRange: true, reduceR: true } },
    standard: { label: "Follows the RFC rules", ed: { checkS: true, canonical: true, rejectSmallOrder: false }, ec: {} },
    strict: { label: "Strict: also no malleable or weak inputs", ed: { checkS: true, canonical: true, rejectSmallOrder: true }, ec: { lowS: true } },
  };
  /** Edge cases in the spirit of Wycheproof (this is a handful of hand-made cases, not the real suite). Every one should be rejected unless noted. */
  function edgeCases() {
    const seed = fromHex(V.ed[1].seed), pub = fromHex(V.ed[1].pub), msg = fromHex(V.ed[1].msg), sig = fromHex(V.ed[1].sig);
    const S = leToBig(sig.slice(32)), malS = concat(sig.slice(0, 32), bigToLe(S + L25, 32));
    const ident = compress(ID25), identNon = bigToLe(P25 + 1n, 32);     // the neutral point (y = 1), and y written as p + 1
    const forged = concat(ident, new Uint8Array(32)), nonCanon = edSignWith(seed, msg, 0n, identNon);
    const d = BigInt("0x" + V.ec.d), h = toBig(sha256(utf8("sample"))), Q = ecPub(d), raw = ecSign(d, h, rfc6979(d, fromHex(hex(sha256(utf8("sample")))))), good = [raw[0], raw[1] > n256 / 2n ? n256 - raw[1] : raw[1]];   // the low-s form of the RFC 6979 signature
    return [
      { id: "ed-valid", kind: "Ed25519", name: "A valid signature (RFC 8032 test 2)", shouldAccept: true, run: (p) => edVerify(pub, msg, sig, p.ed) },
      { id: "ed-s-plus-l", kind: "Ed25519", name: "The same signature with S replaced by S + L", why: "S is only defined modulo L, so a verifier that skips the S < L check accepts a second, different signature for the same message.", run: (p) => edVerify(pub, msg, malS, p.ed) },
      { id: "ed-noncanon", kind: "Ed25519", name: "A signature that writes R's y as p + 1 instead of 1", why: "Two byte strings for one point: a verifier that reduces y accepts both, and two libraries may then disagree.", run: (p) => edVerify(pub, msg, nonCanon, p.ed) },
      { id: "ed-small-order", kind: "Ed25519", name: "A weak public key (the neutral point) with a made-up signature on any message", why: "With a small-order key the equation holds for every message. The RFC does not forbid it; strict libraries reject such keys.", run: (p) => edVerify(ident, utf8("anything at all"), forged, p.ed) },
      { id: "ec-valid", kind: "ECDSA", name: "A valid ECDSA signature (the RFC 6979 example, in its low-s form)", shouldAccept: true, run: (p) => ecVerify(Q, h, good, p.ec) },
      { id: "ec-high-s", kind: "ECDSA", name: "The same signature with s replaced by n − s", why: "(r, s) and (r, n − s) both verify, so a third party can re-sign your transaction. Bitcoin and Ethereum reject the high-s form.", run: (p) => ecVerify(Q, h, [good[0], n256 - good[1]], p.ec) },
      { id: "ec-r-plus-n", kind: "ECDSA", name: "The same signature with r replaced by r + n", why: "An implementation that reduces r before comparing accepts a number that is out of range.", run: (p) => ecVerify(Q, h, [good[0] + n256, good[1]], p.ec) },
      { id: "ec-zero-s", kind: "ECDSA", name: "s = 0", why: "Not invertible mod n. Every verifier must reject it, never crash on it.", run: (p) => { try { return ecVerify(Q, h, [good[0], 0n], p.ec); } catch (e) { return false; } } },
    ];
  }
  function runEdgeCases(profileKey) {
    const p = PROFILES[profileKey];
    return edgeCases().map((c) => { let accepted; try { accepted = !!c.run(p); } catch (e) { accepted = false; } return { id: c.id, kind: c.kind, name: c.name, why: c.why, shouldAccept: !!c.shouldAccept, accepted, good: accepted === !!c.shouldAccept }; });
  }

  // --------------------------------------------------------------------------- choosing today
  /** answers: { fips: bool, interop: "new"|"webauthn"|"tls"|"jwt"|"ssh"|"bitcoin"|"smartcard", } */
  function choose(a) {
    const out = [];
    if (a.interop === "bitcoin") return { sig: "ECDSA on secp256k1 (and Schnorr on the same curve where the chain supports it)", kex: "n/a: not the job here", why: ["The chain fixes the curve. Use the ecosystem's audited library, deterministic nonces and the low-s rule it already enforces."] };
    if (a.interop === "webauthn") return { sig: "ES256 (ECDSA on P-256) for broad support; EdDSA where the platform offers it", kex: "n/a", why: ["Passkeys and security keys speak ES256 almost everywhere. Your server just verifies; use a WebAuthn library and the strict checks it ships."] };
    if (a.fips) { out.push("A validated module is the real constraint: use what it lists."); return { sig: "ECDSA on P-256 (P-384 if policy says so); Ed25519 is approved in FIPS 186-5 but check your module's validated list", kex: "ECDH on P-256 or P-384 (X25519 only once your module supports it)", why: out.concat(["Use the validated module's own API, with deterministic or hedged nonces if it offers them."]) }; }
    if (a.interop === "tls") return { sig: "Whatever your certificate authority issues (P-256 or RSA is typical); you rarely choose", kex: "X25519 (and the hybrid post-quantum groups where available), P-256 as the fallback", why: ["Let the TLS library negotiate. Your job is a current library and sane configuration, not hand-picking curves."] };
    if (a.interop === "jwt") return { sig: "EdDSA (Ed25519) or ES256, depending on what the other side's library supports", kex: "n/a", why: ["Check library and gateway support for EdDSA before picking it. Pin the allowed algorithm on the verifier, never trust the token's own header."] };
    if (a.interop === "ssh") return { sig: "Ed25519 keys", kex: "curve25519-sha256 (the OpenSSH default)", why: ["Both ends are modern OpenSSH, so the defaults are already the good choice."] };
    return { sig: "Ed25519", kex: "X25519", why: ["No outside constraint: the deterministic, simple-to-implement choice, from a vetted library such as libsodium or your language's standard crypto."] };
  }

  root.ECLab = {
    mod, pow, inv, isSquare, sqrt, factor,
    wCurve, wAdd, wAddT, wMul, wOn, wPoints, wOrder, TOY17, TOY37, P256,
    MP, MA, EA, ED, mOn, mAddT, eAdd, eOn, mToE, eToM, TOYG, caseCounts,
    encodePoint, checkPoint,
    IC, ICc, countPoints, foreignPoint, FOREIGN, noValidate,
    hashInt, ecPub, ecSign, ecVerify, ecRecover, rfc6979, rng, biasedNonces, topHistogram, n256,
    sha512, P25, L25, B25, ID25, emul, eadd, compress, decompress, isSmallOrder, expand, edPublic, edSign, edSignWith, edVerify, edEq,
    clamp, x25519, BASE9, allZero,
    compareSteps, compareProfile, scalarOps,
    V, runKATs, PROFILES, edgeCases, runEdgeCases, choose, leToBig, bigToLe,
  };
  if (typeof module !== "undefined" && module.exports) module.exports = root.ECLab;
})(typeof window !== "undefined" ? window : globalThis);
