/*
 * crypto.js - the maths behind every demo on the page, written from scratch so each step can be shown.
 * EDUCATIONAL ONLY: never use this code to protect real data. Real code should use the browser's
 * Web Crypto API or a vetted library.
 *
 * Works in the browser (window.Lab) and in Node (module.exports) so it can be tested.
 */
(function (root) {
  "use strict";

  // --------------------------------------------------------------------------- bytes and helpers
  const te = new TextEncoder(), td = new TextDecoder("utf-8", { fatal: false });
  const utf8 = (s) => te.encode(s);
  const text = (b) => td.decode(b);
  const hex = (b, sep = "") => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join(sep);
  const fromHex = (h) => Uint8Array.from((h.replace(/\s+/g, "").match(/../g) || []), (x) => parseInt(x, 16));
  const bits = (b) => Array.from(b, (x) => x.toString(2).padStart(8, "0")).join("");
  const randBytes = (n) => { const b = new Uint8Array(n); for (let i = 0; i < n; i += 65536) root.crypto.getRandomValues(b.subarray(i, i + 65536)); return b; };
  const concat = (...arrs) => { const o = new Uint8Array(arrs.reduce((n, a) => n + a.length, 0)); let i = 0; for (const a of arrs) { o.set(a, i); i += a.length; } return o; };
  const xor = (a, b) => { const n = Math.min(a.length, b.length), o = new Uint8Array(n); for (let i = 0; i < n; i++) o[i] = a[i] ^ b[i]; return o; };
  const chunks = (b, n = 16) => { const o = []; for (let i = 0; i < b.length; i += n) o.push(b.subarray(i, i + n)); return o; };
  const bitDiff = (a, b) => { let d = 0; for (let i = 0; i < Math.min(a.length, b.length); i++) { let x = a[i] ^ b[i]; while (x) { d += x & 1; x >>= 1; } } return d; };
  const equalBytes = (a, b) => { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i]; return d === 0; };
  const randInt = (n) => { const b = new Uint32Array(1); const lim = Math.floor(0x100000000 / n) * n; do { root.crypto.getRandomValues(b); } while (b[0] >= lim); return b[0] % n; };

  // --------------------------------------------------------------------------- PART 1: classical ciphers
  const ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const FREQ = [8.2, 1.5, 2.8, 4.3, 12.7, 2.2, 2.0, 6.1, 7.0, 0.15, 0.77, 4.0, 2.4, 6.7, 7.5, 1.9,
    0.095, 6.0, 6.3, 9.1, 2.8, 0.98, 2.4, 0.15, 2.0, 0.074];
  const SAMPLE = "Cryptography is the science of keeping information safe when other people might be watching it " +
    "or trying to change it. Confidentiality asks whether anyone else can read the message. Integrity asks " +
    "whether the message was changed on the way. Authentication asks who you are really talking to, and " +
    "non repudiation asks whether the sender can deny sending it. Every day you use all of these ideas when " +
    "you send a message, pay for something online, log in to a website, or open any page that starts with " +
    "https. The old ciphers are weak but they teach the key lessons, because every modern cipher fixes " +
    "a problem that someone found in an older one.";

  const letters = (s) => s.toUpperCase().replace(/[^A-Z]/g, "");
  const mod = (a, n) => ((a % n) + n) % n;

  function caesar(s, k) {
    return s.replace(/[A-Za-z]/g, (ch) => {
      const base = ch <= "Z" ? 65 : 97;
      return String.fromCharCode(mod(ch.charCodeAt(0) - base + k, 26) + base);
    });
  }

  function counts(s) { const c = new Array(26).fill(0); for (const ch of letters(s)) c[ch.charCodeAt(0) - 65]++; return c; }

  function chi2(s) {
    const c = counts(s), n = c.reduce((a, b) => a + b, 0) || 1;
    return c.reduce((sum, got, i) => { const want = FREQ[i] / 100 * n; return sum + (got - want) ** 2 / want; }, 0);
  }

  function vigenere(s, key, decrypt = false) {
    const k = letters(key);
    if (!k) return s;
    let i = 0;
    return s.replace(/[A-Za-z]/g, (ch) => {
      const shift = k.charCodeAt(i++ % k.length) - 65, base = ch <= "Z" ? 65 : 97;
      return String.fromCharCode(mod(ch.charCodeAt(0) - base + (decrypt ? -shift : shift), 26) + base);
    });
  }

  function ic(s) {
    const n = s.length;
    if (n < 2) return 0;
    return counts(s).reduce((a, c) => a + c * (c - 1), 0) / (n * (n - 1));
  }

  /** Find a Vigenere key: guess the length from the index of coincidence, then solve each column as a Caesar cipher. */
  function breakVigenere(ct, maxLen = 12) {
    const t = letters(ct), scores = [];
    let len = null;
    for (let L = 1; L <= maxLen; L++) {
      let avg = 0;
      for (let i = 0; i < L; i++) avg += ic(t.slice(i).split("").filter((_, j) => j % L === 0).join(""));
      avg /= L;
      scores.push({ len: L, ic: avg });
      if (len === null && avg > 0.06) len = L;
    }
    if (len === null) return { scores, len: null, key: null };
    let key = "";
    for (let i = 0; i < len; i++) {
      const col = t.slice(i).split("").filter((_, j) => j % len === 0).join("");
      let best = 0, bestScore = Infinity;
      for (let s = 0; s < 26; s++) { const sc = chi2(caesar(col, -s)); if (sc < bestScore) { bestScore = sc; best = s; } }
      key += ALPHA[best];
    }
    return { scores, len, key };
  }

  // --- Enigma I, rotors I-II-III, reflector B
  const ROTORS = { I: ["EKMFLGDQVZNTOWYHXUSPAIBRCJ", "Q"], II: ["AJDKSIRUXBLHWTMCQGZNPYFVOE", "E"], III: ["BDFHJLCPRTXVZNYEIWGAKMUSQO", "V"] };
  const REFLECTOR = "YRUHQSLDPXNGOKMIEBFZCWVJAT";

  class Enigma {
    constructor(order = ["I", "II", "III"], start = "AAA", plugs = "") {
      this.w = order.map((r) => ROTORS[r][0]);
      this.notch = order.map((r) => ROTORS[r][1].charCodeAt(0) - 65);
      this.pos = start.toUpperCase().split("").map((c) => c.charCodeAt(0) - 65);
      this.plug = {};
      for (const c of ALPHA) this.plug[c] = c;
      for (const pair of plugs.toUpperCase().split(/\s+/).filter(Boolean)) {
        if (!/^[A-Z]{2}$/.test(pair) || pair[0] === pair[1]) throw new Error(`Bad plugboard cable "${pair}": use two different letters, like AB.`);
        const [a, b] = pair;
        if (this.plug[a] !== a || this.plug[b] !== b) throw new Error(`A letter in "${pair}" already has a cable. Each letter can use only one.`);
        this.plug[a] = b; this.plug[b] = a;
      }
    }
    step() {
      const [l, m, r] = [0, 1, 2];
      if (this.pos[m] === this.notch[m]) { this.pos[l] = (this.pos[l] + 1) % 26; this.pos[m] = (this.pos[m] + 1) % 26; }   // double step
      else if (this.pos[r] === this.notch[r]) this.pos[m] = (this.pos[m] + 1) % 26;
      this.pos[r] = (this.pos[r] + 1) % 26;
    }
    /** Press one key. Returns the lamp letter and the signal path through the machine. */
    press(ch) {
      this.step();
      const path = [ch, this.plug[ch]];
      let c = this.plug[ch].charCodeAt(0) - 65;
      for (const i of [2, 1, 0]) { c = mod(this.w[i].charCodeAt(mod(c + this.pos[i], 26)) - 65 - this.pos[i], 26); path.push(ALPHA[c]); }
      c = REFLECTOR.charCodeAt(c) - 65; path.push(ALPHA[c]);
      for (const i of [0, 1, 2]) { c = mod(this.w[i].indexOf(ALPHA[mod(c + this.pos[i], 26)]) - this.pos[i], 26); path.push(ALPHA[c]); }
      const out = this.plug[ALPHA[c]];
      path.push(out);
      return { out, path };
    }
    text(s) { return letters(s).split("").map((c) => this.press(c).out).join(""); }
    get window() { return this.pos.map((p) => ALPHA[p]).join(""); }
  }

  // --------------------------------------------------------------------------- PART 2: SHA-256 (with a round-by-round trace)
  const K256 = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
  const H256 = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];

  function sha256Pad(msg) {
    const l = msg.length, n = Math.ceil((l + 9) / 64) * 64, p = new Uint8Array(n);
    p.set(msg); p[l] = 0x80;
    const dv = new DataView(p.buffer), bitLen = l * 8;
    dv.setUint32(n - 8, Math.floor(bitLen / 0x100000000)); dv.setUint32(n - 4, bitLen >>> 0);
    return p;
  }

  /** SHA-256. If `trace` is an array, the working values a..h of the FIRST block are pushed after every round. */
  function sha256(msg, trace) {
    const p = sha256Pad(msg), dv = new DataView(p.buffer), H = H256.slice(), W = new Uint32Array(64);
    const rotr = (x, n) => (x >>> n) | (x << (32 - n));
    for (let off = 0; off < p.length; off += 64) {
      for (let t = 0; t < 16; t++) W[t] = dv.getUint32(off + 4 * t);
      for (let t = 16; t < 64; t++) {
        const s0 = rotr(W[t - 15], 7) ^ rotr(W[t - 15], 18) ^ (W[t - 15] >>> 3);
        const s1 = rotr(W[t - 2], 17) ^ rotr(W[t - 2], 19) ^ (W[t - 2] >>> 10);
        W[t] = (W[t - 16] + s0 + W[t - 7] + s1) >>> 0;
      }
      let [a, b, c, d, e, f, g, h] = H;
      if (trace && off === 0) trace.push([a, b, c, d, e, f, g, h]);
      for (let t = 0; t < 64; t++) {
        const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25), ch = (e & f) ^ (~e & g);
        const T1 = (h + S1 + ch + K256[t] + W[t]) >>> 0;
        const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22), maj = (a & b) ^ (a & c) ^ (b & c);
        const T2 = (S0 + maj) >>> 0;
        h = g; g = f; f = e; e = (d + T1) >>> 0; d = c; c = b; b = a; a = (T1 + T2) >>> 0;
        if (trace && off === 0) trace.push([a, b, c, d, e, f, g, h]);
      }
      H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0; H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
      H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0; H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
    }
    const out = new Uint8Array(32), odv = new DataView(out.buffer);
    H.forEach((v, i) => odv.setUint32(4 * i, v));
    return out;
  }

  function hmac(hash, key, msg) {                      // HMAC for any hash with 64-byte blocks
    if (key.length > 64) key = hash(key);
    const k = new Uint8Array(64); k.set(key);
    const ipad = k.map((x) => x ^ 0x36), opad = k.map((x) => x ^ 0x5c);
    return hash(concat(opad, hash(concat(ipad, msg))));
  }
  const hmacSha256 = (key, msg) => hmac(sha256, key, msg);

  // --------------------------------------------------------------------------- SHA-1 (broken for collisions, still what authenticator apps use inside HMAC)
  function sha1(msg) {
    const p = sha256Pad(msg), dv = new DataView(p.buffer), H = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0], W = new Uint32Array(80);
    const rotl = (x, n) => (x << n) | (x >>> (32 - n));
    for (let off = 0; off < p.length; off += 64) {
      for (let t = 0; t < 16; t++) W[t] = dv.getUint32(off + 4 * t);
      for (let t = 16; t < 80; t++) W[t] = rotl(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
      let [a, b, c, d, e] = H;
      for (let t = 0; t < 80; t++) {
        const [f, k] = t < 20 ? [(b & c) | (~b & d), 0x5a827999] : t < 40 ? [b ^ c ^ d, 0x6ed9eba1]
          : t < 60 ? [(b & c) | (b & d) | (c & d), 0x8f1bbcdc] : [b ^ c ^ d, 0xca62c1d6];
        const tmp = (rotl(a, 5) + f + e + k + W[t]) >>> 0;
        e = d; d = c; c = rotl(b, 30) >>> 0; b = a; a = tmp;
      }
      H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0; H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0; H[4] = (H[4] + e) >>> 0;
    }
    const out = new Uint8Array(20), odv = new DataView(out.buffer);
    H.forEach((v, i) => odv.setUint32(4 * i, v));
    return out;
  }
  const hmacSha1 = (key, msg) => hmac(sha1, key, msg);

  // --------------------------------------------------------------------------- one-time codes (HOTP, RFC 4226; TOTP, RFC 6238)
  const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  function base32Encode(b) {
    let bits = 0, val = 0, out = "";
    for (const x of b) { val = (val << 8) | x; bits += 8; while (bits >= 5) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5; } }
    if (bits) out += B32[(val << (5 - bits)) & 31];
    return out;
  }
  function base32Decode(s) {
    const clean = s.toUpperCase().replace(/[\s=-]/g, ""), out = [];
    let bits = 0, val = 0;
    for (const ch of clean) {
      const i = B32.indexOf(ch);
      if (i < 0) throw new Error("not Base32");
      val = (val << 5) | i; bits += 5;
      if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; }
    }
    return Uint8Array.from(out);
  }
  /** One code from a shared secret and a counter. Returns the steps too, so they can be shown. */
  function hotp(key, counter, digits = 6) {
    const msg = new Uint8Array(8), dv = new DataView(msg.buffer);
    dv.setUint32(0, Math.floor(counter / 0x100000000)); dv.setUint32(4, counter >>> 0);
    const mac = hmacSha1(key, msg), offset = mac[19] & 15;
    const bin = ((mac[offset] & 0x7f) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
    return { counter, msg, mac, offset, bin, code: String(bin % 10 ** digits).padStart(digits, "0") };
  }
  /** The code an authenticator app shows at a given time (seconds since 1970). */
  const totp = (key, seconds, step = 30, digits = 6) => hotp(key, Math.floor(seconds / step), digits);

  // --------------------------------------------------------------------------- PART 3: AES-128 from scratch
  function makeSbox() {
    const sbox = new Array(256).fill(0), rotl = (x, n) => ((x << n) | (x >> (8 - n))) & 0xff;
    let p = 1, q = 1;
    do {
      p = p ^ ((p << 1) & 0xff) ^ (p & 0x80 ? 0x1b : 0);
      q ^= (q << 1) & 0xff; q ^= (q << 2) & 0xff; q ^= (q << 4) & 0xff;
      if (q & 0x80) q ^= 0x09;
      sbox[p] = q ^ rotl(q, 1) ^ rotl(q, 2) ^ rotl(q, 3) ^ rotl(q, 4) ^ 0x63;
    } while (p !== 1);
    sbox[0] = 0x63;
    return sbox;
  }
  const SBOX = makeSbox();
  const RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
  const xtime = (a) => (a & 0x80 ? ((a << 1) ^ 0x11b) & 0xff : a << 1);
  const gmul = (a, b) => { let r = 0; while (b) { if (b & 1) r ^= a; a = xtime(a); b >>= 1; } return r; };

  function expandKey(key) {
    const w = [];
    for (let i = 0; i < 4; i++) w.push(Array.from(key.subarray(4 * i, 4 * i + 4)));
    for (let i = 4; i < 44; i++) {
      let t = w[i - 1].slice();
      if (i % 4 === 0) { t = t.slice(1).concat(t.slice(0, 1)).map((b) => SBOX[b]); t[0] ^= RCON[i / 4 - 1]; }
      w.push(w[i - 4].map((b, j) => b ^ t[j]));
    }
    const rk = [];
    for (let r = 0; r < 11; r++) rk.push([].concat(w[4 * r], w[4 * r + 1], w[4 * r + 2], w[4 * r + 3]));
    return rk;
  }

  const subBytes = (s) => s.map((b) => SBOX[b]);
  const shiftRows = (s) => { const o = new Array(16); for (let c = 0; c < 4; c++) for (let r = 0; r < 4; r++) o[4 * c + r] = s[r + 4 * ((c + r) % 4)]; return o; };
  const addKey = (s, k) => s.map((b, i) => b ^ k[i]);
  function mixColumns(s) {
    const o = [];
    for (let c = 0; c < 4; c++) {
      const a = s.slice(4 * c, 4 * c + 4);
      o.push(gmul(a[0], 2) ^ gmul(a[1], 3) ^ a[2] ^ a[3], a[0] ^ gmul(a[1], 2) ^ gmul(a[2], 3) ^ a[3],
        a[0] ^ a[1] ^ gmul(a[2], 2) ^ gmul(a[3], 3), gmul(a[0], 3) ^ a[1] ^ a[2] ^ gmul(a[3], 2));
    }
    return o;
  }

  /** Encrypt one 16-byte block. If `trace` is an array, every step's state is pushed as {round, step, state}. */
  function aesBlock(block, rk, trace) {
    const log = (round, step, s) => trace && trace.push({ round, step, state: s.slice() });
    let s = Array.from(block);
    log(0, "Plaintext", s);
    s = addKey(s, rk[0]); log(0, "AddRoundKey", s);
    for (let r = 1; r <= 10; r++) {
      s = subBytes(s); log(r, "SubBytes", s);
      s = shiftRows(s); log(r, "ShiftRows", s);
      if (r < 10) { s = mixColumns(s); log(r, "MixColumns", s); }
      s = addKey(s, rk[r]); log(r, "AddRoundKey", s);
    }
    return Uint8Array.from(s);
  }

  const pad = (b) => { const n = 16 - (b.length % 16); return concat(b, new Uint8Array(n).fill(n)); };

  function aesEcb(key, data) {
    const rk = expandKey(key), out = new Uint8Array(data.length);
    for (let i = 0; i + 16 <= data.length; i += 16) out.set(aesBlock(data.subarray(i, i + 16), rk), i);
    return out;
  }

  function aesCbc(key, iv, data, padIt = true) {
    const rk = expandKey(key), p = padIt ? pad(data) : data, out = new Uint8Array(p.length);
    let prev = iv;
    for (let i = 0; i < p.length; i += 16) { prev = aesBlock(xor(p.subarray(i, i + 16), prev), rk); out.set(prev, i); }
    return out;
  }

  function ctrCrypt(rk, icb, data) {
    const out = new Uint8Array(data.length), ctr = new DataView(icb.buffer, icb.byteOffset).getUint32(12);
    for (let i = 0; i < data.length; i += 16) {
      const cb = new Uint8Array(16); cb.set(icb.subarray(0, 12));
      new DataView(cb.buffer).setUint32(12, (ctr + i / 16) >>> 0);
      out.set(xor(data.subarray(i, i + 16), aesBlock(cb, rk)), i);
    }
    return out;
  }

  // --- GCM: counter mode + GHASH tag
  const R_GCM = 0xe1n << 120n;
  const toBig = (b) => b.reduce((a, x) => (a << 8n) | BigInt(x), 0n);
  const fromBig = (x, n) => { const o = new Uint8Array(n); for (let i = n - 1; i >= 0; i--) { o[i] = Number(x & 0xffn); x >>= 8n; } return o; };
  function gfMul(x, y) {
    let z = 0n, v = y;
    for (let i = 127n; i >= 0n; i--) { if ((x >> i) & 1n) z ^= v; v = v & 1n ? (v >> 1n) ^ R_GCM : v >> 1n; }
    return z;
  }
  const zeroPad16 = (b) => concat(b, new Uint8Array((16 - (b.length % 16)) % 16));
  function gcmTag(rk, h, j0, aad, ct) {
    const lens = new Uint8Array(16), dv = new DataView(lens.buffer);
    dv.setUint32(4, aad.length * 8); dv.setUint32(12, ct.length * 8);
    let y = 0n;
    for (const blk of chunks(concat(zeroPad16(aad), zeroPad16(ct), lens))) y = gfMul(y ^ toBig(blk), h);
    return xor(aesBlock(j0, rk), fromBig(y, 16));
  }
  const nonceCtr = (nonce, n) => { const b = new Uint8Array(16); b.set(nonce); b[15] = n; return b; };
  function gcmEncrypt(key, nonce, pt, aad = new Uint8Array(0)) {
    const rk = expandKey(key), h = toBig(aesBlock(new Uint8Array(16), rk));
    const ct = ctrCrypt(rk, nonceCtr(nonce, 2), pt);
    return { ct, tag: gcmTag(rk, h, nonceCtr(nonce, 1), aad, ct) };
  }
  function gcmDecrypt(key, nonce, ct, tag, aad = new Uint8Array(0)) {
    const rk = expandKey(key), h = toBig(aesBlock(new Uint8Array(16), rk));
    if (!equalBytes(gcmTag(rk, h, nonceCtr(nonce, 1), aad, ct), tag)) throw new Error("TAG MISMATCH: message rejected");
    return ctrCrypt(rk, nonceCtr(nonce, 2), ct);
  }

  // --------------------------------------------------------------------------- PART 4: big-number maths
  function modPow(b, e, m) {
    let r = 1n; b %= m; if (b < 0n) b += m;
    while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; }
    return r;
  }
  function gcd(a, b) { a = a < 0n ? -a : a; b = b < 0n ? -b : b; while (b) [a, b] = [b, a % b]; return a; }
  function modInv(a, m) {
    let [r0, r1, s0, s1] = [((a % m) + m) % m, m, 1n, 0n];
    while (r1) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [s0, s1] = [s1, s0 - q * s1]; }
    if (r0 !== 1n) throw new Error("no inverse");
    return ((s0 % m) + m) % m;
  }
  const randBits = (n) => { const b = randBytes(Math.ceil(n / 8)); let x = toBig(b); return x >> BigInt(b.length * 8 - n); };
  function randBelow(n) { const L = n.toString(2).length; let x; do { x = randBits(L); } while (x >= n); return x; }

  const SMALL_PRIMES = [];
  for (let i = 3; SMALL_PRIMES.length < 300; i += 2) if (SMALL_PRIMES.every((p) => i % p)) SMALL_PRIMES.push(i);

  function isPrime(n, rounds = 25) {
    if (n < 4n) return n === 2n || n === 3n;
    if (!(n & 1n)) return false;
    for (const p of SMALL_PRIMES) { const bp = BigInt(p); if (n % bp === 0n) return n === bp; }
    let d = n - 1n, s = 0;
    while (!(d & 1n)) { d >>= 1n; s++; }
    outer: for (let k = 0; k < rounds; k++) {
      let x = modPow(2n + randBelow(n - 3n), d, n);
      if (x === 1n || x === n - 1n) continue;
      for (let i = 1; i < s; i++) { x = (x * x) % n; if (x === n - 1n) continue outer; }
      return false;
    }
    return true;
  }
  function genPrime(nbits) {
    for (;;) { const c = randBits(nbits) | (1n << BigInt(nbits - 1)) | 1n; if (isPrime(c)) return c; }
  }
  /** Returns {n, e, d, p, q} with n of about 2*pbits bits. */
  function rsaKeygen(pbits = 256, e = 65537n) {
    for (;;) {
      const p = genPrime(pbits), q = genPrime(pbits), phi = (p - 1n) * (q - 1n);
      if (p !== q && gcd(e, phi) === 1n) return { n: p * q, e, d: modInv(e, phi), p, q };
    }
  }
  function iroot(x, k) {          // integer k-th root (floor)
    if (x < 2n) return x;
    const K = BigInt(k);
    let r = 1n << BigInt(Math.ceil(x.toString(2).length / k));
    for (;;) { const nr = ((K - 1n) * r + x / r ** (K - 1n)) / K; if (nr >= r) break; r = nr; }
    while (r ** K > x) r--;
    while ((r + 1n) ** K <= x) r++;
    return r;
  }

  // --- elliptic curves y^2 = x^3 + ax + b (mod p)
  class Curve {
    constructor(name, p, a, b, G, n) { Object.assign(this, { name, p, a, b, G, n }); }
    add(P, Q) {
      if (P === null) return Q;
      if (Q === null) return P;
      const p = this.p, [x1, y1] = P, [x2, y2] = Q;
      if (x1 === x2 && (y1 + y2) % p === 0n) return null;
      const m = x1 === x2 && y1 === y2
        ? ((3n * x1 * x1 + this.a) * modInv(2n * y1, p)) % p
        : ((y2 - y1) * modInv(x2 - x1, p)) % p;
      const x3 = (((m * m - x1 - x2) % p) + p) % p;
      return [x3, (((m * (x1 - x3) - y1) % p) + p) % p];
    }
    mul(k, P = this.G) {
      let R = null;
      k = BigInt(k);
      while (k > 0n) { if (k & 1n) R = this.add(R, P); P = this.add(P, P); k >>= 1n; }
      return R;
    }
    onCurve(P) { if (P === null) return true; const [x, y] = P; return (y * y - (x * x * x + this.a * x + this.b)) % this.p === 0n; }
  }
  const TOY = new Curve("y² = x³ + 2x + 2 (mod 17)", 17n, 2n, 2n, [5n, 1n], 19n);
  const P256 = new Curve("NIST P-256", 2n ** 256n - 2n ** 224n + 2n ** 192n + 2n ** 96n - 1n, -3n,
    0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604Bn,
    [0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296n,
      0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5n],
    0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551n);

  function ecdsaSign(d, h, k) {
    const n = P256.n, r = P256.mul(k)[0] % n;
    return [r, (modInv(k, n) * (h + r * d)) % n];
  }
  function ecdsaVerify(Q, h, [r, s]) {
    const n = P256.n, w = modInv(s, n);
    const X = P256.add(P256.mul((h * w) % n), P256.mul((r * w) % n, Q));
    return X !== null && X[0] % n === r;
  }
  const hashInt = (s) => toBig(sha256(utf8(s)));

  // --- passkeys (WebAuthn): check a real ES256 login signature with the P-256 code above
  function derSig(der) {                               // SEQUENCE { INTEGER r, INTEGER s }
    if (der[0] !== 0x30) throw new Error("not a DER signature");
    let i = der[1] & 0x80 ? 2 + (der[1] & 0x7f) : 2;
    const int = () => {
      if (der[i++] !== 0x02) throw new Error("not a DER signature");
      const len = der[i++], v = toBig(der.subarray(i, i + len));
      i += len;
      return v;
    };
    return [int(), int()];
  }
  function spkiP256(spki) {                            // the last 65 bytes of a P-256 public key: 04 || x || y
    const p = spki.subarray(spki.length - 65);
    if (p[0] !== 0x04) throw new Error("not an uncompressed P-256 key");
    return [toBig(p.subarray(1, 33)), toBig(p.subarray(33))];
  }
  /** WebAuthn signs authenticatorData || SHA-256(clientDataJSON). */
  function verifyPasskey(spki, authData, clientDataJSON, der) {
    const h = toBig(sha256(concat(authData, sha256(clientDataJSON))));
    return ecdsaVerify(spkiP256(spki), h, derSig(der));
  }

  // --------------------------------------------------------------------------- PART 5: toy lattice encryption (Regev / LWE)
  function regevKeygen(q = 97, n = 6, m = 16) {
    const s = Array.from({ length: n }, () => randInt(q));
    const A = Array.from({ length: m }, () => Array.from({ length: n }, () => randInt(q)));
    const e = A.map(() => randInt(3) - 1);
    const b = A.map((row, i) => mod(row.reduce((acc, a, j) => acc + a * s[j], 0) + e[i], q));
    return { q, n, m, s, A, b, e };
  }
  function regevEncrypt(pk, bit) {
    const { q, n, m, A, b } = pk, S = [];
    for (let i = 0; i < m; i++) if (randInt(2)) S.push(i);
    const u = Array.from({ length: n }, (_, j) => mod(S.reduce((acc, i) => acc + A[i][j], 0), q));
    const v = mod(S.reduce((acc, i) => acc + b[i], 0) + bit * Math.floor(q / 2), q);
    return { S, u, v };
  }
  function regevDecrypt(pk, { u, v }) {
    const { q, s } = pk, r = mod(v - u.reduce((acc, x, j) => acc + x * s[j], 0), q);
    return { r, bit: r > q / 4 && r < (3 * q) / 4 ? 1 : 0 };
  }

  root.Lab = {
    utf8, text, hex, fromHex, bits, randBytes, concat, xor, chunks, bitDiff, equalBytes, randInt,
    ALPHA, FREQ, SAMPLE, letters, mod, caesar, counts, chi2, vigenere, ic, breakVigenere, Enigma,
    sha256, sha256Pad, hmac, hmacSha256, sha1, hmacSha1, base32Encode, base32Decode, hotp, totp,
    SBOX, expandKey, subBytes, shiftRows, mixColumns, addKey, aesBlock, pad, aesEcb, aesCbc, ctrCrypt, gcmEncrypt, gcmDecrypt, toBig, fromBig,
    modPow, gcd, modInv, randBits, randBelow, isPrime, genPrime, rsaKeygen, iroot, Curve, TOY, P256, ecdsaSign, ecdsaVerify, hashInt,
    derSig, spkiP256, verifyPasskey,
    regevKeygen, regevEncrypt, regevDecrypt,
  };
  if (typeof module !== "undefined" && module.exports) module.exports = root.Lab;
})(typeof window !== "undefined" ? window : globalThis);
