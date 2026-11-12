/* broken.js - the logic and the data behind the demos in "Case Studies in Cryptographic Failures".
   Pure functions, no DOM, so it runs in the browser (window.Broken) and in Node (module.exports) for testing.
   Every demo is TEACHING CODE ON INVENTED DATA: a toy cipher, toy keys, a toy compressor and a made-up web page.
   Nothing here talks to a network, and none of it attacks a real system or product.
   The hashes come from ../../shared/crypto.js (written from scratch to show each step; never use it to protect real data). */
(function (root) {
  "use strict";
  const Lab = root.Lab || (typeof require === "function" ? require("../../shared/crypto.js") : null);
  const u8 = (s) => Lab.utf8(s);
  const sha = (b) => Lab.sha256(typeof b === "string" ? u8(b) : b);
  const hex = (b) => Lab.hex(b);
  const cat = (...a) => Lab.concat(...a.map((x) => (x instanceof Uint8Array ? x : Uint8Array.from(x))));
  const xor = (a, b) => Lab.xor(a, b);

  // a small seeded random generator, so tests are repeatable (mulberry32); pages pass a real one
  function rng(seed) {
    let a = seed >>> 0;
    return function () {
      a = (a + 0x6d2b79f5) >>> 0; let t = a;
      t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }
  const cryptoRand = () => Lab.randInt(0x7fffffff) / 0x7fffffff;

  function humanTime(sec) {
    if (!isFinite(sec)) return "never";
    if (sec < 0.001) return "under a millisecond";
    if (sec < 1) return Math.round(sec * 1000) + " ms";
    if (sec < 90) return sec.toFixed(sec < 10 ? 1 : 0) + " seconds";
    if (sec < 5400) return Math.round(sec / 60) + " minutes";
    if (sec < 172800) return Math.round(sec / 3600) + " hours";
    if (sec < 86400 * 365 * 2) return Math.round(sec / 86400) + " days";
    const y = sec / (86400 * 365.25);
    if (y < 1e6) return Math.round(y).toLocaleString("en-US") + " years";
    if (y < 1e9) return (y / 1e6).toFixed(1) + " million years";
    if (y < 1e12) return (y / 1e9).toFixed(1) + " billion years";
    return "about 10^" + Math.round(Math.log10(y)) + " years";
  }

  // =========================================================================== the title terminal: where does it stand today?
  // Wording follows the RFCs and advisories named in "src"; checked 9 November 2026.
  const STATUS = [
    { id: "sslv2", names: ["ssl 2.0", "sslv2", "ssl2", "ssl 2"], label: "SSL 2.0", verdict: "Prohibited", tone: "bad", when: "March 2011",
      why: "RFC 6176 requires that TLS clients and servers never negotiate SSL 2.0. DROWN (2016) showed that merely supporting it endangers servers that share a key.", src: "RFC 6176; drownattack.com" },
    { id: "sslv3", names: ["ssl 3.0", "sslv3", "ssl3", "ssl 3", "ssl"], label: "SSL 3.0", verdict: "Prohibited", tone: "bad", when: "June 2015",
      why: "RFC 7568 requires that SSLv3 not be used, after POODLE (2014). The RFC also prohibits falling back to it.", src: "RFC 7568" },
    { id: "tls10", names: ["tls 1.0", "tls1.0", "tls 10", "tls10", "tls 1.1", "tls1.1", "tls 11", "tls11", "tls 1", "tls"], label: "TLS 1.0 and 1.1", verdict: "Deprecated", tone: "bad", when: "March 2021",
      why: "RFC 8996 formally deprecates them and moves them to Historic. RFC 9325 (2022) says implementations must not negotiate them.", src: "RFC 8996; RFC 9325" },
    { id: "tls12", names: ["tls 1.2", "tls1.2", "tls 12", "tls12"], label: "TLS 1.2", verdict: "Still fine, with care", tone: "ok", when: "RFC 9325, 2022",
      why: "RFC 9325 recommends supporting TLS 1.2 and 1.3, with forward secrecy and AEAD cipher suites, and none of the legacy items on this list.", src: "RFC 9325" },
    { id: "tls13", names: ["tls 1.3", "tls1.3", "tls 13", "tls13"], label: "TLS 1.3", verdict: "Current", tone: "ok", when: "August 2018",
      why: "RFC 8446. It removed static RSA and Diffie-Hellman suites, compression and every non-AEAD cipher, and added a downgrade sentinel in the server's random value.", src: "RFC 8446" },
    { id: "rc4", names: ["rc4"], label: "RC4 in TLS", verdict: "Prohibited", tone: "bad", when: "February 2015",
      why: "RFC 7465: TLS clients and servers must never negotiate RC4 cipher suites. RFC 9325 repeats it.", src: "RFC 7465; RFC 9325" },
    { id: "3des", names: ["3des", "triple des", "triple-des", "tdea", "des"], label: "3DES (TDEA)", verdict: "Disallowed by NIST", tone: "bad", when: "after 2023",
      why: "NIST: three-key TDEA encryption was deprecated through 2023 and disallowed after; SP 800-67 Rev. 2 was withdrawn on 1 January 2024. Sweet32 (2016) showed the 64-bit block problem.", src: "NIST SP 800-131A Rev. 2; NIST news, 2023; sweet32.info" },
    { id: "md5", names: ["md5"], label: "MD5", verdict: "Broken for signatures", tone: "bad", when: "since 2004",
      why: "Collisions were shown in 2004, a rogue CA certificate in 2008, the Flame certificate in 2012 and RADIUS forgery (Blast-RADIUS) in 2024. RFC 9325: MD5 must not be used for signatures when authenticating with RSA.", src: "blastradius.fail; MSRC advisory 2718704; RFC 9325" },
    { id: "sha1", names: ["sha1", "sha-1", "sha 1"], label: "SHA-1", verdict: "Retiring by 2030", tone: "y", when: "NIST, December 2022",
      why: "SHAttered (2017) and a practical chosen-prefix collision (2019/2020). NIST: phase it out by the end of 2030. Public CAs stopped issuing SHA-1 certificates in 2016 (Ballot 118). RFC 9325: must not be used for signatures when authenticating with RSA.", src: "shattered.io; sha-mbles.github.io; NIST; CA/B Forum Ballot 118; RFC 9325" },
    { id: "export", names: ["export", "export ciphers", "export grade", "export-grade", "rsa export", "rsa_export", "dhe_export", "dhe export"], label: "Export-grade suites", verdict: "Remove them", tone: "bad", when: "1990s relic",
      why: "40- and 56-bit suites left over from 1990s US export rules enabled FREAK and Logjam (2015). RFC 9325: never negotiate suites with less than 112 bits of security, including export-level ones.", src: "freakattack.com; weakdh.org; RFC 9325" },
    { id: "static-rsa", names: ["static rsa", "rsa key exchange", "rsa kx", "tls_rsa", "rsa key transport"], label: "RSA key exchange (TLS_RSA_*)", verdict: "Removed in TLS 1.3", tone: "y", when: "2018",
      why: "TLS 1.3 removed static RSA and Diffie-Hellman suites so every key exchange has forward secrecy. RFC 9325: should not be negotiated. ROBOT (2017) hit RSA key exchange.", src: "RFC 8446; RFC 9325; robotattack.org" },
    { id: "cbc", names: ["cbc", "cbc mode", "mac-then-encrypt", "mac then encrypt", "aes-cbc", "aes cbc"], label: "CBC cipher suites", verdict: "Avoid; gone in TLS 1.3", tone: "y", when: "TLS 1.3, 2018",
      why: "TLS 1.3 keeps only AEAD ciphers. RFC 9325: CBC suites should not be used unless encrypt-then-MAC (RFC 7366) is negotiated. Lucky Thirteen and POODLE were padding oracles in CBC.", src: "RFC 8446; RFC 9325; RFC 7366" },
    { id: "compression", names: ["compression", "tls compression", "http compression", "gzip"], label: "TLS compression", verdict: "Off", tone: "y", when: "removed in TLS 1.3",
      why: "CRIME (2012) used TLS compression; BREACH (2013) showed that HTTP compression leaks too. RFC 9325: TLS 1.2 deployments should not support TLS-level compression; TLS 1.3 removed it.", src: "RFC 8446; RFC 9325; breachattack.com" },
    { id: "wep", names: ["wep"], label: "WEP", verdict: "Broken since 2001", tone: "bad", when: "2001",
      why: "The Fluhrer, Mantin and Shamir attack on RC4's key scheduling (2001) was turned into a practical WEP key recovery the same year. WPA (2003) and WPA2 (2004) replaced it.", src: "Fluhrer, Mantin, Shamir 2001; Stubblefield, Ioannidis, Rubin 2001; Wi-Fi Alliance history (sources differ on exact dates)" },
    { id: "dualec", names: ["dual_ec", "dual ec", "dual_ec_drbg", "dualec", "dual ec drbg"], label: "Dual_EC_DRBG", verdict: "Withdrawn", tone: "bad", when: "2013 to 2015",
      why: "NIST's September 2013 bulletin recommended that it no longer be used; SP 800-90A Rev. 1 (June 2015) formally withdraws it.", src: "NIST SP 800-90 historical information; NIST SP 800-90A Rev. 1" },
    { id: "gcm", names: ["aes-gcm", "aes gcm", "gcm", "chacha20-poly1305", "chacha20", "aead"], label: "AEAD (AES-GCM, ChaCha20-Poly1305)", verdict: "Current", tone: "ok", when: "TLS 1.3 requires it",
      why: "Authenticated encryption is what TLS 1.3 allows. The nonce rules still apply: see Using Crypto Correctly in Code.", src: "RFC 8446" },
  ];
  const norm = (s) => String(s).toLowerCase().replace(/[_\s]+/g, " ").trim();
  function audit(q) {
    const t = norm(q);
    if (!t) return null;
    return STATUS.find((e) => e.names.some((n) => norm(n) === t)) || null;
  }

  // =========================================================================== Debian, 2006-2008: the key space was tiny
  // The toy: a "key" is made from a seed. Debian's seed was the process ID: 15 bits, 32,767 values per architecture.
  const toyKey = (seed) => hex(sha("toy-key|" + seed)).slice(0, 16);
  function blocklist(bits) {
    if (bits < 1 || bits > 20) throw new Error("bits out of range");
    const set = new Set(), n = 2 ** bits;
    for (let s = 1; s < n; s++) set.add(toyKey(s));
    return set;
  }
  const goodKey = () => hex(sha(Lab.randBytes(16))).slice(0, 16);

  // =========================================================================== ROCA, 2017: structured primes leave a fingerprint
  // The toy follows the shape reported by Nemec et al. (CCS 2017): p = k*M + (65537^a mod M) with M a primorial, so that
  // N mod each small prime lies in the group generated by 65537. The real library used a longer list of primes; this one uses 20.
  const ROCA_PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71];
  const GEN = 65537n;
  const BM = ROCA_PRIMES.reduce((a, p) => a * BigInt(p), 1n);
  function modpow(b, e, m) { let r = 1n; b %= m; while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; } return r; }
  const bitlen = (n) => n.toString(2).length;
  function randBig(rand, bits) {
    let r = 0n, left = bits;
    while (left > 0) { const take = Math.min(32, left); r = (r << BigInt(take)) | BigInt(Math.floor(rand() * 2 ** take)); left -= take; }
    return r;
  }
  const MR_BASES = [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n, 41n, 43n, 47n, 53n];
  function isPrime(n) {
    if (n < 2n) return false;
    for (const p of MR_BASES) { if (n === p) return true; if (n % p === 0n) return false; }
    let d = n - 1n, s = 0; while ((d & 1n) === 0n) { d >>= 1n; s++; }
    outer: for (const a of MR_BASES) {
      let x = modpow(a, d, n);
      if (x === 1n || x === n - 1n) continue;
      for (let i = 1; i < s; i++) { x = (x * x) % n; if (x === n - 1n) continue outer; }
      return false;
    }
    return true;
  }
  function plainPrime(rand, bits) {
    for (;;) { const c = randBig(rand, bits) | (1n << BigInt(bits - 1)) | 1n; if (isPrime(c)) return c; }
  }
  function structuredPrime(rand, bits) {
    const kbits = bits - bitlen(BM) + 1;
    if (kbits < 8) throw new Error("bits too small for this M");
    for (;;) {
      const k = randBig(rand, kbits) | (1n << BigInt(kbits - 1));
      const a = randBig(rand, 40);
      const p = k * BM + modpow(GEN, a, BM);
      if (bitlen(p) === bits && isPrime(p)) return p;
    }
  }
  function genKey(rand, kind, primeBits) {
    primeBits = primeBits || 112;
    const make = kind === "roca" ? structuredPrime : plainPrime;
    let p = make(rand, primeBits), q = make(rand, primeBits);
    while (q === p) q = make(rand, primeBits);
    return { p, q, n: p * q, kind };
  }
  // the subgroup of (Z/lZ)* generated by 65537, for each small prime l
  const SUBGROUPS = ROCA_PRIMES.map((l) => {
    const L = BigInt(l), g = GEN % L, set = new Set();
    if (l === 2) { set.add(1); return { l, set, order: 1 }; }
    let x = 1n; do { set.add(Number(x)); x = (x * g) % L; } while (x !== 1n);
    return { l, set, order: set.size };
  });
  function fingerprint(n) {
    const rows = SUBGROUPS.map((g) => { const r = Number(n % BigInt(g.l)); return { l: g.l, r, pass: g.set.has(r), order: g.order }; });
    const matches = rows.filter((r) => r.pass).length;
    return { rows, matches, structured: matches === rows.length };
  }
  // chance that a random modulus passes every test: product of |group| / (l - 1)
  function falsePositiveOdds() {
    let p = 1;
    for (const g of SUBGROUPS) p *= g.l === 2 ? 1 : g.order / (g.l - 1);
    return { p, oneIn: 1 / p };
  }
  function parseModulus(s) {
    s = String(s).trim().replace(/[\s:_]/g, "");
    if (!s) return null;
    try { if (/^0x[0-9a-f]+$/i.test(s)) return BigInt(s); if (/^[0-9]+$/.test(s)) return BigInt(s); if (/^[0-9a-f]+$/i.test(s)) return BigInt("0x" + s); } catch (e) { /* fall through */ }
    return null;
  }

  // =========================================================================== hash collisions: the birthday bound
  function birthday(bits, salt) {
    if (bits < 4 || bits > 32) throw new Error("bits out of range");
    const seen = new Map(), shift = 2 ** (32 - bits);
    for (let i = 0; ; i++) {
      const m = salt + ":" + i, h = sha(m);
      const v = Math.floor((h[0] * 16777216 + h[1] * 65536 + h[2] * 256 + h[3]) / shift);
      if (seen.has(v)) return { trials: i + 1, a: seen.get(v), b: m, value: v };
      seen.set(v, m);
    }
  }
  const birthdayExpected = (bits) => 1.2533 * 2 ** (bits / 2);

  // =========================================================================== padding oracles, on a toy cipher
  // An 8-byte block cipher made from a 4-round Feistel network with SHA-256 as the round function. It is NOT a real cipher:
  // it only exists so that CBC mode and padding can be shown on small numbers.
  const BS = 8;
  const rf = (key, round, half) => sha(cat(key, [round], half)).slice(0, 4);
  function encBlock(key, blk) {
    let L = blk.slice(0, 4), R = blk.slice(4, 8);
    for (let r = 0; r < 4; r++) { const nL = R, nR = xor(L, rf(key, r, R)); L = nL; R = nR; }
    return cat(L, R);
  }
  function decBlock(key, blk) {
    let L = blk.slice(0, 4), R = blk.slice(4, 8);
    for (let r = 3; r >= 0; r--) { const pR = L, pL = xor(R, rf(key, r, L)); L = pL; R = pR; }
    return cat(L, R);
  }
  function pad(msg) { const n = BS - (msg.length % BS); return cat(msg, new Uint8Array(n).fill(n)); }
  function cbcEncrypt(key, iv, msg) {
    const p = pad(msg), out = []; let prev = iv;
    for (let i = 0; i < p.length; i += BS) { prev = encBlock(key, xor(p.slice(i, i + BS), prev)); out.push(prev); }
    return out;                        // array of ciphertext blocks (the IV is public and sent first)
  }
  function paddingValid(block) {
    const n = block[BS - 1];
    if (n < 1 || n > BS) return false;
    for (let i = BS - n; i < BS; i++) if (block[i] !== n) return false;
    return true;
  }
  // the "server": decrypt [prev, target], look at the padding, and answer in one of two styles
  function oracle(key, prev, target, mode) {
    const ok = paddingValid(xor(decBlock(key, target), prev));
    if (mode === "uniform") return { ok, text: "decryption failed" };
    return { ok, text: ok ? "padding OK (then MAC fails)" : "bad padding" };
  }
  function oracleGrid(key, target, mode) {
    const cells = [];
    for (let g = 0; g < 256; g++) {
      const prev = new Uint8Array(BS); prev[BS - 1] = g;
      const r = oracle(key, prev, target, mode);
      cells.push({ g, ok: r.ok, text: r.text });
    }
    return cells;
  }
  // with distinct errors, the one valid cell shows D(target)[7] XOR g = 0x01
  function lastByteFromGrid(key, target, prevReal, cells, mode) {
    const lit = cells.filter((c) => c.ok && mode !== "uniform");
    if (!lit.length) return { known: false, lit: cells.filter((c) => c.ok).length };
    let g = lit[0].g;
    if (lit.length > 1) {                // a longer padding like 02 02 can also be valid: flip an earlier byte and ask again
      for (const c of lit) {
        const prev = new Uint8Array(BS); prev[BS - 1] = c.g; prev[BS - 2] = 0xff;
        if (oracle(key, prev, target, mode).ok) { g = c.g; break; }
      }
    }
    return { known: true, lit: lit.length, g, byte: g ^ 1 ^ prevReal[BS - 1] };
  }
  function makeCipherDemo(rand, message) {
    message = message || "pin=4271";
    const key = Lab.randBytes ? Lab.randBytes(16) : Uint8Array.from({ length: 16 }, () => Math.floor(rand() * 256));
    const iv = Uint8Array.from({ length: BS }, () => Math.floor(rand() * 256));
    const blocks = cbcEncrypt(key, iv, u8(message));
    return { key, iv, blocks, message };
  }

  // =========================================================================== downgrade and legacy: who wins the negotiation?
  const VERS = ["SSL 3.0", "TLS 1.0", "TLS 1.2", "TLS 1.3"];
  const rank = (v) => VERS.indexOf(v);
  const highest = (set) => VERS.slice().reverse().find((v) => set.has(v)) || null;
  function negotiate(o) {
    const client = new Set(o.client), server = new Set(o.server);
    const steps = [];
    const out = (r) => Object.assign({ steps, exportNote: exportNote(o) }, r);
    const top = highest(client);
    if (!top) return out({ ok: false, version: null, outcome: "failed", note: "The client supports no version." });
    let attempt = top, first = true;
    for (let guard = 0; guard < 8; guard++) {
      steps.push((first ? "Client offers up to " : "Client retries, offering up to ") + attempt + (!first && o.scsv ? " (with TLS_FALLBACK_SCSV)" : ""));
      if (o.attacker && rank(attempt) > rank("SSL 3.0")) {
        steps.push("The attacker on the network resets the connection.");
        if (!o.dance) return out({ ok: false, version: null, outcome: "blocked", note: "The client doesn't retry with lower versions: no connection, and no downgrade." });
        const lower = VERS.slice(0, rank(attempt)).reverse().find((v) => client.has(v));
        if (!lower) return out({ ok: false, version: null, outcome: "blocked", note: "No lower version left to try: no connection." });
        attempt = lower; first = false; continue;
      }
      const common = VERS.filter((v) => client.has(v) && server.has(v) && rank(v) <= rank(attempt));
      const neg = common.length ? common[common.length - 1] : null;
      if (!neg) return out(o.attacker && !first
        ? { ok: false, version: null, outcome: "blocked", note: "The server has no old version left to fall back to: the attacker can cause a failure, not a downgrade." }
        : { ok: false, version: null, outcome: "failed", note: "No version in common." });
      const serverTop = highest(server);
      if (!first && o.scsv && rank(serverTop) > rank(attempt)) {
        steps.push("The server sees a fallback but supports " + serverTop + ": it answers inappropriate_fallback.");
        return out({ ok: false, version: null, outcome: "defended", note: "The fallback signal stopped the downgrade: the connection fails instead of using " + neg + "." });
      }
      if (o.sentinel && client.has("TLS 1.3") && server.has("TLS 1.3") && rank(neg) < rank("TLS 1.3")) {
        steps.push("The server answers with " + neg + " and sets the last bytes of its random value to DOWNGRD.");
        steps.push("The client supports TLS 1.3, sees the sentinel and aborts with illegal_parameter.");
        return out({ ok: false, version: null, outcome: "defended", note: "The TLS 1.3 downgrade sentinel caught it: the connection fails instead of using " + neg + "." });
      }
      steps.push("The server and client agree on " + neg + ".");
      const weak = rank(neg) <= rank("TLS 1.0");
      return out({ ok: true, version: neg, outcome: weak ? "weak" : "safe",
        note: weak ? (neg === "SSL 3.0" ? "SSL 3.0 is prohibited (RFC 7568): POODLE applies to its CBC padding." : "TLS 1.0 is deprecated (RFC 8996): it still has CBC with the old padding design.") : neg + " is acceptable." });
    }
    return out({ ok: false, version: null, outcome: "failed", note: "Too many retries." });
  }
  function exportNote(o) {
    if (!o.serverExport) return "The server offers no export-grade suites: nothing for FREAK or Logjam to force.";
    return o.attacker
      ? "The server still offers export-grade suites (512-bit RSA or Diffie-Hellman). A network attacker can try to force them: Logjam did it to any client against servers with DHE_EXPORT, and FREAK did it to clients with the bug. A 512-bit value can be broken: the Logjam team broke the most common 512-bit prime."
      : "The server still offers export-grade suites. Nothing forces them in this run, but one active attacker could: switch the attacker on.";
  }

  // =========================================================================== compression side channel, on an invented page
  // The toy compressor counts bytes the way an LZ77 coder roughly does: a literal costs 1, a back-reference of 3+ bytes costs 2.
  function toyCompress(s) {
    const n = s.length; let i = 0, out = 0;
    while (i < n) {
      let best = 0;
      for (let j = Math.max(0, i - 4096); j < i; j++) { let k = 0; while (i + k < n && s[j + k] === s[i + k]) k++; if (k > best) best = k; }
      if (best >= 3) { out += 2; i += best; } else { out += 1; i++; }
    }
    return out;
  }
  const HEX = "0123456789abcdef";
  function makeSecret(rand) { let s = ""; for (let i = 0; i < 12; i++) s += HEX[Math.floor(rand() * 16)]; return s; }
  function pageFor(secret, reflected, mitigation, rand) {
    let tokenShown = secret;
    if (mitigation === "mask") {         // a fresh random pad per response: the token on the page changes every time
      let pad = "", masked = "";
      for (let i = 0; i < secret.length; i++) { const p = Math.floor(rand() * 16); pad += HEX[p]; masked += HEX[parseInt(secret[i], 16) ^ p]; }
      tokenShown = pad + masked;
    }
    let filler = "";
    if (mitigation === "pad") { const len = Math.floor(rand() * 24); for (let i = 0; i < len; i++) filler += String.fromCharCode(33 + Math.floor(rand() * 90)); }
    return '<form method="post" action="/transfer"><input type="hidden" name="csrf_token" value="' + tokenShown + '"><input name="amount"><button>Pay</button></form><p>Results for: csrf_token" value="' + reflected + "</p>" + filler;
  }
  function leakTable(secret, known, mitigation, rand) {
    const rows = HEX.split("").map((c) => {
      const page = pageFor(secret, known + c, mitigation, rand);
      return { c, size: mitigation === "off" ? page.length : toyCompress(page) };
    });
    const min = Math.min(...rows.map((r) => r.size));
    for (const r of rows) r.best = r.size === min;
    return rows;
  }

  // =========================================================================== the cases
  const CATS = [
    { id: "rand", name: "Randomness" },
    { id: "prim", name: "Aged or weak primitive" },
    { id: "proto", name: "Protocol design" },
    { id: "impl", name: "Implementation" },
    { id: "trust", name: "Trust and process" },
  ];
  // "my classification": a teaching judgement, and several cases fit two categories (each "also" says which)
  const CASES = [
    { id: "debian", name: "Debian OpenSSL", year: "2008", cat: "rand", also: "impl", algo: "No. RSA and DSA were fine; their random input wasn't.", note: "A packaging change removed the entropy mixing. The algorithm was never the problem." },
    { id: "roca", name: "ROCA", year: "2017", cat: "impl", also: "rand", algo: "No. RSA is fine; the library built its primes in a structured way.", note: "Not a bad random-number generator: an algorithmic flaw in how primes were constructed." },
    { id: "ps3", name: "Sony PS3 signing", year: "2010", cat: "rand", also: "impl", algo: "No. ECDSA is fine; a value that must be fresh every time wasn't.", note: "Two signatures with the same secret value reveal the key." },
    { id: "dualec", name: "Dual_EC and Juniper", year: "2007 to 2015", cat: "trust", also: "rand", algo: "Questioned. The design had constants nobody could explain.", note: "A standards-process and supply-chain story as much as a maths one." },
    { id: "flame", name: "MD5 and Flame", year: "2012", cat: "prim", also: "trust", algo: "Yes: MD5 collisions were known from 2004.", note: "A broken hash was still accepted by one CA path, which is also a process failure." },
    { id: "poodle", name: "POODLE", year: "2014", cat: "proto", also: "prim", algo: "No. SSL 3.0's construction left padding outside the MAC.", note: "The design checked the MAC but not the padding, and clients would fall back to it." },
    { id: "robot", name: "ROBOT", year: "2017", cat: "impl", also: "proto", algo: "Old: RSA encryption with PKCS #1 v1.5 padding is fragile, and servers still leaked.", note: "The authors call it an implementation bug in servers: nothing clients can do." },
    { id: "downgrade", name: "FREAK, Logjam, DROWN", year: "2015 to 2016", cat: "proto", also: "trust", algo: "Export-grade parameters and SSLv2 were weak by design.", note: "Backwards compatibility with 1990s rules left a lever for an active attacker." },
    { id: "sweet32", name: "Sweet32", year: "2016", cat: "prim", also: "proto", algo: "Yes, at scale: 64-bit blocks collide after about 32 GB under one key.", note: "A cipher used beyond its limits, with nothing forcing a rekey." },
    { id: "crime", name: "CRIME and BREACH", year: "2012 to 2013", cat: "proto", also: "impl", algo: "No. Compression and encryption are each fine; combined they leak length.", note: "Compressing a secret together with attacker-controlled text." },
    { id: "krack", name: "KRACK", year: "2017", cat: "proto", also: "impl", algo: "No. AES-CCMP was fine; a handshake step let a key be installed twice.", note: "The proofs covered secrecy and authentication, not when keys are installed." },
    { id: "heartbleed", name: "Heartbleed", year: "2014", cat: "impl", also: "", algo: "Not a crypto flaw at all.", note: "A missing length check in OpenSSL's heartbeat code let anyone read server memory." },
  ];
  const catName = (id) => CATS.find((c) => c.id === id).name;

  // how long each flaw lived before it was found (dates from the primary sources on each slide)
  const LIFE = [
    { id: "poodle", name: "SSL 3.0 padding (POODLE)", from: "1996-11-18", to: "2014-10-14", fromLabel: "SSL 3.0, Nov 1996", toLabel: "advisory, Oct 2014", found: "Google researchers" },
    { id: "krack", name: "WPA2 handshake (KRACK)", from: "2004-06-01", to: "2017-10-16", fromLabel: "WPA2, 2004", toLabel: "disclosed 16 Oct 2017", found: "University researchers", approx: true },
    { id: "md5", name: "MD5 certificates (Flame)", from: "2004-08-01", to: "2012-06-03", fromLabel: "collisions shown, 2004", toLabel: "advisory 3 Jun 2012", found: "Seen in the wild; analysed by Microsoft and CWI", approx: true },
    { id: "roca", name: "ROCA key generation", from: "2012-01-01", to: "2017-10-16", fromLabel: "in code by 2012 at the latest", toLabel: "public 16 Oct 2017", found: "University researchers", approx: true },
    { id: "heartbleed", name: "Heartbleed", from: "2012-03-14", to: "2014-04-07", fromLabel: "OpenSSL 1.0.1, 14 Mar 2012", toLabel: "fixed 7 Apr 2014", found: "Google and Codenomicon" },
    { id: "debian", name: "Debian OpenSSL", from: "2006-09-17", to: "2008-05-13", fromLabel: "upload, 17 Sep 2006", toLabel: "DSA-1571, 13 May 2008", found: "A researcher (Luciano Bello)" },
  ];
  const years = (a, b) => (Date.parse(b) - Date.parse(a)) / (365.25 * 86400000);

  // my mapping of controls to cases (a teaching judgement, not a standard)
  const CONTROLS = {
    debian: { prevent: "Review any patch to randomness code upstream; add a test that two key generations never match.", detect: "Blocklists of known-weak keys (ssh-vulnkey, dowkd); scan your own keys after the advisory.", limit: "Short-lived keys and certificates, and a rehearsed way to replace them." },
    roca: { prevent: "Check the statistics of keys a device produces before trusting it; do not treat certification as analysis.", detect: "A public-key fingerprint test over your key inventory: it needs only the public key.", limit: "Know which chip made each key, and keep lifetimes short enough to rotate." },
    ps3: { prevent: "Use a vetted signing API, or derive the nonce deterministically (RFC 6979); never let application code choose it.", detect: "Look for repeated r values in signatures you can see; a test that two signatures differ.", limit: "Per-device or per-product signing keys instead of one key that signs everything." },
    dualec: { prevent: "Prefer designs whose constants are explained; flag unexplained constants in review.", detect: "Diff third-party and firmware code for changed constants; public scrutiny of standards.", limit: "Don't use one generator's output raw: mix sources, and keep the ability to switch algorithms." },
    flame: { prevent: "Retire MD5 and SHA-1 everywhere, including odd corners, and inventory every CA and key purpose.", detect: "Certificate Transparency and monitoring (these came after 2012) and alerts on unexpected signing certificates.", limit: "Restrict key usage on intermediates, and be ready to revoke trust quickly." },
    poodle: { prevent: "Disable SSL 3.0 and move to AEAD suites; use the fallback signal while you can't.", detect: "Regular scans of your own servers for legacy protocols and cipher suites.", limit: "Forward secrecy and short sessions reduce what one broken session exposes." },
    robot: { prevent: "Disable RSA key exchange (TLS_RSA_*) and patch the TLS stack; answer every failure the same way.", detect: "Test your servers and appliances with published checkers; watch vendor advisories.", limit: "Forward secrecy, so a recorded session can't be decrypted later." },
    downgrade: { prevent: "Remove export suites and SSLv2; use unique 2048-bit Diffie-Hellman groups or ECDHE; support TLS 1.3.", detect: "Scan for legacy protocols on every service, mail servers and appliances included.", limit: "Never share a private key between a modern server and one that still speaks SSLv2." },
    sweet32: { prevent: "Stop negotiating 3DES and Blowfish; prefer 128-bit block ciphers.", detect: "Scan cipher lists, including VPNs and embedded devices.", limit: "Cap the data under one key: renegotiate or reconnect." },
    crime: { prevent: "Don't compress secrets together with attacker-controlled text; turn TLS compression off.", detect: "Review pages that reflect input next to a token, and the compression settings.", limit: "Per-request tokens or masking, and hiding the length." },
    krack: { prevent: "Specify and test state: retransmitted and replayed handshake messages, not only the happy path.", detect: "Inventory Wi-Fi clients and access points so you know what needs patching.", limit: "HTTPS or a VPN over Wi-Fi: a second layer so one broken link isn't everything." },
    heartbleed: { prevent: "Fuzzing, bounds checks, review, and memory-safe languages for parsers.", detect: "Scan for the vulnerable version; note the bug left no trace in logs.", limit: "Forward secrecy, fast key rotation and a certificate replacement drill." },
  };

  const AUDIT = [
    "I know which library, chip or service generates each of our keys, and which version.",
    "Key generation uses the operating system's secure generator, and a test shows two runs give different keys.",
    "When a vendor publishes a key-generation advisory, we can scan our public keys for the pattern.",
    "Our TLS configuration has no SSL 2.0 or 3.0 and no TLS 1.0 or 1.1, and we've checked every service, not just the website.",
    "No export-grade suites, RC4, 3DES or static RSA (TLS_RSA_*), and CBC suites only with encrypt-then-MAC.",
    "No MD5 or SHA-1 in signatures: certificates, code signing, SAML, and RADIUS (Message-Authenticator or RADIUS over TLS).",
    "Pages that reflect user input next to a secret don't ship that secret through compression unmasked.",
    "Signatures come from a vetted library with deterministic or hedged nonces; nobody wrote their own ECDSA.",
    "No private key is shared between services, and none is shared with a server that still speaks an old protocol.",
    "Crypto libraries are on the patch list with an owner, and we know how to rotate keys after a leak.",
    "We have rehearsed replacing a key or certificate in a day, so a flaw like these is an afternoon, not a project.",
    "We write incident reviews in six beats: design, failure, how it was found, impact, fix, lesson.",
  ];

  const Broken = {
    rng, cryptoRand, humanTime,
    STATUS, audit,
    toyKey, blocklist, goodKey,
    ROCA_PRIMES, genKey, fingerprint, falsePositiveOdds, parseModulus, isPrime, bitlen, BM,
    birthday, birthdayExpected,
    BS, encBlock, decBlock, pad, cbcEncrypt, paddingValid, oracle, oracleGrid, lastByteFromGrid, makeCipherDemo,
    VERS, negotiate,
    toyCompress, makeSecret, pageFor, leakTable, HEX,
    CATS, CASES, catName, LIFE, years, CONTROLS, AUDIT,
  };
  root.Broken = Broken;
  if (typeof module !== "undefined" && module.exports) module.exports = Broken;
})(typeof window !== "undefined" ? window : globalThis);
