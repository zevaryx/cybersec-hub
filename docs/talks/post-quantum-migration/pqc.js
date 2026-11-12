/* pqc.js - the logic behind "Post-Quantum Migration".
   TEACHING CODE ON INVENTED DATA. Nothing here protects anything:
   - X25519 is the real algorithm (RFC 7748, checked against its test vectors) but not constant-time.
   - The "toy LWE KEM" is a learning-with-errors puzzle with tiny parameters. It is NOT ML-KEM, it has no
     chosen-ciphertext protection, and its parameters can be broken by hand. It stands in for ML-KEM so the hybrid
     demo can show where the two secrets go. Use a vetted library for real work.
   - The size tables are copied from FIPS 203, 204 and 205 (Table 3, Table 2 and Table 2) and from RFC 7748, RFC 8032 and RFC 10024.
   - The handshake cost model is a deliberately simple one (see HS_ASSUMPTIONS), not a measurement.
   Hashes, HMAC and HKDF come from ../../shared/crypto.js (window.Lab). Works in the browser (window.Pqc) and in Node (module.exports). */
(function (root) {
  "use strict";
  const L = root.Lab || (typeof require !== "undefined" ? require("../../shared/crypto.js") : null);
  const { utf8, concat, randBytes, hex, sha256, hkdfExtract, hkdfExpand, equalBytes } = L;

  // --------------------------------------------------------------------------- X25519 (RFC 7748)
  const P = (1n << 255n) - 19n;
  const leToBig = (b) => { let x = 0n; for (let i = b.length - 1; i >= 0; i--) x = (x << 8n) | BigInt(b[i]); return x; };
  const bigToLe = (x, n = 32) => { const o = new Uint8Array(n); for (let i = 0; i < n; i++) { o[i] = Number(x & 0xffn); x >>= 8n; } return o; };
  const fmod = (a) => { const r = a % P; return r >= 0n ? r : r + P; };
  function powmod(b, e) { let r = 1n; b = fmod(b); while (e > 0n) { if (e & 1n) r = (r * b) % P; b = (b * b) % P; e >>= 1n; } return r; }
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
      const A = fmod(x2 + z2), AA = fmod(A * A), B = fmod(x2 - z2), BB = fmod(B * B), E = fmod(AA - BB);
      const C = fmod(x3 + z3), D = fmod(x3 - z3), DA = fmod(D * A), CB = fmod(C * B);
      x3 = fmod((DA + CB) * (DA + CB)); z3 = fmod(x1 * fmod((DA - CB) * (DA - CB)));
      x2 = fmod(AA * BB); z2 = fmod(E * (AA + 121665n * E));
    }
    if (swap) { [x2, x3] = [x3, x2]; [z2, z3] = [z3, z2]; }
    return bigToLe(fmod(x2 * powmod(z2, P - 2n)));
  }
  const BASE = (() => { const b = new Uint8Array(32); b[0] = 9; return b; })();
  const xKeyPair = () => { const priv = randBytes(32); return { priv, pub: x25519(priv, BASE) }; };

  // --------------------------------------------------------------------------- toy LWE KEM (a stand-in, NOT ML-KEM)
  // One Regev-style encryption per bit of a random 128-bit message; the shared secret is a hash of that message and the ciphertext.
  // Parameters are tiny (q = 97, n = 6) so the demo is fast and readable. Real ML-KEM uses q = 3329 and n = 256 with module structure (FIPS 203, Table 2).
  const TOY = { q: 97, n: 6, m: 16, bits: 128 };
  function kemKeygen() {
    const k = L.regevKeygen(TOY.q, TOY.n, TOY.m);
    return { pk: { q: k.q, n: k.n, m: k.m, A: k.A, b: k.b }, sk: { q: k.q, s: k.s } };
  }
  const bitsOf = (bytes) => { const o = []; for (const by of bytes) for (let i = 7; i >= 0; i--) o.push((by >> i) & 1); return o; };
  const bytesOf = (bitsArr) => { const o = new Uint8Array(bitsArr.length / 8); bitsArr.forEach((b, i) => { if (b) o[i >> 3] |= 1 << (7 - (i & 7)); }); return o; };
  const ctBytes = (ct) => { const o = []; for (const c of ct) { for (const x of c.u) o.push(x); o.push(c.v); } return Uint8Array.from(o); };
  const kemKey = (m, ct) => sha256(concat(utf8("toy-kem v1"), m, ctBytes(ct)));
  function kemEncaps(pk, mOverride) {
    const m = mOverride || randBytes(TOY.bits / 8);
    const ct = bitsOf(m).map((bit) => { const e = L.regevEncrypt(pk, bit); return { u: e.u, v: e.v }; });
    return { ct, ss: kemKey(m, ct), m };
  }
  function kemDecaps(sk, ct) {
    const m = bytesOf(ct.map((c) => L.regevDecrypt(sk, c).bit));
    return kemKey(m, ct);
  }
  const kemSizes = () => ({ pk: TOY.m * TOY.n + TOY.m, ct: TOY.bits * (TOY.n + 1), ss: 32 });     // toy "bytes": one byte per number

  // --------------------------------------------------------------------------- hybrid combiner (the shape of RFC 10024, simplified)
  // In TLS 1.3 with X25519MLKEM768 the client share is ML-KEM encapsulation key || X25519 share, and the shared secret is
  // ML-KEM secret || X25519 secret (64 bytes), which goes into the TLS key schedule. Here HKDF stands in for that schedule.
  function combine(ssKem, ssX, context) {
    const ikm = concat(ssKem, ssX);
    const prk = hkdfExtract(utf8("pqc-demo hybrid v1"), ikm);
    return hkdfExpand(prk, utf8("session key | " + (context || "")), 32);
  }
  function hybridHandshake() {
    const cx = xKeyPair(), ck = kemKeygen();                                   // client: X25519 key pair + toy KEM key pair
    const sx = xKeyPair(), enc = kemEncaps(ck.pk);                             // server: X25519 pair + encapsulates to the client's KEM key
    const serverSsX = x25519(sx.priv, cx.pub), serverSsK = enc.ss;
    const clientSsX = x25519(cx.priv, sx.pub), clientSsK = kemDecaps(ck.sk, enc.ct);
    const ctx = hex(cx.pub) + "|" + hex(sx.pub);
    const keyS = combine(serverSsK, serverSsX, ctx), keyC = combine(clientSsK, clientSsX, ctx);
    return { cx, ck, sx, enc, serverSsX, serverSsK, clientSsX, clientSsK, keyS, keyC, ctx, agree: equalBytes(keyS, keyC) };
  }
  /** What an eavesdropper can compute if one half (or both) of the exchange has been broken. Unknown halves are guessed as zeros. */
  function attackerKey(run, { brokeX, brokeKem }) {
    const known = (b, x) => (b ? x : new Uint8Array(32));
    const guess = combine(known(brokeKem, run.serverSsK), known(brokeX, run.serverSsX), run.ctx);
    return { guess, recovered: equalBytes(guess, run.keyS) };
  }

  // --------------------------------------------------------------------------- real sizes (bytes)
  const KEMS = [
    { id: "x25519", name: "X25519", family: "classical", pk: 32, ct: 32, ss: 32, src: "RFC 7748" },
    { id: "p256", name: "ECDH P-256", family: "classical", pk: 65, ct: 65, ss: 32, src: "SEC 1, uncompressed point" },
    { id: "mlkem512", name: "ML-KEM-512", family: "pq", pk: 800, sk: 1632, ct: 768, ss: 32, cat: 1, src: "FIPS 203, Table 3" },
    { id: "mlkem768", name: "ML-KEM-768", family: "pq", pk: 1184, sk: 2400, ct: 1088, ss: 32, cat: 3, src: "FIPS 203, Table 3" },
    { id: "mlkem1024", name: "ML-KEM-1024", family: "pq", pk: 1568, sk: 3168, ct: 1568, ss: 32, cat: 5, src: "FIPS 203, Table 3" },
    { id: "x25519mlkem768", name: "X25519MLKEM768 (hybrid)", family: "hybrid", pk: 1184 + 32, ct: 1088 + 32, ss: 64, src: "RFC 10024, section 4" },
  ];
  const SIGS = [
    { id: "ed25519", name: "Ed25519", family: "classical", pk: 32, sig: 64, src: "RFC 8032" },
    { id: "ecdsa256", name: "ECDSA P-256", family: "classical", pk: 65, sig: 72, src: "SEC 1; DER signature, up to 72 bytes (raw r||s is 64)" },
    { id: "rsa2048", name: "RSA-2048", family: "classical", pk: 256, sig: 256, src: "PKCS #1; modulus size (a DER public key adds about 38 bytes)" },
    { id: "mldsa44", name: "ML-DSA-44", family: "pq", pk: 1312, sig: 2420, cat: 2, src: "FIPS 204, Table 2" },
    { id: "mldsa65", name: "ML-DSA-65", family: "pq", pk: 1952, sig: 3309, cat: 3, src: "FIPS 204, Table 2" },
    { id: "mldsa87", name: "ML-DSA-87", family: "pq", pk: 2592, sig: 4627, cat: 5, src: "FIPS 204, Table 2" },
    { id: "slh128s", name: "SLH-DSA-128s", family: "pq", pk: 32, sig: 7856, cat: 1, src: "FIPS 205, Table 2" },
    { id: "slh128f", name: "SLH-DSA-128f", family: "pq", pk: 32, sig: 17088, cat: 1, src: "FIPS 205, Table 2" },
    { id: "slh192s", name: "SLH-DSA-192s", family: "pq", pk: 48, sig: 16224, cat: 3, src: "FIPS 205, Table 2" },
    { id: "slh192f", name: "SLH-DSA-192f", family: "pq", pk: 48, sig: 35664, cat: 3, src: "FIPS 205, Table 2" },
    { id: "slh256s", name: "SLH-DSA-256s", family: "pq", pk: 64, sig: 29792, cat: 5, src: "FIPS 205, Table 2" },
    { id: "slh256f", name: "SLH-DSA-256f", family: "pq", pk: 64, sig: 49856, cat: 5, src: "FIPS 205, Table 2" },
  ];
  const byId = (arr, id) => arr.find((x) => x.id === id);
  const sizeRatio = (a, b) => a / b;

  // --------------------------------------------------------------------------- handshake cost model
  const HS_ASSUMPTIONS = {
    clientBase: 300,        // a ClientHello without key shares (SNI, groups, signature algorithms, ALPN...): an assumed round figure
    serverBase: 250,        // ServerHello, EncryptedExtensions, Finished and record headers, without key share, certificates or signature
    certOverhead: 600,      // names, validity, extensions per certificate: an assumed round figure
    sctOverhead: 47,        // SCT fields besides the signature (version, log id, timestamp, extensions length, algorithm, length)
    cvOverhead: 8,          // CertificateVerify header and algorithm/length fields
    keyShareHeader: 4,      // type/length of a key share entry
    mss: 1460,              // TCP payload on a 1500-byte link
    initcwndSegments: 10,   // RFC 6928
    quicDatagram: 1200,     // RFC 9000: client Initial datagrams are padded to at least 1200 bytes
    quicAmplification: 3,   // RFC 9000, section 8.1: three times the data received from an unvalidated address
    quicClientPayload: 1100,// room for ClientHello bytes in one 1200-byte datagram after headers (assumed)
  };
  const LINKS = {
    fibre: { name: "Fast home fibre", kbps: 100000, rtt: 20, mtu: 1500 },
    mobile: { name: "Good mobile", kbps: 10000, rtt: 60, mtu: 1500 },
    poor: { name: "Poor mobile", kbps: 1000, rtt: 150, mtu: 1500 },
    sat: { name: "Satellite", kbps: 20000, rtt: 600, mtu: 1500 },
    iot: { name: "Constrained IoT radio", kbps: 250, rtt: 100, mtu: 127 },
  };
  function tcpFlights(bytes, mss, iw) {                        // slow start: how many round trips to send `bytes`
    const segs = Math.ceil(bytes / mss); let sent = 0, cwnd = iw, rtts = 0;
    while (sent < segs) { sent += cwnd; cwnd *= 2; rtts++; }
    return Math.max(1, rtts);
  }
  /** opts: { kex, leaf, chain, certs (1..3), scts (0..3), plainShare (bool), link } -> bytes and round trips under the simple model above. */
  function handshake(opts) {
    const A = HS_ASSUMPTIONS;
    const kex = byId(KEMS, opts.kex), leaf = byId(SIGS, opts.leaf), chain = byId(SIGS, opts.chain || opts.leaf);
    const certs = Math.max(1, Math.min(3, opts.certs == null ? 2 : opts.certs)), scts = Math.max(0, Math.min(3, opts.scts == null ? 2 : opts.scts));
    const clientShares = kex.pk + A.keyShareHeader + (opts.plainShare && kex.family !== "classical" ? 32 + A.keyShareHeader : 0);
    const clientBytes = A.clientBase + clientShares;
    const serverShare = kex.ct + A.keyShareHeader;
    const certBytes = [];
    certBytes.push(A.certOverhead + leaf.pk + chain.sig);                         // leaf: its key, signed by the intermediate
    for (let i = 1; i < certs; i++) certBytes.push(A.certOverhead + chain.pk + chain.sig);   // each further certificate: its key, signed by its issuer
    const sctBytes = scts * (A.sctOverhead + chain.sig);
    const cvBytes = A.cvOverhead + leaf.sig;
    const serverBytes = A.serverBase + serverShare + certBytes.reduce((a, b) => a + b, 0) + sctBytes + cvBytes;
    const sigCount = certs + scts + 1, pkCount = certs;
    const link = LINKS[opts.link || "fibre"];
    const payload = Math.max(20, link.mtu - 60);
    const tcpRtts = tcpFlights(serverBytes, Math.min(A.mss, payload), A.initcwndSegments);
    const quicDatagrams = Math.max(1, Math.ceil(clientBytes / A.quicClientPayload));
    const quicLimit = A.quicAmplification * A.quicDatagram * quicDatagrams;
    const quicExtra = (serverBytes > quicLimit ? 1 : 0) + (tcpRtts - 1);              // address validation, then the same window limit
    const packets = Math.ceil(serverBytes / payload);
    const timeMs = (tcpRtts - 1) * link.rtt + (serverBytes + clientBytes) * 8 / link.kbps;
    return { clientBytes, serverBytes, certBytes, sctBytes, cvBytes, sigCount, pkCount, tcpRtts, extraRttsTcp: tcpRtts - 1, quicLimit, quicExtraRtts: quicExtra, quicDatagrams,
             clientFitsOnePacket: clientBytes + 60 <= link.mtu, packets, timeMs, linkName: link.name, initcwnd: A.initcwndSegments * Math.min(A.mss, payload) };
  }

  // --------------------------------------------------------------------------- Mosca's inequality
  /** x = how long the data must stay secret, y = how long migration takes, z = years until a cryptographically relevant quantum computer. Exposed when x + y > z. */
  function mosca({ shelf, migration, crqcYear, nowYear }) {
    const now = nowYear == null ? 2026 : nowYear, z = crqcYear - now, need = shelf + migration;
    const margin = z - need, startBy = crqcYear - need;
    let status = "safe";
    if (margin < 0) status = "exposed"; else if (margin <= 3) status = "tight";
    return { z, need, margin, startBy, status, lateBy: Math.max(0, Math.round((now - startBy) * 10) / 10) };
  }
  const MOSCA_CLASSES = [
    { id: "session", name: "Web session cookies and tokens", kind: "kex", shelf: 0.1, migration: 1, note: "Short-lived. Little to harvest, but the key exchange is the same one that protects longer-lived data." },
    { id: "cards", name: "Payment card data in transit", kind: "kex", shelf: 3, migration: 2, note: "Card numbers expire, but names, addresses and account links last longer." },
    { id: "pii", name: "Customer personal data", kind: "kex", shelf: 10, migration: 3, note: "Records you keep for a decade are still personal a decade later." },
    { id: "health", name: "Health records", kind: "kex", shelf: 30, migration: 4, note: "A diagnosis doesn't expire. Many hospital systems are slow to change." },
    { id: "ip", name: "Trade secrets and designs", kind: "kex", shelf: 20, migration: 3, note: "Valuable for as long as the product or process is." },
    { id: "state", name: "Diplomatic or defence traffic", kind: "kex", shelf: 50, migration: 5, note: "The longest shelf lives of all: why governments move first." },
    { id: "contracts", name: "Signed contracts in an archive", kind: "sig", shelf: 30, migration: 2, note: "A forger needs the quantum computer only later, but the signature has to still be believed in 30 years: re-sign or timestamp." },
    { id: "firmware", name: "Firmware signing keys for devices in the field", kind: "sig", shelf: 15, migration: 6, note: "The device's verifier may be in read-only memory: it has to be right from the factory." },
  ];

  // --------------------------------------------------------------------------- a made-up estate for the inventory triage
  const MIG_YEARS = { 1: 0.5, 2: 1.5, 3: 3, 4: 5, 5: 8 };
  const EXPOSURE_W = { internet: 1, partner: 0.75, internal: 0.4 };
  const ESTATE = [
    { id: "web", name: "Public website and API (TLS at a CDN)", kind: "kex", life: 5, exposure: "internet", change: 1, algs: "TLS 1.3, X25519, ECDSA P-256", why: "A toggle at the CDN. Customer data crosses the internet, and recording it is easy." },
    { id: "vpn", name: "Site-to-site VPN between factories", kind: "kex", life: 15, exposure: "internet", change: 3, algs: "IPsec IKEv2, ECDH P-256", why: "Carries designs for 15 years' value over the public internet, on appliances that need new firmware." },
    { id: "ssh", name: "Admin SSH to servers", kind: "kex", life: 1, exposure: "internal", change: 1, algs: "OpenSSH, curve25519", why: "Short-lived sessions on an internal network, and OpenSSH 10 already uses a hybrid by default." },
    { id: "backup", name: "Off-site encrypted backups (RSA-wrapped keys)", kind: "kex", life: 30, exposure: "partner", change: 3, algs: "AES-256, RSA-3072 key wrap", why: "The data must stay secret for decades, and a stolen copy can be kept until it can be opened. Re-wrap the keys." },
    { id: "hr", name: "HR portal (vendor-run SaaS)", kind: "kex", life: 25, exposure: "internet", change: 5, algs: "TLS (vendor's choice)", why: "Long-lived personal data, but you can only ask the vendor. Put it in the contract." },
    { id: "sso", name: "Single sign-on tokens", kind: "sig", life: 0.1, exposure: "internet", change: 2, algs: "JWT, RS256", why: "Tokens last an hour, so there's nothing to harvest. Signing keys must be swapped before forgery becomes possible." },
    { id: "code", name: "Software release signing", kind: "sig", life: 10, exposure: "internet", change: 4, algs: "ECDSA P-256 in a CI HSM", why: "Products are supported for years, and the HSM and every verifier have to change." },
    { id: "iot", name: "Sensor firmware (boot ROM verifies the signature)", kind: "sig", life: 15, exposure: "internet", change: 5, algs: "ECDSA in mask ROM", why: "Can't be changed after manufacture. Fix it for the next hardware revision and plan for replacement." },
    { id: "ca", name: "Internal CA (20-year root)", kind: "sig", life: 20, exposure: "internal", change: 3, algs: "RSA-3072 root", why: "A long-lived root is a long-lived promise. Plan a new hierarchy." },
    { id: "docs", name: "Signed contract archive", kind: "sig", life: 30, exposure: "internal", change: 2, algs: "RSA-2048 PDF signatures", why: "Add timestamps or re-sign with a post-quantum scheme before the old signatures stop being trusted." },
    { id: "email", name: "S/MIME email", kind: "kex", life: 10, exposure: "internet", change: 4, algs: "RSA key transport", why: "Stored mail can be recorded and read later, and every mail client has to follow." },
    { id: "pos", name: "Legacy payment terminals", kind: "kex", life: 7, exposure: "partner", change: 5, algs: "TLS 1.2, RSA", why: "Old firmware, certification cycles and a partner network: the longest lead time." },
  ];
  function triageScore(s) {
    const mig = MIG_YEARS[s.change], w = s.kind === "sig" ? 0.6 : EXPOSURE_W[s.exposure];
    return +(((s.life + mig) * w).toFixed(2));
  }
  function triageOrder() {
    return ESTATE.map((s) => ({ ...s, score: triageScore(s), mig: MIG_YEARS[s.change] })).sort((a, b) => b.score - a.score || b.change - a.change || (a.id < b.id ? -1 : 1));
  }
  /** Sum of how far each item sits from the model's rank (0 = identical order). */
  function orderDistance(userIds) {
    const model = triageOrder().map((s) => s.id);
    let d = 0; model.forEach((id, i) => { d += Math.abs(i - userIds.indexOf(id)); });
    return { distance: d, max: Math.floor(model.length * model.length / 2), same: d === 0 };
  }

  // --------------------------------------------------------------------------- crypto-agility quiz
  const AGILITY_CLASSES = [
    { id: "config", label: "A configuration change" },
    { id: "code", label: "A code change" },
    { id: "data", label: "A data or protocol change" },
    { id: "hw", label: "New hardware or a vendor" },
  ];
  const AGILITY = [
    { id: "nginx", snippet: "ssl_ecdh_curve X25519;", answer: "config", why: "A list of groups in a config file. With a library that supports the new group, you change the line and reload. Check the library version first." },
    { id: "java", snippet: 'Cipher.getInstance("RSA/ECB/PKCS1Padding");   // 41 call sites', answer: "code", why: "The algorithm is spelled out in code in 41 places. Wrap it behind one interface first; the swap comes after." },
    { id: "column", snippet: "CREATE TABLE docs (id INT, signature VARCHAR(128));", answer: "data", why: "A post-quantum signature is thousands of bytes. The column, the API and every consumer of it need to change." },
    { id: "rom", snippet: "// boot ROM, mask-programmed 2024\nif (!ecdsa_verify(rom_pubkey, image, sig)) halt();", answer: "hw", why: "The verifier is in read-only memory. No update reaches it: the fix is the next hardware revision." },
    { id: "blob", snippet: '{ "alg": "ecdh-p256", "v": 3, "ct": "..." }   // algorithm stored beside every blob', answer: "config", why: "The algorithm and a version travel with the data, so readers can handle old and new side by side. Adding a new alg is mostly an addition." },
    { id: "field", snippet: "struct Hello { uint8 type; uint8 pubkey[65]; uint8 mac[32]; };", answer: "data", why: "A fixed 65-byte key field. A 1,184-byte key needs a new message layout, and every peer must understand it." },
    { id: "hsm", snippet: "HSM firmware 4.2: RSA, ECDSA, AES. Support contract ends 2027.", answer: "hw", why: "Only the vendor can add algorithms, and this one has no roadmap. Ask now, and plan for a replacement." },
    { id: "jwt", snippet: 'JWT.verify(token, key, { algorithms: ["ES256"] });', answer: "code", why: "Pinning the algorithm is right (see the earlier talk), but supporting a new one needs library and key-format support: a code change plus a rollout." },
  ];

  // --------------------------------------------------------------------------- deadlines and the roadmap builder
  const REGIMES = {
    usfed: { id: "usfed", label: "US federal: high-impact systems and high value assets", plan: null, kex: 2030, sigs: 2031, all: 2035,
      rows: ["Key establishment: post-quantum by 31 December 2030", "Digital signatures: post-quantum by 31 December 2031", "TLS 1.3 supported by 2 January 2030", "NIST: quantum-vulnerable public-key crypto deprecated after 2030, disallowed after 2035"],
      src: "NIST IR 8547 (final, 27 October 2026), quoting EO 14412 and OMB M-26-15" },
    usother: { id: "usother", label: "US federal: other systems", plan: null, kex: 2030, sigs: 2035, all: 2035,
      rows: ["Same priority for systems with highly sensitive data, or data still sensitive in 2030", "Deprecated after 2030; disallowed under NIST standards after 2035", "NSM-10: complete the federal migration by 2035"],
      src: "NIST IR 8547 (final, 27 October 2026)" },
    uk: { id: "uk", label: "UK: an organisation following the NCSC", plan: 2028, kex: 2031, sigs: 2031, all: 2035,
      rows: ["By 2028: set goals, run a discovery exercise, draft a migration plan", "By 2031: do the highest-priority migrations and refine the roadmap", "By 2035: complete migration of all systems, services and products"],
      src: "NCSC, PQC migration timelines (20 March 2025)" },
    eu: { id: "eu", label: "EU: member states and critical sectors", plan: 2026, kex: 2030, sigs: 2030, all: 2035,
      rows: ["By 31 December 2026: first steps done, national roadmaps, pilots begun", "By 31 December 2030: high-risk use cases fully migrated; quantum-safe updates on by default", "By 31 December 2035: medium-risk done; low-risk as far as feasible"],
      src: "EU coordinated implementation roadmap (NIS Cooperation Group PQC workstream, June 2025)" },
    nss: { id: "nss", label: "Supplying US national security systems (CNSA 2.0)", plan: null, kex: 2033, sigs: 2030, all: 2035,
      rows: ["Software and firmware signing: exclusive use by 2030", "Web browsers, servers and cloud services: by 2033", "All national security systems: by 2035"],
      src: "NSA CNSA 2.0 FAQ, as reported (the PDF wouldn't download here: check NSA's own copy)" },
    free: { id: "free", label: "A private company with no mandate", plan: 2028, kex: 2030, sigs: 2032, all: 2035,
      rows: ["No deadline applies to you directly: borrow one", "Google and Cloudflare each say they aim to be fully post-quantum by 2029 (company targets, not rules)", "Customers, regulators and insurers may ask for a date: have one"],
      src: "Google Cloud (11 August 2026) and Cloudflare (7 April 2026) roadmaps; the milestone years here are an assumption" },
  };
  const PHASES = [
    { id: "discover", name: "Discover: inventory every use of public-key crypto", milestone: "plan", owner: "security", defaultEnd: 2027 },
    { id: "plan", name: "Prioritise and write the plan", milestone: "plan", owner: "security", defaultEnd: 2027 },
    { id: "pilot", name: "Pilot hybrid key exchange on non-critical systems", milestone: "kex", owner: "platform", defaultEnd: 2028 },
    { id: "kex", name: "Roll out hybrid key exchange (TLS, SSH, VPN)", milestone: "kex", owner: "platform", defaultEnd: 2029 },
    { id: "vendors", name: "Vendors and contracts: roadmaps and clauses", milestone: "kex", owner: "vendors", defaultEnd: 2028 },
    { id: "certs", name: "Certificates, code signing and firmware roots", milestone: "sigs", owner: "pki", defaultEnd: 2031 },
    { id: "retire", name: "Retire classical-only algorithms", milestone: "all", owner: "apps", defaultEnd: 2034 },
  ];
  const OWNERS = [{ id: "security", label: "Security team" }, { id: "platform", label: "Platform team" }, { id: "vendors", label: "Vendor management" }, { id: "pki", label: "PKI team" }, { id: "apps", label: "App teams" }];
  function roadmapCheck(regimeId, ends, custom) {
    const reg = regimeId === "custom" ? { plan: custom.plan, kex: custom.kex, sigs: custom.sigs, all: custom.all } : REGIMES[regimeId];
    return PHASES.map((p) => {
      const limit = reg[p.milestone], end = ends[p.id];
      return { id: p.id, limit, end, ok: limit == null ? true : end <= limit, noLimit: limit == null };
    });
  }

  // --------------------------------------------------------------------------- what the estimates say (and under what assumptions)
  const ESTIMATES = [
    { id: "ge2019", year: "2019", who: "Gidney and Ekerå (as restated in 2025)", target: "rsa", qubits: "20 million noisy qubits", time: "8 hours", assumptions: "Surface code: the benchmark the 2025 paper revises.", src: "arXiv:2505.15917 abstract", href: "https://arxiv.org/abs/2505.15917" },
    { id: "g2025", year: "May 2025", who: "Craig Gidney", target: "rsa", qubits: "under 1 million noisy qubits", time: "under a week", assumptions: "0.1% gate error, 1 µs cycle, 10 µs reaction time, square grid.", src: "arXiv:2505.15917", href: "https://arxiv.org/abs/2505.15917" },
    { id: "pinnacle", year: "Feb 2026", who: "Webster et al. (Iceberg Quantum)", target: "rsa", qubits: "under 100,000 physical qubits", time: "depends on the configuration", assumptions: "Quantum LDPC codes, same error and timing figures; hardware not built.", src: "arXiv:2602.11457", href: "https://arxiv.org/abs/2602.11457" },
    { id: "google", year: "Mar 2026", who: "Babbush et al. (Google Quantum AI)", target: "ecc", qubits: "under 1,450 logical; under half a million physical", time: "minutes", assumptions: "256-bit curve (secp256k1), superconducting, 0.1% error; a zero-knowledge proof backs the numbers.", src: "arXiv:2603.28846", href: "https://arxiv.org/abs/2603.28846" },
    { id: "alice", year: "Oct 2026", who: "Pappalardo et al. (Alice & Bob)", target: "rsa", qubits: "about 23,000 cat qubits", time: "3.14 days", assumptions: "No bit-flips assumed; about 45,000 qubits if relaxed.", src: "IACR ePrint 2026/2665", href: "https://eprint.iacr.org/2026/2665" },
  ];

  // --------------------------------------------------------------------------- hype and reality
  const CLAIMS = [
    { id: "aes", claim: "AES-128 is broken by quantum computers.", verdict: "false", why: "Grover's algorithm gives a quadratic speed-up at best, and NIST's IR 8547 says every approved symmetric primitive with at least 128 bits of classical strength is believed to meet at least Category 1, the lowest post-quantum level. Public-key crypto (RSA, ECDH, ECDSA) is the target." },
    { id: "harvest", claim: "Traffic recorded today with a classical key exchange could be read once a large enough quantum computer exists.", verdict: "true", why: "That's harvest now, decrypt later, the threat IR 8547 names as a main reason the transition is urgent. It only matters if the data will still be sensitive then." },
    { id: "rsa4096", claim: "Switching to RSA-4096 fixes the quantum problem.", verdict: "false", why: "Shor's algorithm factors in polynomial time, so a longer key only makes the attacker's job somewhat bigger. The fix is a different kind of algorithm." },
    { id: "hybrid", claim: "Hybrid key exchange is mandatory now that ML-KEM is a standard.", verdict: "depends", why: "No. NIST says approved hybrids are allowed as long as one component is approved, and calls them typically temporary. They are the common deployment today because they hedge against a flaw in the new algorithm (SIKE is the cautionary tale). Rules differ by sector and country." },
    { id: "wait", claim: "We should wait for better signature algorithms before starting.", verdict: "false", why: "Start with the inventory and with key exchange, which doesn't depend on signature choices. IR 8547 says FN-DSA is still under development, and Cloudflare argues ML-DSA will have to do for the first wave. Waiting leaves long-lead items (firmware, vendors) unstarted." },
    { id: "gov", claim: "Post-quantum cryptography is only a worry for governments.", verdict: "false", why: "About 70% of browser traffic to Cloudflare already uses hybrid ML-KEM (Cloudflare, 29 September 2026), and Apple's OS 26 enables it by default in URLSession and Network. Your own traffic may already be protected, one side at a time." },
    { id: "date", claim: "Experts agree on when a cryptographically relevant quantum computer will exist.", verdict: "false", why: "They don't. The Global Risk Institute survey of 26 experts gives ranges (28-49% within 10 years, 51-70% within 15), and resource estimates have fallen several times since 2019. Plan around a range and a shelf-life, not one date." },
    { id: "sigs", claim: "Certificates and signatures are the easy part; key exchange is the hard part.", verdict: "false", why: "The other way round. Hybrid key exchange fits inside a handshake and is already common. Signatures are bigger, sit in certificates, firmware and archives, and need browsers, CAs and devices to move together." },
  ];

  // --------------------------------------------------------------------------- the title terminal
  // --------------------------------------------------------------------------- the toy LWE puzzle with adjustable noise
  const modq = (a) => ((a % TOY.q) + TOY.q) % TOY.q;
  function lweKeygen(E) {
    const { q, n, m } = TOY;
    const sec = Array.from({ length: n }, () => L.randInt(q));
    const A = Array.from({ length: m }, () => Array.from({ length: n }, () => L.randInt(q)));
    const e = A.map(() => (E ? L.randInt(2 * E + 1) - E : 0));
    const b = A.map((row, i) => modq(row.reduce((acc, x, j) => acc + x * sec[j], 0) + e[i]));
    return { q, n, m, s: sec, A, b, e, E };
  }
  function lweEncrypt(k, bit) {
    const S = []; for (let i = 0; i < k.m; i++) if (L.randInt(2)) S.push(i);
    const u = Array.from({ length: k.n }, (_, j) => modq(S.reduce((acc, i) => acc + k.A[i][j], 0)));
    const v = modq(S.reduce((acc, i) => acc + k.b[i], 0) + bit * Math.floor(k.q / 2));
    return { S, u, v };
  }
  function lweDecrypt(k, ct) {
    const r = modq(ct.v - ct.u.reduce((acc, x, j) => acc + x * k.s[j], 0)), bit = r > k.q / 4 && r < (3 * k.q) / 4 ? 1 : 0;
    let noise = r - bit * Math.floor(k.q / 2); if (noise > k.q / 2) noise -= k.q; if (noise < -k.q / 2) noise += k.q;
    return { r, bit, noise };
  }
  function lweFailRate(E, trials) {
    let fails = 0; const T = trials || 300;
    for (let i = 0; i < T; i++) { const k = lweKeygen(E), bit = L.randInt(2); if (lweDecrypt(k, lweEncrypt(k, bit)).bit !== bit) fails++; }
    return fails / T;
  }
  const powq = (a, e) => { let r = 1; a = modq(a); while (e > 0) { if (e & 1) r = (r * a) % TOY.q; a = (a * a) % TOY.q; e >>= 1; } return r; };
  /** Gaussian elimination mod q on the public equations: with no noise this recovers the secret; with noise the equations contradict each other. */
  function solveLinear(k) {
    const { q, n } = k, M = k.A.map((row, i) => [...row, k.b[i]]);
    let r = 0; const pivCols = [];
    for (let c = 0; c < n && r < M.length; c++) {
      let p = -1; for (let i = r; i < M.length; i++) if (M[i][c] % q !== 0) { p = i; break; }
      if (p < 0) continue;
      [M[r], M[p]] = [M[p], M[r]];
      const inv = powq(M[r][c], q - 2); M[r] = M[r].map((x) => modq(x * inv));
      for (let i = 0; i < M.length; i++) if (i !== r && M[i][c] % q !== 0) { const f = M[i][c]; M[i] = M[i].map((x, j) => modq(x - f * M[r][j])); }
      pivCols.push(c); r++;
    }
    let consistent = true; for (let i = r; i < M.length; i++) if (M[i][n] % q !== 0) consistent = false;
    const sol = consistent && r === n ? pivCols.map((c, i) => M[i][n]) : null;
    return { consistent, rank: r, s: sol, equations: M.length, unknowns: n };
  }

  // --------------------------------------------------------------------------- what a quantum computer does to each primitive
  const PRIMS = [
    { id: "rsa", name: "RSA", group: "public-key", verdict: "shor", why: "Shor's algorithm factors in polynomial time on a large, error-corrected quantum computer. A longer key only makes the attacker's job somewhat bigger.", next: "ML-KEM for key establishment; ML-DSA or SLH-DSA for signatures." },
    { id: "dh", name: "Diffie-Hellman (finite field)", group: "public-key", verdict: "shor", why: "The discrete logarithm problem falls to Shor's algorithm in the same way.", next: "ML-KEM (in a hybrid today)." },
    { id: "ecdh", name: "ECDH: X25519, P-256", group: "public-key", verdict: "shor", why: "The elliptic-curve discrete logarithm is also solved by a variant of Shor's algorithm. Smaller keys mean smaller quantum computers, not safety.", next: "ML-KEM, combined with X25519 in today's hybrid (X25519MLKEM768)." },
    { id: "ecdsa", name: "ECDSA", group: "public-key", verdict: "shor", why: "Signatures built on the elliptic-curve discrete log are forgeable once the key can be recovered from the public key.", next: "ML-DSA, SLH-DSA; FN-DSA is still under development (IR 8547, October 2026)." },
    { id: "eddsa", name: "EdDSA: Ed25519", group: "public-key", verdict: "shor", why: "Same family of problem, same fate. NIST's IR 8547 lists EdDSA as deprecated after 2030 and disallowed after 2035.", next: "ML-DSA, SLH-DSA." },
    { id: "aes128", name: "AES-128", group: "symmetric", verdict: "grover", why: "Grover's algorithm searches in about the square root of the time, in principle. It parallelises poorly and each step is expensive, and NIST's IR 8547 says approved symmetric primitives at 128 bits or more are believed to meet at least Category 1 (the lowest post-quantum level), the level of AES-128 key search.", next: "Keep it. Move to AES-256 where a bigger margin is cheap or required." },
    { id: "aes256", name: "AES-256", group: "symmetric", verdict: "ok", why: "Category 5 in NIST's scheme: a large margin even after Grover's speed-up.", next: "Nothing to change." },
    { id: "sha256", name: "SHA-256", group: "hash", verdict: "ok", why: "NIST's categories treat collision search on a 256-bit hash as Category 2. Preimage attacks get Grover's quadratic speed-up at most.", next: "Nothing to change." },
    { id: "sha3", name: "SHA3-384", group: "hash", verdict: "ok", why: "Collision search on a 384-bit hash is Category 4 (IR 8547, Table 1).", next: "Nothing to change." },
    { id: "hmac", name: "HMAC-SHA-256", group: "mac", verdict: "ok", why: "Built from a hash: the same reasoning, and a 256-bit key.", next: "Nothing to change." },
    { id: "chacha", name: "ChaCha20-Poly1305", group: "symmetric", verdict: "ok", why: "A 256-bit key, so the same Grover argument as AES-256. NIST's approved list doesn't include ChaCha20, so this is the general argument, not a NIST category.", next: "Nothing to change." },
  ];

  // --------------------------------------------------------------------------- harvest now, decrypt later versus forge later
  const HNDL_ITEMS = [
    { id: "tls", name: "A TLS session with customer records", kind: "conf", year: 2026, hold: 10 },
    { id: "vpn", name: "VPN traffic carrying product designs", kind: "conf", year: 2027, hold: 15 },
    { id: "login", name: "A web login session", kind: "conf", year: 2026, hold: 0.01 },
    { id: "update", name: "A software update signed now, trusted by devices for 15 years", kind: "sig", year: 2026, trust: 15 },
    { id: "cert", name: "A TLS certificate valid for 200 days", kind: "sig", year: 2026, trust: 0.55 },
    { id: "contract", name: "A contract signed now and relied on for 30 years", kind: "sig", year: 2026, trust: 30, archive: true },
  ];
  function hndl(item, o) {
    if (item.kind === "conf") {
      const classical = item.year < o.kexYear, stillSensitive = item.year + item.hold > o.crqc;
      if (!classical) return { exposed: false, why: "Recorded after your key exchange became post-quantum: nothing useful to harvest." };
      if (!stillSensitive) return { exposed: false, why: "Recorded with a classical key exchange, but no longer sensitive by then." };
      return { exposed: true, why: "Recorded now, still sensitive when the computer arrives. The attacker needs it only later." };
    }
    const trusted = item.year + item.trust > o.crqc;
    if (!trusted) return { exposed: false, why: "Expires before the computer exists: nothing to forge." };
    if (item.archive) return o.resign ? { exposed: false, why: "Re-signed or timestamped before then." } : { exposed: true, why: "Still relied on after the computer exists: the classical signature could be forged or back-dated." };
    return o.sigYear <= o.crqc ? { exposed: false, why: "Keys and verifiers replaced before the computer exists." } : { exposed: true, why: "Verifiers still trust classical keys when the computer arrives. No recording needed." };
  }

  // --------------------------------------------------------------------------- long-lived signatures: firmware and roots of trust
  function signingPlan({ lifetime, ship, crqcYear, updatable }) {
    const now = NOW_YEAR, fieldEnd = now + ship + lifetime, window = Math.max(0, fieldEnd - crqcYear), yrs = window + " year" + (window === 1 ? "" : "s");
    const out = { fieldEnd, window, level: "ok", verdict: "", advice: [] };
    if (window === 0) {
      out.verdict = "This product retires before the earliest date you chose: a classical verifier can do for this generation.";
      out.advice = ["Still record the algorithm in the design so the next generation can change it.", "Re-check the date: lifetimes often stretch."];
    } else if (updatable === "yes") {
      out.level = "y"; out.verdict = "In the field for " + yrs + " after the earliest date, but you can still change it.";
      out.advice = ["Build the update path now and test it on real devices.", "Plan dual signatures (classical plus post-quantum) for the changeover."];
    } else if (updatable === "partly") {
      out.level = "y"; out.verdict = "In the field for " + yrs + " after the earliest date, with a verifier you can only partly change.";
      out.advice = ["Find the fixed stage: the first-stage loader is the one that matters.", "Ship a verifier that accepts a post-quantum signature now, even if you sign classically at first."];
    } else {
      out.level = "bad"; out.verdict = "Exposed: the verifier you ship now has to survive " + yrs + " past the earliest date.";
      out.advice = ["Ship a post-quantum-capable verifier in this hardware revision. CNSA 2.0 names LMS and XMSS (NIST SP 800-208) for firmware: mind the state rules.", "If that isn't possible, write the replacement date into the support policy."];
    }
    return out;
  }
  const SIG_USES = {
    tls: { label: "TLS certificates", pick: "ML-DSA-44 or -65 today; watch Merkle Tree Certificates", why: "Handshake size is the cost (slide 13). Browsers and CAs move together, so follow their programmes, not your own preference." },
    firmware: { label: "Firmware and boot signing", pick: "LMS or XMSS (SP 800-208) for CNSA 2.0; ML-DSA where state handling is a risk", why: "Verification is cheap and keys are few, but stateful schemes need strict control of the signing state." },
    docs: { label: "Long-lived documents", pick: "Timestamp now; re-sign with ML-DSA or SLH-DSA", why: "The risk is a forged, back-dated signature decades on. A trusted timestamp and a later re-signature help." },
    iot: { label: "Constrained devices", pick: "Ask the vendor; SLH-DSA is conservative but very large", why: "Bytes, memory and CPU are the limits. A 7,856-byte signature (SLH-DSA-128s) may not fit a radio frame budget." },
  };

  const NOW_YEAR = 2026, TERM_MIGRATION = 5;
  function heroLine(raw) {
    const t = String(raw).trim(), low = t.toLowerCase().replace(/[_\s]+/g, " ");
    const num = /^-?\d+(\.\d+)?$/.test(t) ? Number(t) : null;
    if (t === "") return { kind: "empty", note: "# type a number of years your data must stay secret (try 15), or a word like mosca, shor, harvest." };
    const eggs = {
      "mosca": "# Michele Mosca's inequality: shelf life + migration time > time until a quantum computer, and you are already late. Slide 7 lets you play with it.",
      "x + y > z": "# the inequality, in its usual letters. Different papers use different letters for the three terms; the idea is the same.",
      "x+y>z": "# the inequality, in its usual letters. Different papers use different letters for the three terms; the idea is the same.",
      "shor": "# Peter Shor, 1994: a quantum algorithm that factors and takes discrete logs in polynomial time. The reason RSA and elliptic curves are on the list.",
      "grover": "# Lov Grover, 1996: a quantum search that is quadratically faster, not exponentially. Why symmetric keys and hashes stay, with 128 bits or more.",
      "harvest": "# \"harvest now, decrypt later\": the phrase NIST's IR 8547 uses for recording traffic today to open it later.",
      "harvest now decrypt later": "# \"harvest now, decrypt later\": the phrase NIST's IR 8547 uses for recording traffic today to open it later.",
      "hndl": "# HNDL: harvest now, decrypt later. It's a confidentiality threat; signatures face a different one (slide 5).",
      "q-day": "# Q-Day, \"Y2Q\" and similar names mean the day a cryptographically relevant quantum computer exists. Nobody knows the date, which is the point of this talk.",
      "y2q": "# Y2Q: like Y2K, except nobody has a date. The planning problem is a range and a lead time.",
      "2030": "# 2030: NIST deprecates quantum-vulnerable public-key crypto after it, and US federal high-impact systems must have post-quantum key establishment by 31 December 2030.",
      "2031": "# 2031: the UK NCSC's date for the highest-priority migrations, and the US federal date for post-quantum signatures on the most sensitive systems.",
      "2035": "# 2035: where NIST disallows quantum-vulnerable public-key crypto, and where the UK, the EU and NSM-10 all aim to be finished.",
      "2029": "# 2029: Google and Cloudflare each say they aim to be fully post-quantum by then. Company targets, not rules.",
      "sike": "# SIKE, an isogeny scheme, was broken in 2022 by an ordinary computer: about an hour at first, about ten minutes in the final paper. Why hybrids exist.",
      "kyber": "# CRYSTALS-Kyber became ML-KEM in FIPS 203 (13 August 2024). The final standard changed details, so early Kyber and ML-KEM are not compatible.",
      "ml-kem": "# ML-KEM, FIPS 203, from CRYSTALS-Kyber. n = 256, q = 3329, shared secrets of 32 bytes. Slide 11 has the sizes.",
      "dilithium": "# CRYSTALS-Dilithium became ML-DSA in FIPS 204. Signatures run from 2,420 to 4,627 bytes.",
      "sphincs": "# SPHINCS+ became SLH-DSA in FIPS 205: hash-based, conservative, and the signatures are big (7,856 to 49,856 bytes).",
      "falcon": "# Falcon is becoming FN-DSA. NIST's IR 8547 (October 2026) still says a FIPS for it is under development.",
      "hqc": "# HQC, selected in 2025 as a backup to ML-KEM. IR 8547 says its FIPS is under development.",
      "3329": "# 3329: the prime modulus q in every ML-KEM parameter set (FIPS 203, Table 2).",
      "256": "# 256: the polynomial degree n in ML-KEM and ML-DSA, and the number of bits in a lot of other things.",
      "1216": "# 1,216 bytes: the client's X25519MLKEM768 key share (1,184 for ML-KEM plus 32 for X25519), RFC 10024.",
      "4588": "# 4588 (0x11EC): the TLS code point for X25519MLKEM768 in RFC 10024.",
      "0x11ec": "# 0x11EC: the TLS code point for X25519MLKEM768 in RFC 10024.",
      "rsa": "# RSA, 1977: fine against ordinary computers for a long while yet. Shor's algorithm is the problem, not today's attackers.",
      "aes": "# AES-128 is believed to meet NIST's lowest post-quantum category (IR 8547). Symmetric crypto isn't the target.",
      "hello": "# hello to you too. Try a number of years, or mosca, shor, harvest, 2035.",
    };
    if (eggs[low]) return { kind: "egg", note: eggs[low] };
    if (num != null && num < 0) return { kind: "egg", note: "# a negative shelf life means the secret was already public. Nothing to harvest; a bigger problem." };
    if (num === 0) return { kind: "egg", note: "# zero years: nothing to harvest and nothing to protect. Delete the data and the problem goes away." };
    if (num != null && num > 150) return { kind: "egg", note: "# beyond a century. Plan for that and you're planning for more than quantum computers." };
    if (num != null) {
      const total = num + TERM_MIGRATION, year = NOW_YEAR + total;
      const horizon = total <= 10 ? "Global Risk Institute survey (2025 edition, 26 experts): a computer that could break today's public-key crypto within 10 years is \"quite possible\": 28-49%."
        : total <= 15 ? "Global Risk Institute survey (2025 edition, 26 experts): within 15 years is \"likely\": 51-70%."
        : "That's beyond the survey's 15-year horizon. Opinion and resource estimates will move; plan around a range.";
      const egg = num === 1 ? "# one year: short, but the key exchange protecting it may also protect longer-lived secrets sent the same way." : num === 10 ? "# ten years: one of the two horizons the Global Risk Institute reports on." : num === 30 ? "# thirty years: health records, deeds, designs. Exactly the data this talk is about." : null;
      return { kind: "calc", shelf: num, total, year, horizon, note: egg || "# a ballpark, not a forecast: slide 7 lets you move every number." };
    }
    return { kind: "unknown", note: "# not sure what that is. Try a number of years (1, 15, 30), or a word: mosca, shor, grover, harvest, sike, kyber, 2035." };
  }

  const api = {
    x25519, xKeyPair, BASE, TOY, kemKeygen, kemEncaps, kemDecaps, kemSizes, combine, hybridHandshake, attackerKey,
    KEMS, SIGS, byId, sizeRatio, lweKeygen, lweEncrypt, lweDecrypt, lweFailRate, solveLinear, PRIMS, HNDL_ITEMS, hndl, signingPlan, SIG_USES, HS_ASSUMPTIONS, LINKS, handshake, tcpFlights, mosca, MOSCA_CLASSES, MIG_YEARS, EXPOSURE_W, ESTATE, triageScore, triageOrder, orderDistance,
    AGILITY, AGILITY_CLASSES, REGIMES, PHASES, OWNERS, roadmapCheck, ESTIMATES, CLAIMS, heroLine, NOW_YEAR, TERM_MIGRATION, bitsOf, bytesOf,
  };
  root.Pqc = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof window !== "undefined" ? window : globalThis);
