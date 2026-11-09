/* app.js - the live demos for "Using Crypto Correctly in Code".
   The crypto here is the teaching code in ../../shared/crypto.js: real AES-GCM, HKDF and HMAC-SHA256, written to be read.
   Never use it to protect real data: use Web Crypto or a vetted library. Everything runs in your browser; nothing is sent anywhere.
   The timings, hashes and logs on some slides are simulated or invented, and say so on the slide. */
(function () {
  "use strict";
  const L = window.Lab;

  // --------------------------------------------------------------------------- helpers
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const sp = (cls, s) => `<span class="${cls}">${esc(s)}</span>`;
  const click = (id, fn) => $(id).addEventListener("click", fn);
  const short = (h, n) => (h.length > n ? h.slice(0, n) + "…" : h);
  const pretty = (b) => Array.from(b, (x) => (x >= 32 && x < 127 ? String.fromCharCode(x) : "·")).join("");
  function store(key, val) {
    try { if (val === undefined) return localStorage.getItem(key); localStorage.setItem(key, val); } catch (e) {}
    return null;
  }
  const segPick = (id, attr, fn) => {
    const box = $(id);
    box.addEventListener("click", (e) => {
      const b = e.target.closest("button[" + attr + "]"); if (!b) return;
      for (const x of box.querySelectorAll("button")) x.setAttribute("aria-pressed", String(x === b));
      fn(b.getAttribute(attr));
    });
  };
  const fmtBig = (x) => (x < 1e15 ? Math.round(x).toLocaleString("en-US") : x.toExponential(1).replace("e+", "×10^"));

  // --------------------------------------------------------------------------- title: seal a message
  const HERO_KEY = L.randBytes(32);
  function hero() {
    const el = $("hero-in"), v = el.value;
    el.style.width = Math.min(26, Math.max(8, v.length + 1)) + "ch";
    const nonce = L.randBytes(12), { ct, tag } = L.gcmEncrypt(HERO_KEY, nonce, L.utf8(v));
    let back;
    try { back = L.text(L.gcmDecrypt(HERO_KEY, nonce, ct, tag)); } catch (e) { back = "(rejected)"; }
    $("hero-out").innerHTML = `${sp("k", "nonce:")} ${esc(L.hex(nonce))}<br>${sp("k", "data: ")} ${esc(short(L.hex(ct), 40) || "(empty)")}<br>${sp("k", "tag:  ")} ${esc(L.hex(tag))}<br>${sp("k", "open():")} ${sp("ok", JSON.stringify(back))}`;
    const t = v.trim().toLowerCase();
    let note = "# a fresh random nonce every time: same message, different bytes. The tag is what rejects tampering.";
    if (t === "hello world") note = "# the classic. Different bytes every time, thanks to the nonce.";
    else if (t === "password") note = "# please don't encrypt passwords you need to check. Hash them (part 3).";
    else if (t === "42") note = "# the answer, and two bytes of ciphertext. Encryption hides content, not length.";
    else if (v === "") note = "# an empty message still gets a tag. Authenticity doesn't need content.";
    else if (/^(.)\1{15,}$/.test(v)) note = "# sixteen or more identical letters in, no repeats out. In ECB mode identical blocks give identical output.";
    $("hero-note").textContent = note;
  }

  // --------------------------------------------------------------------------- want X, use Y
  const JOBS = {
    encrypt: { use: "Authenticated encryption: AES-256-GCM or ChaCha20-Poly1305", why: "Hides the data and detects any change in one step. A recipe (secretbox, Tink's Aead) also chooses the nonce for you.",
      never: "ECB. CBC or CTR without a MAC. A home-made XOR scheme.",
      web: 'crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data)', py: "AESGCM(key).encrypt(nonce, data, aad) · ChaCha20Poly1305", other: "libsodium crypto_secretbox_easy · Node createCipheriv(\"aes-256-gcm\") · Tink Aead" },
    password: { use: "Argon2id (scrypt, bcrypt or PBKDF2 where required), through the library's hash and verify", why: "Deliberately slow and salted, with the settings stored inside the hash string so you can raise them later.",
      never: "A plain SHA-256 or MD5 of the password. Your own loop of hashes. Comparing hashes yourself.",
      web: "Only PBKDF2 (deriveBits). Do password hashing on the server with a library.", py: "argon2-cffi: PasswordHasher().hash(pw) · .verify(stored, pw)", other: "libsodium crypto_pwhash_str · Node scrypt" },
    sign: { use: "Ed25519, or ECDSA P-256 / RSA-PSS where a standard needs them", why: "Anyone can check a signature; only the key holder can make one. Verify with a key you already trust, never one that arrives with the message.",
      never: "A checksum used as a signature. Verifying with whatever key the message names.",
      web: 'crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, data) (Ed25519 in newer browsers: check support)', py: "Ed25519PrivateKey.generate().sign(msg) · public_key.verify(sig, msg)", other: "libsodium crypto_sign_detached · Tink PublicKeySign" },
    kx: { use: "X25519 (or ECDH P-256), then HKDF to turn the shared secret into keys. Better: a ready-made protocol such as TLS, Noise or HPKE", why: "Two parties end up with the same secret without sending it. It does not tell you who you're talking to: authenticate the other side too.",
      never: "Using the raw shared secret as a key. An exchange nobody authenticates (anyone can sit in the middle).",
      web: "crypto.subtle.deriveBits with ECDH (X25519 in newer browsers) · then HKDF", py: "X25519PrivateKey.exchange(peer_public) · HKDF(...)", other: "libsodium crypto_kx_* / crypto_box · Tink hybrid encryption" },
    hash: { use: "SHA-256 (SHA-2), or SHA-3 / BLAKE2 / BLAKE3 when you need speed", why: "A fingerprint of data. If someone could swap the file and the hash together, the hash proves nothing: sign it, or fetch it from somewhere they can't change.",
      never: "MD5 or SHA-1 for anything security-related. A hash stored right beside the file as 'proof'.",
      web: 'crypto.subtle.digest("SHA-256", data)', py: "hashlib.sha256(data).hexdigest()", other: "Node createHash(\"sha256\") · libsodium crypto_generichash (BLAKE2b)" },
    mac: { use: "HMAC-SHA256, a constant-time compare, and a timestamp inside what you sign", why: "Proves a message came from someone who holds the shared secret. The timestamp stops a captured request being replayed.",
      never: "== on the digest. hash(secret + message). A signature that doesn't cover everything that matters.",
      web: 'crypto.subtle.sign("HMAC", key, data) · crypto.subtle.verify', py: "hmac.new(key, msg, hashlib.sha256) · hmac.compare_digest(a, b)", other: "Node createHmac + timingSafeEqual · Tink Mac" },
    token: { use: "16 to 32 random bytes from the system's secure generator, stored hashed", why: "A secret token's strength is the size of its random source. Treat it like a password: keep only a hash of it.",
      never: "Math.random() or random.random(). Timestamps or counters. Sequential IDs. A UUID used as a secret (RFC 9562 says not to).",
      web: "crypto.getRandomValues(new Uint8Array(32))", py: "secrets.token_urlsafe(32)", other: "Node crypto.randomBytes(32) · libsodium randombytes_buf" },
    pubenc: { use: "HPKE (RFC 9180) or a sealed box / hybrid encryption from libsodium or Tink", why: "Public-key encryption is for small things like keys. These constructions pick a fresh symmetric key per message and wrap it for you.",
      never: "Raw RSA over your data. RSA with no padding. Encrypting big files directly with a public key.",
      web: "RSA-OAEP only to wrap a small key (crypto.subtle.encrypt)", py: "RSA with OAEP padding for small keys · or a library's hybrid scheme", other: "libsodium crypto_box_seal · Tink HybridEncrypt/HybridDecrypt" },
  };
  function job(k) {
    const j = JOBS[k];
    $("job-use").textContent = j.use; $("job-why").textContent = j.why; $("job-never").textContent = j.never;
    $("job-web").textContent = j.web; $("job-py").textContent = j.py; $("job-other").textContent = j.other;
  }

  // --------------------------------------------------------------------------- red flags: use or avoid (invented packages)
  const PKGS = [
    { t: "VaultMax: military-grade, unbreakable 4096-bit encryption using our proprietary algorithm. No audit needed: it has never been broken.", avoid: true,
      flags: ["\"Military-grade\" is marketing, not a standard", "A proprietary algorithm nobody has attacked in public", "\"Never been broken\" means \"never been looked at\""], why: "Algorithms earn trust by surviving years of public attack. Secret ones haven't had any." },
    { t: "tinybox-seal: a thin wrapper over libsodium's secretbox. Three functions: seal, open, keygen. Tests include tampered data and wrong keys. Last release two months ago.", avoid: false,
      flags: ["A thin layer over a trusted core", "Tiny API, safe defaults", "Tests cover the failure paths", "Recently maintained"], why: "Still skim the code and the issues, but this is what a good dependency looks like: boring and small." },
    { t: "fast-aes-js: AES in pure JavaScript, \"optimised\". Last commit 2019. 41 open issues, one titled \"decrypts wrong data silently\".", avoid: true,
      flags: ["Hand-built from raw blocks", "Abandoned: last commit 2019", "An open issue about silent wrong results"], why: "A cipher that returns wrong data without complaint is worse than one that fails loudly. Use the platform's AES-GCM." },
    { t: "easycrypt: encrypt(data, password). Uses AES-CBC with a key made from MD5(password) and a fixed IV \"for speed\".", avoid: true,
      flags: ["MD5 of a password is not a key derivation function", "A fixed IV", "CBC with no authentication"], why: "Three of the mistakes from the next few slides in one README." },
    { t: "Your platform's Web Crypto (or your language's standard library) AES-GCM, with a key from your KMS.", avoid: false,
      flags: ["Maintained by the platform", "Standard algorithm, standard API", "Keys kept out of your code"], why: "The boring answer. You still manage nonces and associated data: that's part 2." },
    { t: "pw-hash-lite: \"bcrypt-compatible\" password hashing in 40 lines. No tests. \"Faster than bcrypt!\"", avoid: true,
      flags: ["A reimplementation of an existing algorithm", "No tests", "Speed is the selling point: a password hash should be slow"], why: "Use the real bcrypt, or better, Argon2id, from a maintained library." },
  ];
  let rfI = 0, rfScore = 0, rfDone = false;
  function rfShow() {
    const p = PKGS[rfI];
    $("rf-count").textContent = `Package ${rfI + 1} of ${PKGS.length}`;
    $("rf-readme").textContent = p.t;
    $("rf-verdict").hidden = true; $("rf-next").hidden = true; $("rf-flags").innerHTML = ""; $("rf-why").textContent = "";
    for (const b of $("rf-btns").querySelectorAll("[data-a]")) { b.disabled = false; b.hidden = false; }
    rfDone = false;
  }
  function rfAnswer(a) {
    if (rfDone) return; rfDone = true;
    const p = PKGS[rfI], ok = (a === "avoid") === p.avoid;
    if (ok) rfScore++;
    for (const b of $("rf-btns").querySelectorAll("[data-a]")) b.disabled = true;
    const v = $("rf-verdict"); v.hidden = false; v.className = "verdict " + (ok ? "ok" : "bad");
    v.textContent = (ok ? "Right" : "Not quite") + ": " + (p.avoid ? "avoid it." : "use it (after a look).");
    $("rf-flags").innerHTML = p.flags.map((f) => `<li class="${p.avoid ? "bad" : "ok"}"><b>${p.avoid ? "✗" : "✓"}</b>${esc(f)}</li>`).join("");
    $("rf-why").textContent = "# " + p.why;
    $("rf-score").textContent = `Score: ${rfScore} / ${rfI + 1}`;
    $("rf-next").hidden = false; $("rf-next").textContent = rfI === PKGS.length - 1 ? "See score" : "Next ›";
  }
  function rfNext() {
    if (rfI < PKGS.length - 1) { rfI++; rfShow(); return; }
    const n = PKGS.length;
    let m = `Final score: ${rfScore} / ${n}.`;
    if (rfScore === n) m += " # all six. Your dependency reviews are in good hands.";
    else if (rfScore >= n - 1) m += " # nearly there. The plausible-looking ones are the dangerous ones.";
    else m += " # the tell is rarely the code at first glance: read the README for claims, and the issues for silence.";
    $("rf-score").textContent = m;
    $("rf-readme").textContent = "Round over"; $("rf-count").textContent = "";
    $("rf-verdict").hidden = true; $("rf-flags").innerHTML = ""; $("rf-why").textContent = "";
    for (const b of $("rf-btns").querySelectorAll("[data-a]")) b.hidden = true;
    $("rf-next").textContent = "Play again"; $("rf-next").onclick = () => { rfI = 0; rfScore = 0; $("rf-next").onclick = null; $("rf-score").textContent = ""; rfShow(); };
  }

  // --------------------------------------------------------------------------- aead: why the tag matters
  const AE_KEY = L.randBytes(32);
  let ae = null;                                   // { nonce, ct, tag, msg, flips: Map(index -> mask) }
  function aeMake() {
    const msg = L.utf8($("ae-msg").value);
    const nonce = L.randBytes(12), { ct, tag } = L.gcmEncrypt(AE_KEY, nonce, msg);
    ae = { nonce, ct, tag, msg, flips: new Map() };
    aeRender();
  }
  function aeRender() {
    if (!ae) return;
    const ct2 = ae.ct.slice();
    for (const [i, m] of ae.flips) ct2[i] ^= m;
    $("ae-bytes").innerHTML = Array.from(ct2, (b, i) => `<button type="button" class="${ae.flips.has(i) ? "flipped" : ""}" data-i="${i}" aria-label="Byte ${i + 1}: ${b.toString(16).padStart(2, "0")}">${b.toString(16).padStart(2, "0")}</button>`).join("");
    const plain = L.gcmEncrypt(AE_KEY, ae.nonce, ct2).ct;       // CTR without the tag check: same keystream
    $("ae-plain").innerHTML = Array.from(plain, (b, i) => {
      const ch = b >= 32 && b < 127 ? String.fromCharCode(b) : "·";
      return b !== ae.msg[i] ? `<mark>${esc(ch)}</mark>` : esc(ch);
    }).join("");
    let g;
    try { g = sp("ok", "Accepted: " + L.text(L.gcmDecrypt(AE_KEY, ae.nonce, ct2, ae.tag))); }
    catch (e) { g = sp("bad", e.message); }
    $("ae-gcm").innerHTML = g;
    $("ae-note").textContent = ae.flips.size
      ? `# ${ae.flips.size} byte${ae.flips.size > 1 ? "s" : ""} changed. Without the key, an attacker can't read this, but can still edit it.`
      : "# press a ciphertext byte to flip a bit in it, or use the button.";
  }
  function aePreset() {
    const m = ae.msg; let i = m.findIndex((b) => b >= 48 && b <= 57);
    ae.flips = new Map();
    if (i < 0) i = 0;
    ae.flips.set(i, m[i] ^ 57);                    // turn the first digit into a 9
    if (m[i] === 57) ae.flips.set(i, 1);
    aeRender();
  }

  // --------------------------------------------------------------------------- nonces: birthday effect and the limit
  function nnDraw(b) {                              // draws random b-bit nonces until one repeats (b <= 40)
    const seen = new Set(), buf = new Uint32Array(2048); let n = 0;
    for (;;) {
      crypto.getRandomValues(buf);
      for (let i = 0; i < buf.length; i += 2) {
        const v = b <= 32 ? buf[i] >>> (32 - b) : (buf[i] >>> (64 - b)) * 4294967296 + buf[i + 1];
        n++; if (seen.has(v)) return n; seen.add(v);
      }
    }
  }
  let nnBusy = false;
  function nnRun() {
    const b = +$("nn-bits").value, out = $("nn-out");
    if (b > 40) {
      out.innerHTML = sp("m", `Not running: with ${b}-bit nonces the first repeat is expected after roughly 2^${b / 2} draws. That's the point: it's too far away to find.`);
      return;
    }
    if (nnBusy) return; nnBusy = true;
    const trials = b <= 32 ? 10 : 3, res = [];
    $("nn-run").disabled = true;
    out.textContent = "Drawing…";
    const step = () => {
      if (res.length >= trials) {
        const avg = res.reduce((a, x) => a + x, 0) / res.length, exp = 1.25 * Math.pow(2, b / 2);
        out.innerHTML = `${sp("k", "first repeat after (draws):")} ${esc(res.map((x) => x.toLocaleString("en-US")).join(", "))}<br>${sp("k", "average:")} ${esc(Math.round(avg).toLocaleString("en-US"))} ${sp("m", "· expected about " + Math.round(exp).toLocaleString("en-US") + " (1.25 × 2^" + b / 2 + ")")}`;
        $("nn-run").disabled = false; nnBusy = false; return;
      }
      res.push(nnDraw(b));
      out.textContent = `Draw ${res.length} of ${trials} done…`;
      setTimeout(step, 0);
    };
    setTimeout(step, 0);
  }
  function nnCalc() {
    const b = +$("nn-bits").value, k = +$("nn-k").value;
    $("nn-k-out").textContent = "2^" + k + " ≈ " + fmtBig(Math.pow(2, k));
    const x = Math.pow(2, 2 * k - b - 1), p = -Math.expm1(-x);
    let txt;
    if (p >= 0.01) txt = (p * 100).toFixed(p > 0.99 ? 3 : 1) + "% chance that some nonce has repeated";
    else txt = "about 1 in " + fmtBig(1 / p) + " that some nonce has repeated";
    $("nn-prob").innerHTML = `${sp("k", b + "-bit random nonces, 2^" + k + " messages:")} ${sp(p > 0.5 ? "bad" : p >= 2 ** -32 * 1.01 ? "y" : "ok", txt)}`;
    let note = "# the odds of any repeat grow with the square of the message count.";
    if (b === 96 && k === 32) note = "# exactly NIST's limit for random 96-bit nonces: about 1 in 8.6 billion for a repeat. That's where the rule says stop and rotate the key.";
    else if (b === 96 && k > 32) note = "# past NIST's 2^32 limit for random 96-bit nonces. Time to have rotated the key.";
    else if (b === 192) note = "# long random nonces: you could encrypt a staggering amount before repeat odds matter. That's why XChaCha20 is popular.";
    else if (p > 0.5) note = "# a repeat is now more likely than not.";
    $("nn-note").textContent = note;
  }

  // --------------------------------------------------------------------------- nonce reuse: the keystream cancels
  let ruMode = "fresh";
  const RU_KEY = L.randBytes(32);
  function ruCalc() {
    const a = L.utf8($("ru-a").value), b = L.utf8($("ru-b").value), n = Math.min(a.length, b.length);
    const A = a.slice(0, n), B = b.slice(0, n);
    const n1 = L.randBytes(12), n2 = ruMode === "same" ? n1 : L.randBytes(12);
    const c1 = L.gcmEncrypt(RU_KEY, n1, A).ct, c2 = L.gcmEncrypt(RU_KEY, n2, B).ct;
    const xp = L.xor(A, B), xc = L.xor(c1, c2), same = L.hex(xp) === L.hex(xc);
    $("ru-c1").textContent = short(L.hex(c1), 48); $("ru-c2").textContent = short(L.hex(c2), 48);
    $("ru-xp").textContent = short(L.hex(xp), 48); $("ru-xc").textContent = short(L.hex(xc), 48);
    const v = $("ru-verdict");
    v.className = "verdict " + (same ? "bad" : "ok");
    v.textContent = same ? "Cipher A ⊕ cipher B equals A ⊕ B: the keystream cancelled." : "No relationship visible: the two keystreams are unrelated.";
    $("ru-rec").innerHTML = `${sp("k", "Knowing A, an eavesdropper gets B:")} ${sp(same ? "bad" : "m", pretty(L.xor(xc, A)))}`;
  }

  // --------------------------------------------------------------------------- associated data
  const AD_KEY = L.randBytes(32);
  const AD_ROWS = [{ id: 17, user: "alice", text: "salary: 91,000" }, { id: 42, user: "bob", text: "salary: 64,000" }, { id: 58, user: "carol", text: "salary: 78,500" }];
  let adRows = [];
  const adAad = (r) => ($("ad-on").checked ? L.utf8(`user=${r.user};rec=${r.id}`) : new Uint8Array(0));
  function adReset() {
    adRows = AD_ROWS.map((r) => { const nonce = L.randBytes(12), e = L.gcmEncrypt(AD_KEY, nonce, L.utf8(r.text), adAad(r)); return { ...r, nonce, ct: e.ct, tag: e.tag }; });
    adRender(); $("ad-out").innerHTML = sp("m", "Read a row to open it.");
  }
  function adRender() {
    $("ad-table").querySelector("tbody").innerHTML = adRows.map((r, i) => `<tr><td>${r.id}</td><td>${r.user}</td><td><code>${esc(short(L.hex(r.ct), 20))}</code></td><td><button type="button" class="btn btn-ghost btn-sm" data-i="${i}">Read as ${r.user}</button></td></tr>`).join("");
  }
  function adRead(i) {
    const r = adRows[i];
    try { $("ad-out").innerHTML = `${sp("k", r.user + "'s row:")} ${sp("ok", L.text(L.gcmDecrypt(AD_KEY, r.nonce, r.ct, r.tag, adAad(r))))}`; }
    catch (e) { $("ad-out").innerHTML = `${sp("k", r.user + "'s row:")} ${sp("bad", e.message)}`; }
  }
  function adSwap() {
    const a = adRows[0], b = adRows[1];
    adRows[1] = { ...b, nonce: a.nonce, ct: a.ct, tag: a.tag };
    adRender();
    $("ad-out").innerHTML = sp("m", "Alice's ciphertext now sits in Bob's row. Read Bob's row.");
  }

  // --------------------------------------------------------------------------- keys: HKDF and where secrets come from
  const KY_CARDS = {
    random: ["Generate it, don't derive it", "Ask the secure generator for 32 bytes and keep them in a KMS or secret store. A key that came from a random source has full strength. Never from a timestamp, a counter or a hash of something guessable."],
    key: ["Derive separate keys with HKDF", "One strong master key, one HKDF call per job, each with its own label (\"v1/encrypt/invoices\", \"v1/mac/invoices\"). Fast, and a leak of one derived key doesn't give away the others or the master."],
    password: ["Use a slow password function, then keep the result", "Argon2id (or scrypt, bcrypt, PBKDF2) with a random salt and the settings in the table. Deliberately slow, because guessers try millions. HKDF is too fast for passwords: MDN says so too."],
  };
  let hkMaster = L.randBytes(32);
  function kyPick() {
    const c = KY_CARDS[$("ky-src").value];
    $("ky-card").innerHTML = `<b>${esc(c[0])}</b><span>${esc(c[1])}</span>`;
  }
  function hk() {
    $("hk-master").textContent = short(L.hex(hkMaster), 32);
    const prk = L.hkdfExtract(new Uint8Array(0), hkMaster);
    const l1 = $("hk-l1").value, l2 = $("hk-l2").value;
    $("hk-k1").textContent = short(L.hex(L.hkdfExpand(prk, L.utf8(l1), 32)), 32);
    $("hk-k2").textContent = short(L.hex(L.hkdfExpand(prk, L.utf8(l2), 32)), 32);
    let note = "# one character of difference in the label gives a completely different key.";
    if ((l1 + l2).toLowerCase().includes("password")) note = "# HKDF is for keys, not passwords. It's fast, so a guesser is fast too. Use Argon2id for those.";
    else if (l1 === l2) note = "# same label, same key. That's the point of labels: never let two jobs share a key.";
    else if (!l1 || !l2) note = "# an empty label is legal, but then everything shares a key. Labels are free: use them.";
    $("hk-note").textContent = note;
  }

  // --------------------------------------------------------------------------- envelope encryption
  const EV_DOCS = [
    { name: "invoice-2026-11.pdf", size: "12 KB", bytes: 12e3, text: "Invoice 2026-11: total 1,240.00" },
    { name: "backup-nov.tar", size: "3 MB", bytes: 3e6, text: "(contents of the November backup)" },
    { name: "photos.zip", size: "450 KB", bytes: 450e3, text: "(contents of the photo archive)" },
    { name: "archive-2025.tar", size: "80 MB", bytes: 80e6, text: "(contents of last year's archive)" },
  ];
  let ev = null;
  function evNew() {
    const kek = L.randBytes(32);
    ev = { kek, ver: 1, docs: EV_DOCS.map((d) => {
      const dek = L.randBytes(32), n = L.randBytes(12), e = L.gcmEncrypt(dek, n, L.utf8(d.text));
      return { ...d, n, ct: e.ct, tag: e.tag, w: evWrap(kek, d.name, dek) };
    }) };
    evRender(); $("ev-log").innerHTML = sp("m", "Read a document, rotate the KEK, or destroy it.");
  }
  function evWrap(kek, name, dek) { const wn = L.randBytes(12), e = L.gcmEncrypt(kek, wn, dek, L.utf8(name)); return { wn, ct: e.ct, tag: e.tag }; }
  function evRender() {
    $("ev-kek-state").innerHTML = ev.kek ? sp("ok", `KEK v${ev.ver}: in the KMS, never stored with the data`) : sp("bad", `KEK v${ev.ver}: destroyed`);
    $("ev-table").querySelector("tbody").innerHTML = ev.docs.map((d, i) => `<tr><td>${esc(d.name)}</td><td>${esc(d.size)}</td><td><code>${esc(short(L.hex(d.w.ct), 16))}</code></td><td><button type="button" class="btn btn-ghost btn-sm" data-i="${i}">Read</button></td></tr>`).join("");
  }
  function evRead(i) {
    const d = ev.docs[i];
    if (!ev.kek) { $("ev-log").innerHTML = sp("bad", `${d.name}: the KEK is gone, so the data key can't be unwrapped. The ciphertext is still there, and unreadable.`); return; }
    const dek = L.gcmDecrypt(ev.kek, d.w.wn, d.w.ct, d.w.tag, L.utf8(d.name));
    $("ev-log").innerHTML = `${sp("k", d.name + ":")} unwrapped its data key with KEK v${ev.ver}, then opened: ${sp("ok", L.text(L.gcmDecrypt(dek, d.n, d.ct, d.tag)))}`;
  }
  function evRotate() {
    if (!ev.kek) { $("ev-log").innerHTML = sp("bad", "There's no KEK to rotate: it was destroyed."); return; }
    const nk = L.randBytes(32), total = ev.docs.reduce((a, d) => a + d.bytes, 0);
    for (const d of ev.docs) { const dek = L.gcmDecrypt(ev.kek, d.w.wn, d.w.ct, d.w.tag, L.utf8(d.name)); d.w = evWrap(nk, d.name, dek); }
    ev.kek = nk; ev.ver++; evRender();
    $("ev-log").innerHTML = `${sp("ok", `Rotated to KEK v${ev.ver}.`)} Re-wrapped ${ev.docs.length} data keys (${ev.docs.length} × 32 bytes). Data re-encrypted: ${sp("ok", "0 bytes")}. Without envelopes you'd re-encrypt ${(total / 1e6).toFixed(1)} MB.`;
  }
  function evDestroy() {
    if (!ev.kek) return;
    ev.kek = null; evRender();
    $("ev-log").innerHTML = sp("bad", "KEK destroyed. Every data key is now locked forever, and so is everything it encrypted: crypto-shredding. (Also why KEK backups need thought.)");
  }

  // --------------------------------------------------------------------------- versioned formats
  const FM_KEY = L.randBytes(32);
  const FM_RECS = [[101, "address: 12 Elm Street"], [102, "address: 7 Harbour Road"], [103, "address: 55 Mill Lane"], [104, "address: 3 Oak Court"], [105, "address: 90 River Walk"], [106, "address: 21 Hill View"]];
  let fm = [];
  const fmAad = (id) => L.utf8("rec=" + id);
  function fmReset() {
    fm = FM_RECS.map(([id, text]) => { const nonce = L.randBytes(12), e = L.gcmEncrypt(FM_KEY, nonce, L.utf8(text), new Uint8Array(0)); return { id, v: 1, nonce, ct: e.ct, tag: e.tag }; });
    fmRender(); $("fm-log").innerHTML = sp("m", "Read a record, or read them all.");
  }
  function fmRender() {
    $("fm-table").querySelector("tbody").innerHTML = fm.map((r, i) => `<tr><td>${r.id}</td><td><code><span class="${r.v === 2 ? "ok" : "y"}">v${r.v}</span>.${esc(short(L.hex(r.nonce), 8))}.${esc(short(L.hex(r.ct), 10))}</code></td><td><button type="button" class="btn btn-ghost btn-sm" data-i="${i}">Read</button></td></tr>`).join("");
    const n = fm.filter((r) => r.v === 2).length;
    $("fm-prog").textContent = `${n} of ${fm.length} records on v2`;
    if (n === fm.length) $("fm-prog").textContent += " # every record on v2, no downtime, no big-bang migration. Boring and wonderful.";
  }
  function fmOpen(i) {
    const r = fm[i];
    if (r.v === 1) {
      const text = L.text(L.gcmDecrypt(FM_KEY, r.nonce, r.ct, r.tag, new Uint8Array(0)));
      const nonce = L.randBytes(12), e = L.gcmEncrypt(FM_KEY, nonce, L.utf8(text), fmAad(r.id));
      fm[i] = { id: r.id, v: 2, nonce, ct: e.ct, tag: e.tag };
      return `${sp("k", "rec " + r.id + ":")} opened by the v1 rules, rewritten as v2 (now bound to rec=${r.id}): ${sp("ok", text)}`;
    }
    return `${sp("k", "rec " + r.id + ":")} opened by the v2 rules: ${sp("ok", L.text(L.gcmDecrypt(FM_KEY, r.nonce, r.ct, r.tag, fmAad(r.id))))}`;
  }

  // --------------------------------------------------------------------------- passwords: stored strings and rehash policy
  const PW = {
    a2: { s: "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$aGFzaGhlcmU", ok: true, msg: "Meets the OWASP minimum (m=19456 KiB, t=2, p=1). Verified; no rehash needed." },
    a2old: { s: "$argon2id$v=19$m=4096,t=3,p=1$c29tZXNhbHQ$aGFzaGhlcmU", ok: false, msg: "Argon2id, but m=4096 KiB is below today's minimum (19456 KiB). Verified; rehash now, with the new settings." },
    bc: { s: "$2b$08$somesaltsomesaltsomeseOhashhashhashhashhashhashhashha", ok: false, msg: "bcrypt cost 8 is below the minimum of 10. Verified; rehash now, ideally to Argon2id." },
    pb: { s: "pbkdf2_sha256$100000$c29tZXNhbHQ$aGFzaGhlcmU", ok: false, msg: "PBKDF2 with 100,000 iterations is below the 600,000 minimum for HMAC-SHA256. Verified; rehash now, ideally to Argon2id." },
    sha: { s: "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", ok: false, bad: true, msg: "Not a password hash: no salt, no work factor, no parameters, and a guesser can try billions per second. Verify by hashing and comparing, then store Argon2id on this sign-in (or wrap the old hash right away)." },
  };
  function pw() { $("pw-stored").textContent = PW[$("pw-pick").value].s; $("pw-out").innerHTML = sp("m", "Press the button to simulate a sign-in."); }
  function pwLogin() {
    const p = PW[$("pw-pick").value];
    $("pw-out").innerHTML = `${sp("k", "verify(stored, password):")} ${sp("ok", "OK")}<br>${sp("k", "needs_rehash(stored):")} ${sp(p.ok ? "ok" : "bad", p.ok ? "no" : "yes")}<br>${sp("m", p.msg)}`;
  }

  // --------------------------------------------------------------------------- comparing secrets (simulated timings)
  function cm() {
    const secret = $("cm-secret").value, guess = $("cm-guess").value;
    let m = 0; while (m < secret.length && m < guess.length && secret[m] === guess[m]) m++;
    const n = secret.length, T = (k) => 40 + 25 * k, max = T(n) + 20;
    const bars = (fn) => Array.from({ length: n + 1 }, (_, k) => `<i class="${k === m ? "me" : ""}" style="height:${Math.round(fn(k) / max * 100)}%" title="${k} leading characters match: ${fn(k)} ns"><span>${k}</span></i>`).join("");
    $("cm-early").innerHTML = bars((k) => T(k));
    $("cm-const").innerHTML = bars(() => T(n));
    let note = `Your guess matches the first ${m} character${m === 1 ? "" : "s"}. Early-exit: ${T(m)} ns. Constant-time: ${T(n)} ns, whatever the guess.`;
    if (guess.length !== secret.length) note = "# different lengths: Node's timingSafeEqual would throw. Compare fixed-size values such as HMAC outputs. " + note;
    else if (m === n) note = "# a match! Both comparators say yes. Only one of them told the neighbours how close you were.";
    $("cm-note").textContent = note;
  }

  // --------------------------------------------------------------------------- randomness: a clock-seeded generator
  const mulberry32 = (a) => () => { a |= 0; a = (a + 0x6d2b79f5) | 0; let t = Math.imul(a ^ (a >>> 15), 1 | a); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return (t ^ (t >>> 14)) >>> 0; };
  let rnLast = null;
  function rnWeak() {
    const seed = Math.floor(Date.now() / 1000), r = mulberry32(seed);
    const tok = Array.from({ length: 4 }, () => r().toString(16).padStart(8, "0")).join("");
    $("rn-w-tok").textContent = tok; $("rn-w-seed").textContent = `seed = clock second ${seed}`;
    $("rn-out").innerHTML = `${sp("k", "Weak token's guessing space")} for anyone who knows roughly when it was made: ${sp("bad", "3,600 seeds per hour")}. It looks like 128 bits and acts like 12.`;
    $("rn-note").textContent = rnLast === seed ? "# same second, same seed, same token. A reset token that repeats is a reset token that can be guessed." : "# press it again within the same second.";
    rnLast = seed;
  }
  function rnStrong() {
    $("rn-s-tok").textContent = L.hex(L.randBytes(16));
    $("rn-out").innerHTML = `${sp("k", "Strong token's guessing space:")} ${sp("ok", "2^128 ≈ 3.4×10^38")}. Different every time, from the operating system's generator.`;
    $("rn-note").textContent = "# looks the same as the weak one. The difference is the source, and you can't see a source.";
  }

  // --------------------------------------------------------------------------- signed tokens
  const JW_SECRET = L.randBytes(32), JW_OTHER = L.randBytes(32);
  const b64u = (bytes) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const unb64u = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
  const jwtMake = (h, p, key) => { const hp = b64u(L.utf8(JSON.stringify(h))) + "." + b64u(L.utf8(JSON.stringify(p))); return hp + "." + (key ? b64u(L.hmacSha256(key, L.utf8(hp))) : ""); };
  const NOW = Math.floor(Date.now() / 1000);
  const JW_BASE = { sub: "sam", role: "user", iss: "api.acme.test", aud: "acme-web", exp: NOW + 3600 };
  const HS = { alg: "HS256", typ: "JWT" };
  const JW_TOK = {};
  (function () {
    JW_TOK.valid = jwtMake(HS, JW_BASE, JW_SECRET);
    JW_TOK.expired = jwtMake(HS, { ...JW_BASE, exp: NOW - 3600 }, JW_SECRET);
    JW_TOK.none = jwtMake({ alg: "none", typ: "JWT" }, { ...JW_BASE, role: "admin" }, null);
    const [h, , s] = JW_TOK.valid.split(".");
    JW_TOK.tampered = h + "." + b64u(L.utf8(JSON.stringify({ ...JW_BASE, role: "admin" }))) + "." + s;
    JW_TOK.aud = jwtMake(HS, { ...JW_BASE, aud: "other-app" }, JW_SECRET);
    JW_TOK.otherkey = jwtMake(HS, JW_BASE, JW_OTHER);
  })();
  function jwParse(t) { const [h, p, s] = t.split("."); return { h, p, s, hj: JSON.parse(L.text(unb64u(h))), pj: JSON.parse(L.text(unb64u(p))) }; }
  const jwSigOk = (t) => { const { h, p, s } = jwParse(t); return s !== "" && L.equalBytes(unb64u(s), L.hmacSha256(JW_SECRET, L.utf8(h + "." + p))); };
  function jwNaive(t) {                              // believes the token's own header (a bug some libraries once had)
    const j = jwParse(t);
    if (j.hj.alg === "none") return [true, "Accepted: the header says \"none\", so no signature was checked."];
    if (j.hj.alg === "HS256") return jwSigOk(t) ? [true, "Accepted: signature OK. (Expiry and audience were never checked.)"] : [false, "Rejected: bad signature."];
    return [false, "Rejected: unknown algorithm."];
  }
  function jwPinned(t) {                             // the server decides the algorithm, then checks the claims
    const j = jwParse(t);
    if (j.hj.alg !== "HS256") return [false, `Rejected: algorithm "${j.hj.alg}" is not allowed here.`];
    if (!jwSigOk(t)) return [false, "Rejected: signature doesn't match."];
    if (j.pj.exp <= NOW) return [false, "Rejected: expired."];
    if (j.pj.iss !== "api.acme.test") return [false, "Rejected: wrong issuer."];
    if (j.pj.aud !== "acme-web") return [false, "Rejected: this token is for another audience."];
    return [true, "Accepted: allowed algorithm, signature and claims all check out."];
  }
  function jw(k) {
    const t = JW_TOK[k], j = jwParse(t);
    $("jw-token").innerHTML = `<span class="t1">${esc(j.h)}</span>.<span class="t2">${esc(j.p)}</span>.<span class="t3">${esc(j.s) || "(empty)"}</span>`;
    $("jw-json").textContent = JSON.stringify(j.hj) + "\n" + JSON.stringify(j.pj, null, 1).replace(/\n\s*/g, " ");
    const card = (id, name, [ok, msg]) => { $(id).className = "jw-verdict " + (ok ? "ok" : "bad"); $(id).innerHTML = `<b>${name}</b><span>${esc(msg)}</span>`; };
    card("jw-naive", "Naive verifier (trusts the token's header)", jwNaive(t));
    card("jw-pinned", "Pinned verifier (you choose the algorithm)", jwPinned(t));
  }

  // --------------------------------------------------------------------------- TLS in code
  const TLS = {
    py: { bad: 'requests.get("https://api.test.internal/v1/users", verify=False)', good: 'requests.get("https://api.test.internal/v1/users", verify="test-ca.pem")' },
    node: { bad: 'https.get(url, { rejectUnauthorized: false })\n// or: NODE_TLS_REJECT_UNAUTHORIZED=0', good: 'https.get(url, { ca: fs.readFileSync("test-ca.pem") })' },
    go: { bad: "&tls.Config{ InsecureSkipVerify: true }", good: "pool := x509.NewCertPool()\npool.AppendCertsFromPEM(testCA)\n&tls.Config{ RootCAs: pool }" },
    curl: { bad: "curl -k https://api.test.internal/v1/users", good: "curl --cacert test-ca.pem https://api.test.internal/v1/users" },
  };
  const tlSeen = new Set();
  function tl(k) {
    $("tl-bad").textContent = TLS[k].bad; $("tl-good").textContent = TLS[k].good;
    tlSeen.add(k);
    $("tl-note").textContent = tlSeen.size === 4
      ? "# four tools, four ways to say \"trust everything\", four ways to say \"trust this one CA\". Always use the second."
      : "# the second one is no harder. It just names who to trust.";
  }

  // --------------------------------------------------------------------------- logs: a toy secret scrubber
  const LOGS = {
    web: "GET /api/v1/profile 200 12ms\nAuthorization: Bearer 9f8a7c6b5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f00\nCookie: session=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzYW0ifQ.c2lnbmF0dXJl\nPOST /login?user=sam&password=hunter2 302 40ms",
    app: "DEBUG aws key id AKIAIOSFODNN7EXAMPLE loaded\nDEBUG api_key=sk_test_FAKE0000000000000000 used for request 8841\nDEBUG derived key 3f4e1d9c7b5a2f8e6d4c1b9a7e5f3d2c1b0a99887766554433221100ffeeddcc",
    clean: "INFO key rotated: kek v2 active (3 documents rewrapped)\nWARN token rejected: expired (request 7710)",
  };
  const LOG_PATS = [
    [/Bearer\s+[A-Za-z0-9._~+\/-]{8,}/g, "Bearer token"], [/eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*/g, "JWT"],
    [/AKIA[0-9A-Z]{16}/g, "cloud key ID"], [/(?:password|passwd|secret|api[_-]?key|token)\s*[=:]\s*[^\s&]+/gi, "named secret"],
    [/\b[0-9a-f]{32,}\b/gi, "long hex (a key?)"],
  ];
  function lg() {
    const text = $("lg-in").value, hits = [];
    for (const [re, name] of LOG_PATS) { re.lastIndex = 0; let m; while ((m = re.exec(text))) hits.push({ s: m.index, e: m.index + m[0].length, name }); }
    hits.sort((a, b) => a.s - b.s || b.e - a.e);
    const kept = []; let end = 0; for (const h of hits) if (h.s >= end) { kept.push(h); end = h.e; }
    let hi = "", red = "", pos = 0;
    for (const h of kept) { hi += esc(text.slice(pos, h.s)) + `<mark title="${esc(h.name)}">${esc(text.slice(h.s, h.e))}</mark>`; red += esc(text.slice(pos, h.s)) + `<span class="red">[REDACTED ${esc(h.name)}]</span>`; pos = h.e; }
    hi += esc(text.slice(pos)); red += esc(text.slice(pos));
    $("lg-out").innerHTML = `<small>FOUND</small><pre>${hi}</pre><small>AS LOGGED, AFTER REDACTION</small><pre>${red}</pre>`;
    $("lg-note").textContent = kept.length ? `# ${kept.length} secret${kept.length > 1 ? "s" : ""} in the log. Anyone who can read the log can use them: rotate, then fix the logger.`
      : text.trim() ? "# nothing flagged. That proves little: this toy only knows five shapes. Log events, not values." : "# paste a log line (invented ones only).";
  }

  // --------------------------------------------------------------------------- spot the bug
  const SNIPS = [
    { title: "1 · Python: store a customer's address", lang: "python", lines: [
      ["import hashlib"], ["from Crypto.Cipher import AES"], ["from Crypto.Util.Padding import pad"], ["def save_address(user_id, password, address):"],
      ["    key = hashlib.md5(password.encode()).digest()", "A fast hash of a password is not a key derivation function, and it has no salt. Use a random key from a KMS, or a password KDF such as Argon2id."],
      ['    iv = b"0000000000000000"', "A fixed IV. CBC needs a fresh unpredictable IV for every message."],
      ["    cipher = AES.new(key, AES.MODE_CBC, iv)", "CBC with no authentication tag: the ciphertext can be changed undetected. Use AES-GCM or ChaCha20-Poly1305."],
      ["    blob = cipher.encrypt(pad(address.encode(), 16))"], ["    db.store(user_id, blob)"]] },
    { title: "2 · JavaScript: password-reset tokens", lang: "js", lines: [
      ["function makeResetToken(user) {"],
      ["  const token = Math.random().toString(36).slice(2);", "Math.random() isn't a secure generator, so the token is predictable. Use crypto.randomBytes(32) or crypto.getRandomValues."],
      ["  db.save({ user, token, expires: Date.now() + 3600000 });", "The token is stored in the clear. A database leak would hand out live reset links: store only a hash of it."],
      ["  return token;"], ["}"], ["function checkToken(user, given) {"], ["  const row = db.find(user);"],
      ["  return row.token === given && Date.now() < row.expires;", "=== stops at the first different character. Compare hashes in constant time (timingSafeEqual)."], ["}"]] },
    { title: "3 · Python: a partner's webhook", lang: "python", lines: [
      ["def handle_webhook(request):"], ["    body = request.body"], ['    sig = request.headers["X-Signature"]'], ["    expected = hmac.new(SECRET, body, hashlib.sha256).hexdigest()"],
      ["    if sig == expected:", "== on a digest isn't constant-time. Use hmac.compare_digest(sig, expected)."],
      ["        process(json.loads(body))", "No timestamp inside the signed data, so a captured request can be replayed forever. Sign a timestamp too and reject old ones."],
      ['    return "ok"'], ["def fetch_partner(url):"],
      ["    return requests.get(url, verify=False)", "Certificate checking is switched off: any man in the middle is accepted. Trust a test CA instead."]] },
    { title: "4 · Node.js: an AES-GCM helper", lang: "js", lines: [
      ["const key = crypto.randomBytes(32);", "A key made at start-up is gone at restart, and everything it encrypted with it. Keys come from a KMS or secret store."],
      ["const iv = Buffer.alloc(12);", "An all-zero nonce, reused on every call. Generate a fresh one per message and store it with the ciphertext."],
      ["function seal(plaintext, recordId) {"],
      ['  const c = crypto.createCipheriv("aes-256-gcm", key, iv);', "recordId is never bound as associated data (no c.setAAD(...)), so ciphertexts can be moved between records."],
      ["  const ct = Buffer.concat([c.update(plaintext), c.final()]);"], ["  return { ct, tag: c.getAuthTag() };"], ["}"], ["function open(box, recordId) {"],
      ["  try { return decrypt(box, recordId); }"], ["  catch (e) { return { error: e.message }; }", "The exact failure reason goes back to the caller. Say \"decryption failed\" and log the detail privately."], ["}"]] },
    { title: "5 · Python: who is this user?", lang: "python", lines: [
      ["def current_user(token):"],
      ['    claims = jwt.decode(token, options={"verify_signature": False})', "Signature checking is off: anyone can write their own claims."],
      ['    return db.get_user(claims["sub"])'], ["def is_admin(token):"],
      ['    alg = jwt.get_unverified_header(token)["alg"]', "The algorithm comes from the token itself (see the next line)."],
      ["    claims = jwt.decode(token, SECRET, algorithms=[alg])", "The token chooses its own algorithm. Pin it: algorithms=[\"HS256\"]."],
      ['    return claims.get("role") == "admin"'], ["def refresh_ok(token):"],
      ['    return jwt.decode(token, SECRET, algorithms=["HS256"], options={"verify_exp": False})', "Expiry checking is off, so old tokens work forever."]] },
  ];
  let bhI = 0; const bhMarks = SNIPS.map(() => new Set()); let bhRevealed = SNIPS.map(() => false);
  function bhPicker() {
    $("bh-pick").innerHTML = SNIPS.map((s, i) => `<button type="button" data-i="${i}" aria-pressed="${i === bhI}">${i + 1}</button>`).join("");
  }
  function bhRender() {
    const s = SNIPS[bhI], marks = bhMarks[bhI], rev = bhRevealed[bhI];
    $("bh-title").textContent = s.title;
    $("bh-code").innerHTML = s.lines.map(([code, why], i) => {
      let cls = marks.has(i) ? "flag" : "";
      if (rev) cls = why ? (marks.has(i) ? "found" : "missed") : (marks.has(i) ? "extra" : "");
      return `<li class="${cls}"><button type="button" data-i="${i}">${esc(code)}</button></li>`;
    }).join("");
    const total = s.lines.filter((l) => l[1]).length;
    if (!rev) { $("bh-findings").innerHTML = ""; $("bh-score").textContent = `${marks.size} line${marks.size === 1 ? "" : "s"} marked · ${total} bugs hidden`; $("bh-note").textContent = "# click the lines that worry you, then reveal."; return; }
    const found = s.lines.filter((l, i) => l[1] && marks.has(i)).length, extra = s.lines.filter((l, i) => !l[1] && marks.has(i)).length;
    $("bh-score").textContent = `Found ${found} of ${total} · ${extra} extra mark${extra === 1 ? "" : "s"}`;
    $("bh-findings").innerHTML = s.lines.map((l, i) => l[1] ? `<li class="${marks.has(i) ? "m" : "bad"}"><b>line ${i + 1}</b>${esc(l[1])}</li>` : "").join("");
    $("bh-note").textContent = found === total && !extra ? "# every bug found and no false alarms. That's a review I'd merge." : found === total ? "# every bug found. The extra marks are worth a second look, but better too careful than too relaxed." : "# the missed lines are in red. The commonest bug is the line that isn't there: no tag, no expiry, no replay check.";
  }

  // --------------------------------------------------------------------------- review checklist
  const RV_KEY = "crypto-in-code-review";
  function review() {
    const boxes = Array.from(document.querySelectorAll("#rv-list input[type=checkbox]"));
    let saved = {};
    try { saved = JSON.parse(store(RV_KEY) || "{}"); } catch (e) {}
    boxes.forEach((b) => { b.checked = !!saved[b.dataset.k]; });
    const update = () => {
      const done = boxes.filter((b) => b.checked).length;
      store(RV_KEY, JSON.stringify(Object.fromEntries(boxes.map((b) => [b.dataset.k, b.checked]))));
      const n = $("rv-note"); n.className = "comment";
      if (done === boxes.length) { n.textContent = "# 12 of 12. Your crypto is boring now. In security, that's the highest compliment."; n.classList.add("ok"); }
      else if (!done) n.textContent = "# tick what your project does today. Each gap is a ticket, not a failure. Saved in this browser only.";
      else n.textContent = `# ${done} of ${boxes.length}. Pick the unticked box most likely to bite and fix that first.`;
    };
    boxes.forEach((b) => b.addEventListener("change", update));
    update();
  }

  // --------------------------------------------------------------------------- console hint
  function consoleHint() {
    console.log("%cUsing Crypto Correctly in Code", "font: 700 24px monospace; color: #ff2e88; text-shadow: 0 0 8px #ff2e88");
    console.log("%cEvery demo here uses real AES-GCM, HKDF and HMAC from shared/crypto.js: teaching code, never for real data. Try sealing the same message twice, then reusing a nonce on purpose.", "font: 14px monospace; color: #00f0ff");
  }

  // --------------------------------------------------------------------------- start
  function start() {
    consoleHint();
    $("hero-in").addEventListener("input", hero); hero();
    segPick("job-pick", "data-j", job); job("encrypt");
    for (const b of $("rf-btns").querySelectorAll("[data-a]")) b.addEventListener("click", () => rfAnswer(b.dataset.a));
    $("rf-next").addEventListener("click", () => { if (!$("rf-next").onclick) rfNext(); }); rfShow();
    $("ae-msg").addEventListener("input", aeMake); click("ae-preset", aePreset); click("ae-reset", () => { ae.flips = new Map(); aeRender(); });
    $("ae-bytes").addEventListener("click", (e) => { const b = e.target.closest("button[data-i]"); if (!b) return; const i = +b.dataset.i; if (ae.flips.has(i)) ae.flips.delete(i); else ae.flips.set(i, 1); aeRender(); });
    aeMake();
    $("nn-out").textContent = "Pick a size and press the button."; $("nn-bits").addEventListener("change", () => { $("nn-out").textContent = "Pick a size and press the button."; nnCalc(); }); $("nn-k").addEventListener("input", nnCalc); click("nn-run", nnRun); nnCalc();
    segPick("ru-pick", "data-m", (m) => { ruMode = m; ruCalc(); if (m === "same") $("ru-verdict").textContent += " (One nonce, used twice: the secret walks out. That's why the library should make nonces for you.)"; });
    $("ru-a").addEventListener("input", ruCalc); $("ru-b").addEventListener("input", ruCalc); ruCalc();
    $("ad-on").addEventListener("change", adReset); click("ad-swap", adSwap); click("ad-reset", adReset);
    $("ad-table").addEventListener("click", (e) => { const b = e.target.closest("button[data-i]"); if (b) adRead(+b.dataset.i); }); adReset();
    $("ky-src").addEventListener("change", kyPick); kyPick();
    $("hk-l1").addEventListener("input", hk); $("hk-l2").addEventListener("input", hk); click("hk-rotate", () => { hkMaster = L.randBytes(32); hk(); }); hk();
    $("ev-table").addEventListener("click", (e) => { const b = e.target.closest("button[data-i]"); if (b) evRead(+b.dataset.i); });
    click("ev-rotate", evRotate); click("ev-destroy", evDestroy); click("ev-reset", evNew); evNew();
    $("fm-table").addEventListener("click", (e) => { const b = e.target.closest("button[data-i]"); if (!b) return; const line = fmOpen(+b.dataset.i); fmRender(); $("fm-log").innerHTML = line; });
    click("fm-all", () => { const lines = fm.map((_, i) => fmOpen(i)); fmRender(); $("fm-log").innerHTML = lines.join("<br>"); }); click("fm-reset", fmReset); fmReset();
    $("pw-pick").addEventListener("change", pw); click("pw-login", pwLogin); pw();
    $("cm-secret").addEventListener("input", cm); $("cm-guess").addEventListener("input", cm); cm();
    click("rn-weak", rnWeak); click("rn-strong", rnStrong);
    segPick("jw-pick", "data-t", jw); jw("valid");
    segPick("tl-pick", "data-l", tl); tl("py");
    segPick("lg-pick", "data-s", (s) => { $("lg-in").value = LOGS[s]; lg(); }); $("lg-in").addEventListener("input", lg); $("lg-in").value = LOGS.web; lg();
    bhPicker(); bhRender();
    $("bh-pick").addEventListener("click", (e) => { const b = e.target.closest("button[data-i]"); if (!b) return; bhI = +b.dataset.i; bhPicker(); bhRender(); });
    $("bh-code").addEventListener("click", (e) => { const b = e.target.closest("button[data-i]"); if (!b || bhRevealed[bhI]) return; const i = +b.dataset.i; const m = bhMarks[bhI]; if (m.has(i)) m.delete(i); else m.add(i); bhRender(); });
    click("bh-check", () => { bhRevealed[bhI] = true; bhRender(); });
    click("bh-reset", () => { bhMarks[bhI].clear(); bhRevealed[bhI] = false; bhRender(); });
    review();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
})();
