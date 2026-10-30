/* app.js - wires every demo on the page to the maths in crypto.js. */
(function () {
  "use strict";
  const L = window.Lab;
  const HW = window.hashwasm || null;                 // optional: md5, sha1, sha3, blake2b, bcrypt, scrypt, argon2id

  // --------------------------------------------------------------------------- helpers
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const sp = (cls, s) => `<span class="${cls}">${esc(s)}</span>`;
  const fmt = (n) => n.toLocaleString("en-US");
  const q = (s) => JSON.stringify(s);                  // show a string in quotes
  const cut = (s, n = 32) => (s.length > n ? s.slice(0, n) + "…" : s);
  const hex64 = (x) => x.toString(16).padStart(64, "0");
  const wait = (ms = 0) => new Promise((r) => setTimeout(r, ms));
  const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  const enc = L.utf8;

  /** Run fn now and again whenever any of the inputs change. */
  function bind(ids, fn) {
    for (const id of [].concat(ids)) $(id).addEventListener("input", fn);
    fn();
  }
  function click(id, fn) { $(id).addEventListener("click", fn); }
  async function busy(btn, fn) {
    const label = btn.textContent;
    btn.disabled = true; btn.textContent = "Working…";
    await wait(30);                                    // let the button repaint before heavy maths
    try { await fn(); } finally { btn.disabled = false; btn.textContent = label; }
  }
  function err(id, msg) { const el = $(id); el.textContent = msg || ""; el.hidden = !msg; }
  const ago = (t0) => `${(performance.now() - t0).toFixed(0)} ms`;

  // number words for big counts
  function bigWords(n) {
    const names = [[1e18, "quintillion"], [1e15, "quadrillion"], [1e12, "trillion"], [1e9, "billion"], [1e6, "million"]];
    if (n >= 1e21) { const e = Math.floor(Math.log10(n)); return `${(n / 10 ** e).toFixed(1)} × 10^${e}`; }
    for (const [v, w] of names) if (n >= v) return `${(n / v).toFixed(1).replace(/\.0$/, "")} ${w}`;
    return fmt(Math.round(n));
  }
  function duration(s) {
    const Y = 31557600;
    if (s < 1) return `${(s * 1000).toFixed(1)} milliseconds`;
    if (s < 120) return `${s.toFixed(1)} seconds`;
    if (s < 7200) return `${(s / 60).toFixed(1)} minutes`;
    if (s < 2 * 86400) return `${(s / 3600).toFixed(1)} hours`;
    if (s < Y) return `${(s / 86400).toFixed(1)} days`;
    if (s < 1e6 * Y) return `${fmt(Math.round(s / Y * 10) / 10)} years`;
    return `${bigWords(s / Y)} years`;
  }

  // --------------------------------------------------------------------------- easter eggs
  function passwordEgg(s) {
    const t = s.trim().toLowerCase().replace(/\s+/g, " ");
    if (t === "hunter2") return `\n\n${sp("m", "hunter2? funny, all I see is *******")}`;
    if (t === "4") return `\n\n${sp("m", "A private key of 4? Even eMudhra regrets weak keys.")}`;
    if (t.includes("correct horse battery staple"))
      return `\n\n${sp("y", "xkcd 936:")} ${sp("m", "four random words beat a short, complex password. Just don't use these four: everyone knows them now.")}`;
    return "";
  }

  // --------------------------------------------------------------------------- hero (slide 1)
  function hero() {
    const a = $("hero-a").value, b = $("hero-b").value;
    for (const el of [$("hero-a"), $("hero-b")]) el.style.width = Math.max(4, el.value.length + 1) + "ch";
    const ha = L.sha256(enc(a)), hb = L.sha256(enc(b)), xa = L.hex(ha), xb = L.hex(hb);
    $("hero-ha").textContent = xa;
    $("hero-hb").innerHTML = [...xb].map((c, i) => (c !== xa[i] ? `<span class="diff">${c}</span>` : c)).join("");
    let changed = 0;
    for (let i = 0; i < Math.max(a.length, b.length); i++) if (a[i] !== b[i]) changed++;
    $("hero-note").innerHTML = !a || !b
      ? "# even nothing has a fingerprint:<br># e3b0c442… is the SHA-256 of an empty input."
      : a === b
      ? "# same input, same hash. try changing one letter."
      : `# ${changed === 1 ? "one letter changed" : "inputs differ"}.<br># a completely different hash: ${L.bitDiff(ha, hb)} of 256 bits flipped.`;
  }

  // --------------------------------------------------------------------------- Caesar (slide 4)
  function caesar() {
    const msg = $("caesar-msg").value, k = +$("caesar-key").value;
    $("caesar-key-out").textContent = k;
    const ct = L.caesar(msg, k), used = new Set(L.letters(msg));
    const cells = (row) => [...L.ALPHA].map((c, i) => {
      const ch = row === "p" ? c : L.ALPHA[(i + k) % 26];
      return `<span class="${row}${used.has(c) ? " used" : ""}">${ch}</span>`;
    }).join("");
    $("caesar-alpha").innerHTML = cells("p") + cells("q");
    const egg = L.letters(msg) === "HAL" && k === 1 ? "I'm sorry, Dave. (HAL, from 2001: A Space Odyssey, shifted by 1)"
      : L.letters(ct) === "NEVERROLLYOUROWNCRYPTO" ? "You solved the puzzle hidden in this page's source. Tell zevaryx!" : "";
    $("caesar-result").innerHTML = (msg ? `${esc(msg)}<span class="arrow">→</span><span class="k">${esc(ct)}</span>` : sp("m", "type a message")) +
      (egg ? `<small class="egg">${esc(egg)}</small>` : "");

    const long = L.letters(ct).length > 12;
    let best = -1, bestScore = Infinity;
    if (long) for (let s = 1; s <= 25; s++) { const sc = L.chi2(L.caesar(ct, -s)); if (sc < bestScore) { bestScore = sc; best = s; } }
    $("caesar-brute").innerHTML = Array.from({ length: 25 }, (_, i) => {
      const s = i + 1;
      return `<li${s === best ? ' class="best"' : ""}>key ${String(s).padStart(2)}: <b>${esc(L.caesar(ct, -s))}</b>${s === best ? "  ← looks like English" : ""}</li>`;
    }).join("");

    const longCt = L.caesar(L.SAMPLE, k), cnt = L.counts(longCt), max = Math.max(...cnt), top = cnt.indexOf(max);
    $("caesar-bars").innerHTML = cnt.map((c, i) => `<div><i class="${i === top ? "top" : ""}" style="height:${(c / max) * 100}%"></i><span>${L.ALPHA[i]}</span></div>`).join("");
    const guess = L.mod(top - 4, 26);
    $("caesar-freq").innerHTML = `most common ciphertext letter: ${sp("k", L.ALPHA[top])}  →  it was probably E, so the key is ${sp("y", guess)}\n` +
      `decrypted: ${esc(cut(L.caesar(longCt, -guess), 52))}  ${guess === k ? sp("ok", "✓ cracked") : sp("bad", "✗ wrong guess")}`;
  }

  // --------------------------------------------------------------------------- Vigenere (slide 5)
  function vigenere() {
    const m = L.letters($("vig-msg").value).slice(0, 40), k = L.letters($("vig-key").value);
    if (!m || !k) {
      $("vig-tiles").innerHTML = ""; $("vig-ic").innerHTML = "";
      $("vig-how").textContent = "The message and the keyword each need at least one letter A–Z.";
      $("vig-break").textContent = "";
      return;
    }
    const ct = L.vigenere(m, k), ks = k.repeat(Math.ceil(m.length / k.length)).slice(0, m.length);
    const cnt = L.counts(m), common = L.ALPHA[cnt.indexOf(Math.max(...cnt))];
    const row = (cls, label, s, mark) => `<tr class="${cls}"><th>${label}</th>${[...s].map((c, i) => `<td class="${mark && m[i] === common ? "same" : ""}">${c}</td>`).join("")}</tr>`;
    $("vig-tiles").innerHTML = row("msg", "Message", m, true) + row("key", `Keyword "${k}"`, ks) + row("ct", "Secret", ct, true);
    const repeats = [...m].filter((c) => c === common).length;
    const how = (i) => `${m[i]} with ${ks[i]}: ${ks[i]} is letter #${ks.charCodeAt(i) - 64}, so shift ${m[i]} forward ${ks.charCodeAt(i) - 65} places. ${m[i]} becomes ${ct[i]}.`;
    $("vig-how").innerHTML = `<b>How one letter works.</b> ${esc(how(0))}${m.length > 1 ? " Next, " + esc(how(1)) : ""}` +
      (repeats > 1 ? ` Look at the ${repeats} ${common}'s: they became ${esc([...ct].filter((_, i) => m[i] === common).join(", "))}.` : "");

    const res = L.breakVigenere(L.vigenere(L.SAMPLE, k));
    $("vig-ic").innerHTML = res.scores.map((s) => `<div><i class="${s.len === res.len ? "top" : ""}" style="height:${Math.min(1, s.ic / 0.075) * 100}%"></i><span>${s.len}</span></div>`).join("");
    $("vig-break").innerHTML = res.len
      ? `bars = how English-like each guessed key length looks (index of coincidence; English ≈ 0.066)\n` +
        `key length ${sp("y", res.len)} stands out → each column is a Caesar cipher\n` +
        `recovered keyword: ${sp("k", res.key)}   (real: ${esc(k)})  ${res.key === k ? sp("ok", "✓") : sp("m", "(a repeat of the real key works too)")}`
      : `no key length up to 12 looks like English.\n${sp("ok", "A long keyword resists this attack.")} A key as long as the message never repeats at all: that is the one-time pad.`;
  }

  // --------------------------------------------------------------------------- one-time pad (slide 6)
  let otpKey = "XMCKL";                               // the slide's key, until someone asks for a new one
  const randLetters = (n) => Array.from({ length: n }, () => L.ALPHA[L.randInt(26)]).join("");
  function otp() {
    const m = L.letters($("otp-msg").value);
    if (otpKey.length !== m.length) otpKey = randLetters(m.length);
    const ct = L.vigenere(m, otpKey);
    const row = (cls, label, s) => `<tr class="${cls}"><th>${label}</th>${[...s].map((c) => `<td>${c}</td>`).join("")}</tr>`;
    $("otp-tiles").innerHTML = m ? row("msg", "Message", m) + row("key", "Random key", otpKey) + row("ct", "Secret", ct) : "";
    const other = L.letters($("otp-other").value);
    if (!m) $("otp-fake").textContent = "Type a message (letters A–Z).";
    else if (other.length !== m.length) $("otp-fake").innerHTML = sp("m", `Pick a word with exactly ${m.length} letters to see the trick.`);
    else {
      const fake = L.vigenere(ct, other, true);
      $("otp-fake").innerHTML = `Same secret, other key:\n  ${sp("k", ct)} + key ${sp("y", fake)} = ${sp("c", L.vigenere(ct, fake, true))}\n` +
        `Any ${m.length}-letter word fits some key, so a guess tells you nothing: ${sp("ok", "perfect secrecy")}.`;
    }
  }
  let reuseKey = L.randBytes(16);
  function otpReuse() {
    const p1 = enc("ATTACK AT DAWN!!"), p2 = enc("RETREAT AT NOON!"), c1 = L.xor(p1, reuseKey), c2 = L.xor(p2, reuseKey);
    $("otp-reuse").innerHTML = `key  = ${L.hex(reuseKey)}  ${sp("m", "(used twice!)")}\n` +
      `c1   = ${L.hex(c1)}\nc2   = ${L.hex(c2)}\n\n` +
      `c1 ⊕ c2 = ${sp("k", L.hex(L.xor(c1, c2)))}\np1 ⊕ p2 = ${sp("k", L.hex(L.xor(p1, p2)))}  ${sp("m", "← identical: the key cancelled out")}\n\n` +
      `know p1 "ATTACK AT DAWN!!"? recover p2: ${sp("bad", q(L.text(L.xor(L.xor(c1, c2), p1))))}`;
  }

  // --------------------------------------------------------------------------- Enigma (slide 7)
  const EN_ROWS = ["QWERTZUIO", "ASDFGHJK", "PYXCVBNML"];
  let machine, tapeIn = "", tapeOut = "", lastPath = null, lampTimer;
  function enigmaSettings() {
    const start = (L.letters($("en-start").value) + "AAA").slice(0, 3);
    let plugs = $("en-plugs").value;
    try { new L.Enigma(undefined, start, plugs); err("en-err"); }
    catch (e) { err("en-err", e.message + " Running without plugboard cables."); plugs = ""; }
    return { start, plugs };
  }
  function enigmaReset() {
    const { start, plugs } = enigmaSettings();
    machine = new L.Enigma(undefined, start, plugs);
    tapeIn = tapeOut = ""; lastPath = null;
    enigmaDraw();
    const five = new L.Enigma(undefined, start, plugs).text("AAAAA");
    $("en-aaaaa").innerHTML = `A A A A A  →  ${sp("y", five.split("").join(" "))}` +
      (start === "AAA" && !plugs.trim() ? `   ${sp("m", "(slide: B D Z G O)")}` : "") +
      `\nSame key, a different letter each time.`;
    const long = L.letters(L.SAMPLE), out = new L.Enigma(undefined, start, plugs).text(long);
    const self = [...long].filter((c, i) => out[i] === c).length;
    const f = (n) => { let r = 1n; for (let i = 2n; i <= n; i++) r *= i; return r; };
    const total = 60n * 26n ** 3n * (f(26n) / (f(6n) * f(10n) * 2n ** 10n));
    $("en-facts").innerHTML = `settings: 60 rotor orders × 26³ positions × plugboards\n        = ${sp("y", BigInt(total).toLocaleString("en-US"))}  (~159 quintillion)\n\n` +
      `${sp("k", "A letter never turns into itself:")} ${self} of ${long.length} letters\nstayed the same. Codebreakers used that flaw, plus\noperators repeating predictable phrases.`;
  }
  function enigmaDraw() {
    machine.window.split("").forEach((c, i) => ($("en-w" + i).textContent = c));
    let s = `typed : ${esc(tapeIn) || sp("m", "(press some keys)")}\nlamps : ${sp("y", tapeOut)}`;
    if (lastPath) {
      const p = lastPath;
      s += `\n\nsignal: key ${sp("c", p[0])} → plugboard ${p[1]} → rotors ${p[2]} ${p[3]} ${p[4]} → reflector ${sp("k", p[5])}\n` +
        `        → rotors ${p[6]} ${p[7]} ${p[8]} → plugboard → lamp ${sp("y", p[9])}`;
    }
    if (tapeOut) s += `\n\n${sp("m", "To decrypt: reset the machine and type the lamp letters back in.")}`;
    $("en-tape").innerHTML = s;
  }
  function enigmaPress(ch) {
    const { out, path } = machine.press(ch);
    tapeIn += ch; tapeOut += out; lastPath = path;
    document.querySelectorAll("#en-lamps span").forEach((el) => el.classList.toggle("on", el.dataset.l === out));
    clearTimeout(lampTimer);
    lampTimer = setTimeout(() => document.querySelectorAll("#en-lamps span.on").forEach((el) => el.classList.remove("on")), 900);
    const key = document.querySelector(`#en-keys button[data-l="${ch}"]`);
    if (key) { key.classList.add("down"); setTimeout(() => key.classList.remove("down"), 150); }
    enigmaDraw();
  }
  function enigmaInit() {
    $("en-lamps").innerHTML = EN_ROWS.map((r) => `<div>${[...r].map((c) => `<span data-l="${c}">${c}</span>`).join("")}</div>`).join("");
    $("en-keys").innerHTML = EN_ROWS.map((r) => `<div>${[...r].map((c) => `<button type="button" data-l="${c}" aria-label="Key ${c}">${c}</button>`).join("")}</div>`).join("");
    $("en-keys").addEventListener("click", (e) => { const b = e.target.closest("button"); if (b) enigmaPress(b.dataset.l); });
    $("en-keys").addEventListener("keydown", (e) => {
      if (/^[a-z]$/i.test(e.key) && !e.ctrlKey && !e.metaKey && !e.altKey) { e.preventDefault(); enigmaPress(e.key.toUpperCase()); }
    });
    bind(["en-start", "en-plugs"], enigmaReset);
    click("en-reset", enigmaReset);
  }

  // --------------------------------------------------------------------------- hashing vs encryption (slide 8)
  const hveKey = L.randBytes(16), hveNonce = L.randBytes(12);
  function hve() {
    const s = $("hve-in").value, b = enc(s), h = L.sha256(b), { ct, tag } = L.gcmEncrypt(hveKey, hveNonce, b);
    $("hve-out").innerHTML =
      `input      ${esc(q(s))}  ${sp("m", `${b.length} bytes`)}\n\n` +
      `${sp("c", "SHA-256")}    ${L.hex(h)}\n           ${sp("m", "always 32 bytes · no key · no way back")}\n\n` +
      `${sp("k", "AES-GCM")}    ${esc(cut(L.hex(ct), 64)) || sp("m", "(empty)")}\n           ${sp("m", "same length as the input, plus a 16-byte tag")}\n` +
      `decrypt    ${esc(q(L.text(L.gcmDecrypt(hveKey, hveNonce, ct, tag))))}  ${sp("ok", "the secret key gets it back")}`;
  }

  // --------------------------------------------------------------------------- encoding: bytes, hex, Base64 (Part 1)
  const toB64 = (bytes) => btoa(Array.from(bytes, (b) => String.fromCharCode(b)).join(""));
  const fromB64 = (s) => Uint8Array.from(atob(s.replace(/\s+/g, "")), (c) => c.charCodeAt(0));
  const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  function encoding() {
    const s = $("enc-in").value, b = enc(s), chars = [...s].length;
    if (!b.length) { $("enc-out").innerHTML = sp("m", "Type some text."); }
    else {
      const first = b.subarray(0, 3), bits24 = L.bits(first).padEnd(24, "0"), groups = bits24.match(/.{6}/g).slice(0, Math.ceil(first.length * 8 / 6));
      $("enc-out").innerHTML =
        `text     ${esc(q(s))}  ${sp("m", `${chars} character${chars === 1 ? "" : "s"}`)}\n` +
        `UTF-8    ${esc(cut(L.hex(b, " "), 60))}  ${sp("m", `${b.length} bytes${b.length > chars ? " (some characters need more than one)" : ""}`)}\n` +
        `binary   ${esc(cut(Array.from(b.subarray(0, 4), (x) => x.toString(2).padStart(8, "0")).join(" "), 60))}${b.length > 4 ? "…" : ""}\n` +
        `hex      ${sp("y", cut(L.hex(b), 60))}  ${sp("m", "2 characters per byte")}\n` +
        `Base64   ${sp("c", cut(toB64(b), 60))}  ${sp("m", "4 characters per 3 bytes")}\n\n` +
        `${sp("m", "How Base64 works: the first bytes")} ${esc(L.hex(first, " "))} ${sp("m", "are")} ${bits24.slice(0, first.length * 8).match(/.{8}/g).join(" ")}\n` +
        `${sp("m", "regrouped into 6-bit pieces")} ${groups.join(" ")} ${sp("m", "→")} ${sp("c", groups.map((g) => B64[parseInt(g, 2)]).join(" "))}`;
    }
    let decoded;
    try { decoded = sp("ok", q(L.text(fromB64($("enc-b64").value)))); } catch (e) { decoded = sp("bad", "not valid Base64"); }
    $("enc-dec").innerHTML = `decoded  ${decoded}\n${sp("m", "No key, no secret: anyone can do this. Encoding only changes how data is written down.")}`;
  }

  // --------------------------------------------------------------------------- passkeys (Part 4), simulated with P-256 ECDSA
  // Simplified from WebAuthn: the device signs SHA-256(origin + challenge). Real passkeys sign a little more, the same way.
  const PK_SITE = "https://bank.example", PK_FAKE = "https://bank-examp1e.com";
  let pkDevice = null, pkServer = null;
  const pkHash = (origin, challenge) => L.toBig(L.sha256(L.concat(enc(origin), challenge)));
  const pkVerify = (sig, challenge) => L.ecdsaVerify(pkServer, pkHash(PK_SITE, challenge), sig);
  const pkSign = (origin, challenge) => L.ecdsaSign(pkDevice.d, pkHash(origin, challenge), L.randBelow(L.P256.n - 1n) + 1n);
  const short64 = (x) => cut(hex64(x), 20);
  function passkey(action) {
    const out = $("pk-out");
    if (action === "register") {
      const d = L.randBelow(L.P256.n - 1n) + 1n;
      pkDevice = { site: PK_SITE, d }; pkServer = L.P256.mul(d);
      out.innerHTML = `${sp("c", "Your device")} makes a new key pair just for ${PK_SITE}\n  private key  ${sp("k", "stays on the device, never sent")}\n` +
        `${sp("y", "bank.example")} stores only the public key\n  Q.x = ${short64(pkServer[0])}\n\n` +
        `${sp("m", "If the bank's database leaks, attackers get public keys: they can check signatures, not make them.")}`;
      return;
    }
    if (!pkDevice) { out.innerHTML = sp("m", "Create a passkey first (button 1)."); return; }
    const challenge = L.randBytes(16), t0 = performance.now();
    if (action === "login") {
      const sig = pkSign(PK_SITE, challenge), ok = pkVerify(sig, challenge);
      out.innerHTML = `${sp("y", "bank.example")} sends a random challenge  ${L.hex(challenge)}\n` +
        `${sp("c", "your device")} signs (origin + challenge) with the private key\n  r = ${short64(sig[0])}  s = ${short64(sig[1])}\n` +
        `${sp("y", "bank.example")} checks it with your public key: ${ok ? sp("ok", "valid, you're logged in") : sp("bad", "invalid")}  ${sp("m", `(${ago(t0)})`)}\n\n` +
        `${sp("m", "No password was sent or stored. A fresh challenge every time means an old signature can't be replayed.")}`;
      return;
    }
    // phishing: the look-alike site relays the real bank's challenge and hopes for a usable signature
    const forced = pkSign(PK_FAKE, challenge), ok = pkVerify(forced, challenge);
    out.innerHTML = `${sp("bad", "bank-examp1e.com")} (a look-alike) relays the bank's challenge  ${L.hex(challenge)}\n\n` +
      `${sp("c", "your device")} looks for a passkey for bank-examp1e.com: ${sp("ok", "none, so nothing is signed")}\n\n` +
      `even if it were tricked, the browser puts the real origin into what gets signed:\n  signed for ${PK_FAKE}\n` +
      `${sp("y", "bank.example")} checks it expecting ${PK_SITE}: ${ok ? sp("bad", "accepted?!") : sp("ok", "doesn't match, rejected")}\n\n` +
      `${sp("m", "A password typed into the fake site would have worked for the attacker. A passkey can't be phished.")}`;
  }

  // --------------------------------------------------------------------------- a real passkey, through the browser's WebAuthn API
  // First press creates one; later presses log in with it (or any passkey you already have for this site).
  const PK_STORE = "crypto101-passkey";
  const b64u = (bytes) => toB64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const pkLoad = () => { try { return JSON.parse(localStorage.getItem(PK_STORE)); } catch (e) { return null; } };
  const pkSave = (v) => { try { if (v) localStorage.setItem(PK_STORE, JSON.stringify(v)); else localStorage.removeItem(PK_STORE); } catch (e) { /* storage blocked */ } };
  const ALGS = { "-7": "ES256: ECDSA on P-256, the curve from this talk", "-8": "EdDSA (Ed25519)", "-257": "RS256: RSA signatures" };
  const flagsText = (f) => (f & 0x08 ? (f & 0x10 ? "synced: backed up to your password manager" : "can sync, not backed up yet") : "device-bound: lives only on this authenticator");
  function pkRealLabel() {
    const has = !!pkLoad();
    $("pk-real").textContent = has ? "Use my real passkey" : "Create a real passkey";
    $("pk-forget").hidden = !has;
  }
  async function pkCreate(out) {
    const cred = await navigator.credentials.create({ publicKey: {
      challenge: L.randBytes(32), rp: { name: "Crypto 101 Lab" },
      user: { id: enc("crypto101-demo"), name: "crypto101-demo", displayName: "Crypto 101 demo" },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
      authenticatorSelection: { residentKey: "required", userVerification: "preferred" }, attestation: "none", timeout: 120000 } });
    const r = cred.response, spki = r.getPublicKey ? r.getPublicKey() : null, alg = r.getPublicKeyAlgorithm ? r.getPublicKeyAlgorithm() : null;
    const auth = r.getAuthenticatorData ? new Uint8Array(r.getAuthenticatorData()) : null, id = b64u(new Uint8Array(cred.rawId));
    pkSave({ id, spki: spki ? toB64(new Uint8Array(spki)) : null, alg, made: new Date().toISOString().slice(0, 10) });
    let pt = null;
    try { if (spki && alg === -7) pt = L.spkiP256(new Uint8Array(spki)); } catch (e) { /* show the raw key instead */ }
    const where = { platform: "on this device", "cross-platform": "on a phone or security key" }[cred.authenticatorAttachment] || "by your authenticator";
    out.innerHTML = `${sp("ok", "REAL PASSKEY CREATED")} for ${esc(location.hostname)}\n\n` +
      `credential ID  ${esc(cut(id, 32))}\n` +
      `algorithm      ${esc(ALGS[alg] || (alg === null ? "not reported by this browser" : "COSE " + alg))}\n` +
      (pt ? `public key     x = ${cut(hex64(pt[0]), 24)}\n               y = ${cut(hex64(pt[1]), 24)}  ${sp("m", "← all the site keeps")}\n`
        : spki ? `public key     ${cut(L.hex(new Uint8Array(spki)), 40)}  ${sp("m", "← all the site keeps")}\n` : "") +
      `stored         ${esc(where)}${auth ? `, ${esc(flagsText(auth[32]))}` : ""}\n` +
      `private key    ${sp("k", "never leaves the authenticator")}\n\n` +
      sp("m", 'Press the button again to log in with it. It is saved as "Crypto 101 demo" in your password manager; delete it there any time.');
  }
  async function pkUse(out, stored) {
    const challenge = L.randBytes(32);
    const cred = await navigator.credentials.get({ publicKey: { challenge, allowCredentials: [], userVerification: "preferred", timeout: 120000 } });
    const r = cred.response, auth = new Uint8Array(r.authenticatorData), cdj = new Uint8Array(r.clientDataJSON), sig = new Uint8Array(r.signature);
    const cd = JSON.parse(L.text(cdj)), id = b64u(new Uint8Array(cred.rawId)), mine = !!stored && stored.id === id;
    let check;
    if (mine && stored.spki && stored.alg === -7) {
      let ok = false;
      try { ok = L.verifyPasskey(fromB64(stored.spki), auth, cdj, sig); } catch (e) { ok = false; }
      check = ok ? sp("ok", "✓ valid, checked with this talk's own P-256 code") : sp("bad", "✗ invalid");
    } else if (mine) check = sp("m", "not an ES256 key, so this demo can't check it");
    else check = sp("m", "a passkey from another visit or device: this browser doesn't have its public key\n               (a real site would look it up in its database)");
    out.innerHTML = `${sp("ok", "LOGGED IN WITH YOUR PASSKEY")}${mine && stored.made ? sp("m", `  (created ${stored.made})`) : ""}\n\n` +
      `credential ID  ${esc(cut(id, 32))}\n` +
      `challenge      ${esc(cut(b64u(challenge), 32))}  ${cd.challenge === b64u(challenge) ? sp("ok", "signed back unchanged") : sp("bad", "different!")}\n` +
      `signed origin  ${esc(cd.origin)}  ${cd.origin === location.origin ? sp("ok", "this site") : sp("bad", "not this site")}\n` +
      `user verified  ${auth[32] & 0x04 ? "yes (fingerprint, face or PIN)" : "no, presence only"}\n` +
      `signature      ${esc(cut(L.hex(sig), 44))}\n` +
      `check          ${check}`;
  }
  async function pkReal() {
    const out = $("pk-out"), btn = $("pk-real");
    if (!window.PublicKeyCredential || !navigator.credentials || !window.isSecureContext) {
      out.innerHTML = `${sp("bad", "Passkeys aren't available here.")}\n${sp("m", "They need a modern browser and an https page, like the live site.")}`;
      return;
    }
    btn.disabled = true; btn.textContent = "Waiting for your device…";
    try {
      const stored = pkLoad();
      if (stored) await pkUse(out, stored); else await pkCreate(out);
    } catch (e) {
      out.innerHTML = e && e.name === "NotAllowedError"
        ? `${sp("m", "Cancelled, timed out, or no passkey was chosen.")}\n${sp("m", "Nothing was created or sent.")}`
        : `${sp("bad", "The browser said: " + esc((e && e.message) || e))}`;
    } finally { btn.disabled = false; pkRealLabel(); }
  }
  function pkForget() {
    pkSave(null); pkRealLabel();
    $("pk-out").innerHTML = `${sp("m", "Forgotten in this browser. The passkey itself stays in your password manager")}\n${sp("m", 'until you delete it there (look for "Crypto 101 demo").')}`;
  }

  // --------------------------------------------------------------------------- randomness (Part 3): a clock-seeded generator vs the secure one
  const lcg = (seed) => { let x = seed >>> 0; return () => (x = (Math.imul(1664525, x) + 1013904223) >>> 0); };
  const lcgKey = (seed) => { const next = lcg(seed), b = new Uint8Array(16), dv = new DataView(b.buffer); for (let i = 0; i < 4; i++) dv.setUint32(4 * i, next()); return b; };
  let rngState = null;
  function rngMake() {
    const seed = Math.floor(Date.now() / 1000), weak = lcgKey(seed), strong = L.randBytes(16), zero = new Uint8Array(16);
    rngState = { seed, weak };
    bitGrid($("rng-weak-grid"), weak, zero);
    bitGrid($("rng-strong-grid"), strong, zero);
    $("rng-weak").innerHTML = `seed  the clock: ${seed}\nkey   ${sp("y", L.hex(weak))}`;
    $("rng-strong").innerHTML = `seed  from the operating system\nkey   ${sp("c", L.hex(strong))}`;
    $("rng-attack").innerHTML = sp("m", "Both keys look like noise. Press the attacker button.");
  }
  function rngGuess() {
    if (!rngState) rngMake();
    const now = Math.floor(Date.now() / 1000), t0 = performance.now();
    let tries = 0, found = null;
    for (let s = now; s > now - 86400; s--) { tries++; if (L.equalBytes(lcgKey(s), rngState.weak)) { found = s; break; } }
    $("rng-attack").innerHTML = (found !== null
      ? `attacker: "it was made today, so try every second since midnight"\n  seed ${found} found after ${fmt(tries)} ${tries === 1 ? "try" : "tries"} (${ago(t0)})  ${sp("bad", "→ the same key")}`
      : sp("m", "The weak key is more than a day old; make a new one.")) +
      `\n\nsecure key: 2^128 possibilities, and no seed to guess  ${sp("ok", "safe")}`;
  }

  // --------------------------------------------------------------------------- end-to-end encryption (Part 5)
  let e2e = null;
  const e2eKey = (point) => L.hmacSha256(enc("e2e demo"), L.fromBig(point[0], 32)).slice(0, 16);
  function safetyNumber(p1, p2) {                      // the same on both phones only if both saw the same two public keys
    const [x, y] = [p1[0], p2[0]].sort((u, v) => (u < v ? -1 : 1));
    const digits = L.toBig(L.sha256(L.concat(L.fromBig(x, 32), L.fromBig(y, 32))).slice(0, 13)).toString().padStart(30, "0").slice(0, 30);
    return digits.match(/.{5}/g).join(" ");
  }
  function e2eSend(swap) {
    const P = L.P256, rnd = () => L.randBelow(P.n - 1n) + 1n, msg = enc($("e2e-msg").value), t0 = performance.now();
    if (!e2e) { const a = rnd(), b = rnd(); e2e = { a, A: P.mul(a), b, B: P.mul(b) }; }
    const { a, A, b, B } = e2e, nonce = L.randBytes(12), short = (u) => cut(L.hex(u), 28);
    let alice, server, bob, aliceSees, bobSees;
    if (!swap) {
      aliceSees = B; bobSees = A;
      const { ct, tag } = L.gcmEncrypt(e2eKey(P.mul(a, B)), nonce, msg);
      const got = L.text(L.gcmDecrypt(e2eKey(P.mul(b, A)), nonce, ct, tag));
      alice = `encrypts with a key only\nshe and Bob share (ECDH)\n${sp("k", short(ct))}`;
      server = `${sp("m", "TLS only:")} ${sp("bad", q(L.text(msg)))}\n${sp("m", "end-to-end:")} ${sp("ok", short(ct))}\n${sp("m", "it just passes this on")}`;
      bob = `decrypts with the same key\n${sp("ok", q(got))}`;
    } else {
      const m = rnd(), M = P.mul(m);                    // the server hands each side its own key instead
      aliceSees = M; bobSees = M;
      const { ct, tag } = L.gcmEncrypt(e2eKey(P.mul(a, M)), nonce, msg);
      const read = L.text(L.gcmDecrypt(e2eKey(P.mul(m, A)), nonce, ct, tag));
      const again = L.gcmEncrypt(e2eKey(P.mul(m, B)), nonce, enc(read));
      const got = L.text(L.gcmDecrypt(e2eKey(P.mul(b, M)), nonce, again.ct, again.tag));
      alice = `encrypts to "Bob's" key\n${sp("bad", "(really the server's)")}\n${sp("k", short(ct))}`;
      server = `swapped both keys, so it\ndecrypts: ${sp("bad", q(read))}\nthen re-encrypts for Bob`;
      bob = `decrypts fine:\n${sp("ok", q(got))}\n${sp("m", "nothing looks wrong")}`;
    }
    $("e2e-alice").innerHTML = alice; $("e2e-server").innerHTML = server; $("e2e-bob").innerHTML = bob;
    const sa = safetyNumber(A, aliceSees), sb = safetyNumber(bobSees, B);
    $("e2e-safety").innerHTML = `safety number on Alice's phone  ${sa}\nsafety number on Bob's phone    ${sb}  ` +
      (sa === sb ? sp("ok", "match: nobody is in the middle") : sp("bad", "DIFFERENT: someone swapped the keys")) + `  ${sp("m", `(${ago(t0)})`)}`;
  }

  // --------------------------------------------------------------------------- checkpoints (slides 9, 16, 25, 32)
  // [question, hint, answer]: answers stay folded away so the room can discuss first
  const CHECKPOINTS = [
    [["Name something you did today that used cryptography. Which of the four goals did it need?", "Logging in, messaging, paying, streaming.",
      "Any https:// page needs confidentiality, integrity and authentication. Logging in adds authentication of you; paying online needs all four, including non-repudiation."],
      ["Why might a website prefer to hash your password instead of encrypting it?", "Who would hold the key if it were encrypted?",
        "If passwords were encrypted, the site would hold the key, so a thief with the database and the key gets every password. A hash lets the site check a password without ever being able to recover it."],
      ["A Caesar cipher has 25 keys. Roughly how many keys would make guessing hopeless?", "How many guesses can a computer make per second?",
        "Computers try billions of keys per second, so you need numbers far beyond that: modern keys have 128 to 256 bits. 2^128 is about 3.4 × 10^38 keys."]],
    [["Two users have the same unsalted password hash. What does an attacker learn?", "Cracking one hash cracks both, and rainbow tables work.",
      "That they chose the same password. Cracking one cracks both, and if it is a common password a pre-computed table reveals it straight away."],
      ["Why is a slow hash good for storing passwords, but bad for checking a big file download?", "Count the hashes an attacker needs versus an honest user.",
        "An honest user hashes once per login, but an attacker must hash once per guess, billions of times, so slowness hurts only the attacker. A file check has no guessing to slow down, so it should be fast."],
      ["Your database leaks, but the pepper stays safe in a vault. What is still protected?", "The attacker has the salts and hashes, but not one ingredient.",
        "The passwords. Without the pepper the attacker cannot even test a guess against the stored hashes."]],
    [["In the padlock picture, why did the outline survive ECB encryption?", "What happens to blocks that hold identical data?",
      "ECB encrypts every 16-byte block on its own with the same key, so identical blocks (the flat colours) give identical ciphertext and the shapes stay visible."],
      ["What could go wrong if you reuse a nonce with the same key?", "Think back to the one-time pad: a key used twice.",
        "The scrambled stream repeats, so combining two ciphertexts cancels it out and leaks the messages, just like a reused one-time pad. With GCM it also lets attackers forge tags."],
      ["AES needs both sides to share a secret key. How could two strangers agree on one safely?", "This puzzle leads into the next part.",
        "With asymmetric cryptography: a key exchange such as ECDH, or by locking the key with the other person's public key."]],
    [["Why do real systems use RSA or ECC to share a key, then AES for the data?", "Compare speed and key sharing in the earlier table.",
      "Asymmetric crypto solves sharing a key with a stranger but is slow; AES is fast but needs a shared key. Use each for what it does best. That is exactly what TLS does."],
      ["Alice signs with her private key. Why can anyone check it, but nobody forge it?", "Who has the private key? Who has the public key?",
        "Checking needs only the public key, which everyone has. Making a signature needs the private key, and working it out from the public key is the hard puzzle (factoring or curve maths)."],
      ["Your browser connects to a bank. What can an eavesdropper see, and what stays secret?", "Think about ECDH: what is public, what is private?",
        "They see which site you contact, its certificate, the public key-exchange values, and the size and timing of the traffic. The shared key, the pages, your cookies and your password stay secret."]],
  ];
  function checkpoints() {
    document.querySelectorAll(".checkpoint[data-cp]").forEach((el) => {
      el.innerHTML = CHECKPOINTS[+el.dataset.cp].map(([qq, hint, answer]) =>
        `<li><p>${esc(qq)}</p><details><summary>Hint</summary><p>${esc(hint)}</p></details>` +
        `<details class="answer"><summary>Answer</summary><p>${esc(answer)}</p></details></li>`).join("");
    });
  }

  // --------------------------------------------------------------------------- key exchange with paint (slide 30)
  // a pot of paint is a list of pigments; its colour is their average
  const hexRgb = (h) => [1, 3, 5].map((i) => parseInt(h.slice(i, i + 2), 16));
  const mix = (...pots) => { const all = pots.flat(); return [0, 1, 2].map((c) => Math.round(all.reduce((s, p) => s + p[c], 0) / all.length)); };
  const swatch = (rgb, label, cls = "") => `<figure class="swatch ${cls}"><i style="background:rgb(${rgb.join(",")})"></i><figcaption>${label}</figcaption></figure>`;
  function paint() {
    const P = [hexRgb($("paint-p").value)], a = [hexRgb($("paint-a").value)], b = [hexRgb($("paint-b").value)];
    const A = [...P, ...a], B = [...P, ...b];
    const sa = mix(B, a), sb = mix(A, b), eve = mix(A, B);
    const same = sa.every((v, i) => v === sb[i]);
    $("paint").innerHTML =
      `<div class="paint-col"><b>Alice</b>${swatch(mix(a), "1 · her secret colour")}${swatch(mix(A), "2 · mixes it into the starting paint: A")}${swatch(sa, "3 · adds her secret to Bob's pot", "final")}</div>` +
      `<div class="paint-col wire"><b>Public · Eve sees all of this</b>${swatch(mix(P), "starting paint")}<div class="pair">${swatch(mix(A), "A")}${swatch(mix(B), "B")}</div>${swatch(eve, "Eve mixes A + B: wrong colour", "eve")}</div>` +
      `<div class="paint-col"><b>Bob</b>${swatch(mix(b), "1 · his secret colour")}${swatch(mix(B), "2 · mixes it into the starting paint: B")}${swatch(sb, "3 · adds his secret to Alice's pot", "final")}</div>` +
      `<p class="paint-verdict">${same ? '<span class="ok">Alice and Bob end up with the same colour.</span>' : ""} Eve's pot has the starting paint in it twice, so it never matches.</p>`;
  }
  const randHex = () => "#" + Array.from(L.randBytes(3), (x) => x.toString(16).padStart(2, "0")).join("");

  // --------------------------------------------------------------------------- avalanche (slide 10)
  function bitGrid(el, a, b) { el.innerHTML = L.bits(L.xor(a, b)).split("").map((x) => `<i class="${x === "1" ? "on" : ""}"></i>`).join(""); }
  function avalanche() {
    const b = enc($("av-in").value), slider = $("av-bit");
    if (!b.length) { $("av-out").textContent = "Type something to hash."; $("av-grid").innerHTML = ""; $("av-count").textContent = ""; return; }
    slider.max = b.length * 8 - 1;
    const i = Math.min(+slider.value, b.length * 8 - 1);
    $("av-bit-out").textContent = i;
    const f = b.slice(), byte = i >> 3; f[byte] ^= 0x80 >> (i & 7);
    const ha = L.sha256(b), hb = L.sha256(f), d = L.bitDiff(ha, hb);
    const bitsWithMark = (x) => x.toString(2).padStart(8, "0").split("").map((c, j) => (j === (i & 7) ? sp("k", c) : c)).join("");
    $("av-out").innerHTML = `byte ${byte} (${esc(q(String.fromCharCode(b[byte])))}): ${bitsWithMark(b[byte])} → ${bitsWithMark(f[byte])}\n\n` +
      `sha256(original) = ${L.hex(ha)}\nsha256(flipped)  = ${[...L.hex(hb)].map((c, j) => (c !== L.hex(ha)[j] ? sp("k", c) : c)).join("")}`;
    bitGrid($("av-grid"), ha, hb);
    $("av-count").innerHTML = `<b>${d} of 256</b> output bits changed (${(d / 2.56).toFixed(0)}%). Each lit square is a flipped output bit.`;
  }

  // --------------------------------------------------------------------------- SHA-256 rounds (slide 11)
  function sha() {
    const s = $("sha-in").value, b = enc(s), padded = L.sha256Pad(b), trace = [], r = +$("sha-round").value;
    $("sha-round-out").textContent = r;
    const digest = L.sha256(b, trace), n = padded.length;
    $("sha-block").innerHTML = Array.from(padded.subarray(0, 64), (x, i) => {
      const cls = i < b.length ? "b-msg" : i === b.length ? "b-80" : i >= n - 8 ? "b-len" : "";
      return `<span class="${cls}">${x.toString(16).padStart(2, "0")}</span>`;
    }).join("");
    const names = "abcdefgh", cur = trace[r], prev = trace[Math.max(0, r - 1)];
    $("sha-regs").innerHTML = cur.map((v, i) => `<div class="${r > 0 && v !== prev[i] ? "chg" : ""}"><b>${names[i]}</b>${v.toString(16).padStart(8, "0")}</div>`).join("");
    const next = s ? s.slice(0, -1) + String.fromCharCode(s.charCodeAt(s.length - 1) + 1) : "";
    const d2 = L.sha256(enc(next));
    $("sha-out").innerHTML =
      `input      ${esc(q(s))}\nas bytes   ${esc(cut(L.hex(b, " "), 60)) || sp("m", "(none)")}\n` +
      `padded     ${n * 8} bits = ${n / 64} chunk${n > 64 ? "s (the grid shows chunk 1)" : ""} · 64 rounds per chunk\n` +
      (r === 0 ? `round 0    ${sp("m", "the 8 values start as fixed constants (the IV)")}\n` : r < 64 ? `round ${r}   ${sp("m", "shift, flip and add bits to scramble")}\n` : `round 64   ${sp("m", "add the starting values back in, and the 8 values are the hash")}\n`) +
      `\nSHA-256    ${sp("y", L.hex(digest))}` +
      (s ? `\n${esc(q(next)).padEnd(10)} ${L.hex(d2)}  ${sp("m", `${L.bitDiff(digest, d2)} bits differ`)}` : "");
  }

  // --------------------------------------------------------------------------- collisions and algorithms (slide 12)
  async function collision() {
    const nb = +$("col-bits").value, seen = new Map(), t0 = performance.now();
    for (let tries = 1; ; tries++) {
      const m = "msg" + tries, h = L.sha256(enc(m));
      const t = (((h[0] << 24) | (h[1] << 16) | (h[2] << 8) | h[3]) >>> 0) >>> (32 - nb);
      if (seen.has(t)) {
        const other = seen.get(t), hx = L.hex(h), ho = L.hex(L.sha256(enc(other))), keep = Math.ceil(nb / 4);
        $("col-out").innerHTML = `collision after ${sp("y", fmt(tries))} tries (${ago(t0)}):\n` +
          `  sha256(${q(other).padEnd(11)}) = ${sp("k", ho.slice(0, keep))}${ho.slice(keep, 24)}…\n  sha256(${q(m).padEnd(11)}) = ${sp("k", hx.slice(0, keep))}${hx.slice(keep, 24)}…\n` +
          `same first ${nb} bits.\n\nexpected about 2^(${nb}/2) = ${sp("c", fmt(Math.round(2 ** (nb / 2))))} tries, not 2^${nb} = ${fmt(2 ** nb)}.\n` +
          `a full SHA-256 needs ~2^128 tries: out of reach.\nMD5 and SHA-1 had flaws that made collisions cheap.`;
        return;
      }
      seen.set(t, m);
      if (tries % 4000 === 0) await wait();
    }
  }
  let algToken = 0;
  async function algorithms() {
    const token = ++algToken, s = $("alg-in").value, b = enc(s);
    const subtle = window.crypto && window.crypto.subtle;
    const viaSubtle = (name) => (subtle ? subtle.digest(name, b).then((d) => L.hex(new Uint8Array(d))) : Promise.reject(new Error("no Web Crypto")));
    const rows = [
      ["MD5", 128, "bad", () => (HW ? HW.md5(b) : Promise.reject())],
      ["SHA-1", 160, "bad", () => (HW ? HW.sha1(b) : viaSubtle("SHA-1"))],
      ["SHA-256", 256, "ok", async () => L.hex(L.sha256(b))],
      ["SHA-512", 512, "ok", () => (HW ? HW.sha512(b) : viaSubtle("SHA-512"))],
      ["SHA3-256", 256, "ok", () => (HW ? HW.sha3(b, 256) : Promise.reject())],
      ["BLAKE2b", 256, "ok", () => (HW ? HW.blake2b(b, 256) : Promise.reject())],
    ];
    const draw = (out) => {
      $("alg-table").innerHTML = "<tbody>" + rows.map(([name, bitsN, verdict], i) =>
        `<tr><th>${name}${verdict === "bad" ? ' <span class="tag tag-bad">broken</span>' : ""}</th><td class="bits">${bitsN} bits</td>` +
        `<td>${out[i] ? esc(cut(out[i], 64)) : out[i] === undefined ? '<span class="m">computing…</span>' : '<span class="m">not available in this browser</span>'}</td></tr>`).join("") + "</tbody>";
    };
    draw(rows.map(([name]) => (name === "SHA-256" ? L.hex(L.sha256(b)) : undefined)));
    const out = await Promise.all(rows.map(([, , , f]) => f().catch(() => null)));
    if (token === algToken) draw(out);
  }

  // --------------------------------------------------------------------------- salt and pepper (slide 13)
  const COMMON = ["123456", "password", "qwerty", "letmein", "dragon", "monkey", "sunshine", "iloveyou", "admin", "welcome"];
  const PEPPER = enc("app-secret-kept-in-a-vault");
  let saltA = L.randBytes(8), saltB = L.randBytes(8);
  function salt() {
    const pw = enc($("salt-pw").value), H = (...p) => L.hex(L.sha256(L.concat(...p)));
    const table = new Map(COMMON.map((w) => [H(enc(w)), w]));
    const plain = H(pw), cracked = table.get(plain);
    $("salt-none").innerHTML = `stored = sha256(password)\n\nalice ${cut(plain, 24)}\nbob   ${cut(plain, 24)}\n${sp("bad", "same hash → same password")}\n\n` +
      `attacker's pre-computed table:\n${cracked ? sp("bad", `cracked: ${q(cracked)}`) : sp("m", "not in this tiny table, but real\nrainbow tables hold billions")}` +
      passwordEgg($("salt-pw").value);
    const sa = H(saltA, pw), sb = H(saltB, pw);
    $("salt-salt").innerHTML = `stored = salt + hash(salt + password)\n\nalice ${sp("c", L.hex(saltA))} ${cut(sa, 12)}\nbob   ${sp("c", L.hex(saltB))} ${cut(sb, 12)}\n${sp("ok", "different hashes")}\n\n` +
      `table lookup: ${table.has(sa) ? sp("bad", "match") : sp("ok", "no match")}\nthe attacker must crack each\nuser separately.`;
    const stored = H(saltA, PEPPER, pw);
    $("salt-pepper").innerHTML = `stored = salt + hash(salt + pepper + password)\n\nalice ${sp("c", L.hex(saltA))} ${cut(stored, 12)}\n\n` +
      `attacker has the database but\nno pepper. can they check a guess?\n  ${H(saltA, pw) === stored ? sp("bad", "yes") : sp("ok", "no")}\n` +
      `the server has the pepper:\n  ${H(saltA, PEPPER, pw) === stored ? sp("ok", "password checks out") : sp("bad", "no")}`;
  }

  // --------------------------------------------------------------------------- slow hashing (slides 14-15)
  async function bench() {
    const cell = (k, v) => (document.querySelector(`[data-bench="${k}"]`).innerHTML = v);
    const status = $("bench-status"), pw = enc("correct horse"), saltB = L.randBytes(16);
    const time = async (f) => { const t = performance.now(); await f(); return performance.now() - t; };
    const ms = (x) => (x < 1 ? `${(x * 1000).toFixed(1)} µs` : x < 1000 ? `${x.toFixed(0)} ms` : `${(x / 1000).toFixed(2)} s`);
    ["sha256", "pbkdf2", "bcrypt", "scrypt", "argon2"].forEach((k) => cell(k, "…"));
    status.textContent = "Timing SHA-256…";
    const t = await time(async () => { for (let i = 0; i < 2000; i++) L.sha256(pw); });
    cell("sha256", `${ms(t / 2000)} per hash`);
    status.textContent = "Timing PBKDF2 with 600,000 repeats…"; await wait(30);
    try {
      const key = await crypto.subtle.importKey("raw", pw, "PBKDF2", false, ["deriveBits"]);
      cell("pbkdf2", ms(await time(() => crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: saltB, iterations: 600000 }, key, 256))));
    } catch { cell("pbkdf2", '<span class="m">unavailable</span>'); }
    if (!HW) {
      ["bcrypt", "scrypt", "argon2"].forEach((k) => cell(k, '<span class="m">unavailable</span>'));
      status.textContent = "bcrypt, scrypt and Argon2id need WebAssembly, which this browser blocked."; return;
    }
    try {
      status.textContent = "Timing bcrypt…"; await wait(30);
      const r = [];
      for (const cost of [10, 12]) r.push(`cost ${cost}: ${ms(await time(() => HW.bcrypt({ password: pw, salt: saltB, costFactor: cost, outputType: "encoded" })))}`);
      cell("bcrypt", r.join("<br>"));
      status.textContent = "Timing scrypt…"; await wait(30);
      cell("scrypt", `${ms(await time(() => HW.scrypt({ password: pw, salt: saltB, costFactor: 2 ** 14, blockSize: 8, parallelism: 1, hashLength: 32 })))}<br><span class="m">16 MiB</span>`);
      status.textContent = "Timing Argon2id…"; await wait(30);
      cell("argon2", `${ms(await time(() => HW.argon2id({ password: pw, salt: saltB, iterations: 2, parallelism: 1, memorySize: 19456, hashLength: 32 })))}<br><span class="m">19 MiB, 2 passes</span>`);
      status.textContent = "Done. Each password guess costs an attacker this much time too.";
    } catch (e) { status.textContent = "Could not finish: " + e.message; }
  }
  function crack() {
    const a = Math.max(2, Math.min(100, +$("crack-alpha").value || 36)), n = Math.max(1, Math.min(30, +$("crack-len").value || 8)), total = a ** n;
    $("crack-out").innerHTML =
      `<div class="stat"><b>${bigWords(total)}</b><span>possible passwords to try (${a}<sup>${n}</sup>)</span></div>` +
      `<div class="stat fast"><b>~${duration(total / 1e10)}</b><span>fast hash: 10 billion guesses per second</span></div>` +
      `<div class="stat slow"><b>~${duration(total / 1e4)}</b><span>tuned Argon2id: 10,000 guesses per second</span></div>`;
  }

  // --------------------------------------------------------------------------- XOR (slide 17)
  let xorKey = 0b00111010;                            // the slide's key
  function xor() {
    let ch = $("xor-ch").value || "H";
    if (ch.charCodeAt(0) > 126 || ch.charCodeAt(0) < 32) ch = "H";
    const p = ch.charCodeAt(0), c = p ^ xorKey, b = (x) => x.toString(2).padStart(8, "0");
    const shown = (x) => (x >= 32 && x < 127 ? `"${String.fromCharCode(x)}"` : `byte ${x}`);
    const row = (cls, label, x, note) => `<div class="xor-row ${cls}"><b>${label}</b>${[...b(x)].map((d, i) => `<span class="${d === "1" ? "one" : ""}" data-i="${i}">${d}</span>`).join("")}<em>${esc(note)}</em></div>`;
    $("xor-rows").innerHTML = row("", "P", p, `letter ${ch}`) + row("key", "K", xorKey, "the key: click a bit") + row("res", "C=P^K", c, `scrambled: ${shown(c)}`) + row("", "C^K", c ^ xorKey, `${ch} again`);
  }

  // --------------------------------------------------------------------------- AES (slides 19-20)
  const FIPS_KEY = "000102030405060708090a0b0c0d0e0f", FIPS_PT = "00112233445566778899aabbccddeeff";
  let aesTrace = [], aesRk = [], aesOk = { key: L.fromHex(FIPS_KEY), pt: L.fromHex(FIPS_PT) };
  const STEP_DESC = {
    Plaintext: "The 16 input bytes fill the 4 × 4 grid column by column.",
    AddRoundKey: "The block is combined (XOR) with the round key. This is the only step that uses the key.",
    SubBytes: "Each byte is swapped using a fixed lookup table (the S-box). This hides patterns: confusion.",
    ShiftRows: "Rows slide sideways by different amounts (row 0 by 0, row 1 by 1, row 2 by 2, row 3 by 3), so bytes move between columns.",
    MixColumns: "Each column is blended so every byte affects its neighbours: diffusion.",
  };
  function aesInput() {
    const k = $("aes-key").value.trim(), p = $("aes-pt").value.trim(), ok = (h) => /^[0-9a-fA-F]{32}$/.test(h);
    if (!ok(k) || !ok(p)) err("aes-err", "Key and plaintext must each be exactly 32 hex digits (0–9, a–f).");
    else { err("aes-err"); aesOk = { key: L.fromHex(k), pt: L.fromHex(p) }; }
    aesRk = L.expandKey(aesOk.key); aesTrace = [];
    const ct = L.aesBlock(aesOk.pt, aesRk, aesTrace);
    const fips = L.hex(aesOk.key) === FIPS_KEY && L.hex(aesOk.pt) === FIPS_PT;
    $("aes-final").dataset.ct = L.hex(ct); $("aes-final").dataset.fips = fips ? "1" : "";
    aesStep();
    const a = new Uint8Array(16), b = new Uint8Array(16); b[15] = 1;
    const ca = L.aesBlock(a, aesRk), cb = L.aesBlock(b, aesRk);
    $("aes-aval").innerHTML = `input A   ${L.hex(a)}\ninput B   ${L.hex(b)}  ${sp("m", "← 1 bit differs")}\n\n` +
      `output A  ${L.hex(ca)}\noutput B  ${L.hex(cb)}\n${sp("k", `${L.bitDiff(ca, cb)} of 128`)} output bits differ`;
    bitGrid($("aes-aval-grid"), ca, cb);
  }
  function aesStep() {
    const i = +$("aes-step").value, s = aesTrace[i], prev = aesTrace[Math.max(0, i - 1)];
    $("aes-step-out").textContent = i;
    let cells = "";
    for (let r = 0; r < 4; r++) for (let c = 0; c < 4; c++) {
      const j = r + 4 * c;
      cells += `<span class="${i > 0 && s.state[j] !== prev.state[j] ? "chg" : ""}"><small>b${j}</small>${s.state[j].toString(16).padStart(2, "0")}</span>`;
    }
    $("aes-grid").innerHTML = cells;
    $("aes-step-name").textContent = s.step === "Plaintext" ? "Start: plaintext" : `Round ${s.round} · ${s.step}`;
    $("aes-step-desc").textContent = STEP_DESC[s.step] + (s.round === 10 && s.step === "ShiftRows" ? " The last round skips MixColumns." : "");
    const f = $("aes-final");
    f.innerHTML = (s.step === "AddRoundKey" ? `round key ${s.round}: ${L.hex(aesRk[s.round])}\n` : "") +
      (i === aesTrace.length - 1 ? `ciphertext   ${sp("y", f.dataset.ct)}` + (f.dataset.fips ? `\n${sp("ok", "✓ matches the official FIPS-197 test vector")}` : "") : `${sp("m", `step ${i} of ${aesTrace.length - 1}`)}`);
  }
  function aesChecks() {
    const mc = L.mixColumns([0xdb, 0x13, 0x53, 0x45, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).slice(0, 4);
    const hx = (x) => x.toString(16).toUpperCase().padStart(2, "0");
    $("aes-checks").innerHTML =
      `1. SubBytes     0x53  →  0x${sp("y", hx(L.SBOX[0x53]))}\n` +
      `2. ShiftRows    row 1: a b c d  →  b c d a\n` +
      `3. MixColumns   DB 13 53 45  →  ${sp("y", mc.map(hx).join(" "))}\n` +
      `4. AddRoundKey  0x8E ^ 0x2B = 0x${sp("y", hx(0x8e ^ 0x2b))}\n\n` +
      `AES-128: 10 rounds · AES-192: 12 · AES-256: 14`;
  }

  // --------------------------------------------------------------------------- modes (slide 21)
  let modeKey = L.randBytes(16), modeIv = L.randBytes(16), modeNonce = L.randBytes(12);
  const BLOCK_COLORS = ["--pink", "--cyan", "--yellow", "--ok", "--bad"];
  function modes() {
    const data = enc($("modes-msg").value), padded = L.pad(data);
    const ptBlocks = L.chunks(padded), ecb = L.chunks(L.aesEcb(modeKey, padded)), cbc = L.chunks(L.aesCbc(modeKey, modeIv, data));
    const counts = new Map(); ecb.forEach((b) => counts.set(L.hex(b), (counts.get(L.hex(b)) || 0) + 1));
    const color = new Map(); let ci = 0;
    const label = (p) => q(L.text(p).replace(/[\x00-\x1f]/g, "·"));
    $("modes-ecb").innerHTML = ecb.map((b, i) => {
      const h = L.hex(b), rep = counts.get(h) > 1;
      if (rep && !color.has(h)) color.set(h, css(BLOCK_COLORS[ci++ % BLOCK_COLORS.length]));
      return `<span class="${rep ? "rep" : ""}" style="${rep ? `border-color:${color.get(h)};color:${color.get(h)}` : ""}"><em>${esc(label(ptBlocks[i]))}</em>${h}</span>`;
    }).join("");
    $("modes-cbc").innerHTML = cbc.map((b, i) => `<span><em>${esc(label(ptBlocks[i]))}</em>${L.hex(b)}</span>`).join("");
    const aad = enc("header"), { ct, tag } = L.gcmEncrypt(modeKey, modeNonce, data, aad);
    const t2 = L.gcmEncrypt(new Uint8Array(16), new Uint8Array(12), new Uint8Array(16));
    const repeats = [...counts.values()].some((n) => n > 1);
    $("modes-gcm").innerHTML = `ciphertext ${esc(cut(L.hex(ct), 64))}\ntag        ${L.hex(tag)}  ${sp("m", "← the tamper check")}\n` +
      `decrypts   ${esc(q(L.text(L.gcmDecrypt(modeKey, modeNonce, ct, tag, aad))))}\n` +
      `${L.hex(t2.ct) === "0388dace60b6a392f328c2b971b2fe78" && L.hex(t2.tag) === "ab6e47d42cec13bdf53a67b21257bddf" ? sp("ok", "✓ matches the NIST GCM test vector") : sp("bad", "✗ test vector mismatch")}` +
      `\n\n${repeats ? sp("k", "ECB: identical plaintext blocks gave identical ciphertext blocks (same color). Patterns leak.") : sp("m", "Tip: repeat a 16-character chunk to see ECB leak.")}\n${sp("c", "CBC: each block is mixed with the previous one first, so repeats look different.")}`;
  }

  // --------------------------------------------------------------------------- ECB padlock (slides 22-23)
  let padPixels = null;
  function padDraw() {
    const cv = $("pad-orig"), g = cv.getContext("2d"), W = cv.width, H = cv.height;
    g.fillStyle = "#1c1745"; g.fillRect(0, 0, W, H);
    g.strokeStyle = "#00f0ff"; g.lineWidth = 16; g.beginPath(); g.arc(W / 2, 64, 36, Math.PI, 0); g.lineTo(W / 2 + 36, 74); g.moveTo(W / 2 - 36, 64); g.lineTo(W / 2 - 36, 74); g.stroke();
    g.fillStyle = "#ff2e88"; g.fillRect(W / 2 - 66, 72, 132, 76);
    g.fillStyle = "#f6e94b"; g.font = "bold 26px 'JetBrains Mono', monospace"; g.textAlign = "center"; g.textBaseline = "middle"; g.fillText("SECRET", W / 2, 112);
    padPixels = new Uint8Array(g.getImageData(0, 0, W, H).data);   // 4 bytes per pixel, so each 16-byte block is exactly 4 pixels
  }
  function padShow(id, bytes) {                       // paint each encrypted 16-byte block (4 pixels) as one colour
    const cv = $(id), g = cv.getContext("2d"), img = g.createImageData(cv.width, cv.height), d = img.data;
    for (let b = 0; b < d.length; b += 16) for (let p = b; p < b + 16; p += 4) { d[p] = bytes[b]; d[p + 1] = bytes[b + 1]; d[p + 2] = bytes[b + 2]; d[p + 3] = 255; }
    g.putImageData(img, 0, 0);
  }
  function padEncrypt() {                             // ~150 ms of AES over 9,600 blocks
    if (!padPixels) padDraw();
    const key = L.randBytes(16);
    padShow("pad-ecb", L.aesEcb(key, padPixels));
    padShow("pad-cbc", L.aesCbc(key, L.randBytes(16), padPixels, false));
  }

  // --------------------------------------------------------------------------- tampering and nonce reuse (slides 22, 24)
  const tKey = L.randBytes(16), tNonce = L.randBytes(12);
  function tamper() {
    const from = enc($("tamp-from").value), to = enc($("tamp-to").value);
    if (from.length !== to.length) {
      err("tamp-err", `Keep both messages the same length (${from.length} vs ${to.length} bytes), so Mallory can flip bits in place.`);
      $("tamp-ctr").textContent = $("tamp-gcm").textContent = ""; return;
    }
    err("tamp-err");
    const delta = L.xor(from, to), flips = [...delta].filter(Boolean).length;
    const icb = L.concat(tNonce, Uint8Array.of(0, 0, 0, 1)), c = L.ctrCrypt(L.expandKey(tKey), icb, from), forged = L.xor(c, delta);
    const mallory = `Mallory XORs in ${esc(q(L.text(from)))} ⊕ ${esc(q(L.text(to)))}\n  ${sp("m", `(she only flips bits in the ${flips} byte${flips === 1 ? "" : "s"} that differ)`)}\n`;
    $("tamp-ctr").innerHTML = `Alice sends  ${esc(q(L.text(from)))}\non the wire  ${cut(L.hex(c), 32)}\n\n${mallory}\n` +
      `Bob decrypts ${sp("bad", q(L.text(L.ctrCrypt(L.expandKey(tKey), icb, forged))))}\n${flips ? sp("bad", "ACCEPTED: no tamper check") : sp("m", "nothing changed")}`;
    const { ct, tag } = L.gcmEncrypt(tKey, tNonce, from), fg = L.xor(ct, delta);
    let verdict;
    try { verdict = sp("ok", `accepted: ${q(L.text(L.gcmDecrypt(tKey, tNonce, fg, tag)))}`) + (flips ? "" : sp("m", "  (nothing changed)")); }
    catch (e) { verdict = `Bob recomputes the tag: ${sp("ok", "no match, message REJECTED")}`; }
    $("tamp-gcm").innerHTML = `Alice sends  ${esc(q(L.text(from)))}\nciphertext   ${cut(L.hex(ct), 32)}\ntag          ${L.hex(tag).slice(0, 24)}…  ${sp("m", "(16 bytes)")}\n\n${mallory}\n${verdict}`;

    const m1 = enc("Pay Bob $100"), m2 = enc("Meet at noon"), rk = L.expandKey(tKey);
    const c1 = L.ctrCrypt(rk, icb, m1), c2 = L.ctrCrypt(rk, icb, m2);
    $("tamp-reuse").innerHTML = `two messages, the SAME key and nonce:\nc1 ⊕ c2 = ${sp("k", L.hex(L.xor(c1, c2)))}\nm1 ⊕ m2 = ${sp("k", L.hex(L.xor(m1, m2)))}  ${sp("m", "← the secret stream cancelled out")}\n` +
      `attacker knows m1 "Pay Bob $100" → recovers m2: ${sp("bad", q(L.text(L.xor(L.xor(c1, c2), m1))))}`;
  }

  // --------------------------------------------------------------------------- RSA vs ECC key sizes (slide 26)
  function keybars() {
    const rows = [[112, 2048, 224], [128, 3072, 256], [192, 7680, 384], [256, 15360, 512]];
    $("keybars").innerHTML = rows.map(([s, r, e]) =>
      `<div class="keybar"><b>${s}-bit</b><div><i class="r" style="width:${(r / 15360) * 100}%"></i><small>RSA ${fmt(r)} bits</small>` +
      `<i class="e" style="width:${(e / 15360) * 100}%"></i><small>ECC ${e} bits</small></div></div>`).join("") +
      `<p class="note">Security level on the left. ECC 256 ≈ RSA 3072.</p>`;
  }

  // --------------------------------------------------------------------------- RSA (slides 27-28)
  const bigOf = (id) => { const v = $(id).value.trim(); return /^\d{1,40}$/.test(v) ? BigInt(v) : null; };
  function rsa() {
    const p = bigOf("rsa-p"), qq = bigOf("rsa-q"), e = bigOf("rsa-e"), m = bigOf("rsa-m");
    const steps = [], bad = (s) => `<span class="bad">${esc(s)}</span>`;
    const finish = (extra = "") => { $("rsa-steps").innerHTML = steps.map((s) => `<li>${s}</li>`).join(""); $("rsa-run").innerHTML = extra; $("rsa-flaws").innerHTML = ""; };
    if (p === null || qq === null || e === null || m === null) { steps.push(bad("Use whole numbers only.")); return finish(); }
    if (!L.isPrime(p) || !L.isPrime(qq)) { steps.push(bad(`${!L.isPrime(p) ? p : qq} is not prime. Try 61 and 53, or 11 and 17.`)); return finish(); }
    if (p === qq) { steps.push(bad("p and q must be different primes.")); return finish(); }
    const n = p * qq, phi = (p - 1n) * (qq - 1n);
    steps.push(`<span class="lbl">Pick two prime numbers.</span> p = ${p}, q = ${qq}. Multiply them: n = <span class="y">${n}</span>`);
    steps.push(`<span class="lbl">Work out a helper number.</span> (p − 1)(q − 1) = ${p - 1n} × ${qq - 1n} = ${phi}`);
    if (e < 2n || e >= phi || L.gcd(e, phi) !== 1n) { steps.push(bad(`e = ${e} must be between 2 and ${phi - 1n} and share no factors with ${phi}. Try 17, 7 or 65537.`)); return finish(); }
    const d = L.modInv(e, phi);
    steps.push(`<span class="lbl">Pick the public number e.</span> e = ${e} (shares no factors with ${phi}). Public key = <span class="c">(${n}, ${e})</span>`);
    steps.push(`<span class="lbl">Find the private number d.</span> d = <span class="k">${d}</span>, because ${e} × ${d} = ${e * d} = 1 + ${(e * d - 1n) / phi} × ${phi}`);
    if (m >= n) { $("rsa-steps").innerHTML = steps.map((s) => `<li>${s}</li>`).join(""); $("rsa-run").innerHTML = sp("bad", `The message must be smaller than n = ${n}.`); $("rsa-flaws").innerHTML = ""; return; }
    const c = L.modPow(m, e, n);
    $("rsa-steps").innerHTML = steps.map((s) => `<li>${s}</li>`).join("");
    $("rsa-run").innerHTML = `message   m = ${sp("c", m)}\nencrypt   c = m^e mod n = ${m}^${e} mod ${n} = ${sp("y", c)}\ndecrypt   m = c^d mod n = ${c}^${d} mod ${n} = ${sp("c", L.modPow(c, d, n))}`;
    const a = 7n, b = 11n;
    $("rsa-flaws").innerHTML = `${sp("k", "Predictable")}  encrypting ${m} again gives ${L.modPow(m, e, n)} every time, so guesses can be checked\n` +
      (a * b < n ? `${sp("k", "Malleable")}    E(${a}) × E(${b}) mod n = ${(L.modPow(a, e, n) * L.modPow(b, e, n)) % n} = E(${a * b}) = ${L.modPow(a * b, e, n)}\n             an attacker can multiply encrypted messages without the key\n` : "") +
      `${sp("k", "Short messages")} if m^e is smaller than n, just take the e-th root (try the button)`;
  }
  async function rsaSmallM() {
    const t0 = performance.now(), k = L.rsaKeygen(256, 3n), m = 1000n, c = L.modPow(m, 3n, k.n), root = L.iroot(c, 3);
    $("rsa-big").innerHTML = `key: n has ${k.n.toString(2).length} bits, e = 3  ${sp("m", `(${ago(t0)})`)}\n` +
      `message m = 1000\nc = m^3 mod n = ${c}   ${sp("m", "← m^3 is smaller than n, so nothing wrapped around")}\n` +
      `attacker takes the cube root of c: ${sp("bad", root)}  ${sp("m", "no private key needed")}`;
  }
  async function rsaGenerate() {
    const t0 = performance.now(), k = L.rsaKeygen(1024), took = ago(t0);
    const msg = "Pay Bob $100", m = L.toBig(enc(msg)), c = L.modPow(m, k.e, k.n), back = L.text(L.fromBig(L.modPow(c, k.d, k.n), enc(msg).length));
    $("rsa-big").innerHTML = `generated two 1024-bit primes in ${took}\nn  = ${cut(k.n.toString(16), 48)}  ${sp("y", `(${k.n.toString(2).length} bits, ${k.n.toString().length} digits)`)}\n` +
      `e  = ${k.e}\nround trip of ${q(msg)}: ${sp("ok", q(back))}\n${sp("m", "Factoring this n is far beyond any computer today.")}`;
  }

  // --------------------------------------------------------------------------- elliptic curves (slide 29)
  /** Size a canvas's pixels to how big it really is on screen, so graphs stay sharp at any zoom.
      Drawing code keeps using the canvas's original width/height as its coordinate system. */
  function sharp(cv) {
    if (!cv.dataset.w) { cv.dataset.w = cv.width; cv.dataset.h = cv.height; }
    const W = +cv.dataset.w, H = +cv.dataset.h, shown = cv.getBoundingClientRect().width;
    const k = Math.min(4, Math.max(1, (shown ? shown / W : 1) * (window.devicePixelRatio || 1)));
    const bw = Math.round(W * k), bh = Math.round(H * k);
    if (cv.width !== bw || cv.height !== bh) { cv.width = bw; cv.height = bh; }
    const g = cv.getContext("2d");
    g.setTransform(bw / W, 0, 0, bh / H, 0, 0);
    return { g, W, H };
  }
  function eccReal() {
    const { g, W, H } = sharp($("ecc-real"));
    const X0 = -2.2, X1 = 3.2, Y0 = -4.6, Y1 = 4.6;
    const sx = (x) => ((x - X0) / (X1 - X0)) * W, sy = (y) => H - ((y - Y0) / (Y1 - Y0)) * H;
    const f = (x) => x ** 3 - x + 1, ROOT = -1.324718;
    g.fillStyle = css("--void"); g.fillRect(0, 0, W, H);
    g.strokeStyle = css("--line"); g.lineWidth = 1; g.beginPath(); g.moveTo(0, sy(0)); g.lineTo(W, sy(0)); g.moveTo(sx(0), 0); g.lineTo(sx(0), H); g.stroke();
    g.strokeStyle = css("--cyan"); g.lineWidth = 2.5; g.beginPath();
    const xs = []; for (let t = 0; t <= 1; t += 0.002) xs.push(ROOT + (X1 - ROOT) * t * t);
    xs.forEach((x, i) => { const y = Math.sqrt(Math.max(0, f(x))); i ? g.lineTo(sx(x), sy(y)) : g.moveTo(sx(x), sy(y)); });
    g.moveTo(sx(ROOT), sy(0));
    xs.forEach((x) => g.lineTo(sx(x), sy(-Math.sqrt(Math.max(0, f(x))))));
    g.stroke();
    g.fillStyle = css("--muted"); g.font = "13px 'JetBrains Mono', monospace"; g.fillText("y² = x³ − x + 1", 10, 20);

    const pt = (xid, nid) => { const x = +$(xid).value, y = Math.sqrt(Math.max(0, f(x))); return [x, $(nid).checked ? -y : y]; };
    const P = pt("ecc-px", "ecc-pneg"), Q = pt("ecc-qx", "ecc-qneg");
    const dot = (p, color, label, r = 6) => { g.fillStyle = color; g.beginPath(); g.arc(sx(p[0]), sy(p[1]), r, 0, 7); g.fill(); g.font = "bold 14px 'Chakra Petch', sans-serif"; g.fillText(label, sx(p[0]) + 9, sy(p[1]) - 9); };
    const fx = (v) => v.toFixed(2);
    let note;
    if (Math.abs(P[0] - Q[0]) < 1e-9 && Math.abs(P[1] + Q[1]) < 1e-9) {
      g.strokeStyle = css("--yellow"); g.setLineDash([6, 6]); g.beginPath(); g.moveTo(sx(P[0]), 0); g.lineTo(sx(P[0]), H); g.stroke(); g.setLineDash([]);
      note = "P and Q are mirror images, so the line is vertical and never hits the curve again. P + Q is the special \"point at infinity\" (the curve's zero).";
    } else {
      const same = Math.abs(P[0] - Q[0]) < 1e-9;
      const m = same ? (3 * P[0] ** 2 - 1) / (2 * P[1]) : (Q[1] - P[1]) / (Q[0] - P[0]);
      const x3 = m * m - P[0] - Q[0], yR = P[1] + m * (x3 - P[0]), S = [x3, -yR];
      g.strokeStyle = css("--yellow"); g.lineWidth = 1.5; g.beginPath(); g.moveTo(0, sy(P[1] + m * (X0 - P[0]))); g.lineTo(W, sy(P[1] + m * (X1 - P[0]))); g.stroke();
      g.setLineDash([5, 5]); g.strokeStyle = css("--muted"); g.beginPath(); g.moveTo(sx(x3), sy(yR)); g.lineTo(sx(x3), sy(-yR)); g.stroke(); g.setLineDash([]);
      dot([x3, yR], css("--muted"), "−R", 5);
      dot(S, css("--pink"), "P+Q", 7);
      note = `P = (${fx(P[0])}, ${fx(P[1])}), Q = (${fx(Q[0])}, ${fx(Q[1])}). ${same ? "P = Q, so the line is the tangent. " : ""}The line hits the curve again at −R = (${fx(x3)}, ${fx(yR)}); flip it: P + Q = (${fx(S[0])}, ${fx(S[1])})` +
        (sy(S[1]) < 0 || sy(S[1]) > H || sx(S[0]) > W ? ", which is off the edge of the chart." : ".");
    }
    dot(P, css("--fg"), "P"); dot(Q, css("--fg"), "Q");
    $("ecc-real-note").textContent = note;
  }
  function eccToy() {
    const T = L.TOY, a = +$("ecc-secret").value; $("ecc-secret-out").textContent = a;
    const mult = Array.from({ length: 18 }, (_, i) => T.mul(i + 1));
    const { g, W } = sharp($("ecc-toy")), pad = 30, cell = (W - 2 * pad) / 16;
    const X = (x) => pad + Number(x) * cell, Y = (y) => W - pad - Number(y) * cell;
    g.fillStyle = css("--void"); g.fillRect(0, 0, W, W);
    g.strokeStyle = css("--panel-2"); g.lineWidth = 1;
    for (let i = 0; i <= 16; i++) { g.beginPath(); g.moveTo(X(i), Y(0)); g.lineTo(X(i), Y(16)); g.moveTo(X(0), Y(i)); g.lineTo(X(16), Y(i)); g.stroke(); }
    g.fillStyle = css("--muted"); g.font = "10px 'JetBrains Mono', monospace"; g.textAlign = "center";
    for (let i = 0; i <= 16; i += 4) { g.fillText(i, X(i), W - 10); g.fillText(i, 12, Y(i) + 3); }
    g.strokeStyle = css("--line"); g.lineWidth = 1.2; g.beginPath();
    for (let k = 0; k < a; k++) { const p = mult[k]; k ? g.lineTo(X(p[0]), Y(p[1])) : g.moveTo(X(p[0]), Y(p[1])); }
    g.stroke();
    mult.forEach((p, i) => {
      const k = i + 1, hit = k === a, isG = k === 1;
      g.fillStyle = hit ? css("--pink") : isG ? css("--cyan") : k <= a ? css("--fg") : css("--muted");
      g.beginPath(); g.arc(X(p[0]), Y(p[1]), hit || isG ? 7 : 4, 0, 7); g.fill();
      g.font = `${hit ? "bold 13px" : "11px"} 'JetBrains Mono', monospace`; g.textAlign = "left";
      g.fillText(`${k}G`, X(p[0]) + 7, Y(p[1]) - 7);
    });
    const pts = mult.map((p) => `(${p[0]}, ${p[1]})`);
    let list = "";
    for (let k = 1; k <= 18; k += 2) list += `${String(k).padStart(2)}G = ${pts[k - 1].padEnd(9)}   ${String(k + 1).padStart(2)}G = ${pts[k]}\n`;
    const tgt = mult[a - 1];
    $("ecc-toy-out").innerHTML = `G = (5, 1), the starting point. Each step adds G again:\n${list}19G = point at infinity  ${sp("m", "(this toy curve has only 19 points)")}\n\n` +
      `Alice: secret number ${sp("k", a)}, public point ${a}G = ${sp("y", `(${tgt[0]}, ${tgt[1]})`)}\n` +
      `forward is easy: add G to itself ${a} times.\nbackward, an attacker tries 1G, 2G, 3G… and finds a match after ${sp("bad", a)} tries.\n${sp("m", "Easy here; a real curve has about 2^256 points, too many to ever guess through.")}` +
      (a === 4 ? `\n\n${sp("y", "A private key of 4? Bold choice. eMudhra's CA keys weren't random enough either.")}` : "");
  }

  // --------------------------------------------------------------------------- ECDH (slide 30)
  function ecdhToy() {
    const T = L.TOY, a = 2 + L.randInt(17), b = 2 + L.randInt(17), A = T.mul(a), B = T.mul(b), S1 = T.mul(a, B), S2 = T.mul(b, A);
    const p = (P) => (P ? `(${P[0]}, ${P[1]})` : "∞");
    $("ecdh-alice").innerHTML = `secret a = ${sp("k", a)}\nsends A = a·G\n      = ${p(A)}\n\ncomputes a·B\n  = ${sp("y", p(S1))}`;
    $("ecdh-wire").innerHTML = `curve y² = x³+2x+2 mod 17\nG = (5, 1)\nA = ${p(A)}\nB = ${p(B)}\n${sp("m", "an eavesdropper sees only this")}`;
    $("ecdh-bob").innerHTML = `secret b = ${sp("k", b)}\nsends B = b·G\n      = ${p(B)}\n\ncomputes b·A\n  = ${sp("y", p(S2))}`;
    $("ecdh-result").innerHTML = `Both get ${sp("y", p(S1))} = (${a}·${b})·G = ${(a * b) % 19}G. ${String(S1) === String(S2) ? '<span class="ok">They agree.</span>' : ""}`;
  }
  async function ecdhReal() {
    const P = L.P256, t0 = performance.now();
    const a = L.randBelow(P.n - 1n) + 1n, b = L.randBelow(P.n - 1n) + 1n, A = P.mul(a), B = P.mul(b), S1 = P.mul(a, B), S2 = P.mul(b, A);
    const h = (x) => cut(hex64(x), 16);
    $("ecdh-alice").innerHTML = `secret a =\n ${sp("k", h(a))}\n${sp("m", "(256 bits, never sent)")}\n\ncomputes a·B, x =\n ${sp("y", h(S1[0]))}`;
    $("ecdh-wire").innerHTML = `curve NIST P-256\nA.x = ${h(A[0])}\nB.x = ${h(B[0])}\n${sp("m", "an eavesdropper sees only this")}`;
    $("ecdh-bob").innerHTML = `secret b =\n ${sp("k", h(b))}\n${sp("m", "(256 bits, never sent)")}\n\ncomputes b·A, x =\n ${sp("y", h(S2[0]))}`;
    $("ecdh-result").innerHTML = `Shared secret: <code>${hex64(S1[0])}</code><br>${S1[0] === S2[0] ? '<span class="ok">Both sides agree</span>' : '<span class="bad">Mismatch</span>'} (${ago(t0)} in plain JavaScript).`;
  }

  // --------------------------------------------------------------------------- signatures (slides 30-31)
  let sigKey = null;
  function signatures() {
    if (!sigKey) sigKey = L.rsaKeygen(256);
    const { n, e, d } = sigKey, msg = $("sig-msg").value, recv = $("sig-recv").value;
    const h = L.hashInt(msg), sig = L.modPow(h, d, n);
    const check = (m) => {
      const opened = L.modPow(sig, e, n), ok = opened === L.hashInt(m);
      return `${esc(q(m).padEnd(18))} ${ok ? "hashes match " : "hashes differ"}  ${ok ? sp("ok", "VALID") : sp("bad", "REJECTED")}`;
    };
    $("sig-out").innerHTML = `${sp("c", "Alice signs")}\n  hash      = SHA-256(${esc(q(msg))}) = ${cut(hex64(h), 24)}\n  signature = hash^d mod n = ${cut(sig.toString(16), 24)}  ${sp("m", "(d is her PRIVATE key)")}\n\n` +
      `${sp("k", "Bob checks")} sig^e mod n with Alice's PUBLIC key, then compares to the hash of what he got:\n  ${check(msg)}\n  ${check(recv)}\n\n` +
      sp("m", "(Textbook signing without padding, with a 512-bit toy key: the idea, not safe for real use.)");
  }
  function ecdsa(reuse) {
    const P = L.P256, n = P.n, t0 = performance.now();
    const d = L.randBelow(n - 1n) + 1n, Q = P.mul(d), h1 = L.hashInt("Message one"), h2 = L.hashInt("Message two");
    const k1 = L.randBelow(n - 1n) + 1n, k2 = reuse ? k1 : L.randBelow(n - 1n) + 1n;
    const s1 = L.ecdsaSign(d, h1, k1), s2 = L.ecdsaSign(d, h2, k2);
    const kk = ((((h1 - h2) % n) + n) * L.modInv(s1[1] - s2[1], n)) % n;
    const stolen = ((((s1[1] * kk - h1) % n) + n) * L.modInv(s1[0], n)) % n;
    const h = (x) => cut(hex64(x), 20);
    $("ecdsa-out").innerHTML = `private key d = ${h(d)}  ${sp("m", "(secret)")}\n\n` +
      `sign "Message one"  r = ${h(s1[0])}  s = ${h(s1[1])}\nsign "Message two"  r = ${h(s2[0])}  s = ${h(s2[1])}\n` +
      `both signatures verify: ${L.ecdsaVerify(Q, h1, s1) && L.ecdsaVerify(Q, h2, s2) ? sp("ok", "yes") : sp("bad", "no")}   same r? ${s1[0] === s2[0] ? sp("bad", "yes, k was reused") : sp("ok", "no")}\n\n` +
      `attacker solves: k = (h1 − h2) / (s1 − s2),  d = (s1·k − h1) / r\nrecovered d = ${h(stolen)}  ${stolen === d ? sp("bad", "✓ PRIVATE KEY STOLEN") : sp("ok", "✗ wrong: fresh k values keep the key safe")}\n${sp("m", `(${ago(t0)})`)}`;
  }

  // --------------------------------------------------------------------------- lattices (slide 34)
  let latTarget = [300, 130];
  function lattice() {
    const { g, W, H } = sharp($("lat-canvas")), o = [W / 2, H / 2], b1 = [58, 16], b2 = [22, 50];
    g.fillStyle = css("--void"); g.fillRect(0, 0, W, H);
    const pts = [];
    for (let i = -12; i <= 12; i++) for (let j = -12; j <= 12; j++) {
      const p = [o[0] + i * b1[0] + j * b2[0], o[1] - (i * b1[1] + j * b2[1])];
      if (p[0] > -10 && p[0] < W + 10 && p[1] > -10 && p[1] < H + 10) pts.push(p);
    }
    let best = pts[0], bd = Infinity;
    for (const p of pts) { const d = Math.hypot(p[0] - latTarget[0], p[1] - latTarget[1]); if (d < bd) { bd = d; best = p; } }
    g.strokeStyle = css("--line"); g.lineWidth = 2;
    g.beginPath(); g.moveTo(o[0], o[1]); g.lineTo(o[0] + b1[0], o[1] - b1[1]); g.moveTo(o[0], o[1]); g.lineTo(o[0] + b2[0], o[1] - b2[1]); g.stroke();
    g.fillStyle = css("--muted");
    for (const p of pts) { g.beginPath(); g.arc(p[0], p[1], 3, 0, 7); g.fill(); }
    g.strokeStyle = css("--yellow"); g.setLineDash([4, 4]); g.beginPath(); g.moveTo(latTarget[0], latTarget[1]); g.lineTo(best[0], best[1]); g.stroke(); g.setLineDash([]);
    g.fillStyle = css("--cyan"); g.beginPath(); g.arc(best[0], best[1], 7, 0, 7); g.fill();
    g.strokeStyle = css("--pink"); g.lineWidth = 2.5; g.beginPath(); g.arc(latTarget[0], latTarget[1], 9, 0, 7); g.stroke();
    g.beginPath(); g.moveTo(latTarget[0] - 14, latTarget[1]); g.lineTo(latTarget[0] + 14, latTarget[1]); g.moveTo(latTarget[0], latTarget[1] - 14); g.lineTo(latTarget[0], latTarget[1] + 14); g.stroke();
    g.fillStyle = css("--pink"); g.font = "bold 13px 'Chakra Petch', sans-serif"; g.fillText("target t", latTarget[0] + 12, latTarget[1] - 12);
    $("lat-note").innerHTML = `The <span class="c">closest grid point</span> is ${bd.toFixed(1)} px from the <span class="k">target</span>. Here we just checked all ${pts.length} points. With hundreds of dimensions there are more points than atoms in the universe.`;
  }
  function lwe() {
    $("lwe-out").innerHTML = `${sp("ok", "Without noise (easy to solve):")}\n  3x + 4y = 26\n  7x + 1y = 19   →  x = 2, y = 5\n\n${sp("k", "With a little noise (hard):")}\n  3x + 4y = 27\n  7x + 1y = 18   →  x, y = ?`;
    let cells = "";
    for (let y = 9; y >= 0; y--) for (let x = 0; x <= 9; x++) {
      const fit = Math.abs(3 * x + 4 * y - 27) <= 1 && Math.abs(7 * x + y - 18) <= 1;
      cells += `<span class="${fit ? "fit" : ""}" title="x=${x}, y=${y}">${fit ? `${x},${y}` : ""}</span>`;
    }
    $("lwe-grid").innerHTML = cells;
  }
  let regevPk = L.regevKeygen();
  function regev() {
    const raw = $("regev-bits").value.replace(/[^01]/g, "").slice(0, 12), pk = regevPk, half = Math.floor(pk.q / 2);
    let s = `public key: ${pk.m} noisy equations in ${pk.n} unknowns, mod ${pk.q}\n  first row: A = [${pk.A[0].join(", ")}], b = ${pk.b[0]}\nsecret s = [${pk.s.join(", ")}]  ${sp("m", "(only the receiver knows it)")}\n\n`;
    if (!raw) s += sp("m", "Type some 0s and 1s to encrypt.");
    for (const ch of raw) {
      const bit = +ch, ctx = L.regevEncrypt(pk, bit), { r, bit: out } = L.regevDecrypt(pk, ctx);
      s += `encrypt ${sp("c", bit)} → (u = [${ctx.u.map((x) => String(x).padStart(2)).join(",")}], v = ${String(ctx.v).padStart(2)})   ` +
        `v − u·s = ${String(r).padStart(2)}  ${sp("m", r > pk.q / 4 && r < (3 * pk.q) / 4 ? `near ${half}` : "near 0")} → ${out === bit ? sp("ok", out) : sp("bad", out)}\n`;
    }
    $("regev-out").innerHTML = s.trimEnd();
  }

  // --------------------------------------------------------------------------- secure website (slide 35)
  async function website() {
    const items = [...document.querySelectorAll("#web-flow li")], terms = items.map((li) => li.querySelector(".term"));
    items.forEach((li) => li.classList.remove("active", "done")); terms.forEach((t) => (t.innerHTML = "")); $("web-done").textContent = "";
    const t0 = performance.now(), step = async (i, fn) => { items[i].classList.add("active"); await wait(350); terms[i].innerHTML = await fn(); items[i].classList.replace("active", "done"); };
    const H = (s) => L.hashInt(s);
    await step(0, () => {
      const ca = L.rsaKeygen(256), srv = L.rsaKeygen(256), body = `example.com|${srv.n}|${srv.e}`, sig = L.modPow(H(body), ca.d, ca.n);
      const proof = L.modPow(H("handshake-transcript"), srv.d, srv.n);
      return `certificate for example.com, signed by the CA: ${L.modPow(sig, ca.e, ca.n) === H(body) ? sp("ok", "signature checks out") : sp("bad", "bad signature")}\n` +
        `server proves it holds the certificate's private key: ${L.modPow(proof, srv.e, srv.n) === H("handshake-transcript") ? sp("ok", "yes") : sp("bad", "no")}`;
    });
    let key;
    await step(1, () => {
      const P = L.P256, a = L.randBelow(P.n - 1n) + 1n, b = L.randBelow(P.n - 1n) + 1n, A = P.mul(a), B = P.mul(b), s1 = P.mul(a, B)[0], s2 = P.mul(b, A)[0];
      key = L.hmacSha256(enc("handshake salt"), L.fromBig(s1, 32)).slice(0, 16);
      return `on the wire: A.x = ${cut(hex64(A[0]), 16)}  B.x = ${cut(hex64(B[0]), 16)}\nboth sides compute the same secret: ${s1 === s2 ? sp("ok", "yes") : sp("bad", "no")} · AES key derived from it ${sp("m", "(never sent)")}`;
    });
    const req = enc($("web-req").value), nonce = L.fromBig(1n, 12), aad = enc("https://example.com");
    const { ct, tag } = L.gcmEncrypt(key, nonce, req, aad);
    await step(2, () => `AES-128-GCM, nonce = counter 1 (never repeats)\non the wire: ${cut(L.hex(ct), 40)}  tag ${L.hex(tag).slice(0, 16)}…`);
    await step(3, () => {
      const bad = ct.slice(); if (bad.length) bad[0] ^= 1;
      let r;
      try { L.gcmDecrypt(key, nonce, bad, tag, aad); r = sp("bad", "accepted?!"); } catch (e) { r = sp("ok", "tag mismatch, dropped"); }
      return `attacker flips one bit: ${r}\nuntouched message decrypts to: ${sp("y", q(L.text(L.gcmDecrypt(key, nonce, ct, tag, aad))))}`;
    });
    await step(4, async () => {
      const pw = $("web-pw").value, salt = L.randBytes(16), pepper = enc("vault-secret");
      if (HW) {
        const hash = await HW.argon2id({ password: pw, salt, secret: pepper, iterations: 2, parallelism: 1, memorySize: 19456, hashLength: 32, outputType: "encoded" });
        const good = await HW.argon2Verify({ password: pw, secret: pepper, hash }), wrong = await HW.argon2Verify({ password: pw + "!", secret: pepper, hash });
        return `database stores only: ${cut(hash, 58)}\nlogin with the right password: ${good ? sp("ok", "accepted") : sp("bad", "rejected")} · with a wrong one: ${wrong ? sp("bad", "accepted") : sp("ok", "rejected")}`;
      }
      const k = await crypto.subtle.importKey("raw", L.concat(enc(pw), pepper), "PBKDF2", false, ["deriveBits"]);
      const h = new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: 600000 }, k, 256));
      return `database stores salt + PBKDF2 hash: ${L.hex(salt).slice(0, 12)}… ${cut(L.hex(h), 20)}\n${sp("m", "(Argon2id needs WebAssembly, which this browser blocked)")}`;
    });
    $("web-done").innerHTML = `<b>Every idea from today in one page load</b> (${((performance.now() - t0) / 1000).toFixed(1)} s, including pauses so you can watch).`;
  }

  // --------------------------------------------------------------------------- start
  const PUZZLE = "QVJJUkUgRUJZWSBMQkhFIEJKQSBQRUxDR0I=";
  function consolePuzzle() {
    console.log("%cCRYPTO 101", "font: 700 28px monospace; color: #ff2e88; text-shadow: 0 0 8px #ff2e88");
    console.log(`%cA secret for the curious:\n\n    ${PUZZLE}\n\nEvery tool you need is in this deck.\nFirst undo the encoding, then the oldest cipher in the talk.`, "font: 14px monospace; color: #00f0ff");
  }

  function start() {
    consolePuzzle();
    bind(["hero-a", "hero-b"], hero);
    bind(["caesar-msg", "caesar-key"], caesar);
    bind(["vig-msg", "vig-key"], vigenere);
    bind(["otp-msg", "otp-other"], otp);
    click("otp-new", () => { otpKey = randLetters(L.letters($("otp-msg").value).length); otp(); });
    otpReuse(); click("otp-reuse-new", () => { reuseKey = L.randBytes(16); otpReuse(); });
    enigmaInit();
    bind(["enc-in", "enc-b64"], encoding);
    bind("hve-in", hve);
    checkpoints();
    bind(["av-in", "av-bit"], avalanche);
    bind(["sha-in", "sha-round"], sha);
    bind("col-bits", () => ($("col-bits-out").textContent = $("col-bits").value));
    click("col-run", (e) => busy(e.currentTarget, collision));
    bind("alg-in", algorithms);
    bind("salt-pw", salt);
    click("salt-new", () => { saltA = L.randBytes(8); saltB = L.randBytes(8); salt(); });
    click("bench-run", (e) => busy(e.currentTarget, bench));
    bind(["crack-alpha", "crack-len"], crack);
    bind("xor-ch", xor);
    click("xor-new", () => { xorKey = 1 + L.randInt(255); xor(); });
    $("xor-rows").addEventListener("click", (e) => { const s = e.target.closest(".key span"); if (s) { xorKey ^= 0x80 >> +s.dataset.i; xor(); } });
    $("xor-128").innerHTML = `A 128-bit key has 2<sup>128</sup> = <span class="y">${(2n ** 128n).toLocaleString("en-US")}</span> possible values. More than anyone can try.`;
    bind(["aes-key", "aes-pt"], aesInput);
    bind("aes-step", aesStep);
    aesChecks();
    bind("modes-msg", modes);
    click("modes-new", () => { modeKey = L.randBytes(16); modeIv = L.randBytes(16); modeNonce = L.randBytes(12); modes(); });
    click("pad-new", (e) => busy(e.currentTarget, padEncrypt));
    bind(["tamp-from", "tamp-to"], tamper);
    keybars();
    bind(["rsa-p", "rsa-q", "rsa-e", "rsa-m"], rsa);
    click("rsa-smallm", (e) => busy(e.currentTarget, rsaSmallM));
    click("rsa-gen", (e) => busy(e.currentTarget, rsaGenerate));
    bind(["ecc-px", "ecc-qx", "ecc-pneg", "ecc-qneg"], eccReal);
    bind("ecc-secret", eccToy);
    bind(["paint-p", "paint-a", "paint-b"], paint);
    click("paint-new", () => { $("paint-a").value = randHex(); $("paint-b").value = randHex(); paint(); });
    ecdhToy(); click("ecdh-toy", ecdhToy);
    click("ecdh-real", (e) => busy(e.currentTarget, ecdhReal));
    bind(["sig-msg", "sig-recv"], signatures);
    click("ecdsa-reuse", (e) => busy(e.currentTarget, () => ecdsa(true)));
    click("ecdsa-fresh", (e) => busy(e.currentTarget, () => ecdsa(false)));
    for (const a of ["register", "login", "phish"]) click("pk-" + a, (e) => busy(e.currentTarget, () => passkey(a)));
    rngMake(); click("rng-make", rngMake); click("rng-guess", (e) => busy(e.currentTarget, rngGuess));
    click("e2e-send", (e) => busy(e.currentTarget, () => e2eSend(false)));
    click("e2e-swap", (e) => busy(e.currentTarget, () => e2eSend(true)));
    click("pk-real", pkReal);
    click("pk-forget", pkForget);
    pkRealLabel();
    lattice();
    $("lat-canvas").addEventListener("click", (e) => {
      const r = e.currentTarget.getBoundingClientRect();
      latTarget = [(e.clientX - r.left) * (+e.currentTarget.dataset.w / r.width), (e.clientY - r.top) * (+e.currentTarget.dataset.h / r.height)];
      lattice();
    });
    lwe();
    bind("regev-bits", regev);
    click("regev-new", () => { regevPk = L.regevKeygen(); regev(); });
    click("web-run", (e) => busy(e.currentTarget, website));
    padEncrypt();
    const redraw = () => { eccReal(); eccToy(); lattice(); };
    let redrawTimer;
    window.addEventListener("resize", () => { clearTimeout(redrawTimer); redrawTimer = setTimeout(redraw, 120); });
    document.addEventListener("deck:slide", (e) => { if (e.detail.querySelector("#ecc-real, #ecc-toy, #lat-canvas")) redraw(); });
    if (document.fonts && document.fonts.ready) document.fonts.ready.then(() => { eccReal(); eccToy(); lattice(); padDraw(); padEncrypt(); });
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
})();
