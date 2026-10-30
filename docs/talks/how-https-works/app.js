/* app.js - the live demos for "How HTTPS Really Works". Shared maths: ../../shared/crypto.js (window.Lab).
   The handshake uses real P-256 ECDH, real TLS 1.3 HKDF labels, real ECDSA and real AES-GCM;
   only the message formats are simplified. */
(function () {
  "use strict";
  const L = window.Lab;
  const enc = L.utf8;

  // --------------------------------------------------------------------------- helpers
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const sp = (cls, s) => `<span class="${cls}">${esc(s)}</span>`;
  const cut = (s, n = 32) => (s.length > n ? s.slice(0, n) + "…" : s);
  const hex64 = (x) => x.toString(16).padStart(64, "0");
  const wait = (ms = 0) => new Promise((r) => setTimeout(r, ms));
  const fmt = (n) => n.toLocaleString("en-US");
  function bind(ids, fn) { for (const id of [].concat(ids)) $(id).addEventListener("input", fn); fn(); }
  function click(id, fn) { $(id).addEventListener("click", fn); }
  const DOC_IP = "203.0.113.10";                   // a documentation address (RFC 5737), not a real server

  // --------------------------------------------------------------------------- title terminal
  function hero() {
    const el = $("hero-url"), raw = el.value.trim();
    el.style.width = Math.max(6, el.value.length + 1) + "ch";
    let u;
    try { u = new URL(/^[a-z]+:\/\//i.test(raw) ? raw : "https://" + raw); } catch (e) { u = null; }
    if (!u || !u.hostname) { $("hero-out").innerHTML = sp("m", "type a web address"); $("hero-note").textContent = ""; return; }
    const host = u.hostname, rest = (u.pathname + u.search + u.hash) || "/", plain = u.protocol === "http:";
    $("hero-out").innerHTML = plain
      ? `${sp("k", "the network sees:")} ${sp("bad", "everything")}<br>&nbsp;&nbsp;${esc(host)}${esc(rest)}, cookies, forms, the whole page`
      : `${sp("k", "the network sees:")} ${esc(host)}, its address, size, timing<br>${sp("c", "stays secret:")} ${esc(cut(rest, 30))}, cookies, the page`;
    let note = "";
    if (plain) note = "# No padlock? In this economy?";
    else if (host === "localhost" || host === "127.0.0.1" || host === "[::1]") note = "# There's no place like 127.0.0.1.";
    else if (host === "example.com" || host === "www.example.com") note = "# example.com is reserved for examples (RFC 2606). Busiest fake site on earth.";
    else note = "# the S in HTTPS is doing a lot of work here.";
    $("hero-note").textContent = note;
  }

  // --------------------------------------------------------------------------- DNS lookup
  let dnsToken = 0;
  async function dnsLookup() {
    const token = ++dnsToken, name = ($("dns-name").value.trim().toLowerCase() || "example.com").replace(/\.$/, "");
    const doh = $("dns-doh").checked, tld = name.includes(".") ? name.split(".").pop() : "com";
    const steps = [
      ["Your device", `asks the resolver: "where is ${name}?"`, doh ? "encrypted (DNS over HTTPS)" : "sent in the clear"],
      ["Resolver", `asks a root server: "who handles .${tld}?"`, ""],
      ["Root server", `"ask the .${tld} servers"`, ""],
      [`.${tld} servers`, `"ask ${name}'s own name server"`, ""],
      [`${name}'s name server`, `"${name} is at ${DOC_IP}"`, "the answer"],
      ["Resolver", `remembers the answer for a while (caching) and tells your device`, ""],
    ];
    $("dns-steps").innerHTML = steps.map(([who, what, tag], i) => `<li data-i="${i}"><b>${esc(who)}</b><span>${esc(what)}</span>${tag ? `<em>${esc(tag)}</em>` : ""}</li>`).join("");
    const who = [["Your Wi-Fi", !doh], ["Your internet provider", !doh], ["The resolver", true], ["Root and ." + tld + " servers", true], [name + "'s name server", true]];
    $("dns-who").innerHTML = who.map(([w, saw]) => `<div class="${saw ? "saw" : "hid"}"><b>${esc(w)}</b><span>${saw ? "saw the name" : "saw only encrypted data"}</span></div>`).join("") +
      (/dns/.test(name) ? `<p class="haiku">It's not DNS.<br>There's no way it's DNS.<br>It was DNS.</p>` : "");
    for (let i = 0; i < steps.length; i++) {
      if (token !== dnsToken) return;
      document.querySelector(`#dns-steps li[data-i="${i}"]`).classList.add("on");
      await wait(350);
    }
  }

  // --------------------------------------------------------------------------- café Wi-Fi view
  function cafe() {
    const https = $("cafe-https").checked, evil = $("cafe-evil").checked;
    let path = $("cafe-path").value.trim() || "/";
    if (!path.startsWith("/")) path = "/" + path;
    const teapot = path.toLowerCase() === "/coffee";
    const url = `${https ? "https" : "http"}://bank.example${path}`;
    const injected = evil && !https, broken = evil && https;
    $("cafe-browser").innerHTML =
      `<div class="bar"><span class="lock ${https ? "on" : "off"}">${https ? "🔒" : "⚠"}</span><span class="url">${esc(url)}</span></div>` +
      `<div class="page">` +
      (broken ? `<p class="bad">⚠ The connection was interrupted. Someone changed the data on the way, and the browser noticed.</p>`
        : teapot ? `<p class="y">418 I'm a teapot</p><p class="m">This server refuses to brew coffee because it is, permanently, a teapot. (RFC 2324, an April Fools' joke from 1998 that the web still remembers.)</p>`
          : `${injected ? `<p class="evil">🎁 Congratulations! Confirm your card number to claim your prize!</p>` : ""}<b>BANK · Sign in</b><label>Username<input readonly value="alice"></label><label>Password<input readonly type="password" value="hunter2-but-longer"></label>`) +
      `</div>`;
    const req = `POST ${path} HTTP/1.1\nHost: bank.example\nCookie: session=7f3a9c\n\nuser=alice&password=hunter2-but-longer`;
    const blob = L.hex(L.randBytes(28)).match(/.{2}/g).join(" ");
    $("cafe-capture").innerHTML = https
      ? `${sp("m", "DNS     ")} bank.example → ${DOC_IP}\n${sp("m", "TLS     ")} ClientHello  server name: ${sp("y", "bank.example")}\n` +
        `${sp("m", "TLS     ")} application data, 312 bytes:\n        ${sp("c", blob)}…\n\n` +
        (broken ? sp("ok", "edit attempted → tag check failed → connection closed") : sp("ok", "the page, the path and the password are unreadable"))
      : `${sp("m", "DNS     ")} bank.example → ${DOC_IP}\n${sp("m", "HTTP    ")} ${sp("bad", req.split("\n").join("\n        "))}\n\n` +
        (injected ? sp("bad", "the reply was edited on the way: a fake prize banner was added") : sp("bad", "everything readable, including the password"));
  }

  // --------------------------------------------------------------------------- PKI for the handshake and the certificate slide
  const P = L.P256;
  const rnd = () => L.randBelow(P.n - 1n) + 1n;
  const xhex = (pt) => hex64(pt[0]);
  function signCert(body, issuerKey) {
    const h = L.toBig(L.sha256(enc(JSON.stringify(body))));
    return L.ecdsaSign(issuerKey, h, rnd());
  }
  const verifyCert = (body, sig, issuerPub) => L.ecdsaVerify(issuerPub, L.toBig(L.sha256(enc(JSON.stringify(body)))), sig);
  function makePki() {
    const rootKey = rnd(), interKey = rnd(), leafKey = rnd();
    const now = new Date(), day = 86400000;
    const root = { subject: "Neon Root CA", issuer: "Neon Root CA", pub: xhex(P.mul(rootKey)) };
    const inter = { subject: "Neon Issuing CA 1", issuer: "Neon Root CA", pub: xhex(P.mul(interKey)) };
    const leaf = { subject: "example.com", issuer: "Neon Issuing CA 1", notBefore: new Date(now - 30 * day).toISOString().slice(0, 10),
      notAfter: new Date(+now + 60 * day).toISOString().slice(0, 10), pub: xhex(P.mul(leafKey)) };
    return { rootKey, interKey, leafKey, rootPub: P.mul(rootKey), interPub: P.mul(interKey), leafPub: P.mul(leafKey), root, inter, leaf,
      rootSig: signCert(root, rootKey), interSig: signCert(inter, rootKey), leafSig: signCert(leaf, interKey) };
  }

  // --------------------------------------------------------------------------- the handshake
  const STEPS = [
    ["ClientHello", "Browser → server, readable by anyone", "The browser says hello: a random number, the key-exchange groups it supports, its public key share, and the site name it wants (so one server can host many sites)."],
    ["ServerHello", "Server → browser, readable by anyone", "The server picks the options and sends its own random number and public key share. These two messages are the only unencrypted part."],
    ["Shared secret", "Computed on both sides, never sent", "Each side combines its own secret with the other's public share. Both arrive at the same value; the network saw only the public shares."],
    ["Key schedule", "HKDF, exactly as TLS 1.3 does it", "Both sides feed the shared secret and a hash of the conversation so far into HKDF, producing separate handshake keys for each direction. From now on, everything is encrypted."],
    ["Certificate", "Encrypted, server → browser", "The server sends its certificate chain. The browser checks each signature up to a root it already trusts, the name and the dates."],
    ["CertificateVerify", "Encrypted, server → browser", "The server signs a hash of the whole conversation with the certificate's private key. Only the real owner of the certificate can do this."],
    ["Finished", "Encrypted, both directions", "Each side sends a checksum (HMAC) over everything so far. If anyone changed a single handshake byte, the checksums don't match and the connection stops."],
    ["Application data", "Encrypted with the application keys", "Fresh keys for the actual traffic. The browser's first request goes out encrypted and tagged."],
  ];
  const LADDER = [[0, "→", "ClientHello", "clear"], [1, "←", "ServerHello", "clear"], [2, "·", "both compute the shared secret", "calc"], [3, "·", "both derive handshake keys", "calc"],
    [4, "←", "{Certificate}", "enc"], [5, "←", "{CertificateVerify}", "enc"], [6, "⇄", "{Finished}", "enc"], [7, "→", "[GET /account]", "app"]];
  let hs = null, hsCount = 0;
  function buildHandshake() {
    const a = rnd(), b = rnd(), A = P.mul(a), B = P.mul(b), cr = L.randBytes(32), sr = L.randBytes(32);
    const sharedA = L.fromBig(P.mul(a, B)[0], 32), sharedB = L.fromBig(P.mul(b, A)[0], 32);
    const hello = L.concat(enc("ClientHello"), cr, L.fromBig(A[0], 32), enc("ServerHello"), sr, L.fromBig(B[0], 32));
    const th1 = L.sha256(hello);
    const early = L.hkdfExtract(new Uint8Array(0), new Uint8Array(32));
    const hsSecret = L.hkdfExtract(L.hkdfExpandLabel(early, "derived", L.sha256(new Uint8Array(0)), 32), sharedA);
    const cHs = L.hkdfExpandLabel(hsSecret, "c hs traffic", th1, 32), sHs = L.hkdfExpandLabel(hsSecret, "s hs traffic", th1, 32);
    const sKey = L.hkdfExpandLabel(sHs, "key", new Uint8Array(0), 16), sIv = L.hkdfExpandLabel(sHs, "iv", new Uint8Array(0), 12);
    const pki = makePki();
    const certMsg = enc(JSON.stringify([pki.leaf, pki.inter]));
    const certEnc = L.gcmEncrypt(sKey, sIv, certMsg);
    const th2 = L.sha256(L.concat(hello, certMsg));
    const cvContent = L.concat(new Uint8Array(64).fill(0x20), enc("TLS 1.3, server CertificateVerify"), Uint8Array.of(0), th2);
    const cvSig = L.ecdsaSign(pki.leafKey, L.toBig(L.sha256(cvContent)), rnd());
    const cvOk = L.ecdsaVerify(pki.leafPub, L.toBig(L.sha256(cvContent)), cvSig);
    const th3 = L.sha256(L.concat(hello, certMsg, enc("cv")));
    const sFin = L.hmacSha256(L.hkdfExpandLabel(sHs, "finished", new Uint8Array(0), 32), th3);
    const cFin = L.hmacSha256(L.hkdfExpandLabel(cHs, "finished", new Uint8Array(0), 32), L.sha256(L.concat(hello, certMsg, enc("cv"), sFin)));
    const master = L.hkdfExtract(L.hkdfExpandLabel(hsSecret, "derived", L.sha256(new Uint8Array(0)), 32), new Uint8Array(32));
    const cAp = L.hkdfExpandLabel(master, "c ap traffic", th3, 32);
    const aKey = L.hkdfExpandLabel(cAp, "key", new Uint8Array(0), 16), aIv = L.hkdfExpandLabel(cAp, "iv", new Uint8Array(0), 12);
    const request = enc("GET /account HTTP/1.1\r\nHost: example.com\r\nCookie: session=7f3a\r\n\r\n");
    const app = L.gcmEncrypt(aKey, aIv, L.concat(request, Uint8Array.of(0x17)));
    const chainOk = [verifyCert(pki.leaf, pki.leafSig, pki.interPub), verifyCert(pki.inter, pki.interSig, pki.rootPub), verifyCert(pki.root, pki.rootSig, pki.rootPub)];
    hs = { a, b, A, B, cr, sr, sharedA, sharedB, th1, hsSecret, cHs, sHs, sKey, certEnc, cvSig, cvOk, sFin, cFin, aKey, app, request, pki, chainOk };
    pki.certSlideReady = true;
  }
  function drawHandshake() {
    const i = +$("hs-step").value, [title, sub, desc] = STEPS[i], h = hs, H = (b, n = 24) => cut(L.hex(b), n);
    $("hs-step-out").textContent = `${i + 1} / ${STEPS.length}`;
    $("hs-ladder").innerHTML = LADDER.map(([s, dir, label, kind]) =>
      `<li class="${kind}${s === i ? " on" : ""}${s < i ? " done" : ""}"><span class="side l">${dir === "→" ? "browser" : dir === "⇄" ? "both" : dir === "·" ? "browser" : ""}</span><span class="msg"><i>${dir}</i>${esc(label)}</span><span class="side r">${dir === "←" ? "server" : dir === "·" ? "server" : ""}</span></li>`).join("");
    $("hs-title").textContent = `${i + 1}. ${title}`;
    $("hs-desc").innerHTML = `${sp("c", sub)}. ${esc(desc)}`;
    const D = [
      () => `random        ${H(h.cr)}\nkey share     ${sp("y", cut(xhex(h.A), 24))}  ${sp("m", "(P-256 public point)")}\nsupported     X25519MLKEM768, X25519, P-256\nsite name     ${sp("bad", "example.com")}  ${sp("m", "← readable, unless ECH")}`,
      () => `random        ${H(h.sr)}\nchosen group  P-256  ${sp("m", "(browsers usually get the X25519 + ML-KEM hybrid)")}\nkey share     ${sp("y", cut(xhex(h.B), 24))}`,
      () => `browser: its secret × server share = ${sp("ok", H(h.sharedA))}\nserver:  its secret × browser share = ${sp("ok", H(h.sharedB))}\n${L.equalBytes(h.sharedA, h.sharedB) ? sp("ok", "identical") : sp("bad", "mismatch")}\n\n${sp("m", "the network saw only the two public key shares")}`,
      () => `transcript hash    ${H(h.th1)}\nhandshake secret   ${H(h.hsSecret)}\nbrowser→server key ${H(h.cHs)}\nserver→browser key ${H(h.sHs)}\n${sp("m", 'HKDF labels: "derived", "c hs traffic", "s hs traffic", "key", "iv"')}`,
      () => `on the wire   ${sp("c", H(h.certEnc.ct, 28))} ${sp("m", `(${h.certEnc.ct.length} bytes, encrypted)`)}\n\nbrowser checks the chain:\n  example.com       signed by Neon Issuing CA 1  ${h.chainOk[0] ? sp("ok", "✓") : sp("bad", "✗")}\n  Neon Issuing CA 1 signed by Neon Root CA       ${h.chainOk[1] ? sp("ok", "✓") : sp("bad", "✗")}\n  Neon Root CA      in the browser's store       ${h.chainOk[2] ? sp("ok", "✓") : sp("bad", "✗")}\n  name matches, dates valid                      ${sp("ok", "✓")}`,
      () => `server signs SHA-256(context + transcript) with the certificate's key\n  r = ${cut(hex64(h.cvSig[0]), 24)}\n  s = ${cut(hex64(h.cvSig[1]), 24)}\nbrowser verifies with example.com's public key: ${h.cvOk ? sp("ok", "valid") : sp("bad", "invalid")}`,
      () => `server Finished   ${H(h.sFin)}  ${sp("ok", "✓ matches")}\nbrowser Finished  ${H(h.cFin)}  ${sp("ok", "✓ matches")}\n${sp("m", "HMAC over every handshake byte: tampering would change these")}`,
      () => `application key   ${H(h.aKey)}\nrequest (secret)  ${sp("y", "GET /account · Cookie: session=7f3a")}\non the wire       ${sp("c", H(h.app.ct, 28))}\ntag               ${H(h.app.tag, 32)}\n${sp("ok", "the page loads; the padlock appears")}`,
    ];
    $("hs-detail").innerHTML = D[i]();
  }
  function newConnection() {
    buildHandshake(); drawHandshake(); certs();
    hsCount++;
    if (hsCount === 10) $("hs-desc").innerHTML += ` ${sp("y", "That's 10 handshakes. Hand sanitiser?")}`;
  }

  // --------------------------------------------------------------------------- certificate slide
  function certs() {
    if (!hs) return;
    const p = hs.pki, wrongName = $("cert-name").checked, expired = $("cert-expired").checked, noRoot = $("cert-root").checked, tamper = $("cert-tamper").checked;
    // an expired certificate was genuinely signed; it's just old. Tampering changes the body after signing.
    if (expired && !p.oldLeaf) {
      p.oldLeaf = { ...p.leaf, notBefore: "2025-01-01", notAfter: "2025-07-20" };
      p.oldSig = signCert(p.oldLeaf, p.interKey);
    }
    const leaf = { ...(expired ? p.oldLeaf : p.leaf) }, sig = expired ? p.oldSig : p.leafSig;
    if (tamper) leaf.pub = leaf.pub.replace(/^./, (c) => (c === "a" ? "b" : "a"));
    const site = wrongName ? "examp1e.com" : "example.com";
    const sigOk = verifyCert(leaf, sig, p.interPub);
    const interOk = verifyCert(p.inter, p.interSig, p.rootPub);
    const today = new Date().toISOString().slice(0, 10), dateOk = leaf.notBefore <= today && today <= leaf.notAfter;
    const nameOk = leaf.subject === site, rootOk = !noRoot;
    const row = (ok, text) => `${ok ? sp("ok", "✓") : sp("bad", "✗")} ${text}`;
    $("cert-chain").innerHTML =
      `<div class="${rootOk ? "" : "bad"}"><b>Neon Root CA</b><small>${rootOk ? "in your browser's store" : "unknown to your browser"}</small></div><i>signs ↓</i>` +
      `<div><b>Neon Issuing CA 1</b><small>intermediate</small></div><i>signs ↓</i>` +
      `<div class="${sigOk && dateOk && nameOk ? "" : "bad"}"><b>example.com</b><small>valid ${esc(leaf.notBefore)} → ${esc(leaf.notAfter)}</small></div>`;
    $("cert-checks").innerHTML = `you're visiting   ${sp(wrongName ? "bad" : "y", site)}\n\n` +
      [row(nameOk, `name: the certificate is for example.com`), row(dateOk, `dates: today (${today}) is inside the validity period`),
        row(sigOk, `signature: the issuing CA really signed this certificate`), row(interOk, `signature: the root really signed the issuing CA`),
        row(rootOk, `trust: the root is in your browser's store`)].join("\n");
    const problems = [!nameOk && ["Wrong name", "NET::ERR_CERT_COMMON_NAME_INVALID", "This certificate is for a different site. You may be talking to an impostor."],
      !dateOk && ["Expired", "NET::ERR_CERT_DATE_INVALID", "The certificate has expired (or your device's clock is wrong)."],
      !sigOk && ["Tampered", "Certificate is not valid", "The signature doesn't match: the certificate was altered."],
      !rootOk && ["Unknown issuer", "NET::ERR_CERT_AUTHORITY_INVALID", "Your browser doesn't trust whoever issued this certificate."]].filter(Boolean);
    $("cert-verdict").className = `verdict ${problems.length ? "warn" : "ok"}`;
    $("cert-verdict").innerHTML = problems.length
      ? `<b>⚠ Your connection is not private</b>${problems.map(([t, code, d]) => `<p><span>${esc(code)}</span>${esc(d)}</p>`).join("")}` +
        (problems.length === 4 ? `<p class="egg">Achievement unlocked: Certificate Chaos. Four problems at once: impressive.</p>` : "")
      : `<b>🔒 Connection is secure</b><p>The name matches, the dates are valid, every signature checks out, and the chain ends at a root you trust.</p>`;
  }

  // --------------------------------------------------------------------------- round trips
  function rtt() {
    const ms = +$("rtt-ms").value;
    $("rtt-ms-out").textContent = `${ms} ms`;
    const rows = [["HTTP (no encryption)", [["connect", 1]], "m"], ["HTTPS with TLS 1.2", [["connect", 1], ["TLS", 2]], "bad"],
      ["HTTPS with TLS 1.3", [["connect", 1], ["TLS", 1]], "ok"], ["HTTP/3 (QUIC + TLS 1.3)", [["connect + TLS", 1]], "c"]];
    const max = 4 * ms;
    $("rtt-bars").innerHTML = rows.map(([name, parts, cls]) => {
      const total = parts.reduce((s, p) => s + p[1], 0) + 1;
      return `<div class="rtt-row"><b>${name}</b><div class="rtt-track">${parts.map(([l, n]) => `<span class="seg ${l === "connect" ? "tcp" : "tls"}" style="width:${(n * ms / max) * 100}%">${l}</span>`).join("")}<span class="seg req" style="width:${(ms / max) * 100}%">request</span></div><em class="${cls}">${fmt(total * ms)} ms</em></div>`;
    }).join("");
    $("rtt-note").innerHTML = ms >= 600 ? `${sp("y", "600 ms: hello from geostationary orbit. Satellite users feel every round trip.")}`
      : `Time before the first byte of the page arrives, counting only round trips. At ${ms} ms, TLS 1.3 saves ${fmt(ms)} ms on every new connection.`;
  }

  // --------------------------------------------------------------------------- encrypted records
  const recKey = L.randBytes(16), recNonce = L.randBytes(12);
  let recTampered = false;
  function records() {
    const req = enc($("rec-in").value), pad = $("rec-pad").checked;
    const inner = L.concat(req, Uint8Array.of(0x17), new Uint8Array(pad ? (256 - ((req.length + 1) % 256)) % 256 : 0));
    const { ct, tag } = L.gcmEncrypt(recKey, recNonce, inner), len = ct.length + 16;
    const header = Uint8Array.of(0x17, 0x03, 0x03, len >> 8, len & 255);
    const body = recTampered ? (() => { const c = ct.slice(); c[0] ^= 1; return c; })() : ct;
    $("rec-bytes").innerHTML = `<span class="h" title="record header">${L.hex(header, " ")}</span><span class="c" title="encrypted">${cut(L.hex(body, " "), 72)}</span><span class="t" title="tag">${L.hex(tag, " ").slice(0, 23)}…</span>`;
    let result;
    try { L.gcmDecrypt(recKey, recNonce, body, tag); result = sp("ok", "server decrypts it: tag checks out"); }
    catch (e) { result = sp("bad", "tag mismatch → alert \"bad_record_mac\" → connection closed"); }
    $("rec-out").innerHTML = `${sp("y", "17")} = application data   ${sp("y", "03 03")} = TLS (legacy version field)   ${sp("y", L.hex(header.slice(3)))} = length ${fmt(len)} bytes\n` +
      `your request: ${req.length} bytes → on the wire: ${fmt(5 + len)} bytes ${pad ? sp("ok", "(padded: lengths blur together)") : sp("m", "(size reveals roughly how big it is)")}\n${result}`;
  }

  // --------------------------------------------------------------------------- what leaks
  function leaks() {
    const doh = $("leak-doh").checked, ech = $("leak-ech").checked, vpn = $("leak-vpn").checked;
    const nameHidden = (doh && ech) || vpn;
    const rows = [
      ["Which site (name)", vpn ? "hidden" : nameHidden ? "hidden" : "visible", vpn ? "VPN company" : !doh && !ech ? "from DNS and the ClientHello" : !doh ? "from DNS" : !ech ? "from the ClientHello" : "the IP address may still hint at it"],
      ["The server's IP address", vpn ? "hidden" : "visible", vpn ? "VPN company sees it instead" : "needed to deliver the data"],
      ["How much data, and when", "visible", vpn ? "still visible as one encrypted stream" : "sizes and timing of records"],
      ["The page or path (/account)", "hidden", "inside the encrypted records"],
      ["Cookies, passwords, forms", "hidden", "inside the encrypted records"],
      ["The page content", "hidden", "inside the encrypted records"],
    ];
    $("leak-table").innerHTML = `<thead><tr><th>Your Wi-Fi and internet provider can see…</th><th></th><th>Why</th></tr></thead><tbody>` +
      rows.map(([w, s, why]) => `<tr><th>${w}</th><td class="${s === "visible" ? "vis" : "hid"}">${s === "visible" ? "👁 visible" : "🔒 hidden"}</td><td>${esc(why)}</td></tr>`).join("") + "</tbody>";
    $("leak-note").innerHTML = vpn ? "With a VPN, your Wi-Fi sees only an encrypted tunnel, but the VPN company now sees what your provider used to. You've moved the trust, not removed it."
      : doh && ech ? "Encrypted DNS plus ECH hide the name from the network. The server's IP address can still narrow it down, especially for big sites with their own addresses."
        : "Tick the options to see what each one hides, and from whom.";
  }

  // --------------------------------------------------------------------------- HSTS scenarios
  const HSTS = {
    none: [["You type", "bank.example (no https://)", ""], ["Browser", "tries http://bank.example first: unencrypted", "bad"],
      ["Network", "someone on the Wi-Fi could keep you on http and pass pages along", "bad"], ["Site", "would have redirected you to https://, but that reply can be intercepted", "bad"],
      ["Result", "a window where you're not protected", "bad"]],
    remembered: [["You type", "bank.example", ""], ["Browser", "remembers bank.example said \"HTTPS only\" on an earlier visit", "ok"],
      ["Browser", "goes straight to https://, before sending anything", "ok"], ["Warnings", "certificate problems can't be clicked through on this site", "ok"],
      ["Result", "safe, from the second visit on", "ok"]],
    preload: [["You type", "bank.example", ""], ["Browser", "finds bank.example on its built-in preload list", "ok"],
      ["Browser", "uses https:// even on the very first visit", "ok"], ["Bonus", "whole endings like .app and .dev are preloaded: HTTPS only, always", "ok"],
      ["Result", "safe from the very first visit", "ok"]],
  };
  function hsts(kind) {
    document.querySelectorAll("[data-hsts]").forEach((b) => b.classList.toggle("on", b.dataset.hsts === kind));
    $("hsts-steps").innerHTML = HSTS[kind].map(([who, what, cls], i) => `<li class="${cls}" style="animation-delay:${i * 0.15}s"><b>${esc(who)}</b><span>${esc(what)}</span></li>`).join("");
  }

  // --------------------------------------------------------------------------- Certificate Transparency log
  let ctLog = [], ctBroken = false;
  function ctAppend(text, mine) {
    const prev = ctLog.length ? ctLog[ctLog.length - 1].head : new Uint8Array(32);
    const head = L.sha256(L.concat(prev, enc(text)));
    ctLog.push({ text, mine, head });
  }
  function ctDraw(msg) {
    $("ct-log").innerHTML = ctLog.map((e, i) => `<li class="${e.mine === "rogue" ? "rogue" : e.mine ? "mine" : ""}${ctBroken && i >= 1 ? " broken" : ""}"><span>#${i + 1}</span><b>${esc(e.text)}</b><code>${cut(L.hex(e.head), 12)}</code></li>`).join("");
    $("ct-out").innerHTML = msg;
  }
  function ctInit() {
    ctLog = []; ctBroken = false;
    ["shop.example · issued by Neon Issuing CA 1", "news.example · issued by Other CA", "bank.example · issued by Neon Issuing CA 1"].forEach((t, i) => ctAppend(t, i === 2));
    ctDraw(sp("m", "The bank's monitor watches every new entry for bank.example."));
  }

  // --------------------------------------------------------------------------- inspect: what this page knows about its own connection
  function inspect() {
    const secure = window.isSecureContext, proto = location.protocol;
    let nav = null;
    try { nav = performance.getEntriesByType("navigation")[0]; } catch (e) { nav = null; }
    const http = nav && nav.nextHopProtocol ? nav.nextHopProtocol : "not reported";
    $("inspect-out").innerHTML = `this page, from JavaScript's point of view:\n  address      ${esc(location.host || "(a local file)")}\n  protocol     ${esc(proto)} ${proto === "https:" ? sp("ok", "encrypted") : sp("y", "(run locally, so no TLS)")}\n` +
      `  secure page  ${secure ? sp("ok", "yes") : sp("bad", "no")}\n  HTTP version ${esc(http)}\n${sp("m", "the TLS details and certificate are only visible in the browser's own tools")}`;
  }

  // --------------------------------------------------------------------------- start
  function start() {
    console.log("%cHOW HTTPS REALLY WORKS", "font: 700 24px monospace; color: #47ffa3; text-shadow: 0 0 8px #47ffa3");
    console.log("%cYou're in the dev tools already. Find the security section: it shows the real handshake this page used.", "font: 14px monospace; color: #00f0ff");
    bind("hero-url", hero);
    click("dns-go", dnsLookup); $("dns-doh").addEventListener("change", dnsLookup); dnsLookup();
    document.querySelectorAll('input[name="cafe-mode"]').forEach((r) => r.addEventListener("change", cafe));
    $("cafe-evil").addEventListener("change", cafe); bind("cafe-path", cafe);
    buildHandshake();
    bind("hs-step", drawHandshake);
    click("hs-new", newConnection);
    ["cert-name", "cert-expired", "cert-root", "cert-tamper"].forEach((id) => $(id).addEventListener("change", certs)); certs();
    bind("rtt-ms", rtt);
    bind("rec-in", records); $("rec-pad").addEventListener("change", records);
    click("rec-tamper", () => { recTampered = !recTampered; $("rec-tamper").textContent = recTampered ? "Undo the flipped bit" : "Flip one bit on the way"; records(); });
    ["leak-doh", "leak-ech", "leak-vpn"].forEach((id) => $(id).addEventListener("change", leaks)); leaks();
    document.querySelectorAll("[data-hsts]").forEach((b) => b.addEventListener("click", () => hsts(b.dataset.hsts))); hsts("none");
    ctInit();
    click("ct-normal", () => { ctBroken = false; ctAppend("bank.example · issued by Neon Issuing CA 1 (renewal)", true); ctDraw(sp("ok", "monitor: new bank.example certificate from our usual CA. Expected.")); });
    click("ct-rogue", () => { ctBroken = false; ctAppend("bank.example · issued by Sketchy CA", "rogue"); ctDraw(sp("bad", "monitor ALERT: a bank.example certificate we didn't ask for! Report it so the CA revokes it and browsers act.")); });
    click("ct-edit", () => { if (ctLog.length < 2) return; ctBroken = true; ctDraw(sp("bad", "entry #1 changed → every later hash no longer matches. The edit is obvious to anyone checking the log.")); });
    inspect();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
})();
