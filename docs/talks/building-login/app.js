/* app.js - the live demos for "Building Login and Accounts Safely".
   Every demo is a simulation in this page: a made-up user table, a pretend session store, a pretend mail server.
   The hashes are real (Argon2id from hash-wasm, P-256 signatures from the shared crypto code); nothing is fetched
   and nothing you type is sent anywhere. The server-side logic is in auth.js. */
(function () {
  "use strict";
  const L = window.Lab, A = window.Auth, HW = window.hashwasm || null;

  // --------------------------------------------------------------------------- helpers
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const sp = (cls, s) => `<span class="${cls}">${esc(s)}</span>`;
  const click = (id, fn) => $(id).addEventListener("click", fn);
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const short = (s, n = 8) => (s.length > n + 1 ? s.slice(0, n) + "…" : s);
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
  const say = (id, cls, text) => { const el = $(id); el.className = "comment" + (cls ? " " + cls : ""); el.textContent = text; };
  const verdict = (id, cls, text) => { const el = $(id); el.className = "verdict " + cls; el.textContent = text; };
  /** Disable a button while an async job runs (the maths and the hashing take a moment). */
  const busy = async (btn, fn) => { btn.disabled = true; try { await fn(); } finally { btn.disabled = false; } };
  const hms = (d = new Date()) => d.toTimeString().slice(0, 8);

  // Argon2id through hash-wasm, in the shape auth.js expects
  const H = {
    argon2id: (pw, o = {}) => HW.argon2id({ password: pw, salt: L.randBytes(16), iterations: o.t || 2, parallelism: 1, memorySize: o.m || 19456, hashLength: 32, outputType: "encoded" }),
    verify: (enc, pw) => HW.argon2Verify({ password: pw, hash: enc }),
  };

  // --------------------------------------------------------------------------- title: the same answer for every failure
  const KNOWN = ["alice", "bob", "carol"];
  function hero() {
    const el = $("hero-in"), v = el.value;
    el.style.width = Math.min(30, Math.max(6, v.length + 1)) + "ch";
    const t = v.trim().toLowerCase(), known = KNOWN.includes(t);
    $("hero-out").innerHTML =
      `${sp("k", "server knows:")}  account ${known ? sp("ok", "exists") : sp("bad", "does not exist")}  ${sp("m", "(never shown)")}<br>` +
      `${sp("k", "client sees: ")}  401 Invalid email or password<br>` +
      `${sp("k", "work done:   ")}  one password hash, either way`;
    let note;
    if (t === "admin") note = "# Achievement unlocked: every IoT device ever. (The default account that should have been disabled.)";
    else if (t === "root") note = "# root: the other famous default. Same answer, same cost, no matter who is asking.";
    else if (t === "hunter2") note = "# *******. An old IRC joke: it only ever showed stars. Same answer here too.";
    else if (v === "") note = "# no name at all: still the same answer. Validate it, don't comment on it.";
    else if (v.length > 30) note = "# a very long username: same answer. Cap the length, so nobody posts you a novel.";
    else if (known) note = "# alice has an account, and nobody outside can tell. That's the goal.";
    else note = "# no such account, and nobody outside can tell either. Try alice, bob or carol.";
    $("hero-note").textContent = note;
  }

  // --------------------------------------------------------------------------- password rules
  function pr() {
    const pw = $("pr-pw").value, user = $("pr-user").value, mfa = $("pr-mfa").checked;
    const r = A.checkPassword(pw, { mfa, username: user });
    $("pr-list").innerHTML = r.checks.map((c) => `<li class="${c.ok === true ? "ok" : c.ok === false ? "bad" : "y"}"><b>${c.ok === true ? "✓" : c.ok === false ? "✗" : "!"}</b><span>${esc(c.text)}</span></li>`).join("") +
      `<li class="y"><b>!</b><span>${r.oldStyle ? "old-style complexity rules would pass this" : "old-style complexity rules would reject this"}</span></li>`;
    const p = A.pwnedRange(pw), hit = A.isBlocked(pw);
    $("pr-range").innerHTML = pw === "" ? sp("m", "Type a password to see the breach check.") :
      `${sp("k", "SHA-1 (made here):")} ${sp("c", p.prefix)}${sp("m", p.suffix)}\n` +
      `${sp("k", "leaves this page:  ")} GET /range/${sp("c", p.prefix)}   ${sp("m", "← five characters, nothing else")}\n` +
      `${sp("k", "compared at home:  ")} ${sp("m", p.suffix)}  ${hit ? sp("bad", "found in the toy list: breached") : sp("ok", "not in the toy list")}`;
    const t = pw.trim().toLowerCase(), u = user.trim().toLowerCase();
    let note;
    if (u === "admin" && t === "admin") note = "# Achievement unlocked: every IoT device ever.";
    else if (t === "password1!") note = "# Complexity theatre: every old rule satisfied, and it's on every blocklist.";
    else if (t === "correct horse battery staple") note = "# xkcd 936. Famous passphrases are likely on blocklists by now: pick your own words.";
    else if (t === "hunter2") note = "# *******. A classic, and on the list.";
    else if (pw === "") note = "# use a made-up password: nothing leaves this page, but it's a good habit anyway.";
    else if (r.accepted) note = "# accepted. Notice what it didn't need: a symbol, a capital, or a calendar reminder.";
    else note = "# rejected, with a reason. Always say why: \"try another\" teaches nothing.";
    say("pr-note", r.accepted ? "ok" : "", note);
  }

  // --------------------------------------------------------------------------- rehash on login
  const DEMO = { alice: "summer2019", bob: "letmein123", carol: "blue-lantern-42", dave: "mango-river-sky", eve: "swordfish" };
  let rhDb = null, rhLog = [], rhFlash = null;
  const rhStatus = (name) => {
    const rec = rhDb[name];
    if (rec.expired) return { cls: "exp", text: "expired: reset by email" };
    const s = A.hashStatus(rec.hash);
    if (s.good) return { cls: "good", text: "✓ current Argon2id" };
    if (s.kind === "argon2id") return { cls: "weak", text: "✗ Argon2id, weak settings" };
    return { cls: "weak", text: "✗ fast, unsalted " + s.kind.toUpperCase() };
  };
  function rhRender() {
    $("rh-rows").innerHTML = Object.keys(DEMO).map((n) => {
      const st = rhStatus(n), h = rhDb[n].hash;
      return `<tr class="${rhFlash === n ? "flash" : ""}"><td>${n}${n === "eve" ? '<small class="m"> (last seen 2019)</small>' : ""}</td><td>${esc(h.startsWith("$") ? h.slice(0, 32) + "…" : short(h, 30))}</td><td class="${st.cls}">${esc(st.text)}</td></tr>`;
    }).join("");
    $("rh-log").innerHTML = rhLog.slice(-7).join("\n");
  }
  const rhPush = (html) => { rhLog.push(html); rhRender(); };
  async function rhInit() {
    if (!HW) { $("rh-log").textContent = "hash-wasm didn't load, so this demo can't run here."; return; }
    rhDb = {
      alice: { hash: "sha1:" + L.hex(L.sha1(L.utf8(DEMO.alice))) },
      bob: { hash: "sha256:" + A.sha256hex(DEMO.bob) },
      carol: { hash: await H.argon2id(DEMO.carol, { m: 4096, t: 1 }) },
      dave: { hash: await H.argon2id(DEMO.dave) },
      eve: { hash: "sha1:" + L.hex(L.sha1(L.utf8(DEMO.eve))) },
    };
    rhLog = []; rhFlash = null;
    $("rh-user").innerHTML = Object.keys(DEMO).map((n) => `<option>${n}</option>`).join("");
    $("rh-pw").value = DEMO.alice;
    say("rh-note", "", "# the passwords are filled in for you. Try a wrong one first.");
    rhRender();
  }
  async function rhLogin(name, pw) {
    const t0 = performance.now();
    const r = await A.loginWithRehash(rhDb, name, pw, H), ms = Math.round(performance.now() - t0);
    if (r.expired) rhPush(`${sp("y", "✗")} ${esc(name)}: the old hash was expired, so a reset email is needed`);
    else if (!r.ok) rhPush(`${sp("bad", "✗")} ${esc(name)}: login failed ${sp("m", "(\"Invalid email or password\"; nothing was changed)")}`);
    else if (r.rehashed) { rhFlash = name; rhPush(`${sp("ok", "✓")} ${esc(name)} logged in · rehashed ${sp("k", r.from.kind)} → ${sp("ok", "argon2id")} ${sp("m", "(m=19456, t=2) · " + ms + " ms")}`); }
    else rhPush(`${sp("ok", "✓")} ${esc(name)} logged in · hash already current, nothing to do ${sp("m", "· " + ms + " ms")}`);
    rhNote();
    return r;
  }
  function rhNote() {
    const others = Object.keys(DEMO).filter((n) => n !== "eve");
    const cur = (n) => !rhDb[n].expired && A.hashStatus(rhDb[n].hash).good;
    if (others.every(cur) && rhDb.eve.expired) say("rh-note", "ok", "# every account is current or expired, and nobody was asked to do anything. Boring is the goal.");
    else if (others.every(cur)) say("rh-note", "", "# four accounts upgraded silently. Eve never logs in, so nothing can upgrade her: expire her hash.");
    else say("rh-note", "", `# ${others.filter(cur).length} of 4 active accounts are current so far.`);
  }
  async function rhAll(btn) {
    for (const n of ["alice", "bob", "carol", "dave"]) { $("rh-user").value = n; $("rh-pw").value = DEMO[n]; await rhLogin(n, DEMO[n]); await sleep(60); }
    $("rh-pw").value = DEMO.eve; $("rh-user").value = "eve";
  }

  // --------------------------------------------------------------------------- sessions
  let S, planted, ids;
  function sessFresh() { S = new A.SessionStore(); planted = null; ids = {}; sessRender(); say("se-note", "", "# try fixation first (row 1), with the box ticked and then unticked."); }
  function sessStatus(r) {
    if (r.revoked) return sp("bad", "revoked: " + r.revoked);
    if (S.now - r.last > S.idle) return sp("y", "expired: idle");
    if (S.now - r.created > S.absolute) return sp("y", "expired: absolute");
    return sp("ok", "valid");
  }
  const pad = (s, n) => String(s).padEnd(n, " ");
  function sessRender() {
    const rows = [...S.rows.entries()];
    $("se-table").innerHTML = `${sp("m", "clock: +" + Math.round(S.now / 60) + " min    idle limit 30 min · absolute 8 h")}\n` +
      `${sp("m", pad("who", 11) + pad("device", 17) + pad("ID (hash)", 11) + "status")}\n` +
      (rows.length ? rows.map(([k, r]) => `${pad(r.user || "anonymous", 11)}${esc(pad(r.device || "-", 17))}${sp("c", pad(k.slice(0, 8), 11))}${sessStatus(r)}`).join("\n") : sp("m", "(no sessions yet)"));
  }
  function sessInit() {
    sessFresh();
    click("se-reset", sessFresh);
    click("se-plant", () => { planted = S.create(null, "planted by attacker"); sessRender(); say("se-note", "", `# the attacker now knows ID ${planted.slice(0, 8)}… and gets the victim to arrive with it (a crafted link, or a cookie set from a sibling site).`); });
    click("se-victim", () => {
      if (!planted) return say("se-note", "", "# plant an ID first.");
      const rot = $("se-rotate").checked;
      ids.victim = S.login("alice", "victim's browser", planted, { rotate: rot }); sessRender();
      say("se-note", "", rot ? "# login: a brand-new ID was issued, and the planted one retired." : "# login: the server kept the ID the browser arrived with, and just added the user. That's the bug.");
    });
    click("se-use", () => {
      if (!planted) return say("se-note", "", "# plant an ID first.");
      const c = S.check(planted); sessRender();
      say("se-note", c.ok && c.user ? "bad" : "ok", c.ok && c.user ? `# ✗ the attacker's ID works: they are signed in as ${c.user}.` : `# ✓ the attacker's ID is useless now (${c.reason || "no user on it"}).`);
    });
    const signIn = (dev) => { ids[dev] = S.login("alice", dev, null, { rotate: true }); sessRender(); say("se-note", "", `# signed in on the ${dev}.`); };
    click("se-laptop", () => signIn("laptop")); click("se-phone", () => signIn("phone"));
    click("se-idle", () => { S.advance(31 * 60); sessRender(); say("se-note", "", "# 31 minutes with no activity. Anything idle for longer than 30 minutes has expired, server-side."); });
    click("se-day", () => { S.advance(9 * 3600); sessRender(); say("se-note", "", "# 9 hours later: past the 8-hour absolute limit, however active the session was."); });
    click("se-pw", () => {
      if (!ids.laptop || !S.check(ids.laptop).ok) return say("se-note", "", "# sign in on the laptop first (the password change happens from there).");
      ids.laptop = S.changePassword("alice", ids.laptop); sessRender();
      say("se-note", "ok", "# password changed: the laptop got a new ID, and every other session was ended.");
    });
    click("se-out", () => { const n = S.revokeAll("alice"); sessRender(); say("se-note", "", `# signed out everywhere: ${n} session${n === 1 ? "" : "s"} ended on the server. A copied cookie is dead too.`); });
  }

  // --------------------------------------------------------------------------- refresh tokens
  let G, rfN, rfFirst, rfApp, rfLog;
  const rfName = (t) => "R" + (rfN.get(t) || "?");
  function rfFresh() {
    G = new A.RefreshGrant(); rfN = new Map(); rfApp = G.issue(); rfN.set(rfApp, 1); rfFirst = rfApp;
    rfLog = [`${sp("m", "login")}: the app is given refresh token ${sp("c", "R1")}`];
    rfDraw();
  }
  const rfDraw = () => { $("rf-log").innerHTML = rfLog.slice(-9).join("\n"); };
  function rfInit() {
    rfFresh();
    click("rf-reset", rfFresh);
    click("rf-legit", () => {
      const r = G.refresh(rfApp);
      if (r.ok) { rfN.set(r.token, rfN.size + 1); rfLog.push(`${sp("ok", "✓")} app refreshes with ${sp("c", rfName(rfApp))} → gets ${sp("c", rfName(r.token))}; ${rfName(rfApp)} is retired`); rfApp = r.token; }
      else rfLog.push(`${sp("bad", "✗")} app refreshes with ${sp("c", rfName(rfApp))}: ${esc(r.reason)}`);
      rfDraw();
    });
    click("rf-thief", () => {
      const r = G.refresh(rfFirst);
      if (r.ok) { rfN.set(r.token, rfN.size + 1); rfLog.push(`${sp("y", "!")} thief replays ${sp("c", "R1")} and it was still the current token: they get ${sp("c", rfName(r.token))}. (Refresh once, then try again.)`); rfApp = r.token; }
      else rfLog.push(`${sp("bad", "✗")} thief replays ${sp("c", "R1")}: ${esc(r.reason)}${r.reuse ? "\n   " + sp("m", "the server can't tell who is real, so it ends the grant for both") : ""}`);
      rfDraw();
    });
  }

  // --------------------------------------------------------------------------- TOTP verifier
  let V, tpSecret, tpLast = "", tpLockUntil = 0;
  function tpFresh() {
    tpSecret = L.randBytes(20); V = new A.TotpVerifier(tpSecret);
    $("tp-secret").value = L.base32Encode(tpSecret).match(/.{1,4}/g).join(" ");
    $("tp-log").innerHTML = ""; verdict("tp-verdict", "y", "Press Verify."); tpTick();
  }
  const tpPhoneNow = () => Date.now() / 1000 + (+$("tp-off").value);
  function tpTick() {
    const t = tpPhoneNow(), c = Math.floor(t / 30);
    $("tp-code").textContent = V.codeAt(c);
    $("tp-left").textContent = `new code in ${30 - Math.floor(t % 30)} s`;
  }
  const tpPush = (html) => { tpLast = (tpLast ? tpLast + "\n" : "") + html; $("tp-log").innerHTML = tpLast.split("\n").slice(-6).join("\n"); tpLast = tpLast.split("\n").slice(-6).join("\n"); };
  function tpVerify() {
    const code = $("tp-in").value.trim(), now = Date.now() / 1000, step = Math.floor(now / 30);
    if (Date.now() < tpLockUntil) { verdict("tp-verdict", "bad", "Throttled: too many wrong codes. A real server slows down here."); return; }
    const r = V.verify(code, now);
    tpPush(`${sp("m", hms())} server step ${step} (accepts ${step - 1}–${step + 1}) · code ${esc(code || "(empty)")} → ${r.ok ? sp("ok", "accepted") : sp("bad", r.reason)}`);
    if (r.ok) verdict("tp-verdict", "ok", r.message);
    else if (r.reason === "wrong" && /^0{6}$/.test(code)) verdict("tp-verdict", "bad", "Nice try. Rejected.");
    else verdict("tp-verdict", r.reason === "reused" ? "y" : "bad", r.message);
    if (V.fails >= 5) { tpLockUntil = Date.now() + 8000; V.fails = 0; tpPush(sp("y", "5 wrong codes in a row: throttled for 8 s")); }
  }

  // --------------------------------------------------------------------------- passkeys (WebAuthn), simulated with real P-256 signatures
  const RPID = "example.com", ORIGIN = "https://login.example.com";
  let RP, AU, lastResp = null;
  const waOut = (html) => { $("wa-out").innerHTML = html; };
  const waFlags = (f) => ["UP", "UV", "BE", "BS"].filter((k) => f & A.FLAGS[k]).join(" ");
  const waHelp = () => waOut(`${sp("m", "Press 1 to create a passkey for " + RPID + ", then 2 to log in with it.\nEach step shows what the server sends, what comes back, and what it keeps.\n\nThe signatures are real P-256 (the curve from Crypto 101); the rest is simplified.")}`);
  function waFresh() { RP = new A.RelyingParty(RPID, ORIGIN); AU = null; lastResp = null; waHelp(); }
  const steps = (list) => list.map((s) => `  ${s.ok ? sp("ok", "✓") : sp("bad", "✗")} ${esc(s.name)}${s.detail ? "  " + sp("m", s.detail) : ""}`).join("\n");
  function waRegister() {
    AU = new A.Authenticator(); const rec = RP.register(AU); lastResp = null;
    const pt = L.spkiP256(rec.publicKey), h = (x) => x.toString(16).padStart(64, "0");
    waOut(`${sp("c", "YOUR DEVICE")}  (fingerprint, face or PIN)\n  makes a key pair for ${sp("y", RPID)}\n  private key   ${sp("k", "stays in the authenticator. Always.")}\n\n` +
      `${sp("c", "THE SERVER KEEPS")}  ${sp("m", "(this is the whole record)")}\n  credential ID  ${esc(short(rec.credentialId, 22))}\n  public key     x = ${esc(h(pt[0]).slice(0, 24))}…\n                 y = ${esc(h(pt[1]).slice(0, 24))}…\n  signCount      ${rec.signCount}\n  rpIdHash       SHA-256("${RPID}") = ${esc(L.hex(rec.rpIdHash).slice(0, 20))}…\n  backup flags   ${sp("m", "backup-eligible: a synced passkey")}\n\n` +
      sp("m", "Nothing here can log in as the user. A stolen table is no use to an attacker."));
  }
  function waLogin() {
    if (!AU) return waOut(sp("y", "Create a passkey first (button 1)."));
    const ch = RP.challenge(), resp = AU.sign({ rpId: RPID, origin: ORIGIN, challenge: ch }); lastResp = resp;
    const v = RP.verify(resp), cd = L.text(resp.clientDataJSON);
    waOut(`${sp("c", "SERVER → BROWSER")}   challenge ${esc(short(ch, 20))}  ${sp("m", "(random, single use)")}\n\n` +
      `${sp("c", "DEVICE → SERVER")}\n  clientDataJSON  ${esc(cd.replace(ch, short(ch, 10)))}\n  authenticatorData  rpIdHash | flags ${sp("y", waFlags(resp.authData[32]))} | signCount ${new DataView(resp.authData.buffer, 33, 4).getUint32(0)}\n  signature  ${esc(short(L.hex(resp.signature), 40))}\n\n` +
      `${sp("c", "SERVER CHECKS")}\n${steps(v.steps)}\n\n${v.ok ? sp("ok", "✓ LOGGED IN") + sp("m", "  The signature proves the device holds the key.") : sp("bad", "✗ REJECTED")}`);
  }
  function waReplay() {
    if (!AU) return waOut(sp("y", "Create a passkey first (button 1)."));
    if (!lastResp) return waOut(sp("y", "Log in first (button 2): the replay needs a captured login."));
    const v = RP.verify(lastResp);
    waOut(`${sp("c", "ATTACKER → SERVER")}   the exact login message from before, sent again\n\n${sp("c", "SERVER CHECKS")}\n${steps(v.steps)}\n\n${v.ok ? sp("bad", "✗ ACCEPTED (should never happen)") : sp("ok", "✓ REJECTED") + sp("m", "  Every challenge works once, so a captured login is worth nothing.")}`);
  }
  function waPhish() {
    waOut(`${sp("c", "A LOOK-ALIKE SITE")}  ${sp("y", "login-example.com")} asks the browser to sign in with a passkey for ${sp("y", RPID)}\n\n` +
      `${sp("c", "BROWSER")}   this page isn't ${RPID}: it won't ask for ${RPID}'s passkey\n${sp("c", "DEVICE")}    no passkey for login-example.com: ${sp("ok", "nothing is signed")}\n\n` +
      `${sp("m", "There is nothing to type, and nothing to relay.\nYour passkey: \"I don't know that website.\"")}`);
  }
  function waClone() {
    if (!AU) return waOut(sp("y", "Create a passkey first (button 1)."));
    if (!lastResp) { waLogin(); }
    const rec = RP.creds.get(AU.credentialId), ch = RP.challenge();
    const resp = AU.sign({ rpId: RPID, origin: ORIGIN, challenge: ch, counter: rec.signCount });
    const v = RP.verify(resp);
    waOut(`${sp("c", "A COPY OF THE KEY SIGNS")}  ${sp("m", "(the signature is valid, but its counter didn't move on)")}\n\n${sp("c", "SERVER CHECKS")}\n${steps(v.steps)}\n\n` +
      `${v.clone ? sp("y", "! SIGNAL, NOT PROOF") + sp("m", "  Log it, maybe ask for another factor. Many synced passkeys always report 0: that's normal.") : v.ok ? sp("ok", "✓ accepted") : sp("bad", "✗ rejected")}`);
  }

  // --------------------------------------------------------------------------- reset links
  let R, rsCount = 0;
  function rsFresh() { R = new A.ResetService(); rsCount = 0; $("rs-mail").textContent = "(nothing yet)"; $("rs-db").textContent = "(nothing yet)"; $("rs-log").innerHTML = ""; verdict("rs-verdict", "y", 'Press "Request a reset".'); }
  function rsDraw() {
    const mins = (t) => Math.round((t - R.now) / 60);
    $("rs-db").innerHTML = R.db.length ? R.db.slice(-3).map((r) => `${sp("c", r.hash.slice(0, 14))}…\n  ${sp("m", "for")} ${esc(r.email)}\n  ${r.used === true ? sp("m", "used") : r.used ? sp("m", r.used) : R.now > r.expires ? sp("y", "expired") : sp("ok", "expires in " + mins(r.expires) + " min")}`).join("\n\n") : "(nothing yet)";
    $("rs-log").innerHTML = R.log.slice(rsCount >= 10 ? -2 : -3).map((l) => sp("m", "server: " + l)).join("\n") + (rsCount >= 10 ? "\n" + sp("y", "# Have you tried a password manager? We did a whole talk.") : "");
  }
  function rsInit() {
    rsFresh();
    click("rs-reset", rsFresh);
    click("rs-req", () => {
      rsCount++;
      const before = R.outbox.length, r = R.request("alice@example.test", true);
      verdict("rs-verdict", "y", "The user sees: \"" + r.message + "\"");
      if (R.outbox.length > before) $("rs-mail").innerHTML = `To: alice@example.test\nSubject: Reset your password\n\nhttps://example.test/reset?token=\n${sp("c", r.token)}\n\n${sp("m", "valid once, for 30 minutes")}`;
      else $("rs-mail").innerHTML = sp("m", "(no new email arrived: the server stopped sending after 3 in an hour, and said nothing different)");
      rsDraw();
    });
    const useLink = (label) => {
      if (!R.outbox.length) return verdict("rs-verdict", "y", 'Request a reset first.');
      const r = R.redeem(R.outbox[R.outbox.length - 1].token); rsDraw();
      verdict("rs-verdict", r.ok ? "ok" : "bad", r.ok ? "Link accepted. Now: set the password, end other sessions, email the user, no auto-login." : "Rejected: " + r.reason + ".");
    };
    click("rs-use", () => useLink()); click("rs-again", () => useLink());
    click("rs-late", () => { R.advance(31 * 60); rsDraw(); verdict("rs-verdict", "y", "The clock moved on 31 minutes. Try the link."); });
  }

  // --------------------------------------------------------------------------- recovery codes
  let RC;
  function rcDraw() {
    if (!RC) return;
    $("rc-out").innerHTML = `${sp("c", "SHOWN ONCE TO THE USER")}  ${sp("m", "(print them, or save them in a password manager)")}\n` +
      RC.codes.map((c, i) => `  ${RC.rows[i].used ? sp("m", c + "  used") : sp("ok", c)}`).join("\n") +
      `\n\n${sp("c", "WHAT THE DATABASE KEEPS")}  ${sp("m", RC.left + " of 10 left")}\n` +
      RC.rows.slice(0, 4).map((r) => `  sha256 ${esc(r.hash.slice(0, 20))}…  ${r.used ? "used" : "unused"}`).join("\n") + `\n  ${sp("m", "… (10 hashes in all, no codes)")}`;
  }
  function rcInit() {
    click("rc-gen", () => { RC = new A.RecoveryCodes(); rcDraw(); say("rc-note", "", "# the codes are random, and only their hashes are kept. Try the first one."); $("rc-in").value = RC.codes[0]; });
    click("rc-use", () => {
      if (!RC) return say("rc-note", "", '# press "Make 10 codes" first.');
      const r = RC.redeem($("rc-in").value); rcDraw();
      say("rc-note", r.ok ? "ok" : "bad", r.ok ? `# ✓ accepted. ${r.left} left. A real server also emails the user: "a recovery code was used".` + (r.left === 0 ? " All used up: offer a fresh set." : "") : "# ✗ " + r.reason + ".");
    });
  }

  // --------------------------------------------------------------------------- credential stuffing
  const fmt = (n) => n.toLocaleString("en-US");
  function st() {
    $("st-mfa-o").textContent = $("st-mfa").value + "%";
    const o = { ips: +$("st-ips").value, ipLimit: $("st-ipl").checked, breachCheck: $("st-breach").checked, risk: $("st-risk").checked, mfaPct: +$("st-mfa").value };
    const s = A.simulateStuffing(o), none = A.simulateStuffing({ ips: o.ips });
    $("st-stats").innerHTML =
      `<div><b>${fmt(s.tries)}</b><span>guesses made</span></div>` +
      `<div class="${s.blockedIp ? "good" : ""}"><b>${fmt(s.blockedIp)}</b><span>stopped by address limit</span></div>` +
      `<div class="${s.takenOver ? "bad" : "good"}"><b>${fmt(s.takenOver)}</b><span>accounts taken over (${fmt(none.takenOver)} with no defences)</span></div>` +
      `<div><b>${fmt(s.friction)}</b><span>honest sign-ins in 1,000 asked for an extra step</span></div>`;
    const row = (label, n, extra = "") => `  ${esc(label.padEnd(24))}${esc(fmt(n).padStart(5))}${extra}`;
    $("st-log").innerHTML =
      `${sp("m", "2,000 stolen pairs · 1 try each · from " + fmt(o.ips) + " address" + (o.ips === 1 ? "" : "es"))}\n` +
      row("stopped by address limit", s.blockedIp) + "\n" + row("wrong password", s.wrong, "  " + sp("m", "(not reused: the other 80%)")) + "\n" + row("valid pairs", s.valid) + "\n" +
      row("breached-password block", s.breachBlocked) + "\n" + row("new-device step-up", s.riskBlocked) + "\n" + row("stopped by MFA", s.mfaBlocked) + "\n" +
      sp(s.takenOver ? "bad" : "ok", row("taken over", s.takenOver));
    let note;
    if (s.takenOver === 0) note = "# zero. Each layer caught what the one before it missed.";
    else if (o.ips === 1 && o.ipLimit) note = "# one address is easy to stop, and attackers know it: they rent more.";
    else if (o.ipLimit && !o.breachCheck && !o.risk && !o.mfaPct) note = "# a per-address limit barely registers: each address only tries a few times.";
    else if (!o.ipLimit && !o.breachCheck && !o.risk && !o.mfaPct) note = "# no defences: every reused password works. Try blocking breached passwords next.";
    else if (s.takenOver < none.takenOver / 4) note = `# down from ${fmt(none.takenOver)} to ${fmt(s.takenOver)}. Notice what it costs honest users.`;
    else note = "# better, not enough. Layer another defence.";
    say("st-note", s.takenOver === 0 ? "ok" : "", note);
  }

  // --------------------------------------------------------------------------- account enumeration
  let enMode = "naive";
  const EN_KNOWN = ["alice@example.test", "bob@example.test", "carol@example.test"], EN_PW = "correct-horse";
  async function enSend(user, pw) {
    const exists = EN_KNOWN.includes(user.trim().toLowerCase()), r = A.loginResponse(enMode, exists, exists && pw === EN_PW);
    const t0 = performance.now();
    if (r.hashes) { if (HW) await H.argon2id(pw || "x"); else await sleep(90); }
    return { r, ms: Math.round(performance.now() - t0), exists };
  }
  const enLines = [];
  async function enOne() {
    const u = $("en-user").value, res = await enSend(u, $("en-pw").value);
    enLines.push(`POST /login  ${esc(u)}\n   ${sp(res.r.status === 200 ? "ok" : "bad", res.r.status + " " + res.r.body)}   ${sp("c", res.ms + " ms")}`);
    $("en-out").innerHTML = enLines.slice(-4).join("\n");
    say("en-note", "", enMode === "naive" ? (res.exists ? "# slower and a different message: this account exists." : "# fast, and a different message: there is no such account.") : "# same message, same status, about the same time, whatever the account.");
  }
  async function enProbe(btn) {
    const names = ["alice", "mallory", "bob", "zed", "carol", "trent"].map((n) => n + "@example.test"), rows = [];
    let found = 0;
    for (const n of names) {
      const res = await enSend(n, "x");
      const guess = enMode === "naive" ? (res.r.body.startsWith("No account") ? "no" : "YES") : "can't tell";
      if (guess === "YES") found++;
      rows.push(`${esc(n.padEnd(21))}${sp("m", String(res.r.status))} ${esc(res.r.body.padEnd(28))}${sp("c", String(res.ms).padStart(4) + " ms")}   ${guess === "YES" ? sp("bad", "→ has an account") : guess === "no" ? sp("m", "→ none") : sp("ok", "→ can't tell")}`);
      $("en-out").innerHTML = rows.join("\n");
    }
    enLines.length = 0;
    say("en-note", enMode === "naive" ? "" : "ok", enMode === "naive" ? `# the attacker learned that ${found} of 6 names are real customers, without a single password.` : "# nothing to learn: every reply says the same thing in the same time. That's the point.");
  }

  // --------------------------------------------------------------------------- review checklist
  const RV_KEY = "login-review";
  function review() {
    const boxes = Array.from(document.querySelectorAll("#rv-list input[type=checkbox]"));
    let saved = {};
    try { saved = JSON.parse(store(RV_KEY) || "{}"); } catch (e) {}
    boxes.forEach((b) => { b.checked = !!saved[b.dataset.k]; });
    const update = () => {
      const done = boxes.filter((b) => b.checked).length;
      store(RV_KEY, JSON.stringify(Object.fromEntries(boxes.map((b) => [b.dataset.k, b.checked]))));
      const n = $("rv-note"); n.className = "comment";
      if (done === boxes.length) { n.textContent = `# ${done} of ${done}. Ship it, then run the list again in three months: libraries, standards and attackers all move.`; n.classList.add("ok"); }
      else if (!done) n.textContent = "# tick what your project does today. Each gap is a ticket, not a failure. Saved in this browser only.";
      else n.textContent = `# ${done} of ${boxes.length}. Pick the unticked box most likely to bite and fix that first.`;
    };
    boxes.forEach((b) => b.addEventListener("change", update));
    update();
  }

  // --------------------------------------------------------------------------- easter egg: console
  function consoleHint() {
    console.log("%cBuilding Login and Accounts Safely", "font: 700 24px monospace; color: #ff2e88; text-shadow: 0 0 8px #ff2e88");
    console.log("%cYou found the console. The best passwords here are long and boring. Try 000000 in the TOTP demo, or ask for ten password resets.", "font: 14px monospace; color: #00f0ff");
  }

  function start() {
    consoleHint();
    $("hero-in").addEventListener("input", hero); hero();
    for (const id of ["pr-user", "pr-pw"]) $(id).addEventListener("input", pr);
    $("pr-mfa").addEventListener("change", pr); pr();
    rhInit().then(() => {
      $("rh-user").addEventListener("change", () => { $("rh-pw").value = DEMO[$("rh-user").value]; });
      click("rh-login", (e) => busy(e.currentTarget, () => rhLogin($("rh-user").value, $("rh-pw").value)));
      click("rh-all", (e) => busy(e.currentTarget, rhAll));
      click("rh-sweep", () => { const d = A.sweepExpire(rhDb); rhPush(d.length ? `${sp("y", "sweep")}: expired ${esc(d.join(", "))} (they set a new password by email at next visit)` : sp("m", "sweep: nothing left to expire")); rhNote(); });
      click("rh-reset", (e) => busy(e.currentTarget, rhInit));
    });
    sessInit(); rfInit();
    tpFresh(); setInterval(tpTick, 500); $("tp-off").addEventListener("change", tpTick);
    click("tp-fill", () => { $("tp-in").value = $("tp-code").textContent; });
    click("tp-go", tpVerify); $("tp-in").addEventListener("keydown", (e) => { if (e.key === "Enter") tpVerify(); });
    waFresh();
    click("wa-reg", (e) => busy(e.currentTarget, async () => { await sleep(20); waRegister(); }));
    click("wa-login", (e) => busy(e.currentTarget, async () => { await sleep(20); waLogin(); }));
    click("wa-replay", (e) => busy(e.currentTarget, async () => { await sleep(20); waReplay(); }));
    click("wa-phish", waPhish);
    click("wa-clone", (e) => busy(e.currentTarget, async () => { await sleep(20); waClone(); }));
    click("wa-reset", waFresh);
    rsInit(); rcInit();
    for (const id of ["st-ips", "st-ipl", "st-breach", "st-risk"]) $(id).addEventListener("change", st);
    $("st-mfa").addEventListener("input", st); st();
    segPick("en-mode", "data-m", (m) => { enMode = m; enLines.length = 0; $("en-out").innerHTML = ""; say("en-note", "", ""); });
    click("en-send", (e) => busy(e.currentTarget, enOne));
    click("en-probe", (e) => busy(e.currentTarget, () => enProbe()));
    review();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
})();
