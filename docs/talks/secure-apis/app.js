/* app.js - the live demos for "Building Secure APIs".
   Every demo is a simulation in this page: a mock API with invented users and invoices, a token inspector that signs
   tokens with a throwaway key made when the page loads, and invented error messages. Nothing is fetched and nothing
   you type is sent anywhere. The signing maths is the page's own P-256 code from ../../shared/crypto.js (window.Lab). */
(function () {
  "use strict";
  const L = window.Lab;

  // --------------------------------------------------------------------------- helpers
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const sp = (cls, s) => `<span class="${cls}">${esc(s)}</span>`;
  const click = (id, fn) => $(id).addEventListener("click", fn);
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
  const presets = (id, attr, fn) => $(id).addEventListener("click", (e) => { const b = e.target.closest("button[" + attr + "]"); if (b) fn(b.getAttribute(attr)); });
  const verdict = (id, cls, text) => { const el = $(id); el.className = "verdict " + cls; el.textContent = text; };
  const clock = () => (typeof window.__clock === "function" ? window.__clock() : performance.now());
  const json = (o) => JSON.stringify(o, null, 2);

  // --------------------------------------------------------------------------- title: the four gates
  function hero() {
    const el = $("hero-in"), v = el.value;
    el.style.width = Math.min(34, Math.max(8, v.length + 1)) + "ch";
    const t = v.trim();
    let m = /^([A-Za-z]+)\s+(\S+)/.exec(t), method, path;
    if (m) { method = m[1].toUpperCase(); path = m[2]; }
    else if (/^\//.test(t)) { method = "GET"; path = t.split(/\s+/)[0]; }
    const out = $("hero-out");
    if (!path) {
      out.innerHTML = `${sp("m", "1 who is calling?   2 may they?   3 is the input right?   4 how often?")}`;
      $("hero-note").textContent = "# no request, no gates. Type a method and a path.";
      return;
    }
    const write = method !== "GET" && method !== "HEAD";
    const idSeg = /\/(\d+|[0-9a-f]{8}-[0-9a-f-]{27}|me)(\/|$)/i.test(path.split("?")[0]);
    const priv = /\/(admin|internal|debug|export|impersonate)(\/|$)/i.test(path);
    const fn = priv ? "admin-only: needs a role" : write ? `${method} changes data: own rule` : "read: still needs a rule";
    const obj = idSeg ? "this object: the caller's?" : "no ID: scope lists to caller";
    const row = (label, ...lines) => `<span class="g"><b class="k">${esc(label)}</b><span>${lines.map(esc).join("<br>")}</span></span>`;
    out.innerHTML =
      row("1 authenticate", "who is calling? none → 401") +
      row("2 authorize", fn, obj) +
      row("3 validate", write ? "body: schema, no extras" : "path, query: type, range") +
      row("4 limit", "per key or user → 429");
    const low = t.toLowerCase();
    let note;
    if (method === "BREW") note = "# BREW is from RFC 2324, an April Fools' RFC (1 April 1998). The answer there is 418. RFC 9110 now reserves 418 so nobody can use it for real.";
    else if (/\/invoices\/42(\?|$|\/)/.test(low)) note = "# 42: the answer to life, the universe and everything. Still needs the same four gates.";
    else if (/\/\.env/.test(low)) note = "# a scanner's favourite. Your API shouldn't serve files from its own folders, and secrets don't belong in them.";
    else if (priv) note = "# a hidden path isn't a protected path: this route needs its own rule.";
    else if (/\/(health|status|ping)(\/|$|\?)/.test(low)) note = "# public on purpose: a deliberate exception, written down, beats an accidental one.";
    else if (write) note = `# ${method} is a write: check the caller may change this, then check the body.`;
    else note = "# four gates, every request, in this order. Try BREW /coffee, a path with an ID, or an admin path.";
    $("hero-note").textContent = note;
  }

  // --------------------------------------------------------------------------- generic quiz (selects, check, reset)
  function quiz(cfg) {
    const { rows, data, options, check, reset, score, note, ok, prefix } = cfg;
    const render = () => {
      $(rows).innerHTML = data.map(([q], i) => `<tr><th scope="row">${esc(q)}</th><td><select data-i="${i}" aria-label="Answer for: ${esc(q)}"><option value="">Choose…</option>${Object.entries(options).map(([k, n]) => `<option value="${k}">${esc(n)}</option>`).join("")}</select><span class="qz-why" id="${prefix}-why-${i}"></span></td></tr>`).join("");
      $(score).textContent = ""; $(note).textContent = "";
    };
    const run = () => {
      let right = 0, answered = 0;
      $(rows).querySelectorAll("select").forEach((s) => {
        const i = +s.dataset.i, [, good, why] = data[i], isGood = good.includes(s.value);
        if (s.value) answered++;
        if (isGood) right++;
        const w = $(`${prefix}-why-${i}`); w.className = "qz-why " + (isGood ? "ok" : "bad");
        w.textContent = (isGood ? "✓ " : `✗ ${good.map((k) => options[k]).join(" or ")}. `) + why;
      });
      $(score).textContent = `${right} of ${data.length}`;
      $(note).textContent = right === data.length ? ok : "";
    };
    render(); click(check, run); click(reset, render);
  }

  const ST = [
    ["No Authorization header at all", ["401"], "Nobody has said who they are. Say how to authenticate (WWW-Authenticate)."],
    ["Valid token, but the route is admin-only and the caller is a normal user", ["403"], "We know who they are, and the answer is no."],
    ["Valid token, someone else's invoice (and you'd rather not confirm it exists)", ["404", "403"], "404 is the usual choice: 403 confirms the invoice exists. RFC 9110 allows hiding behind 404."],
    ["Token expired five minutes ago", ["401"], "An expired token is a failed authentication: 401 with error=\"invalid_token\"."],
    ["Valid token, but it lacks the invoices:write scope", ["403"], "Authenticated but not permitted: 403 with error=\"insufficient_scope\" (RFC 6750)."],
    ["Valid token, the caller's own invoice number, but no such invoice", ["404"], "Nothing there: 404."],
  ];
  const TK = [
    ["Your nightly billing job calls the Invoices API from your own server", ["key", "oauth"], "A program with no user: a scoped API key, or an OAuth client-credentials token."],
    ["Your own web app, same site as its API, for signed-in people", ["cookie"], "An HttpOnly, Secure, SameSite session cookie: the browser stores it and scripts can't read it. Add CSRF checks."],
    ["A mobile or partner app acting for a user, across organisations", ["oauth"], "OAuth: short-lived, scoped, audience-restricted tokens, so users can revoke the app and you can limit it."],
    ["A single-page app for your own users, where you can run a small backend", ["cookie"], "A backend-for-frontend keeps the OAuth tokens and gives the page a cookie: RFC 10017's top recommendation."],
  ];

  // --------------------------------------------------------------------------- object-level authorization
  const BO_NAME = { 1: "Alice", 2: "Bob", 3: "Carol" };
  const BO_INV = [
    { id: 1041, uuid: "7c1f3a52-96d0-4b8e-a3f1-0d2e5b7a9c14", owner: 1, customer: "Northwind", amount: 1200 },
    { id: 1042, uuid: "e48b0d7a-2c53-41f9-8a06-b3d19f5c7e20", owner: 2, customer: "Northwind", amount: 9800 },
    { id: 1043, uuid: "1a9d6c3e-7f24-4e8b-b5a0-c82f4d13e6a7", owner: 1, customer: "O'Brien", amount: 85.5 },
    { id: 1044, uuid: "b30e8f51-5a7c-4d92-9c1e-6f08a2d4b3e9", owner: 2, customer: "Harbor Labs", amount: 3150 },
    { id: 1045, uuid: "5d2c9a74-e1b8-4306-a7f3-9e4c0b1d8a62", owner: 3, customer: "Juniper & Co", amount: 612.75 },
    { id: 42, uuid: "0f4e7b2a-8d36-4c15-b9a1-3e6d5c80f7b4", owner: 2, customer: "Deep Thought Ltd", amount: 42 },
  ];
  let boUser = 1;
  const boUuid = () => $("bo-uuid").checked;
  const idOf = (inv) => (boUuid() ? inv.uuid : String(inv.id));
  function boMine() {
    const mine = BO_INV.filter((i) => i.owner === boUser && i.id !== 42);
    $("bo-mine").innerHTML = `The app only <i>shows</i> ${esc(BO_NAME[boUser])} her own invoices: ` + mine.map((i) => `<code>${esc(boUuid() ? i.uuid.slice(0, 8) + "…" : i.id)}</code>`).join(" and ") + ".";
    if (boUser === 2) $("bo-mine").innerHTML = `The app only <i>shows</i> Bob his own invoices: ` + BO_INV.filter((i) => i.owner === 2).map((i) => `<code>${esc(boUuid() ? i.uuid.slice(0, 8) + "…" : i.id)}</code>`).join(", ") + ".";
  }
  function boSend() {
    const raw = $("bo-id").value.trim(), method = $("bo-method").value, check = $("bo-check").checked, uuid = boUuid();
    const out = (code, obj) => { $("bo-out").textContent = `HTTP/1.1 ${code}\n` + (obj === undefined ? "" : json(obj)); };
    const who = BO_NAME[boUser];
    const valid = uuid ? /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(raw) : /^\d+$/.test(raw);
    if (!valid) {
      out("400 Bad Request", { error: uuid ? "invoice id must be a UUID" : "invoice id must be a number" });
      verdict("bo-verdict", "ok", "Rejected before any lookup: the ID isn't the right shape.");
      $("bo-note").textContent = /or|--|'/i.test(raw) ? "# that's the SQL trick from the Web App Security talk. Here the ID is parsed first, so it's just a 400." : "# IDs are parsed and validated before anything else happens.";
      return;
    }
    const inv = BO_INV.find((x) => (uuid ? x.uuid === raw.toLowerCase() : x.id === Number(raw)));
    if (!inv) { out("404 Not Found", { error: "not found" }); verdict("bo-verdict", "y", "No invoice with that ID."); $("bo-note").textContent = ""; return; }
    const mine = inv.owner === boUser;
    let note = "";
    if (inv.id === 42) note = mine ? "# 42: The Answer to Life, the Universe and Everything. And, Bob, it's yours." : "# 42: The Answer to Life, the Universe and Everything. Not your invoice, though.";
    if (!mine && check) {
      out("404 Not Found", { error: "not found" });
      verdict("bo-verdict", "ok", `Blocked: not ${who}'s, so as far as ${who} can tell it doesn't exist.`);
      $("bo-note").textContent = note || "# the query now includes owner = caller. 404 rather than 403 avoids confirming the invoice exists.";
      return;
    }
    if (method === "DELETE") {
      out("204 No Content");
      if (mine) { verdict("bo-verdict", "ok", `${who} deleted their own invoice (restored for the demo).`); $("bo-note").textContent = note || "# a delete is a write: it needs the same check as a read."; }
      else { verdict("bo-verdict", "bad", `${who} deleted ${BO_NAME[inv.owner]}'s invoice (restored for the demo): the server only checked that someone was signed in.`); $("bo-note").textContent = note || "# reading was bad; deleting is worse. Check every method."; }
      return;
    }
    out("200 OK", { id: inv.id, owner: BO_NAME[inv.owner].toLowerCase(), customer: inv.customer, amount: inv.amount });
    if (mine) { verdict("bo-verdict", "ok", `${who}'s own invoice.`); $("bo-note").textContent = note || (uuid ? "# fine. Now try \"A UUID someone shared\"." : "# fine. Now press \"id + 1\"."); }
    else {
      verdict("bo-verdict", "bad", `Leaked ${BO_NAME[inv.owner]}'s invoice: the server only checked that someone was signed in.`);
      $("bo-note").textContent = note || (uuid ? "# random IDs made guessing hard, but a UUID that leaked works exactly like a number. Only the check protects it." : "# the UI never shows this one, but the API answers anyway. Hiding a number isn't a check.");
    }
  }
  function boStep(d) {
    if (boUuid()) { $("bo-note").textContent = "# you can't walk random IDs: that's their point. They slow guessing; they don't check anything."; return; }
    const el = $("bo-id"); el.value = /\d+/.test(el.value) ? el.value.replace(/(\d+)(?!.*\d)/, (m) => String(Math.max(0, Number(m) + d))) : "1041"; boSend();
  }
  function boReset() {
    const own = BO_INV.find((i) => i.owner === boUser && i.id !== 42);
    $("bo-id").value = idOf(own); boMine();
  }

  // --------------------------------------------------------------------------- function-level: route matrix
  const BF_BASE = [
    { m: "GET", p: "/api/invoices/{id}", need: "user", hGuard: true, cGuard: true },
    { m: "GET", p: "/api/admin/users", need: "admin", hGuard: true, cGuard: true },
    { m: "DELETE", p: "/api/users/{id}", need: "admin", hGuard: true, cGuard: true },
    { m: "POST", p: "/api/admin/refunds", need: "admin", hGuard: false, cGuard: true },
    { m: "GET", p: "/api/internal/metrics", need: "admin", hGuard: false, cGuard: true },
  ];
  const BF_NEW = [
    ["POST", "/api/admin/export"], ["POST", "/api/internal/debug"], ["GET", "/api/admin/test2"], ["GET", "/api/admin/backup-2019"], ["POST", "/api/v1/old/users-FINAL-final"],
  ];
  let bfMode = "handler", bfRoutes = [], bfNew = 0;
  function bfReset() { bfRoutes = BF_BASE.map((r) => ({ ...r })); bfNew = 0; bfRender(); $("bf-note").textContent = ""; }
  function bfAnswer(r, who) {         // who: anon | alice | dana
    const guard = bfMode === "handler" ? r.hGuard : r.cGuard;
    if (!guard) return bfMode === "handler" ? 200 : (who === "anon" ? 401 : 403);   // handler: nobody wrote a check; central: no rule means closed
    if (who === "anon") return 401;
    if (r.need === "admin" && who !== "dana") return 403;
    return 200;
  }
  function bfRender() {
    let open = 0;
    $("bf-rows").innerHTML = bfRoutes.map((r) => {
      const cells = ["anon", "alice", "dana"].map((who) => {
        const a = bfAnswer(r, who), should = who === "anon" ? false : r.need === "user" || who === "dana";
        let cls = "ok", txt = String(a);
        if (a === 200 && !should) { cls = "bad"; open++; txt = "200 ✗"; }
        else if (a !== 200 && should && r.isNew && !(bfMode === "handler" ? r.hGuard : r.cGuard)) { cls = "y"; txt = a + " (closed)"; }
        return `<td class="${cls}">${esc(txt)}</td>`;
      }).join("");
      return `<tr${r.isNew ? ' class="new"' : ""}><th scope="row"><b>${esc(r.m)}</b>${esc(r.p)}</th>${cells}</tr>`;
    }).join("");
    $("bf-add").disabled = bfNew >= BF_NEW.length;
    const unguarded = bfRoutes.some((r) => r.isNew && !r.hGuard);
    $("bf-rule").disabled = !unguarded;
    if (open) verdict("bf-verdict", "bad", `${open} cell${open > 1 ? "s" : ""} let someone call a route they shouldn't (marked ✗).`);
    else verdict("bf-verdict", "ok", "Every route answers as designed.");
  }
  function bfAdd() {
    if (bfNew >= BF_NEW.length) return;
    const [m, p] = BF_NEW[bfNew++];
    bfRoutes.push({ m, p, need: "admin", hGuard: false, cGuard: false, isNew: true });
    bfRender();
    $("bf-note").textContent = bfNew >= BF_NEW.length
      ? "# /old/users-FINAL-final: improper inventory management (API9) in one name. Retire what you stop using."
      : bfMode === "handler" ? `# ${p} shipped open: nobody wrote its check yet. This is how it happens.` : `# ${p} is closed by default until someone writes its rule.`;
  }
  function bfRule() {
    const r = bfRoutes.find((x) => x.isNew && !x.hGuard); if (!r) return;
    r.hGuard = r.cGuard = true; bfRender();
    $("bf-note").textContent = `# ${r.p} now needs an admin. In central mode it was safe the whole time; in handler mode it was open until now.`;
  }

  // --------------------------------------------------------------------------- API key rotation
  let kr;
  function krInit() {
    kr = { keys: [{ id: 1, scope: "invoices:read", status: "active", uses: 0 }], on: { billing: 1, "reports-cron": 1 }, revokedTooEarly: false };
    $("kr-out").textContent = ""; $("kr-note").textContent = "";
    krRender(); verdict("kr-verdict", "y", "Two clients share key 1. Rotate it without an outage.");
  }
  const krName = (id) => `key ${id} · sk_live_${["7f3a", "c91e", "2b4d"][id - 1] || "0000"}…`;
  function krRender() {
    $("kr-rows").innerHTML = kr.keys.map((k) => {
      const users = Object.keys(kr.on).filter((c) => kr.on[c] === k.id);
      return `<tr><th scope="row">${esc(krName(k.id))}</th><td>${esc(k.scope)}</td><td class="${k.status === "active" ? "ok" : "bad"}">${k.status}</td><td>${esc(users.length ? users.join(", ") : "nobody")} · ${k.uses} req</td></tr>`;
    }).join("");
    $("kr-new").disabled = kr.keys.length >= 2;
    $("kr-switch").disabled = $("kr-switch2").disabled = kr.keys.length < 2;
  }
  function krSend() {
    const lines = [];
    for (const c of Object.keys(kr.on)) {
      const k = kr.keys.find((x) => x.id === kr.on[c]);
      if (k.status === "active") { k.uses++; lines.push(`${c.padEnd(13)} → ${krName(k.id)}: 200 OK`); }
      else lines.push(`${c.padEnd(13)} → ${krName(k.id)}: 401 Unauthorized (revoked)`);
    }
    $("kr-out").textContent = lines.join("\n"); krRender();
    const failing = lines.filter((l) => l.includes("401")).length;
    if (failing) verdict("kr-verdict", "bad", `${failing} of ${lines.length} clients are getting 401: an outage.`);
    else verdict("kr-verdict", "ok", "Both clients are working.");
    return failing;
  }
  function krStep(what) {
    const note = $("kr-note");
    if (what === "new") {
      kr.keys.push({ id: 2, scope: "invoices:read", status: "active", uses: 0 }); note.textContent = "# two keys are live: nothing has broken, and nothing has moved yet."; krRender();
    } else if (what === "billing" || what === "reports-cron") {
      kr.on[what] = 2; note.textContent = `# ${what} now uses key 2. Look at "used by" before revoking key 1.`; krRender();
    } else if (what === "revoke") {
      const k = kr.keys[0]; if (k.status === "revoked") { note.textContent = "# key 1 is already revoked."; return; }
      k.status = "revoked"; krRender();
      const still = Object.keys(kr.on).filter((c) => kr.on[c] === 1);
      if (still.length) { verdict("kr-verdict", "bad", `Revoked key 1 while ${still.join(" and ")} still use it: they will now get 401.`); note.textContent = "# the outage nobody scheduled. The cron job nobody remembered is the classic. Check \"used by\" first."; }
      else { verdict("kr-verdict", "ok", "Clean rotation: nobody was using key 1 when it was revoked."); note.textContent = "# overlap, move, revoke. Boring, and that's the goal."; }
    }
  }

  // --------------------------------------------------------------------------- JWT inspector (real ES256, in the page)
  const ISS = "https://auth.example.com/", AUD = "https://api.example.com";
  let KEY = null, OTHER = null, jwScenario = "valid", jwMode = "full", jwNow = 0;
  const b64u = (bytes) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const unb64u = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
  const bj = (o) => b64u(L.utf8(JSON.stringify(o)));
  function genKey() { const d = L.randBelow(L.P256.n - 1n) + 1n; return { d, Q: L.P256.mul(d) }; }
  const pubBytes = (Q) => L.concat(Uint8Array.of(4), L.fromBig(Q[0], 32), L.fromBig(Q[1], 32));
  function signES256(input, key) {
    const n = L.P256.n, h = L.hashInt(input);
    for (;;) {
      const k = L.randBelow(n - 1n) + 1n, [r, s] = L.ecdsaSign(key.d, h, k);
      if (r !== 0n && s !== 0n) return L.concat(L.fromBig(r, 32), L.fromBig(s, 32));
    }
  }
  function verifyES256(input, sig, Q) {           // rejects r or s outside 1..n-1 (the check Java 15-18 forgot, CVE-2022-21449)
    if (sig.length !== 64) return false;
    const n = L.P256.n, r = L.toBig(sig.subarray(0, 32)), s = L.toBig(sig.subarray(32));
    if (r < 1n || r >= n || s < 1n || s >= n) return false;
    return L.ecdsaVerify(Q, L.hashInt(input), [r, s]);
  }
  function jwBuild(sc) {
    jwNow = Math.floor(Date.now() / 1000);
    let header = { alg: "ES256", typ: "at+jwt", kid: "k1" };
    let pay = { iss: ISS, sub: "alice", aud: AUD, iat: jwNow, exp: jwNow + 900, scope: "invoices:read" };
    let key = KEY, sigMode = "es";
    if (sc === "expired") { pay.iat = jwNow - 4500; pay.exp = jwNow - 3600; }
    else if (sc === "aud") pay.aud = "https://billing.example.com";
    else if (sc === "iss") pay.iss = "https://staging.auth.example.com/";
    else if (sc === "typ") header.typ = "JWT";
    else if (sc === "other") key = OTHER;
    else if (sc === "none") { header = { alg: "none", typ: "at+jwt" }; pay = { ...pay, sub: "dana", scope: "invoices:read admin" }; sigMode = "none"; }
    else if (sc === "hs") { header = { alg: "HS256", typ: "at+jwt", kid: "k1" }; pay = { ...pay, sub: "dana", scope: "invoices:read admin" }; sigMode = "hs"; }
    const h = bj(header), p = bj(pay), input = h + "." + p;
    let sig;
    if (sc === "tamper") {
      const good = signES256(input, KEY), forged = { ...pay, sub: "dana", scope: "invoices:read admin" };
      return { header, pay: forged, h, p: bj(forged), sig: b64u(good), signedInput: input };   // payload edited, signature copied from the real one
    }
    if (sigMode === "none") sig = "";
    else if (sigMode === "hs") sig = b64u(L.hmacSha256(pubBytes(KEY.Q), L.utf8(input)));
    else sig = b64u(signES256(input, key));
    return { header, pay, h, p, sig };
  }
  function jwEval(tok, mode) {
    // returns { items: [[state, text]], verdictCls, verdictText, note }
    const input = tok.h + "." + tok.p, sigBytes = tok.sig ? unb64u(tok.sig) : new Uint8Array(0);
    const bad = jwScenario !== "valid";
    if (mode === "decode") {
      return { items: [["m", "Nothing is verified: decoding only reads the fields"]], cls: bad ? "bad" : "y", text: bad ? "Decoded, and believed. Anyone can write these fields." : "Decoded. That proves nothing about who made it.", note: "# base64 isn't encryption and decoding isn't validating. Never make decisions from claims you haven't verified." };
    }
    if (mode === "naive") {
      const alg = tok.header.alg; let sigOk, label;
      if (alg === "none") { sigOk = true; label = "alg \"none\": the token says it needs no signature, so none is checked"; }
      else if (alg === "HS256") { sigOk = L.equalBytes(L.hmacSha256(pubBytes(KEY.Q), L.utf8(input)), sigBytes); label = "alg HS256, so HMAC with the key we have on file (the public key!)"; }
      else { sigOk = verifyES256(input, sigBytes, KEY.Q); label = "alg ES256, signature checked with the issuer's key"; }
      const items = [["ok", "Three parts, valid JSON"], [sigOk ? "ok" : "bad", `Signature, using the algorithm the token names: ${label}`], ["m", "Claims (iss, aud, exp, typ) are not looked at"]];
      if (!sigOk) return { items, cls: "ok", text: "Rejected: the signature doesn't verify.", note: "# even the naive validator catches this one. The next ones are the trouble." };
      let note = "";
      if (jwScenario === "none") note = "# the 2015 bug: believing the token's own alg field. Servers choose the algorithm; tokens don't.";
      else if (jwScenario === "hs") note = "# the public key is public: anyone can sign with it as an HMAC secret if the library lets the token choose HS256.";
      else if (bad) note = "# the signature is fine; the token just isn't meant for us, or isn't fresh. A signature isn't permission.";
      else note = "# a valid token passes everything. The naive validator's problem is the others.";
      return { items, cls: bad ? "bad" : "ok", text: bad ? "ACCEPTED, and it shouldn't be." : "Accepted: a genuine token.", note };
    }
    // full validation
    const checks = [
      ["Three dot-separated parts, valid JSON", () => true],
      ["alg is ES256: pinned in our config, never taken from the token", () => tok.header.alg === "ES256"],
      ["Signature verifies with the issuer's key (kid k1, from our config)", () => verifyES256(input, sigBytes, KEY.Q)],
      ["typ is at+jwt (an access token, not an ID token)", () => tok.header.typ === "at+jwt"],
      [`iss is ${ISS}`, () => tok.pay.iss === ISS],
      [`aud includes ${AUD}`, () => [].concat(tok.pay.aud).includes(AUD)],
      ["exp is in the future (30 s leeway)", () => tok.pay.exp + 30 > Math.floor(Date.now() / 1000)],
    ];
    const items = []; let failed = -1;
    checks.forEach(([text, fn], i) => {
      if (failed >= 0) { items.push(["m", text + "  (not reached)"]); return; }
      if (fn()) items.push(["ok", text]); else { items.push(["bad", text]); failed = i; }
    });
    const notes = { none: "# Bold of you to assume. alg \"none\" is never accepted, whatever the header claims.", hs: "# the algorithm is pinned, so the header can't talk us into HMAC with a public key.", tamper: "# one changed character in the payload and the signature no longer matches.", other: "# a perfectly valid signature, from a key that isn't the issuer's.", expired: "# a stolen token's best defence is a short life. Keep exp short.", aud: "# a token for the billing API is not a token for ours. Without the aud check, any API sharing the issuer could replay it here.", iss: "# same keys, different issuer: only the iss check notices.", typ: "# claims lined up, but it's the wrong kind of token. Explicit typing (RFC 8725) keeps token types from being swapped.", valid: "# every check passed: signed by our issuer, meant for us, still fresh. Only now do we read the scope." };
    if (failed < 0) return { items, cls: "ok", text: "Accepted: signed by our issuer, meant for us, still fresh.", note: notes.valid };
    return { items, cls: "ok", text: `Rejected at check ${failed + 1} of ${checks.length}. Fail closed.`, note: notes[jwScenario] };
  }
  function jwRender() {
    if (!KEY) { KEY = genKey(); OTHER = genKey(); }
    const tok = jwBuild(jwScenario);
    $("jw-token").innerHTML = `${sp("h", tok.h)}${sp("d", ".")}${sp("p", tok.p)}${sp("d", ".")}${sp("s", tok.sig || "")}${tok.sig ? "" : sp("d", "(empty signature)")}`;
    $("jw-header").textContent = json(tok.header);
    const rel = tok.pay.exp - jwNow, relTxt = rel >= 0 ? `in ${Math.round(rel / 60)} min` : `${Math.round(-rel / 60)} min ago`;
    $("jw-payload").textContent = json(tok.pay) + `\n# exp: ${relTxt}`;
    const r = jwEval(tok, jwMode);
    $("jw-checks").innerHTML = r.items.map(([c, t]) => `<li class="${c}"><b>${c === "ok" ? "✓" : c === "bad" ? "✗" : "·"}</b><span>${esc(t)}</span></li>`).join("");
    verdict("jw-verdict", r.cls, r.text); $("jw-note").textContent = r.note;
  }

  // --------------------------------------------------------------------------- OAuth scopes
  const OA_CALLS = [
    { call: "GET /api/invoices/1041  (Alice's invoice)", scope: "invoices:read", users: { alice: [true], dana: [true, "admins may read any invoice"] } },
    { call: "POST /api/invoices  (create one)", scope: "invoices:write", users: { alice: [true], dana: [true] } },
    { call: "GET /api/users/me", scope: "users:read", users: { alice: [true], dana: [true] } },
    { call: "GET /api/admin/users", scope: "admin", users: { alice: [false, "Alice isn't an admin"], dana: [true] } },
    { call: "GET /api/invoices/1042  (Bob's invoice)", scope: "invoices:read", users: { alice: [false, "not Alice's invoice: 404, whatever the scope"], dana: [true, "admins may read any invoice"] } },
  ];
  function oaRender() {
    const user = document.querySelector("#oa-user [aria-pressed=true]").dataset.u;
    const have = Array.from(document.querySelectorAll("#oa-scopes input:checked"), (i) => i.dataset.s);
    $("oa-list").innerHTML = OA_CALLS.map((c) => {
      const [allowed, why] = c.users[user];
      if (!have.includes(c.scope)) return `<li class="bad"><b>${esc(c.call)}</b><span><i>✗ 403 insufficient_scope</i> · the token lacks <code>${esc(c.scope)}</code></span></li>`;
      if (!allowed) return `<li class="bad"><b>${esc(c.call)}</b><span><i>✗ ${/404/.test(why) ? "404 not found" : "403 forbidden"}</i> · scope is fine; ${esc(why)}</span></li>`;
      return `<li class="ok"><b>${esc(c.call)}</b><span><i>✓ 200 OK</i> · scope <code>${esc(c.scope)}</code> ✓${why ? ", and " + esc(why) : ", and the user may"}</span></li>`;
    }).join("");
    $("oa-note").textContent = have.length === 4
      ? "# Flashlight Deluxe wants all four? A flashlight needs none. Least privilege applies to apps too."
      : "# effective access = the token's scope AND the user's own rights. Both checks run on every call.";
  }

  // --------------------------------------------------------------------------- mass assignment
  const MA_BODY = {
    normal: '{\n  "name": "Alice Liddell",\n  "email": "alice@example.org"\n}',
    role: '{\n  "name": "Alice Liddell",\n  "email": "alice@example.org",\n  "role": "admin"\n}',
    isadmin: '{\n  "name": "Alice Liddell",\n  "isAdmin": true\n}',
    credit: '{\n  "name": "Alice Liddell",\n  "credit": 1000000\n}',
    type: '{\n  "name": 12345,\n  "email": ["not", "an", "email"]\n}',
    proto: '{\n  "name": "Alice",\n  "__proto__": { "isAdmin": true }\n}',
  };
  let maMode = "copy";
  const MA_USER = () => new Map([["id", 7], ["name", "Alice"], ["email", "alice@example.com"], ["role", "user"], ["isAdmin", false], ["credit", 0], ["plan", "free"]]);
  const mapJson = (m) => "{\n" + Array.from(m, ([k, v]) => `  ${JSON.stringify(k)}: ${JSON.stringify(v)}`).join(",\n") + "\n}";
  function maSend() {
    let body;
    const out = (code, text) => { $("ma-out").textContent = `HTTP/1.1 ${code}\n` + text; };
    try { body = JSON.parse($("ma-body").value); } catch (e) { out("400 Bad Request", json({ error: "body isn't valid JSON" })); verdict("ma-verdict", "ok", "Rejected: not JSON."); $("ma-note").textContent = ""; return; }
    if (body === null || typeof body !== "object" || Array.isArray(body)) { out("400 Bad Request", json({ error: "body must be a JSON object" })); verdict("ma-verdict", "ok", "Rejected: not an object."); $("ma-note").textContent = ""; return; }
    const keys = Object.keys(body), rec = MA_USER(), before = MA_USER();
    const extras = keys.filter((k) => k !== "name" && k !== "email");
    let note = "";
    if (maMode === "schema") {
      const errs = extras.map((k) => ({ field: k, message: "unknown field" }));
      if ("name" in body && !(typeof body.name === "string" && body.name.length >= 1 && body.name.length <= 50)) errs.push({ field: "name", message: "must be a string of 1 to 50 characters" });
      if ("email" in body && !(typeof body.email === "string" && body.email.length <= 254 && /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(body.email))) errs.push({ field: "email", message: "must be an email address" });
      if (errs.length) {
        out("422 Unprocessable Content", json({ errors: errs }));
        verdict("ma-verdict", "ok", `Rejected: ${errs.map((e) => e.field).join(", ")}. Nothing was changed.`);
        note = extras.includes("__proto__") ? "# __proto__ is just another unknown field here: refused by name." : extras.length ? "# an unknown field, refused loudly: the client developer hears about it today, not after an incident." : "# wrong types and lengths are refused too: the schema is the contract.";
      } else {
        for (const k of keys) rec.set(k, body[k]);
        out("200 OK", mapJson(rec)); verdict("ma-verdict", "ok", "Accepted: only name and email, both valid."); note = "# the happy path stays happy.";
      }
    } else if (maMode === "allow") {
      for (const k of ["name", "email"]) if (k in body) rec.set(k, body[k]);
      out("200 OK", mapJson(rec));
      const badType = typeof rec.get("name") !== "string" || typeof rec.get("email") !== "string";
      if (badType) { verdict("ma-verdict", "y", "Extras ignored, but the wrong types were stored: allow-listing alone doesn't validate."); note = "# pick the fields, then validate them too."; }
      else if (extras.length) { verdict("ma-verdict", "y", `Safe, but ${extras.join(", ")} was dropped silently: the client got 200 and can't tell.`); note = "# safe today. A schema that says no would tell the client developer."; }
      else { verdict("ma-verdict", "ok", "Accepted."); note = ""; }
    } else {
      for (const k of keys) rec.set(k, body[k]);
      out("200 OK", mapJson(rec));
      const changed = Array.from(rec.keys()).filter((k) => !before.has(k) || JSON.stringify(rec.get(k)) !== JSON.stringify(before.get(k)));
      const extraChanged = changed.filter((k) => k !== "name" && k !== "email");
      if (extraChanged.length) verdict("ma-verdict", "bad", `Mass assignment: the server copied every field, so Alice set ${extraChanged.join(", ")} herself.`);
      else if (typeof rec.get("name") !== "string" || typeof rec.get("email") !== "string") verdict("ma-verdict", "bad", "Stored a number as the name and an array as the email: nothing checks types.");
      else verdict("ma-verdict", "ok", "Only name and email changed. This time.");
      if (keys.includes("__proto__")) note = "# __proto__ is a classic JavaScript key: naive merge code can let it reach prototypes. A schema never lets it in.";
      else if (keys.includes("isAdmin") || keys.includes("role")) note = "# the form never shows this field. The request can still send it. (GitHub's 2012 incident was this bug with a user_id field.)";
      else if (keys.includes("credit")) note = "# the form never shows a credit field either: every field the model has is a field the client can try.";
    }
    $("ma-note").textContent = note;
  }

  // --------------------------------------------------------------------------- response shaping
  const OS = [
    ["id", 12, "ok", true], ["display_name", "Jo Rivera", "ok", true], ["avatar_url", "https://cdn.example.com/u/12.png", "ok", true], ["created_at", "2024-03-02", "ok", true],
    ["email", "jo@example.com", "sens", false], ["birth_date", "1991-07-19", "sens", false], ["last_login_ip", "203.0.113.58", "sens", false],
    ["password_hash", "$argon2id$v=19$m=…$…", "secret", false], ["internal_notes", "Asked about refund twice", "secret", false], ["stripe_customer", "cus_demo123", "secret", false],
  ];
  let osMode = "row"; const osOn = new Set(OS.filter((f) => f[3]).map((f) => f[0]));
  function osRender() {
    $("os-fields").innerHTML = OS.map(([k, , kind]) => `<label class="${kind === "sens" ? "sens" : kind === "secret" ? "secret" : ""}${osMode === "row" ? " off" : ""}"><input type="checkbox" data-k="${k}" ${osMode === "row" || osOn.has(k) ? "checked" : ""} ${osMode === "row" ? "disabled" : ""}> ${esc(k)}<small>${kind === "sens" ? "personal" : kind === "secret" ? "internal" : ""}</small></label>`).join("");
    const shown = OS.filter(([k]) => osMode === "row" || osOn.has(k));
    const lines = shown.map(([k, v, kind]) => {
      const t = `  ${JSON.stringify(k)}: ${JSON.stringify(v)}`;
      return kind === "secret" ? sp("lk-bad", t) : kind === "sens" ? sp("lk", t) : esc(t);
    });
    $("os-out").innerHTML = "{\n" + lines.join(",\n") + "\n}";
    const sens = shown.filter((f) => f[2] !== "ok");
    if (sens.length) verdict("os-verdict", "bad", `${sens.length} sensitive field${sens.length > 1 ? "s" : ""} in another user's public profile: ${sens.map((f) => f[0]).join(", ")}.`);
    else verdict("os-verdict", "ok", "Only what a profile page needs leaves the server.");
    $("os-note").textContent = osMode === "row" ? "# the UI shows a name and an avatar. The network tab shows all of this." : osOn.has("password_hash") ? "# a password hash isn't public data: stolen hashes get cracked offline. See the Passwords talk." : sens.length ? "# a schema is code, so it can be wrong too. Review it like code." : "# the schema is the contract. A new database column can't reach clients until someone adds it here.";
  }

  // --------------------------------------------------------------------------- token-bucket rate limiter
  const RL_CAP = 10, RL_RATE = 2;           // tokens, tokens per second
  let rlBy = "global", rlB = {}, rlLog = [], rlRejects = 0, rlTeapot = false, rlLast = "";
  function rlInit() {
    const t = clock(); rlB = { global: { t: RL_CAP, at: t }, alice: { t: RL_CAP, at: t }, scraper: { t: RL_CAP, at: t } };
    rlLog = []; rlRejects = 0; rlTeapot = false; rlLast = ""; rlRender();
  }
  function rlRefill(b) { const t = clock(); b.t = Math.min(RL_CAP, b.t + ((t - b.at) / 1000) * RL_RATE); b.at = t; }
  function rlFire(who, n) {
    const bucket = rlB[rlBy === "global" ? "global" : who], name = who === "alice" ? "Alice  " : "Scraper";
    for (let i = 0; i < n; i++) {
      rlRefill(bucket);
      if (bucket.t >= 1) { bucket.t -= 1; rlRejects = 0; rlLog.push(["ok", `${name} → 200 OK`]); rlLast = who + ":ok"; }
      else {
        rlRejects++; const wait = Math.max(1, Math.ceil((1 - bucket.t) / RL_RATE));
        rlLog.push(["bad", `${name} → 429 Too Many Requests · Retry-After: ${wait}`]); rlLast = who + ":429";
        if (rlRejects === 100 && !rlTeapot) { rlTeapot = true; rlLog.push(["y", `${name} → 418 I'm a teapot (RFC 2324: that's enough, now)`]); break; }
      }
    }
    if (rlLog.length > 40) rlLog = rlLog.slice(-40);
    rlRender(n);
  }
  function rlRender() {
    const names = rlBy === "global" ? [["global", "everyone, one bucket"]] : [["alice", "Alice's key"], ["scraper", "Scraper's key"]];
    $("rl-buckets").innerHTML = names.map(([k, label]) => { rlRefill(rlB[k]); const n = Math.floor(rlB[k].t + 1e-9);
      return `<div class="rl-b"><header><b>${esc(label)}</b><span>${rlB[k].t.toFixed(1)} / ${RL_CAP} tokens · +${RL_RATE}/s</span></header><div class="rl-cells">${Array.from({ length: RL_CAP }, (_, i) => `<i class="${i < n ? "on" : ""}"></i>`).join("")}</div></div>`; }).join("");
    $("rl-log").innerHTML = rlLog.slice(-8).map(([c, t]) => `<li class="${c}">${esc(t)}</li>`).join("");
    if (!rlLast) verdict("rl-verdict", "y", "Fire some requests.");
    else if (rlLast === "alice:429") verdict("rl-verdict", "bad", "Alice is throttled, though she did nothing wrong: the scraper emptied the shared bucket.");
    else if (rlLast === "scraper:429") verdict("rl-verdict", rlBy === "key" ? "ok" : "y", rlBy === "key" ? "The scraper is throttled; Alice's bucket is untouched." : "The scraper is throttled, but so is everyone else sharing this bucket.");
    else verdict("rl-verdict", "ok", "Allowed: within the limit.");
    $("rl-note").textContent = rlTeapot ? "# a hundred rejections in a row: it's a teapot. RFC 2324's 418 is reserved by RFC 9110 so nobody can use it for real." : rlLast === "scraper:429" && rlBy === "global" ? "# one noisy client shouldn't spend everybody's budget." : "# a token bucket allows bursts and enforces an average rate.";
  }
  function rlPage() {
    const raw = $("rl-limit").value.trim(), n = Number(raw);
    if (!/^\d+$/.test(raw) || n < 1) { $("rl-page").textContent = "limit must be a positive whole number: the server answers 400."; return; }
    const cap = Math.min(n, 100);
    $("rl-page").textContent = n > 100 ? `Asked for ${n.toLocaleString("en-US")} → the server returns ${cap} per page. An uncapped limit could build a response ${Math.round(n / 100).toLocaleString("en-US")} times as big.` : `Asked for ${n} → the server returns ${cap} per page. Within the cap.`;
  }

  // --------------------------------------------------------------------------- errors and logs
  const ER = {
    json: { req: "POST /api/invoices  {\"customer\": \"Northwind\",", debug: ["500 Internal Server Error", { error: "JSONDecodeError: Expecting property name enclosed in double quotes: line 1 column 27 (char 26)", trace: "/srv/billing/app/views/invoices.py:88 in create → json.loads(request.body)", framework: "FrameworkX 4.2.1 (DEBUG=True)" }], leaks: ["a stack trace with file paths", "the framework and its version", "a 500 for a client mistake (it should be a 400)"], safe: ["400 Bad Request", { type: "https://api.example.com/problems/invalid-json", title: "The request body isn't valid JSON", status: 400, instance: "/requests/9f3a1c" }], err: "JSONDecodeError at char 26" },
    db: { req: "GET /api/invoices/1041", debug: ["500 Internal Server Error", { error: "OperationalError: could not connect to server \"db-prod-3.internal.example.net\" (10.2.4.17), port 5432: Connection refused", sql: "SELECT id, owner_id, customer, amount FROM invoices WHERE id = 1041" }], leaks: ["an internal hostname and IP address", "the database type and port", "the SQL text with table and column names"], safe: ["500 Internal Server Error", { type: "https://api.example.com/problems/internal-error", title: "Something went wrong on our side", status: 500, instance: "/requests/c41d07" }], err: "OperationalError: connection refused (db-prod-3:5432)" },
    nf: { req: "GET /api/invoices/999", debug: ["404 Not Found", { error: "no row in table invoices where id = 999 and owner_id = 7", sql: "SELECT id, owner_id, customer, amount FROM invoices WHERE id = 999 AND owner_id = 7" }], leaks: ["the SQL text with table and column names", "that the check is on owner_id (a map for an attacker)"], safe: ["404 Not Found", { type: "https://api.example.com/problems/not-found", title: "No such invoice", status: 404, instance: "/requests/5be2a9" }], err: "invoice 999 not found for user u_7" },
    nouser: { req: "POST /api/login  {\"email\": \"zed@example.com\", ...}", debug: ["404 Not Found", { error: "no user with that email" }], leaks: ["whether an account exists for that email (account enumeration)"], safe: ["401 Unauthorized", { type: "https://api.example.com/problems/bad-credentials", title: "Wrong email or password", status: 401, instance: "/requests/77d0e4" }], err: "login failed: unknown email (hash only)" },
    badpw: { req: "POST /api/login  {\"email\": \"alice@example.com\", ...}", debug: ["401 Unauthorized", { error: "password does not match for user alice@example.com (3 attempts left)" }], leaks: ["that the account exists (a different message from an unknown email)", "how many attempts the attacker has left"], safe: ["401 Unauthorized", { type: "https://api.example.com/problems/bad-credentials", title: "Wrong email or password", status: 401, instance: "/requests/21c8f3" }], err: "login failed: bad password for u_7" },
  };
  let erScenario = "json", erMode = "debug";
  function erRender() {
    const s = ER[erScenario], d = erMode === "debug";
    const [code, body] = d ? s.debug : s.safe;
    const corr = s.safe[1].instance.split("/").pop();
    $("er-client").textContent = `${s.req}\nHTTP/1.1 ${code}\n` + (d ? "" : "Content-Type: application/problem+json\n") + json(body);
    $("er-log").textContent = d
      ? `${code.slice(0, 3)} ${s.req.split("  ")[0]}\n  headers: Authorization: Bearer eyJhbGciOiJFUzI1NiIsInR5cCI6…\n  ${s.err}`
      : json({ level: "error", corr, route: s.req.split("  ")[0], user: "u_7", authorization: "[redacted]", detail: s.err });
    const leaks = d ? s.leaks.concat(["the Authorization header written to the log in full"]) : [];
    $("er-leaks").innerHTML = d ? leaks.map((t) => `<li>${esc(t)}</li>`).join("") : `<li class="ok">nothing about our internals reaches the client</li><li class="ok">the log has the detail and a correlation ID (${esc(corr)}), minus secrets</li>`;
    if (d) verdict("er-verdict", "bad", `${leaks.length} thing${leaks.length > 1 ? "s" : ""} the client (or the log reader) shouldn't get.`);
    else verdict("er-verdict", "ok", "Generic for the client, detailed for you.");
    $("er-note").textContent = !d && (erScenario === "nouser" || erScenario === "badpw") ? "# switch between the two sign-in scenarios: the bodies are identical, so attackers can't tell which emails have accounts." : d ? "# debug mode is for your laptop. In production it's documentation for whoever's probing you." : "# the client quotes the correlation ID to support, and you find the full story in the log.";
  }

  // --------------------------------------------------------------------------- OWASP API Top 10 map
  const OW = [
    ["API1", "Broken Object Level Authorization", "An endpoint takes an object ID and doesn't check that this caller may access that object. The commonest and most damaging API bug.", [["#bola", "Invoice explorer"], ["#patterns", "Scoped queries"]]],
    ["API2", "Broken Authentication", "Weak or mis-validated credentials: unvalidated tokens, keys that never expire, no limits on sign-in.", [["#keys", "API keys"], ["#sessions", "Sessions or tokens"], ["#jwt", "JWT inspector"]]],
    ["API3", "Broken Object Property Level Authorization", "Reading or writing properties the caller shouldn't: over-sharing in responses and mass assignment in requests.", [["#mass", "Schemas on input"], ["#output", "Schemas on output"]]],
    ["API4", "Unrestricted Resource Consumption", "No limits on rate, size, page size or cost, so one client (or one bug) can starve everyone.", [["#rate", "Rate limits"]]],
    ["API5", "Broken Function Level Authorization", "Privileged functions reachable by the wrong roles: admin routes, exports, methods other than GET.", [["#bfla", "Route matrix"]]],
    ["API6", "Unrestricted Access to Sensitive Business Flows", "Not just a bug: a legitimate flow (buying, signing up, posting) abused at scale. Only touched on today: limit per flow, not just per request.", [["#rate", "Limits"]]],
    ["API7", "Server Side Request Forgery", "Your API fetches a URL the client chose, and ends up reaching things only your server can.", [["#ssrf", "Fetching URLs"], ["../web-app-security/#ssrf", "The SSRF demo"]]],
    ["API8", "Security Misconfiguration", "Missing hardening, permissive CORS, verbose errors, debug mode left on. Today: the error handling.", [["#errors", "Errors and logs"]]],
    ["API9", "Improper Inventory Management", "Old versions, debug routes and forgotten hosts that nobody maintains but everybody can reach.", [["#bfla", "/old/users-FINAL-final"], ["#why", "Optus"]]],
    ["API10", "Unsafe Consumption of APIs", "Trusting what upstream and third-party APIs send you more than you'd trust a client.", [["#ssrf", "Untrusted upstreams"]]],
  ];
  const owSeen = new Set();
  function owRender() {
    $("ow-grid").innerHTML = OW.map(([k, n], i) => `<li><button type="button" data-i="${i}" aria-pressed="false"><small>${k}:2023</small><b>${esc(n)}</b></button></li>`).join("");
  }
  function owPick(i) {
    const [k, n, d, links] = OW[i]; owSeen.add(i);
    document.querySelectorAll("#ow-grid button").forEach((b) => { b.setAttribute("aria-pressed", String(+b.dataset.i === i)); if (owSeen.has(+b.dataset.i)) b.classList.add("seen"); });
    $("ow-detail").innerHTML = `<b>${k} ${esc(n)}</b> ${esc(d)}${links.length ? " Today: " + links.map(([h, t]) => `<a href="${h}">${esc(t)}</a>`).join(" · ") : ""}` +
      (owSeen.size === OW.length ? '<span class="comment"># all ten opened. That\'s the whole map; the territory is your own API.</span>' : "");
  }

  // --------------------------------------------------------------------------- review checklist
  const RV_KEY = "secureapis-review";
  function review() {
    const boxes = Array.from(document.querySelectorAll("#rv-list input[type=checkbox]"));
    let saved = {};
    try { saved = JSON.parse(store(RV_KEY) || "{}"); } catch (e) {}
    boxes.forEach((b) => { b.checked = !!saved[b.dataset.k]; });
    const update = () => {
      const done = boxes.filter((b) => b.checked).length;
      store(RV_KEY, JSON.stringify(Object.fromEntries(boxes.map((b) => [b.dataset.k, b.checked]))));
      const n = $("rv-note"); n.className = "comment";
      if (done === boxes.length) { n.textContent = "# 12 of 12. Ship it, then run the list again next quarter: APIs grow new routes faster than anyone updates the docs."; n.classList.add("ok"); }
      else if (!done) n.textContent = "# tick what your API does today. Each gap is a ticket, not a failure. Saved in this browser only.";
      else n.textContent = `# ${done} of ${boxes.length}. Pick the unticked box most likely to bite and fix that first.`;
    };
    boxes.forEach((b) => b.addEventListener("change", update));
    update();
  }

  // --------------------------------------------------------------------------- easter egg: console
  function consoleHint() {
    console.log("%cBuilding Secure APIs", "font: 700 24px monospace; color: #ff2e88; text-shadow: 0 0 8px #ff2e88");
    console.log("%cYou opened the console: where every API gets tested first. Everything here is a simulation; try the invoice explorer, then tick \"Scope the query to the caller\".", "font: 14px monospace; color: #00f0ff");
  }

  function start() {
    consoleHint();
    $("hero-in").addEventListener("input", hero); hero();
    quiz({ rows: "st-rows", data: ST, options: { 401: "401", 403: "403", 404: "404" }, check: "st-check", reset: "st-reset", score: "st-score", note: "st-note", prefix: "st", ok: "# fluent in status codes. Teapots excepted." });
    quiz({ rows: "tk-rows", data: TK, options: { key: "API key", cookie: "Session cookie", oauth: "OAuth access token" }, check: "tk-check", reset: "tk-reset", score: "tk-score", note: "tk-note", prefix: "tk", ok: "# four for four: pick the mechanism for the caller, not for the library you already know." });
    segPick("bo-user", "data-u", (u) => { boUser = Number(u); boReset(); boSend(); });
    click("bo-send", boSend); click("bo-prev", () => boStep(-1)); click("bo-next", () => boStep(1));
    $("bo-id").addEventListener("keydown", (e) => { if (e.key === "Enter") boSend(); });
    $("bo-check").addEventListener("change", boSend);
    $("bo-method").addEventListener("change", boSend);
    $("bo-uuid").addEventListener("change", () => { boReset(); boSend(); });
    click("bo-leak", () => { const other = BO_INV.find((i) => i.owner !== boUser && i.id !== 42); $("bo-uuid").checked = true; boMine(); $("bo-id").value = other.uuid; boSend(); });
    boReset(); boSend();
    segPick("bf-mode", "data-m", (m) => { bfMode = m; bfRender(); $("bf-note").textContent = ""; });
    click("bf-add", bfAdd); click("bf-rule", bfRule); click("bf-reset", bfReset); bfReset();
    click("kr-new", () => krStep("new")); click("kr-switch", () => krStep("billing")); click("kr-switch2", () => krStep("reports-cron"));
    click("kr-revoke", () => krStep("revoke")); click("kr-send", krSend); click("kr-reset", krInit); krInit();
    segPick("jw-pick", "data-s", (s) => { jwScenario = s; jwRender(); });
    segPick("jw-mode", "data-v", (v) => { jwMode = v; jwRender(); }); jwRender();
    segPick("oa-user", "data-u", oaRender);
    $("oa-scopes").addEventListener("change", oaRender); oaRender();
    presets("ma-presets", "data-b", (b) => { $("ma-body").value = MA_BODY[b]; maSend(); });
    segPick("ma-mode", "data-m", (m) => { maMode = m; maSend(); });
    $("ma-body").addEventListener("input", maSend); $("ma-body").value = MA_BODY.normal; maSend();
    segPick("os-mode", "data-m", (m) => { osMode = m; osRender(); });
    $("os-fields").addEventListener("change", (e) => { const k = e.target.dataset.k; if (!k) return; if (e.target.checked) osOn.add(k); else osOn.delete(k); osRender(); }); osRender();
    segPick("rl-by", "data-b", (b) => { rlBy = b; rlInit(); });
    click("rl-a1", () => rlFire("alice", 1)); click("rl-s5", () => rlFire("scraper", 5)); click("rl-s100", () => rlFire("scraper", 100)); click("rl-reset", rlInit);
    rlInit(); setInterval(() => { if (rlLog.length || rlB.global.t < RL_CAP || rlB.alice.t < RL_CAP || rlB.scraper.t < RL_CAP) rlRender(); }, 300);
    $("rl-limit").addEventListener("input", rlPage); rlPage();
    segPick("er-pick", "data-s", (s) => { erScenario = s; erRender(); });
    segPick("er-mode", "data-m", (m) => { erMode = m; erRender(); }); erRender();
    owRender(); $("ow-grid").addEventListener("click", (e) => { const b = e.target.closest("button[data-i]"); if (b) owPick(+b.dataset.i); });
    review();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
})();
