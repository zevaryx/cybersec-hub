/* app.js - the live demos for "Identity and Access Management". Shared maths: ../../shared/crypto.js (window.Lab).
   The ID token is a real ES256 JWT (P-256 ECDSA over SHA-256), made and checked in your browser.
   The identity provider, phone, policies and help desk are simulations; nothing is sent anywhere. */
(function () {
  "use strict";
  const L = window.Lab;

  // --------------------------------------------------------------------------- helpers
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const sp = (cls, s) => `<span class="${cls}">${esc(s)}</span>`;
  function bind(ids, fn) { for (const id of [].concat(ids)) $(id).addEventListener("input", fn); fn(); }
  function click(id, fn) { $(id).addEventListener("click", fn); }
  const b64u = (bytes) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const b64uText = (s) => b64u(L.utf8(s));
  const unb64u = (s) => { s = s.replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "="; return Uint8Array.from(atob(s), (c) => c.charCodeAt(0)); };
  const toBytes32 = (x) => L.fromHex(x.toString(16).padStart(64, "0"));
  const fromBytes = (b) => BigInt("0x" + (L.hex(b) || "0"));

  // --------------------------------------------------------------------------- title: a username is a claim
  function hero() {
    const el = $("hero-in"), v = el.value;
    el.style.width = Math.max(6, v.length + 1) + "ch";
    const t = v.trim().toLowerCase();
    $("hero-out").innerHTML = `${sp("k", "claimed:")} ${esc(v.trim() || "(nobody)")}<br>${sp("k", "proven:")} ${sp("bad", "not yet")}  ${sp("m", "(a name is a claim, not proof)")}`;
    let note = "# prove it: something you have, know, or are.";
    if (t === "root") note = "# root? On the first try? Bold.";
    else if (t === "admin" || t === "administrator") note = "# Everyone's admin until someone checks.";
    else if (t === "guest") note = "# The guest account: still enabled since 2009, probably.";
    else if (t === "") note = "# no username, no problem? Anonymous access is an identity too.";
    $("hero-note").textContent = note;
  }

  // --------------------------------------------------------------------------- SSO and the leaver
  const APPS = [{ n: "Email", sso: 1 }, { n: "Chat", sso: 1 }, { n: "Payroll", sso: 1 }, { n: "Cloud console", sso: 1 },
    { n: "CRM", sso: 1 }, { n: "Wiki", sso: 1 }, { n: "Old file share", sso: 1, forgot: 1 }, { n: "Design tool", sso: 1, forgot: 1 }];
  let left = false;
  function sso() {
    const on = $("sso-on").checked;
    $("sso-apps").innerHTML = (on ? `<div class="idp ${left ? "off" : ""}">Identity provider · Sam</div>` : "") +
      APPS.map((a) => {
        const open = left && !on && a.forgot;
        const st = !left ? "on" : open ? "open" : "off";
        return `<div class="app ${st}"><b>${esc(a.n)}</b><span>${st === "on" ? (on ? "via SSO" : "own password") : st === "open" ? "still open" : "closed"}</span></div>`;
      }).join("");
    if (!left) $("sso-out").textContent = on ? "# one identity, eight apps." : "# eight apps, eight separate accounts for Sam.";
    else if (on) $("sso-out").textContent = "# one switch in the identity provider: every app closed at once.";
    else $("sso-out").textContent = "# IT closed the six accounts it knew about. Two are still open, and Sam still knows the passwords.";
  }

  // --------------------------------------------------------------------------- a real ES256 ID token
  let idp = null, jwt = null;
  function issue() {
    if (!idp) { const d = L.randBelow(L.P256.n - 1n) + 1n; idp = { d, Q: L.P256.mul(d) }; }
    const now = Math.floor(Date.now() / 1000);
    const header = JSON.stringify({ alg: "ES256", typ: "JWT", kid: "idp-2026-10" });
    const payload = JSON.stringify({ iss: "https://idp.example.com", sub: "alice-7f3a", aud: "wiki-app", name: "Alice", role: "editor", iat: now, exp: now + 3600, nonce: "n-0S6_WzA2Mj" });
    const signing = b64uText(header) + "." + b64uText(payload);
    const [r, s] = L.ecdsaSign(idp.d, L.hashInt(signing), L.randBelow(L.P256.n - 1n) + 1n);
    jwt = { h: b64uText(header), p: b64uText(payload), s: b64u(L.concat(toBytes32(r), toBytes32(s))) };
    show();
  }
  function edit(fn) {
    const h = JSON.parse(L.text(unb64u(jwt.h))), p = JSON.parse(L.text(unb64u(jwt.p)));
    fn(h, p);
    jwt = { h: b64uText(JSON.stringify(h)), p: b64uText(JSON.stringify(p)), s: jwt.s };
    show();
  }
  function verify() {
    const h = JSON.parse(L.text(unb64u(jwt.h))), p = JSON.parse(L.text(unb64u(jwt.p)));
    if (h.alg !== "ES256") return { ok: false, why: `alg is "${h.alg}": refused. Only ES256 is accepted, whatever the token says.`, none: h.alg === "none" };
    const sig = unb64u(jwt.s);
    const ok = sig.length === 64 && L.ecdsaVerify(idp.Q, L.hashInt(jwt.h + "." + jwt.p), [fromBytes(sig.slice(0, 32)), fromBytes(sig.slice(32))]);
    if (!ok) return { ok: false, why: "signature doesn't match the header and payload: refused." };
    if (p.aud !== "wiki-app") return { ok: false, why: "audience isn't this app: refused." };
    if (p.exp < Date.now() / 1000) return { ok: false, why: "expired: refused." };
    return { ok: true, p };
  }
  function show() {
    const cut = (s, n) => (s.length > n ? s.slice(0, n) + "…" : s);
    $("jwt-raw").innerHTML = `<span class="c-h">${esc(cut(jwt.h, 44))}</span>.<span class="c-p">${esc(cut(jwt.p, 120))}</span>.<span class="c-s">${esc(cut(jwt.s, 44))}</span>`;
    const p = JSON.parse(L.text(unb64u(jwt.p))), h = JSON.parse(L.text(unb64u(jwt.h)));
    const v = verify();
    let out = `${sp("k", "header ")} ${esc(JSON.stringify(h))}\n${sp("k", "payload")} iss ${esc(p.iss)}\n        sub ${esc(p.sub)}  aud ${esc(p.aud)}\n        name ${esc(p.name)}  role ${p.role === "admin" ? sp("bad", p.role) : esc(p.role)}\n        exp in ${Math.round((p.exp - Date.now() / 1000) / 60)} min\n\n`;
    out += v.ok ? sp("ok", `the wiki checks the signature with the IdP's public key: valid. Welcome, ${p.name}.`) : sp("bad", "the wiki: " + v.why);
    if (v.none) out += `\n\n${sp("y", "alg: none is the token equivalent of a note saying \"let me in, I'm allowed\".")}`;
    $("jwt-out").innerHTML = out;
  }

  // --------------------------------------------------------------------------- push fatigue
  let pushTimer = null, pushN = 0, pushCode = 0;
  function pushStop() { clearInterval(pushTimer); pushTimer = null; }
  function pushPrompt() {
    pushN++;
    const match = $("push-match").checked;
    pushCode = 10 + L.randInt(90);
    const time = `0${2}:${String(3 + pushN * 2).padStart(2, "0")}`;
    $("push-phone").innerHTML = `<div class="notif"><small>${time} · Sign-in request #${pushN}</small><b>Are you trying to sign in?</b><span>Unknown device · new location</span>` +
      (match ? `<label class="m">Enter the number shown on the sign-in screen <input id="push-num" inputmode="numeric" maxlength="2" placeholder="??"></label><div class="btns"><button type="button" class="btn btn-sm" data-a="num">Submit</button><button type="button" class="btn btn-ghost btn-sm" data-a="deny">Deny</button></div>`
        : `<div class="btns"><button type="button" class="btn btn-sm" data-a="approve">Approve</button><button type="button" class="btn btn-ghost btn-sm" data-a="deny">Deny</button></div>`) + `</div>`;
    $("push-out").textContent = match ? "# the attacker sees a number on their screen. You don't." : `# prompt ${pushN}. It's ${time}. They'll keep coming.`;
  }
  function pushStart() {
    pushStop(); pushN = 0; pushPrompt();
    pushTimer = setInterval(() => { if (pushN < 12) pushPrompt(); else { pushStop(); $("push-out").textContent = "# twelve prompts ignored. The attacker gives up. Now report it."; } }, 2200);
  }
  function pushAnswer(a) {
    const match = $("push-match").checked;
    pushStop();
    if (a === "deny") { $("push-phone").innerHTML = `<p class="ok">Denied. Reported to security.</p>`; $("push-out").textContent = "# right call: a prompt you didn't ask for means your password is known."; return; }
    if (a === "num") {
      const v = ($("push-num") || {}).value || "";
      $("push-phone").innerHTML = `<p class="ok">Sign-in failed: wrong number.</p>`;
      $("push-out").textContent = v ? `# you guessed ${v}; the screen showed ${pushCode}. Number matching wins.` : "# no number to type, because you didn't start this sign-in. Number matching wins.";
      return;
    }
    $("push-phone").innerHTML = `<p class="bad">Approved. The attacker is in.</p>`;
    $("push-out").textContent = pushN >= 10 ? "# You approved prompt 10 at 2am. Congratulations: you're the breach. (It happens to tired people. That's why number matching exists.)"
      : `# approved on prompt ${pushN}. That's push fatigue.`;
  }

  // --------------------------------------------------------------------------- conditional access
  const CA = { who: "staff", dev: "managed", loc: "usual", app: "email" };
  function ca() {
    const r = [];
    let verdict = "allow";
    const up = (v) => { const o = ["allow", "mfa", "key", "block"]; if (o.indexOf(v) > o.indexOf(verdict)) verdict = v; };
    if (CA.loc === "travel") { r.push("impossible travel: two countries in 20 minutes"); up("block"); }
    if (CA.who === "admin" && CA.dev !== "managed") { r.push("admins only from managed, up-to-date devices"); up("block"); }
    if (CA.app === "console" && CA.who !== "admin") { r.push("only admins may open the cloud console"); up("block"); }
    if (CA.dev === "old") { r.push("device is behind on updates"); up(CA.app === "email" ? "mfa" : "block"); }
    if (CA.who === "admin" || CA.app === "console") { r.push("admin access needs a security key"); up("key"); }
    if (CA.app === "payroll") { r.push("payroll needs MFA every time"); up("mfa"); }
    if (CA.loc === "new") { r.push("new country: confirm it's you"); up("mfa"); }
    if (CA.who === "contractor" && CA.dev === "personal") { r.push("contractors on personal devices: web access only"); up("mfa"); }
    const label = { allow: sp("ok", "ALLOW"), mfa: sp("y", "ALLOW after MFA"), key: sp("y", "ALLOW with a security key"), block: sp("bad", "BLOCK") }[verdict];
    $("ca-out").innerHTML = `${sp("k", "decision:")} ${label}\n\n` + (r.length ? r.map((x) => "  ▸ " + esc(x)).join("\n") : sp("m", "  no rules triggered")) +
      (verdict === "block" ? `\n\n${sp("m", "blocked sign-ins are logged and alert the security team")}` : "");
  }

  // --------------------------------------------------------------------------- joiners, movers, leavers
  const JOBS = [["support", ["ticket-system", "customer-lookup"]], ["sales", ["crm", "price-lists"]], ["finance", ["payroll", "bank-portal"]],
    ["sales lead", ["crm-admin", "discount-approvals"]], ["finance lead", ["payment-approval", "audit-exports"]], ["intern mentor", ["intern-wiki"]]];
  let drift = null;
  function driftReset() { drift = { t: 0, job: 0, access: new Set(["email", "chat", ...JOBS[0][1]]), log: ["month 0: Dana joins support"] }; driftShow(); }
  function driftStep() {
    const reviews = $("drift-review").checked;
    drift.t += 6;
    const next = (drift.job + 1) % JOBS.length;
    if (drift.t % 12 === 0 && drift.job < JOBS.length - 1) {
      if (reviews) drift.access = new Set(["email", "chat"]);
      drift.job = next;
      JOBS[next][1].forEach((a) => drift.access.add(a));
      drift.log.push(`month ${drift.t}: Dana moves to ${JOBS[next][0]}` + (reviews ? ", old access removed" : ""));
    } else {
      if (!reviews) drift.access.add(["shared-drive-all", "temp-admin", "old-project-x", "vendor-portal", "prod-db-read"][(drift.t / 6) % 5]);
      drift.log.push(`month ${drift.t}: ` + (reviews ? "access review: nothing extra found" : "a \"temporary\" grant, never removed"));
    }
    driftShow();
  }
  function driftShow() {
    const need = new Set(["email", "chat", ...JOBS[drift.job][1]]);
    const extra = [...drift.access].filter((a) => !need.has(a));
    let out = `${sp("k", "Dana's job:")} ${esc(JOBS[drift.job][0])}\n${sp("k", "needs:")}     ${esc([...need].join(", "))}\n${sp("k", "has:")}       ${drift.access.size} permissions` +
      (extra.length ? `  ${sp("bad", "(" + extra.length + " not needed)")}` : `  ${sp("ok", "(exactly the job)")}`) + "\n\n" + drift.log.slice(-5).map((l) => sp("m", l)).join("\n");
    if (extra.length) out += `\n${sp("bad", "extra: " + extra.join(", "))}`;
    if (drift.t >= 36 && !$("drift-review").checked) out += `\n\n${sp("y", "Three years in: Dana can approve payments, export the audit and read production. Dana mentors the interns.")}`;
    $("drift-out").innerHTML = out;
  }

  // --------------------------------------------------------------------------- the help desk call
  const CALL = [
    { say: "\"Hi, it's Jordan, VP of Sales. I'm about to board, my phone died, and I'm locked out before a huge client call. Can you reset my MFA? Quickly, please.\"",
      opts: [["verify", "Call Jordan back on the number in the directory"], ["reset", "Reset it: they sound senior and stressed"], ["please", "Reset it: they said please"]] },
    { say: "The directory number goes to Jordan's real phone. Jordan answers: \"Reset my MFA? No, I'm sitting at my desk.\"",
      opts: [["report", "Report the call to security"]] },
  ];
  function call(step, choice) {
    if (choice === "reset" || choice === "please") {
      $("call").innerHTML = `<p class="bad">MFA reset. The caller enrols their own phone and signs in as Jordan.</p>`;
      $("call-choices").innerHTML = `<button type="button" class="btn btn-ghost btn-sm" data-c="restart">Try again</button>`;
      $("call-out").textContent = choice === "please" ? "# Manners are lovely. They're not identity verification." : "# urgency and seniority are the two oldest tricks. The script exists for exactly this call.";
      return;
    }
    if (choice === "report") {
      $("call").innerHTML = `<p class="ok">Security is alerted, Jordan's account is watched, and nobody else gets reset today.</p>`;
      $("call-choices").innerHTML = `<button type="button" class="btn btn-ghost btn-sm" data-c="restart">Play again</button>`;
      $("call-out").textContent = "# one minute slower, one breach fewer.";
      return;
    }
    const s = CALL[step];
    $("call").innerHTML = `<p>${esc(s.say)}</p>`;
    $("call-choices").innerHTML = s.opts.map(([c, t]) => `<button type="button" class="btn btn-ghost btn-sm" data-c="${c}" data-s="${step + 1}">${esc(t)}</button>`).join("");
    $("call-out").textContent = step ? "# verified the safe way." : "# the help desk phone rings.";
  }

  // --------------------------------------------------------------------------- the 90-day plan
  const STORE = "identity-and-access-plan";
  function plan() {
    const boxes = [...$("plan-grid").querySelectorAll("input")];
    let saved = [];
    try { saved = JSON.parse(localStorage.getItem(STORE) || "[]"); } catch (e) {}
    boxes.forEach((b, i) => { b.checked = !!saved[i]; });
    const upd = () => {
      const n = boxes.filter((b) => b.checked).length;
      try { localStorage.setItem(STORE, JSON.stringify(boxes.map((b) => b.checked))); } catch (e) {}
      $("plan-note").textContent = n === boxes.length ? "12 of 12. Identity: managed. Now schedule the next review." : `${n} of 12 done. This page remembers, on this device only.`;
      $("plan-note").classList.toggle("ok", n === boxes.length);
    };
    boxes.forEach((b) => b.addEventListener("change", upd));
    upd();
  }

  // --------------------------------------------------------------------------- easter eggs
  function consoleHint() {
    console.log("%cIdentity and Access", "font: 700 24px monospace; color: #ff2e88; text-shadow: 0 0 8px #ff2e88");
    console.log("%cWho are you? Your browser's dev tools know: look at this site's cookies. (There aren't any. That's the point.)", "font: 14px monospace; color: #00f0ff");
  }

  function start() {
    consoleHint();
    bind("hero-in", hero);
    $("sso-on").addEventListener("change", () => { left = false; sso(); });
    click("sso-leave", () => { left = true; sso(); });
    sso();
    issue();
    click("jwt-new", issue);
    click("jwt-admin", () => edit((h, p) => { p.role = "admin"; }));
    click("jwt-none", () => edit((h, p) => { h.alg = "none"; }));
    click("push-go", pushStart);
    $("push-match").addEventListener("change", () => { pushStop(); $("push-phone").innerHTML = `<p class="m">Your phone is quiet. For now.</p>`; $("push-out").textContent = ""; });
    $("push-phone").addEventListener("click", (e) => { const b = e.target.closest("button[data-a]"); if (b) pushAnswer(b.dataset.a); });
    $("ca").addEventListener("change", (e) => { const s = e.target.closest("select"); if (s) { CA[s.dataset.k] = s.value; ca(); } });
    ca();
    driftReset();
    click("drift-go", driftStep);
    click("drift-reset", driftReset);
    $("drift-review").addEventListener("change", driftReset);
    $("call-choices").addEventListener("click", (e) => { const b = e.target.closest("button[data-c]"); if (!b) return; b.dataset.c === "restart" ? call(0) : call(+b.dataset.s, b.dataset.c); });
    call(0);
    plan();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
})();
