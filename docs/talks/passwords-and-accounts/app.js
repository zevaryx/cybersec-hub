/* app.js - the live demos for "Passwords and Accounts". Shared maths: ../../shared/crypto.js (window.Lab). */
(function () {
  "use strict";
  const L = window.Lab;
  const HW = window.hashwasm || null;                 // Argon2id for the vault demo
  const enc = L.utf8;

  // --------------------------------------------------------------------------- helpers
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const sp = (cls, s) => `<span class="${cls}">${esc(s)}</span>`;
  const fmt = (n) => n.toLocaleString("en-US");
  const cut = (s, n = 32) => (s.length > n ? s.slice(0, n) + "…" : s);
  const wait = (ms = 0) => new Promise((r) => setTimeout(r, ms));
  function bind(ids, fn) { for (const id of [].concat(ids)) $(id).addEventListener("input", fn); fn(); }
  function click(id, fn) { $(id).addEventListener("click", fn); }
  const store = {
    get(k) { try { return localStorage.getItem(k); } catch (e) { return null; } },
    set(k, v) { try { localStorage.setItem(k, v); } catch (e) { /* storage blocked: the list just won't remember */ } },
    del(k) { try { localStorage.removeItem(k); } catch (e) { /* ignore */ } },
  };
  function bigWords(n) {
    const names = [[1e18, "quintillion"], [1e15, "quadrillion"], [1e12, "trillion"], [1e9, "billion"], [1e6, "million"]];
    if (n >= 1e21) { const e = Math.floor(Math.log10(n)); return `${(n / 10 ** e).toFixed(1)} × 10^${e}`; }
    for (const [v, w] of names) if (n >= v) return `${(n / v).toFixed(1).replace(/\.0$/, "")} ${w}`;
    return fmt(Math.round(n));
  }
  function duration(s) {
    const Y = 31557600;
    if (s < 1) return "under a second";
    if (s < 120) return `${s.toFixed(0)} seconds`;
    if (s < 7200) return `${(s / 60).toFixed(0)} minutes`;
    if (s < 2 * 86400) return `${(s / 3600).toFixed(1)} hours`;
    if (s < Y) return `${(s / 86400).toFixed(0)} days`;
    if (s < 1e6 * Y) return `${fmt(Math.round(s / Y))} years`;
    return `${bigWords(s / Y)} years`;
  }
  const FAST = 1e10, SLOW = 1e4;                      // guesses per second: fast hash on GPUs vs a tuned slow hash

  // common passwords and patterns attackers try first (a tiny sample)
  const COMMON = ["123456", "password", "123456789", "12345678", "qwerty", "abc123", "password1", "password123", "111111", "iloveyou",
    "admin", "welcome", "letmein", "monkey", "dragon", "sunshine", "football", "princess", "qwerty123", "1q2w3e4r", "hunter2", "trustno1"];
  function weakness(pw) {
    const p = pw.toLowerCase();
    if (!pw) return "an empty password is guessed first";
    if (COMMON.includes(p)) return "this is on every attacker's list of common passwords";
    if (/^(.)\1+$/.test(pw)) return "one character repeated";
    if (/^(?:0?123456?7?8?9?0?|qwert[yz]?u?i?o?p?|asdfg?h?j?k?l?)$/i.test(pw)) return "a keyboard or number sequence";
    if (/^[a-z]+(?:19|20)\d\d[!@#$%^&*?.]*$/i.test(pw)) return "a word, a year and a symbol: one of the first patterns attackers try";
    if (/^[a-z]+\d{1,4}[!@#$%^&*?.]?$/i.test(pw)) return "a word followed by digits: attackers try this pattern early";
    if (/p[a@]ssw[o0]rd|l[e3]tm[e3]in|w[e3]lc[o0]m[e3]/i.test(pw)) return "swapping letters for symbols (p@ssw0rd) fools nobody";
    return "";
  }
  function pool(pw) {
    let n = 0;
    if (/[a-z]/.test(pw)) n += 26;
    if (/[A-Z]/.test(pw)) n += 26;
    if (/\d/.test(pw)) n += 10;
    if (/[^A-Za-z0-9]/.test(pw)) n += 33;
    return n;
  }

  // --------------------------------------------------------------------------- easter eggs
  const EGGS = {
    hunter2: "hunter2? funny, all I see is *******",
    swordfish: "swordfish: the speakeasy password in Horse Feathers (1932). Still guessed first, 90+ years later.",
    "12345": "12345? That's the kind of combination an idiot would have on his luggage. (Spaceballs)",
    "correct horse battery staple": "xkcd 936! Great advice, famous example: it's on every guess list now.",
  };
  const egg = (pw) => EGGS[pw.trim().toLowerCase().replace(/\s+/g, " ")] || "";

  // --------------------------------------------------------------------------- title terminal
  function hero() {
    const el = $("hero-pw"), pw = el.value;
    el.style.width = Math.max(4, [...pw].length + 1) + "ch";
    const n = pool(pw), len = [...pw].length, total = n ** len, weak = weakness(pw);
    $("hero-out").innerHTML = pw
      ? `${len} characters from ${n} possible → ${bigWords(total)} combinations\nfast hash: ${sp(weak ? "bad" : "y", weak ? "seconds (it's a pattern)" : duration(total / FAST))}`
      : sp("m", "type a (fake!) password");
    const e = egg(pw);
    $("hero-note").innerHTML = e ? `# ${esc(e)}` : weak ? `# ${esc(weak)}.` : "# if it was picked at random. people rarely do that.";
  }

  // --------------------------------------------------------------------------- password reuse
  const SITES = [["Email", "📧"], ["Bank", "🏦"], ["Shopping", "🛒"], ["Streaming", "🎬"], ["Game forum", "🎮"], ["Work", "💼"]];
  let leaked = null;
  const uniquePw = SITES.map(() => L.base32Encode(L.randBytes(10)).toLowerCase());
  function reuse() {
    const same = $("reuse-same").checked, mfa = $("reuse-2fa").checked;
    let fallen = 0;
    $("reuse-sites").innerHTML = SITES.map(([name, icon], i) => {
      const pw = same ? "sunshine2026" : uniquePw[i].slice(0, 12), protectedBy2fa = mfa && (name === "Email" || name === "Bank");
      let state = "", label = "safe";
      if (leaked !== null) {
        if (i === leaked) { state = "leak"; label = "LEAKED"; fallen++; }
        else if (same && !protectedBy2fa) { state = "fall"; label = "attacker logged in"; fallen++; }
        else if (same && protectedBy2fa) { state = "held"; label = "blocked by two-factor"; }
        else { state = "safe"; label = "different password: safe"; }
      }
      return `<button type="button" class="site ${state}" data-i="${i}"><span class="ico" aria-hidden="true">${icon}</span><b>${name}</b><code>${esc(pw)}</code><em>${label}</em>${protectedBy2fa ? '<small>two-factor on</small>' : ""}</button>`;
    }).join("");
    $("reuse-out").innerHTML = leaked === null
      ? sp("m", "Nothing has leaked yet.")
      : `${esc(SITES[leaked][0])} leaked its email + password list.\nthe attacker's bot tried them on the other ${SITES.length - 1} sites:  ${fallen > 1 ? sp("bad", `${fallen} of ${SITES.length} accounts taken over`) : sp("ok", "only the leaked site is affected")}`;
  }

  // --------------------------------------------------------------------------- what a site stores
  let storeToken = 0;
  async function storage() {
    const pw = $("store-pw").value, token = ++storeToken, fastHash = L.hex(L.sha256(enc(pw)));
    const common = COMMON.includes(pw.toLowerCase());
    const row = (cls, title, stored, verdict) => `<div class="store ${cls}"><b>${title}</b><code>${stored}</code><span>${verdict}</span></div>`;
    const draw = (slow) => {
      $("store-rows").innerHTML =
        row("bad", "Plain text", esc(pw) || "(empty)", "A leak shows everyone's password directly. Never acceptable.") +
        row("bad", "Fast hash (SHA-256)", cut(fastHash, 40), common ? "Common password: cracked instantly from a pre-computed table." : "Billions of guesses per second on a graphics card. Weak passwords fall quickly.") +
        row("ok", "Salted slow hash (Argon2id)", slow, "Unique salt per user, about a tenth of a second per guess. Attackers must crack each user separately.");
    };
    draw(sp("m", "computing…"));
    let slow;
    if (HW) {
      const t0 = performance.now();
      slow = await HW.argon2id({ password: pw, salt: L.randBytes(16), iterations: 2, parallelism: 1, memorySize: 19456, hashLength: 32, outputType: "encoded" });
      slow = `${esc(cut(slow, 64))} <i>(${(performance.now() - t0).toFixed(0)} ms)</i>`;
    } else slow = sp("m", "(needs WebAssembly, blocked in this browser)");
    if (token === storeToken) draw(slow);
  }

  // --------------------------------------------------------------------------- k-anonymity leak check (simulated)
  function leakCheck() {
    const pw = $("leak-pw").value, h = L.hex(L.sha1(enc(pw))).toUpperCase(), prefix = h.slice(0, 5), suffix = h.slice(5);
    const found = pw && COMMON.includes(pw.toLowerCase());
    // a made-up reply: random suffixes, plus the real one if this is a famous password
    const fake = Array.from({ length: 5 }, () => L.hex(L.randBytes(18)).toUpperCase().slice(0, 35));
    if (found) fake.splice(2, 0, suffix);
    $("leak-out").innerHTML =
      `SHA-1(password) = ${sp("k", prefix)}${sp("m", suffix)}\n\n` +
      `${sp("c", "your device sends:")}   ${sp("k", prefix)}   ${sp("m", "(5 characters, nothing else)")}\n` +
      `${sp("c", "service replies:")}     ${sp("m", "every leaked hash starting with " + prefix + ", e.g.")}\n` +
      fake.map((s) => `   ${s === suffix ? sp("bad", s) : s}`).join("\n") + `\n   ${sp("m", "… hundreds more")}\n\n` +
      (pw ? (found ? `${sp("bad", "found: this password has appeared in breaches. Never use it.")}` : `${sp("ok", "not in this sample")} ${sp("m", "(the real check covers billions of leaked passwords)")}`) : sp("m", "type a password"));
  }

  // --------------------------------------------------------------------------- length vs complexity
  function estimate() {
    const len = +$("est-len").value, words = +$("est-words").value;
    $("est-len-out").textContent = len; $("est-words-out").textContent = words;
    let n = 0;
    if ($("est-lower").checked) n += 26;
    if ($("est-upper").checked) n += 26;
    if ($("est-digits").checked) n += 10;
    if ($("est-symbols").checked) n += 33;
    const pw = n ** len, pp = 7776 ** words;
    const stat = (cls, big, label) => `<div class="stat ${cls}"><b>${big}</b><span>${label}</span></div>`;
    $("est-out").innerHTML = n === 0
      ? stat("", "–", "pick at least one character type")
      : stat("fast", `~${duration(pw / FAST)}`, `${len} random characters (${n} types each): ${bigWords(pw)} combinations · fast hash`) +
        stat("slow", `~${duration(pp / FAST)}`, `${words} random words: ${bigWords(pp)} combinations · fast hash`);
  }

  // --------------------------------------------------------------------------- generator
  const SETS = { lower: "abcdefghijkmnopqrstuvwxyz", upper: "ABCDEFGHJKLMNPQRSTUVWXYZ", digits: "23456789", symbols: "!#$%&*+-=?@^_~" };
  function generate() {
    const len = +$("gen-len").value, sym = $("gen-symbols").checked;
    $("gen-len-out").textContent = len;
    const chars = SETS.lower + SETS.upper + SETS.digits + (sym ? SETS.symbols : "");
    let pw = "";
    for (let i = 0; i < len; i++) pw += chars[L.randInt(chars.length)];   // unbiased, from the secure generator
    const bits = len * Math.log2(chars.length);
    $("gen-out").textContent = pw;
    $("gen-info").innerHTML = `${chars.length} possible characters × ${len} = about ${sp("y", bits.toFixed(0))} bits of randomness\n` +
      `fast hash: ${sp("ok", duration(2 ** bits / FAST))}\n${sp("m", "(look-alike characters like l, 1, O and 0 are left out)")}` +
      (len >= 40 ? `\n${sp("y", "Nobody will ever crack this. Including you, so let the password manager remember it.")}` : "");
  }

  // --------------------------------------------------------------------------- autofill only on the real site
  function autofill() {
    const site = $("af-site").value, real = site === "bank.example";
    $("af-browser").innerHTML =
      `<div class="bar"><span class="lock">🔒</span><span class="url">https://<b>${esc(site)}</b>/login</span></div>` +
      `<div class="page"><b>BANK · Sign in</b>` +
      `<label>Email<input readonly value="${real ? "you@example.com" : ""}"></label>` +
      `<label>Password<input readonly type="${real ? "password" : "text"}" value="${real ? "x8#Kq2!vR9mZ" : ""}"></label>` +
      `<p class="${real ? "ok" : "bad"}">${real ? "✓ Password manager filled this in: saved for bank.example" : "✗ No saved login for this site. That's a warning: check the address."}</p></div>`;
  }

  // --------------------------------------------------------------------------- vault: master password → slow hash → key → AES-GCM
  let vault = null;
  const VAULT = JSON.stringify([{ site: "bank.example", user: "you@example.com", password: "x8#Kq2!vR9mZ" },
    { site: "mail.example", user: "you@example.com", password: "u7$Lm3@cW1pQ" }]);
  async function deriveKey(master, salt) {
    const t0 = performance.now();
    let key;
    if (HW) key = await HW.argon2id({ password: master, salt, iterations: 2, parallelism: 1, memorySize: 19456, hashLength: 16, outputType: "binary" });
    else {
      const k = await crypto.subtle.importKey("raw", enc(master), "PBKDF2", false, ["deriveBits"]);
      key = new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: 600000 }, k, 128));
    }
    return { key, ms: performance.now() - t0, kdf: HW ? "Argon2id (19 MiB, 2 passes)" : "PBKDF2 (600,000 rounds)" };
  }
  async function lockVault(btn) {
    btn.disabled = true; await wait(20);
    try {
      const salt = L.randBytes(16), nonce = L.randBytes(12), { key, ms, kdf } = await deriveKey($("vault-master").value, salt);
      const { ct, tag } = L.gcmEncrypt(key, nonce, enc(VAULT));
      vault = { salt, nonce, ct, tag };
      $("vault-out").innerHTML =
        `${sp("c", "on your device:")}\n  ${kdf}: master password → key in ${ms.toFixed(0)} ms\n  AES-GCM encrypts ${JSON.parse(VAULT).length} saved logins\n\n` +
        `${sp("k", "what the company stores:")}\n  salt   ${L.hex(salt)}\n  vault  ${cut(L.hex(ct), 48)}\n  tag    ${L.hex(tag)}\n${sp("m", "  no master password, no key")}` +
        (COMMON.includes($("vault-master").value.trim().toLowerCase()) ? `\n${sp("y", "A vault locked with a top-20 password. The lock is mostly decorative.")}` : "");
      $("vault-try-out").textContent = "";
    } finally { btn.disabled = false; }
  }
  async function unlockVault(btn) {
    if (!vault) { $("vault-try-out").innerHTML = sp("m", "Lock the vault first."); return; }
    btn.disabled = true; await wait(20);
    try {
      const { key, ms } = await deriveKey($("vault-try").value, vault.salt);
      try {
        const logins = JSON.parse(L.text(L.gcmDecrypt(key, vault.nonce, vault.ct, vault.tag)));
        $("vault-try-out").innerHTML = `${sp("ok", "unlocked")} ${sp("m", `(${ms.toFixed(0)} ms)`)}\n` + logins.map((l) => `  ${l.site.padEnd(14)} ${l.user}  ${l.password}`).join("\n");
      } catch (e) {
        $("vault-try-out").innerHTML = `${sp("bad", "wrong master password: the tag doesn't match")}\n${sp("m", `that guess cost ${ms.toFixed(0)} ms. An attacker pays that for every guess.`)}`;
      }
    } finally { btn.disabled = false; }
  }

  // --------------------------------------------------------------------------- authenticator codes (TOTP)
  const TOTP_SECRET = "5NB6LB7GEF7KT3GIKR3VZKCWRNRRXAEV";   // public demo secret, also in totp-qr.svg
  const TOTP_KEY = L.base32Decode(TOTP_SECRET), RING = 2 * Math.PI * 54;
  let lastStep = -1;
  function totpTick() {
    const now = Date.now() / 1000, step = Math.floor(now / 30), left = 30 - (now % 30);
    $("totp-left").textContent = Math.ceil(left);
    $("totp-bar").style.strokeDasharray = RING.toFixed(2);
    $("totp-bar").style.strokeDashoffset = (RING * (1 - left / 30)).toFixed(2);
    $("totp-bar").classList.toggle("low", left <= 5);
    if (step === lastStep) return;
    lastStep = step;
    const cur = L.totp(TOTP_KEY, now), next = L.totp(TOTP_KEY, now + 30), code = cur.code;
    $("totp-code").textContent = `${code.slice(0, 3)} ${code.slice(3)}`;
    $("totp-next").innerHTML = `next code ${next.code.slice(0, 3)} ${next.code.slice(3)}   ${sp("m", "(already known to anyone with the secret)")}` +
      (code.includes("42") ? `\n${sp("y", "This code contains 42: the Answer to Life, the Universe and Everything.")}` : "");
    const mac = L.hex(cur.mac), o = cur.offset;
    const macShown = [...Array(20)].map((_, i) => {
      const byte = mac.slice(2 * i, 2 * i + 2);
      return i >= o && i < o + 4 ? sp("k", byte) : i === 19 ? sp("y", byte) : byte;
    }).join(" ");
    $("totp-steps").innerHTML =
      `1. time step  = floor(${fmt(Math.floor(now))} seconds ÷ 30) = ${sp("c", fmt(step))}\n` +
      `2. HMAC-SHA1(secret, time step) =\n   ${macShown}\n` +
      `3. last byte ${sp("y", mac.slice(38))} ends in ${sp("y", o.toString(16))} → take 4 bytes from position ${o}: ${sp("k", mac.slice(2 * o, 2 * o + 8))}\n` +
      `   as a number (top bit dropped) = ${fmt(cur.bin)}\n` +
      `4. last 6 digits: ${fmt(cur.bin)} mod 1,000,000 = ${sp("ok", code)}`;
  }
  function totpInit() {
    $("totp-secret").innerHTML = `${sp("y", TOTP_SECRET.match(/.{4}/g).join(" "))}   ${sp("m", "Base32, 20 random bytes")}`;
    totpTick();
    setInterval(totpTick, 250);
  }

  // --------------------------------------------------------------------------- which method stops which attack
  function mfaInit() {
    const table = $("mfa-table");
    table.querySelector("thead").addEventListener("click", (e) => {
      const b = e.target.closest("button[data-col]");
      if (!b) return;
      const col = +b.dataset.col, on = !b.classList.contains("on");
      table.querySelectorAll("thead button").forEach((x) => x.classList.toggle("on", on && x === b));
      table.querySelectorAll("tr").forEach((tr) => [...tr.children].forEach((cell, i) => cell.classList.toggle("hi", on && i === col)));
    });
  }

  // --------------------------------------------------------------------------- the look-alike site test
  function phish(go) {
    const col = (cls, who, steps) => `<div class="victim ${go ? cls : ""}"><b>${who}</b>${steps.map((s) => `<p>${s}</p>`).join("")}</div>`;
    $("phish").innerHTML = !go
      ? col("", "You type it yourself", ["Waiting for the email…"]) + col("", "Your password manager", ["Waiting…"]) + col("", "A passkey", ["Waiting…"])
      : col("lost", "You type it yourself", ["The page looks exactly like your bank.", "You type your password: " + sp("bad", "sent to the attacker") + ".", "It asks for your app code: you type it, and the attacker uses it within 30 seconds.", sp("bad", "Account taken over.")]) +
        col("warn", "Your password manager", ["It looks for a login saved for bank-examp1e.com.", sp("y", "Nothing saved for this address, so it fills in nothing."), "That's your warning sign: you stop and check the address.", sp("ok", "Safe, if you heed it.")]) +
        col("safe", "A passkey", ["Your device looks for a passkey for bank-examp1e.com.", "There isn't one: passkeys belong to the real address only.", "Even if relayed, a signature names the fake site and the bank rejects it.", sp("ok", "Nothing to steal.")]);
  }

  // --------------------------------------------------------------------------- recovery codes and tonight's checklist
  function recoveryCodes() {
    const a = "abcdefghjkmnpqrstuvwxyz23456789", part = () => Array.from({ length: 4 }, () => a[L.randInt(a.length)]).join("");
    $("rc-codes").innerHTML = Array.from({ length: 10 }, () => `<code>${part()}-${part()}</code>`).join("");
  }
  const TODO = [
    ["Install a password manager", "The one built into your browser or phone is fine to start."],
    ["Give your email a long, unique password", "Email can reset everything else, so it goes first."],
    ["Turn on two-factor for email, bank and the password manager", "An authenticator app, or a passkey where offered."],
    ["Save your recovery codes", "In the password manager and on paper at home."],
    ["Check your email at haveibeenpwned.com", "Change any password from a breach you're in."],
    ["Protect your phone number", "Ask your carrier for a PIN or port-out protection."],
    ["Add passkeys where sites offer them", "Look for \"passkey\" in each site's security settings."],
    ["Replace reused passwords, a few at a time", "Let the password manager generate new ones as you log in."],
  ];
  const TODO_KEY = "hub-passwords-checklist";
  function todo() {
    let done = [];
    try { done = JSON.parse(store.get(TODO_KEY) || "[]"); } catch (e) { done = []; }
    $("todo").innerHTML = TODO.map(([t, d], i) =>
      `<li><label><input type="checkbox" data-i="${i}" ${done.includes(i) ? "checked" : ""}><span><b>${esc(t)}</b><small>${esc(d)}</small></span></label></li>`).join("");
    $("todo-count").textContent = `${done.length} / ${TODO.length}`;
    fortress(done.length === TODO.length);
  }
  function fortress(on) {
    const el = $("todo-fortress");
    if (on && el.hidden) { el.hidden = false; el.classList.remove("pop"); void el.offsetWidth; el.classList.add("pop"); }
    else if (!on) el.hidden = true;
  }
  function todoInit() {
    $("todo").addEventListener("change", () => {
      const done = [...$("todo").querySelectorAll("input:checked")].map((x) => +x.dataset.i);
      store.set(TODO_KEY, JSON.stringify(done));
      $("todo-count").textContent = `${done.length} / ${TODO.length}`;
      fortress(done.length === TODO.length);
    });
    click("todo-clear", () => { store.del(TODO_KEY); todo(); });
    todo();
  }

  // --------------------------------------------------------------------------- start
  function consoleHint() {
    console.log("%cPASSWORDS & ACCOUNTS", "font: 700 26px monospace; color: #ff2e88; text-shadow: 0 0 8px #ff2e88");
    console.log("%cPsst. The speakeasy in Horse Feathers (1932) had a password.\nTry it on the title slide.", "font: 14px monospace; color: #00f0ff");
  }

  function start() {
    consoleHint();
    bind("hero-pw", hero);
    document.querySelectorAll('input[name="reuse-mode"]').forEach((r) => r.addEventListener("change", reuse));
    $("reuse-2fa").addEventListener("change", reuse);
    $("reuse-sites").addEventListener("click", (e) => { const b = e.target.closest(".site"); if (b) { leaked = +b.dataset.i; reuse(); } });
    click("reuse-reset", () => { leaked = null; reuse(); });
    reuse();
    bind("store-pw", storage);
    bind("leak-pw", leakCheck);
    bind(["est-len", "est-words", "est-lower", "est-upper", "est-digits", "est-symbols"], estimate);
    bind(["gen-len", "gen-symbols"], generate);
    click("gen-new", generate);
    $("af-site").addEventListener("change", autofill); autofill();
    click("vault-lock", (e) => lockVault(e.currentTarget));
    click("vault-unlock", (e) => unlockVault(e.currentTarget));
    totpInit();
    mfaInit();
    phish(false);
    click("phish-go", () => phish(true));
    click("phish-reset", () => phish(false));
    recoveryCodes(); click("rc-new", recoveryCodes);
    todoInit();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
})();
