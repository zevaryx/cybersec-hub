/* app.js - the live demos for "Secrets Management".
   Every demo is a simulation in this page: a toy scanner, a toy repository, a made-up cloud, and real (but from-scratch) AES-GCM
   and ECDSA from ../../shared/crypto.js. All keys, tokens and secrets are invented on the spot; nothing is fetched or sent anywhere. */
(function () {
  "use strict";
  const L = window.Lab, S = window.SecretsLab;

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
  const verdict = (id, cls, text) => { const el = $(id); el.className = "verdict " + cls; el.textContent = text; };
  const short = (b, n = 6) => L.hex(b.subarray(0, n)) + "…";

  // --------------------------------------------------------------------------- title: a toy scanner
  function hero() {
    const el = $("hero-in"), v = el.value;
    el.style.width = Math.min(30, Math.max(8, v.length + 1)) + "ch";
    const e = S.entropy(v), found = S.scan(v);
    const kinds = found.length ? found.map((f) => f.kind).join(", ") : "no known key format";
    $("hero-out").innerHTML =
      `${sp("k", "length: ")} ${v.length}<br>${sp("k", "entropy:")} ${e.toFixed(2)} bits per character<br>${sp("k", "match: ")} ${esc(kinds)}`;
    const t = v.trim().toLowerCase();
    let note;
    if (v === "") note = "# nothing to scan. An empty secret is the safest kind, and the least useful.";
    else if (v.includes("AKIAIOSFODNN7EXAMPLE")) note = "# AWS's own documentation example key. It has never opened anything: the best thing a key in a repo can do.";
    else if (t === "hunter2") note = "# hunter2: the old IRC joke says everyone else sees ******. Here you see all of it, and so would a scanner reading a repo.";
    else if (t === "password") note = "# the password 'password' isn't a secret, it's a hint. A scanner flags the assignment, not the word.";
    else if (t === "123456") note = "# six digits, almost no randomness. Entropy is a measure of the string's spread, not of how bad an idea it is.";
    else if (/correct horse battery staple/.test(t)) note = "# xkcd 936. A fine passphrase and a terrible API key: this scanner sees no pattern, which is why patterns aren't enough.";
    else if (/^gh[pousr]_/.test(t)) note = "# a token's prefix is there so scanners can find it. It's the friendliest part of a leak.";
    else if (found.some((f) => f.level === "bad")) note = "# a known key format: this is the kind a scanner catches at push time.";
    else if (found.length) note = "# worth a look, but a pattern can't tell a key from a build ID. People can.";
    else note = "# no known shape. Plain passwords and odd keys sail past scanners, which is why the best fix is to store fewer secrets in code.";
    $("hero-note").textContent = note;
  }

  // --------------------------------------------------------------------------- the usual suspects
  const LEAKS = [
    ["Git history", "Commits are permanent: every clone, fork and cached view keeps its own copy.", "Keep secrets out of the repository, scan at push, and if one lands, revoke it."],
    ["Container images", "ARG and ENV values, and files copied in earlier layers, stay in the image that gets pulled everywhere.", "Use build secret mounts, and inject runtime secrets from the platform."],
    ["CI logs and artifacts", "A debug flag, an <code>env</code> dump or a failing command that prints its URL puts the secret in a log many people can read. Masking works by matching known values, so a changed copy may slip past.", "Use the platform's secret store, don't echo, and prefer short-lived identity over stored keys."],
    ["Chat, tickets and wikis", "\"Can you send me the key?\" is convenient. GitGuardian found about 28% of incidents came entirely from outside repositories, such as Slack, Jira and Confluence.", "Share through a password or secret manager, and treat a pasted secret as leaked."],
    ["Screenshots and recordings", "A terminal showing an environment dump, or a console page with a key on it, in a bug report or a recorded call.", "Hide values by default, blur before sharing, and rotate if one slips through."],
    ["Front-end bundles and apps", "Anything shipped to a browser or a phone can be read by whoever runs it. Minifying isn't hiding.", "Keep secret keys on the server. More in <a href=\"../web-app-security/\">Web Application Security</a>."],
    ["Logs and error pages", "Request logs with keys in the query string, crash reports that include the environment, debug pages left switched on.", "Scrub what you log, never put secrets in URLs, and turn debug off in production."],
    ["Laptops, shell history and command lines", "<code>.env</code> files, shell history, cloud credentials files, and arguments other users can see in the process list. AI coding tools read project files too: GitGuardian found commits assisted by one such tool leaked at 3.2%, against 1.5% across all public commits (the report gives no cause).", "Fetch development secrets on demand, keep production ones off laptops, and pass secrets by file or stdin."],
  ];
  const lkSeen = new Set();
  function leaks() {
    $("lk-grid").innerHTML = LEAKS.map(([t], i) => `<li><button type="button" data-i="${i}" aria-pressed="false"><small>0${i + 1}</small><b>${esc(t)}</b></button></li>`).join("");
    $("lk-grid").addEventListener("click", (e) => {
      const b = e.target.closest("button[data-i]"); if (!b) return;
      const i = +b.dataset.i, [t, how, fix] = LEAKS[i]; lkSeen.add(i);
      document.querySelectorAll("#lk-grid button").forEach((x) => { x.setAttribute("aria-pressed", String(x === b)); if (lkSeen.has(+x.dataset.i)) x.classList.add("seen"); });
      $("lk-detail").innerHTML = `<b>${esc(t)}</b><span><i>How it happens</i> ${how}</span><span><i>Instead</i> ${fix}</span>`;
      $("lk-count").textContent = `${lkSeen.size} of ${LEAKS.length} places opened`;
      $("lk-note").textContent = lkSeen.size === LEAKS.length ? "# eight places, and not one needed a clever attacker: just a convenient copy." : "";
    });
  }

  // --------------------------------------------------------------------------- container image demo
  function image(method) {
    const m = S.imageBuild(method);
    $("im-file").textContent = m.dockerfile.join("\n");
    $("im-hist").innerHTML = m.history.map((l) => {
      const i = l.indexOf(S.SECRET);
      return i < 0 ? esc(l) : esc(l.slice(0, i)) + `<mark class="bad">${esc(S.SECRET)}</mark>` + esc(l.slice(i + S.SECRET.length));
    }).join("\n");
    verdict("im-verdict", m.leaks ? "bad" : "ok", m.leaks ? "✗ The secret is recoverable from the image" : "✓ The secret is not in the image");
    $("im-why").textContent = m.verdict;
    $("im-note").textContent = method === "mount" ? "# the only option where the secret is a guest: it leaves when the instruction ends." : method === "copy" ? "# rm in a later layer is a curtain, not a wall." : "";
  }

  // --------------------------------------------------------------------------- git history demo
  let repo, ghFlags;
  function gh() {
    repo = S.makeRepo(); ghFlags = { del: false, rewrite: false }; ghRender();
  }
  function ghRender() {
    const withKey = (c) => Object.values(c.files).some((v) => v.includes(S.SECRET));
    $("gh-log").innerHTML = repo.commits.slice().reverse().map((c) => {
      const flag = withKey(c) ? sp("bad", "  ← contains the key") : "";
      return `${sp("k", c.id)} ${esc(c.msg)}${flag}`;
    }).join("\n") + (repo.rewritten ? "\n" + sp("m", `(commit ${repo.oldId} no longer exists on the server)`) : "");
    const ks = S.KEY_STATE(repo);
    $("gh-key").className = "gh-key " + (ks.ok ? "ok" : "bad");
    $("gh-key").textContent = (ks.ok ? "✓ " : "✗ ") + ks.text;
    $("gh-where").innerHTML = S.repoWhere(repo).map((w) => `<li class="${w.found ? "bad" : "ok"}"><b>${w.found ? "✗" : "✓"}</b><span><i>${esc(w.where)}</i> ${esc(w.why)}</span></li>`).join("");
    const safe = repo.revoked;
    verdict("gh-verdict", safe ? "ok" : "bad", safe ? "Safe: the key is dead, so every copy is just text." : "Not safe: the key still works, and copies exist.");
    $("gh-note").textContent = safe && ghFlags.del && !ghFlags.rewrite ? "# a revoked key in public history is a museum piece: look, don't touch."
      : safe ? "# revoked first or last, it's the revoke that counts. Cleaning history is housekeeping."
      : ghFlags.rewrite ? "# tidy and slow: the key works for the whole rewrite."
      : ghFlags.del ? "# git remembers. It's the one colleague who never forgets anything." : "";
  }
  function ghInit() {
    click("gh-del", () => { if (!ghFlags.del && !repo.rewritten) { S.repoDeleteInNextCommit(repo); ghFlags.del = true; } ghRender(); });
    click("gh-rewrite", () => { if (!repo.rewritten) { S.repoRewrite(repo); ghFlags.rewrite = true; } ghRender(); });
    click("gh-revoke", () => { repo.revoked = true; ghRender(); });
    click("gh-reset", gh);
    gh();
  }

  // --------------------------------------------------------------------------- scanner demo
  const GH_FAKE = "ghp_" + "EXAMPLE".repeat(5).slice(0, 36);
  const AWS_FAKE = "AKIA" + "7QXDEMOONLY5FAKE";
  const SN = {
    leaky: ["+++ b/deploy/config.py", `+AWS_ACCESS_KEY_ID = "${AWS_FAKE}"`, '+EXAMPLE_KEY_ID = "AKIAIOSFODNN7EXAMPLE"', `+GITHUB_TOKEN = "${GH_FAKE}"`,
      '+DATABASE_URL = "postgres://shop:Tr0ub4dor@db.internal:5432/shop"', '+ADMIN_PASSWORD = "hunter2"', "+API_BASE = \"https://api.example.com\""].join("\n"),
    noise: ["commit 3f786850e387550fdab836ed7e6dc881de23001b", '"integrity": "sha512-kJ8dQ2vXm9Lw3RtYp7NcB4hZ6SaE1uGfT5oPqWxVyIeD0nMlCbAsHrKjUgFiO+9aZ"',
      '"build_id": "7f3a9c1e-52bd-4e08-9a64-1c0d8b2e5f77"', "password = os.environ[\"DB_PASSWORD\"]", "password = \"changeme\""].join("\n"),
    miss: ['const greeting = "Summer2026!Rocks";   // actually the database password', "conn = connect(host, \"s3cr3t-Pa55\")", "data:", "  db: c3VwZXJzZWNyZXQ=   # base64 of a password"].join("\n"),
  };
  let snScanned = false;
  function snRender(scanned) {
    const text = $("sn-in").value, found = scanned ? S.scan(text) : [];
    let html = "", at = 0;
    for (const f of found) { html += esc(text.slice(at, f.start)) + `<mark class="${f.level}">${esc(text.slice(f.start, f.end))}</mark>`; at = f.end; }
    html += esc(text.slice(at));
    $("sn-out").innerHTML = html;
    $("sn-count").textContent = scanned ? `${found.length} finding${found.length === 1 ? "" : "s"}` : "";
    $("sn-list").innerHTML = !scanned ? '<li class="m">Press "Scan".</li>' : found.length ? found.map((f) => {
      const t = f.text.length > 26 ? f.text.slice(0, 24) + "…" : f.text;
      return `<li class="${f.level === "bad" ? "bad" : f.level === "ok" ? "ok" : "y"}"><b>${f.level === "bad" ? "✗" : f.level === "ok" ? "✓" : "!"}</b><span><code>${esc(t)}</code> <i>${esc(f.kind)}.</i> ${esc(f.why)}</span></li>`;
    }).join("") : '<li class="m">Nothing found. That is not the same as nothing there.</li>';
    snScanned = scanned;
  }
  function snNote(p) {
    $("sn-note").textContent = !snScanned ? "" : p === "noise" ? "# a commit ID and a package integrity hash look random: entropy can't tell a hash from a key."
      : p === "miss" ? "# nothing found, and two real passwords sit right there. A scanner reads shapes, not meaning." : p === "leaky" ? "# four kinds of rule found five things. The example key got a pass, because it's AWS's own." : "";
  }
  let snPreset = "leaky";
  function sn() {
    segPick("sn-presets", "data-p", (p) => { snPreset = p; $("sn-in").value = SN[p]; snRender(false); snNote(p); });
    $("sn-in").value = SN.leaky; snRender(false);
    click("sn-scan", () => { snRender(true); snNote(snPreset); });
    $("sn-in").addEventListener("input", () => { snRender(false); $("sn-note").textContent = ""; });
  }

  // --------------------------------------------------------------------------- the ladder: threats against rungs
  const THREATS = [["repo", "A copy of the repository leaks"], ["logs", "A log or crash report captures it"], ["shell", "Someone gets a shell on the server"],
    ["backup", "A backup or disk image is stolen"], ["code", "The app's own code is compromised"], ["audit", "You need to know who read it, and when"]];
  const RUNGS = [["file", "Config file", "in the repo or on disk"], ["env", "Environment variable", "injected at deploy"], ["mgr", "Secret manager", "fetched at run time"],
    ["kms", "Cloud key service", "key never leaves; you send data to it"], ["hsm", "HSM", "hardware holds the key"]];
  const M = {
    repo: [["n", "It's in the repo, so it leaks with it."], ["y", "Not in the code: only as safe as the deploy config."], ["y", "Lives outside the repo."], ["y", "The key was never in the repo."], ["y", "Same."]],
    logs: [["p", "Only if the app prints it."], ["n", "Debug pages, crash reporters and environment dumps often capture it."], ["p", "Once fetched it's in memory like any value: don't log it."], ["y", "The app never holds the master key."], ["y", "The key never reaches the app."]],
    shell: [["n", "Readable by the app's user."], ["n", "Readable from the process's environment."], ["p", "They can fetch what the app can, as the app, and it's logged."], ["p", "They can use the key while on the box, but can't take it away."], ["p", "Same: use, not theft."]],
    backup: [["n", "It's in the backup."], ["p", "Usually not in a data backup, but may be in config backups or images."], ["y", "Stored elsewhere."], ["y", "Encrypted data is useless without the service."], ["y", "Same, and the key can't be copied out."]],
    code: [["n", "Code that can read files reads it."], ["n", "Code can read its own environment."], ["n", "The app is allowed to fetch it, so compromised code is too."], ["p", "It can use the key while it has access; revoke the role to stop it."], ["p", "Same."]],
    audit: [["n", "Nothing records a file read."], ["n", "Nothing records a read."], ["y", "Each fetch can be logged (check retention)."], ["y", "Each use can be logged."], ["y", "Each use can be logged."]],
  };
  const ldSeen = new Set();
  function ladder(tid) {
    ldSeen.add(tid);
    const row = M[tid], mark = { y: "✓", p: "~", n: "✗" }, cls = { y: "ok", p: "y", n: "bad" };
    $("ld-grid").innerHTML = RUNGS.map(([, name, sub], i) => `<div class="ld-rung ${cls[row[i][0]]}"><small>RUNG ${i + 1}</small><b>${esc(name)}</b><em>${esc(sub)}</em><strong>${mark[row[i][0]]}</strong><span>${esc(row[i][1])}</span></div>`).join("");
    $("ld-note").textContent = ldSeen.size === THREATS.length ? "# six threats, and the best answer each time was fewer secrets, held further from the app, with a log." : "";
  }

  // --------------------------------------------------------------------------- envelope encryption
  let masters, recs, evCount, evNum;
  function evStart() {
    masters = [S.mkMaster(1)]; recs = []; evNum = 7;
    for (const [c, t] of [["user:7", "card ending 4242"], ["user:8", "card ending 1881"]]) recs.push({ ctx: c, rec: S.envEncrypt(masters[0], c, t) });
    evCount = null; $("ev-note").textContent = ""; evRender();
  }
  function evRender() {
    const latest = masters[masters.length - 1];
    $("ev-keys").innerHTML = `${sp("k", "Key service holds:")} ${masters.map((m) => m.id + (m === latest ? " (current)" : "")).map(esc).join(", ")}`;
    $("ev-table").innerHTML = "<thead><tr><th>Context</th><th>Master key</th><th>Wrapped data key</th><th>Ciphertext</th><th>Opens?</th></tr></thead><tbody>" + recs.map(({ rec }) => {
      let res;
      try { res = `<span class="ok">✓ ${esc(S.envDecrypt(masters, rec, rec.ctx))}</span>`; }
      catch (e) { res = `<span class="bad">✗ ${esc(e.message.replace(/^TAG MISMATCH: /, "").replace(/^no key with id /, "no key "))}</span>`; }
      return `<tr><td><code>${esc(rec.ctx)}</code></td><td>${esc(rec.kid)}</td><td><code>${short(rec.wct)}</code></td><td><code>${short(rec.ct)}</code></td><td>${res}</td></tr>`;
    }).join("") + "</tbody>";
    const stale = recs.filter((r) => r.rec.kid !== latest.id).length;
    if (evCount) verdict("ev-verdict", "ok", evCount);
    else verdict("ev-verdict", stale ? "y" : "ok", stale ? `${stale} record${stale > 1 ? "s are" : " is"} still wrapped by an older master key.` : "Every record is wrapped by the current master key.");
  }
  function evInit() {
    click("ev-add", () => {
      const v = $("ev-in").value; if (!v) { $("ev-note").textContent = "# an empty record still gets a tag, but you gave it nothing to protect."; return; }
      const c = "user:" + (++evNum + 1); evCount = null;
      recs.push({ ctx: c, rec: S.envEncrypt(masters[masters.length - 1], c, v) });
      $("ev-note").textContent = v.trim().toLowerCase() === "hello" ? "# hello, wrapped. Not exactly a secret, but nicely packaged." : ""; evRender();
    });
    click("ev-new", () => { masters.push(S.mkMaster(masters.length + 1)); evCount = null; $("ev-note").textContent = "# new records use the new key; old ones still point at the old one. Retire it now and they're gone."; evRender(); });
    click("ev-rewrap", () => {
      const latest = masters[masters.length - 1]; let n = 0;
      recs.forEach((r) => { if (r.rec.kid !== latest.id) { const old = masters.find((m) => m.id === r.rec.kid); if (old) { r.rec = S.envRewrap(old, latest, r.rec); n++; } } });
      evCount = `Rewrapped ${n} data key${n === 1 ? "" : "s"}. Bytes of data re-encrypted: 0.`;
      $("ev-note").textContent = n ? "# the wrapped keys changed; the ciphertext didn't. That's the whole saving." : "# nothing to rewrap: everything already uses the current key."; evRender();
    });
    click("ev-retire", () => { masters = masters.slice(-1); evCount = null; $("ev-note").textContent = masters.length ? "# retired. Anything still wrapped by an old key just became unreadable." : ""; evRender(); });
    click("ev-tamper", () => {
      const r = recs[0]; if (!r) return; r.rec = Object.assign({}, r.rec, { ctx: r.rec.ctx === "user:7" ? "user:8" : "user:7" }); evCount = null;
      $("ev-note").textContent = "# the label is authenticated: move this record to another user's context and it refuses to open."; evRender();
    });
    click("ev-reset", evStart);
    evStart();
  }

  // --------------------------------------------------------------------------- a tiny key ceremony: Shamir's secret sharing
  let hsKey, hsShares;
  function hsStart() {
    const kb = L.randBytes(16); hsKey = L.toBig(kb); hsShares = S.shamirSplit(hsKey, 3, 5);
    $("hs-key").innerHTML = `${sp("k", "master key:")} ${esc(L.hex(kb))}`;
    $("hs-shares").innerHTML = hsShares.map((s) => `<label class="hs-share"><input type="checkbox" data-x="${s.x}"><span>share ${s.x}<code>${esc(s.y.toString(16).padStart(64, "0").slice(0, 10))}…</code></span></label>`).join("");
    hsRender();
  }
  function hsRender() {
    const picked = Array.from(document.querySelectorAll("#hs-shares input:checked")).map((i) => hsShares[+i.dataset.x - 1]);
    let note = "";
    if (!picked.length) { verdict("hs-verdict", "y", "Pick some shares to combine."); }
    else {
      const rec = S.shamirCombine(picked), hex = rec.toString(16).padStart(32, "0").slice(-32);
      const ok = rec === hsKey;
      if (picked.length >= 3) verdict("hs-verdict", ok ? "ok" : "bad", ok ? `✓ ${picked.length} shares recover the key: ${hex}` : "✗ these shares don't recover the key");
      else verdict("hs-verdict", "bad", `✗ ${picked.length} share${picked.length > 1 ? "s" : ""} give ${rec.toString(16).padStart(32, "0").slice(0, 32)}: not the key`);
      if (picked.length === 2) note = "# two of five: every possible key is still equally likely. Not 'close', not 'almost': nothing.";
      else if (picked.length === 5) note = "# all five, which rather defeats a committee, but at least it's thorough.";
      else if (picked.length === 3 && ok) note = "# three of five: a heist film, but for good, and with minutes taken.";
    }
    $("hs-note").textContent = note;
  }
  function hsInit() {
    $("hs-shares").addEventListener("change", hsRender);
    click("hs-new", hsStart);
    hsStart();
  }

  // --------------------------------------------------------------------------- short-lived credentials
  const NOW = 1000;
  let idp, TOKS, tkJob = "main", tkPol = "branch", tkSeen = new Set();
  function tkInit() {
    idp = S.makeIdp();
    const claims = (sub, exp) => ({ iss: "https://token.actions.example", aud: "sts.cloud.example", sub, exp: exp || NOW + 300 });
    const evil = S.mintToken(idp, claims("repo:evil-org/fork:ref:refs/heads/main"));
    TOKS = {
      main: S.mintToken(idp, claims("repo:example-org/shop:ref:refs/heads/main")),
      env: S.mintToken(idp, claims("repo:example-org/shop:environment:production")),
      pr: S.mintToken(idp, claims("repo:example-org/shop:pull_request")),
      evil, forged: S.tamper(evil, { sub: "repo:example-org/shop:ref:refs/heads/main" }),
      old: S.mintToken(idp, claims("repo:example-org/shop:ref:refs/heads/main", NOW - 100)),
    };
    segPick("tk-job", "data-j", (j) => { tkJob = j; tkRender(); });
    segPick("tk-policy", "data-p", (p) => { tkPol = p; tkRender(); });
    tkRender();
  }
  function tkRender() {
    const t = TOKS[tkJob], c = t.claims;
    $("tk-token").innerHTML = [["iss", c.iss], ["aud", c.aud], ["sub", c.sub], ["exp", c.exp > NOW ? "in " + Math.round((c.exp - NOW) / 60) + " minutes" : "already past"]].map(([k, v]) => `${sp("k", k + ":")} ${esc(v)}`).join("\n") +
      `\n${sp("k", "sig:")} ${esc("ES256 " + L.hex(L.fromBig(t.sig[0], 32)).slice(0, 16) + "…")}`;
    $("tk-rule").innerHTML = `${sp("k", "Trust rule:")} ${esc(S.POLICIES[tkPol].text)}`;
    const r = S.cloudCheck(idp.Q, t, tkPol, NOW);
    verdict("tk-verdict", r.allow ? "ok" : "bad", r.allow ? "✓ Allowed: temporary credentials issued" : "✗ Refused");
    $("tk-why").textContent = r.why;
    let note = "";
    if (tkJob === "evil" && tkPol === "none") note = "# the open door: with no condition, a stranger's repository gets in. GitHub's docs say you must define at least one condition.";
    else if (tkJob === "forged") note = "# the signature covers the original claims: change one letter and the check fails before the policy even looks.";
    else if (tkJob === "evil" && r.allow === false) note = "# genuine, signed, and still refused: a valid identity isn't the same as the right identity.";
    else if (tkJob === "old") note = "# expired tokens are the point: a stolen one is a pumpkin by tea time.";
    $("tk-note").textContent = note;
  }

  // --------------------------------------------------------------------------- rotation with two keys
  let ring, rtBad;
  function rtStart() { ring = S.makeRing(); rtBad = false; rtRender(""); }
  function rtRender(note) {
    $("rt-ring").innerHTML = `${sp("k", "Signing with:")} ${esc(ring.signing)}<br>${sp("k", "Verifiers trust:")} ${esc(Array.from(ring.trusted).sort().join(", "))}<br>${sp("k", "Clock:")} +${ring.clock} min`;
    let bad = 0, good = 0;
    $("rt-table").innerHTML = "<thead><tr><th>Token</th><th>Signed with</th><th>Expires</th><th>Verifies now?</th></tr></thead><tbody>" + (ring.tokens.length ? ring.tokens.map((t) => {
      const r = S.ringVerify(ring, t); if (r.ok) good++; else if (r.why !== "expired") { bad++; rtBad = true; }
      return `<tr><td>#${t.id}</td><td>${esc(t.kid)}</td><td>+${t.exp} min</td><td class="${r.ok ? "ok" : r.why === "expired" ? "m" : "bad"}">${r.ok ? "✓ " : r.why === "expired" ? "– " : "✗ "}${esc(r.why)}</td></tr>`;
    }).join("") : '<tr><td colspan="4" class="m">Issue a token to begin.</td></tr>') + "</tbody>";
    if (!ring.tokens.length) verdict("rt-verdict", "y", "No tokens yet.");
    else if (bad) verdict("rt-verdict", "bad", `${bad} token${bad > 1 ? "s" : ""} that should work will be rejected: an outage.`);
    else verdict("rt-verdict", "ok", "Everything that's still in date verifies.");
    const done = !ring.trusted.has("key-A") && ring.signing === "key-B" && !rtBad && ring.tokens.some((t) => t.kid === "key-A") && ring.tokens.some((t) => t.kid === "key-B");
    $("rt-note").textContent = bad && ring.tokens.some((t) => t.kid === "key-A" && !ring.trusted.has("key-A")) ? "# nothing's wrong with the token: the verifier just doesn't know who signed it. Order is the whole trick."
      : bad ? "# the signer moved to B before the verifiers knew B. Publish first, switch second." : done ? "# four steps, zero failed requests. Boring, which is exactly the goal." : note;
  }
  function rtInit() {
    click("rt-1", () => { if (!ring.keys["key-B"]) ring.keys["key-B"] = S.newKey("key-B"); ring.trusted.add("key-B"); rtRender("# B is published: verifiers accept A or B."); });
    click("rt-2", () => { if (!ring.keys["key-B"]) ring.keys["key-B"] = S.newKey("key-B"); ring.signing = "key-B"; rtRender("# new tokens now name key-B."); });
    click("rt-3", () => { ring.clock += 60; rtRender("# an hour passes: every token signed with A has now expired."); });
    click("rt-4", () => { ring.trusted.delete("key-A"); rtRender("# key A is retired."); });
    click("rt-issue", () => { S.ringIssue(ring, 60); rtRender(""); });
    click("rt-wait", () => { ring.clock += 15; rtRender(""); });
    click("rt-reset", rtStart);
    rtStart();
  }

  // --------------------------------------------------------------------------- tabletop
  const TT = [
    { q: "14:02. A scanner emails you: a cloud key that can read the customer-exports bucket was committed to a public repository at 09:40. What's your first move?",
      opts: [
        ["Delete the file and push a fix", "bad", "Done in three minutes, and it feels good. But the key is still in history, in clones and perhaps in someone's scraper, and it still works.", { line: "14:05  File deleted and pushed. The key still works.", revoke: null }],
        ["Revoke the key, deploy a replacement", "good", "Right. Create the replacement, deploy it, revoke the old one: minutes. GitHub's own guide says to revoke or rotate first.", { line: "14:20  Replacement deployed, old key revoked.", revoke: "14:20" }],
        ["Rewrite history and force-push", "bad", "Tidy, and slow, and the key works the whole time. After rotation a rewrite may not even be needed.", { line: "14:45  History rewritten. The key still works.", revoke: null }],
        ["Wait for the 16:00 security meeting", "bad", "Two more hours of a working key. The meeting is where you tell people what you did, not where you start.", { line: "16:00  Meeting. Key finally revoked at 16:10.", revoke: "16:10", egg: "# meetings are a lovely way to spend a working key's afternoon." }],
      ] },
    { q: "Next: the usage logs. Which period do you read?",
      opts: [
        ["The last hour", "bad", "That's since you noticed. The key was public from 09:40, so you miss almost everything. You find nothing and relax; reads from 11:12 sit unseen.", { line: "14:40  Logs checked for the last hour: nothing seen." }],
        ["From 09:40 until now", "good", "Right: start at the exposure, not the alert. In this scenario you find reads of the exports bucket at 11:12 from an address you don't recognise. It's a data incident now, not only a key incident.", { line: "15:05  Logs from 09:40: reads at 11:12 from an unknown address." }],
        ["Skip it: no alarm went off", "bad", "No alarm only means nothing was set up to ring. Public code is watched by automated scanners, so assume it was seen.", { line: "14:40  Logs not checked." }],
      ] },
    { q: "Last: how did a key get into a commit at all, and what do you do about that?",
      opts: [
        ["Remind everyone to be careful", "bad", "A reminder fades by Friday. Fix the system, so the next tired person can't do the same thing.", { line: "Next week  Reminder email sent." }],
        ["Add push protection, move the key into the manager, give the app a role", "good", "Right: block it at the push, remove the stored key, and use an identity instead. Then the same mistake is harder to make and cheaper if it happens.", { line: "Next week  Push protection on; app uses a role; no stored key." }],
        ["Find out who did it", "bad", "Blame is cheap and teaches people to hide mistakes. Ask what let one commit expose a bucket.", { line: "Next week  A name goes in the report.", egg: "# blame teaches hiding; the fix belongs to the system that allowed it." }],
      ] },
  ];
  let tt;
  function ttStart() { tt = { round: 0, picks: [], lines: ["09:40  Key committed to a public repo.", "14:02  Scanner alert arrives."], revoke: undefined, locked: false }; ttRender(); }
  function ttRender() {
    $("tt-time").innerHTML = tt.lines.map((l) => `<li>${esc(l)}</li>`).join("");
    const r = TT[tt.round];
    if (!r) {
      $("tt-scene").textContent = "Debrief";
      $("tt-opts").innerHTML = ""; $("tt-fb").textContent = "";
      const good = tt.picks.filter((p) => p === "good").length;
      $("tt-verdict").hidden = false;
      verdict("tt-verdict", good === 3 ? "ok" : good ? "y" : "bad", `${good} of 3 good calls. ${tt.revoke ? "The key was dead at " + tt.revoke + "." : "The key is still working."}`);
      $("tt-note").textContent = good === 3 ? "# revoke, read from the exposure, fix the system. The order matters more than the speed of any one step." : tt.revoke ? "" : "# round one was the one that mattered: nothing else helps while the key works.";
      return;
    }
    $("tt-scene").textContent = r.q;
    $("tt-opts").innerHTML = r.opts.map((o, i) => `<button type="button" class="btn btn-ghost btn-sm tt-opt" data-i="${i}">${esc(o[0])}</button>`).join("");
    if (!tt.locked) { $("tt-fb").textContent = ""; $("tt-fb").className = "tt-fb"; }
    if (!tt.picks.length) { $("tt-verdict").className = "verdict"; $("tt-verdict").textContent = ""; $("tt-note").textContent = ""; }
  }
  function ttInit() {
    $("tt-opts").addEventListener("click", (e) => {
      const b = e.target.closest("button"); if (!b) return;
      if (b.id === "tt-next") { tt.round++; tt.locked = false; ttRender(); return; }
      const o = TT[tt.round].opts[+b.dataset.i]; if (!o) return;
      tt.picks.push(o[1]); tt.lines.push(o[3].line);
      if (o[3].revoke !== undefined) tt.revoke = o[3].revoke;
      tt.locked = true;
      $("tt-fb").className = "tt-fb " + (o[1] === "good" ? "ok" : "bad");
      $("tt-fb").textContent = (o[1] === "good" ? "✓ " : "✗ ") + o[2];
      $("tt-note").textContent = o[3].egg || "";
      $("tt-time").innerHTML = tt.lines.map((l) => `<li>${esc(l)}</li>`).join("");
      $("tt-opts").innerHTML = `<button type="button" class="btn btn-sm" id="tt-next">${tt.round === TT.length - 1 ? "Debrief" : "Next round"}</button>`;
    });
    click("tt-reset", ttStart);
    ttStart();
  }

  // --------------------------------------------------------------------------- review checklist
  const RV_KEY = "secrets-review";
  function review() {
    const boxes = Array.from(document.querySelectorAll("#rv-list input[type=checkbox]"));
    let saved = {};
    try { saved = JSON.parse(store(RV_KEY) || "{}"); } catch (e) {}
    boxes.forEach((b) => { b.checked = !!saved[b.dataset.k]; });
    const update = () => {
      const done = boxes.filter((b) => b.checked).length;
      store(RV_KEY, JSON.stringify(Object.fromEntries(boxes.map((b) => [b.dataset.k, b.checked]))));
      const n = $("rv-note"); n.className = "comment";
      if (done === boxes.length) { n.textContent = "# 12 of 12. Now rotate one secret for real, on a quiet afternoon, to prove it."; n.classList.add("ok"); }
      else if (!done) n.textContent = "# tick what your team does today. Each gap is a ticket, not a failure. Saved in this browser only.";
      else n.textContent = `# ${done} of ${boxes.length}. Pick the unticked box that would have shortened your last incident, and fix that first.`;
    };
    boxes.forEach((b) => b.addEventListener("change", update));
    update();
  }

  // --------------------------------------------------------------------------- easter egg: console
  function consoleHint() {
    console.log("%cSecrets Management", "font: 700 24px monospace; color: #ff2e88; text-shadow: 0 0 8px #ff2e88");
    console.log("%cYou opened the console, where many secrets end up by accident: console.log(apiKey) is a classic. Everything here is invented; try the Git demo's three fixes in different orders.", "font: 14px monospace; color: #00f0ff");
  }

  function start() {
    consoleHint();
    $("hero-in").addEventListener("input", hero); hero();
    leaks();
    segPick("im-pick", "data-m", image); image("arg");
    ghInit();
    sn();
    $("ld-pick").innerHTML = THREATS.map(([k, t], i) => `<button type="button" data-t="${k}" aria-pressed="${i === 0}">${esc(t)}</button>`).join("");
    segPick("ld-pick", "data-t", ladder); $("ld-q").textContent = "Rule of thumb, not a ranking: ✓ helps a lot · ~ partly · ✗ not really."; ladder("repo"); ldSeen.clear();
    evInit();
    hsInit();
    tkInit();
    rtInit();
    ttInit();
    $("hb-note").textContent = "# the best secret is the one you never had to store.";
    review();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
})();
