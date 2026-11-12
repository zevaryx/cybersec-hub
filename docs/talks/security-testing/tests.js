/* tests.js - the logic behind the demos in "Security Testing in Your Workflow" (window.TestLab; also loads in Node).
   Everything here is a small teaching model: a tool-coverage table, a toy static scanner, a mock API with a test suite,
   filename sanitisers, a pipeline planner, a suppression-file linter, six invented findings and a findings-metrics simulation.
   Nothing is fetched or sent anywhere, and none of it is a real scanner. */
(function (root) {
  "use strict";

  // ------------------------------------------------------------------ 1. which tool catches what (a rule of thumb, not a measurement)
  const TOOLS = [
    { id: "sast", label: "Static analysis (SAST)" },
    { id: "dast", label: "Dynamic scan (DAST)" },
    { id: "dep", label: "Dependency scan" },
    { id: "sec", label: "Secret scan" },
    { id: "fuzz", label: "Fuzzing" },
    { id: "unit", label: "Your own tests" },
    { id: "review", label: "Human review" },
  ];
  // ratings per tool, in TOOLS order: 2 usually, 1 sometimes, 0 rarely
  const BUGS = [
    { id: "inj", label: "SQL injection in a search box", r: [2, 1, 0, 0, 1, 1, 2],
      lesson: "Static analysis follows data from the request to the query. A running scanner has to find the page and notice the effect. Neither is certain, so a parameterised query is the real fix." },
    { id: "secret", label: "A leaked API key in the repository", r: [1, 0, 0, 2, 0, 0, 1],
      lesson: "Matching known token formats beats general code analysis. Push protection stops the key before it is in history at all, which is far cheaper than rotating it afterwards." },
    { id: "dep", label: "A library with a known vulnerability", r: [0, 1, 2, 0, 0, 0, 0],
      lesson: "Only a tool that knows your dependency list and a vulnerability database can see this. It usually can't tell whether your code calls the broken part, which is why triage matters." },
    { id: "authz", label: "A missing authorization check", r: [0, 1, 0, 0, 0, 2, 2],
      lesson: "Nothing in the code looks wrong; something is missing. Generic rules don't know who should be allowed to do what. Your own tests and a reviewer do." },
    { id: "crash", label: "A parser that crashes on odd input", r: [1, 1, 0, 0, 2, 1, 1],
      lesson: "Fuzzing exists for this: it throws huge numbers of odd inputs at a function and watches for crashes and hangs." },
    { id: "config", label: "Debug mode left on, security headers missing", r: [1, 2, 0, 0, 0, 0, 1],
      lesson: "A scan of the running app sees what the browser sees: headers, cookies, error pages. (Scanners for infrastructure-as-code files cover the config before it ships.)" },
    { id: "logic", label: "A coupon that can be used twice", r: [0, 0, 0, 0, 0, 2, 2],
      lesson: "No tool knows your business rules. A test that states the rule, and a design review that asks 'what if I do this twice?', are the defences." },
    { id: "crypto", label: "Passwords hashed with MD5, or AES in ECB mode", r: [2, 0, 0, 0, 0, 1, 2],
      lesson: "These are recognisable patterns in code, so static analysis is good at them. It can't tell you the design is wrong, only that a weak primitive is in use." },
  ];
  const RATING = ["rarely", "sometimes", "usually"];
  function toolsFor(bugId) {
    const b = BUGS.find((x) => x.id === bugId); if (!b) return null;
    const out = { usually: [], sometimes: [], rarely: [] };
    TOOLS.forEach((t, i) => out[RATING[b.r[i]]].push(t.label));
    return { bug: b, groups: out };
  }

  // ------------------------------------------------------------------ 2. a toy static scanner (pattern mode vs taint mode)
  const SNIPPETS = [
    { id: "direct", label: "A: query built right here", truth: "vulnerable",
      src: 'def search(request):\n    term = request.args["q"]\n    sql = "SELECT * FROM items WHERE name = \'" + term + "\'"\n    return db.execute(sql)' },
    { id: "helper", label: "B: built in another file", truth: "vulnerable",
      src: 'def search(request):\n    term = request.args["q"]\n    return repo.find_items(term)   # repo.py builds the query with +' },
    { id: "param", label: "C: parameterised", truth: "safe",
      src: 'def search(request):\n    term = request.args["q"]\n    return db.execute("SELECT * FROM items WHERE name = ?", (term,))' },
    { id: "allow", label: "D: table name from an allowlist", truth: "safe",
      src: 'def report(request):\n    table = pick_from(["sales", "returns"], request.args["t"])\n    sql = f"SELECT * FROM {table}"\n    return db.execute(sql)' },
    { id: "authz", label: "E: anyone can read any invoice", truth: "vulnerable",
      src: 'def get_invoice(request, invoice_id):\n    return db.execute("SELECT * FROM invoices WHERE id = ?", (invoice_id,))' },
  ];
  const SANITIZERS = /^(pick_from|int|escape|quote)\(/;
  const BUILDS_STRING = /(\+|%\s*[(\w]|\bf["']|\.format\()/;
  // the first argument of the first execute( call on a line
  function firstArg(line) {
    const i = line.indexOf("execute(");
    if (i < 0) return null;
    let depth = 0, q = null, out = "";
    for (let k = i + 8; k < line.length; k++) {
      const c = line[k];
      if (q) { out += c; if (c === q && line[k - 1] !== "\\") q = null; continue; }
      if (c === '"' || c === "'") { q = c; out += c; continue; }
      if (c === "(" || c === "[" || c === "{") depth++;
      if (c === ")" || c === "]" || c === "}") { if (depth === 0) break; depth--; }
      if (c === "," && depth === 0) break;
      out += c;
    }
    return out.trim();
  }
  // mode "pattern": looks at how the query text is built. mode "taint": also asks whether request data can reach it.
  function scan(src, mode) {
    const lines = src.split("\n"), built = new Set(), tainted = new Set(), findings = [];
    const mentions = (expr, set) => { for (const v of set) if (new RegExp("\\b" + v + "\\b").test(expr)) return true; return false; };
    lines.forEach((line, i) => {
      const as = /^\s*(\w+)\s*=\s*(.+)$/.exec(line);
      if (as) {
        const name = as[1], expr = as[2].split("#")[0].trim();
        const sanitized = SANITIZERS.test(expr);
        if (BUILDS_STRING.test(expr)) built.add(name);
        if (!sanitized && (/\brequest\./.test(expr) || mentions(expr, tainted))) tainted.add(name);
      }
      const arg = firstArg(line);
      if (arg === null) return;
      const isVar = /^\w+$/.test(arg);
      const builds = BUILDS_STRING.test(arg) || (isVar && built.has(arg));
      const reaches = /\brequest\./.test(arg) || (isVar && tainted.has(arg)) || (!isVar && mentions(arg, tainted));
      if (mode === "pattern" && builds) findings.push({ line: i + 1, rule: "sql-built-from-string", text: "query text is built with string formatting" });
      if (mode === "taint" && builds && reaches) findings.push({ line: i + 1, rule: "sql-injection", text: "request data reaches a query built from a string" });
    });
    return findings;
  }
  function judge(snippet, findings) {
    const flagged = findings.length > 0;
    if (snippet.truth === "vulnerable") return flagged ? "caught" : "missed";
    return flagged ? "false alarm" : "quiet (correctly)";
  }

  // ------------------------------------------------------------------ 3. a mock invoice API and its authorization tests
  const USERS = { alice: { id: "alice", role: "user", tenant: "t1" }, bob: { id: "bob", role: "user", tenant: "t1" }, admin1: { id: "admin1", role: "admin", tenant: "t1" } };
  const BUG_OPTIONS = [
    { id: "none", label: "No bug", about: "Every check is in place." },
    { id: "read-no-owner", label: "Read doesn't check the owner", about: "GET /invoices/{id} only checks that you are signed in." },
    { id: "delete-no-owner", label: "Delete doesn't check the owner", about: "The read path was fixed; DELETE was missed." },
    { id: "admin-cross-tenant", label: "Admins reach other tenants", about: "The admin branch forgets to compare tenants." },
    { id: "list-all", label: "The list returns everyone's invoices", about: "GET /invoices has no filter on the owner." },
    { id: "role-from-header", label: "Trusts a role sent by the client", about: "The role comes from a request header when one is present." },
  ];
  function makeApi(bug) {
    let inv;
    const reset = () => { inv = { 1: { id: 1, owner: "alice", tenant: "t1" }, 2: { id: 2, owner: "bob", tenant: "t1" }, 3: { id: 3, owner: "carol", tenant: "t2" } }; };
    reset();
    const roleOf = (user, hdr) => (bug === "role-from-header" && hdr && hdr.role ? hdr.role : user.role);
    function allowed(user, rec, op, hdr) {
      const role = roleOf(user, hdr);
      if (role === "admin") return bug === "admin-cross-tenant" ? true : rec.tenant === user.tenant;
      if (op === "read") return bug === "read-no-owner" ? true : rec.owner === user.id;
      return bug === "delete-no-owner" ? true : rec.owner === user.id;
    }
    return {
      reset,
      get(user, id, hdr) {
        if (!user) return { status: 401 };
        const rec = inv[id]; if (!rec) return { status: 404 };
        return allowed(user, rec, "read", hdr) ? { status: 200, body: rec } : { status: 403 };
      },
      del(user, id, hdr) {
        if (!user) return { status: 401 };
        const rec = inv[id]; if (!rec) return { status: 404 };
        if (!allowed(user, rec, "delete", hdr)) return { status: 403 };
        delete inv[id]; return { status: 200 };
      },
      adminReport(user, hdr) {
        if (!user) return { status: 401 };
        return roleOf(user, hdr) === "admin" ? { status: 200 } : { status: 403 };
      },
      list(user) {
        if (!user) return { status: 401 };
        const all = Object.values(inv);
        return { status: 200, body: bug === "list-all" ? all : all.filter((r) => r.owner === user.id) };
      },
    };
  }
  const TESTS = [
    { id: "t1", name: "test_owner_can_read_own_invoice", run: (a) => a.get(USERS.alice, 1).status === 200,
      src: 'r = api.get(alice, invoice_id=1)\nassert r.status == 200' },
    { id: "t2", name: "test_other_user_cannot_read_invoice", run: (a) => a.get(USERS.bob, 1).status === 403,
      src: 'r = api.get(bob, invoice_id=1)     # alice\'s invoice\nassert r.status == 403' },
    { id: "t3", name: "test_anonymous_gets_401", run: (a) => a.get(null, 1).status === 401,
      src: 'r = api.get(None, invoice_id=1)\nassert r.status == 401' },
    { id: "t4", name: "test_other_user_cannot_delete_invoice", run: (a) => a.del(USERS.bob, 1).status === 403 && a.get(USERS.alice, 1).status === 200,
      src: 'r = api.delete(bob, invoice_id=1)\nassert r.status == 403\nassert api.get(alice, 1).status == 200   # still there' },
    { id: "t5", name: "test_owner_can_delete_own_invoice", run: (a) => a.del(USERS.alice, 1).status === 200,
      src: 'r = api.delete(alice, invoice_id=1)\nassert r.status == 200' },
    { id: "t6", name: "test_admin_can_read_invoice_in_own_tenant", run: (a) => a.get(USERS.admin1, 2).status === 200,
      src: 'r = api.get(admin1, invoice_id=2)   # bob\'s, same tenant\nassert r.status == 200' },
    { id: "t7", name: "test_admin_cannot_read_other_tenants_invoice", run: (a) => a.get(USERS.admin1, 3).status === 403,
      src: 'r = api.get(admin1, invoice_id=3)   # carol\'s, tenant t2\nassert r.status == 403' },
    { id: "t8", name: "test_list_returns_only_own_invoices", run: (a) => { const r = a.list(USERS.alice); return r.status === 200 && r.body.length === 1 && r.body[0].owner === "alice"; },
      src: 'r = api.list(alice)\nassert [i.owner for i in r.body] == ["alice"]' },
    { id: "t9", name: "test_client_cannot_claim_admin_role", run: (a) => a.adminReport(USERS.bob, { role: "admin" }).status === 403,
      src: 'r = api.get("/admin/report", as_user=bob, headers={"role": "admin"})\nassert r.status == 403   # the server decides who is an admin' },
  ];
  // run the suite against a bug; enabled is a set (or array) of test ids to include (default: all)
  function runSuite(bug, enabled) {
    const on = enabled ? new Set(enabled) : null;
    return TESTS.map((t) => {
      if (on && !on.has(t.id)) return { id: t.id, name: t.name, status: "skipped" };
      const api = makeApi(bug); let ok = false;
      try { ok = !!t.run(api); } catch (e) { ok = false; }
      return { id: t.id, name: t.name, status: ok ? "pass" : "fail" };
    });
  }

  // ------------------------------------------------------------------ 4. input handling: filename sanitisers and the properties a test would check
  const RESERVED = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])$/i;
  const BAD_CHARS = /[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩]/;
  function problems(out) {
    const p = [];
    if (typeof out !== "string" || out.length === 0) { p.push("empty result"); return p; }
    if (out.length > 100) p.push("longer than 100 characters");
    if (/[\/\\]/.test(out)) p.push("contains a path separator");
    if (out.indexOf("..") >= 0) p.push("contains ..");
    if (BAD_CHARS.test(out)) p.push("contains a control or direction character");
    if (out.indexOf("%") >= 0) p.push("contains % (may be decoded later)");
    if (RESERVED.test(out.split(".")[0])) p.push("is a reserved device name on Windows");
    if (out[0] === ".") p.push("starts with a dot (hidden or config file)");
    if (/[. ]$/.test(out)) p.push("ends with a dot or space (Windows drops it)");
    return p;
  }
  const SANITIZERS_FN = {
    v1: { label: "Version 1: remove ..", fn: (s) => s.replace(/\.\./g, "") },
    v2: { label: "Version 2: also strip slashes and control characters", fn: (s) => s.replace(/[\u0000-\u001f]/g, "").replace(/[\/\\]/g, "_").replace(/\.{2,}/g, "_") },
    v3: { label: "Version 3: allowlist, length cap, reserved names", fn: (s) => {
      let o = String(s).replace(/[^A-Za-z0-9._-]/g, "_").replace(/\.{2,}/g, ".").replace(/^[.\-]+/, "").replace(/[. ]+$/, "");
      if (o.length > 100) o = o.slice(0, 100).replace(/[. ]+$/, "");
      if (!o) o = "file";
      if (RESERVED.test(o.split(".")[0])) o = "_" + o;
      return o;
    } },
  };
  const BATTERY = [
    { id: "ok", label: "a normal name", input: "report.pdf" },
    { id: "empty", label: "empty", input: "" },
    { id: "trav", label: "path traversal", input: "../../etc/passwd" },
    { id: "nest", label: "a doubled-up traversal", input: "....//....//secret" },
    { id: "sep", label: "both kinds of slash", input: "a/b\\c.txt" },
    { id: "pct", label: "percent-encoded dots", input: "%2e%2e%2fsecret" },
    { id: "nul", label: "a null byte", input: "name\u0000.png" },
    { id: "dev", label: "a Windows device name", input: "CON" },
    { id: "huge", label: "10,000 characters", input: "a".repeat(10000) },
    { id: "rtl", label: "a right-to-left override", input: "invoice‮fdp.exe" },
    { id: "dot", label: "a leading dot", input: ".htaccess" },
    { id: "trail", label: "a trailing dot and space", input: "notes.txt. " },
  ];
  function runBattery(version) {
    const f = SANITIZERS_FN[version].fn;
    return BATTERY.map((c) => { const out = f(c.input); const p = problems(out); return { id: c.id, label: c.label, input: c.input, out, problems: p, ok: p.length === 0 }; });
  }

  // ------------------------------------------------------------------ 5. where each check runs
  const STAGES = [
    { id: "pre", label: "Before each commit", budget: 10 },
    { id: "pr", label: "On each pull request", budget: 600 },
    { id: "main", label: "After merge to main", budget: 1800 },
    { id: "night", label: "Nightly", budget: 8 * 3600 },
    { id: "week", label: "Weekly", budget: 24 * 3600 },
  ];
  const PIPE_TOOLS = [
    { id: "secret-diff", label: "Secret scan of the staged changes", secs: 3, note: "Seconds, high signal, and the only moment a secret is cheap to remove." },
    { id: "format", label: "Formatter and linter", secs: 5, note: "Not a security tool by itself, but it clears noise so reviewers see the real change." },
    { id: "sast-fast", label: "Static analysis, fast rules, changed files", secs: 30, note: "A few high-confidence rules, scoped to the diff." },
    { id: "tests", label: "Unit and security tests", secs: 120, note: "Includes the authorization and input tests from this talk." },
    { id: "deps", label: "Dependency scan of the lock file", secs: 40, note: "Fast, because it only reads a list and a database." },
    { id: "fuzz-smoke", label: "Five-minute fuzzing smoke run", secs: 300, note: "Replays saved inputs and explores briefly." },
    { id: "image", label: "Container image scan", secs: 180, note: "Only if you build images." },
    { id: "sast-deep", label: "Deep static analysis, whole program", secs: 900, note: "Slower, finds more, noisier." },
    { id: "dast-base", label: "Dynamic baseline scan (passive)", secs: 300, note: "Looks at responses, headers and cookies without attacking." },
    { id: "dast-full", label: "Authenticated dynamic scan", secs: 5400, note: "Logs in as two users and probes widely." },
    { id: "secret-history", label: "Secret scan of the full history", secs: 1200, note: "Catches what older commits still hold." },
    { id: "fuzz-long", label: "Long fuzzing run (hours)", secs: 6 * 3600, note: "Where fuzzing earns its keep." },
  ];
  const SUGGESTED = { "secret-diff": "pre", format: "pre", "sast-fast": "pr", tests: "pr", deps: "pr", "fuzz-smoke": "pr", image: "pr", "sast-deep": "main", "dast-base": "main", "dast-full": "night", "secret-history": "night", "fuzz-long": "week" };
  function checkPlan(plan) {
    const warns = [], totals = {};
    STAGES.forEach((s) => { totals[s.id] = { tools: 0, longest: 0 }; });
    PIPE_TOOLS.forEach((t) => {
      const st = STAGES.find((s) => s.id === plan[t.id]); if (!st) return;
      totals[st.id].tools++; totals[st.id].longest = Math.max(totals[st.id].longest, t.secs);
      if (t.secs > st.budget) warns.push({ tool: t.id, kind: "slow", text: `${t.label}: about ${fmt(t.secs)}, but "${st.label.toLowerCase()}" should finish within ${fmt(st.budget)}. Checks that block for that long get skipped.` });
    });
    if (["main", "night", "week"].includes(plan["secret-diff"])) warns.push({ tool: "secret-diff", kind: "late", text: "A secret found after the commit is already in history. Run the staged-changes scan before the push, or at the latest on the pull request." });
    if (plan.tests === "night" || plan.tests === "week") warns.push({ tool: "tests", kind: "late", text: "Your own tests are the fastest feedback you have. Running them only nightly means a broken authorization check ships first and is found later." });
    return { warns, totals };
  }
  function fmt(s) { return s < 60 ? s + " s" : s < 3600 ? Math.round(s / 60) + " min" : (Math.round(s / 360) / 10) + " h"; }

  // ------------------------------------------------------------------ 6. suppressions: reason, owner, expiry
  const TODAY = "2026-11-11"; // the demo's pretend date, so it behaves the same every time
  const LAZY = /^(fp|n\/a|na|ok|todo|tbd|wontfix|later|false positive|not an issue|ignore|none|-)\.?$/i;
  function dayNum(iso) { const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(iso || ""); if (!m) return NaN; const t = Date.UTC(+m[1], +m[2] - 1, +m[3]); const d = new Date(t); return d.getUTCMonth() === +m[2] - 1 ? t / 86400000 : NaN; }
  function lintSuppressions(text, today) {
    const now = dayNum(today || TODAY), out = [];
    text.split("\n").forEach((raw, i) => {
      const line = raw.trim(); if (!line || line[0] === "#") return;
      const parts = line.split("|").map((x) => x.trim());
      const head = parts[0], reason = parts[1] || "", owner = parts[2] || "", until = parts[3] || "";
      const issues = [];
      if (!reason) issues.push("no reason"); else if (LAZY.test(reason) || reason.length < 15) issues.push("the reason says nothing a future reader can check");
      if (!owner) issues.push("no owner");
      if (!until) issues.push("no expiry date");
      else {
        const d = dayNum(until);
        if (isNaN(d)) issues.push("the expiry isn't a valid YYYY-MM-DD date");
        else if (d < now) issues.push(`expired ${now - d} day${now - d === 1 ? "" : "s"} ago, so the finding is back`);
        else if (d - now > 180) issues.push(`expires in ${d - now} days: that's closer to permanent than temporary`);
      }
      out.push({ line: i + 1, head, ok: issues.length === 0, issues });
    });
    return out;
  }

  // ------------------------------------------------------------------ 7. triage
  const FINDINGS = [
    { id: "sqli", tool: "Static analysis", title: "SQL injection: query built from request data", where: "api/search.py:14",
      code: 'term = request.args["q"]\nsql = "SELECT * FROM items WHERE name = \'" + term + "\'"\nreturn db.execute(sql)',
      truth: "real", priority: "Fix this sprint, before anything that is only a warning.",
      why: "The data flows from the request into a string-built query on a public endpoint. It's the textbook true positive. The fix is a parameterised query, and the test that proves it is a case with a quote in the search term." },
    { id: "fixture", tool: "Static analysis", title: "Hard-coded password", where: "tests/fixtures/users.py:3",
      code: 'DEMO_USER = {"name": "demo", "password": "hunter2"}', truth: "noise", priority: "Close it, and add a rule exclusion for the fixtures folder.",
      why: "It's a fixture for a throwaway test database. Check once that the same password isn't accepted anywhere real, then exclude the folder with a reason, so the scanner doesn't cry wolf at every review." },
    { id: "tiff", tool: "Dependency scan", title: "Critical CVE in the image library's TIFF decoder", where: "package-lock.json: imagelib 4.1.0",
      code: 'we upload PNG and JPEG only; nothing calls the TIFF code',
      truth: "noise", priority: "Not exploitable for now. Suppress it with a reason and an expiry, and upgrade in the next routine update.",
      why: "The vulnerable code can't be reached from your inputs, so the 'critical' label doesn't describe your risk. But 'we never call it' is a claim, so write it down with who checked it and a date it expires. Reachability tools help, and so does a failing test that sends a TIFF and expects a rejection." },
    { id: "awsdoc", tool: "Secret scan", title: "AWS access key ID found", where: "docs/setup.md:41",
      code: 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE', truth: "noise", priority: "Close it. Allowlist the string so it stays quiet.",
      why: "That exact key ID is the example in AWS's own documentation. It was never a credential. The check that earns its keep is the validated one: many scanners can test whether a key is live, and the live ones are the ones to rush." },
    { id: "ghp", tool: "Secret scan", title: "GitHub token found, validated as active", where: "commit 3fa9c1e (two years old), scripts/deploy.sh",
      code: 'GH_TOKEN=ghp_************************************', truth: "real", priority: "Today. Revoke it first, then clean up.",
      why: "A live token is a live key, however old the commit. Revoke it before anything else: removing it from history doesn't help if someone already copied it. Then find out what it could reach and check the logs for use." },
  ];

  // ------------------------------------------------------------------ 8. measuring: counts vs time to fix
  const TODAY_DAY = 80;
  const FIX = [4, 9, 90, 12, 5, 20, 7, 10, 3, 50, 8, 6];
  function baseFindings() {
    const a = [];
    for (let i = 0; i < 24; i++) { const opened = 3 * i + 8, closed = opened + FIX[i % 12]; a.push({ opened, state: closed <= TODAY_DAY ? "fixed" : "open", closed: closed <= TODAY_DAY ? closed : null }); }
    return a;
  }
  function scannerFindings() {
    const a = [], fixes = [5, 8, 11, 6, 30, 40];
    for (let i = 0; i < 24; i++) a.push({ opened: 49, state: "noise", closed: 51 });       // dismissed in two days
    fixes.forEach((f) => a.push({ opened: 49, state: 49 + f <= TODAY_DAY ? "fixed" : "open", closed: 49 + f <= TODAY_DAY ? 49 + f : null }));
    return a;
  }
  function metrics(opts) {
    opts = opts || {};
    let list = baseFindings();
    if (opts.scanner) list = list.concat(scannerFindings());
    if (opts.hide) list = list.map((f) => (f.state === "open" && TODAY_DAY - f.opened > 30 ? { opened: f.opened, state: "suppressed", closed: TODAY_DAY } : f));
    const fixed = list.filter((f) => f.state === "fixed").map((f) => f.closed - f.opened).sort((a, b) => a - b);
    const open = list.filter((f) => f.state === "open");
    const med = fixed.length ? (fixed.length % 2 ? fixed[(fixed.length - 1) / 2] : (fixed[fixed.length / 2 - 1] + fixed[fixed.length / 2]) / 2) : 0;
    return {
      found: list.length, open: open.length, fixed: fixed.length,
      dismissed: list.filter((f) => f.state === "noise").length, suppressed: list.filter((f) => f.state === "suppressed").length,
      medianDaysToFix: med, oldestOpenDays: open.length ? Math.max.apply(null, open.map((f) => TODAY_DAY - f.opened)) : 0,
      openOver30: open.filter((f) => TODAY_DAY - f.opened > 30).length,
    };
  }

  // ------------------------------------------------------------------ 9. the title-slide test-name linter
  function lintTestName(raw) {
    const name = String(raw || "").trim();
    if (!name) return { level: "y", text: "# a test with no name is a test nobody can read when it fails." };
    const core = name.toLowerCase().replace(/^test[_\s-]*/, "").replace(/[\s-]+/g, "_");
    if (/^(it_?works|works|it_worked|works_fine|it_is_fine)$/.test(core)) return { level: "bad", text: "Narrator: it did not." };
    if (!core || /^\d+$/.test(core) || /^(a|b|foo|bar|baz|tmp|temp|test|x|stuff|thing)$/.test(core)) return { level: "y", text: "# a name should say what breaks when it fails. 'test1' says nothing." };
    if (/^(security|auth|authz|authn|permissions?|login|api)$/.test(core)) return { level: "y", text: "# that's a topic, not a behaviour. Who should be able to do what?" };
    if (/(cannot|can_?not|cant|never|rejects?|denied|denies|forbidden|unauthori[sz]ed|\b401\b|\b403\b|only|requires?|refuses?)/.test(core)) return { level: "ok", text: "# that reads like a rule: who, what, and what should happen. When it fails, you know which rule broke." };
    return { level: "y", text: "# a decent start. Add who and what: user_cannot_read_other_invoice." };
  }

  const api = { TOOLS, BUGS, RATING, toolsFor, SNIPPETS, scan, judge, USERS, BUG_OPTIONS, TESTS, makeApi, runSuite, SANITIZERS_FN, BATTERY, runBattery, problems,
    STAGES, PIPE_TOOLS, SUGGESTED, checkPlan, fmt, TODAY, lintSuppressions, FINDINGS, metrics, lintTestName };
  if (typeof module !== "undefined" && module.exports) module.exports = api; else root.TestLab = api;
})(typeof window !== "undefined" ? window : globalThis);
