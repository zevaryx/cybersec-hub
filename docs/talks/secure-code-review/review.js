/* review.js - the logic behind this talk's demos, kept apart from the page so it can be tested in Node.
   EDUCATIONAL ONLY. Every code sample here is invented and deliberately flawed, and each one comes with its fix and a model review comment.
   The tracer and the line scanner are tiny teaching tools: they read text and report patterns. They never run, parse or send the code. */
(function (root) {
  "use strict";

  // =========================================================================== 1. the exercises
  /* A snippet is a small pull request. Lines are 1-based. `findings` are the planted flaws (a line number in `lines` marks where a reviewer would
     comment); `decoys` are lines that look suspicious but are fine, with the reason; `bonus` findings don't count towards the score. */
  const ROUNDS = [
    { n: 1, key: "code", name: "Data treated as code", sinks: "queries, shell commands, HTML, file paths, redirects" },
    { n: 2, key: "authz", name: "Authorization", sinks: "who is allowed to do this, to this record?" },
    { n: 3, key: "crypto", name: "Secrets and crypto", sinks: "keys, hashes, randomness, tokens" },
    { n: 4, key: "config", name: "Configuration and errors", sinks: "debug modes, CORS, error messages, logs" }
  ];

  const SNIPPETS = [
    // ------------------------------------------------------------------ round 1
    { id: "r1-search", round: 1, tab: "Product search", lang: "Python (Flask)", file: "shop/api/products.py",
      title: "Add product search", desc: "Adds a search endpoint so the storefront can filter by name and maximum price.",
      code: [
        '@app.get("/api/products")',
        'def search_products():',
        '    name = request.args.get("name", "")',
        '    max_price = request.args.get("max_price", "1000")',
        '    db = get_db()',
        '    query = f"SELECT id, name, price FROM products WHERE name LIKE \'%{name}%\' AND price <= {max_price}"',
        '    rows = db.execute(query).fetchall()',
        '    return jsonify([dict(r) for r in rows])'
      ],
      findings: [
        { id: "sqli", lines: [6], title: "Query text built from request values", sev: "Blocking",
          why: "name and max_price come straight from the URL and are pasted into the SQL. A value containing a quote or SQL text changes what the query does, instead of being compared as data.",
          fix: ['rows = db.execute(', '    "SELECT id, name, price FROM products WHERE name LIKE ? AND price <= ?",', '    (f"%{name}%", float(max_price)),', ').fetchall()'],
          comment: "Blocking: `name` and `max_price` come from the query string and are interpolated into the SQL on line 6, so a value with a quote changes the query itself (SQL injection). Could we bind them as parameters (`?`) and convert `max_price` to a number first? The same pattern may be in the other queries in this file, happy to look with you.",
          cwe: "CWE-89" },
        { id: "unbounded", lines: [7], title: "No limit on how many rows come back", sev: "Should fix",
          why: "An empty name matches every product, and nothing caps the page size. One request can ask the database for the whole table and the server to serialise all of it.",
          fix: ['"... AND price <= ? ORDER BY id LIMIT 50 OFFSET ?"'],
          comment: "Should fix: with an empty `name` this returns every row. Can we add a `LIMIT` (and a page parameter)? It protects the database and the response size, and it's cheap to do now.",
          cwe: "CWE-770" }
      ],
      decoys: [{ line: 5, why: "Getting a connection is fine here. What matters is what's done with it." }, { line: 8, why: "jsonify turns rows into JSON for you. The problem is upstream, in what was asked of the database." }]
    },
    { id: "r1-thumb", round: 1, tab: "Thumbnails", lang: "Node.js", file: "server/thumbnail.js",
      title: "Generate thumbnails for uploads", desc: "Adds a button that makes a PNG thumbnail of an uploaded image with ImageMagick.",
      code: [
        'const { exec } = require("child_process");',
        '',
        'app.post("/api/thumbnail", requireLogin, (req, res) => {',
        '  const file = req.body.filename;',
        '  const size = req.body.size || "200";',
        '  exec(`convert uploads/${file} -resize ${size}x${size} thumbs/${file}.png`, (err) => {',
        '    if (err) return res.status(500).send("failed");',
        '    res.json({ url: `/thumbs/${file}.png` });',
        '  });',
        '});'
      ],
      findings: [
        { id: "shell", lines: [1, 6], title: "User text becomes part of a shell command", sev: "Blocking",
          why: "exec() starts a shell and the command is one string, so characters like ; and $( ) in filename or size are read by the shell as commands, not as part of a name.",
          fix: ['const { execFile } = require("child_process");', 'const px = Number.parseInt(size, 10);', 'if (!(px >= 16 && px <= 1024)) return res.status(400).end();', 'execFile("convert", [src, "-resize", `${px}x${px}`, dest], cb);'],
          comment: "Blocking: `exec` runs a shell, and `file` and `size` are user-controlled, so shell characters in them become commands. Node's docs say never to pass unsanitized input to `exec`. Could we use `execFile` with an argument array and check `size` is an integer in a sane range?",
          cwe: "CWE-78" },
        { id: "path", lines: [4, 6], title: "The filename can point outside the uploads folder", sev: "Blocking",
          why: "The name is used as-is in a path, so ../ sequences can reach other files, and the output path uses the same text. Which files a user can name is a decision the server has to make.",
          fix: ['const id = req.body.id;                    // an id we issued, not a name', 'const src = path.join(UPLOADS, `${id}.upload`);', 'if (!src.startsWith(UPLOADS + path.sep)) return res.status(400).end();'],
          comment: "Blocking: `filename` goes straight into a path, so `../` can leave `uploads/`. Could the client send an id we issued instead of a name, and could we resolve the final path and check it's still inside the uploads folder?",
          cwe: "CWE-22" }
      ],
      decoys: [{ line: 3, why: "requireLogin is there, which is good, but being logged in doesn't make the input trustworthy." }, { line: 7, why: "A generic error is the right instinct: it doesn't leak details." }]
    },
    { id: "r1-welcome", round: 1, tab: "Welcome and redirect", lang: "Node.js (Express)", file: "server/pages.js",
      title: "Friendlier welcome page and a ?next= redirect", desc: "Greets the user by name and sends them back to where they were after sign-in.",
      code: [
        'app.get("/welcome", (req, res) => {',
        '  const name = req.query.name || "friend";',
        '  res.send(`<h1>Welcome back, ${name}!</h1>`);',
        '});',
        '',
        'app.get("/go", (req, res) => {',
        '  const next = req.query.next || "/";',
        '  res.redirect(next);',
        '});'
      ],
      findings: [
        { id: "xss", lines: [3], title: "Request text placed into HTML", sev: "Blocking",
          why: "name is written into the page without escaping, so a value containing tags becomes part of the page's markup and runs in the visitor's browser, in your site's origin.",
          fix: ['res.render("welcome", { name });     // the template engine escapes by default', '// or: res.send(`<h1>Welcome back, ${escapeHtml(name)}!</h1>`);'],
          comment: "Blocking: `name` is interpolated into HTML unescaped, so a crafted link can run script on our origin (XSS). Could we render it through the template engine, which escapes by default, or at least escape it here?",
          cwe: "CWE-79" },
        { id: "redirect", lines: [7, 8], title: "Redirect to any address the link says", sev: "Should fix",
          why: "next is sent back as the destination, so a link on our domain can send people to any other site, which makes phishing links look trustworthy.",
          fix: ['const ok = typeof next === "string" && next.startsWith("/") && !next.startsWith("//");', 'res.redirect(ok ? next : "/");'],
          comment: "Should fix: `next` is used as the redirect target as-is, so `/go?next=https://elsewhere.example` bounces people off our domain. Could we only allow paths that start with a single `/`, or match against a short list?",
          cwe: "CWE-601" }
      ],
      decoys: [{ line: 2, why: "A default value is fine. It's the next line that decides what happens to the text." }]
    },
    // ------------------------------------------------------------------ round 2
    { id: "r2-orders", round: 2, tab: "Orders", lang: "Node.js", file: "server/orders.js",
      title: "Add order lookup and cancellation", desc: "Adds endpoints so the mobile app can show and delete an order.",
      code: [
        '// TODO: security',
        'app.get("/api/orders/:id", requireLogin, async (req, res) => {',
        '  const order = await db.orders.findById(req.params.id);',
        '  if (!order) return res.status(404).json({ error: "not found" });',
        '  res.json(order);',
        '});',
        '',
        'app.delete("/api/orders/:id", requireLogin, async (req, res) => {',
        '  await db.orders.deleteById(req.params.id);',
        '  res.status(204).end();',
        '});'
      ],
      findings: [
        { id: "bola-read", lines: [3, 5], title: "Any signed-in user can read any order", sev: "Blocking",
          why: "The route checks that someone is logged in, but never that this order belongs to them. Changing the id in the URL returns somebody else's order.",
          fix: ['const order = await db.orders.findOne({ id: req.params.id, userId: req.user.id });', 'if (!order) return res.status(404).json({ error: "not found" });   // same answer for "not yours"'],
          comment: "Blocking: this checks the caller is signed in, but not that the order is theirs, so any user can read any order by changing the id. Could we put `userId: req.user.id` in the query so a record that isn't theirs is simply not found?",
          cwe: "CWE-639" },
        { id: "bola-delete", lines: [9], title: "Any signed-in user can delete any order", sev: "Blocking",
          why: "Same missing ownership check, on a write. Deleting is worse than reading, and it should also be allowed only if the order's state permits cancelling.",
          fix: ['const r = await db.orders.deleteOne({ id: req.params.id, userId: req.user.id, status: "pending" });', 'if (!r.deletedCount) return res.status(404).end();'],
          comment: "Blocking: same ownership gap on delete, and this one changes data. Can the delete be scoped to the caller's own order, and should it only work while the order is still pending?",
          cwe: "CWE-639" },
        { id: "todo", lines: [1], bonus: true, title: "A comment that says what it is", sev: "Found it!",
          why: "The easiest finding in history: the author already knew. A TODO about security in a pull request is a request to finish the work before merging.",
          fix: ['// (resolve it in this PR, or open a ticket and link it here)'],
          comment: "Nit: this TODO says security work is missing, and it is (see the comments below). Can we resolve it in this PR rather than merge it as a note?" }
      ],
      decoys: [{ line: 4, why: "Returning 404 for a missing record is fine, and it's what you want for \"not yours\" too." }]
    },
    { id: "r2-profile", round: 2, tab: "Profile and admin", lang: "Python (Flask)", file: "shop/api/account.py",
      title: "Let users edit their profile; add an admin export", desc: "A profile update endpoint for the settings page, and a user export for the support team.",
      code: [
        '@app.post("/api/profile")',
        '@login_required',
        'def update_profile():',
        '    user = current_user()',
        '    data = request.get_json()',
        '    user.update(**data)',
        '    return jsonify(user.to_dict())',
        '',
        '@app.get("/admin/export")',
        '@login_required',
        'def export_users():',
        '    return jsonify(all_users())   # the Admin link is hidden for normal users in the UI'
      ],
      findings: [
        { id: "mass", lines: [5, 6], title: "The client decides which fields get changed", sev: "Blocking",
          why: "Every key in the request body is applied to the user record, including ones the form never shows, such as role or is_admin. Whatever the client sends, the server stores.",
          fix: ['ALLOWED = {"display_name", "email", "timezone"}', 'user.update(**{k: v for k, v in data.items() if k in ALLOWED})'],
          comment: "Blocking: `user.update(**data)` applies whatever fields the client sends, so someone can set `role` or `is_admin` themselves. Could we allow-list the fields this form may change?",
          cwe: "CWE-915" },
        { id: "function-level", lines: [9, 10, 11, 12], title: "Admin only in the user interface", sev: "Blocking",
          why: "Hiding a link isn't access control. The URL still works for anyone signed in, and the response is the whole user table.",
          fix: ['@app.get("/admin/export")', '@require_role("admin")        # checked on the server, denies by default', 'def export_users():', '    return jsonify(all_users())'],
          comment: "Blocking: the Admin link is hidden in the UI, but the route only checks that someone is logged in, so any user who knows the URL gets every account. Could we enforce an admin role on the server (and deny by default for new routes)?",
          cwe: "CWE-862" }
      ],
      decoys: [{ line: 4, why: "Loading the current user from the session is right: the profile being changed comes from who's signed in, not from the request." }]
    },
    // ------------------------------------------------------------------ round 3
    { id: "r3-store", round: 3, tab: "Passwords and cards", lang: "Python", file: "shop/security.py",
      title: "Store passwords and protect card numbers", desc: "Helpers for saving a user's password and encrypting a stored card number.",
      code: [
        'import hashlib',
        'from Crypto.Cipher import AES',
        '',
        'PAYMENTS_API_KEY = "pk_demo_not_a_real_key_0000"',
        'KEY = b"0123456789abcdef"',
        '',
        'def store_password(user, password):',
        '    user.pw_hash = hashlib.md5(password.encode()).hexdigest()',
        '',
        'def protect_card(card_number: str) -> bytes:',
        '    cipher = AES.new(KEY, AES.MODE_ECB)',
        '    return cipher.encrypt(card_number.ljust(32).encode())'
      ],
      findings: [
        { id: "hardcoded", lines: [4, 5], title: "Keys written into the source", sev: "Blocking",
          why: "Anyone with the repository (or a copy of it, or a build artifact) has the keys, and they can't be rotated without a code change. Secrets in Git history stay there.",
          fix: ['import os', 'PAYMENTS_API_KEY = os.environ["PAYMENTS_API_KEY"]   # from the secret store, not the repo', 'KEY = load_key_from_kms("card-encryption")'],
          comment: "Blocking: the API key and the AES key are in the source, so they're in Git history and every checkout. Could both come from the environment or a secret store, and could we rotate the ones already committed?",
          cwe: "CWE-798" },
        { id: "md5", lines: [8], title: "A fast hash for passwords", sev: "Blocking",
          why: "MD5 was built to be fast, which lets an attacker who gets the table try billions of guesses a second. There's also no salt, so equal passwords look equal.",
          fix: ['from argon2 import PasswordHasher', 'ph = PasswordHasher()                     # salted, slow, memory-hard', 'user.pw_hash = ph.hash(password)'],
          comment: "Blocking: MD5 is a fast, unsalted hash, which is the wrong tool for passwords. OWASP's Password Storage Cheat Sheet recommends Argon2id. Could we switch to an Argon2id library and re-hash each user at their next sign-in?",
          cwe: "CWE-916" },
        { id: "ecb", lines: [11, 12], title: "A mode that shows patterns, with a fixed key", sev: "Blocking",
          why: "ECB encrypts every block on its own, so equal inputs give equal ciphertext and nothing detects tampering. The key is also fixed in code. Better still: don't store card numbers at all.",
          fix: ['# prefer: store a token from the payment provider, not the number', 'from cryptography.hazmat.primitives.ciphers.aead import AESGCM', 'nonce = os.urandom(12)', 'ct = AESGCM(key).encrypt(nonce, data, aad)   # a fresh nonce every time, stored with the ciphertext'],
          comment: "Blocking: ECB leaks patterns (equal blocks encrypt equally) and gives no integrity check. Could we use an authenticated mode like AES-GCM from a library with a fresh nonce each time, or, better, stop storing the card number and keep a token from the payment provider?",
          cwe: "CWE-327" }
      ],
      decoys: [{ line: 1, why: "Importing hashlib isn't the issue, which algorithm gets used is." }]
    },
    { id: "r3-reset", round: 3, tab: "Password reset token", lang: "JavaScript", file: "server/reset.js",
      title: "Password reset by email", desc: "Creates a reset token for the email link and checks it when the user comes back.",
      code: [
        'function makeResetToken(user) {',
        '  const token = Math.random().toString(36).slice(2);',
        '  db.resetTokens.save({ userId: user.id, token, created: Date.now() });',
        '  return token;',
        '}',
        '',
        'function checkResetToken(userId, supplied) {',
        '  const row = db.resetTokens.find(userId);',
        '  return row && row.token == supplied;',
        '}'
      ],
      findings: [
        { id: "random", lines: [2], title: "A predictable random number generator", sev: "Blocking",
          why: "Math.random() isn't built to be unpredictable, and this token is short. MDN says not to use it for anything security-related. The token is a password for the account.",
          fix: ['const token = crypto.randomBytes(32).toString("base64url");   // node:crypto'],
          comment: "Blocking: `Math.random()` isn't cryptographically secure (MDN says not to use it for anything security-related), and this token unlocks an account. Could we use `crypto.randomBytes(32)` here?",
          cwe: "CWE-338" },
        { id: "lifetime", lines: [8, 9], title: "The check ignores expiry and one-time use", sev: "Blocking",
          why: "created is saved but never looked at, and the row isn't deleted after use, so an old email stays a working key. Compare with == also coerces types: be explicit.",
          fix: ['if (!row || Date.now() - row.created > 30 * 60 * 1000) return false;', 'db.resetTokens.delete(userId);                  // single use', 'return timingSafeEqual(hash(supplied), row.tokenHash);'],
          comment: "Blocking: we save `created` but never check it, and the token isn't deleted after use, so an old reset email keeps working. Could we expire it (say 30 minutes), delete it on use, and compare with a constant-time function?",
          cwe: "CWE-640" },
        { id: "plain", lines: [3], title: "The token is stored as-is", sev: "Should fix",
          why: "If the table leaks (a backup, a SQL read bug), every pending token works. Store a hash of it, as you would a password, and compare hashes.",
          fix: ['db.resetTokens.save({ userId: user.id, tokenHash: sha256(token), created: Date.now() });'],
          comment: "Should fix: the token is stored in the clear, so anyone who can read the table can take over accounts with pending resets. Could we store a hash and compare hashes?",
          cwe: "CWE-256" }
      ],
      decoys: [{ line: 4, why: "Returning the token to the caller is expected: it goes in the email, and only there." }]
    },
    // ------------------------------------------------------------------ round 4
    { id: "r4-config", round: 4, tab: "App setup", lang: "Python (Flask)", file: "shop/app.py",
      title: "Let the new web app call the API", desc: "Allows our dashboard (a different domain) to call the API with the user's cookie, and makes the dev server easy to reach.",
      code: [
        'app = Flask(__name__)',
        'app.config["SECRET_KEY"] = "dev"',
        '',
        '@app.after_request',
        'def add_cors(resp):',
        '    origin = request.headers.get("Origin", "*")',
        '    resp.headers["Access-Control-Allow-Origin"] = origin',
        '    resp.headers["Access-Control-Allow-Credentials"] = "true"',
        '    return resp',
        '',
        'if __name__ == "__main__":',
        '    app.run(host="0.0.0.0", debug=True)'
      ],
      findings: [
        { id: "cors", lines: [6, 7, 8], title: "Every website is allowed to use the user's cookie", sev: "Blocking",
          why: "The code echoes back whatever Origin asked, and says credentials are allowed. That is \"any site may call this API as the signed-in user and read the answer\". Browsers block the * wildcard with credentials; echoing the origin gets round that block.",
          fix: ['ALLOWED = {"https://dashboard.example.com"}', 'if origin in ALLOWED:', '    resp.headers["Access-Control-Allow-Origin"] = origin', '    resp.headers["Access-Control-Allow-Credentials"] = "true"', '    resp.headers["Vary"] = "Origin"'],
          comment: "Blocking: this reflects any `Origin` and allows credentials, so any website can call the API as the signed-in user and read the response. Could we check the origin against an allow-list (just the dashboard) and add `Vary: Origin`?",
          cwe: "CWE-942" },
        { id: "debug", lines: [12], title: "Debug mode, open to the network", sev: "Blocking",
          why: "Flask's docs say never to run the debugger in production: it lets someone run Python from the browser. With host 0.0.0.0 it's reachable from other machines. Make sure this can't be the way production starts.",
          fix: ['if __name__ == "__main__":', '    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")   # default off, localhost only', '# production: a real server (gunicorn, uWSGI) started by your deploy tooling'],
          comment: "Blocking: `debug=True` on `0.0.0.0` exposes the Werkzeug debugger, which Flask's docs say must never run in production. Could debug be off by default (and the dev server bound to localhost), with production started by the real server instead?",
          cwe: "CWE-489" },
        { id: "secretkey", lines: [2], title: "A guessable signing key", sev: "Blocking",
          why: "SECRET_KEY signs the session cookie. \"dev\" is a key anyone can guess, so cookies can be forged. If it ships, it ships everywhere.",
          fix: ['app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]   # long, random, from the environment'],
          comment: "Blocking: `SECRET_KEY` signs session cookies, and `dev` is guessable. Could we read a long random value from the environment and refuse to start without one?",
          cwe: "CWE-1188" }
      ],
      decoys: []
    },
    { id: "r4-login", round: 4, tab: "Login handler", lang: "Node.js", file: "server/login.js",
      title: "Add logging and error handling to login", desc: "Adds a log line for support and returns error details so the front end can show them.",
      code: [
        'app.post("/api/login", async (req, res) => {',
        '  const { email, password } = req.body;',
        '  logger.info(`login attempt ${email} / ${password}`);',
        '  try {',
        '    const user = await auth.verify(email, password);',
        '    res.json({ token: user.makeToken() });',
        '  } catch (err) {',
        '    res.status(500).json({ error: err.message, stack: err.stack });',
        '  }',
        '});'
      ],
      findings: [
        { id: "logpw", lines: [3], title: "The password is written to the log", sev: "Blocking",
          why: "Logs are copied, searched, shipped to vendors and kept for months, usually with weaker access control than the database. A password in a log is a password everywhere the log goes.",
          fix: ['logger.info("login attempt", { email_hash: hash(email) });   // never the password'],
          comment: "Blocking: this logs the password in the clear, and logs travel a lot further than the database. Could we log only the fact of the attempt (and a hashed or truncated identifier), never the secret?",
          cwe: "CWE-532" },
        { id: "verbose", lines: [8], title: "Internal details sent to the caller", sev: "Should fix",
          why: "err.message and the stack trace tell a stranger how the server is built, and a differing message for \"no such user\" and \"wrong password\" lets them find real accounts. Return one generic answer, log the detail on the server.",
          fix: ['logger.error("login failed", { err });                       // detail stays on the server', 'res.status(401).json({ error: "Email or password is incorrect" });   // the same for every failure'],
          comment: "Should fix: `err.message` and the stack go to the client, which leaks internals and may reveal whether an account exists. Could we log the detail server-side and return the same generic 401 for every failure?",
          cwe: "CWE-209" }
      ],
      decoys: [{ line: 2, why: "Reading the body is normal. The question is where the values go next." }]
    },
    { id: "r4-clean", round: 4, tab: "A clean one", lang: "Node.js", file: "server/notes.js", clean: true,
      title: "Add a read endpoint for notes", desc: "Lets a user fetch one of their own notes by id.",
      code: [
        'app.get("/api/notes/:id", requireLogin, async (req, res) => {',
        '  const id = Number.parseInt(req.params.id, 10);',
        '  if (!Number.isSafeInteger(id)) return res.status(400).json({ error: "bad id" });',
        '  const note = await db.notes.findOne({ id, ownerId: req.user.id });',
        '  if (!note) return res.status(404).json({ error: "not found" });',
        '  res.json({ id: note.id, title: note.title, body: note.body });',
        '});'
      ],
      findings: [],
      decoys: [
        { line: 2, why: "The id is turned into a number and checked before it's used." },
        { line: 4, why: "The owner is part of the query, so \"not yours\" and \"doesn't exist\" look the same." },
        { line: 5, why: "A plain 404 with no detail." },
        { line: 6, why: "Fields are chosen one by one, so a new column won't leak by accident." }
      ],
      verdict: "Looks good to me, and that's the right answer. Input is validated, the query is scoped to the owner, and the response lists its fields. Reviewing means knowing when to approve."
    }
  ];

  // =========================================================================== 2. grading and the scoreboard
  const byId = (id) => SNIPPETS.find((s) => s.id === id);
  const required = (s) => s.findings.filter((f) => !f.bonus);
  /** flags: a Set (or array) of 1-based line numbers the reviewer would comment on. */
  function grade(snippet, flags) {
    const set = new Set(flags);
    const found = [], missed = [], bonus = [];
    for (const f of snippet.findings) {
      const hit = f.lines.some((n) => set.has(n));
      if (f.bonus) { if (hit) bonus.push(f.id); } else (hit ? found : missed).push(f.id);
    }
    const covered = new Set();
    for (const f of snippet.findings) for (const n of f.lines) covered.add(n);
    const extra = [], decoyHits = [];
    for (const n of set) {
      if (covered.has(n)) continue;
      const d = snippet.decoys.find((x) => x.line === n);
      if (d) decoyHits.push({ line: n, why: d.why }); else extra.push(n);
    }
    const total = required(snippet).length;
    return { found, missed, bonus, falseFlags: decoyHits.concat(extra.map((n) => ({ line: n, why: null }))), total, perfect: found.length === total && !missed.length, flaggedCount: set.size };
  }
  /** results: { snippetId: { found: n, total: n } } for the snippets the pairs have checked. */
  function scoreboard(results) {
    const rounds = ROUNDS.map((r) => {
      const sn = SNIPPETS.filter((s) => s.round === r.n && s.findings.length);
      let found = 0, total = 0, done = 0;
      for (const s of sn) { total += required(s).length; const x = results[s.id]; if (x) { done++; found += x.found; } }
      return { round: r.n, name: r.name, found, total, checked: done, snippets: sn.length };
    });
    const found = rounds.reduce((a, r) => a + r.found, 0), total = rounds.reduce((a, r) => a + r.total, 0);
    const allChecked = SNIPPETS.filter((s) => s.findings.length).every((s) => results[s.id]);
    return { rounds, found, total, allChecked, eagleEye: allChecked && found === total };
  }
  const totalFindings = () => SNIPPETS.reduce((a, s) => a + required(s).length, 0);

  // =========================================================================== 3. the line scanner (a toy, for the title slide)
  const SCAN_RULES = [
    { id: "todo", re: /\bTODO\b[^\n]*\bsecurity\b/i, label: "Found it!", why: "The easiest finding in history: the author already knew. Fix it in this pull request or open a ticket and link it.", fix: "resolve the TODO or link a ticket" },
    { id: "sqli", re: /(\bselect\b[^\n]*\bfrom\b|\binsert\s+into\b|\bupdate\b[^\n]*\bset\b|\bdelete\s+from\b)[^\n]*(['"`]\s*\+|\+\s*['"`]|\$\{|\{[a-z_]+\}|['\"]\s*%\s*[\w(])/i,
      label: "SQL built by joining text", why: "Values pasted into a query can change what it does.", fix: "use placeholders: execute(sql, (value,))" },
    { id: "shell", re: /\b(os\.system|subprocess\.\w+\([^)]*shell\s*=\s*True|child_process|\bexec\s*\(|\bexecSync\s*\(|\bpopen\s*\()/, label: "A shell command", why: "A shell reads ; and $( ) as commands. If any part is user text, it can run commands.", fix: "pass an argument array without a shell (execFile, subprocess.run([...]))" },
    { id: "eval", re: /\beval\s*\(|\bnew\s+Function\s*\(|\bFunction\s*\(\s*['"`]/, label: "Text run as code", why: "eval turns data into code.", fix: "parse data (JSON.parse); use a lookup table, not eval" },
    { id: "html", re: /\binnerHTML\b|\bdocument\.write\b|\bdangerouslySetInnerHTML\b|\|\s*safe\b|\bMarkup\(/, label: "HTML written from text", why: "Text placed in markup can carry tags and script.", fix: "textContent, or a template engine that escapes by default" },
    { id: "redirect", re: /\bredirect\s*\(\s*(req|request)\./i, label: "Redirect to a request value", why: "Anyone can build a link that sends people elsewhere.", fix: "allow only local paths or a short list" },
    { id: "path", re: /\b(readFile|readFileSync|createReadStream|sendFile|open)\s*\([^)]*(req\.|request\.|\+\s*\w*(file|name|path))/i, label: "A file path from the request", why: "../ can step outside the folder you meant.", fix: "resolve the path and check it's inside the folder (or use an id)" },
    { id: "secret", re: /\b(api[_-]?key|secret|passwd|password|token|private[_-]?key)\w*\s*[:=]\s*['"][^'"\s]{6,}['"]/i, label: "A secret in the source", why: "Anything in Git stays in Git history.", fix: "read it from the environment or a secret store" },
    { id: "weakhash", re: /\b(md5|sha1)\b/i, label: "A weak or fast hash", why: "Fine for a checksum, wrong for passwords and signatures.", fix: "Argon2id for passwords; SHA-256 or better for integrity" },
    { id: "ecb", re: /(^|[^A-Za-z])ECB(?![A-Za-z])/, label: "ECB mode", why: "Equal blocks encrypt to equal ciphertext.", fix: "an authenticated mode such as AES-GCM from a library" },
    { id: "random", re: /\bMath\.random\s*\(|\brandom\.(random|randint|choice)\s*\(/, label: "Not a security-grade random number", why: "Predictable numbers make guessable tokens.", fix: "crypto.randomBytes / secrets.token_urlsafe" },
    { id: "debug", re: /\bdebug\s*[=:]\s*(True|true)\b|\bapp\.run\([^)]*debug\s*=\s*True/, label: "Debug mode on", why: "Debuggers and verbose pages are for development machines.", fix: "off by default; set from the environment" },
    { id: "cors", re: /Access-Control-Allow-Origin["']?[\]:=,\s]+["']?\*|origin\s*:\s*["']\*["']|origins\s*=\s*["']\*["']/i, label: "Any website allowed (CORS)", why: "Check who needs access, and never combine it with credentials.", fix: "an allow-list of origins" },
    { id: "tls", re: /verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|NODE_TLS_REJECT_UNAUTHORIZED/, label: "Certificate checks switched off", why: "Without them, anyone on the path can pretend to be the server.", fix: "fix the trust problem instead (add the CA); never disable the check" },
    { id: "logsecret", re: /\b(log|logger|console)\.\w+\([^)]*\b(password|passwd|token|secret|apikey|authorization)\b/i, label: "A secret going into a log", why: "Logs travel further than databases.", fix: "log the event, not the value" }
  ];
  function scanLine(line) {
    const s = String(line == null ? "" : line);
    if (!s.trim()) return { id: "empty", label: "Nothing to review", why: "An empty change is the safest change.", fix: "" };
    for (const r of SCAN_RULES) if (r.re.test(s)) return { id: r.id, label: r.label, why: r.why, fix: r.fix };
    return { id: "none", label: "No known pattern on this line", why: "A line that looks fine can still be wrong because of what it connects to. Follow the data.", fix: "" };
  }

  // =========================================================================== 4. the source-to-sink tracer
  const TRACE_SOURCE = /\b(req|request)\.(query|body|params|headers|cookies|args|form|json|get_json)\b|\brequest\.(args|form|json|values)\b|\bprocess\.argv\b|\binput\s*\(/;
  const TRACE_SINKS = [
    { kind: "SQL", re: /\b(db|conn|connection|client|pool)\.(query|execute|raw)\s*\(|\.execute\s*\(/ },
    { kind: "HTML", re: /\bres\.send\s*\(\s*[`"'][^`"']*</ },
    { kind: "Shell", re: /\b(exec|execSync|system|popen)\s*\(/ },
    { kind: "File path", re: /\b(readFile|readFileSync|createReadStream|sendFile|open)\s*\(/ },
    { kind: "Redirect", re: /\bredirect\s*\(/ }
  ];
  const TRACE_CLEANERS = /\b(Number|parseInt|parseFloat|Number\.parseInt|int|float|escapeHtml|escape|encodeURIComponent|basename|path\.basename|secure_filename|allowlist|isUuid)\s*\(/;
  const TRACE_EXAMPLE = [
    'app.get("/search", async (req, res) => {',
    '  const term = req.query.q;',
    '  const page = Number(req.query.page) || 1;',
    '  const sort = req.query.sort;',
    '  const like = "%" + term + "%";',
    '  const sql = "SELECT * FROM items WHERE name LIKE \'" + like + "\' ORDER BY " + sort + " LIMIT 20 OFFSET " + (page - 1) * 20;',
    '  const rows = await db.query(sql);',
    '  res.send("<h1>Results for " + term + "</h1>" + render(rows));',
    '});'
  ];
  const wordRe = (v) => new RegExp("(^|[^A-Za-z0-9_$.])" + v.replace(/[$]/g, "\\$") + "(?![A-Za-z0-9_$])");
  const assignRe = /^\s*(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*=(?!=)\s*(.*)$/;
  /** Works out, for each assigned variable, whether it carries request data ("dirty"), has been cleaned, or is plain. */
  function traceModel(lines) {
    const info = {};  // name -> {line, dirty, cleaned, from:[names]}
    lines.forEach((text, i) => {
      const m = assignRe.exec(text); if (!m) return;
      const name = m[1], rhs = m[2];
      const from = Object.keys(info).filter((v) => wordRe(v).test(rhs));
      const direct = TRACE_SOURCE.test(rhs);
      const cleaned = TRACE_CLEANERS.test(rhs);
      const tainted = (direct || from.some((v) => info[v].dirty)) && !cleaned;
      // the result of a query or call that is itself a sink is fresh data from that system, not the request's text
      const fromSink = TRACE_SINKS.some((k) => k.re.test(rhs));
      info[name] = { name, line: i + 1, dirty: tainted && !fromSink, cleaned: (direct || from.some((v) => info[v].dirty)) && cleaned, direct, from: fromSink ? [] : from };
    });
    return info;
  }
  /** Follow one variable: every line that uses it, and the sinks it reaches (directly, or through a variable built from it). */
  function trace(lines, name) {
    const model = traceModel(lines);
    const me = model[name];
    if (!me) return { name, known: false, uses: [], sinks: [], dirty: false, cleaned: false, line: 0, derived: [], from: [] };
    // everything built from this variable, transitively
    const family = new Set([name]);
    let grew = true;
    while (grew) {
      grew = false;
      for (const v of Object.keys(model)) if (!family.has(v) && model[v].from.some((f) => family.has(f)) && !model[v].cleaned) { family.add(v); grew = true; }
    }
    const uses = [], sinks = [];
    lines.forEach((text, i) => {
      const assigns = assignRe.exec(text);
      const rhs = assigns ? assigns[2] : text;
      const reads = Array.from(family).filter((v) => wordRe(v).test(rhs));
      if (me.line === i + 1) uses.push({ line: i + 1, via: [], role: "origin" });
      else if (reads.length) uses.push({ line: i + 1, via: reads.filter((v) => v !== name), role: "use" });
      if (reads.length && me.line !== i + 1) for (const k of TRACE_SINKS) if (k.re.test(text)) sinks.push({ line: i + 1, kind: k.kind, via: reads });
    });
    return { name, known: true, line: me.line, dirty: me.dirty, cleaned: me.cleaned, direct: me.direct, from: me.from, derived: Array.from(family).filter((v) => v !== name), uses, sinks };
  }
  const traceVars = (lines) => Object.keys(traceModel(lines));

  // =========================================================================== 5. "empty, huge or hostile?"
  const PROBES = {
    text: { label: "A name or free text", values: ["(empty)", "a 1 MB string", "Ünï©ødé and emoji 🙂", "O'Brien; DROP TABLE", "<b>bold</b> or ${7*7}", "line one\\r\\nline two"],
      ask: "Is it length-limited? Escaped where it's shown? Stored as given or as normalised?" },
    number: { label: "A number (an id, a quantity, a price)", values: ["0", "-1", "2147483648", "1e999", "NaN", "3.14 where an integer is expected"],
      ask: "Is it parsed and range-checked? What happens on overflow, a negative or a decimal?" },
    id: { label: "An id in the URL", values: ["somebody else's id", "an id that doesn't exist", "(empty)", "an id of another type", "../ or %2e%2e/", "the same id twice"],
      ask: "Does the query include the caller? Do 'not yours' and 'doesn't exist' look the same?" },
    file: { label: "An uploaded file or filename", values: ["(empty file)", "a 4 GB file", "a name with ../", "a .jpg that is not an image", "a name that is just a dot", "a zip with a million files"],
      ask: "Is the type checked by content? Is the size capped? Is the name ever used in a path?" },
    list: { label: "A list or JSON body", values: ["[] (empty)", "100,000 items", "nested 10,000 deep", "an unexpected extra field", "a field with the wrong type", "null instead of an object"],
      ask: "Is there a size limit and a schema? Are unknown fields ignored or rejected?" }
  };

  // =========================================================================== 6. writing the comment
  const FINDING = { line: 6, what: "the query is built by putting `name` into the SQL text", risk: "a value containing a quote changes the query itself (SQL injection)", fix: "bind it as a parameter (`?`) and convert `max_price` to a number first", why: "OWASP's cheat sheet and Python's own sqlite3 docs both say to use placeholders", help: "I'm happy to pair on the other queries in this file." };
  /** opts: {where, risk, fix, why, label ("Blocking"|"Nit"|"Optional"|"FYI"|""), help, aboutPerson} -> {text, score, missing[]} */
  function composeComment(o) {
    const parts = [], missing = [];
    const lab = o.label ? o.label + ": " : "";
    const person = !!o.aboutPerson;
    let first;
    if (person) first = "Why would you build this query by hand? " + (o.where ? "Look at line 6." : "");
    else first = o.where ? "On line 6, " + FINDING.what + "." : "This query needs another look.";
    if (!o.where) missing.push("where: name the line and the variable");
    parts.push(lab + first);
    if (o.risk) parts.push(person ? "You've left it wide open to injection." : "That means " + FINDING.risk + ".");
    else missing.push("what can go wrong, concretely");
    if (o.why) parts.push(FINDING.why[0].toUpperCase() + FINDING.why.slice(1) + ".");
    if (o.fix) parts.push(person ? "Just use parameters." : "Could we " + FINDING.fix + "?");
    else missing.push("a suggested fix, or a question");
    if (o.help) parts.push(FINDING.help);
    if (!o.label) missing.push("a label so the author knows how hard to push: Blocking, Nit, Optional or FYI");
    if (person) missing.push("aim at the code, not the person");
    let score = 0;
    if (o.where) score++; if (o.risk) score++; if (o.fix) score++; if (o.why) score++; if (o.label) score++; if (!person) score++; if (o.help) score++;
    const actionable = !!(o.where && o.risk && o.fix && !person);
    return { text: parts.join(" "), score, max: 7, missing, actionable, kind: person ? "personal" : actionable ? (score >= 6 ? "great" : "good") : "thin" };
  }

  // =========================================================================== 7. machine or human?
  const AUTO_ITEMS = [
    { id: "secret", text: "A live API key committed in a config file", best: "machine", why: "Secret scanning finds known key formats in seconds, on every push. A human is still needed to rotate the key." },
    { id: "cve", text: "A dependency with a known vulnerability", best: "machine", why: "Dependency scanners compare your lock file with advisory databases all day long." },
    { id: "format", text: "Inconsistent formatting and naming", best: "machine", why: "A formatter and a linter settle it, so nobody spends review energy (or goodwill) on it." },
    { id: "sqlpat", text: "SQL built by joining strings, in a familiar pattern", best: "both", why: "Static analysis catches the common shapes. A person still checks the wrappers and helpers the tool doesn't recognise." },
    { id: "owner", text: "A new endpoint that never checks who owns the record", best: "human", why: "A tool doesn't know who is supposed to own what. The OWASP cheat sheet lists authorization logic among the things manual review does best." },
    { id: "feature", text: "\"Should we collect and keep this data at all?\"", best: "human", why: "A design and policy question. Only people who know the product can answer it." },
    { id: "race", text: "Two requests that can both withdraw the last 10 euros", best: "human", why: "Race conditions and business-logic flaws sit in the same hard-to-automate group in the OWASP cheat sheet." },
    { id: "tone", text: "Whether a comment will land as help or as blame", best: "human", why: "Only a person can read tone. This is also why the automated parts should be automated: it saves that attention for people." }
  ];
  const AUTO_CHOICES = ["machine", "human", "both"];
  function autoScore(answers) {
    let right = 0, answered = 0;
    for (const it of AUTO_ITEMS) { const a = answers[it.id]; if (!a) continue; answered++; if (a === it.best) right++; }
    return { right, answered, total: AUTO_ITEMS.length };
  }

  // =========================================================================== 8. a short checklist
  const CHECKLIST = [
    { k: "who", t: "Who can call this, and what stops the wrong person? (every new route, query and job)" },
    { k: "owner", t: "Is the record scoped to the caller in the query, not just in the user interface?" },
    { k: "input", t: "Where does input enter, where does it end up, and does anything clean it on the way? (sources to sinks)" },
    { k: "hostile", t: "What if this is empty, huge or hostile? Is it length-limited, typed and range-checked?" },
    { k: "fields", t: "Does the response, the log line or the error message contain only what the caller should see?" },
    { k: "secrets", t: "Any key, token or password in the diff, the config or the tests?" },
    { k: "crypto", t: "Is the randomness, hash or cipher from a vetted library and used for the job it was built for?" },
    { k: "defaults", t: "Do new settings fail closed: debug off, narrow CORS, the least privilege that works?" },
    { k: "fail", t: "What happens when it fails or times out: closed or open, and who is told what?" },
    { k: "tests", t: "Is there a test for the case that must not work (someone else's id, a bad input)?" }
  ];

  const api = { ROUNDS, SNIPPETS, byId, required, grade, scoreboard, totalFindings, SCAN_RULES, scanLine, TRACE_EXAMPLE, trace, traceVars, traceModel,
    PROBES, FINDING, composeComment, AUTO_ITEMS, AUTO_CHOICES, autoScore, CHECKLIST };
  root.ReviewLab = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof window !== "undefined" ? window : globalThis);
