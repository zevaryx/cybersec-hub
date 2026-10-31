/* app.js - the live demos for "Cloud Security Fundamentals".
   Every cloud here is a simulation: the policies, buckets, servers, metadata service, bills and policy checker
   run in your browser. No cloud account is touched and nothing is sent anywhere. */
(function () {
  "use strict";

  // --------------------------------------------------------------------------- helpers
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const sp = (cls, s) => `<span class="${cls}">${esc(s)}</span>`;
  function bind(ids, fn) { for (const id of [].concat(ids)) $(id).addEventListener("input", fn); fn(); }
  function click(id, fn) { $(id).addEventListener("click", fn); }
  const money = (n) => "$" + Math.round(n).toLocaleString("en-US");

  // --------------------------------------------------------------------------- title: a stranger lists our bucket
  function hero() {
    const el = $("hero-in"), v = el.value.trim();
    el.style.width = Math.max(8, el.value.length + 1) + "ch";
    const t = v.toLowerCase();
    $("hero-out").innerHTML = v
      ? `${sp("bad", "An error occurred (AccessDenied) when calling the ListObjectsV2 operation: Access Denied")}`
      : `${sp("m", "usage: storage ls s3://<bucket>")}`;
    let note = "# AccessDenied. Good: that's the answer strangers should get, every time.";
    if (t === "169.254.169.254" || t.startsWith("169.254.")) note = "# that's not a bucket, that's the metadata service's address. Hold that thought until part 3.";
    else if (t.includes("public")) note = "# a bucket called public. At least it's honest about it.";
    else if (t.includes("final")) note = "# final, final-v2, final-FINAL. Naming things: one of the two hard problems in computer science.";
    else if (t.includes("backup")) note = "# backups. In a different account from production, right? Right?";
    else if (!v) note = "# no bucket name, no listing. Even the error is useful.";
    $("hero-note").textContent = note;
  }

  // --------------------------------------------------------------------------- shared responsibility
  const ROWS = ["Your data", "Accounts and access", "Application code and settings", "Runtime and database engine",
    "Operating system and patches", "Network rules", "Virtualisation", "Hardware and buildings"];
  const MODELS = {
    onprem: { r: "yyyyyyyy", c: "# your own servers: every row is yours, down to the locks on the building." },
    iaas: { r: "yyyyybpp", c: "# virtual machines: the provider runs the hardware. You patch the operating system and everything above it." },
    paas: { r: "yyyppbpp", c: "# managed database: the provider patches the engine and the OS. You still decide who can connect, and what's in it." },
    saas: { r: "yybppppp", c: "# software as a service: the provider runs almost everything. Your data and who can sign in are still yours." },
  };
  let model = "iaas";
  function shared() {
    const m = MODELS[model];
    const who = { y: ["you", "You"], b: ["both", "Shared"], p: ["prov", "Provider"] };
    $("sr-stack").innerHTML = ROWS.map((r, i) => { const [cls, label] = who[m.r[i]]; return `<div class="sr-row ${cls}"><b>${esc(r)}</b><span>${label}</span></div>`; }).join("");
    $("sr-out").textContent = m.c;
    for (const b of $("sr-pick").querySelectorAll("button")) b.setAttribute("aria-pressed", String(b.dataset.m === model));
  }

  // --------------------------------------------------------------------------- policy simulator (AWS's evaluation order)
  const ORG = [
    { sid: "NoDeletingProdBuckets", eff: "Deny", act: ["s3:DeleteBucket"], res: ["prod-bucket"] },
    { sid: "NoNewIamUsers", eff: "Deny", act: ["iam:CreateUser"], res: ["*"] },
  ];
  const IDENTITY = {
    dev: [{ sid: "DevReadWrite", eff: "Allow", act: ["s3:GetObject", "s3:PutObject"], res: ["dev-bucket"] },
          { sid: "ProdRead", eff: "Allow", act: ["s3:GetObject"], res: ["prod-bucket"] }],
    ci: [{ sid: "DeploySite", eff: "Allow", act: ["s3:PutObject"], res: ["prod-bucket"] },
         { sid: "ManageServers", eff: "Allow", act: ["ec2:*"], res: ["*"] }],
    intern: [{ sid: "ReadDev", eff: "Allow", act: ["s3:GetObject"], res: ["dev-bucket"] }],
    old: [{ sid: "Everything", eff: "Allow", act: ["*"], res: ["*"] }],
  };
  const BUCKET = { "prod-bucket": [{ sid: "HttpsOnly", eff: "Deny", act: ["s3:*"], res: ["prod-bucket"], cond: "only when the request isn't HTTPS", tls: true }] };
  const WHO = { dev: "dev-role", ci: "ci-deploy role", intern: "intern", old: "old-admin key" };
  const actMatch = (pat, a) => pat === "*" || pat === a || (pat.endsWith(":*") && a.startsWith(pat.slice(0, -1)));
  const resMatch = (pat, r) => pat === "*" || pat === r;
  function matches(st, a, r, tls) {
    if (!st.act.some((p) => actMatch(p, a)) || !st.res.some((p) => resMatch(p, r))) return false;
    return st.tls ? !tls : true;
  }
  function simulate() {
    const who = $("ps-who").value, a = $("ps-act").value, r = $("ps-res").value, tls = $("ps-tls").checked;
    const sets = [{ name: "Organisation guardrail", sts: ORG }, { name: `${WHO[who]}: identity policy`, sts: IDENTITY[who] }];
    sets.push(BUCKET[r] ? { name: `${r}: bucket policy`, sts: BUCKET[r] } : { name: `${r}: no resource policy`, sts: [] });
    const hit = (st) => matches(st, a, r, tls);
    $("ps-policies").innerHTML = sets.map((s) => `<div class="pol"><b>${esc(s.name)}</b>` + (s.sts.length ? s.sts.map((st) => {
      const on = hit(st) ? (st.eff === "Deny" ? " hit-deny" : " hit-allow") : "";
      return `<div class="st${on}"><span class="${st.eff === "Deny" ? "bad" : "ok"}">${st.eff}</span> ${esc(st.act.join(", "))} <span class="m">on</span> ${esc(st.res.join(", "))}${st.cond ? ` <span class="m">${esc(st.cond)}</span>` : ""}<small>${esc(st.sid)}</small></div>`;
    }).join("") : `<div class="st m">nothing here</div>`) + `</div>`).join("");
    const all = sets.flatMap((s) => s.sts);
    const denies = all.filter((st) => st.eff === "Deny" && hit(st));
    const allows = all.filter((st) => st.eff === "Allow" && hit(st));
    const step = (q, ans, cls) => `<li><b>${esc(q)}</b><span class="${cls}">${esc(ans)}</span></li>`;
    let verdict, vcls, trace = step("1. Does any policy explicitly deny it?", denies.length ? "Yes: " + denies.map((d) => d.sid).join(", ") : "No", denies.length ? "bad" : "m");
    if (denies.length) { verdict = "DENIED: an explicit deny always wins"; vcls = "bad"; trace += step("2. Does anything allow it?", allows.length ? "Doesn't matter: " + allows.map((x) => x.sid).join(", ") + " is overruled" : "Doesn't matter", "m"); }
    else if (allows.length) { verdict = "ALLOWED by " + allows.map((x) => x.sid).join(", "); vcls = "ok"; trace += step("2. Does anything allow it?", "Yes: " + allows.map((x) => x.sid).join(", "), "ok"); }
    else { verdict = "DENIED: nothing allowed it (implicit deny)"; vcls = "bad"; trace += step("2. Does anything allow it?", "No", "m"); }
    $("ps-trace").innerHTML = trace;
    $("ps-verdict").className = "verdict " + vcls;
    $("ps-verdict").textContent = verdict;
    let note = denies.length ? "# deny wins, whoever wrote the allow." : allows.length ? "# allowed: exactly what the policy says, no more." : "# nothing said yes, so the answer is no. Silence means deny.";
    if (who === "intern" && a === "iam:CreateUser") note = "# the intern tried to create a user. No allow anywhere, and the organisation says no on top. Interns: ask for a role. (We love you.)";
    else if (who === "old" && denies.some((d) => d.sid === "NoDeletingProdBuckets")) note = "# \"*\" allowed it; the guardrail denied it. Deny beats even the all-powerful key.";
    else if (denies.some((d) => d.sid === "HttpsOnly")) note = "# the bucket refuses plain HTTP, whoever asks, whatever their policy says.";
    else if (who === "old" && allows.length && !denies.length) note = "# allowed by \"*\". \"Exactly what the policy says\" is the problem: this key's policy says everything.";
    else if (who === "ci" && a === "ec2:TerminateInstances") note = "# allowed by ec2:* on everything. A deploy job that can delete every server: does it need to?";
    $("ps-note").textContent = note;
  }

  // --------------------------------------------------------------------------- blast radius
  const TIMES = [["15 minutes", 0.25], ["1 hour", 1], ["6 hours", 6], ["1 day", 24], ["1 week", 168], ["1 month", 720], ["1 year", 8760], ["4 years", 35040]];
  const REACH = [
    ["Read customer data in prod-bucket", 1, 0],
    ["Upload files to the website", 1, 1],
    ["Start and delete servers", 1, 1],
    ["Create new access keys for itself", 1, 0],
  ];
  function blast() {
    const [label, h] = TIMES[+$("br-time").value];
    $("br-when").textContent = label + " after the leak";
    const card = (title, sub, live, status, col) => `<h3>${esc(title)}</h3><p class="m">${esc(sub)}</p>` +
      `<p class="br-status ${live ? "bad" : "ok"}">${esc(status)}</p><ul class="br-list">` +
      REACH.map((r) => { const can = live && r[col]; return `<li class="${can ? "can" : "cant"}"><span>${can ? "can" : "can't"}</span>${esc(r[0])}</li>`; }).join("") + "</ul>";
    $("br-key").innerHTML = card("Leaked: old-admin access key", "Long-lived, created 2022, allowed \"*\" on \"*\"", true, "Still works. It works until someone deletes it.", 1);
    const roleLive = h < 1;
    $("br-role").innerHTML = card("Leaked: ci-deploy role session", "Short-lived, issued to one CI job, scoped to deploying", roleLive,
      roleLive ? `Works for about ${Math.round((1 - h) * 60)} more minutes, then expires by itself.` : "Expired. Useless to the attacker now.", 2);
    let note = roleLive ? "# both are bad right now, but compare what each can reach. Scope is the first limit." : "# the role's session has expired. The key doesn't care what time it is.";
    if (h >= 35040) note = "# four years on, the key still works. Mandiant found Snowflake logins stolen in 2020 still working in 2024. Keys don't expire unless you make them.";
    $("br-note").textContent = note;
  }

  // --------------------------------------------------------------------------- public storage
  function storage() {
    const block = $("pub-block").checked, pol = $("pub-policy").value, acl = $("pub-acl").checked;
    const bucketPublic = pol === "public" && !block, aclPublic = acl && !block;
    const files = [["invoice-0001.pdf", bucketPublic], ["invoice-0002.pdf", bucketPublic], ["customers.csv", bucketPublic || aclPublic]];
    $("pub-view").innerHTML = `<b>acme-invoices</b>` + files.map(([f, open]) =>
      `<div class="pub-file ${open ? "open" : ""}"><span>${esc(f)}</span><em>${open ? "anyone on the internet can read" : "private"}</em></div>`).join("");
    let note = "# private: only our own roles can read it.";
    if (block && (pol === "public" || acl)) note = "# someone made it public, and the account-wide block quietly overruled them. That's the point of setting it once, above every bucket.";
    else if (bucketPublic) note = "# the whole bucket is public. One policy line, every invoice.";
    else if (aclPublic) note = "# one file made public by an old-style ACL. New buckets have ACLs switched off for exactly this reason; old ones may not.";
    $("pub-out").textContent = note;
  }

  // --------------------------------------------------------------------------- open ports
  const SOURCES = { internet: "0.0.0.0/0 (the internet)", vpn: "Office VPN (10.20.0.0/16)", web: "Web servers' security group", none: "Nobody (we use session tools)" };
  const NET = [{ p: 443, f: "Website (HTTPS)", s: "internet" }, { p: 22, f: "SSH (admin)", s: "internet" },
    { p: 5432, f: "PostgreSQL database", s: "internet" }, { p: 6379, f: "Redis cache", s: "internet" }];
  let extra = null;
  function netRows() {
    $("net-rows").innerHTML = NET.map((r, i) => `<tr class="${r.s === "internet" && r.p !== 443 ? "exposed" : ""}"><th>${r.p}</th><td>${esc(r.f)}</td><td><select data-i="${i}" aria-label="Who may reach port ${r.p}">` +
      Object.entries(SOURCES).map(([k, v]) => `<option value="${k}"${k === r.s ? " selected" : ""}>${esc(v)}</option>`).join("") + `</select></td></tr>`).join("") +
      (extra ? `<tr class="exposed"><th>${extra}</th><td>Something you added</td><td>${esc(SOURCES.internet)}</td></tr>` : "");
    const open = NET.filter((r) => r.s === "internet").length + (extra ? 1 : 0);
    const risky = NET.filter((r) => r.s === "internet" && r.p !== 443).map((r) => r.f);
    let note = risky.length ? `# ${open} port${open === 1 ? "" : "s"} open to the internet, including: ${risky.join(", ")}. Scanners will find them.` :
      open === 1 && NET[0].s === "internet" ? "# one port faces the internet, and it's the front door." : `# ${open} port${open === 1 ? "" : "s"} open to the internet.`;
    if (NET[0].s !== "internet" && !risky.length && !extra) note = "# nothing faces the internet, including the website. Very secure; very few customers.";
    if (extra === 1337) note = "# port 1337 open to the whole internet. Very elite. Very scanned.";
    else if (extra === 23) note = "# Telnet sends passwords in plain text, and its RFC (1983) is older than the web. Please use the session tools.";
    else if (extra === 3389) note = "# RDP open to the internet: put it behind a VPN or the provider's bastion instead.";
    else if (extra) note = `# port ${extra} is now open to everyone. Was that on purpose?`;
    $("net-out").textContent = note;
  }
  function netPort() {
    const v = $("net-port").value.trim(), n = Number(v);
    extra = v && Number.isInteger(n) && n >= 1 && n <= 65535 ? n : null;
    netRows();
    if (v && !extra) $("net-out").textContent = "# ports run from 1 to 65535. That one's not on the map.";
  }

  // --------------------------------------------------------------------------- the metadata service and SSRF
  const PRESETS = [["A normal page", "https://example.com/"], ["The role's name", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"],
    ["The role's credentials", "http://169.254.169.254/latest/meta-data/iam/security-credentials/web-app-role"], ["An internal admin page", "http://localhost:8080/admin"]];
  const isPrivate = (h) => /^(127\.|10\.|192\.168\.|169\.254\.|0\.)/.test(h) || /^172\.(1[6-9]|2\d|3[01])\./.test(h) || h === "localhost" || h === "[::1]" || h === "metadata.google.internal";
  function fetchSim() {
    const raw = $("md-url").value.trim(), v2 = $("md-v2").checked, block = $("md-block").checked;
    let out, note = "", u;
    try { u = new URL(raw); } catch (e) { $("md-out").textContent = "error: that isn't a URL"; $("md-out").dataset.note = ""; return; }
    const host = u.hostname;
    if (u.protocol === "file:") { out = "refused: file:// isn't http or https"; note = "# nice try. A link previewer should only ever speak http and https, and this one does."; }
    else if (!/^https?:$/.test(u.protocol)) { out = `refused: ${u.protocol} isn't http or https`; note = "# only http and https, by design."; }
    else if (block && isPrivate(host)) { out = `refused: ${host} is a private or link-local address`; note = "# stopped before the request even left. Allow-lists beat block-lists, but this already helps a lot."; }
    else if (host === "169.254.169.254") {
      if (v2) { out = "HTTP 401 Unauthorized"; note = "# IMDSv2 wants a session token from a PUT request with a special header first. A link preview can only send a plain GET, so it gets nothing."; }
      else if (/security-credentials\/web-app-role\/?$/.test(u.pathname)) {
        const exp = new Date(Date.now() + 6 * 3600e3).toISOString().slice(0, 19) + "Z";
        out = `HTTP 200\n{\n  "Code": "Success",\n  "Type": "AWS-HMAC",\n  "AccessKeyId": "ASIAIOSFODNN7EXAMPLE",\n  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",\n  "Token": "IQoJb3JpZ2luX2VjE…EXAMPLE",\n  "Expiration": "${exp}"\n}`;
        note = "# the server just handed its own role's credentials to a stranger. This is the Capital One pattern. (These keys are made-up examples.)";
      } else if (/security-credentials\/?$/.test(u.pathname)) { out = "HTTP 200\nweb-app-role"; note = "# the role's name. One more request gets its credentials."; }
      else if (u.pathname.startsWith("/latest/meta-data")) { out = "HTTP 200\nami-id\nhostname\niam/\ninstance-id\nlocal-ipv4\nplacement/\nsecurity-groups"; note = "# the server describing itself to anyone who asks it to fetch a URL."; }
      else { out = "HTTP 404 Not Found"; }
    }
    else if (host === "localhost" || host.startsWith("127.") || host === "[::1]") { out = "HTTP 200\n<h1>Internal admin</h1>\n<p>Only reachable from this server. Probably.</p>"; note = "# SSRF isn't only about the cloud: anything that trusts \"it came from inside\" is reachable too."; }
    else if (host === "example.com" || host === "www.example.com") { out = "HTTP 200\nTitle: Example Domain\nThis domain is for use in documentation examples without needing permission."; note = "# a normal preview. This is what the feature was for."; }
    else { out = `HTTP 200\nTitle: (a preview of ${host})`; note = "# fetched (in this simulation, nothing really leaves your browser)."; }
    $("md-out").textContent = out + (note ? "\n\n" + note : "");
  }

  // --------------------------------------------------------------------------- misconfiguration hunt
  const TF = [
    ['resource "aws_s3_bucket" "invoices" {'], ['  bucket = "acme-invoices"'], ["}"],
    ['resource "aws_s3_bucket_public_access_block" "invoices" {'], ["  bucket              = aws_s3_bucket.invoices.id"],
    ["  block_public_policy = false", "s3", "Bucket allows public bucket policies (block_public_policy = false)"], ["}"],
    ['resource "aws_security_group_rule" "admin" {'], ['  type        = "ingress"'], ["  from_port   = 22"], ["  to_port     = 22"],
    ['  cidr_blocks = ["0.0.0.0/0"]', "ssh", "SSH (port 22) open to 0.0.0.0/0"], ["}"],
    ['resource "aws_instance" "web" {'], ['  instance_type = "t3.small"'],
    ['  metadata_options { http_tokens = "optional" }', "imds", 'Instance metadata allows IMDSv1 (http_tokens should be "required")'],
    ["  root_block_device { encrypted = false }", "ebs", "Root disk is not encrypted"], ["}"],
    ['resource "aws_iam_role_policy" "web" {'], ["  role   = aws_iam_role.web.id"], ["  policy = jsonencode({ Statement = [{"],
    ['    Effect = "Allow", Action = "*", Resource = "*" }] })', "iam", 'Role policy allows every action on every resource ("*" on "*")'], ["}"],
    ['resource "aws_db_instance" "orders" {'], ['  engine              = "postgres"'],
    ["  publicly_accessible = true", "db", "Database is publicly accessible"], ["}"],
  ];
  const ISSUES = TF.filter((l) => l[1]).length;
  let flagged = new Set(), ran = false, byEye = false;
  function tfDraw() {
    $("tf-code").innerHTML = TF.map((l, i) => {
      let cls = flagged.has(i) ? "flag" : "";
      if (ran) cls = l[1] ? (flagged.has(i) ? "found" : "missed") : (flagged.has(i) ? "extra" : "");
      return `<li class="${cls}"><button type="button" data-i="${i}" aria-pressed="${flagged.has(i)}">${esc(l[0])}</button></li>`;
    }).join("");
    const good = [...flagged].filter((i) => TF[i][1]).length, extraFlags = flagged.size - good;
    $("tf-score").textContent = `${flagged.size} flagged`;
    if (!ran) { $("tf-findings").innerHTML = ""; $("tf-note").textContent = "# your move. Click the lines you'd question in a pull request."; return; }
    $("tf-findings").innerHTML = TF.map((l, i) => l[1] ? `<li class="${flagged.has(i) ? "ok" : "bad"}"><b>FAIL</b> line ${i + 1}: ${esc(l[2])}</li>` : "").join("") +
      `<li class="m"><b>PASS</b> ${TF.length - ISSUES} other lines</li>`;
    let note = `# you found ${good} of ${ISSUES}; the check found all ${ISSUES}.` + (extraFlags ? ` You also flagged ${extraFlags} line${extraFlags === 1 ? "" : "s"} it passed: worth a question in review, if you have a reason.` : "");
    if (byEye) note = `# ${ISSUES} of ${ISSUES} by eye, before the tool. The checker agrees, and it never gets tired. Use both.`;
    note += " (What no checker can tell you: whether this app should hold customer data at all.)";
    $("tf-note").textContent = note;
  }

  // --------------------------------------------------------------------------- billing alert
  const DAYS = Array.from({ length: 30 }, (_, i) => {
    const base = 40 + ((i * 37) % 11) - 5;                                    // a quiet, slightly wobbly month
    return i < 8 ? base : i === 8 ? base + 210 : base + 2300 + ((i * 53) % 300);   // a key leaks on day 9
  });
  const THRESH = [1, 50, 100, 250, 500, 1000, 2500, 5000, null];
  function billing() {
    const th = THRESH[+$("bill-th").value], max = Math.max(...DAYS), scale = (v) => Math.sqrt(v / max) * 100;
    $("bill-th-out").textContent = th === null ? "no alert" : `${money(th)} a day`;
    const fire = th === null ? -1 : DAYS.findIndex((d) => d > th);
    $("bill-chart").innerHTML = DAYS.map((d, i) => `<i class="${i >= 8 ? "mine" : ""}${i === fire ? " fire" : ""}" style="height:${scale(d).toFixed(1)}%" title="Day ${i + 1}: ${money(d)}"></i>`).join("") +
      (th !== null && th < max ? `<span class="bill-line" style="bottom:${scale(th).toFixed(1)}%"></span>` : "") + `<em class="bill-leak">key leaks</em>`;
    const total = DAYS.reduce((a, b) => a + b, 0), upTo = (n) => DAYS.slice(0, n + 1).reduce((a, b) => a + b, 0);
    let note;
    if (th === 1) note = "# an alert for every dollar, every day. By Tuesday everyone has muted it, and that's how real alerts get missed.";
    else if (fire === -1) note = `# no alert fired. You find out from the invoice: ${money(total)} for the month, about ${money(DAYS.slice(8).reduce((a, d) => a + d - 40, 0))} of it someone else's mining.`;
    else if (fire < 8) note = `# fires on day ${fire + 1}, before anything happened: a false alarm every day. Set it above your normal spend.`;
    else note = `# fires on day ${fire + 1}, the day it started showing. Spend so far ${money(upTo(fire))}, instead of ${money(total)} on the invoice.`;
    $("bill-out").textContent = note;
  }

  // --------------------------------------------------------------------------- the first-week checklist
  const STORE = "cloud-security-plan";
  function plan() {
    const boxes = [...$("plan-list").querySelectorAll("input")];
    let saved = [];
    try { saved = JSON.parse(localStorage.getItem(STORE) || "[]"); } catch (e) {}
    boxes.forEach((b, i) => { b.checked = !!saved[i]; });
    const upd = () => {
      const n = boxes.filter((b) => b.checked).length;
      try { localStorage.setItem(STORE, JSON.stringify(boxes.map((b) => b.checked))); } catch (e) {}
      $("plan-note").textContent = n === boxes.length ? "12 of 12. Your cloud is boring now. In security, that's the highest compliment." : `${n} of 12 done. This page remembers, on this device only.`;
      $("plan-note").classList.toggle("ok", n === boxes.length);
    };
    boxes.forEach((b) => b.addEventListener("change", upd));
    upd();
  }

  // --------------------------------------------------------------------------- easter eggs
  function consoleHint() {
    console.log("%cCloud Security", "font: 700 24px monospace; color: #ff2e88; text-shadow: 0 0 8px #ff2e88");
    console.log("%c169.254.169.254 is just a string on this page. On a cloud server it's the address that knows the server's secrets. Try it on the title slide.", "font: 14px monospace; color: #00f0ff");
  }

  function start() {
    consoleHint();
    bind("hero-in", hero);
    $("sr-pick").addEventListener("click", (e) => { const b = e.target.closest("button[data-m]"); if (b) { model = b.dataset.m; shared(); } });
    shared();
    for (const id of ["ps-who", "ps-act", "ps-res", "ps-tls"]) $(id).addEventListener("change", simulate);
    simulate();
    bind("br-time", blast);
    for (const id of ["pub-block", "pub-policy", "pub-acl"]) $(id).addEventListener("change", storage);
    storage();
    $("net-rows").addEventListener("change", (e) => { const s = e.target.closest("select[data-i]"); if (s) { NET[+s.dataset.i].s = s.value; netRows(); } });
    bind("net-port", netPort);
    $("md-presets").innerHTML = PRESETS.map(([l, u]) => `<button type="button" class="btn btn-ghost btn-sm" data-u="${esc(u)}">${esc(l)}</button>`).join("");
    $("md-presets").addEventListener("click", (e) => { const b = e.target.closest("button[data-u]"); if (b) { $("md-url").value = b.dataset.u; fetchSim(); } });
    click("md-go", fetchSim);
    $("md-url").addEventListener("keydown", (e) => { if (e.key === "Enter") fetchSim(); });
    for (const id of ["md-v2", "md-block"]) $(id).addEventListener("change", fetchSim);
    fetchSim();
    $("tf-code").addEventListener("click", (e) => { const b = e.target.closest("button[data-i]"); if (!b) return; const i = +b.dataset.i; flagged.has(i) ? flagged.delete(i) : flagged.add(i); tfDraw(); });
    click("tf-run", () => { if (!ran) byEye = flagged.size === ISSUES && [...flagged].every((i) => TF[i][1]); ran = true; tfDraw(); });
    click("tf-reset", () => { ran = byEye = false; flagged = new Set(); tfDraw(); });
    tfDraw();
    bind("bill-th", billing);
    plan();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
})();
