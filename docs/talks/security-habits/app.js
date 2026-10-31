/* app.js - the live demos for "Security Habits for New Developers". Everything here runs in the browser:
   the "server", "database" and "Git history" are small simulations, so nothing is sent anywhere. */
(function () {
  "use strict";

  // --------------------------------------------------------------------------- helpers
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const sp = (cls, s) => `<span class="${cls}">${esc(s)}</span>`;
  function bind(ids, fn) { for (const id of [].concat(ids)) $(id).addEventListener("input", fn); fn(); }
  function click(id, fn) { $(id).addEventListener("click", fn); }
  // xkcd 327: any demo field can meet Little Bobby Tables
  const bobby = (s) => /drop\s+table/i.test(s) ? `\n\n${sp("y", "Little Bobby Tables says hi. (xkcd 327) We hope you've learned to sanitise your database inputs.")}` : "";

  // --------------------------------------------------------------------------- title: trust()
  const QUIPS = ["it came from outside this code", "nice try", "I don't know where that's been", "input is guilty until validated",
    "even if you typed it yourself", "especially if it looks harmless"];
  function hero() {
    const el = $("hero-in"), v = el.value;
    el.style.width = Math.max(6, v.length + 1) + "ch";
    const t = v.trim().toLowerCase();
    let note = "# " + QUIPS[v.length % QUIPS.length];
    if (t === "me" || t === "myself") note = "# especially you. You're the one typing.";
    else if (t === "admin" || t === "root") note = "# claiming to be admin is exactly what an attacker would say.";
    else if (t === "") note = "# empty input is still input. Check it.";
    $("hero-out").innerHTML = `${sp("k", "source:")} outside your code<br>${sp("k", "trusted:")} ${sp("bad", "false")}  ${sp("m", "(always)")}`;
    $("hero-note").textContent = note;
    if (/drop\s+table/i.test(v)) $("hero-note").textContent = "# Little Bobby Tables says hi. (xkcd 327)";
  }

  // --------------------------------------------------------------------------- trust boundaries
  const FLOWS = [
    { id: "b-api", label: "Browser → API", from: "browser", to: "api", cross: true,
      check: ["validate every field (type, length, format)", "who is this? (authentication)", "may they do this, to this thing? (authorisation)", "limit how often (rate limits)"] },
    { id: "pay-api", label: "Payment webhook → API", from: "pay", to: "api", cross: true,
      check: ["verify the webhook's signature", "don't trust the amount in it: look the order up yourself", "handle the same event arriving twice"] },
    { id: "ai-api", label: "AI model reply → API", from: "ai", to: "api", cross: true,
      check: ["treat the reply as untrusted input", "never run code or commands it suggests unchecked", "limit which actions it can trigger"] },
    { id: "api-db", label: "API → database", from: "api", to: "db", cross: true,
      check: ["use query parameters, never glued strings", "a database user that can only do this app's job"] },
    { id: "api-b", label: "API → browser", from: "api", to: "browser", cross: true,
      check: ["encode output for HTML", "no stack traces or secrets in responses", "only the fields this user may see"] },
  ];
  let flowSel = 0;
  function flows() {
    $("flows").innerHTML = FLOWS.map((f, i) => `<button type="button" aria-pressed="${i === flowSel}" data-i="${i}">${esc(f.label)}</button>`).join("");
    const f = FLOWS[flowSel];
    for (const el of $("zones").querySelectorAll("[data-c]")) el.className = el.dataset.c === f.from ? "from" : el.dataset.c === f.to ? "to" : "";
    $("flow-out").innerHTML = `${sp("k", "flow")}      ${esc(f.label)}\n${sp("k", "boundary?")} ${f.cross ? sp("y", "yes: data changes hands") : sp("ok", "no")}\n\n${sp("c", "check here:")}\n` +
      f.check.map((c) => "  ▸ " + esc(c)).join("\n");
  }

  // --------------------------------------------------------------------------- SQL: data as code
  const STUDENTS = ["Ada", "Grace", "Linus", "Margaret", "Alan"];
  function sql() {
    const v = $("sql-in").value;
    const glued = `SELECT * FROM students WHERE name = '${v}'`;
    let res;
    if (/drop\s+table/i.test(v)) res = sp("bad", "students table: DROPPED");
    else if (/'\s*or\s*'?1'?\s*=\s*'?1/i.test(v) || /'\s*or\s+true/i.test(v)) res = sp("bad", `${STUDENTS.length} rows: ${STUDENTS.join(", ")}  (the condition is now always true)`);
    else if ((v.match(/'/g) || []).length % 2 === 1) res = sp("bad", `syntax error near "${v.slice(v.indexOf("'"))}'"`);
    else res = STUDENTS.includes(v) ? `1 row: ${esc(v)}` : sp("m", "0 rows");
    const safeRes = STUDENTS.includes(v) ? `1 row: ${esc(v)}` : sp("m", "0 rows (the whole text is one value)");
    $("sql-out").innerHTML = `${sp("bad", "glued together")}\n  ${esc(glued)}\n  → ${res}\n\n` +
      `${sp("ok", "with a parameter")}\n  SELECT * FROM students WHERE name = ?   ${sp("m", "[" + JSON.stringify(v) + "]")}\n  → ${safeRes}` + bobby(v);
  }

  // --------------------------------------------------------------------------- the shop that trusts the client
  const PRICE = 49.99;
  function shop() {
    const qty = Math.max(1, Math.min(99, parseInt($("shop-qty").value, 10) || 1));
    const raw = $("shop-price").value, sent = parseFloat(raw);
    const checked = $("shop-check").checked;
    const charged = checked ? PRICE : sent;
    let out = `${sp("k", "browser sends")}  { item: "neon-keyboard", qty: ${qty}, price: ${esc(JSON.stringify(raw))} }\n`;
    if (checked) out += `${sp("k", "server")}         looks up the price: $${PRICE.toFixed(2)} ${sp("m", "(ignores the client's price)")}\n${sp("ok", `charged $${(PRICE * qty).toFixed(2)}`)}`;
    else if (!Number.isFinite(sent)) out += `${sp("k", "server")}         believes the client\n${sp("bad", "500 Internal Server Error: price is not a number")}`;
    else {
      out += `${sp("k", "server")}         believes the client\n` + (charged === PRICE ? sp("ok", `charged $${(charged * qty).toFixed(2)}`) : sp("bad", `charged $${(charged * qty).toFixed(2)}  (should be $${(PRICE * qty).toFixed(2)})`));
      if (charged < 0) out += `\n\n${sp("y", "We now owe you money. Accounting has entered the chat.")}`;
      else if (charged === 0) out += `\n\n${sp("y", "Free keyboards for everyone! Finance would like a word.")}`;
    }
    $("shop-out").innerHTML = out + bobby(raw);
  }

  // --------------------------------------------------------------------------- encoding output
  function enc() {
    const v = $("enc-in").value;
    const tags = [...v.matchAll(/<\s*([a-z0-9]+)([^>]*)>/gi)];
    let raw = `${sp("k", "the browser reads")} ${esc(v)}\n\n`;
    if (!tags.length) raw += sp("ok", "no tags: plain text either way");
    else for (const t of tags) {
      const name = t[1].toLowerCase(), attrs = t[2];
      if (name === "script") raw += sp("bad", "<script>: runs JavaScript as your site") + "\n";
      else if (/\son\w+\s*=/i.test(attrs)) raw += sp("bad", `<${name}> with an ${(attrs.match(/\s(on\w+)/i) || [])[1]} handler: runs JavaScript`) + "\n";
      else if (/javascript:/i.test(attrs)) raw += sp("bad", `<${name}> with a javascript: link: runs when clicked`) + "\n";
      else raw += sp("y", `<${name}>: becomes real HTML on your page`) + "\n";
    }
    $("enc-raw").innerHTML = raw.trimEnd() + bobby(v);
    $("enc-safe").textContent = v;                    // the safe way: text, never HTML
  }

  // --------------------------------------------------------------------------- permissions on every request
  const INVOICES = { 1041: { owner: 3, who: "customer 3", total: "$1,280.00", item: "12 office chairs" },
    1042: { owner: 7, who: "you (customer 7)", total: "$49.99", item: "1 neon keyboard" },
    1043: { owner: 12, who: "customer 12", total: "$310.50", item: "a standing desk" } };
  function idor() {
    const raw = $("idor-in").value.trim(), id = parseInt(raw, 10), checked = $("idor-check").checked;
    const inv = INVOICES[id];
    let out = `${sp("k", "GET")} /invoices/${esc(raw)}   ${sp("m", "(signed in as customer 7)")}\n\n`;
    if (!inv) out += sp("m", "404 Not Found");
    else if (checked && inv.owner !== 7) out += `${sp("ok", "404 Not Found")}  ${sp("m", "(not yours, and we won't even say it exists)")}`;
    else out += `${inv.owner === 7 ? sp("ok", "200 OK") : sp("bad", "200 OK: someone else's invoice")}\n  customer: ${esc(inv.who)}\n  items:    ${esc(inv.item)}\n  total:    ${esc(inv.total)}`;
    $("idor-out").innerHTML = out + bobby(raw);
  }

  // --------------------------------------------------------------------------- a secret in Git history
  const KEY = 'PAY_API_KEY = "demo-not-a-real-key-7f3a9c"';
  let rotated = false, gitView = "log";
  function git() {
    const k = rotated ? `${sp("bad", KEY)}  ${sp("ok", "← revoked: worthless now")}` : sp("bad", KEY);
    let out;
    if (gitView === "log")
      out = `${sp("y", "c3e1a90")} Add tests for checkout\n${sp("y", "b72d4f1")} Oops, remove key\n${sp("y", "a91c0e2")} Add payment client\n\n${sp("m", "Looks clean. Try git log -p.")}`;
    else
      out = `${sp("y", "b72d4f1")} Oops, remove key\n${sp("bad", "- ")}${k}\n\n${sp("y", "a91c0e2")} Add payment client\n${sp("ok", "+ ")}import payments\n${sp("ok", "+ ")}${k}\n\n` +
        (rotated ? sp("ok", "Still in the history, but the key no longer works. That's the fix.") : sp("bad", "The key is still in the history. Anyone with a clone can read it."));
    $("git-out").innerHTML = out;
  }

  // --------------------------------------------------------------------------- failing safely
  function errors(fire) {
    const prod = $("err-prod").checked;
    if (!fire) { $("err-user").innerHTML = sp("m", "press Trigger the bug"); $("err-log").innerHTML = sp("m", "(nothing yet)"); return; }
    const ref = "ERR-" + Math.floor(Math.random() * 0xffff).toString(16).toUpperCase().padStart(4, "0");
    const trace = `TypeError: cannot read 'total' of undefined\n  at checkout (app/orders.js:88)\n  at db.query("SELECT * FROM orders WHERE id = 1042")`;
    $("err-user").innerHTML = prod
      ? `Something went wrong on our side.\nPlease try again, or contact support\nwith reference ${sp("y", ref)}.`
      : `${sp("bad", trace)}\n${sp("bad", "DATABASE_URL=postgres://app:hunter2@db.internal:5432/shop")}\n\n${sp("y", "hunter2? All I see is *******. (So can everyone else.)")}`;
    $("err-log").innerHTML = `${sp("k", "ref")}   ${ref}\n${sp("k", "user")}  customer 7\n${esc(trace)}\n${sp("k", "db")}    postgres://app:${sp("ok", "[REDACTED]")}@db.internal`;
  }

  // --------------------------------------------------------------------------- least privilege
  const PERM = { "read:orders": "read every order", "write:orders": "change or cancel orders", "read:customers": "read customers' names, emails and addresses",
    refunds: "send refunds to an account they choose", admin: "create users, change settings, delete anything", "never-expires": "keep doing all of this until someone notices" };
  function perms() {
    const on = [...$("perms").querySelectorAll("input:checked")].map((i) => i.dataset.p);
    const extra = on.filter((p) => p !== "read:orders").length;
    let out = `${sp("k", "if this token leaks, an attacker can:")}\n` + (on.length ? on.map((p) => (p === "read:orders" ? "  ▸ " : sp("bad", "  ▸ ")) + esc(PERM[p])).join("\n") : sp("m", "  nothing. (The report can't run either, though.)"));
    out += `\n\n${extra === 0 && on.length ? sp("ok", "Least privilege: exactly what the job needs.") : extra ? sp("bad", `${extra} permission${extra > 1 ? "s" : ""} more than the job needs.`) : ""}`;
    if (on.length === Object.keys(PERM).length) out += `\n\n${sp("y", "Congratulations: you've built a skeleton key for a sales report.")}`;
    $("perm-out").innerHTML = out;
  }

  // --------------------------------------------------------------------------- the checklist and the Habit Machine
  const STORE = "security-habits-checklist";
  function checklist() {
    const boxes = [...$("habits").querySelectorAll("input")];
    let saved = [];
    try { saved = JSON.parse(localStorage.getItem(STORE) || "[]"); } catch (e) {}
    boxes.forEach((b, i) => { b.checked = !!saved[i]; });
    const upd = () => {
      const n = boxes.filter((b) => b.checked).length;
      try { localStorage.setItem(STORE, JSON.stringify(boxes.map((b) => b.checked))); } catch (e) {}
      $("habit-count").textContent = n === boxes.length ? "10 of 10. You are the Habit Machine." : `${n} of 10 ticked. This page remembers, on this device only.`;
      $("machine").classList.toggle("on", n === boxes.length);
    };
    boxes.forEach((b) => b.addEventListener("change", upd));
    upd();
  }

  // --------------------------------------------------------------------------- easter eggs
  function consoleHint() {
    console.log("%cSecurity Habits", "font: 700 24px monospace; color: #ff2e88; text-shadow: 0 0 8px #ff2e88");
    console.log("%cReal developers read the console. So do attackers. Say hi to both.", "font: 14px monospace; color: #00f0ff");
    console.log("%cEverything on this page that looks like a server is JavaScript in your browser. Which is the point.", "font: 12px monospace; color: #f6e94b");
  }

  function start() {
    consoleHint();
    bind("hero-in", hero);
    $("flows").addEventListener("click", (e) => { const b = e.target.closest("button"); if (b) { flowSel = +b.dataset.i; flows(); } });
    flows();
    bind("sql-in", sql);
    document.querySelectorAll("[data-sql]").forEach((b) => b.addEventListener("click", () => { $("sql-in").value = b.dataset.sql; sql(); }));
    bind(["shop-qty", "shop-price"], shop);
    $("shop-check").addEventListener("change", shop);
    click("shop-buy", shop);
    bind("enc-in", enc);
    bind("idor-in", idor);
    $("idor-check").addEventListener("change", idor);
    click("git-log", () => { gitView = "log"; git(); });
    click("git-patch", () => { gitView = "patch"; git(); });
    click("git-rotate", () => { rotated = true; gitView = "patch"; git(); });
    git();
    click("err-go", () => errors(true));
    $("err-prod").addEventListener("change", () => errors(true));
    errors(false);
    $("perms").addEventListener("change", perms);
    perms();
    checklist();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
})();
