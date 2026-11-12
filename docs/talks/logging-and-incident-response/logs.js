/* logs.js - the logic and the made-up data behind the demos in "Logging, Monitoring and Incident Response".
   Pure functions, no DOM, so it runs in the browser (window.Logs) and in Node (module.exports) for testing.
   Everything here is a simulation: the logs, accounts, addresses (documentation ranges only) and incidents are invented.
   The hash chain uses the real SHA-256 and HMAC-SHA-256 from ../../shared/crypto.js (teaching code: never use it to protect real logs). */
(function (root) {
  "use strict";
  const Lab = root.Lab || (typeof require === "function" ? require("../../shared/crypto.js") : null);

  // a small seeded random generator, so the "random" data is the same every time (mulberry32)
  function rng(seed) {
    let a = seed >>> 0;
    return function () {
      a = (a + 0x6d2b79f5) >>> 0; let t = a;
      t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  // =========================================================================== 1. the log-line linter (title slide, slide 4)
  // Five questions every log line should answer. A toy: it looks for shapes, not truth.
  const RX = {
    isoZ: /\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?\s?(?:Z|[+-]\d{2}:?\d{2})(?![\w])/,
    epoch: /\b1\d{9}(?:\d{3})?\b/,
    isoNoZone: /\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?\b/,
    syslog: /\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s{1,2}\d{1,2}\s\d{2}:\d{2}:\d{2}\b/,
    timeOnly: /\b\d{1,2}:\d{2}(?::\d{2})?\b/,
    whoKey: /\b(?:user(?:name)?|usr|account|acct|uid|principal|actor|subject|by)\s*[=:]\s*["']?([\w.@\\-]+)/i,
    whoWord: /\b(?:for|by)\s+(?:invalid\s+user\s+)?([A-Za-z][\w.@-]+)/i,
    email: /\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b/,
    what: /\b(log(?:ged)?[ -]?(?:in|on|out|off)|login|logon|logoff|logout|sign(?:ed)?[ -]?(?:in|out)|signin|authenticat\w*|creat(?:e|ed|ion)|delet(?:e|ed)|disabl(?:e|ed)|enabl(?:e|ed)|grant(?:ed)?|revok(?:e|ed)|chang(?:e|ed)|modif(?:y|ied)|add(?:ed)?|remov(?:e|ed)|clear(?:ed)?|stopp?(?:ed)?|start(?:ed)?|download(?:ed)?|upload(?:ed)?|access(?:ed)?|read|wrote|write|execut(?:e|ed)|install(?:ed)?|reset|export(?:ed)?|connect(?:ed|ion)?|session)\b/i,
    action: /\baction\s*[=:]\s*([\w.-]+)/i,
    ip4: /\b(?:\d{1,3}\.){3}\d{1,3}\b/,
    whereKey: /\b(?:src|source|from|host|hostname|ip|client|device|dst|addr|address)\s*[=:]\s*(\S+)/i,
    whereFrom: /\bfrom\s+([\w][\w.-]*)/i,
    outcome: /\b(success(?:ful(?:ly)?)?|succeeded|fail(?:ed|ure|ures)?|denied|allowed|blocked|rejected|refused|accepted|error|timeout|ok)\b/i,
    outcomeKey: /\b(?:outcome|result|status)\s*[=:]\s*([\w.-]+)/i,
    secretKey: /\b(pass(?:word|wd)?|pwd|secret|token|api[_-]?key|authorization)\s*[=:]\s*\S+/i,
    bearer: /\bBearer\s+[A-Za-z0-9._~+\/-]{10,}/,
    cardish: /\b(?:\d[ -]?){13,19}\b/,
  };
  const NOT_A_NAME = new Set(["user", "users", "account", "the", "a", "an", "this", "that", "it", "you", "them", "all", "any", "some", "now", "one", "unknown", "example"]);
  function luhn(digits) {
    let sum = 0, alt = false;
    for (let i = digits.length - 1; i >= 0; i--) { let n = digits.charCodeAt(i) - 48; if (alt) { n *= 2; if (n > 9) n -= 9; } sum += n; alt = !alt; }
    return sum % 10 === 0;
  }
  function findSecret(line) {
    let m = RX.secretKey.exec(line);
    if (m) return m[1].toLowerCase().startsWith("pass") || m[1].toLowerCase() === "pwd" ? "a password" : "a " + m[1].toLowerCase().replace(/[_-]/g, " ");
    if (RX.bearer.test(line)) return "a bearer token";
    const c = RX.cardish.exec(line);
    if (c) { const d = c[0].replace(/[ -]/g, ""); if (d.length >= 13 && d.length <= 19 && luhn(d)) return "a card number"; }
    return null;
  }
  /** score one log line against the five questions. Returns { checks:[{k,label,state,note}], score, secret } */
  function lint(line) {
    const s = String(line);
    const checks = [];
    // when
    let when;
    if (RX.isoZ.test(s)) when = { state: "ok", note: "a full date, time and time zone" };
    else if (RX.epoch.test(s)) when = { state: "ok", note: "Unix time: always UTC" };
    else if (RX.isoNoZone.test(s)) when = { state: "part", note: "no time zone: whose clock is it?" };
    else if (RX.syslog.test(s)) when = { state: "part", note: "no year and no time zone" };
    else if (RX.timeOnly.test(s)) when = { state: "part", note: "a time of day, but no date or zone" };
    else when = { state: "bad", note: "no time. Try 2026-11-09T03:12:44Z" };
    checks.push({ k: "when", label: "when", ...when });
    // who
    let who = null, m = RX.whoKey.exec(s);
    if (m && !NOT_A_NAME.has(m[1].toLowerCase())) who = m[1];
    if (!who) { m = RX.whoWord.exec(s); if (m && !NOT_A_NAME.has(m[1].toLowerCase())) who = m[1]; }
    if (!who) { m = RX.email.exec(s); if (m) who = m[0]; }
    checks.push({ k: "who", label: "who", state: who ? "ok" : "bad", note: who ? who : "no account named" });
    // what
    m = RX.action.exec(s) || RX.what.exec(s);
    checks.push({ k: "what", label: "what", state: m ? "ok" : "bad", note: m ? (m[1] || m[0]).toLowerCase() : "no action named" });
    // where
    m = RX.ip4.exec(s) || RX.whereKey.exec(s) || RX.whereFrom.exec(s);
    checks.push({ k: "where", label: "where from", state: m ? "ok" : "bad", note: m ? (m[1] || m[0]) : "no address or host" });
    // outcome
    m = RX.outcomeKey.exec(s) || RX.outcome.exec(s);
    checks.push({ k: "outcome", label: "outcome", state: m ? "ok" : "bad", note: m ? (m[1] || m[0]).toLowerCase() : "did it work?" });
    return { checks, score: checks.filter((c) => c.state === "ok").length, secret: findSecret(s) };
  }

  // =========================================================================== 2. clocks: the same six events, three different stories
  const TIME_EVENTS = [
    { id: "vpn",  host: "vpn-gw",      text: "session start user=dana src=198.51.100.23", utc: "2026-11-09T03:12:40Z", written: "2026-11-08 22:12:40", kind: "local",  offsetMin: -300, driftMin: 0 },
    { id: "idp",  host: "idp",         text: "login success user=dana mfa=push",            utc: "2026-11-09T03:12:44Z", written: "2026-11-09T03:12:44Z", kind: "utc",    offsetMin: 0,    driftMin: 0 },
    { id: "read", host: "file-srv",    text: "read /hr/payroll.xlsx user=dana",             utc: "2026-11-09T03:13:02Z", written: "Nov  9 03:06:02",      kind: "syslog", offsetMin: 0,    driftMin: -7 },
    { id: "acct", host: "idp",         text: "account created svc-backup2 by=dana",         utc: "2026-11-09T03:14:10Z", written: "2026-11-09T03:14:10Z", kind: "utc",    offsetMin: 0,    driftMin: 0 },
    { id: "stop", host: "cloud-audit", text: "StopLogging trail=main by=dana",              utc: "2026-11-09T03:15:20Z", written: "2026-11-09T03:15:20Z", kind: "utc",    offsetMin: 0,    driftMin: 0 },
    { id: "bulk", host: "file-srv",    text: "bulk copy 4,200 files user=dana",             utc: "2026-11-09T03:16:41Z", written: "Nov  9 03:09:41",      kind: "syslog", offsetMin: 0,    driftMin: -7 },
  ];
  const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  /** where does a naive tool place an event? mode: "raw" (take the text at face value), "zone" (fix time zones), "drift" (also fix the slow clock) */
  function placeEvent(ev, mode) {
    let ms;
    if (ev.kind === "syslog") {
      const m = /^(\w{3})\s+(\d+)\s(\d\d):(\d\d):(\d\d)$/.exec(ev.written);
      ms = Date.UTC(2026, MONTHS.indexOf(m[1]), +m[2], +m[3], +m[4], +m[5]);            // the year had to be guessed
    } else if (ev.kind === "local") {
      const m = /^(\d{4})-(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d)$/.exec(ev.written);
      ms = Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]);                       // read as if it were UTC
    } else ms = Date.parse(ev.written);
    if (mode === "zone" || mode === "drift") if (ev.kind === "local") ms -= ev.offsetMin * 60000;
    if (mode === "drift") ms -= ev.driftMin * 60000;
    return ms;
  }
  function orderEvents(mode) {
    const rows = TIME_EVENTS.map((ev) => ({ ev, ms: placeEvent(ev, mode) }));
    rows.sort((a, b) => a.ms - b.ms);
    const isTrue = rows.every((r, i) => r.ev.id === TIME_EVENTS[i].id);
    return { rows, isTrue };
  }

  // =========================================================================== 3. a tamper-evident log: a hash chain
  const GENESIS = "0".repeat(64);
  const CHAIN_TEXTS = [
    "03:12:44Z login success user=dana src=203.0.113.50",
    "03:14:10Z account created svc-backup2 by=dana",
    "03:15:20Z audit logging disabled by=dana",
    "03:16:41Z bulk read 4200 files user=dana",
    "03:21:09Z outbound transfer 4.2GB dst=198.51.100.77",
    "03:30:00Z session end user=dana",
  ];
  function link(prevHex, text, key) {
    const msg = Lab.utf8(prevHex + "|" + text);
    return Lab.hex(key ? Lab.hmacSha256(key, msg) : Lab.sha256(msg));
  }
  function chainBuild(texts, key) {
    const out = []; let prev = GENESIS;
    texts.forEach((t, i) => { const h = link(prev, t, key); out.push({ n: i + 1, text: t, prev, hash: h }); prev = h; });
    return out;
  }
  /** check every entry. rows[i].ok is false where the text, the hash or the link to the previous entry doesn't add up. */
  function chainVerify(entries, key, anchor) {
    const rows = entries.map((e, i) => {
      const wantPrev = i === 0 ? GENESIS : entries[i - 1].hash;
      if (e.prev !== wantPrev) return { n: e.n, ok: false, why: "link broken" };
      if (link(e.prev, e.text, key) !== e.hash) return { n: e.n, ok: false, why: "hash mismatch" };
      return { n: e.n, ok: true, why: "" };
    });
    const head = entries.length ? entries[entries.length - 1].hash : GENESIS;
    const headOk = anchor === undefined || anchor === null ? null : head === anchor;
    return { rows, headOk, internallyOk: rows.every((r) => r.ok) };
  }
  // what an attacker with write access to the log can do. They never have the defender's HMAC key, so they can only use plain SHA-256.
  const attack = {
    editText(entries, i, text) { return entries.map((e, j) => (j === i ? { ...e, text } : { ...e })); },
    editFixHash(entries, i, text) { return entries.map((e, j) => (j === i ? { ...e, text, hash: link(e.prev, text, null) } : { ...e })); },
    rewriteAll(entries, i, text) {
      const out = []; let prev = i === 0 ? GENESIS : entries[i - 1].hash;
      entries.forEach((e, j) => {
        if (j < i) { out.push({ ...e }); return; }
        const t = j === i ? text : e.text, h = link(prev, t, null);
        out.push({ n: e.n, text: t, prev, hash: h }); prev = h;
      });
      return out;
    },
    deleteEntry(entries, i) { return entries.filter((_, j) => j !== i).map((e) => ({ ...e })); },
    truncate(entries, keep) { return entries.slice(0, keep).map((e) => ({ ...e })); },
  };

  // =========================================================================== 4. the log explorer: a small, made-up log with an attack in it
  // each row: [time UTC, host, user, action, outcome, src, geo, detail, story group or 0]
  const D8 = "2026-11-08T", D9 = "2026-11-09T";
  const RAW = [
    [D8 + "22:05:12Z", "idp", "ravi", "login", "success", "192.0.2.31", "HQ", "mfa=push", 0],
    [D8 + "22:14:40Z", "idp", "mei", "login", "failure", "192.0.2.52", "HQ", "bad password", 0],
    [D8 + "22:15:03Z", "idp", "mei", "login", "success", "192.0.2.52", "HQ", "mfa=push", 0],
    [D8 + "22:30:00Z", "file-srv", "svc-backup", "bulk_read", "success", "192.0.2.40", "HQ", "1,200 files /projects (nightly backup)", 0],
    [D8 + "22:41:19Z", "idp", "omar", "login", "failure", "192.0.2.77", "HQ", "bad password", 0],
    [D8 + "22:41:48Z", "idp", "omar", "login", "success", "192.0.2.77", "HQ", "mfa=push", 0],
    [D8 + "22:58:07Z", "vpn", "lena", "login", "success", "198.51.100.9", "home", "mfa=push", 0],
    [D8 + "23:15:44Z", "idp", "priya", "login", "success", "198.51.100.200", "new city", "hotel Wi-Fi, mfa=push, travel approved (TRV-0412)", 0],
    [D8 + "23:40:02Z", "idp", "ops-admin", "account_created", "success", "192.0.2.5", "HQ", "svc-print, ticket CHG-2214", 0],
    [D8 + "23:40:30Z", "idp", "ops-admin", "role_granted", "success", "192.0.2.5", "HQ", "svc-print to Print Operators, ticket CHG-2214", 0],
    [D9 + "00:03:11Z", "vpn", "lena", "logout", "success", "198.51.100.9", "home", "session 1h05m", 0],
    [D9 + "00:20:33Z", "idp", "tomas", "login", "failure", "192.0.2.64", "HQ", "bad password", 0],
    [D9 + "00:21:05Z", "idp", "tomas", "login", "failure", "192.0.2.64", "HQ", "bad password", 0],
    [D9 + "00:21:40Z", "idp", "tomas", "login", "success", "192.0.2.64", "HQ", "mfa=push", 0],
    [D9 + "00:48:30Z", "file-srv", "mei", "file_read", "success", "192.0.2.52", "HQ", "/projects/plan.docx", 0],
    [D9 + "01:15:50Z", "file-srv", "svc-backup", "file_read", "success", "192.0.2.40", "HQ", "/projects/archive (nightly backup)", 0],
    // the attack: a password spray (one source, many accounts, one try each)
    [D9 + "01:41:03Z", "idp", "amir", "login", "failure", "203.0.113.50", "new country", "bad password", 1],
    [D9 + "01:41:41Z", "idp", "bea", "login", "failure", "203.0.113.50", "new country", "bad password", 1],
    [D9 + "01:42:20Z", "idp", "chen", "login", "failure", "203.0.113.50", "new country", "bad password", 1],
    [D9 + "01:43:02Z", "idp", "dana", "login", "failure", "203.0.113.50", "new country", "bad password", 1],
    [D9 + "01:43:47Z", "idp", "eli", "login", "failure", "203.0.113.50", "new country", "bad password", 1],
    [D9 + "01:44:31Z", "idp", "fay", "login", "failure", "203.0.113.50", "new country", "bad password", 1],
    [D9 + "01:45:15Z", "idp", "gus", "login", "failure", "203.0.113.50", "new country", "bad password", 1],
    [D9 + "01:46:03Z", "idp", "hana", "login", "failure", "203.0.113.50", "new country", "bad password", 1],
    [D9 + "01:46:49Z", "idp", "ivan", "login", "failure", "203.0.113.50", "new country", "bad password", 1],
    [D9 + "01:47:30Z", "idp", "jo", "login", "failure", "203.0.113.50", "new country", "bad password", 1],
    [D9 + "01:48:12Z", "idp", "kai", "login", "failure", "203.0.113.50", "new country", "bad password", 1],
    [D9 + "01:49:37Z", "idp", "lena", "login", "failure", "203.0.113.50", "new country", "bad password", 1],
    [D9 + "01:52:10Z", "idp", "dana", "login", "success", "203.0.113.50", "new country", "legacy protocol, no MFA", 2],
    [D9 + "02:17:05Z", "idp", "dana", "account_created", "success", "203.0.113.50", "new country", "svc-backup2, no ticket", 3],
    [D9 + "02:18:40Z", "idp", "dana", "role_granted", "success", "203.0.113.50", "new country", "svc-backup2 to Admins, no ticket", 4],
    [D9 + "02:24:11Z", "idp", "svc-backup2", "login", "success", "203.0.113.50", "new country", "service account, interactive sign-in", 5],
    [D9 + "02:31:52Z", "cloud-audit", "svc-backup2", "logging_disabled", "success", "203.0.113.50", "new country", "audit trail stopped (StopLogging)", 6],
    [D9 + "02:41:09Z", "file-srv", "svc-backup2", "bulk_read", "success", "203.0.113.50", "new country", "3,400 files /finance", 7],
    [D9 + "02:44:30Z", "fw", "svc-backup2", "outbound_transfer", "success", "10.0.4.12", "internal", "4.2 GB to 198.51.100.77", 8],
    // more ordinary night-time activity
    [D9 + "03:02:40Z", "idp", "ops-admin", "login", "success", "192.0.2.5", "HQ", "mfa=push", 0],
    [D9 + "03:30:00Z", "file-srv", "svc-backup", "bulk_read", "success", "192.0.2.40", "HQ", "1,150 files /projects (nightly backup)", 0],
    [D9 + "03:45:12Z", "idp", "ravi", "login", "success", "192.0.2.31", "HQ", "mfa=push", 0],
  ];
  const LOG = RAW.map((r, i) => ({ id: i + 1, t: r[0], host: r[1], user: r[2], action: r[3], outcome: r[4], src: r[5], geo: r[6], detail: r[7], story: r[8] }));
  const STORY = [
    null,
    { n: 1, hint: "Look at failed sign-ins from one address.", title: "A password spray", why: "One address tried one password against twelve accounts: no single account failed more than once, so a per-account lockout never noticed." },
    { n: 2, hint: "Did anyone succeed from that address afterwards?", title: "A spray victim signs in", why: "dana's password was one of the guesses. The sign-in used a legacy protocol, which skips MFA." },
    { n: 3, hint: "Who created an account, and is there a change ticket?", title: "A new account", why: "svc-backup2 was created with no change ticket. Compare the ops-admin account created earlier, which had one." },
    { n: 4, hint: "Who was given administrator rights?", title: "Made an administrator", why: "The new account was added to Admins, again with no ticket." },
    { n: 5, hint: "Who signed in as the new account?", title: "The new account signs in", why: "A service account with an interactive sign-in from the same new address." },
    { n: 6, hint: "Did anything switch logging off?", title: "Logging switched off", why: "The audit trail was stopped. Everything after this is missing from that log, so you need the other sources." },
    { n: 7, hint: "Search for a large burst of reads.", title: "Bulk read", why: "3,400 files read in one burst from the finance share. The nightly backup reads about 1,200 and always comes from 192.0.2.40." },
    { n: 8, hint: "Did data leave? Try the firewall.", title: "Data leaves", why: "4.2 GB went to an address nobody at the company uses." },
  ];
  const FIELDS = ["host", "user", "action", "outcome", "src", "geo", "detail", "t"];
  /** a tiny query language: words match anywhere; field:value matches that field; a leading - excludes. Quotes keep spaces. */
  function parseQuery(q) {
    const toks = [], re = /(-?)(?:(\w+):)?("[^"]*"|\S+)/g;
    let m;
    while ((m = re.exec(q || ""))) {
      const neg = m[1] === "-", field = m[2] && FIELDS.includes(m[2].toLowerCase()) ? m[2].toLowerCase() : null;
      let val = m[3];
      if (m[2] && !field) val = m[2] + ":" + m[3];                 // an unknown "field:" is just text
      val = val.replace(/^"|"$/g, "").toLowerCase();
      if (val) toks.push({ neg, field, val });
    }
    return toks;
  }
  function search(events, q) {
    const toks = parseQuery(q);
    if (!toks.length) return events.slice();
    return events.filter((e) => toks.every((t) => {
      const hay = t.field ? String(e[t.field]).toLowerCase() : FIELDS.map((f) => e[f]).join(" ").toLowerCase();
      return hay.includes(t.val) !== t.neg;
    }));
  }
  /** score a case file: which of the eight story groups did the flagged rows cover, and how many flags were off target? */
  function checkCase(flaggedIds) {
    const flagged = LOG.filter((e) => flaggedIds.includes(e.id));
    const found = new Set(flagged.filter((e) => e.story).map((e) => e.story));
    const missed = []; for (let g = 1; g <= 8; g++) if (!found.has(g)) missed.push(g);
    return { found: [...found].sort((a, b) => a - b), missed, falseFlags: flagged.filter((e) => !e.story).length, total: flagged.length };
  }

  // =========================================================================== 5. the alert-tuning lab
  const DAY = 1440;
  /** a week of failed sign-ins (minutes from Monday 00:00), with three real attacks hidden among the noise. */
  function authSim(seed) {
    const r = rng(seed == null ? 2026 : seed), ev = [];
    const users = Array.from({ length: 300 }, (_, i) => "u" + String(i + 1).padStart(3, "0"));
    const officeIp = (u) => "192.0.2." + (1 + (parseInt(u.slice(1), 10) % 20));      // twenty shared addresses, as behind office NAT
    const poisson = (lam) => { const L = Math.exp(-lam); let k = 0, p = 1; do { k++; p *= r(); } while (p > L); return k - 1; };
    for (let d = 0; d < 7; d++) {
      const weekday = d < 5, rate = weekday ? 0.4 : 0.04;
      for (const u of users) {
        const n = poisson(rate);
        for (let i = 0; i < n; i++) ev.push({ t: d * DAY + 480 + r() * 600, user: u, src: officeIp(u), atk: 0 });          // a typo, some time between 08:00 and 18:00
        if (weekday && r() < 0.025) {                                                                                       // a forgotten password: a burst of retries
          const t0 = d * DAY + 480 + r() * 600, k = 6 + Math.floor(r() * 5);
          for (let i = 0; i < k; i++) ev.push({ t: t0 + (i / k) * 3, user: u, src: officeIp(u), atk: 0 });
        }
      }
    }
    for (const d of [2, 3]) for (let m = 0; m < 120; m += 2) ev.push({ t: d * DAY + 540 + m, user: "svc-sync", src: "192.0.2.201", atk: 0 });   // a misconfigured service, every two minutes
    for (let i = 0; i < 25; i++) ev.push({ t: 1 * DAY + 510 + r() * 120, user: "u" + String(261 + i).padStart(3, "0"), src: "192.0.2.99", atk: 0 });   // a shared kiosk
    const A0 = 1 * DAY + 100;                                                                                               // attack 1: spray, Tuesday 01:40
    for (let i = 0; i < 40; i++) ev.push({ t: A0 + (i * 8) / 40, user: "u" + String(101 + i).padStart(3, "0"), src: "203.0.113.50", atk: 1 });
    const B0 = 3 * DAY + 14 * 60 + 5;                                                                                       // attack 2: brute force, Thursday 14:05
    for (let i = 0; i < 60; i++) ev.push({ t: B0 + (i * 3) / 60, user: "u007", src: "198.51.100.23", atk: 2 });
    const C0 = 5 * DAY + 120;                                                                                               // attack 3: slow spray, Saturday 02:00 for six hours
    for (let i = 0; i < 30; i++) ev.push({ t: C0 + i * 12 + r() * 6, user: "u" + String(201 + i).padStart(3, "0"), src: "203.0.113.77", atk: 3 });
    ev.sort((a, b) => a.t - b.t);
    return { events: ev, attacks: [null, { id: 1, name: "password spray (8 min)" }, { id: 2, name: "brute force (3 min)" }, { id: 3, name: "slow spray (6 hours)" }] };
  }
  /** rule "account": alert when one account has >= n failures within w minutes. rule "source": when one address has failed against >= n different accounts within w minutes. */
  function runRule(sim, rule, n, w) {
    const alerts = [], state = new Map(), quiet = new Map();
    for (const e of sim.events) {
      const key = rule === "account" ? e.user : e.src;
      let st = state.get(key); if (!st) { st = { items: [], who: new Map() }; state.set(key, st); }
      st.items.push(e); st.who.set(e.user, (st.who.get(e.user) || 0) + 1);
      while (st.items.length && st.items[0].t < e.t - w) {
        const o = st.items.shift(), c = st.who.get(o.user) - 1;
        if (c <= 0) st.who.delete(o.user); else st.who.set(o.user, c);
      }
      const count = rule === "account" ? st.items.length : st.who.size;
      if (count >= n && !(quiet.get(key) > e.t)) { alerts.push({ t: e.t, key, atk: e.atk }); quiet.set(key, e.t + w); }
    }
    const caught = [...new Set(alerts.filter((a) => a.atk).map((a) => a.atk))].sort();
    const falseAlerts = alerts.filter((a) => !a.atk).length;
    const days = Array.from({ length: 7 }, () => ({ f: 0, t: 0 }));
    for (const a of alerts) days[Math.min(6, Math.floor(a.t / DAY))][a.atk ? "t" : "f"]++;
    return { alerts: alerts.length, falseAlerts, trueAlerts: alerts.length - falseAlerts, caught, perDay: falseAlerts / 7, days };
  }
  /** both rules at once: the per-address rule you choose, plus a per-account rule of 15 failures in 10 minutes */
  function runBoth(sim, n, w) {
    const a = runRule(sim, "source", n, w), b = runRule(sim, "account", 15, 10);
    const caught = [...new Set(a.caught.concat(b.caught))].sort(), falseAlerts = a.falseAlerts + b.falseAlerts;
    const days = a.days.map((d, i) => ({ f: d.f + b.days[i].f, t: d.t + b.days[i].t }));
    return { alerts: a.alerts + b.alerts, falseAlerts, trueAlerts: a.trueAlerts + b.trueAlerts, caught, perDay: falseAlerts / 7, days };
  }
  /** a rough, made-up "how does that feel" scale for false alerts per day */
  function fatigue(perDay) {
    if (perDay <= 1) return { level: 0, label: "quiet: every alert gets read" };
    if (perDay <= 5) return { level: 1, label: "busy but workable" };
    if (perDay <= 15) return { level: 2, label: "heavy: alerts start to wait" };
    return { level: 3, label: "fatigue: nobody reads these any more" };
  }

  // =========================================================================== 6. a very rough picture of what your logs can see
  const SOURCES = [
    { id: "idp", name: "Identity provider", gb: 0.1, q: "who signed in, from where; who changed an account or role" },
    { id: "cloud", name: "Cloud control plane", gb: 0.2, q: "who changed what in the cloud, incl. logging off" },
    { id: "endpoint", name: "Endpoints", gb: 2.0, q: "what ran, as whom, with what command line" },
    { id: "dns", name: "DNS", gb: 1.5, q: "which names a machine looked up" },
    { id: "network", name: "Network flow and proxy", gb: 5.0, q: "who talked to whom; how much data moved" },
    { id: "app", name: "Web and app logs", gb: 1.0, q: "what users did in your applications" },
    { id: "db", name: "Database audit", gb: 0.8, q: "who read or changed which data" },
  ];
  // which attack steps each source helps you reconstruct (a judgement, not a measurement)
  const STEPS = [
    { id: "access", name: "how they got in", by: ["idp", "app", "network", "dns"] },
    { id: "persist", name: "what they set up to stay", by: ["idp", "cloud", "endpoint"] },
    { id: "move", name: "where they went next", by: ["network", "endpoint", "idp"] },
    { id: "reach", name: "what they could reach", by: ["cloud", "db", "app", "idp"] },
    { id: "take", name: "what left the building", by: ["network", "dns", "app"] },
    { id: "cover", name: "what they did to hide it", by: ["endpoint", "cloud"] },
  ];
  function budget(selected, staff, hotDays, totalDays) {
    const perDay = SOURCES.filter((s) => selected.includes(s.id)).reduce((a, s) => a + s.gb, 0) * (staff / 1000);
    const hot = perDay * hotDays, total = perDay * totalDays;
    const steps = STEPS.filter((st) => st.by.some((s) => selected.includes(s)));
    return { perDay, hot, cold: Math.max(0, total - hot), total, steps: steps.length, blind: STEPS.filter((st) => !steps.includes(st)).map((st) => st.name) };
  }

  // =========================================================================== 7. ATT&CK-style coverage map (a simplification)
  // Enterprise ATT&CK (v20, October 2026) has 15 tactics. Defense Evasion was split into Stealth and Defense Impairment in v19 (April 2026).
  const TACTICS = [
    { id: "TA0043", name: "Reconnaissance" }, { id: "TA0042", name: "Resource Development" }, { id: "TA0001", name: "Initial Access" },
    { id: "TA0002", name: "Execution" }, { id: "TA0003", name: "Persistence" }, { id: "TA0004", name: "Privilege Escalation" },
    { id: "TA0005", name: "Stealth" }, { id: "TA0112", name: "Defense Impairment" }, { id: "TA0006", name: "Credential Access" },
    { id: "TA0007", name: "Discovery" }, { id: "TA0008", name: "Lateral Movement" }, { id: "TA0009", name: "Collection" },
    { id: "TA0011", name: "Command and Control" }, { id: "TA0010", name: "Exfiltration" }, { id: "TA0040", name: "Impact" },
  ];
  // how well each source lets you see each tactic: 2 = good view, 1 = some view (an illustrative judgement)
  const SEE = {
    idp:      { TA0001: 2, TA0003: 1, TA0004: 2, TA0005: 1, TA0006: 2, TA0008: 1 },
    cloud:    { TA0001: 1, TA0003: 2, TA0004: 2, TA0112: 2, TA0009: 1, TA0010: 1, TA0040: 1 },
    endpoint: { TA0002: 2, TA0003: 2, TA0004: 1, TA0005: 2, TA0112: 2, TA0006: 1, TA0007: 2, TA0008: 1, TA0009: 1, TA0040: 2 },
    dns:      { TA0001: 1, TA0011: 2, TA0010: 1 },
    network:  { TA0001: 1, TA0007: 1, TA0008: 2, TA0011: 2, TA0010: 2 },
    app:      { TA0001: 2, TA0002: 1, TA0009: 1, TA0010: 1 },
    db:       { TA0009: 2, TA0010: 1, TA0040: 1 },
  };
  function coverage(selected) {
    return TACTICS.map((t) => {
      const score = selected.reduce((a, s) => a + ((SEE[s] && SEE[s][t.id]) || 0), 0);
      return { ...t, score, level: score >= 3 ? "good" : score >= 1 ? "some" : "dark" };
    });
  }

  // =========================================================================== 8. the tabletop exercise
  // Four meters, all 0-100. spread: how far the attacker has reached (lower is better). evidence: how much you can still prove (higher is better).
  // disruption: harm to the business (lower is better). clarity: how well people know what is happening (higher is better).
  const METERS = [
    { id: "spread", name: "Attacker's reach", good: "low" },
    { id: "evidence", name: "Evidence kept", good: "high" },
    { id: "disruption", name: "Business disruption", good: "low" },
    { id: "clarity", name: "Shared clarity", good: "high" },
  ];
  const SCENARIOS = {
    admin: {
      id: "admin", title: "3 a.m., a new country", start: { spread: 40, evidence: 100, disruption: 0, clarity: 50 },
      intro: "About 400 staff, no 24-hour security team. You are the on-call IT person. Your phone buzzes at 03:12 UTC.",
      rounds: [
        { time: "03:12", title: "The first alert", text: "An alert: dana.admin, an administrator account, signed in from a country it has never used before. MFA was approved. Dana is not answering her phone yet.", options: [
          { t: "Call Dana to ask whether that was her, and wait for an answer", fx: { spread: 8, clarity: 8 }, why: "Checking with the person is a good instinct, and it's slow. Do it in parallel with containment, not instead of it: an administrator account is too powerful to leave open while you wait." },
          { t: "Disable the account and revoke its sessions and tokens, then call Dana", fx: { spread: -20, disruption: 5, clarity: 5 }, why: "For an administrator signing in from somewhere new in the middle of the night, containing first is reasonable. Disabling the sign-in isn't enough on its own: existing sessions and tokens need revoking too. The account is kept, so the evidence stays." },
          { t: "Watch what it does for 30 minutes before deciding", fx: { spread: 15, evidence: 4, clarity: 6 }, why: "Watching an intruder is a real technique, but it needs a team, good logging and the nerve to stop them if it goes wrong. CISA's playbook describes monitoring an actor in a sandbox as something for advanced SOCs with mature capabilities. For one on-call person, it mostly gives the attacker time." },
          { t: "Leave it until morning: MFA was approved, so it's probably fine", fx: { spread: 30, clarity: -10 }, why: "An approved prompt only shows that someone approved it. Attackers can tire people into approving, or sit in the middle of a sign-in. The useful review question is why waiting looked reasonable at 3 a.m." },
        ] },
        { time: "03:40", title: "More in the logs", text: "Searching the logs, you find dana.admin created a new account, svc-backup2, added it to Admins, and stopped the cloud audit trail at 03:31.", options: [
          { t: "Disable svc-backup2, and rotate Dana's credentials and the other admin secrets", fx: { spread: -15, disruption: 10, clarity: 5 }, why: "This removes the access the attacker built. Do it after you've noted what you found, so you know what to look for in the other accounts." },
          { t: "Restart the audit trail, and copy the last 24 hours of every log somewhere the attacker can't reach", fx: { spread: -4, evidence: 12, clarity: 10 }, why: "Logging was switched off on purpose: turning it back on, and saving what exists, protects your ability to answer 'what did they do?' later. It isn't containment by itself, so pair it with the step above." },
          { t: "Pull the plug on the file server and the domain controller", fx: { spread: -10, evidence: -25, disruption: 35, clarity: -5 }, why: "It stops activity and destroys what's in memory, and takes the whole office down. RFC 3227 says to collect volatile evidence before shutting down, and isolating a machine from the network usually stops the harm without that cost." },
          { t: "Email everyone to change their password now", fx: { spread: -5, disruption: 20, clarity: -5 }, why: "A mass reset can help later, once you know what's affected. Now it floods the help desk, and the attacker's own account may be among those resetting." },
        ] },
        { time: "07:00", title: "The CEO arrives", text: "Containment seems to hold. The CEO asks: 'Was customer data taken?' You don't know yet.", options: [
          { t: "Say what you know, what you don't, what you're checking, and when you'll update them next", fx: { clarity: 20 }, why: "'We don't know yet' is an honest answer when followed by a plan and a time. People tolerate uncertainty far better than a story that changes." },
          { t: "Say 'No customer data was affected', to settle things down", fx: { clarity: -25 }, why: "You can't know that yet. If it's wrong, you must retract it, and everything else you say next loses some trust." },
          { t: "Say nothing until the investigation is finished", fx: { clarity: -15 }, why: "Silence lets rumours fill the gap. A short, regular update costs little and keeps leadership on your side." },
          { t: "Bring in your lawyer and your insurer, start a fact timeline, and agree when the next update is", fx: { clarity: 15, evidence: 5 }, why: "Who must be told, and when, depends on contracts and laws that apply to you. Getting counsel and your insurer involved early is routine. Remember to tell the CEO something as well." },
        ] },
      ],
    },
    ransom: {
      id: "ransom", title: "The Monday-morning note", start: { spread: 55, evidence: 100, disruption: 40, clarity: 40 },
      intro: "About 150 staff. At 08:10 on Monday the finance team says they can't open their files.",
      rounds: [
        { time: "08:10", title: "Files that won't open", text: "Shared-drive files have strange names ending in .locked, and every folder holds a text file with a message. The file server's disk light is flickering.", options: [
          { t: "Isolate the file server from the network, but leave it powered on", fx: { spread: -25, disruption: 8, clarity: 5 }, why: "Cutting the network stops it spreading to other machines and keeps memory and disk as they are. This is the usual first move for ransomware." },
          { t: "Power the file server off right now", fx: { spread: -15, evidence: -20, disruption: 12 }, why: "It stops the encryption, and loses what's in memory, which can hold clues about how it started. Isolating it from the network usually gets you the same protection without that loss." },
          { t: "Delete the note and start restoring from last night's backup", fx: { spread: 10, evidence: -30, disruption: -5, clarity: -5 }, why: "If the attacker is still inside, they'll do it again, and you've destroyed your trail. Last night's backup may even hold encrypted files." },
          { t: "Unplug the whole office from the internet", fx: { spread: -30, disruption: 40, clarity: -5 }, why: "Blunt but effective at stopping outside control. It costs the whole day's work and doesn't help if the damage is already inside. Choose the smallest thing that works." },
        ] },
        { time: "09:00", title: "What you can restore from", text: "The first encrypted file is stamped 02:14 on Sunday, written by the svc-backup account. The online backup store is also encrypted. A copy from Friday evening sits on a disk in the safe.", options: [
          { t: "Check that the Friday disk restores, on an isolated machine, before doing anything else", fx: { clarity: 10, evidence: 2 }, why: "A backup you haven't restored is a hope. Testing it away from the network tells you what you actually have." },
          { t: "Start restoring Friday's copy onto the original server immediately", fx: { spread: 15, disruption: -10, evidence: -10 }, why: "It's tempting. If the attacker still has a way in, they encrypt the restored files too. First work out how they got in and close it." },
          { t: "Build a clean server, and restore onto that once you know the way in is closed", fx: { spread: -10, disruption: 5, clarity: 8 }, why: "Rebuilding from known-good gives you a clean base, and leaves the old server's disk intact for investigation." },
          { t: "Look through remote-access and VPN logs for the week to find how they got in", fx: { evidence: 10, clarity: 12 }, why: "Finding the way in is part of eradicating it. Check that those logs still exist: this is when a short retention period hurts." },
        ] },
        { time: "14:00", title: "Who needs to know", text: "The finance team holds customer payment details. Your insurer's helpline, a regulator's website and two customers' contracts all say 'notify promptly'.", options: [
          { t: "Bring in counsel now, note the time you became aware, and check each notification clock", fx: { clarity: 18, evidence: 4 }, why: "Some clocks start when you become aware of an incident, others when you decide it's material. Recording the time and asking counsel early is cheap." },
          { t: "Wait until you're sure what was taken", fx: { clarity: -15 }, why: "Notification clocks can run while you investigate, and information can be sent in stages. Waiting for certainty can mean being late." },
          { t: "Tell the customers it was a minor IT problem", fx: { clarity: -30 }, why: "If it later turns out to involve their data, you've misled them. Say what you know and what you don't." },
          { t: "Ask the attacker's contact page how much they want, to understand your options", fx: { clarity: -10, spread: 5, evidence: -5 }, why: "Whether to contact the criminals at all is a decision for your leadership, counsel, insurer and law enforcement together, not for whoever is on call." },
        ] },
      ],
    },
  };
  // things that go wrong in the middle of any incident: two are drawn at random
  const INJECTS = [
    { id: "ceo", title: "The CEO phones", text: "'I can't open my email and I have a board call in ten minutes. Fix it.'", options: [
      { t: "Give a two-minute update: what you know, what it means for them, and when the next one is", fx: { clarity: 10 }, why: "Leaders who hear it from you stay out of the technical channel." },
      { t: "Drop the investigation and fix their email first", fx: { disruption: -3, spread: 5, evidence: -3 }, why: "Priorities slip when whoever is loudest gets served first. Decide who handles requests like this, so the technical lead doesn't." },
      { t: "Tell them you're too busy to talk right now", fx: { clarity: -15 }, why: "It's very human, and it leaves a leader guessing. Someone, ideally the communications lead, owns this conversation." },
    ] },
    { id: "press", title: "A journalist emails", text: "A reporter has heard about an 'outage and hacking rumours' and wants comment by 17:00.", options: [
      { t: "Pass it to your communications lead and counsel: 'we're aware of an issue and will share more when we can'", fx: { clarity: 10 }, why: "One voice, a short true statement, nothing guessed. The technical team keeps working." },
      { t: "Reply 'no comment' straight away", fx: { clarity: -5 }, why: "It's safe, and it sounds like you have something to hide. A short acknowledgement usually serves you better." },
      { t: "Answer in detail with your best guess about what happened", fx: { clarity: -20 }, why: "Guesses become headlines. If any are wrong you must correct them, in public." },
    ] },
    { id: "rotate", title: "A log expires in six hours", text: "Your IT provider warns that the firewall logs for the affected period will be overwritten in about six hours.", options: [
      { t: "Export and copy those logs somewhere safe right now", fx: { evidence: 15 }, why: "Cheap, quick, and one of the most useful things done all day. This is what 'retention' means in practice." },
      { t: "Ask the provider to extend retention, and to confirm it in writing", fx: { evidence: 10, clarity: 5 }, why: "Good, and still copy what you can now. A promise to keep logs isn't a copy of them." },
      { t: "Leave it: you have the other logs", fx: { evidence: -25 }, why: "Firewall logs are often where you see data leaving. They're easy to save and impossible to recreate." },
    ] },
    { id: "second", title: "A second alert", text: "A different administrator account now shows odd activity.", options: [
      { t: "Treat it as part of this incident: widen the scope and contain that account too", fx: { spread: -10, disruption: 5, clarity: 5 }, why: "Two odd admin accounts in one night is rarely a coincidence. Widening scope early is cheaper than finding out later." },
      { t: "Log it as a separate, low-priority ticket", fx: { spread: 15, clarity: -5 }, why: "Separate tickets are how connected incidents stay unconnected. You can always split them later." },
      { t: "Stop everything and investigate only the new account", fx: { spread: 8, evidence: -5 }, why: "Chasing the newest alert leaves the old fire burning. Keep the incident lead's overall picture." },
    ] },
    { id: "tired", title: "Fourteen hours in", text: "Your lead engineer has been awake since yesterday and wants to keep going.", options: [
      { t: "Swap in a rested person with a handover from the scribe's timeline", fx: { clarity: 10 }, why: "Handovers are where the written timeline pays for itself. Tired people make more mistakes, and are the last to notice." },
      { t: "Let them carry on, they know the most", fx: { clarity: -10, evidence: -5 }, why: "Knowledge matters, and so does the fact that a tired person typing commands as an administrator makes mistakes. The scribe's timeline is what makes a handover possible." },
      { t: "Send everyone home to rest", fx: { spread: 20, disruption: 5 }, why: "Rest is needed, in shifts. Everyone leaving at once leaves the incident without anyone watching it." },
    ] },
    { id: "legal", title: "Legal needs an answer", text: "Your lawyer asks: 'What data did the attacker see? I need to know by noon.'", options: [
      { t: "Give what's confirmed, what's not, and the evidence you've collected so far", fx: { clarity: 15 }, why: "Counsel can work with 'confirmed' and 'unknown' if you keep them apart. They can't work with a guess dressed as a fact." },
      { t: "Give your best guess, so they have something", fx: { clarity: -15 }, why: "A guess in a legal file becomes a statement. Offer a range, with the reasoning, and the date it was true." },
      { t: "Say nothing until the investigation ends", fx: { clarity: -10 }, why: "Clocks may be running. Counsel needs partial facts now and can plan around them." },
    ] },
  ];
  function clamp(n) { return Math.max(0, Math.min(100, n)); }
  /** draw k distinct inject indexes using the supplied random function (0..1) */
  function drawInjects(k, rand) {
    const pool = INJECTS.map((_, i) => i), out = [];
    while (out.length < k && pool.length) out.push(pool.splice(Math.floor(rand() * pool.length), 1)[0]);
    return out;
  }
  /** the steps of a game: round 1, round 2 + inject, round 3 + inject. Each step is { kind, round, ...content } */
  function ttPlan(scenarioId, injectIdx) {
    const sc = SCENARIOS[scenarioId], steps = [];
    sc.rounds.forEach((r, i) => {
      steps.push({ kind: "round", round: i, time: r.time, title: r.title, text: r.text, options: r.options });
      if (i >= 1) { const inj = INJECTS[injectIdx[i - 1]]; steps.push({ kind: "inject", round: i, time: r.time, title: inj.title, text: inj.text, options: inj.options, injectId: inj.id }); }
    });
    return steps;
  }
  function ttNew(scenarioId, injectIdx) {
    const sc = SCENARIOS[scenarioId];
    return { scenario: scenarioId, injectIdx, steps: ttPlan(scenarioId, injectIdx), step: 0, meters: { ...sc.start }, log: [], done: false };
  }
  function ttChoose(state, optionIndex) {
    const st = state.steps[state.step], opt = st.options[optionIndex];
    const meters = { ...state.meters };
    for (const k of Object.keys(opt.fx)) meters[k] = clamp(meters[k] + opt.fx[k]);
    const log = state.log.concat([{ step: state.step, title: st.title, time: st.time, kind: st.kind, choice: opt.t, why: opt.why, fx: opt.fx }]);
    const step = state.step + 1;
    return { ...state, meters, log, step, done: step >= state.steps.length };
  }
  function ttSummary(state) {
    const m = state.meters, words = {};
    words.spread = m.spread <= 20 ? "contained" : m.spread <= 45 ? "partly contained" : "still spreading";
    words.evidence = m.evidence >= 80 ? "well preserved" : m.evidence >= 50 ? "partly preserved" : "mostly lost";
    words.disruption = m.disruption <= 25 ? "low" : m.disruption <= 55 ? "moderate" : "high";
    words.clarity = m.clarity >= 60 ? "clear" : m.clarity >= 40 ? "muddled" : "confusing";
    return { meters: m, words };
  }

  // =========================================================================== 9. "spot the leak" lines for the secrets slide
  const LEAKS = [
    { line: "GET /reset?token=9f3a1c07b2e44d0a 200", leak: true, why: "A reset token in the URL. Anyone who can read the log can use it. Log the path without the query string, or log a short hash of the token to match events.", fix: "GET /reset 200 token_id=7c1e" },
    { line: "login failed user=dana password=Summer2026!", leak: true, why: "A failed login often holds a real password with one typo. Log that it failed, never what was typed.", fix: "login failed user=dana reason=bad_password" },
    { line: "payment ok card=4111111111111111 amount=19.99", leak: true, why: "A full card number. Log a token or the last four digits, if you log anything.", fix: "payment ok card=****1111 amount=19.99" },
    { line: "login failed user=dana src=203.0.113.9 reason=bad_password", leak: false, why: "Who, where from and why, and no secret. This is what you want to see.", fix: "" },
    { line: "name=dana\\n2026-11-09T03:12:44Z login success user=admin", leak: true, why: "A user-typed value containing a newline forges a second, fake line: 'admin signed in'. Encode user input, and prefer structured (for example JSON) logs.", fix: "{\"event\":\"signup\",\"name\":\"dana\\n2026-11-09T03:12:44Z login success user=admin\"}" },
    { line: "export ok user=bob rows=1200 table=customers", leak: false, why: "Counts and names, not contents. You can see that a large export happened without keeping the data in the log.", fix: "" },
  ];

  const Logs = {
    rng, lint, luhn, TIME_EVENTS, placeEvent, orderEvents, GENESIS, CHAIN_TEXTS, link, chainBuild, chainVerify, attack,
    LOG, STORY, FIELDS, parseQuery, search, checkCase, authSim, runRule, runBoth, fatigue, SOURCES, STEPS, budget, TACTICS, SEE, coverage,
    METERS, SCENARIOS, INJECTS, drawInjects, ttPlan, ttNew, ttChoose, ttSummary, LEAKS,
  };
  root.Logs = Logs;
  if (typeof module !== "undefined" && module.exports) module.exports = Logs;
})(typeof window !== "undefined" ? window : globalThis);
