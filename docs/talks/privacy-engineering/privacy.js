/* privacy.js - the logic behind the demos in "Privacy Engineering" (window.PrivLab; also loads in Node).
   EDUCATIONAL ONLY. Every person, record, log line and "database" here is invented, and nothing is fetched or sent.
   It reuses SHA-256 and HMAC from ../../shared/crypto.js, and the browser's Web Crypto for the envelope-encryption demo.
   Contents: 1. a personal-data spotter   2. a re-identification dataset with k-anonymity   3. a data-minimisation form
   4. purpose limitation and consent   5. a data map   6. envelope encryption and crypto-shredding   7. plain hashes vs keyed pseudonyms
   8. differential privacy (Laplace noise)   9. a log redactor   10. access and audit   11. retention   12. deletion plans
   13. data-subject-request deadlines and export   14. LINDDUN prompts */
(function (root) {
  "use strict";
  const L = root.Lab || (typeof require !== "undefined" ? require("../../shared/crypto.js") : null);
  const escapeHtml = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  function mulberry32(seed) {
    let a = seed >>> 0;
    return () => { a = (a + 0x6d2b79f5) >>> 0; let t = a; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
  }

  // ------------------------------------------------------------------ 1. spotting personal data
  function luhn(digits) {
    let sum = 0, alt = false;
    for (let i = digits.length - 1; i >= 0; i--) { let n = digits.charCodeAt(i) - 48; if (alt) { n *= 2; if (n > 9) n -= 9; } sum += n; alt = !alt; }
    return digits.length >= 13 && sum % 10 === 0;
  }
  const SPECIAL = /\b(diagnos\w*|pregnan\w*|asthma|diabet\w*|depress\w*|religio\w*|trade union|union member|sexual orientation|ethnic\w*|HIV|cancer)\b/gi;
  /** Which kinds of personal data does this text contain? Returns [{kind, text, sensitive}] and a joke for special inputs. */
  function spot(text) {
    let rest = String(text || "");
    const found = [];
    const take = (re, kind, sensitive, ok) => {
      rest = rest.replace(re, (m) => { if (ok && !ok(m)) return m; found.push({ kind, text: m.trim(), sensitive: !!sensitive }); return " ".repeat(m.length); });
    };
    take(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, "email address");
    take(/\b(?:\d[ -]?){12,18}\d\b/g, "payment card number", true, (m) => luhn(m.replace(/\D/g, "")));
    take(/\b\d{3}-\d{2}-\d{4}\b/g, "national ID number (SSN-shaped)", true);
    take(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, "IP address");
    take(/\b\d{4}-\d{2}-\d{2}\b|\b\d{1,2}\/\d{1,2}\/\d{2,4}\b/g, "date (a birth date, if it is one)");
    take(/\+?\d[\d\s().-]{7,}\d/g, "phone number");
    take(SPECIAL, "special-category word (health, belief, etc.)", true);
    take(/\b[A-Z][a-z]+ [A-Z][a-z]+\b/g, "might be a person's name");
    const t = String(text || "").trim(), low = t.toLowerCase();
    let egg = "";
    if (!t) egg = "An empty box holds no personal data. That's the cheapest field to protect.";
    else if (/rumpelstiltskin/.test(low)) egg = "Your name stays secret. You've clearly read the privacy policy.";
    else if (/^hunter2$/.test(low)) egg = "That's a password, not personal data. Both still stay out of logs.";
    else if (/example\.(com|org|net)\b|@example\./.test(low) && found.length) egg = "example.com is reserved for documentation, so this one is safe to use in a talk.";
    return { found, egg, sensitive: found.filter((f) => f.sensitive).length };
  }

  // ------------------------------------------------------------------ 2. re-identification and k-anonymity
  const FIRST = ["Avery", "Blake", "Casey", "Devon", "Emery", "Finley", "Gray", "Harper", "Indigo", "Jordan"];
  const LAST = ["Ashdown", "Brookfield", "Calloway", "Dunmore", "Eastwick", "Fairweather"];
  const ZIPS = ["80521", "80522", "80524", "80631", "80634", "80701"];
  const DIAG = ["asthma", "diabetes", "depression", "hypertension", "migraine", "none recorded"];
  function makePeople() {
    const rnd = mulberry32(2026);
    const people = [];
    for (const f of FIRST) for (const l of LAST) {
      const year = 1950 + Math.floor(rnd() * 55), month = 1 + Math.floor(rnd() * 12), day = 1 + Math.floor(rnd() * 28);
      const g = rnd() < 0.48 ? "F" : rnd() < 0.96 ? "M" : "X";
      people.push({ name: f + " " + l, zip: ZIPS[Math.floor(rnd() * ZIPS.length)], year, month, day, gender: g, dx: DIAG[Math.floor(rnd() * DIAG.length)] });
    }
    return people;
  }
  const PEOPLE = makePeople();
  const ZIP_LEVELS = ["5 digits", "3 digits", "2 digits", "removed"];
  const BIRTH_LEVELS = ["full date", "month and year", "year", "decade", "removed"];
  function genZip(zip, lv) { return lv === 0 ? zip : lv === 1 ? zip.slice(0, 3) + "**" : lv === 2 ? zip.slice(0, 2) + "***" : "*"; }
  function genBirth(p, lv) {
    const mm = String(p.month).padStart(2, "0"), dd = String(p.day).padStart(2, "0");
    return lv === 0 ? `${p.year}-${mm}-${dd}` : lv === 1 ? `${p.year}-${mm}` : lv === 2 ? String(p.year) : lv === 3 ? Math.floor(p.year / 10) * 10 + "s" : "*";
  }
  function quasi(p, cfg) { return [genZip(p.zip, cfg.zip), genBirth(p, cfg.birth), cfg.gender ? p.gender : "*"].join(" | "); }
  /** cfg = {zip:0-3, birth:0-4, gender:true|false}. Groups people by their released quasi-identifiers. */
  function anonymity(cfg, people) {
    const ps = people || PEOPLE;
    const groups = new Map();
    for (const p of ps) { const k = quasi(p, cfg); if (!groups.has(k)) groups.set(k, []); groups.get(k).push(p); }
    const sizes = [...groups.values()].map((g) => g.length);
    const uniq = sizes.filter((s) => s === 1).length;
    const homogeneous = [...groups.values()].filter((g) => g.length > 1 && new Set(g.map((p) => p.dx)).size === 1).reduce((n, g) => n + g.length, 0);
    return { groups, count: groups.size, k: Math.min(...sizes), unique: uniq, homogeneous, total: ps.length, avg: ps.length / groups.size };
  }
  /** The attacker's view: they know a named person's public details (from a register) and look at the release. */
  function lookup(name, cfg) {
    const q = String(name || "").trim().toLowerCase();
    if (!q) return { status: "empty" };
    if (q === "rumpelstiltskin") return { status: "egg", message: "Your name stays secret. You've clearly read the privacy policy." };
    const p = PEOPLE.find((x) => x.name.toLowerCase() === q);
    if (!p) return { status: "unknown" };
    const key = quasi(p, cfg);
    const match = PEOPLE.filter((x) => quasi(x, cfg) === key);
    const dxs = [...new Set(match.map((m) => m.dx))];
    return { status: "found", person: p, matches: match.length, diagnoses: dxs, learned: dxs.length === 1 ? dxs[0] : null };
  }

  // ------------------------------------------------------------------ 3. data minimisation
  const FIELDS = [
    { k: "email", label: "Email address", purpose: "Sign in, order receipts", owner: "Accounts team", needed: true, risk: 2 },
    { k: "name", label: "Full name", purpose: "Name on the parcel", owner: "Delivery team", needed: true, risk: 2 },
    { k: "address", label: "Home address", purpose: "Deliver the order", owner: "Delivery team", needed: true, risk: 3 },
    { k: "phone", label: "Phone number", purpose: "Courier can call at the door (optional)", owner: "Delivery team", needed: false, risk: 2 },
    { k: "dob", label: "Date of birth", purpose: "Nobody remembers", owner: "(nobody)", needed: false, risk: 3 },
    { k: "gender", label: "Gender", purpose: "\"Marketing wanted it\"", owner: "(nobody)", needed: false, risk: 2 },
    { k: "employer", label: "Employer", purpose: "Nobody remembers", owner: "(nobody)", needed: false, risk: 1 },
    { k: "contacts", label: "Phone contact list", purpose: "A growth experiment from 2021", owner: "(nobody)", needed: false, risk: 3 },
    { k: "adid", label: "Advertising ID", purpose: "Analytics (consent not asked)", owner: "Growth team", needed: false, risk: 2 },
  ];
  /** keep = set of field keys still collected. */
  function minimiseReport(keep) {
    const kept = FIELDS.filter((f) => keep.has(f.k));
    const missing = FIELDS.filter((f) => f.needed && !keep.has(f.k));
    const orphans = kept.filter((f) => f.owner === "(nobody)");
    return {
      count: kept.length, risk: kept.reduce((n, f) => n + f.risk, 0), maxRisk: FIELDS.reduce((n, f) => n + f.risk, 0),
      broken: missing.map((f) => f.label), orphans: orphans.map((f) => f.label), unneeded: kept.filter((f) => !f.needed).length,
      empty: kept.length === 0,
      verdict: kept.length === 0 ? "min" : missing.length ? "broken" : kept.some((f) => !f.needed) ? "extra" : "lean",
    };
  }

  // ------------------------------------------------------------------ 4. purpose limitation and consent
  const PURPOSES = ["delivery", "security", "support", "marketing", "analytics"];
  const DATA = [
    { k: "email", label: "Email address", purposes: { delivery: "", security: "", support: "", marketing: "consent" } },
    { k: "phone", label: "Phone number", purposes: { delivery: "", security: "", support: "" } },
    { k: "address", label: "Home address", purposes: { delivery: "", support: "" } },
    { k: "orders", label: "Order history", purposes: { delivery: "", support: "", analytics: "consent", marketing: "consent" } },
    { k: "device", label: "Device ID", purposes: { security: "", analytics: "consent" } },
  ];
  /** consents = {marketing:bool, analytics:bool}. Each purpose is either listed for the field, allowed, or needs consent. */
  function access(purpose, consents) {
    return DATA.map((d) => {
      const rule = d.purposes[purpose];
      if (rule === undefined) return { k: d.k, label: d.label, ok: false, why: "not collected for this purpose" };
      if (rule === "consent" && !(consents && consents[purpose])) return { k: d.k, label: d.label, ok: false, why: "needs consent, and there is none" };
      return { k: d.k, label: d.label, ok: true, why: rule === "consent" ? "consent given" : "part of the original purpose" };
    });
  }

  // ------------------------------------------------------------------ 5. data map
  const STORES = [
    { k: "db", label: "Main database", holds: ["email", "name", "address", "orders", "location"], retention: 0, owner: "Platform" },
    { k: "replica", label: "Read replica", holds: ["email", "name", "address", "orders", "location"], retention: 0, owner: "Platform" },
    { k: "search", label: "Search index", holds: ["name", "orders"], retention: 0, owner: "Search team" },
    { k: "cache", label: "Cache", holds: ["email", "name", "address"], retention: 1, owner: "Platform" },
    { k: "logs", label: "Application logs", holds: ["email", "location", "ip"], retention: 30, owner: "(nobody)" },
    { k: "errors", label: "Error tracker (vendor)", holds: ["email", "ip", "orders"], retention: 90, owner: "(nobody)" },
    { k: "analytics", label: "Analytics (vendor)", holds: ["location", "ip", "orders"], retention: 400, owner: "Growth" },
    { k: "support", label: "Support desk (vendor)", holds: ["email", "name", "address", "orders"], retention: 0, owner: "Support" },
    { k: "warehouse", label: "Data warehouse", holds: ["email", "orders", "location"], retention: 0, owner: "Data team" },
    { k: "backups", label: "Backups", holds: ["email", "name", "address", "orders", "location"], retention: 35, owner: "Platform" },
  ];
  const MAP_FIELDS = [["email", "Email"], ["name", "Name"], ["address", "Address"], ["orders", "Order history"], ["location", "Location"], ["ip", "IP address"]];
  function whereIs(field) {
    const hits = STORES.filter((s) => s.holds.includes(field));
    return { hits, count: hits.length, total: STORES.length, noOwner: hits.filter((s) => s.owner === "(nobody)").length, noExpiry: hits.filter((s) => s.retention === 0).length };
  }

  // ------------------------------------------------------------------ 6. envelope encryption and crypto-shredding
  const subtle = () => (root.crypto && root.crypto.subtle) || null;
  const b64 = (u8) => { let s = ""; for (const b of u8) s += String.fromCharCode(b); return typeof btoa === "function" ? btoa(s) : Buffer.from(u8).toString("base64"); };
  const rnd = (n) => root.crypto.getRandomValues(new Uint8Array(n));
  /** A tiny key hierarchy: one master key (the KEK, held in a "key service") wraps one data key per customer. */
  async function makeVault() {
    const s = subtle();
    const kek = await s.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    const vault = { kek, keys: new Map(), rows: new Map(), backup: null, async enroll(user, plaintext) {
      const raw = rnd(32);
      const dek = await s.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
      const wrapIv = rnd(12);
      const wrapped = new Uint8Array(await s.encrypt({ name: "AES-GCM", iv: wrapIv }, kek, raw));
      vault.keys.set(user, { wrapIv, wrapped });
      const iv = rnd(12);
      const ct = new Uint8Array(await s.encrypt({ name: "AES-GCM", iv, additionalData: new TextEncoder().encode(user) }, dek, new TextEncoder().encode(plaintext)));
      vault.rows.set(user, { iv, ct });
    },
    async read(user, snapshot) {
      const keys = snapshot ? snapshot.keys : vault.keys, rows = snapshot ? snapshot.rows : vault.rows;
      const k = keys.get(user), r = rows.get(user);
      if (!r) return { ok: false, why: "no such row" };
      if (!k) return { ok: false, why: "no data key: the ciphertext is just noise now" };
      try {
        const raw = await s.decrypt({ name: "AES-GCM", iv: k.wrapIv }, kek, k.wrapped);
        const dek = await s.importKey("raw", raw, "AES-GCM", false, ["decrypt"]);
        const pt = await s.decrypt({ name: "AES-GCM", iv: r.iv, additionalData: new TextEncoder().encode(user) }, dek, r.ct);
        return { ok: true, text: new TextDecoder().decode(pt) };
      } catch (e) { return { ok: false, why: "decryption failed" }; }
    },
    /** A backup copies the rows, and (the mistake) maybe the wrapped keys too. */
    snapshot(withKeys) { vault.backup = { rows: new Map(vault.rows), keys: withKeys ? new Map(vault.keys) : new Map() }; return vault.backup; },
    shred(user) { vault.keys.delete(user); },
    ciphertextPreview(user) { const r = vault.rows.get(user); return r ? b64(r.ct).slice(0, 28) + "…" : "(none)"; } };
    return vault;
  }

  // ------------------------------------------------------------------ 7. plain hashes vs keyed pseudonyms
  const normaliseEmail = (e) => String(e).trim().toLowerCase();
  const plainHash = (email) => L.hex(L.sha256(L.utf8(normaliseEmail(email))));
  const keyedPseudonym = (key, email) => L.hex(L.hmacSha256(L.utf8(key), L.utf8(normaliseEmail(email))));
  const CANDIDATES = ["alex.morgan@example.com", "sam.lee@example.com", "jo.kim@example.com", "pat.rivers@example.com", "robin.hale@example.com", "kai.north@example.com",
    "dana.wren@example.com", "lee.ford@example.com", "max.dunn@example.com", "ivy.stone@example.com", "noor.ali@example.com", "tess.moore@example.com"];
  const TABLE_EMAILS = ["sam.lee@example.com", "dana.wren@example.com", "noor.ali@example.com", "someone.new@example.org"];
  /** An attacker with a leaked table and a list of likely emails. Returns how many rows each scheme gives away. */
  function reverseAttack(emails, guesses, key, keyLeaked) {
    const plainTable = emails.map(plainHash), keyedTable = emails.map((e) => keyedPseudonym(key, e));
    const g = guesses.map(normaliseEmail);
    const gPlain = new Map(g.map((e) => [plainHash(e), e]));
    const plainHits = plainTable.filter((h) => gPlain.has(h)).length;
    const gKeyed = new Map(g.map((e) => [keyedPseudonym(keyLeaked ? key : "attacker-guess", e), e]));
    const keyedHits = keyedTable.filter((h) => gKeyed.has(h)).length;
    return { plainTable, keyedTable, plainHits, keyedHits, total: emails.length };
  }

  // ------------------------------------------------------------------ 8. differential privacy
  function laplace(scale, rand) { const u = (rand ? rand() : Math.random()) - 0.5; return -scale * Math.sign(u) * Math.log(1 - 2 * Math.abs(u)); }
  /** A counting query changes by at most 1 when one person is added or removed, so the noise scale is 1/epsilon. */
  function noisyCount(trueCount, epsilon, rand) { return trueCount + laplace(1 / epsilon, rand); }
  const expectedAbsError = (epsilon) => 1 / epsilon;
  function noiseRuns(trueCount, epsilon, n, rand) { return Array.from({ length: n }, () => noisyCount(trueCount, epsilon, rand)); }
  const mean = (a) => a.reduce((s, x) => s + x, 0) / a.length;
  function histogram(values, lo, hi, bins) {
    const h = new Array(bins).fill(0), w = (hi - lo) / bins;
    for (const v of values) { const i = Math.floor((v - lo) / w); if (i >= 0 && i < bins) h[i]++; }
    return h;
  }

  // ------------------------------------------------------------------ 9. log redactor
  const SAMPLE_LOG = [
    '2026-11-11T09:14:02Z INFO  login ok user=dana.wren@example.com ip=203.0.113.42',
    '2026-11-11T09:14:05Z DEBUG request headers: Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI0MiJ9.c2lnbmF0dXJl',
    '2026-11-11T09:15:11Z ERROR payment failed card=4111 1111 1111 1111 name="Noor Ali" retry=2',
    '2026-11-11T09:15:30Z DEBUG POST /signup {"email":"sam.lee@example.com","password":"correct-horse-battery","phone":"+44 20 7946 0958"}',
    '2026-11-11T09:16:44Z WARN  config loaded key=AKIAIOSFODNN7EXAMPLE region=eu-west-1',
    '2026-11-11T09:17:01Z INFO  address saved: 12 Fictional Row, Testville (free text: not caught)',
  ].join("\n");
  const REDACT_RULES = [
    { kind: "bearer token", re: /\b(Bearer\s+)[A-Za-z0-9._~+\/=-]{10,}/g, sub: (m, p) => p + "[token]" },
    { kind: "JWT", re: /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*/g, sub: () => "[jwt]" },
    { kind: "cloud key", re: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g, sub: () => "[cloud-key]" },
    { kind: "API token", re: /\b(ghp_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{16,})\b/g, sub: () => "[api-token]" },
    { kind: "password field", re: /(["']?password["']?\s*[:=]\s*["']?)[^"'\s,}]+/gi, sub: (m, p) => p + "[secret]" },
    { kind: "email", re: /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, sub: null },
    { kind: "card number", re: /\b(?:\d[ -]?){12,18}\d\b/g, sub: () => "[card]", ok: (m) => luhn(m.replace(/\D/g, "")) },
    { kind: "SSN-shaped number", re: /\b\d{3}-\d{2}-\d{4}\b/g, sub: () => "[id]" },
    { kind: "phone", re: /\+\d[\d\s().-]{7,}\d/g, sub: () => "[phone]" },
    { kind: "IP address", re: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, sub: () => "[ip]" },
  ];
  /** mode "mask": every match becomes a fixed label. mode "pseudonym": emails become a stable keyed token, so you can still count and join. */
  function redact(text, opts) {
    const o = Object.assign({ mode: "mask", key: "log-pseudonym-key" }, opts || {});
    let out = String(text || "");
    const findings = [];
    for (const r of REDACT_RULES) {
      out = out.replace(r.re, (...a) => {
        const m = a[0];
        if (r.ok && !r.ok(m)) return m;
        findings.push({ kind: r.kind, text: m });
        if (r.kind === "email") return o.mode === "pseudonym" ? "user_" + keyedPseudonym(o.key, m).slice(0, 8) : "[email]";
        return r.sub(...a);
      });
    }
    return { out, findings };
  }

  // ------------------------------------------------------------------ 10. access and audit
  const RECORDS = [
    { id: 1, name: "Dana Wren", email: "dana.wren@example.com", vip: false }, { id: 2, name: "Noor Ali", email: "noor.ali@example.com", vip: false },
    { id: 3, name: "Sam Lee", email: "sam.lee@example.com", vip: false }, { id: 4, name: "Kai North", email: "kai.north@example.com", vip: false },
    { id: 5, name: "Ivy Stone", email: "ivy.stone@example.com", vip: true }, { id: 6, name: "Max Dunn", email: "max.dunn@example.com", vip: false },
    { id: 7, name: "Tess Moore", email: "tess.moore@example.com", vip: false }, { id: 8, name: "Lee Ford", email: "lee.ford@example.com", vip: false },
  ];
  const REASONS = ["Open support ticket", "Customer asked by phone", "Fraud review", "Other"];
  /** Flag reveals that look like browsing: a lot by one person, with no ticket, or on high-profile accounts. */
  function auditReport(log, limit) {
    const lim = limit || 5;
    const byAgent = {};
    for (const e of log) (byAgent[e.agent] = byAgent[e.agent] || []).push(e);
    const alerts = [];
    for (const [agent, es] of Object.entries(byAgent)) {
      if (es.length > lim) alerts.push({ agent, why: `${es.length} reveals in one session (limit ${lim})` });
      const other = es.filter((e) => e.reason === "Other").length;
      if (other >= 2) alerts.push({ agent, why: `${other} reveals with the reason "Other"` });
      const vip = es.filter((e) => e.vip).length;
      if (vip) alerts.push({ agent, why: `${vip} reveal${vip === 1 ? "" : "s"} on a high-profile account` });
    }
    return { alerts, byAgent };
  }

  // ------------------------------------------------------------------ 11. retention
  const CLASSES = [
    { k: "logs", label: "Request logs", days: 30, hold: false, max: 120, per: 12, why: "debugging" },
    { k: "carts", label: "Abandoned carts", days: 30, hold: false, max: 90, per: 8, why: "recovery emails, if consented" },
    { k: "events", label: "Analytics events", days: 90, hold: false, max: 400, per: 14, why: "product decisions" },
    { k: "tickets", label: "Support tickets", days: 365, hold: false, max: 900, per: 10, why: "support history" },
    { k: "invoices", label: "Invoices", days: 2555, hold: false, max: 3200, per: 10, why: "tax and accounting law (varies by country)" },
  ];
  /** Every class has `per` records aged evenly from 0 to `max` days. A purge deletes what is older than its retention, unless held. */
  function purge(policy) {
    const rows = CLASSES.map((c) => {
      const p = policy[c.k] || { days: c.days, hold: false };
      const ages = Array.from({ length: c.per }, (_, i) => Math.round((i / (c.per - 1)) * c.max));
      const old = ages.filter((a) => a > p.days).length;
      return { k: c.k, label: c.label, total: c.per, deleted: p.hold ? 0 : old, held: p.hold ? old : 0, kept: c.per - (p.hold ? 0 : old), days: p.days, hold: !!p.hold, why: c.why };
    });
    const sum = (f) => rows.reduce((n, r) => n + r[f], 0);
    return { rows, deleted: sum("deleted"), held: sum("held"), kept: sum("kept"), total: sum("total") };
  }

  // ------------------------------------------------------------------ 12. deletion across every copy
  const DELSTORES = [
    { k: "db", label: "Main database", opts: [["Delete the rows", 0], ["Soft-delete flag only", null]], def: 0 },
    { k: "replica", label: "Read replica", opts: [["Follows the primary", 0]], def: 0, note: "replication lag, minutes" },
    { k: "cache", label: "Cache", opts: [["Expires on its own (TTL)", 1], ["Never expires, never evicted", null]], def: 0 },
    { k: "search", label: "Search index", opts: [["Remove from the index in the delete job", 0], ["Rebuilt weekly", 7], ["Nothing removes it", null]], def: 1 },
    { k: "warehouse", label: "Data warehouse", opts: [["Delete job runs nightly", 1], ["Never joined to the delete job", null]], def: 1 },
    { k: "logs", label: "Application logs", opts: [["No personal data written (redacted at write)", 0], ["Rotate after 30 days", 30], ["Kept forever", null]], def: 1 },
    { k: "vendor", label: "Analytics + support vendors", opts: [["Call each vendor's deletion API", 3], ["Wait for the vendor's own retention", 400], ["Nobody has asked them", null]], def: 1 },
    { k: "backups", label: "Backups (35-day cycle)", opts: [["Crypto-shred the customer's key", 0], ["Let backups age out; restore re-applies deletions", 35], ["Keep until someone remembers", null]], def: 1 },
  ];
  /** choice = {storeKey: optionIndex}. Each option gives the day the data is really gone, or null when nothing will ever remove it. */
  function deletionPlan(choice) {
    const rows = DELSTORES.map((s) => {
      const i = choice && choice[s.k] !== undefined ? choice[s.k] : s.def;
      const o = s.opts[i] || s.opts[s.def];
      return { k: s.k, label: s.label, option: o[0], day: o[1] };
    });
    const never = rows.filter((r) => r.day === null);
    const days = rows.filter((r) => r.day !== null).map((r) => r.day);
    return { rows, never: never.map((r) => r.label), last: never.length ? null : Math.max(...days), worstFinite: Math.max(...days, 0) };
  }

  // ------------------------------------------------------------------ 13. data subject requests
  const daysIn = (y, m) => new Date(Date.UTC(y, m + 1, 0)).getUTCDate();
  /** Add calendar months, clamping to the end of a short month (31 Jan + 1 month = 28 or 29 Feb). A common reading, not legal advice. */
  function addMonths(iso, n) {
    const [y, m, d] = iso.split("-").map(Number);
    const total = (m - 1) + n, yy = y + Math.floor(total / 12), mm = ((total % 12) + 12) % 12;
    const dd = Math.min(d, daysIn(yy, mm));
    return `${yy}-${String(mm + 1).padStart(2, "0")}-${String(dd).padStart(2, "0")}`;
  }
  function addDays(iso, n) { const t = new Date(iso + "T00:00:00Z"); t.setUTCDate(t.getUTCDate() + n); return t.toISOString().slice(0, 10); }
  const REGIMES = {
    gdpr: { label: "GDPR (Art. 12(3))", base: (d) => addMonths(d, 1), ext: (d) => addMonths(d, 3), baseText: "one month", extText: "two further months, if you tell them within the first month" },
    ccpa: { label: "CCPA/CPRA", base: (d) => addDays(d, 45), ext: (d) => addDays(d, 90), baseText: "45 calendar days", extText: "another 45 days, if you tell them" },
  };
  function dueDates(received, regime) { const r = REGIMES[regime]; return { base: r.base(received), ext: r.ext(received), baseText: r.baseText, extText: r.extText, label: r.label }; }
  const SAMPLE_USER = { id: "u_1042", email: "dana.wren@example.com", name: "Dana Wren", address: "12 Fictional Row, Testville", signedUp: "2023-02-14", orders: [{ id: "o-88", total: 41.5, date: "2026-10-02" }, { id: "o-91", total: 12.0, date: "2026-10-19" }], consents: { marketing: false, analytics: true } };
  /** An export is structured, machine-readable and limited to this person. Internal scores and other people's data stay out. */
  function exportRecord(u) { return JSON.stringify({ subject: u.id, exportedFrom: "example-shop", profile: { name: u.name, email: u.email, address: u.address, signedUp: u.signedUp }, orders: u.orders, consents: u.consents }, null, 2); }

  // ------------------------------------------------------------------ 14. LINDDUN prompts
  const LINDDUN = [
    { k: "L", name: "Linking", q: "Can two records or actions be tied to one person?" },
    { k: "I", name: "Identifying", q: "Can someone work out who a record is about?" },
    { k: "N", name: "Non-repudiation", q: "Can someone be stopped from denying something they should be able to deny?" },
    { k: "D", name: "Detecting", q: "Can someone tell a person is in the system, without seeing the data?" },
    { k: "D2", name: "Data disclosure", q: "Is more data shown to more people than the purpose needs?" },
    { k: "U", name: "Unawareness and unintervenability", q: "Do people know what you hold, and can they correct or delete it?" },
    { k: "N2", name: "Non-compliance", q: "Do data and process match the law, policy and what people were told?" },
  ];
  const MITIGATIONS = ["Not considered yet", "Accept the risk (owner and review date written down)", "Reduce it in the design"];
  const FEATURES = [
    { k: "fit", label: "A fitness app with friend leaderboards", threats: [
      "Leaderboard names plus run times let a stranger link a runner to their home street.", "Public profiles show real names, photos and start points.",
      "Activity logs could be used to show someone was at a place at a time they say they weren't.", "A friend request that is accepted or ignored reveals that someone uses the app.",
      "Every friend sees every route, not just the totals.", "Nobody can see or fix the 'inferred health score' the app keeps.", "Location history kept for years, but the policy says 90 days."] },
    { k: "door", label: "A smart doorbell with cloud video", threats: [
      "Clips from different homes can be matched to the same visitor.", "Faces of neighbours and passers-by are recognisable in the footage.",
      "A cloud log can prove who was home at a given time, even when they'd rather not say.", "Motion alerts reveal when the house is empty.",
      "Support staff can open any customer's live view.", "Visitors on the porch never learn that they are being recorded.", "Clips are kept for a year; the notice says 30 days."] },
    { k: "hr", label: "An HR portal with sick-leave tracking", threats: [
      "Leave records join to payroll and to badge swipes.", "Rare roles make a 'team report' point at one person.",
      "An audit log forces someone to be tied to a leave request they'd withdrawn.", "A calendar showing 'out' in a small team reveals who is ill.",
      "Managers see the reason for leave, not only the dates.", "Employees can't see what is stored about them.", "Health notes kept after the legal retention period."] },
  ];
  function linddunCoverage(choice) {
    const covered = LINDDUN.filter((c) => (choice[c.k] || 0) > 0).length;
    return { covered, total: LINDDUN.length, open: LINDDUN.filter((c) => !(choice[c.k] > 0)).map((c) => c.name) };
  }

  const api = {
    escapeHtml, mulberry32, luhn, spot,
    PEOPLE, ZIP_LEVELS, BIRTH_LEVELS, genZip, genBirth, quasi, anonymity, lookup,
    FIELDS, minimiseReport, PURPOSES, DATA, access, STORES, MAP_FIELDS, whereIs,
    makeVault, normaliseEmail, plainHash, keyedPseudonym, CANDIDATES, TABLE_EMAILS, reverseAttack,
    laplace, noisyCount, expectedAbsError, noiseRuns, mean, histogram,
    SAMPLE_LOG, REDACT_RULES, redact, RECORDS, REASONS, auditReport,
    CLASSES, purge, DELSTORES, deletionPlan, addMonths, addDays, REGIMES, dueDates, SAMPLE_USER, exportRecord,
    LINDDUN, MITIGATIONS, FEATURES, linddunCoverage,
  };
  if (typeof module !== "undefined" && module.exports) module.exports = api; else root.PrivLab = api;
})(typeof window !== "undefined" ? window : globalThis);
