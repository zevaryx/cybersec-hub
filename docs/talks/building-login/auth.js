/* auth.js - teaching versions of the server-side parts of "Building Login and Accounts Safely".
   Real SHA-1/SHA-256/HMAC and real P-256 ECDSA from ../../shared/crypto.js; Argon2id comes from hash-wasm in the page.
   TEACHING CODE, NEVER FOR A REAL LOGIN: use your framework's or provider's implementation.
   Everything is a simulation in this page: no server, no database, no network.
   Works in the browser (window.Auth) and in Node (module.exports) so it can be tested. */
(function (root) {
  "use strict";
  const L = root.Lab || (typeof require !== "undefined" ? require("../../shared/crypto.js") : null);
  const { hex, concat, utf8, randBytes, equalBytes, sha256, sha1 } = L;

  const b64u = (bytes) => {
    let s = "";
    for (const b of bytes) s += String.fromCharCode(b);
    return (typeof btoa === "function" ? btoa(s) : Buffer.from(s, "binary").toString("base64")).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };
  const token = (n = 32) => b64u(randBytes(n));
  const sha256hex = (s) => hex(sha256(utf8(s)));
  const sameText = (a, b) => equalBytes(utf8(String(a)), utf8(String(b)));   // compares the bytes, not the length first

  // =========================================================================== 1. password rules (NIST SP 800-63B-4 style)
  // A toy blocklist. A real one is a breached-password service or a list of millions.
  const COMMON = ["password", "123456", "12345678", "123456789", "qwerty", "qwerty123", "letmein", "hunter2", "admin", "welcome",
    "welcome1", "iloveyou", "dragon", "monkey", "football", "baseball", "111111", "abc123", "password1", "password123", "passw0rd",
    "p@ssw0rd", "password1!", "summer2019", "summer2024", "winter2025", "changeme", "letmein123", "trustno1", "sunshine", "master",
    "login", "starwars", "whatever", "qazwsx", "1q2w3e4r", "zaq12wsx", "princess", "shadow", "superman"];
  const BLOCK = new Set(COMMON);
  const cps = (s) => Array.from(s.normalize("NFC")).length;                     // code points, after NFC normalisation
  const oldStyleOk = (pw) => /[a-z]/.test(pw) && /[A-Z]/.test(pw) && /\d/.test(pw) && /[^A-Za-z0-9]/.test(pw) && pw.length >= 8;
  /** Check a new password the way NIST SP 800-63B-4 suggests. mfa=true: the password is one of two factors. */
  function checkPassword(pw, { mfa = false, username = "", maxLen = 128 } = {}) {
    const n = cps(pw), min = mfa ? 8 : 15, bytes = utf8(pw.normalize("NFC")).length, out = [];
    const lower = pw.normalize("NFC").toLowerCase(), u = username.trim().toLowerCase();
    out.push(n >= min ? { id: "len", ok: true, text: `${n} characters (minimum ${min}${mfa ? ", with a second factor" : ", on its own"})` }
      : { id: "len", ok: false, text: `${n} characters: needs at least ${min}${mfa ? " (with a second factor)" : " (on its own)"}` });
    out.push(n <= maxLen ? { id: "max", ok: true, text: `accepted up to ${maxLen} characters (NIST: allow at least 64), spaces and Unicode included` }
      : { id: "max", ok: false, text: `over ${maxLen} characters: this demo's cap (allow at least 64 in real life)` });
    const blocked = BLOCK.has(lower), ctx = !!u && u.length >= 3 && lower.includes(u);
    out.push(blocked ? { id: "block", ok: false, text: "on the blocklist: a commonly used or breached password. Say why, and ask for another" }
      : ctx ? { id: "block", ok: false, text: "contains the username: an expected guess. Ask for another" }
        : { id: "block", ok: true, text: "not on the toy blocklist (a real check asks a breached-password list, below)" });
    out.push({ id: "comp", ok: true, text: "no rule about upper case, digits or symbols: complexity rules make people predictable, not strong" });
    if (bytes > 72) out.push({ id: "bcrypt", ok: null, text: `${bytes} bytes: bcrypt ignores everything after byte 72. Argon2id has no such limit` });
    return { n, bytes, min, checks: out, accepted: out.every((c) => c.ok !== false), oldStyle: oldStyleOk(pw) };
  }
  /** Have I Been Pwned's range API, offline: what leaves the page is the first five hex characters of the SHA-1 only. */
  function pwnedRange(pw) {
    const h = hex(sha1(utf8(pw))).toUpperCase();
    return { sha1: h, prefix: h.slice(0, 5), suffix: h.slice(5), url: "https://api.pwnedpasswords.com/range/" + h.slice(0, 5) };
  }
  const isBlocked = (pw) => BLOCK.has(pw.normalize("NFC").toLowerCase());

  // =========================================================================== 2. password storage and rehash on login
  /** OWASP's Argon2id minimum settings (p = 1): these (memory KiB, iterations) pairs are treated as equivalent. */
  const ARGON_POLICY = { m: 19456, t: 2, p: 1, accept: [[19456, 2], [47104, 1], [12288, 3], [9216, 4], [7168, 5]] };
  function parseArgon(s) {
    const m = /^\$argon2(id|i|d)\$v=(\d+)\$m=(\d+),t=(\d+),p=(\d+)\$/.exec(s || "");
    return m ? { type: m[1], v: +m[2], m: +m[3], t: +m[4], p: +m[5] } : null;
  }
  /** What kind of record is this, and is it good enough? */
  function hashStatus(stored) {
    if (/^(sha1|sha256|md5):/.test(stored)) return { kind: stored.split(":")[0], good: false, why: "a fast, unsalted hash: guessable at billions per second" };
    const a = parseArgon(stored);
    if (!a) return { kind: "unknown", good: false, why: "an unknown format: treat as needing a reset" };
    if (a.type !== "id") return { kind: "argon2" + a.type, good: false, why: "Argon2" + a.type + ": use the id variant" };
    const ok = ARGON_POLICY.accept.some(([m, t]) => a.m >= m && a.t >= t) && a.p >= 1;
    return ok ? { kind: "argon2id", good: true, why: `Argon2id at m=${a.m} KiB, t=${a.t}: meets the minimum` }
      : { kind: "argon2id", good: false, why: `Argon2id, but m=${a.m} KiB, t=${a.t} is below the minimum (19456 KiB, t=2)` };
  }
  /** Check a password against a stored record. H = { argon2id(pw) -> encoded string, verify(encoded, pw) -> bool }. */
  async function verifyStored(stored, pw, H) {
    if (stored.startsWith("sha1:")) return sameText(stored.slice(5), hex(sha1(utf8(pw))));
    if (stored.startsWith("sha256:")) return sameText(stored.slice(7), sha256hex(pw));
    if (stored.startsWith("$argon2")) return !!(await H.verify(stored, pw));
    return false;
  }
  /** Log in; on success, if the stored hash is out of date, replace it with a fresh Argon2id hash of the password just typed. */
  async function loginWithRehash(db, name, pw, H) {
    const rec = db[name];
    if (!rec) { await H.argon2id("dummy-password-for-timing"); return { ok: false }; }      // same work either way
    if (rec.expired) return { ok: false, expired: true };
    const ok = await verifyStored(rec.hash, pw, H);
    if (!ok) return { ok: false };
    const before = hashStatus(rec.hash);
    if (before.good) return { ok: true, rehashed: false, from: before };
    rec.hash = await H.argon2id(pw);
    return { ok: true, rehashed: true, from: before, to: hashStatus(rec.hash) };
  }
  /** Accounts nobody has logged in to since the policy changed: the sweep. Expire (force a reset), don't leave them weak. */
  function sweepExpire(db) {
    const done = [];
    for (const [name, rec] of Object.entries(db)) if (!hashStatus(rec.hash).good && !rec.expired) { rec.expired = true; done.push(name); }
    return done;
  }

  // =========================================================================== 3. sessions
  const MIN = 60, HOUR = 3600;
  class SessionStore {
    /** The store keeps SHA-256(id), never the ID itself: a leaked table can't be used as cookies. */
    constructor({ idle = 30 * MIN, absolute = 8 * HOUR } = {}) { this.idle = idle; this.absolute = absolute; this.now = 0; this.rows = new Map(); }
    advance(sec) { this.now += sec; }
    _key(id) { return sha256hex(id); }
    /** An anonymous session (e.g. before login), or one for a user. */
    create(user = null, device = "") {
      const id = token(32);
      this.rows.set(this._key(id), { user, device, created: this.now, last: this.now, revoked: null });
      return id;
    }
    get(id) { return this.rows.get(this._key(id)) || null; }
    /** Is this ID good right now? Touches last-seen on success. */
    check(id) {
      const r = this.get(id);
      if (!r) return { ok: false, reason: "unknown ID" };
      if (r.revoked) return { ok: false, reason: "revoked: " + r.revoked };
      if (this.now - r.last > this.idle) return { ok: false, reason: "idle too long" };
      if (this.now - r.created > this.absolute) return { ok: false, reason: "absolute lifetime over" };
      r.last = this.now;
      return { ok: true, user: r.user, device: r.device };
    }
    /** Log a user in. If rotate: issue a brand-new ID and kill any ID the browser arrived with (stops session fixation). */
    login(user, device, presented, { rotate = true } = {}) {
      const old = presented && this.get(presented);
      if (rotate || !old) {
        if (old) old.revoked = "replaced at login";
        return this.create(user, device);
      }
      old.user = user; old.device = device; old.created = this.now; old.last = this.now;      // the unsafe way: keep the ID, add the user
      return presented;
    }
    /** After a password change: new ID for this device, every other session ended. */
    changePassword(user, currentId) {
      const keep = this.get(currentId); if (keep) keep.revoked = "replaced at password change";
      this.revokeAll(user, "password changed");
      return this.create(user, keep ? keep.device : "");
    }
    revokeAll(user, why = "signed out everywhere") { let n = 0; for (const r of this.rows.values()) if (r.user === user && !r.revoked) { r.revoked = why; n++; } return n; }
    list(user) { return [...this.rows.entries()].filter(([, r]) => r.user === user).map(([k, r]) => ({ key: k, ...r })); }
  }

  // =========================================================================== 4. refresh tokens with rotation and reuse detection
  class RefreshGrant {
    constructor() { this.current = null; this.used = new Set(); this.revoked = false; this.count = 0; }
    issue() { const t = "rt_" + token(16); this.current = t; this.count++; return t; }
    /** Exchange a refresh token for a new one. Presenting an old one means someone has a copy: end the whole grant. */
    refresh(t) {
      if (this.revoked) return { ok: false, reason: "grant revoked: the user must sign in again" };
      if (t === this.current) { this.used.add(t); return { ok: true, token: this.issue() }; }
      if (this.used.has(t)) { this.revoked = true; this.current = null; return { ok: false, reuse: true, reason: "an already-used refresh token was presented: copy detected, grant revoked" }; }
      return { ok: false, reason: "unknown token" };
    }
  }

  // =========================================================================== 5. TOTP, the server's side (RFC 6238)
  class TotpVerifier {
    /** window = how many steps either side of now to accept (RFC 6238 recommends allowing at most one step for delay). */
    constructor(secret, { step = 30, window = 1, digits = 6 } = {}) { this.secret = secret; this.step = step; this.window = window; this.digits = digits; this.last = -1; this.fails = 0; }
    codeAt(counter) { return L.hotp(this.secret, counter, this.digits).code; }
    verify(code, nowSec) {
      const c = String(code).trim();
      if (!new RegExp("^\\d{" + this.digits + "}$").test(c)) return { ok: false, reason: "format", message: `Enter the ${this.digits}-digit code.` };
      const now = Math.floor(nowSec / this.step);
      let hit = null;
      for (let d = -this.window; d <= this.window; d++) {          // check every slot; don't stop at the first (no timing difference)
        if (sameText(this.codeAt(now + d), c) && hit === null) hit = d;
      }
      if (hit === null) { this.fails++; return { ok: false, reason: "wrong", message: "Code doesn't match." }; }
      const counter = now + hit;
      if (counter <= this.last) return { ok: false, reason: "reused", counter, message: "That code was already used. Wait for the next one." };
      this.last = counter; this.fails = 0;
      return { ok: true, counter, drift: hit, message: hit === 0 ? "Accepted." : `Accepted, ${Math.abs(hit)} step${Math.abs(hit) > 1 ? "s" : ""} ${hit < 0 ? "behind" : "ahead"} (clock drift).` };
    }
  }

  // =========================================================================== 6. WebAuthn (passkeys), simulated with real P-256 ECDSA
  const SPKI_P256 = Uint8Array.from("3059301306072a8648ce3d020106082a8648ce3d030107034200".match(/../g).map((h) => parseInt(h, 16)));
  const be32 = (n) => Uint8Array.of((n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);
  const FLAGS = { UP: 0x01, UV: 0x04, BE: 0x08, BS: 0x10 };
  const bigBytes = (x, n = 32) => L.fromHex(x.toString(16).padStart(n * 2, "0"));
  function derInt(x) {                                           // minimal DER INTEGER for a positive big number
    let b = L.fromHex(x.toString(16).padStart(x.toString(16).length + (x.toString(16).length % 2), "0"));
    if (b[0] & 0x80) b = concat(Uint8Array.of(0), b);
    return concat(Uint8Array.of(0x02, b.length), b);
  }
  const derSigOf = (r, s) => { const body = concat(derInt(r), derInt(s)); return concat(Uint8Array.of(0x30, body.length), body); };

  /** An authenticator with one passkey: a P-256 key pair that never leaves it. */
  class Authenticator {
    constructor() {
      this.d = L.randBelow(L.P256.n - 1n) + 1n;
      this.Q = L.P256.mul(this.d);
      this.spki = concat(SPKI_P256, Uint8Array.of(4), bigBytes(this.Q[0]), bigBytes(this.Q[1]));
      this.credentialId = b64u(randBytes(16));
      this.signCount = 0;
    }
    /** Sign for a given site. The BROWSER supplies rpId and origin, so a look-alike site can't ask for this site's key. */
    sign({ rpId, origin, challenge, type = "webauthn.get", flags = FLAGS.UP | FLAGS.UV | FLAGS.BE | FLAGS.BS, counter = undefined }) {
      this.signCount = counter === undefined ? this.signCount + 1 : counter;
      const authData = concat(sha256(utf8(rpId)), Uint8Array.of(flags), be32(this.signCount));
      const clientDataJSON = utf8(JSON.stringify({ type, challenge, origin, crossOrigin: false }));
      const h = L.toBig(sha256(concat(authData, sha256(clientDataJSON))));
      const [r, s] = L.ecdsaSign(this.d, h, L.randBelow(L.P256.n - 1n) + 1n);
      return { credentialId: this.credentialId, authData, clientDataJSON, signature: derSigOf(r, s) };
    }
  }
  class RelyingParty {
    constructor(rpId, origin) { this.rpId = rpId; this.origin = origin; this.creds = new Map(); this.pending = new Set(); }
    challenge() { const c = token(32); this.pending.add(c); return c; }
    /** What the server keeps for a passkey: an ID, a public key, a counter and a couple of flags. Never a secret. */
    register(auth) {
      const rec = { credentialId: auth.credentialId, publicKey: auth.spki, signCount: 0, backupEligible: true, rpIdHash: sha256(utf8(this.rpId)) };
      this.creds.set(rec.credentialId, rec); return rec;
    }
    /** Verify a login assertion, step by step (a simplified WebAuthn section 7.2). Returns the list of checks. */
    verify(resp) {
      const steps = [], fail = (name, detail) => { steps.push({ name, ok: false, detail }); return { ok: false, steps }; };
      const rec = this.creds.get(resp.credentialId);
      if (!rec) return fail("credential ID is one we know", "unknown credential");
      steps.push({ name: "credential ID is one we know", ok: true, detail: "found the stored public key" });
      let cd; try { cd = JSON.parse(L.text(resp.clientDataJSON)); } catch (e) { return fail("clientDataJSON parses", "not JSON"); }
      if (cd.type !== "webauthn.get") return fail("type is webauthn.get", cd.type);
      steps.push({ name: "type is webauthn.get", ok: true, detail: "" });
      if (!this.pending.has(cd.challenge)) return fail("challenge is one we issued, and unused", "unknown or already used");
      this.pending.delete(cd.challenge);                                        // single use, whatever happens next
      steps.push({ name: "challenge is one we issued, and unused", ok: true, detail: "now spent: it can't be used twice" });
      if (cd.origin !== this.origin) return fail("origin is ours", `${cd.origin} is not ${this.origin}`);
      steps.push({ name: "origin is ours", ok: true, detail: cd.origin });
      if (!equalBytes(resp.authData.subarray(0, 32), sha256(utf8(this.rpId)))) return fail("rpIdHash = SHA-256(our RP ID)", "hash of a different site");
      steps.push({ name: "rpIdHash = SHA-256(our RP ID)", ok: true, detail: this.rpId });
      const flags = resp.authData[32];
      if (!(flags & FLAGS.UP)) return fail("user was present (UP flag)", "no touch or presence");
      steps.push({ name: "user was present, and verified (UP, UV flags)", ok: true, detail: flags & FLAGS.UV ? "touch plus fingerprint, face or PIN" : "touch only" });
      let sigOk = false; try { sigOk = L.verifyPasskey(rec.publicKey, resp.authData, resp.clientDataJSON, resp.signature); } catch (e) { sigOk = false; }
      if (!sigOk) return fail("signature checks out with the stored public key", "signature invalid");
      steps.push({ name: "signature checks out with the stored public key", ok: true, detail: "over authData + SHA-256(clientDataJSON)" });
      const cnt = new DataView(resp.authData.buffer, resp.authData.byteOffset + 33, 4).getUint32(0);
      if ((cnt !== 0 || rec.signCount !== 0) && cnt <= rec.signCount) {
        steps.push({ name: "signature counter went up", ok: false, detail: `${cnt} is not above ${rec.signCount}: a cloned key, or a fault. Decide your own policy` });
        return { ok: false, clone: true, steps };
      }
      steps.push({ name: "signature counter went up", ok: true, detail: cnt === 0 ? "0 stays 0: many synced passkeys don't count" : `${rec.signCount} → ${cnt}` });
      rec.signCount = cnt;
      return { ok: true, steps };
    }
  }

  // =========================================================================== 7. password reset tokens and recovery codes
  class ResetService {
    /** The service emails the raw token and stores only its SHA-256: a leaked table can't be used as reset links. */
    constructor({ ttl = 30 * MIN, perHour = 3 } = {}) { this.ttl = ttl; this.perHour = perHour; this.now = 0; this.db = []; this.outbox = []; this.sent = []; this.log = []; }
    advance(sec) { this.now += sec; }
    request(email, exists = true) {
      const generic = "If that account exists, we've emailed a reset link.";      // the same answer in every case
      if (!exists) { this.log.push("no such account: nothing sent (same response)"); return { message: generic }; }
      this.sent = this.sent.filter((t) => this.now - t < HOUR);
      if (this.sent.length >= this.perHour) { this.log.push(`more than ${this.perHour} requests this hour: nothing sent (same response)`); return { message: generic, suppressed: true }; }
      this.sent.push(this.now);
      for (const r of this.db) if (r.email === email && !r.used) r.used = "replaced by a newer link";
      const t = token(32);
      this.db.push({ email, hash: sha256hex(t), expires: this.now + this.ttl, used: null });
      this.outbox.push({ to: email, token: t });
      this.log.push("emailed a new link; stored only its hash");
      return { message: generic, token: t };
    }
    redeem(t) {
      const r = this.db.find((x) => sameText(x.hash, sha256hex(t)));
      if (!r) return { ok: false, reason: "no such link" };
      if (r.used) return { ok: false, reason: r.used === true ? "already used" : r.used };
      if (this.now > r.expires) return { ok: false, reason: "expired" };
      r.used = true;
      return { ok: true, email: r.email, after: ["set the new password", "end every other session", "email the user that the password changed", "don't sign them in automatically"] };
    }
  }
  const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  /** Ten recovery codes, 16 random Base32 characters each (80 bits). Stored as SHA-256 hashes, single use. */
  class RecoveryCodes {
    constructor(n = 10) { this.codes = []; this.rows = []; for (let i = 0; i < n; i++) { const c = this._make(); this.codes.push(c); this.rows.push({ hash: sha256hex(this._norm(c)), used: false }); } }
    _make() { const r = randBytes(16); let s = ""; for (const b of r) s += B32[b & 31]; return s.match(/.{4}/g).join("-"); }
    _norm(c) { return String(c).toUpperCase().replace(/[^A-Z2-7]/g, ""); }
    redeem(c) {
      const h = sha256hex(this._norm(c)), row = this.rows.find((r) => sameText(r.hash, h));
      if (!row) return { ok: false, reason: "not a recovery code for this account" };
      if (row.used) return { ok: false, reason: "that code was already used" };
      row.used = true; return { ok: true, left: this.rows.filter((r) => !r.used).length };
    }
    get left() { return this.rows.filter((r) => !r.used).length; }
  }

  // =========================================================================== 8. credential stuffing, as a toy model
  function rng(seed) { let a = seed >>> 0; return () => { a = (a + 0x6D2B79F5) >>> 0; let t = a; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }
  /** One attacker, 2,000 stolen (email, password) pairs, one try per account. All the rates below are invented for the demo. */
  function simulateStuffing({ ips = 500, ipLimit = false, breachCheck = false, risk = false, mfaPct = 0, seed = 7, accounts = 2000, reuse = 0.2, inBreach = 0.85, perIp = 5 } = {}) {
    const R = rng(seed), order = [], fails = new Map();
    for (let i = 0; i < accounts; i++) order.push({ valid: R() < reuse, breached: R() < inBreach, mfa: R() < mfaPct / 100, riskCatch: R() < 0.95 });
    const s = { tries: 0, blockedIp: 0, wrong: 0, breachBlocked: 0, riskBlocked: 0, mfaBlocked: 0, takenOver: 0, valid: 0 };
    order.forEach((a, i) => {
      const ip = i % Math.max(1, ips), f = fails.get(ip) || 0;
      if (ipLimit && f >= perIp) { s.blockedIp++; return; }
      s.tries++;
      if (!a.valid) { s.wrong++; fails.set(ip, f + 1); return; }
      s.valid++;
      if (breachCheck && a.breached) { s.breachBlocked++; return; }
      if (risk && a.riskCatch) { s.riskBlocked++; return; }
      if (a.mfa) { s.mfaBlocked++; return; }
      s.takenOver++;
    });
    // what honest users feel, per 1,000 sign-ins asked for an extra step (all shares invented):
    // risk checks interrupt about 8% (new device or place); MFA prompts about 30% of an enrolled user's sign-ins ("remember this device")
    const pRisk = risk ? 0.08 : 0, pMfa = (mfaPct / 100) * 0.3;
    s.friction = Math.round(1000 * (1 - (1 - pRisk) * (1 - pMfa)));
    return s;
  }

  // =========================================================================== 9. account enumeration
  /** What a login endpoint says. naive: a different message and a different cost for "no such account". */
  function loginResponse(mode, accountExists, passwordOk) {
    if (mode === "naive") {
      if (!accountExists) return { status: 404, body: "No account with that email.", hashes: false };
      if (!passwordOk) return { status: 401, body: "Incorrect password.", hashes: true };
      return { status: 200, body: "Welcome back.", hashes: true };
    }
    if (passwordOk && accountExists) return { status: 200, body: "Welcome back.", hashes: true };
    return { status: 401, body: "Invalid email or password.", hashes: true };            // hashes a dummy value when there's no account
  }

  root.Auth = {
    b64u, token, sha256hex, sameText, COMMON, checkPassword, pwnedRange, isBlocked, oldStyleOk,
    ARGON_POLICY, parseArgon, hashStatus, verifyStored, loginWithRehash, sweepExpire,
    SessionStore, RefreshGrant, TotpVerifier, FLAGS, Authenticator, RelyingParty, derSigOf, ResetService, RecoveryCodes,
    simulateStuffing, loginResponse,
  };
  if (typeof module !== "undefined" && module.exports) module.exports = root.Auth;
})(typeof window !== "undefined" ? window : globalThis);
