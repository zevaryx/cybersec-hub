/* secrets.js - the logic behind this talk's demos, kept apart from the page so it can be tested in Node.
   EDUCATIONAL ONLY. It reuses the from-scratch maths in ../../shared/crypto.js (AES-GCM, ECDSA P-256, SHA-1/256), so nothing
   here should protect real data. Every key, token and "cloud" in the demos is made up on the spot and never leaves the page. */
(function (root) {
  "use strict";
  const L = root.Lab || (typeof require !== "undefined" ? require("../../shared/crypto.js") : null);

  // --------------------------------------------------------------------------- 1. a toy secret scanner
  /** Shannon entropy in bits per character: how "random-looking" a string is. */
  function entropy(s) {
    if (!s.length) return 0;
    const f = new Map();
    for (const ch of s) f.set(ch, (f.get(ch) || 0) + 1);
    let h = 0;
    for (const n of f.values()) { const p = n / s.length; h -= p * Math.log2(p); }
    return h;
  }
  const PEM = "-----BEGIN " + "(?:[A-Z]+ )?PRIVATE KEY-----";
  // [name, regex, level, why]. level: bad = a real secret format, y = worth a look, ok = known harmless example
  const RULES = [
    ["private key", new RegExp(PEM, "g"), "bad", "A private key. Anyone holding it can be you."],
    ["AWS access key ID", /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, "bad", "Looks like an AWS access key ID (AKIA = long-lived, ASIA = temporary). The secret half is usually nearby."],
    ["GitHub token", /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b/g, "bad", "Matches GitHub's token format (the prefix is there so scanners can find it)."],
    ["Slack token", /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g, "bad", "Matches Slack's token format."],
    ["live API key", /\b(?:sk|rk)_live_[A-Za-z0-9]{8,}\b/g, "bad", "A secret-key prefix used by payment APIs. Secret keys never belong in code."],
    ["URL with password", /\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@"']+:[^\s@"']+@[^\s"']+/gi, "bad", "A connection string with the password inside it."],
    ["hard-coded password", /(?<![A-Za-z])(?:password|passwd|pwd|secret|token|api[_-]?key)[A-Za-z0-9_]*["']?\s*[:=]\s*["']?([^\s"',;]{4,})/gi, "y", "A secret-looking name assigned a literal value. No known format, so only a pattern like this can find it."],
  ];
  const EXAMPLES = new Set(["AKIAIOSFODNN7EXAMPLE"]);        // AWS's own documentation example key ID
  const PLACEHOLDER = /^(?:changeme|change_me|your[_-]?.*|<.*>|\$\{?.*\}?|xxx+|\*+|example|todo|null|none|process\.env.*|os\.environ.*)$/i;

  /** Scan text. Returns non-overlapping findings [{start, end, text, kind, level, why}] in order. */
  function scan(text) {
    const hits = [];
    for (const [kind, re, level, why] of RULES) {
      for (const m of text.matchAll(new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g"))) {
        let start = m.index, end = m.index + m[0].length, t = m[0];
        if (kind === "hard-coded password") {               // highlight just the value, and skip obvious placeholders
          const v = m[1]; if (PLACEHOLDER.test(v)) continue;
          start = end - v.length; t = v;
        }
        if (EXAMPLES.has(t)) hits.push({ start, end, text: t, kind: "AWS documentation example", level: "ok", why: "The example key from AWS's own docs. It has never opened anything." });
        else hits.push({ start, end, text: t, kind, level, why });
      }
    }
    // entropy: long strings of key-like characters that no rule claimed
    for (const m of text.matchAll(/[A-Za-z0-9+/_=-]{20,}/g)) {
      const t = m[0], start = m.index, end = start + t.length;
      if (hits.some((h) => start < h.end && end > h.start)) continue;
      const e = entropy(t);
      if (/^[0-9a-f]{32,}$/i.test(t)) hits.push({ start, end, text: t, kind: "hex string", level: "y", why: `${t.length} hex characters (${e.toFixed(1)} bits/char). A key, or just a hash or commit ID? Entropy alone can't tell.` });
      else if (e >= 4.2 && /[A-Z]/.test(t) && /[a-z]/.test(t) && /\d/.test(t)) hits.push({ start, end, text: t, kind: "high-entropy string", level: "y", why: `${e.toFixed(1)} bits per character: random-looking, so worth a look. Could be a key, could be a build ID.` });
    }
    hits.sort((a, b) => a.start - b.start || b.end - a.end);
    const out = [];
    for (const h of hits) if (!out.length || h.start >= out[out.length - 1].end) out.push(h);
    return out;
  }

  // --------------------------------------------------------------------------- 2. what a container build leaves behind
  const SECRET = "sk_live_EXAMPLE_not_a_real_key";
  /** How a secret reaches a build, and what's left in the final image. */
  function imageBuild(method) {
    const M = {
      arg: {
        name: "ARG",
        dockerfile: ["FROM node:22-slim", "ARG NPM_TOKEN", "RUN echo \"//registry.example.com/:_authToken=$NPM_TOKEN\" > ~/.npmrc \\", "    && npm ci", "COPY . ."],
        history: ["ARG NPM_TOKEN=" + SECRET, "RUN |1 NPM_TOKEN=" + SECRET + " /bin/sh -c echo ... > ~/.npmrc && npm ci"],
        leaks: true,
        verdict: "Recoverable. Build arguments are recorded in the image's history, and the .npmrc written in that layer is still in the layer. Docker's docs say build arguments and environment variables are inappropriate for secrets because they persist in the final image.",
      },
      env: {
        name: "ENV",
        dockerfile: ["FROM node:22-slim", "ENV API_KEY=" + SECRET, "COPY . .", "CMD [\"node\", \"server.js\"]"],
        history: ["ENV API_KEY=" + SECRET],
        leaks: true,
        verdict: "Recoverable by anyone who can pull the image: docker inspect shows the environment, and every container started from it has the value.",
      },
      copy: {
        name: "COPY .env, then delete it",
        dockerfile: ["FROM node:22-slim", "COPY .env .env", "RUN ./build.sh", "RUN rm .env", "COPY . ."],
        history: ["COPY .env .env", "RUN rm .env"],
        leaks: true,
        verdict: "Recoverable. Each instruction makes a layer, and a later rm only hides the file in the layers above it. Unpack the earlier layer and .env is right there.",
      },
      mount: {
        name: "RUN --mount=type=secret",
        dockerfile: ["# syntax=docker/dockerfile:1", "FROM node:22-slim", "RUN --mount=type=secret,id=npm_token \\", "    NPM_TOKEN=$(cat /run/secrets/npm_token) ./install.sh", "COPY . ."],
        history: ["RUN /bin/sh -c ./install.sh (mount type=secret)"],
        leaks: false,
        verdict: "Not in the image. The secret is mounted only while that one instruction runs, so it isn't kept in a layer or in the build history. (Your build script must still not write it to a file that ends up in the image.)",
      },
    };
    return M[method];
  }

  // --------------------------------------------------------------------------- 3. the git history demo
  /** A toy repository. Commit IDs are SHA-1 hashes of the commit's content: a real property of Git, simplified. */
  function makeRepo() {
    const mk = (parent, msg, files) => {
      const body = `parent ${parent || "-"}\n${msg}\n` + Object.keys(files).sort().map((f) => `${f}:${files[f]}`).join("\n");
      return { id: L.hex(L.sha1(L.utf8(body))).slice(0, 7), parent, msg, files, body };
    };
    const c1 = mk(null, "Add the app", { "app.py": "print('hello')" });
    const c2 = mk(c1.id, "Add settings", { "app.py": "print('hello')", "settings.py": "API_KEY = '" + SECRET + "'" });
    return { mk, commits: [c1, c2], copies: { clone: [c1.id, c2.id], fork: [c1.id, c2.id], cache: [c2.id] }, revoked: false, rewritten: false };
  }
  function repoDeleteInNextCommit(r) {
    const head = r.commits[r.commits.length - 1];
    const files = Object.assign({}, head.files); delete files["settings.py"]; files["settings.py"] = "API_KEY = os.environ['API_KEY']";
    r.commits.push(r.mk(head.id, "Remove the key from settings", files));
    return r;
  }
  function repoRewrite(r) {
    const bad = r.commits.find((c) => /Add settings/.test(c.msg));
    const keep = [r.commits[0]];
    const fixed = r.mk(r.commits[0].id, "Add settings", { "app.py": "print('hello')", "settings.py": "API_KEY = os.environ['API_KEY']" });
    keep.push(fixed);
    r.commits = keep; r.rewritten = true; r.oldId = bad.id;
    return r;
  }
  /** Where the key can still be found, and whether it still works. */
  function repoWhere(r) {
    const inHistory = r.commits.some((c) => Object.values(c.files).some((v) => v.includes(SECRET)));
    return [
      { where: "origin: the repository's history", found: inHistory, why: inHistory ? "git log -p shows the key in the commit that added it." : "History was rewritten and force-pushed, so the new history doesn't contain it." },
      { where: "every existing clone", found: true, why: "Each teammate's and CI runner's copy still has the old commits until they delete or re-clone it." },
      { where: "every fork", found: true, why: "GitHub's own guide: a commit in any fork stays accessible there." },
      { where: "the old commit by its ID", found: true, why: "GitHub's guide says commits can stay reachable by SHA in cached views; researchers have found secrets in force-pushed commits, too." },
    ];
  }
  const KEY_STATE = (r) => r.revoked ? { ok: true, text: "The key was revoked at the provider. Whoever copied it now holds a dead string." } : { ok: false, text: "The key still works. Every copy above is a working door." };

  // --------------------------------------------------------------------------- 4. envelope encryption (real AES-GCM from crypto.js)
  const mkMaster = (n) => ({ id: "master-v" + n, key: L.randBytes(32) });
  /** Encrypt one record with a fresh data key, then wrap that data key under the master key. */
  function envEncrypt(master, ctx, text) {
    const dek = L.randBytes(32), nonce = L.randBytes(12), wn = L.randBytes(12);
    const d = L.gcmEncrypt(dek, nonce, L.utf8(text), L.utf8(ctx));
    const w = L.gcmEncrypt(master.key, wn, dek, L.utf8("wrap:" + ctx));
    return { ctx, kid: master.id, wn, wct: w.ct, wtag: w.tag, nonce, ct: d.ct, tag: d.tag };
  }
  function envDecrypt(masters, rec, ctx) {
    const m = masters.find((x) => x.id === rec.kid);
    if (!m) throw new Error("no key with id " + rec.kid + ": it was retired too early");
    const dek = L.gcmDecrypt(m.key, rec.wn, rec.wct, rec.wtag, L.utf8("wrap:" + ctx));
    return L.text(L.gcmDecrypt(dek, rec.nonce, rec.ct, rec.tag, L.utf8(ctx)));
  }
  /** Rotate the master key: unwrap each data key with the old master, wrap it with the new one. The data isn't touched. */
  function envRewrap(oldM, newM, rec) {
    const dek = L.gcmDecrypt(oldM.key, rec.wn, rec.wct, rec.wtag, L.utf8("wrap:" + rec.ctx));
    const wn = L.randBytes(12), w = L.gcmEncrypt(newM.key, wn, dek, L.utf8("wrap:" + rec.ctx));
    return Object.assign({}, rec, { kid: newM.id, wn, wct: w.ct, wtag: w.tag });
  }

  // --------------------------------------------------------------------------- 5. splitting a key: Shamir's secret sharing
  const P255 = (1n << 255n) - 19n;
  /** Split a secret (a BigInt below 2^255 - 19) into n shares so that any k of them recover it and fewer reveal nothing. */
  function shamirSplit(secret, k, n) {
    const coef = [secret]; for (let i = 1; i < k; i++) coef.push(L.randBelow(P255));
    const shares = [];
    for (let x = 1; x <= n; x++) {
      let y = 0n; for (let i = coef.length - 1; i >= 0; i--) y = (y * BigInt(x) + coef[i]) % P255;
      shares.push({ x, y });
    }
    return shares;
  }
  function shamirCombine(shares) {
    let s = 0n;
    for (let i = 0; i < shares.length; i++) {
      let num = 1n, den = 1n;
      for (let j = 0; j < shares.length; j++) if (i !== j) { num = (num * BigInt(-shares[j].x)) % P255; den = (den * BigInt(shares[i].x - shares[j].x)) % P255; }
      s = (s + shares[i].y * num % P255 * L.modInv(((den % P255) + P255) % P255, P255)) % P255;
    }
    return ((s % P255) + P255) % P255;
  }

  // --------------------------------------------------------------------------- 6. short-lived credentials: a signed identity token and a trust policy
  const b64u = (b) => (typeof btoa !== "undefined" ? btoa(String.fromCharCode(...b)) : Buffer.from(b).toString("base64")).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const b64uText = (s) => b64u(L.utf8(s));
  function makeIdp() { const d = L.randBelow(L.P256.n - 1n) + 1n; return { d, Q: L.P256.mul(d) }; }
  /** Sign a JWT-shaped token (ES256-style, with this talk's from-scratch P-256). */
  function mintToken(idp, claims) {
    const head = b64uText(JSON.stringify({ alg: "ES256", typ: "JWT" })), body = b64uText(JSON.stringify(claims));
    const h = L.hashInt(head + "." + body), k = L.randBelow(L.P256.n - 1n) + 1n;
    const [r, s] = L.ecdsaSign(idp.d, h, k);
    return { head, body, sig: [r, s], claims };
  }
  const tokenText = (t) => t.head + "." + t.body + "." + L.hex(L.fromBig(t.sig[0], 32)).slice(0, 10) + "…";
  function tamper(t, patch) { return { head: t.head, body: b64uText(JSON.stringify(Object.assign({}, t.claims, patch))), sig: t.sig, claims: Object.assign({}, t.claims, patch) }; }
  const POLICIES = {
    none: { label: "No condition", cond: () => true, text: "Trust anything the issuer signs" },
    repo: { label: "Repository only", cond: (c) => /^repo:example-org\/shop:/.test(c.sub), text: "sub starts with repo:example-org/shop:" },
    branch: { label: "Repository + main branch", cond: (c) => c.sub === "repo:example-org/shop:ref:refs/heads/main", text: "sub is exactly repo:example-org/shop:ref:refs/heads/main" },
    env: { label: "Repository + production environment", cond: (c) => c.sub === "repo:example-org/shop:environment:production", text: "sub is exactly repo:example-org/shop:environment:production" },
  };
  /** What the cloud does with a token: verify the signature, then the standard claims, then the trust policy. */
  function cloudCheck(idpPub, token, policyKey, now) {
    const { head, body, sig, claims } = token;
    const ok = L.ecdsaVerify(idpPub, L.hashInt(head + "." + body), sig);
    // the signature was made over the original claims: a tampered body fails here
    if (!ok) return { allow: false, why: "Signature check failed: the token was changed after the issuer signed it." };
    if (claims.iss !== "https://token.actions.example") return { allow: false, why: "Wrong issuer." };
    if (claims.aud !== "sts.cloud.example") return { allow: false, why: "Wrong audience: this token was minted for somewhere else." };
    if (claims.exp <= now) return { allow: false, why: "Token expired: it was only ever good for a few minutes." };
    if (!POLICIES[policyKey].cond(claims)) return { allow: false, why: "Signature is genuine, but the trust policy doesn't match this token's subject." };
    return { allow: true, why: "Signature, audience, expiry and subject all check out: the cloud returns temporary credentials for one hour." };
  }

  // --------------------------------------------------------------------------- 7. rotation with two keys (real ECDSA signatures)
  function newKey(kid) { const d = L.randBelow(L.P256.n - 1n) + 1n; return { kid, d, Q: L.P256.mul(d) }; }
  /** A signing service and a verifier. The verifier trusts the key IDs in `trusted`; the signer uses `signing`. */
  function makeRing() { const a = newKey("key-A"); return { keys: { "key-A": a }, signing: "key-A", trusted: new Set(["key-A"]), clock: 0, tokens: [], n: 0 }; }
  function ringIssue(ring, lifetime) {
    const k = ring.keys[ring.signing], payload = JSON.stringify({ n: ++ring.n, exp: ring.clock + lifetime, kid: k.kid });
    const h = L.hashInt(k.kid + "." + payload), nonce = L.randBelow(L.P256.n - 1n) + 1n;
    const tok = { id: ring.n, kid: k.kid, payload, exp: ring.clock + lifetime, issued: ring.clock, sig: L.ecdsaSign(k.d, h, nonce) };
    ring.tokens.push(tok); return tok;
  }
  function ringVerify(ring, tok) {
    if (tok.exp <= ring.clock) return { ok: false, why: "expired" };
    if (!ring.trusted.has(tok.kid)) return { ok: false, why: "unknown key " + tok.kid };
    const k = ring.keys[tok.kid];
    return L.ecdsaVerify(k.Q, L.hashInt(tok.kid + "." + tok.payload), tok.sig) ? { ok: true, why: "valid (" + tok.kid + ")" } : { ok: false, why: "bad signature" };
  }

  const api = { entropy, scan, RULES, SECRET, imageBuild, makeRepo, repoDeleteInNextCommit, repoRewrite, repoWhere, KEY_STATE,
    mkMaster, envEncrypt, envDecrypt, envRewrap, P255, shamirSplit, shamirCombine,
    makeIdp, mintToken, tokenText, tamper, POLICIES, cloudCheck, newKey, makeRing, ringIssue, ringVerify, b64uText };
  root.SecretsLab = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof window !== "undefined" ? window : globalThis);
