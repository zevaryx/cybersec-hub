/* hashes.js - the logic behind this talk's demos, kept apart from the page so it can be tested in Node.
   EDUCATIONAL ONLY. It reuses the from-scratch SHA-1, SHA-256 and ECDSA P-256 in ../../shared/crypto.js, so nothing here should
   protect real data. Every file, repository, log and "download" in the demos is made up on the spot and never leaves the page.
   Contents: 1. Git objects (SHA-1 and SHA-256 formats)  2. Merkle trees as in RFC 9162 (and a deliberately naive variant)
             3. a toy reproducible-build model  4. a pin checker  5. checksum-versus-signature scenarios  6. "which hash?" */
(function (root) {
  "use strict";
  const L = root.Lab || (typeof require !== "undefined" ? require("../../shared/crypto.js") : null);
  const u8 = (s) => (typeof s === "string" ? L.utf8(s) : s);

  // --------------------------------------------------------------------------- 1. Git objects
  /** Git names an object by hashing "<type> <size>\0" followed by its content. algo is "sha1" or "sha256" (Git's two object formats). */
  function gitHash(type, content, algo = "sha1") {
    const body = u8(content), head = L.utf8(type + " " + body.length + "\0"), all = L.concat(head, body);
    return algo === "sha256" ? L.sha256(all) : L.sha1(all);
  }
  const gitId = (type, content, algo) => L.hex(gitHash(type, content, algo));
  /** A flat tree: entries are [name, blobIdHex]. Git sorts by name and stores "100644 name\0" + the RAW hash bytes. */
  function treeContent(entries, algo = "sha1") {
    const sorted = entries.slice().sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
    return L.concat(...sorted.map(([name, id]) => L.concat(L.utf8("100644 " + name + "\0"), L.fromHex(id))));
  }
  /** A commit's text. Dates are fixed (seconds since 1970, UTC) so every run gives the same ID. */
  function commitContent({ tree, parent, message, when = 1700000000, who = "Ada Lovelace <ada@example.com>" }) {
    return (`tree ${tree}\n` + (parent ? `parent ${parent}\n` : "") + `author ${who} ${when} +0000\ncommitter ${who} ${when} +0000\n\n${message}\n`);
  }
  /** Build a little history: commits = [{ message, files: {name: text} }, ...] oldest first.
      Returns every object (blob, tree, commit) with its ID, so the page can draw the chain. */
  function buildHistory(commits, algo = "sha1") {
    const out = []; let parent = null;
    commits.forEach((c, i) => {
      const names = Object.keys(c.files).sort();
      const blobs = names.map((n) => ({ name: n, id: gitId("blob", c.files[n], algo), size: u8(c.files[n]).length }));
      const tree = gitId("tree", treeContent(blobs.map((b) => [b.name, b.id]), algo), algo);
      const body = commitContent({ tree, parent, message: c.message, when: 1700000000 + i * 3600 });
      const id = gitId("commit", body, algo);
      out.push({ index: i, message: c.message, blobs, tree, id, parent });
      parent = id;
    });
    return out;
  }

  // --------------------------------------------------------------------------- 2. Merkle trees (RFC 9162, section 2.1)
  const H = L.sha256;
  /** RFC 9162 hashing: a leaf is HASH(0x00 || data), an inner node is HASH(0x01 || left || right). prefixes=false is the naive version. */
  const leafHash = (d, prefixes = true) => H(prefixes ? L.concat(Uint8Array.of(0), u8(d)) : u8(d));
  const nodeHash = (l, r, prefixes = true) => H(prefixes ? L.concat(Uint8Array.of(1), l, r) : L.concat(l, r));
  /** the largest power of two strictly less than n (n > 1) */
  const split = (n) => { let k = 1; while (k * 2 < n) k *= 2; return k; };
  /** Merkle Tree Hash of an array of data items. The empty tree is HASH(""). */
  function mth(items, prefixes = true) {
    if (items.length === 0) return H(new Uint8Array(0));
    if (items.length === 1) return leafHash(items[0], prefixes);
    const k = split(items.length);
    return nodeHash(mth(items.slice(0, k), prefixes), mth(items.slice(k), prefixes), prefixes);
  }
  /** Every level of the tree for drawing: returns { nodes: [{ id, level, lo, hi, hash, left, right }], root } with leaves at level 0. */
  function layout(items, prefixes = true) {
    const nodes = [];
    function build(lo, hi) {
      if (hi - lo === 1) { const n = { id: nodes.length, lo, hi, size: 1, hash: leafHash(items[lo], prefixes), left: null, right: null }; nodes.push(n); return n; }
      const k = split(hi - lo), a = build(lo, lo + k), b = build(lo + k, hi);
      const n = { id: nodes.length, lo, hi, size: hi - lo, hash: nodeHash(a.hash, b.hash, prefixes), left: a, right: b }; nodes.push(n); return n;
    }
    const rootNode = items.length ? build(0, items.length) : null;
    return { nodes, root: rootNode ? rootNode.hash : H(new Uint8Array(0)), rootNode };
  }
  /** Inclusion proof (RFC 9162 PATH): the sibling subtree hashes needed to rebuild the root from leaf m. Returns [{ hash, side, lo, hi }]. */
  function inclusionProof(items, m, prefixes = true) {
    if (items.length <= 1) return [];
    const k = split(items.length);
    if (m < k) return inclusionProof(items.slice(0, k), m, prefixes).concat([{ hash: mth(items.slice(k), prefixes), side: "right", lo: k, hi: items.length }]);
    return inclusionProof(items.slice(k), m - k, prefixes).map((p) => Object.assign({}, p, { lo: p.lo + k, hi: p.hi + k })).concat([{ hash: mth(items.slice(0, k), prefixes), side: "left", lo: 0, hi: k }]);
  }
  /** The RFC 9162 verification algorithm, step by step, so the demo can show each recomputed hash. */
  function verifyInclusion(leafIndex, treeSize, leafH, path, rootH) {
    const steps = [];
    if (leafIndex >= treeSize) return { ok: false, steps, why: "leaf index is outside the tree" };
    let fn = leafIndex, sn = treeSize - 1, r = leafH;
    for (const p of path) {
      if (sn === 0) return { ok: false, steps, why: "proof is longer than the tree is deep" };
      if ((fn & 1) === 1 || fn === sn) {
        r = nodeHash(p, r); steps.push({ side: "left", sibling: p, result: r });
        if ((fn & 1) === 0) { while ((fn & 1) === 0 && fn !== 0) { fn >>= 1; sn >>= 1; } }
      } else { r = nodeHash(r, p); steps.push({ side: "right", sibling: p, result: r }); }
      fn >>= 1; sn >>= 1;
    }
    const ok = sn === 0 && L.equalBytes(r, rootH);
    return { ok, steps, got: r, why: ok ? "the hashes lead to the signed root" : sn !== 0 ? "proof is too short" : "the hashes lead somewhere else" };
  }
  /** Consistency proof (RFC 9162 PROOF/SUBPROOF): proves the first m entries of an n-entry log are exactly the entries behind the old root. */
  function consistencyProof(items, m, prefixes = true) {
    if (m === 0 || m > items.length) return [];
    function sub(mm, list, b) {
      const n = list.length;
      if (mm === n) return b ? [] : [mth(list, prefixes)];
      const k = split(n);
      if (mm <= k) return sub(mm, list.slice(0, k), b).concat([mth(list.slice(k), prefixes)]);
      return sub(mm - k, list.slice(k), false).concat([mth(list.slice(0, k), prefixes)]);
    }
    return sub(m, items, true);
  }
  const isPow2 = (x) => x > 0 && (x & (x - 1)) === 0;
  /** RFC 9162 section 2.1.4.2: recompute BOTH roots from the proof; valid only if both match. */
  function verifyConsistency(first, second, firstH, secondH, proof) {
    if (first > second || first < 0) return { ok: false, why: "the old tree can't be bigger than the new one" };
    if (first === second) return { ok: proof.length === 0 && L.equalBytes(firstH, secondH), why: proof.length === 0 ? "same size: the roots must simply be equal" : "same size needs an empty proof" };
    if (first === 0) return { ok: proof.length === 0, why: "an empty log is consistent with anything" };
    const p = isPow2(first) ? [firstH].concat(proof) : proof.slice();
    if (!p.length) return { ok: false, why: "proof is empty" };
    let fn = first - 1, sn = second - 1;
    while ((fn & 1) === 1) { fn >>= 1; sn >>= 1; }
    let fr = p[0], sr = p[0];
    for (let i = 1; i < p.length; i++) {
      const c = p[i];
      if (sn === 0) return { ok: false, why: "proof is longer than expected" };
      if ((fn & 1) === 1 || fn === sn) {
        fr = nodeHash(c, fr); sr = nodeHash(c, sr);
        if ((fn & 1) === 0) { while ((fn & 1) === 0 && fn !== 0) { fn >>= 1; sn >>= 1; } }
      } else sr = nodeHash(sr, c);
      fn >>= 1; sn >>= 1;
    }
    const ok = sn === 0 && L.equalBytes(fr, firstH) && L.equalBytes(sr, secondH);
    return { ok, why: ok ? "the new log contains the old one unchanged" : sn !== 0 ? "proof is too short" : !L.equalBytes(fr, firstH) ? "the old root doesn't come out of the proof" : "the new root doesn't come out of the proof" };
  }
  /** How many hashes an inclusion proof needs for a log of n entries (at most ceil(log2 n)). */
  const proofLength = (n) => (n <= 1 ? 0 : Math.ceil(Math.log2(n)));

  // --------------------------------------------------------------------------- 3. a toy build, to see why reproducible builds need care
  /** A pretend build: bundle the files into one archive and name it by its SHA-256. The options are the usual sources of drift. */
  function toyBuild(files, opt) {
    const o = Object.assign({ stamp: "2026-11-11T10:42:07Z", sorted: true, path: "/home/dev/app", locale: "en_US" }, opt);
    let names = Object.keys(files);
    if (o.sorted) names.sort(); /* unsorted = whatever order the file system listed them in */
    const parts = names.map((n) => `FILE ${n} ${u8(files[n]).length}\n${files[n]}\n`);
    const meta = `BUILT-AT ${o.stamp}\nBUILT-IN ${o.path}\nLOCALE ${o.locale}\n`;
    const bytes = L.utf8(parts.join("") + meta);
    return { bytes, digest: L.hex(L.sha256(bytes)), size: bytes.length };
  }

  // --------------------------------------------------------------------------- 4. a pin checker: is this dependency line pinned by content?
  /** Classify one line of a dependency or CI file. Returns { kind, level, why } or null for lines it ignores. level: ok / y / bad */
  function checkPin(line) {
    const t = line.trim();
    if (!t || t[0] === "#") return null;
    let m;
    if ((m = /^FROM\s+(\S+)/i.exec(t))) {
      const img = m[1];
      if (/@sha256:[0-9a-f]{64}$/.test(img)) return { kind: "Docker image", level: "ok", why: "Pinned by digest: it names exact content." };
      if (/:latest$/.test(img) || !/[:@]/.test(img)) return { kind: "Docker image", level: "bad", why: "No tag, or :latest. It means whatever was pushed most recently." };
      return { kind: "Docker image", level: "y", why: "A tag is a movable label: the owner (or an attacker with their account) can repoint it." };
    }
    if ((m = /^-?\s*uses:\s*(\S+)/i.exec(t))) {
      const ref = m[1].split("@")[1] || "";
      if (/^[0-9a-f]{40}$/.test(ref) || /^[0-9a-f]{64}$/.test(ref)) return { kind: "GitHub Action", level: "ok", why: "Pinned to a full commit hash: the code can't change under you." };
      if (!ref) return { kind: "GitHub Action", level: "bad", why: "No version at all." };
      return { kind: "GitHub Action", level: "y", why: "A tag or branch can be moved to different code." };
    }
    if ((m = /^([A-Za-z0-9_.\-]+)\s*(==|>=|<=|~=|>|<)\s*([^\s;\\]+)(.*)$/.exec(t))) {
      const pinned = m[2] === "==", hashed = /--hash=sha256:[0-9a-f]{64}/.test(t);
      if (pinned && hashed) return { kind: "Python requirement", level: "ok", why: "Exact version and its file hash: pip refuses a different file." };
      if (pinned) return { kind: "Python requirement", level: "y", why: "Exact version, but no hash: a swapped file with that version number would install." };
      return { kind: "Python requirement", level: "bad", why: "A range: tomorrow's install can differ from today's." };
    }
    if ((m = /^"?([@A-Za-z0-9_./\-]+)"?\s*:\s*"([^"]+)"/.exec(t))) {
      const v = m[2];
      if (/^sha(?:512|256|1)-[A-Za-z0-9+/=]+$/.test(v)) return { kind: "Lock-file integrity", level: "ok", why: "A Subresource Integrity hash of the exact package file." };
      if (/^[\^~><*]|^latest$|x$|^\*$/.test(v)) return { kind: "npm dependency", level: "y", why: "A version range. A lock file with integrity hashes is what pins the content." };
      if (/^\d+\.\d+\.\d+/.test(v)) return { kind: "npm dependency", level: "y", why: "An exact version, but the version number alone doesn't prove which bytes you get." };
    }
    return null;
  }

  // --------------------------------------------------------------------------- 5. checksum versus signature: who can fake what?
  function makeSigner() { const d = L.randBelow(L.P256.n - 1n) + 1n; return { d, Q: L.P256.mul(d) }; }
  const sigOf = (signer, bytes) => L.ecdsaSign(signer.d, L.toBig(L.sha256(bytes)), L.randBelow(L.P256.n - 1n) + 1n);
  const sigOk = (Q, bytes, sig) => L.ecdsaVerify(Q, L.toBig(L.sha256(bytes)), sig);
  const sigText = (sig) => L.hex(L.fromBig(sig[0], 32)).slice(0, 16) + "…";
  /** The release a maintainer publishes: the file, its SHA-256 (on the same web page) and a signature (made with a key you got earlier). */
  function makeRelease(signer, text) {
    const file = u8(text);
    return { file, checksum: L.hex(L.sha256(file)), sig: sigOf(signer, file) };
  }
  /** What can happen to the download, and which checks notice. Each scenario returns what the user receives. */
  const SCENARIOS = {
    honest: { label: "Nothing goes wrong", text: "The file you get is the file the maintainer published." },
    corrupt: { label: "A bit flips in transit", text: "A flaky mirror or connection damages one byte. The web page and its checksum are untouched." },
    mirror: { label: "A mirror serves a changed file", text: "A mirror swaps the file. The checksum comes from the official page, so it still describes the real file." },
    server: { label: "The website itself is broken into", text: "The attacker replaces the file and the checksum on the same page. They don't have the signing key." },
    key: { label: "The signing key is stolen", text: "The attacker holds the maintainer's key, so they can sign their own file." },
  };
  /** Returns { received: {file, checksum, sig, note}, checksumPasses, signaturePasses } for a scenario. */
  function runScenario(name, release, signer, evilText) {
    const evil = u8(evilText || "build a backdoor into the installer\n");
    let r;
    if (name === "honest") r = { file: release.file, checksum: release.checksum, sig: release.sig };
    else if (name === "corrupt") { const f = release.file.slice(); f[Math.floor(f.length / 2)] ^= 0x01; r = { file: f, checksum: release.checksum, sig: release.sig }; }
    else if (name === "mirror") r = { file: evil, checksum: release.checksum, sig: release.sig };
    else if (name === "server") r = { file: evil, checksum: L.hex(L.sha256(evil)), sig: release.sig };       // the old signature can't cover new bytes
    else r = { file: evil, checksum: L.hex(L.sha256(evil)), sig: sigOf(signer, evil) };                       // a stolen key signs anything
    return { received: r, checksumPasses: L.hex(L.sha256(r.file)) === r.checksum, signaturePasses: sigOk(signer.Q, r.file, r.sig) };
  }

  // --------------------------------------------------------------------------- 6. which hash for which job?
  const JOBS = [
    { id: "integrity", job: "Check a file or package wasn't altered", use: "SHA-256 (or SHA-512, SHA-3, BLAKE3)", avoid: "MD5 and SHA-1 for anything an attacker could influence", note: "A plain hash only proves anything if you got the expected value from somewhere the attacker can't change. Otherwise, sign it." },
    { id: "identifier", job: "Name content by what it is (dedup, caches, image digests)", use: "SHA-256", avoid: "A short truncation that could collide by accident at your scale", note: "Content addressing works because finding two inputs with the same hash should be infeasible. Truncate and you lose that." },
    { id: "mac", job: "Prove a message came from someone with a shared key", use: "HMAC-SHA-256 (or KMAC, or an AEAD like AES-GCM)", avoid: "Hashing key and message together yourself, such as SHA-256(key || message)", note: "SHA-256 over key||message allows length extension: someone who sees the hash can compute the hash of a longer message. HMAC is built to avoid that." },
    { id: "password", job: "Store a login password", use: "Argon2id (or scrypt, bcrypt) with a unique salt", avoid: "Any plain fast hash, with or without a salt", note: "Fast is a bug here. Slow, memory-hungry hashing makes each guess expensive. See Passwords and Accounts." },
    { id: "kdf", job: "Turn one strong secret into several keys", use: "HKDF (built on HMAC)", avoid: "Reusing the same key for several jobs", note: "HKDF is for secrets that are already random. For a password, use a password hash instead." },
    { id: "table", job: "A hash table, bloom filter or checksum for accidents", use: "A fast non-cryptographic hash, a keyed one such as SipHash if inputs are attacker-chosen", avoid: "Trusting it against an attacker", note: "Cheap hashes are fine when nobody is trying to collide them. If anyone might, use a keyed or cryptographic hash." },
    { id: "signature", job: "Sign something large", use: "Hash it with SHA-256 (or better), then sign the hash", avoid: "Signing with a weak hash such as SHA-1", note: "A signature is only as strong as the hash under it: collide the hash and the signature carries over." },
  ];

  const api = {
    gitHash, gitId, treeContent, commitContent, buildHistory,
    leafHash, nodeHash, split, mth, layout, inclusionProof, verifyInclusion, consistencyProof, verifyConsistency, proofLength,
    toyBuild, checkPin, makeSigner, sigOf, sigOk, sigText, makeRelease, SCENARIOS, runScenario, JOBS,
  };
  root.HashLab = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof window !== "undefined" ? window : globalThis);
