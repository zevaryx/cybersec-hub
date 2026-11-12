/* app.js - the live demos for "Hashing Beyond Passwords".
   Every demo is a simulation in this page: a mini Git (real Git object format), Merkle trees as in RFC 9162, a toy build, a pin checker,
   and real (but from-scratch) SHA-1, SHA-256 and ECDSA from ../../shared/crypto.js. All files, logs and "downloads" are invented
   on the spot; nothing is fetched or sent anywhere. */
(function () {
  "use strict";
  const L = window.Lab, S = window.HashLab;

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
  const setPressed = (id, attr, val) => { for (const b of $(id).querySelectorAll("button")) b.setAttribute("aria-pressed", String(b.getAttribute(attr) === String(val))); };
  const verdict = (id, cls, text) => { const el = $(id); el.className = "verdict " + cls; el.textContent = text; };
  const note = (id, text, cls) => { const el = $(id); el.className = "comment" + (cls ? " " + cls : ""); el.textContent = text; };
  const hx = (b) => L.hex(b);
  const h6 = (b) => L.hex(b).slice(0, 6);
  const hash = (s) => L.sha256(L.utf8(s));
  const flipFirst = (t) => (t.length ? String.fromCharCode(t.charCodeAt(0) ^ 1) + t.slice(1) : "a");

  // --------------------------------------------------------------------------- title: hash anything
  function hero() {
    const el = $("hero-in"), v = el.value;
    el.style.width = Math.min(30, Math.max(8, v.length + 1)) + "ch";
    $("hero-out").innerHTML = `${sp("k", "sha-256:")}<br>${esc(hx(hash(v)))}<br>${sp("k", "git blob:")} ${esc(S.gitId("blob", v))}`;
    const t = v.trim().toLowerCase();
    let n;
    if (v === "") n = "# the hash of nothing is famous. The empty file's Git ID, e69de29…, turns up in every repository that has an empty file.";
    else if (t === "abc") n = "# 'abc' is the first test message in the SHA-256 standard's examples. If yours ends in ba7816bf, the maths works.";
    else if (t === "password") n = "# a hash can't be undone, but 'password' is in every wordlist, so anyone can just hash their guesses. That's the next-door talk, Passwords and Accounts.";
    else if (t === "the quick brown fox jumps over the lazy dog") n = "# the classic test sentence. Add a full stop and every character of the hash changes.";
    else if (t === "shattered") n = "# SHAttered, 2017: two different PDFs with one SHA-1. Their SHA-256 hashes were different, as they should be.";
    else n = "# same text, same hash, on every machine, forever. Change one letter and the whole thing changes. That's the trick the whole talk rests on.";
    note("hero-note", n);
  }

  // --------------------------------------------------------------------------- 1. naming data by its fingerprint
  const FP_BASE = "Pay Bob $100", FP_HASH = hx(hash(FP_BASE));
  function fingerprint() {
    const cur = $("fp-in").value, hc = hx(hash(cur));
    const bits = L.bitDiff(hash(FP_BASE), hash(cur));
    const lineOf = (str) => [0, 32].map((o) => Array.from(str.slice(o, o + 32), (c, i) => (c === FP_HASH[o + i] ? esc(c) : `<span class="diff">${esc(c)}</span>`)).join("")).join("\n          ");
    $("fp-out").innerHTML = `${sp("k", "original")} ${lineOf(FP_HASH)}\n${sp("k", "yours   ")} ${lineOf(hc)}`;
    if (cur === FP_BASE) { verdict("fp-verdict", "ok", "Same text, same hash: identical."); }
    else verdict("fp-verdict", "y", `${bits} of 256 bits differ (${Math.round((bits / 256) * 100)}%).`);
    let n = "# change anything, even a single bit of the text: about half the bits of the hash flip. That's the avalanche effect.";
    if (cur === "") n = "# the hash of nothing: e3b0c442…, one of the most-seen hashes in the world. Every empty file, empty string and empty body has it.";
    else if (cur === FP_BASE) n = "# back where we started: same text, same hash. A fingerprint is only useful because it never changes.";
    else if (cur === "Pay Bob $101") n = "# one bit of the text changed ('0' to '1'): the hash is unrecognisable. Fine for $1 of damage, too.";
    note("fp-note", n);
  }

  // --------------------------------------------------------------------------- 2. mini Git
  const MG_ORIG = ["hello\n", "hello\n", "hello\n"], MG_PY = "print('hi')\n", MG_MSG = ["Add README", "Add main.py", "Add LICENSE"];
  const mg = { which: 0, algo: "sha1", texts: MG_ORIG.slice(), toggles: 0 };
  const mgDefs = (t) => [
    { message: MG_MSG[0], files: { "README.md": t[0] } },
    { message: MG_MSG[1], files: { "README.md": t[1], "main.py": MG_PY } },
    { message: MG_MSG[2], files: { "README.md": t[2], "main.py": MG_PY, "LICENSE": "MIT\n" } },
  ];
  function minigit() {
    const base = S.buildHistory(mgDefs(MG_ORIG), mg.algo), cur = S.buildHistory(mgDefs(mg.texts), mg.algo);
    let changed = 0, total = 0;
    const cell = (label, id, was) => { total++; const c = id !== was; if (c) changed++; return `<li class="${c ? "chg" : ""}" title="${esc(id)}"><small>${esc(label)}</small><code>${id.slice(0, 10)}</code></li>`; };
    $("mg-chain").innerHTML = cur.map((c, i) => {
      const b = base[i];
      return `<div class="mg-commit${i === mg.which ? " sel" : ""}"><b>Commit ${i + 1}</b><span class="mg-msg">${esc(c.message)}</span><ul>` +
        cell("commit", c.id, b.id) +
        `<li class="mg-par" title="${esc(c.parent || "")}"><small>parent</small><code>${c.parent ? c.parent.slice(0, 10) : "none"}</code></li>` +
        cell("tree", c.tree, b.tree) + c.blobs.map((bl, k) => cell(bl.name, bl.id, b.blobs[k].id)).join("") + `</ul></div>`;
    }).join("");
    $("mg-count").textContent = `${changed} of ${total} IDs differ from the original history.`;
    const edited = mg.texts.some((t, i) => t !== MG_ORIG[i]);
    let n;
    if (!edited && mg.toggles >= 2) n = "# SHA-1, SHA-256, back again: the content never changed, only its name did.";
    else if (!edited) n = "# edit a README or flip a byte. Pink IDs changed. Everything that points at a changed thing has to change too.";
    else if (!changed) n = "# identical bytes, identical IDs: this history can't be told apart from the original.";
    else if (mg.which === 2) n = "# you edited the newest commit: only its own IDs changed, because nothing points at it yet. Now try the oldest.";
    else if (mg.which === 0) n = "# the oldest commit changed, and so did every commit after it. Their trees and files didn't, but each commit holds its parent's ID, so the change runs all the way to the tip.";
    else n = "# commit 2 changed, so commit 3 did too (it holds commit 2's ID). Commit 1 is untouched: parents don't know about their children.";
    note("mg-note", n);
    return changed;
  }
  function mgInit() {
    segPick("mg-which", "data-c", (c) => { mg.which = +c; $("mg-text").value = mg.texts[mg.which]; minigit(); });
    segPick("mg-algo", "data-a", (a) => { if (a !== mg.algo) mg.toggles++; mg.algo = a; minigit(); });
    $("mg-text").value = mg.texts[0];
    $("mg-text").addEventListener("input", () => { mg.texts[mg.which] = $("mg-text").value; minigit(); });
    click("mg-flip", () => { mg.texts[mg.which] = flipFirst(mg.texts[mg.which]); $("mg-text").value = mg.texts[mg.which]; minigit(); });
    click("mg-reset", () => { mg.texts[mg.which] = MG_ORIG[mg.which]; $("mg-text").value = mg.texts[mg.which]; minigit(); });
    minigit();
  }

  // --------------------------------------------------------------------------- 3. the same file in two object formats
  function gitsha() {
    const v = $("g2-in").value + "\n", a = S.gitId("blob", v, "sha1"), b = S.gitId("blob", v, "sha256");
    $("g2-out").innerHTML = `${sp("k", "SHA-1 format  ")} (${a.length} hex)\n${esc(a)}\n\n${sp("k", "SHA-256 format")} (${b.length} hex)\n${esc(b)}`;
  }

  // --------------------------------------------------------------------------- Merkle tree drawing, shared by three slides
  function drawNode(n, cls, labels) {
    const leaf = !n.left, key = n.lo + "-" + n.hi, id = L.hex(n.hash);
    const kids = leaf ? "" : `<div class="mk-kids">${drawNode(n.left, cls, labels)}${drawNode(n.right, cls, labels)}</div>`;
    return `<div class="mk-n"><div class="mk-box ${leaf ? "leaf " : ""}${cls(n, key)}" title="${id}"><b>${id.slice(0, 6)}</b>${leaf ? `<i>${esc(labels[n.lo])}</i>` : ""}</div>${kids}</div>`;
  }
  const drawTree = (lay, labels, cls) => (lay.rootNode ? drawNode(lay.rootNode, cls, labels) : `<div class="mk-box"><b>${hx(lay.root).slice(0, 6)}</b><i>empty</i></div>`);

  // --------------------------------------------------------------------------- 4. build a Merkle tree
  const MK_DEF = ["alice", "bob", "carol", "dave", "erin"];
  const mkKey = (lay) => { const m = new Map(); for (const n of lay.nodes) m.set(n.lo + "-" + n.hi + ":" + n.size, hx(n.hash)); return m; };
  const mkBase = mkKey(S.layout(MK_DEF));
  function merkle() {
    const lines = $("mk-in").value.split("\n").filter((s) => s.length > 0), items = lines.slice(0, 8);
    const lay = S.layout(items);
    $("mk-tree").innerHTML = drawTree(lay, items, (n) => (mkBase.get(n.lo + "-" + n.hi + ":" + n.size) === hx(n.hash) ? "" : "chg"));
    $("mk-root").textContent = "root: " + hx(lay.root);
    let n;
    if (!lines.length) n = "# no leaves: the root is the hash of nothing again, e3b0c442…";
    else if (items.length === 1) n = "# one leaf: the whole tree is that leaf's hash (with its 0x00 byte in front). Add a second line to get a parent.";
    else if (new Set(items).size === 1) n = "# identical leaves give identical leaf hashes. The tree is still fine: a proof also carries the leaf's position, so they can't be swapped.";
    else if (lines.length > 8) n = "# only the first 8 lines are used, to keep the picture readable.";
    else if (items.join("\n") === MK_DEF.join("\n")) n = "# five leaves: the left side takes four (the largest power of two that fits), the right takes the last one. Edit a line: pink hashes changed.";
    else n = "# pink hashes changed: your edit and every parent on the way up to the root, and nothing else.";
    note("mk-note", n);
  }

  // --------------------------------------------------------------------------- 5. inclusion proofs
  const LOG = ["acme.example", "bank.example", "cafe.example", "dev.example", "edu.example", "food.example", "gov.example", "hub.example"];
  const inc = { i: 2, tamper: false, seen: new Set([2]) };
  function inclusion() {
    const lay = S.layout(LOG), proof = S.inclusionProof(LOG, inc.i), sib = new Set(proof.map((p) => p.lo + "-" + p.hi));
    $("inc-tree").innerHTML = drawTree(lay, LOG, (n, key) => (sib.has(key) ? "sib" : n.lo <= inc.i && inc.i < n.hi ? "path" : ""));
    $("inc-pick").innerHTML = LOG.map((e, k) => `<button type="button" data-i="${k}" aria-pressed="${k === inc.i}">${k + 1}</button>`).join("");
    const claimed = inc.tamper ? "evil.example" : LOG[inc.i], lh = S.leafHash(claimed);
    const res = S.verifyInclusion(inc.i, LOG.length, lh, proof.map((p) => p.hash), lay.root);
    $("inc-steps").innerHTML = `<li><b>Entry ${inc.i + 1}:</b> <code>${esc(claimed)}</code> → leaf hash <code>${h6(lh)}</code></li>` +
      res.steps.map((s, k) => `<li>${s.side === "left" ? "hash(<b>proof " + h6(s.sibling) + "</b>, you)" : "hash(you, <b>proof " + h6(s.sibling) + "</b>)"} → <code>${h6(s.result)}</code></li>`).join("") +
      `<li>Trusted root: <code>${h6(lay.root)}</code>. You got: <code>${h6(res.got || lh)}</code></li>`;
    verdict("inc-verdict", res.ok ? "ok" : "bad", res.ok ? `Verified with ${proof.length} hashes: the entry is in the log.` : "Rejected: the hashes lead somewhere other than the root.");
    $("inc-tamper").textContent = inc.tamper ? "Put the real entry back" : "Swap in a different entry";
    $("inc-scale").textContent = "Proof size is at most ceil(log2 n) hashes: 8 entries → " + S.proofLength(8) + ", 1,000 → " + S.proofLength(1000) + ", 1,000,000 → " + S.proofLength(1e6) + ", 1,000,000,000 → " + S.proofLength(1e9) + ".";
    let n = "# the pink boxes are all the verifier needs besides the entry and the root. Pick another entry.";
    if (inc.tamper) n = "# a forged entry with the genuine proof: the recomputed path goes somewhere else. To fake it, you'd need a second input with the same hash.";
    else if (inc.seen.size === LOG.length) n = "# you've seen all eight proofs. Each one is just three hashes, whichever entry you pick.";
    note("inc-note", n);
  }
  function incInit() {
    $("inc-pick").addEventListener("click", (e) => { const b = e.target.closest("button[data-i]"); if (!b) return; inc.i = +b.dataset.i; inc.tamper = false; inc.seen.add(inc.i); inclusion(); });
    click("inc-tamper", () => { inc.tamper = !inc.tamper; inclusion(); });
    inclusion();
  }

  // --------------------------------------------------------------------------- 6. domain separation
  function domain() {
    const pre = $("dm-prefix").checked, a = ["a", "b", "c", "d"];
    const l1 = L.concat(hash("a"), hash("b")), l2 = L.concat(hash("c"), hash("d"));
    const ra = S.mth(a, pre), rb = S.mth([l1, l2], pre), same = L.equalBytes(ra, rb);
    $("dm-a").textContent = hx(ra); $("dm-b").textContent = hx(rb);
    verdict("dm-verdict", same ? "bad" : "ok", same ? "Same root, different data. A proof for one can pass for the other." : "Different roots: a parent can't be passed off as a leaf.");
    note("dm-note", same ? "# two different datasets, one root. Tree B's 'leaves' are tree A's inner hashes, glued together. That ambiguity is what the extra byte rules out." : "# one byte in front of leaves (0x00) and parents (0x01) and the trick is gone. Cheap, and worth copying in your own designs.");
  }

  // --------------------------------------------------------------------------- 7. consistency proofs
  const CS_NAMES = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india", "juliet", "kilo", "lima"];
  const CS_SNAP = 5, cs = { n: 5, rewritten: false, verified: false };
  const csItems = () => CS_NAMES.slice(0, cs.n).map((x, i) => (i === 1 && cs.rewritten ? "bravo-EDITED" : x));
  const csSnapRoot = S.mth(CS_NAMES.slice(0, CS_SNAP));
  function consistency(verify) {
    const items = csItems(), root = S.mth(items);
    $("cs-log").innerHTML = items.map((x, i) => `<span class="cs-e${i < CS_SNAP ? " old" : ""}${i === 1 && cs.rewritten ? " bad" : ""}"><small>${i + 1}</small>${esc(x)}</span>`).join("");
    $("cs-roots").innerHTML = `${sp("k", "saved root")} (${CS_SNAP} entries)\n${esc(hx(csSnapRoot))}\n${sp("k", "log's root")} (${items.length} entries)\n${esc(hx(root))}`;
    $("cs-append").disabled = cs.n >= CS_NAMES.length;
    $("cs-rewrite").textContent = cs.rewritten ? "Undo the rewrite" : "Quietly rewrite entry 2";
    if (!verify) { $("cs-out").textContent = ""; $("cs-verdict").className = "verdict"; $("cs-verdict").textContent = ""; return; }
    const proof = S.consistencyProof(items, CS_SNAP), res = S.verifyConsistency(CS_SNAP, items.length, csSnapRoot, root, proof);
    $("cs-out").innerHTML = `${sp("k", "proof")} (${proof.length} hash${proof.length === 1 ? "" : "es"}): ${proof.length ? esc(proof.map(h6).join("  ")) : "none needed"}\n${sp("k", "recompute")} old root and new root from the proof`;
    verdict("cs-verdict", res.ok ? "ok" : "bad", res.ok ? "Consistent: " + res.why + "." : "Inconsistent: " + res.why + ".");
    if (!res.ok) note("cs-note", "# caught: the log can't produce a proof that ties its new root back to the one you saved, because the history it's showing now isn't the history you saw.");
    else if (items.length === CS_SNAP) note("cs-note", "# same size, same root: nothing to prove. Append an entry first.");
    else note("cs-note", "# the log grew from " + CS_SNAP + " to " + items.length + " entries and nothing earlier changed. A few hashes were enough to show it.");
  }
  function csInit() {
    click("cs-append", () => { if (cs.n < CS_NAMES.length) cs.n++; consistency(false); note("cs-note", "# the log grows. Your saved root doesn't change: it's a receipt for the first 5 entries."); });
    click("cs-rewrite", () => { cs.rewritten = !cs.rewritten; consistency(false); note("cs-note", cs.rewritten ? "# entry 2 was quietly changed. Ask for a consistency proof." : "# undone."); });
    click("cs-restore", () => { cs.n = 5; cs.rewritten = false; consistency(false); note("cs-note", "# back to five entries."); });
    click("cs-verify", () => consistency(true));
    consistency(false);
    note("cs-note", "# append some entries, then ask for a proof. Then rewrite entry 2 and ask again.");
  }

  // --------------------------------------------------------------------------- 8. checksums versus signatures
  const cv = { signer: null, release: null, cur: "server", seen: new Set() };
  function cvReady() {
    if (cv.signer) return;
    cv.signer = S.makeSigner();
    cv.release = S.makeRelease(cv.signer, "installer-1.0: copy the app, leave the system alone\n");
  }
  function checksumDemo() {
    cvReady();
    const sc = S.SCENARIOS[cv.cur], r = S.runScenario(cv.cur, cv.release, cv.signer);
    $("cv-what").textContent = sc.text;
    const f = L.text(r.received.file), actual = hx(L.sha256(r.received.file));
    $("cv-rec").innerHTML = `${sp("k", "file you got   ")} ${esc(f.trim())}\n${sp("k", "its sha-256    ")} ${esc(actual.slice(0, 24))}…\n${sp("k", "page's checksum ")} ${esc(r.received.checksum.slice(0, 24))}…\n${sp("k", "signature      ")} ${esc(S.sigText(r.received.sig))}`;
    const li = (ok, label, why) => `<li class="${ok ? "ok" : "bad"}"><b>${ok ? "✓" : "✗"}</b><span><i>${label}</i> ${esc(why)}</span></li>`;
    $("cv-checks").innerHTML =
      li(r.checksumPasses, "Checksum check", r.checksumPasses ? "passes: the file's hash equals the number on the page." : "fails: the file's hash isn't the number on the page.") +
      li(r.signaturePasses, "Signature check", r.signaturePasses ? "passes: the maintainer's key signed exactly these bytes." : "fails: the maintainer's key didn't sign these bytes.");
    const N = {
      honest: "# both pass. The boring case is the point of all this.",
      corrupt: "# both catch it. Checksums are great for accidents.",
      mirror: "# the checksum caught it, because it came from the official page, not from the mirror.",
      server: "# the checksum passes. A checksum on the same page is a seal the intruder can replace too. The signature still fails: they have no key.",
      key: "# both pass: the attacker signed with the real key. Signatures move the problem to key custody and visibility, which is what the next slide is about.",
    };
    note("cv-note", N[cv.cur]);
  }
  function cvInit() {
    $("cv-pick").innerHTML = Object.keys(S.SCENARIOS).map((k) => `<button type="button" data-s="${k}" aria-pressed="${k === cv.cur}">${esc(S.SCENARIOS[k].label)}</button>`).join("");
    segPick("cv-pick", "data-s", (s) => { cv.cur = s; checksumDemo(); });
    checksumDemo();
  }

  // --------------------------------------------------------------------------- 9. signing with Sigstore (an outline, not a simulation of the real protocol)
  const SS = [
    ["Prove who you are", "The signer (a CI job, or a person) gets an identity token from an identity provider using OpenID Connect. For CI, the token names the repository and workflow.", "Identity"],
    ["Make a one-off key pair", "The signing tool generates a fresh key pair, just for this signing. It exists only in memory.", "Key"],
    ["Get a short-lived certificate", "The certificate authority (Fulcio) checks the token and issues a certificate that ties that identity to that public key. It's valid for about 10 minutes.", "Certificate"],
    ["Sign the digest, drop the key", "The tool signs the artifact's hash with the private key, then discards the key. Nothing long-lived exists to be stolen.", "Signature"],
    ["Record it in the public log", "The signature, certificate and digest are appended to a transparency log (Rekor), a Merkle tree. The log returns an inclusion proof to keep with the artifact.", "Log"],
    ["Verify, later, anywhere", "A verifier checks the signature, that the certificate chains to Sigstore's root, that the identity matches what they expect, and the log's inclusion proof.", "Verify"],
  ];
  const ss = { i: 0, seen: new Set([0]) };
  function sigstore() {
    $("ss-pick").innerHTML = SS.map((s, k) => `<button type="button" data-i="${k}" aria-pressed="${k === ss.i}">${k + 1}. ${esc(s[2])}</button>`).join("");
    const s = SS[ss.i];
    $("ss-detail").innerHTML = `<small>STEP ${ss.i + 1} OF ${SS.length}</small><b>${esc(s[0])}</b><span>${esc(s[1])}</span>`;
    note("ss-note", ss.seen.size === SS.length && ss.i === SS.length - 1 ? "# a key made for one signature, then thrown away: there's nothing left to steal. The trust sits in the identity and the public log." : "# click through the six steps.");
  }
  function ssInit() {
    $("ss-pick").addEventListener("click", (e) => { const b = e.target.closest("button[data-i]"); if (!b) return; ss.i = +b.dataset.i; ss.seen.add(ss.i); sigstore(); });
    sigstore();
  }

  // --------------------------------------------------------------------------- 10. reproducible builds
  const FILES_A = { "util.js": "export const add = (a, b) => a + b;\n", "app.js": "import { add } from './util.js';\nconsole.log(add(2, 3));\n", "README": "A small app.\n" };
  const FILES_B = { "README": "A small app.\n", "app.js": FILES_A["app.js"], "util.js": FILES_A["util.js"] };
  function repro() {
    const ts = $("rp-ts").checked, sorted = $("rp-sort").checked, nopath = $("rp-path").checked;
    const A = S.toyBuild(FILES_A, { stamp: ts ? "1700000000" : "2026-11-11T10:42:07Z", sorted, path: nopath ? "/build" : "/home/alice/app" });
    const B = S.toyBuild(FILES_B, { stamp: ts ? "1700000000" : "2026-11-11T10:42:08Z", sorted, path: nopath ? "/build" : "/home/ben/app" });
    const why = (cls, who, t) => `<li class="${cls}">${who}: ${esc(t)}</li>`;
    const card = (who, b, ts2, path, order) => `<div class="rp-build"><b>${who}</b><code>${b.digest.slice(0, 16)}…</code><ul>${why(ts ? "ok" : "bad", "time", ts2)}${why(sorted ? "ok" : "bad", "file order", order)}${why(nopath ? "ok" : "bad", "build folder", path)}</ul></div>`;
    $("rp-builds").innerHTML =
      card("Alice", A, ts ? "fixed (1700000000)" : "10:42:07", nopath ? "/build" : "/home/alice/app", sorted ? "sorted" : "util.js, app.js, README") +
      card("Ben", B, ts ? "fixed (1700000000)" : "10:42:08", nopath ? "/build" : "/home/ben/app", sorted ? "sorted" : "README, app.js, util.js");
    const same = A.digest === B.digest;
    verdict("rp-verdict", same ? "ok" : "y", same ? "Same hash: anyone can rebuild this and compare." : "Different hashes from the same source: nobody can tell drift from tampering.");
    note("rp-note", same ? "# same input, same bytes, same hash: that's the whole trick." : "# three harmless differences, three different files. Switch the fixes on one at a time.");
  }
  function provenance() {
    const d = S.toyBuild(FILES_A, { stamp: "1700000000", sorted: true, path: "/build" }).digest;
    $("slsa-prov").textContent =
      `{\n  "subject": [{ "name": "app.tar",\n    "digest": { "sha256": "${d.slice(0, 20)}…" } }],\n  "builder": "a hosted, hardened build platform",\n  "source": "git commit 9fceb02…, repo example/app",\n  "signed": "by the build platform's identity"\n}\n// invented example, in the shape of a provenance statement`;
  }

  // --------------------------------------------------------------------------- 11. pin checker
  const hex = (s) => L.hex(hash(s));
  const PN = {
    mixed: ["FROM node:latest", "FROM python:3.12", "- uses: actions/checkout@v4", "- uses: actions/setup-node", "requests>=2.0", "flask==3.0.0", '"left-pad": "^1.3.0"', '"chalk": "5.3.0"'].join("\n"),
    pinned: ["FROM node@sha256:" + hex("node"), "- uses: actions/checkout@" + hex("checkout").slice(0, 40), "requests==2.32.3 --hash=sha256:" + hex("requests"), '"integrity": "sha512-' + hex("left-pad").slice(0, 32) + 'Qw=="'].join("\n"),
    empty: "",
  };
  function pins() {
    const lines = $("pn-in").value.split("\n");
    let ok = 0, seen = 0, out = "";
    for (const line of lines) {
      const r = S.checkPin(line); if (!line.trim()) continue;
      if (!r) { out += `<li class="m"><b>·</b><span><code>${esc(line.trim())}</code> not recognised: skipped</span></li>`; continue; }
      seen++; if (r.level === "ok") ok++;
      out += `<li class="${r.level}"><b>${r.level === "ok" ? "✓" : r.level === "y" ? "!" : "✗"}</b><span><i>${esc(r.kind)}</i><code>${esc(line.trim())}</code><em>${esc(r.why)}</em></span></li>`;
    }
    $("pn-out").innerHTML = out;
    if (!seen) { verdict("pn-score", "ok", "Nothing to check."); }
    else verdict("pn-score", ok === seen ? "ok" : ok ? "y" : "bad", `${ok} of ${seen} lines name exact content.`);
    const t = $("pn-in").value.trim();
    let n = "# the green lines name exact bytes. The rest are labels: whoever controls the label controls what you get.";
    if (!t) n = "# nothing to check: the most pinned dependency list there is.";
    else if (seen && ok === seen) n = "# everything names exact bytes. An update is now a deliberate change in a pull request, not a surprise.";
    note("pn-note", n);
  }
  function pnInit() {
    $("pn-in").value = PN.mixed;
    segPick("pn-pick", "data-p", (p) => { $("pn-in").value = PN[p]; pins(); });
    $("pn-in").addEventListener("input", () => { setPressed("pn-pick", "data-p", ""); pins(); });
    pins();
  }

  // --------------------------------------------------------------------------- 12. choosing a hash
  const CH_SHORT = ["Integrity", "Content IDs", "Message auth", "Passwords", "Key derivation", "Hash table", "Signing"];
  const ch = { i: 0 };
  function choose() {
    $("ch-pick").innerHTML = S.JOBS.map((j, k) => `<button type="button" data-i="${k}" aria-pressed="${k === ch.i}">${esc(CH_SHORT[k])}</button>`).join("");
    const j = S.JOBS[ch.i];
    $("ch-detail").innerHTML = `<b>${esc(j.job)}</b><span><i class="ok">USE</i> ${esc(j.use)}</span><span><i class="bad">AVOID</i> ${esc(j.avoid)}</span><span><i class="y">WHY</i> ${esc(j.note)}</span>`;
    note("ch-note", j.id === "password" ? "# you found the password slot. Fast hashes are wrong here on purpose: slow, memory-hungry Argon2id is the tool. It has a talk of its own: Passwords and Accounts." : j.id === "mac" ? "# the classic mix-up: hash(key + message) looks like a MAC and isn't a safe one. HMAC exists to fix it." : "# pick another job.");
  }
  function chInit() {
    $("ch-pick").addEventListener("click", (e) => { const b = e.target.closest("button[data-i]"); if (!b) return; ch.i = +b.dataset.i; choose(); });
    choose();
  }

  // --------------------------------------------------------------------------- review checklist
  const RV_KEY = "hashing-review";
  function review() {
    const boxes = Array.from(document.querySelectorAll("#rv-list input[type=checkbox]"));
    let saved = {};
    try { saved = JSON.parse(store(RV_KEY) || "{}"); } catch (e) {}
    boxes.forEach((b) => { b.checked = !!saved[b.dataset.k]; });
    const update = () => {
      const done = boxes.filter((b) => b.checked).length;
      store(RV_KEY, JSON.stringify(Object.fromEntries(boxes.map((b) => [b.dataset.k, b.checked]))));
      const n = $("rv-note"); n.className = "comment";
      if (done === boxes.length) { n.textContent = "# 8 of 8. Now rebuild one of your own releases from source and compare the hashes, just to see."; n.classList.add("ok"); }
      else if (!done) n.textContent = "# tick what's true for your team today. Each gap is a ticket, not a failure. Saved in this browser only.";
      else n.textContent = `# ${done} of ${boxes.length}. Pick the unticked box that's cheapest to fix this week.`;
    };
    boxes.forEach((b) => b.addEventListener("change", update));
    update();
  }

  // --------------------------------------------------------------------------- easter egg: console
  function consoleHint() {
    console.log("%cHashing Beyond Passwords", "font: 700 24px monospace; color: #ff2e88; text-shadow: 0 0 8px #ff2e88");
    console.log("%cYou found the console. Try this: the SHA-256 of an empty string starts e3b0c442. Everyone's does.", "font: 14px monospace; color: #00f0ff");
  }

  function start() {
    consoleHint();
    $("hero-in").addEventListener("input", hero); hero();
    $("fp-in").addEventListener("input", fingerprint);
    click("fp-flip", () => { $("fp-in").value = $("fp-in").value ? $("fp-in").value.slice(0, -1) + String.fromCharCode($("fp-in").value.charCodeAt($("fp-in").value.length - 1) ^ 1) : "a"; fingerprint(); });
    click("fp-reset", () => { $("fp-in").value = FP_BASE; fingerprint(); });
    fingerprint();
    mgInit();
    $("g2-in").addEventListener("input", gitsha); gitsha();
    $("mk-in").value = MK_DEF.join("\n");
    $("mk-in").addEventListener("input", merkle);
    click("mk-reset", () => { $("mk-in").value = MK_DEF.join("\n"); merkle(); });
    merkle();
    incInit();
    $("dm-prefix").addEventListener("change", domain); domain();
    csInit();
    cvInit();
    ssInit();
    for (const id of ["rp-ts", "rp-sort", "rp-path"]) $(id).addEventListener("change", repro);
    repro(); provenance();
    pnInit();
    chInit();
    review();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
})();
