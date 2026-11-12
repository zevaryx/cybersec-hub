/* deps.js - the logic behind this talk's demos, kept apart from the page so it can be tested in Node.
   EDUCATIONAL ONLY. Everything here is a toy model: an invented package registry, invented packages and advisories, a toy CI system and a
   toy transparency log. It reuses the from-scratch maths in ../../shared/crypto.js (SHA-1, SHA-256, ECDSA P-256). Nothing is fetched,
   installed or run: the "shell" in the injection demo only splits text into commands, it never executes anything. */
(function (root) {
  "use strict";
  const L = root.Lab || (typeof require !== "undefined" ? require("../../shared/crypto.js") : null);

  // --------------------------------------------------------------------------- 1. look-alike names (typosquats)
  const POPULAR = ["requests", "express", "lodash", "react", "numpy", "django", "flask", "chalk", "axios", "pandas", "urllib3", "cryptography",
    "boto3", "jsonwebtoken", "left-pad", "moment", "webpack", "eslint", "colors", "pillow", "@types/node"];
  /** Damerau-Levenshtein distance (insert, delete, substitute, swap two neighbours). */
  function editDistance(a, b) {
    const n = a.length, m = b.length, d = [];
    for (let i = 0; i <= n; i++) { d[i] = [i]; }
    for (let j = 0; j <= m; j++) d[0][j] = j;
    for (let i = 1; i <= n; i++) for (let j = 1; j <= m; j++) {
      const c = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + c);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
    }
    return d[n][m];
  }
  const norm = (s) => s.trim().toLowerCase();
  const HOMOGLYPH = [[/0/g, "o"], [/1/g, "l"], [/rn/g, "m"], [/vv/g, "w"], [/5/g, "s"]];
  const SUFFIX = /(-|_)?(js|py|official|utils|util|lib|core|pro|new|2|secure|free)$/;
  /** Compare a name with a list of well-known names and say what kind of "close but not the same" it is. */
  function lookalike(name, popular) {
    popular = popular || POPULAR;
    const s = norm(name);
    if (!s) return { kind: "empty", nearest: null, distance: null, tricks: [] };
    if (popular.includes(s)) return { kind: "exact", nearest: s, distance: 0, tricks: [] };
    let best = null, bd = 99;
    for (const p of popular) { const d = editDistance(s, p); if (d < bd) { bd = d; best = p; } }
    const tricks = [];
    const sepA = s.replace(/[-_.]/g, ""), sepB = best.replace(/[-_.]/g, "");
    if (sepA === sepB) tricks.push("only the separator differs");
    else if (editDistance(s, best) === 1 && s.length === best.length && s !== best) {
      const swapped = [...s].some((ch, i) => i < s.length - 1 && ch === best[i + 1] && s[i + 1] === best[i]);
      tricks.push(swapped ? "two letters swapped" : "one letter changed");
    } else if (editDistance(s, best) === 1) tricks.push(s.length < best.length ? "one letter missing" : "one extra letter");
    else if (s.length === best.length && editDistance(s, best) === 2 && [...s].some((ch, i) => i < s.length - 1 && ch === best[i + 1] && s[i + 1] === best[i])) tricks.push("two letters swapped");
    let h = s; for (const [re, to] of HOMOGLYPH) h = h.replace(re, to);
    if (h !== s && popular.includes(h)) tricks.push("looks like the real name when you squint (digits or letter pairs)");
    const stem = s.replace(SUFFIX, "");
    if (stem !== s && popular.includes(stem)) tricks.push("real name plus a reassuring suffix");
    if (s.startsWith("@") && popular.some((p) => p.startsWith("@") && editDistance(s, p) <= 3 && s !== p)) tricks.push("the scope is not the real one");
    if (!s.startsWith("@") && popular.includes("@" + s.replace(/^types[-/]/, "types/"))) tricks.push("the scope is missing");
    const close = bd <= 2 || tricks.length > 0;
    return { kind: close ? "close" : "far", nearest: best, distance: bd, tricks: Array.from(new Set(tricks)) };
  }
  // The spotter game. In each round exactly one option is the name on the project's own page. Every other name is invented for this game.
  const ROUNDS = [
    { need: "the famous Python HTTP library", real: "requests", fakes: [["reqests", "a letter is missing"], ["requests-official", "\"official\" is a name anyone can type"], ["requests_", "a stray underscore: not the same name"]] },
    { need: "the popular Node web framework", real: "express", fakes: [["expresss", "one extra s"], ["exprees", "one letter changed"], ["express-js", "a suffix that sounds helpful"]] },
    { need: "the date library everyone uses (and nobody loves)", real: "moment", fakes: [["momnet", "two letters swapped"], ["m0ment", "a zero standing in for the letter o"], ["moment-js", "a suffix that sounds helpful"]] },
    { need: "Node's type definitions, from a scope run by a trusted team", real: "@types/node", fakes: [["@type/node", "the scope is one letter off, so it's a different publisher"], ["types-node", "no scope at all: a different namespace"], ["@types-node/node", "a look-alike scope"]] },
    { need: "the Python cryptography package", real: "cryptography", fakes: [["cryptograpy", "a letter is missing"], ["crypto-graphy", "an invented hyphen"], ["cryptography-lib", "a suffix that sounds helpful"]] },
    { need: "the Python image library (you install Pillow but import PIL)", real: "pillow", fakes: [["pil", "the import name isn't always the install name: check the project's page"], ["pi11ow", "ones standing in for the letter l"], ["pillow-utils", "a suffix that sounds helpful"]] },
  ];
  /** Deterministic shuffle so tests can predict a round. */
  function shuffle(arr, seed) {
    const a = arr.slice(); let x = (seed * 2654435761) >>> 0 || 1;
    for (let i = a.length - 1; i > 0; i--) { x = (Math.imul(x, 1103515245) + 12345) >>> 0; const j = x % (i + 1); [a[i], a[j]] = [a[j], a[i]]; }
    return a;
  }
  function roundOptions(r, seed) {
    return shuffle([{ name: r.real, real: true, why: "The name on the project's own page and docs." }].concat(r.fakes.map((f) => ({ name: f[0], real: false, why: f[1] }))), seed);
  }

  // --------------------------------------------------------------------------- 2. a dependency tree (all invented)
  const PACKAGES = {
    "shop-web":     { v: "1.0.0", deps: ["fast-router", "forms-kit", "http-client", "pretty-dates", "tiny-logger"], dev: ["build-tools"], note: "Your application." },
    "fast-router":  { v: "6.3.1", deps: ["path-match", "url-parse-lite"], note: "URL routing." },
    "path-match":   { v: "2.0.0", deps: ["regex-bits"], note: "Matches URL paths against patterns." },
    "regex-bits":   { v: "1.0.4", deps: [], note: "A few regular-expression helpers." },
    "forms-kit":    { v: "3.2.0", deps: ["field-rules", "url-parse-lite", "tiny-logger"], note: "Form handling." },
    "field-rules":  { v: "1.9.2", deps: [], note: "Validation rules for form fields." },
    "http-client":  { v: "4.1.0", deps: ["url-parse-lite", "retry-it", "tiny-logger"], note: "Makes outgoing HTTP requests." },
    "retry-it":     { v: "2.0.1", deps: ["sleep-ms"], note: "Retries a failing call." },
    "sleep-ms":     { v: "1.0.0", deps: [], note: "Waits for a number of milliseconds." },
    "pretty-dates": { v: "0.9.1", deps: ["left-pad", "month-names"], note: "Formats dates for people." },
    "left-pad":     { v: "1.3.0", deps: [], note: "Pads a string on the left." },
    "month-names":  { v: "1.1.0", deps: [], note: "Month names in a few languages." },
    "tiny-logger":  { v: "1.5.0", deps: ["color-text"], note: "Small logging helper." },
    "color-text":   { v: "3.0.0", deps: [], note: "Colours for terminal text." },
    "url-parse-lite": { v: "2.1.0", deps: [], note: "Splits a URL into parts.", vuln: { id: "EXAMPLE-2026-0001", below: "2.2.0", sev: "High", text: "mis-parses a crafted URL, so a check on the host can be fooled (invented advisory)" } },
    "build-tools":  { v: "8.0.0", deps: ["bundle-it", "lint-all"], dev: true, note: "Build and lint (development only)." },
    "bundle-it":    { v: "5.2.0", deps: ["tiny-logger", "glob-lite"], dev: true, note: "Bundles the app." },
    "lint-all":     { v: "4.0.0", deps: ["glob-lite", "url-parse-lite"], dev: true, note: "Lints the code." },
    "glob-lite":    { v: "3.1.0", deps: [], dev: true, note: "File-name patterns." },
  };
  const ROOT = "shop-web";
  // direct dependencies that have a release which pulls in the fixed url-parse-lite
  const FIXES = { "forms-kit": "3.3.0", "http-client": "4.2.0", "build-tools": "8.1.0" };
  function directDeps(pk) { pk = pk || PACKAGES; return pk[ROOT].deps.concat(pk[ROOT].dev || []); }
  function edges(pk, name) { const p = pk[name]; return p.deps.concat(p.dev && Array.isArray(p.dev) ? p.dev : []); }
  /** Every unique package below the root, and how many are direct. */
  function treeStats(pk) {
    pk = pk || PACKAGES;
    const seen = new Set(), depth = {};
    (function walk(n, d) { for (const c of edges(pk, n)) { if (!(c in depth) || d + 1 < depth[c]) depth[c] = d + 1; if (!seen.has(c)) { seen.add(c); walk(c, d + 1); } } })(ROOT, 0);
    const all = Array.from(seen), direct = directDeps(pk);
    return { total: all.length, direct: direct.length, transitive: all.length - direct.length, maxDepth: Math.max.apply(null, all.map((n) => depth[n])), all };
  }
  /** Every chain from the root to `target`. */
  function pathsTo(target, pk) {
    pk = pk || PACKAGES; const out = [];
    (function walk(n, trail) { if (n === target) { out.push(trail.slice()); return; } for (const c of edges(pk, n)) { trail.push(c); walk(c, trail); trail.pop(); } })(ROOT, []);
    return out;
  }
  const vparts = (v) => v.split(".").map(Number);
  function cmp(a, b) { const x = vparts(a), y = vparts(b); for (let i = 0; i < 3; i++) { if ((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) < (y[i] || 0) ? -1 : 1; } return 0; }
  /** Which chains still end in the vulnerable version, given the direct dependencies you've updated and whether you've added an override. */
  function vulnState(applied, override) {
    const adv = PACKAGES["url-parse-lite"].vuln;
    const paths = pathsTo("url-parse-lite").map((p) => {
      const direct = p[0], fixed = override || (applied.has(direct) && FIXES[direct]);
      return { path: [ROOT].concat(p), direct, dev: !!PACKAGES[direct].dev, fixed: !!fixed, hasFix: !!FIXES[direct], version: fixed ? "2.2.0" : PACKAGES["url-parse-lite"].v };
    });
    return { advisory: adv, paths, vulnerable: paths.some((p) => !p.fixed), shipped: paths.some((p) => !p.fixed && !p.dev) };
  }

  // --------------------------------------------------------------------------- 3. versions over time: ranges, lock files and cooldowns
  // A made-up registry for one package. day = when it was published; gone = the day it was removed (null = never).
  const REGISTRY = [
    { v: "1.2.0", day: 0, gone: null },
    { v: "1.2.1", day: 3, gone: null },
    { v: "1.3.0", day: 9, gone: null },
    { v: "1.3.1", day: 12, gone: 14, bad: true },
    { v: "1.3.2", day: 16, gone: null },
    { v: "2.0.0", day: 18, gone: null },
  ];
  const RANGE = "^1.2.0";
  /** Caret range: same major version (for 1.x and up), at least the written version. */
  function satisfies(v, range) {
    const m = /^\^(\d+)\.(\d+)\.(\d+)$/.exec(range); if (!m) throw new Error("only caret ranges here");
    return vparts(v)[0] === +m[1] && cmp(v, m.slice(1).join(".")) >= 0;
  }
  const available = (e, day) => e.day <= day && (e.gone === null || day < e.gone);
  function highest(list) { return list.reduce((a, e) => (!a || cmp(e.v, a.v) > 0 ? e : a), null); }
  /** What a fresh install resolves on `day` with no lock file. */
  function resolveRange(day, range, reg) { reg = reg || REGISTRY; return highest(reg.filter((e) => available(e, day) && satisfies(e.v, range || RANGE))); }
  const MODES = {
    range: { label: "No lock file", text: "Every install resolves the range again, so it gets whatever is newest that day." },
    lock: { label: "Lock file, installed as written", text: "The lock file records exact versions and hashes. Installs reproduce them, and nothing changes until someone updates the lock file." },
    bot: { label: "Lock file + update bot (no waiting)", text: "A bot opens an update the moment a new version appears, and it gets merged." },
    cool: { label: "Lock file + update bot with a 3-day wait", text: "The bot only proposes a version once it's three days old, and checks it's still there." },
  };
  /** The version each way of installing would give you, for every day 0..last. */
  function timeline(mode, last, opts) {
    opts = opts || {}; const reg = opts.reg || REGISTRY, range = opts.range || RANGE, cool = mode === "cool" ? (opts.cooldown == null ? 3 : opts.cooldown) : 0, out = [];
    let locked = resolveRange(0, range, reg);
    for (let day = 0; day <= last; day++) {
      let e;
      if (mode === "range") e = resolveRange(day, range, reg);
      else {
        if (mode === "bot" || mode === "cool") {
          const cand = highest(reg.filter((x) => available(x, day) && x.day + cool <= day && satisfies(x.v, range)));
          if (cand && cmp(cand.v, locked.v) > 0) locked = cand;
        }
        e = locked;
      }
      out.push({ day, v: e.v, bad: !!e.bad });
    }
    return out;
  }
  /** A lock-file entry for a downloaded file: the integrity check refuses anything whose hash differs. */
  function integrity(bytes) { return "sha256-" + L.hex(L.sha256(typeof bytes === "string" ? L.utf8(bytes) : bytes)); }
  function installCheck(expected, bytes) { const got = integrity(bytes); return { ok: got === expected, expected, got }; }

  // --------------------------------------------------------------------------- 4. reviewing an update
  function reviewUpdate(oldM, newM, now) {
    const f = []; const age = (d) => Math.max(0, Math.round((now - d) / 86400000));
    const add = (level, id, text) => f.push({ level, id, text });
    const oldS = new Set(Object.keys(oldM.scripts || {})), newS = Object.keys(newM.scripts || {}).filter((k) => !oldS.has(k));
    if (newS.length) add("bad", "script", "New install-time script: " + newS.join(", ") + ". It runs on every machine that installs this.");
    const om = new Set(oldM.maintainers || []), nm = (newM.maintainers || []).filter((m) => !om.has(m));
    if (nm.length) add("bad", "maintainer", "Publisher changed: " + nm.join(", ") + " is new on this package.");
    if (oldM.provenance && !newM.provenance) add("bad", "provenance", "This version has no provenance, and the last one did.");
    const od = new Set(Object.keys(oldM.deps || {})), nd = Object.keys(newM.deps || {}).filter((k) => !od.has(k));
    for (const d of nd) { const a = (newM.depInfo && newM.depInfo[d]) || {}; add(a.days != null && a.days < 30 ? "bad" : "y", "dep", "New dependency: " + d + (a.days != null ? " (first published " + a.days + " days ago)" : "") + "."); }
    if (newM.repo && oldM.repo && newM.repo !== oldM.repo) add("y", "repo", "The source repository link changed.");
    if (oldM.sizeKB && newM.sizeKB && newM.sizeKB > oldM.sizeKB * 3) add("y", "size", "Package grew from " + oldM.sizeKB + " KB to " + newM.sizeKB + " KB.");
    if (vparts(newM.v)[0] > vparts(oldM.v)[0]) add("y", "major", "Major version: expect breaking changes, read the changelog.");
    if (newM.published != null && age(newM.published) < 3) add("y", "young", "Published " + age(newM.published) + " day(s) ago. A short wait costs little.");
    if (!f.length) add("ok", "none", "Nothing unusual in the metadata. Still read the changelog and let the tests run.");
    return f;
  }
  const DAY = 86400000, NOW = 1790000000000;
  const UPDATES = {
    patch: { title: "A routine patch", old: { v: "3.2.0", scripts: {}, maintainers: ["ana"], provenance: true, deps: { "field-rules": 1 }, repo: "github.com/forms/forms-kit", sizeKB: 120 },
      neu: { v: "3.2.1", scripts: {}, maintainers: ["ana"], provenance: true, deps: { "field-rules": 1 }, repo: "github.com/forms/forms-kit", sizeKB: 121, published: NOW - 9 * DAY } },
    odd: { title: "A patch that changes more than it says", old: { v: "3.2.0", scripts: {}, maintainers: ["ana"], provenance: true, deps: { "field-rules": 1 }, repo: "github.com/forms/forms-kit", sizeKB: 120 },
      neu: { v: "3.2.1", scripts: { postinstall: "node setup.js" }, maintainers: ["ana", "kit-helper"], provenance: false, deps: { "field-rules": 1, "net-helper": 1 }, depInfo: { "net-helper": { days: 4 } }, repo: "github.com/forms/forms-kit", sizeKB: 2100, published: NOW - DAY } },
    major: { title: "A new major version", old: { v: "3.2.0", scripts: {}, maintainers: ["ana"], provenance: true, deps: { "field-rules": 1 }, repo: "github.com/forms/forms-kit", sizeKB: 120 },
      neu: { v: "4.0.0", scripts: {}, maintainers: ["ana"], provenance: true, deps: { "field-rules": 1 }, repo: "github.com/forms/forms-kit", sizeKB: 150, published: NOW - 20 * DAY } },
  };

  // --------------------------------------------------------------------------- 5. dependency confusion
  const INTERNAL = { registry: "internal registry", name: "acme-billing", version: "1.4.0" };
  const PUBLIC_FAKE = { registry: "public registry", name: "acme-billing", version: "99.0.0" };
  const STRATEGIES = {
    highest: { label: "Search both registries, highest version wins", text: "The default for some tools when more than one index is configured." },
    scope: { label: "Scoped name (@acme/billing) mapped to the internal registry only", text: "Your organisation's scope is bound to your registry in the config." },
    route: { label: "One proxy registry with a rule: internal names never come from outside", text: "Registry managers can route or block by name." },
    reserve: { label: "Still search both, but you already registered the name publicly", text: "Defence in depth: a placeholder keeps the name taken." },
    lock: { label: "Lock file with hashes, installed as written", text: "Reproduce the exact file you recorded." },
  };
  function resolveConfusion(strategy) {
    switch (strategy) {
      case "highest": return { chosen: PUBLIC_FAKE, bad: true, why: "99.0.0 is higher than 1.4.0, so the public one wins. Nothing was hacked: the tool did what it was told." };
      case "scope": return { chosen: INTERNAL, bad: false, why: "Names under @acme can only be published by acme on the public registry, and the config sends them to the internal registry anyway." };
      case "route": return { chosen: INTERNAL, bad: false, why: "The registry manager refuses to serve a public package that has an internal name." };
      case "reserve": return { chosen: INTERNAL, bad: false, why: "A harmless placeholder (0.0.0) sits on the public registry, so no outsider can claim the name. Don't rely on this alone: it only works for names you remembered to reserve." };
      case "lock": { const e = integrity("acme-billing 1.4.0 contents"), g = integrity("acme-billing 99.0.0 contents"); return { chosen: INTERNAL, bad: false, why: "The lock file records " + e.slice(0, 18) + "…, so a file that hashes to " + g.slice(0, 18) + "… is refused: the build fails loudly instead of installing the wrong thing." }; }
      default: throw new Error("unknown strategy");
    }
  }

  // --------------------------------------------------------------------------- 6. SBOMs
  /** A small CycloneDX-shaped document for an app (illustrative: real SBOMs carry more fields). */
  function sbom(appName, comps) {
    return { bomFormat: "CycloneDX", specVersion: "1.6", version: 1, metadata: { component: { type: "application", name: appName } },
      components: comps.map(([name, version]) => ({ type: "library", name, version, purl: "pkg:npm/" + name + "@" + version })) };
  }
  function sbomFromTree(appName) { return sbom(appName, treeStats().all.map((n) => [n, PACKAGES[n].v])); }
  const FLEET = {
    "shop-web": sbomFromTree("shop-web"),
    "admin-portal": sbom("admin-portal", [["fast-router", "6.2.0"], ["url-parse-lite", "2.0.3"], ["tiny-logger", "1.5.0"], ["color-text", "3.0.0"]]),
    "mailer": sbom("mailer", [["http-client", "4.2.0"], ["url-parse-lite", "2.2.0"], ["retry-it", "2.0.1"], ["sleep-ms", "1.0.0"]]),
    "report-batch": sbom("report-batch", [["pretty-dates", "0.9.1"], ["left-pad", "1.3.0"], ["month-names", "1.1.0"]]),
  };
  /** Which apps ship `pkg` below version `below`. */
  function whichApps(fleet, pkg, below) {
    return Object.keys(fleet).map((app) => {
      const c = fleet[app].components.find((x) => x.name === pkg);
      return { app, version: c ? c.version : null, affected: !!c && cmp(c.version, below) < 0 };
    });
  }

  // --------------------------------------------------------------------------- 7. what a stolen workflow token can do
  const PERMS = ["contents: write", "packages: write", "pull-requests: write", "id-token: write"];
  /** `perms`: a Set of granted permissions (anything not listed is read-only or none). `secrets`: "repo" or "env". */
  function blast(perms, secrets, deployApproval) {
    const has = (p) => perms.has(p);
    const rows = [
      { id: "read", text: "Read the repository's code", ok: true, why: "Every job can read what it checks out." },
      { id: "push", text: "Push a commit or move a tag", ok: has("contents: write"), why: has("contents: write") ? "contents: write lets the token change the repository." : "The token is read-only for contents." },
      { id: "pkg", text: "Publish a package or image", ok: has("packages: write"), why: has("packages: write") ? "packages: write can publish under your name." : "No packages permission, so the registry says no." },
      { id: "pr", text: "Approve or edit pull requests", ok: has("pull-requests: write"), why: has("pull-requests: write") ? "pull-requests: write can comment on and change pull requests." : "No pull-requests permission." },
      { id: "oidc", text: "Ask for a cloud identity token", ok: has("id-token: write"), why: has("id-token: write") ? "id-token: write lets the job request an identity the cloud may trust." : "Without id-token: write the job can't request one." },
      { id: "secrets", text: "Read the production deploy secret", ok: secrets === "repo", why: secrets === "repo" ? "A repository secret is available to every job in every workflow." : (deployApproval ? "An environment secret only reaches a job that passed the environment's required reviewer." : "An environment secret needs the deploy job and its protection rules.") },
    ];
    return { rows, count: rows.filter((r) => r.ok).length };
  }

  // --------------------------------------------------------------------------- 8. a tag that can move, and a commit that can't
  const commitId = (txt) => L.hex(L.sha1(L.utf8(txt)));
  function makeActionRepo() {
    const mk = (n, code) => ({ n, code, id: commitId("acme/setup-tool commit " + n + "\n" + code.join("\n")) });
    const commits = [
      mk(1, ["echo 'installing tool 1.0'", "download tool", "verify tool checksum"]),
      mk(2, ["echo 'installing tool 1.1'", "download tool", "verify tool checksum", "add tool to PATH"]),
      mk(3, ["echo 'installing tool 1.2'", "download tool", "verify tool checksum", "add tool to PATH", "cache the download"]),
      mk(4, ["echo 'installing tool 1.1'", "download tool", "verify tool checksum", "add tool to PATH", "send all environment variables to example.invalid"]),
    ];
    return { commits, tags: { v1: commits[1].id }, main: commits[2].id };
  }
  const byId = (repo, id) => repo.commits.find((c) => c.id === id);
  function moveTag(repo, tag, n) { repo.tags[tag] = repo.commits[n - 1].id; }
  /** What `uses: acme/setup-tool@<ref>` runs right now. */
  function resolveRef(repo, ref) {
    const id = /^[0-9a-f]{40}$/.test(ref) ? ref : (ref === "main" ? repo.main : repo.tags[ref]);
    const c = id && byId(repo, id);
    return c ? { commit: c, id: c.id, bad: c.code.some((l) => /example\.invalid/.test(l)), short: /^[0-9a-f]{40}$/.test(ref) ? false : true } : null;
  }

  // --------------------------------------------------------------------------- 9. untrusted text in a workflow step (nothing is ever executed)
  /** Split shell-ish text into the commands it would start. Understands ; && || newlines, quotes and $( ) or backticks. */
  function shellCommands(src) {
    const out = [];
    (function parse(s) {
      let cur = "", q = "", i = 0;
      const flush = () => { if (cur.trim()) out.push(cur.trim()); cur = ""; };
      while (i < s.length) {
        const c = s[i];
        if (q === "'") { cur += c; if (c === "'") q = ""; i++; continue; }
        if (c === "'" && q === "") { q = "'"; cur += c; i++; continue; }
        if (c === "\\" && i + 1 < s.length) { cur += c + s[i + 1]; i += 2; continue; }
        if (c === "$" && s[i + 1] === "(") {
          let depth = 1, j = i + 2; while (j < s.length && depth) { if (s[j] === "(") depth++; else if (s[j] === ")") depth--; j++; }
          parse(s.slice(i + 2, j - 1)); cur += s.slice(i, j); i = j; continue;
        }
        if (c === "`") { const j = s.indexOf("`", i + 1); if (j > 0) { parse(s.slice(i + 1, j)); cur += s.slice(i, j + 1); i = j + 1; continue; } }
        if (c === '"') { q = q === '"' ? "" : '"'; cur += c; i++; continue; }
        if (q === "" && (c === ";" || c === "\n" || (c === "&" && s[i + 1] === "&") || (c === "|" && s[i + 1] === "|"))) { flush(); i += (c === "&" || c === "|") ? 2 : 1; continue; }
        cur += c; i++;
      }
      flush();
    })(src);
    return out;
  }
  const TEMPLATE = "${{ github.event.issue.title }}";
  const STEPS = {
    unsafe: { label: "Title pasted into the script", yaml: ["- name: Say hello", "  run: echo \"New issue: ${{ github.event.issue.title }}\""], script: 'echo "New issue: ${{ github.event.issue.title }}"', env: false },
    safe: { label: "Title passed as an environment variable", yaml: ["- name: Say hello", "  env:", "    TITLE: ${{ github.event.issue.title }}", "  run: echo \"New issue: $TITLE\""], script: 'echo "New issue: $TITLE"', env: true },
  };
  /** What the runner builds from the step, and which commands the shell would start. */
  function renderStep(kind, title) {
    const st = STEPS[kind];
    const text = st.env ? st.script : st.script.split(TEMPLATE).join(title);
    const baseline = shellCommands(st.env ? st.script : st.script.split(TEMPLATE).join("x")).length;
    const cmds = shellCommands(text);
    return { text, commands: cmds, expected: baseline, extra: Math.max(0, cmds.length - baseline), env: st.env ? "TITLE=" + JSON.stringify(title) : null };
  }

  // --------------------------------------------------------------------------- 10. signing, a toy transparency log and provenance
  const newKey = () => { const d = L.randBelow(L.P256.n - 1n) + 1n; return { d, Q: L.P256.mul(d) }; };
  const digestOf = (bytes) => L.hex(L.sha256(bytes));
  function sign(key, text) { const k = L.randBelow(L.P256.n - 1n) + 1n; return L.ecdsaSign(key.d, L.hashInt(text), k); }
  function verify(pub, text, sig) { return L.ecdsaVerify(pub, L.hashInt(text), sig); }
  /** A toy append-only log: each entry's hash covers the one before it (a hash chain; Rekor uses a Merkle tree). */
  function makeLog() { return { entries: [], head: "0".repeat(64) }; }
  function logAppend(log, digest, sigHex, who) {
    const prev = log.head, body = JSON.stringify({ digest, sig: sigHex, who, prev });
    const h = L.hex(L.sha256(L.utf8(body))); log.entries.push({ index: log.entries.length, digest, sig: sigHex, who, hash: h }); log.head = h; return log.entries.length - 1;
  }
  const sigHex = (sig) => L.hex(L.fromBig(sig[0], 32)).slice(0, 16);
  const logHas = (log, digest, sh) => log.entries.some((e) => e.digest === digest && e.sig === sh);
  /** Make a release: artifact bytes, a signature, and a log entry. */
  function makeRelease(signer, name, content, log, who) {
    const art = L.utf8(content), digest = digestOf(art), sig = sign(signer, digest);
    const idx = logAppend(log, digest, sigHex(sig), who);
    return { name, bytes: art, digest, sig, logIndex: idx };
  }
  /** What a consumer checks. `trusted`: the identity's public key the consumer expects. */
  function verifyRelease(rel, bytes, trusted, log) {
    const d = digestOf(bytes), checks = [];
    checks.push({ id: "sig", ok: verify(trusted, rel.digest, rel.sig), text: "The signature matches the expected signer's key" });
    checks.push({ id: "digest", ok: d === rel.digest, text: "The file's hash matches what was signed" });
    checks.push({ id: "log", ok: logHas(log, rel.digest, sigHex(rel.sig)), text: "The signing event is in the public log" });
    return { ok: checks.every((c) => c.ok), checks, digest: d };
  }
  const PROV = { builder: "https://ci.example/builder@v2", repo: "example-org/shop", ref: "refs/tags/v1.4.0", commit: "9f2c1d0" };
  function statement(art, fields) { return JSON.stringify({ subject: { name: art.name, sha256: digestOf(art.bytes) }, builder: fields.builder, source: { repo: fields.repo, ref: fields.ref, commit: fields.commit } }); }
  const EXPECT = { builders: ["https://ci.example/builder@v2"], repo: "example-org/shop", refRe: /^refs\/tags\/v\d+\.\d+\.\d+$/ };
  /** The policy a deployer applies to a provenance statement. */
  function checkProvenance(att, art, builderPub) {
    const st = JSON.parse(att.text), checks = [];
    checks.push({ id: "sig", ok: verify(builderPub, att.text, att.sig), text: "Signed by the build platform we trust" });
    checks.push({ id: "digest", ok: st.subject.sha256 === digestOf(art.bytes), text: "Describes this exact file (hash matches)" });
    checks.push({ id: "builder", ok: EXPECT.builders.includes(st.builder), text: "Built by an approved builder" });
    checks.push({ id: "repo", ok: st.source.repo === EXPECT.repo, text: "Built from our repository" });
    checks.push({ id: "ref", ok: EXPECT.refRe.test(st.source.ref), text: "Built from a release tag, not a branch or pull request" });
    return { ok: checks.every((c) => c.ok), checks };
  }
  const SCENARIOS = {
    good: { label: "A normal release", note: "Every check passes. The file came from our repository, from a release tag, built by the platform." },
    swap: { label: "File swapped after the build", note: "The attestation is real, but it describes a different file. The hash check catches the swap." },
    edit: { label: "Statement edited by hand", note: "Someone changed the repository name in the statement. The signature no longer matches the text." },
    forge: { label: "Re-signed with a key we don't trust", note: "A perfectly formed statement, signed by someone else. A signature only means something if you know whose key it is." },
    other: { label: "Built in someone else's repository", note: "Genuine, signed provenance for a different repository. Valid is not the same as expected." },
    branch: { label: "Built from a pull request branch", note: "Genuine, but not from a release tag. Your policy decides whether that's acceptable." },
    merged: { label: "Malicious change merged, then built properly", note: "Every check passes. Provenance says how and where it was built, not whether the code is good. That is what review, branch protection and tests are for." },
  };
  /** Build the scenario: returns {art, att, builderPub, result}. Uses fresh keys each time (a toy). */
  function provenanceScenario(kind, builder, other) {
    const art = { name: "shop-1.4.0.tgz", bytes: L.utf8("shop 1.4.0 build output") };
    let fields = Object.assign({}, PROV), signer = builder, shown = art;
    if (kind === "other") fields.repo = "someone-else/shop";
    if (kind === "branch") fields.ref = "refs/pull/212/merge";
    if (kind === "merged") { art.bytes = L.utf8("shop 1.4.0 build output (includes a change that exfiltrates data)"); }
    let text = statement(art, fields), sig;
    if (kind === "forge") signer = other;
    sig = sign(signer, text);
    if (kind === "swap") shown = { name: art.name, bytes: L.utf8("shop 1.4.0 build output (swapped)") };
    if (kind === "edit") text = text.replace("example-org/shop", "example-org/shop-fork");
    const att = { text, sig };
    return { art: shown, att, result: checkProvenance(att, shown, builder.Q) };
  }

  const api = { POPULAR, editDistance, lookalike, ROUNDS, shuffle, roundOptions, PACKAGES, ROOT, FIXES, directDeps, treeStats, pathsTo, vulnState, cmp,
    REGISTRY, RANGE, satisfies, resolveRange, MODES, timeline, integrity, installCheck, UPDATES, reviewUpdate, NOW,
    INTERNAL, PUBLIC_FAKE, STRATEGIES, resolveConfusion, sbom, sbomFromTree, FLEET, whichApps, PERMS, blast,
    makeActionRepo, moveTag, resolveRef, commitId, shellCommands, STEPS, renderStep, TEMPLATE,
    newKey, digestOf, sign, verify, makeLog, logAppend, makeRelease, verifyRelease, PROV, EXPECT, SCENARIOS, provenanceScenario, sigHex };
  root.DepsLab = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof window !== "undefined" ? window : globalThis);
