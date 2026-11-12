/* fuzz.js - the logic behind the demos in "Fuzzing for Developers".
   Everything here is a TOY: an invented record parser with planted bugs, a small coverage-guided fuzzer,
   a test-case minimiser, a Base64 round-trip property test, and a few quiz data sets.
   It runs in the browser (window.FuzzLab) and in Node (module.exports) so it can be tested.
   No network, no eval, nothing is sent anywhere. */
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.FuzzLab = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  // ------------------------------------------------------------------ a small seeded random generator
  function mulberry32(seed) {
    let a = seed >>> 0;
    return function () {
      a = (a + 0x6d2b79f5) >>> 0;
      let t = a;
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }
  const randInt = (rng, n) => Math.floor(rng() * n);
  const pick = (rng, arr) => arr[randInt(rng, arr.length)];

  // ------------------------------------------------------------------ the target: an invented "REC" record parser
  //   REC1:<n>:<text>     version 1: a declared length, then the text
  //   REC2:<f1>;<f2>;...  version 2: fields separated by ";", and a field may start with a tag such as FUZZ
  // Each "branch" is a place the code can go. The fuzzer sees which branches an input reached (its "coverage").
  const BRANCHES = [
    { id: "entry", label: "parse() entered" },
    { id: "empty-input", label: "empty input handled" },
    { id: "bad-magic", label: "rejected: not a REC record" },
    { id: "R", label: "magic: R" },
    { id: "RE", label: "magic: RE" },
    { id: "REC", label: "magic: REC" },
    { id: "bad-version", label: "rejected: unknown version" },
    { id: "v1", label: "version 1 path" },
    { id: "v1-colon", label: "v1: colon after version" },
    { id: "v1-len", label: "v1: declared length read" },
    { id: "v1-text", label: "v1: text read" },
    { id: "v1-short", label: "v1: declared length too big (rejected)" },
    { id: "v1-ok", label: "v1: record accepted" },
    { id: "v2", label: "version 2 path" },
    { id: "v2-colon", label: "v2: colon after version" },
    { id: "v2-fields", label: "v2: fields split" },
    { id: "v2-multi", label: "v2: more than one field" },
    { id: "v2-empty-field", label: "v2: empty field (rejected)" },
    { id: "tag-F", label: "tag starts with F" },
    { id: "tag-FU", label: "tag starts with FU" },
    { id: "tag-FUZ", label: "tag starts with FUZ" },
    { id: "tag-FUZZ", label: "tag FUZZ reached" },
    { id: "tag-FUZZ-ok", label: "tag FUZZ handled safely" },
    { id: "v2-ok", label: "v2: record accepted" }
  ];
  const BUGS = {
    fuzz: { site: "copy_tag", kind: "heap-buffer-overflow (toy)", line: "tag of 4+ bytes copied into a 3-byte buffer" },
    len: { site: "read_field", kind: "read past end (toy)", line: "declared length is bigger than the text it points at" },
    empty: { site: "split_fields", kind: "null dereference (toy)", line: "an empty field has no first byte to look at" }
  };
  const BUG_IDS = ["fuzz", "len", "empty"];

  // bugs: which planted bugs are still in this build. Pass [] for the fixed build.
  function parseRecord(s, bugs) {
    bugs = bugs || ["fuzz"];
    const cov = new Set();
    const cmp = new Set(); // the literals the code compared the input against (real engines can trace these)
    const hit = (id) => cov.add(id);
    const out = { cov, cmp, crash: null, status: "ok" };
    const crash = (id, detail) => {
      const b = BUGS[id];
      out.crash = { id, site: b.site, kind: b.kind, line: b.line, detail: detail || "" };
      out.status = "crash";
      return out;
    };
    hit("entry");
    if (s.length === 0) { hit("empty-input"); out.status = "empty"; return out; }
    cmp.add("REC");
    if (s[0] === "R") hit("R");
    if (s[0] === "R" && s[1] === "E") hit("RE");
    if (s.slice(0, 3) === "REC") hit("REC");
    else { hit("bad-magic"); out.status = "rejected"; return out; }
    const ver = s[3];
    cmp.add("1"); cmp.add("2");
    if (ver === "1") {
      hit("v1");
      cmp.add(":");
      if (s[4] !== ":") { out.status = "rejected"; return out; }
      hit("v1-colon");
      const m = /^(\d+):/.exec(s.slice(5));
      if (!m) { out.status = "rejected"; return out; }
      hit("v1-len");
      const declared = parseInt(m[1], 10);
      const text = s.slice(5 + m[0].length);
      hit("v1-text");
      if (declared > text.length) {
        if (bugs.indexOf("len") >= 0) return crash("len", "declared " + declared + ", text has " + text.length);
        hit("v1-short"); out.status = "rejected"; return out;
      }
      hit("v1-ok");
      return out;
    }
    if (ver === "2") {
      hit("v2");
      cmp.add(":");
      if (s[4] !== ":") { out.status = "rejected"; return out; }
      hit("v2-colon");
      cmp.add(";");
      const fields = s.slice(5).split(";");
      hit("v2-fields");
      if (fields.length > 1) hit("v2-multi");
      for (let i = 0; i < fields.length; i++) {
        const f = fields[i];
        if (f.length === 0) {
          if (bugs.indexOf("empty") >= 0) return crash("empty", "field " + (i + 1) + " is empty");
          hit("v2-empty-field"); out.status = "rejected"; return out;
        }
        cmp.add("F"); cmp.add("FU"); cmp.add("FUZ"); cmp.add("FUZZ");
        if (f[0] === "F") hit("tag-F");
        if (f.slice(0, 2) === "FU") hit("tag-FU");
        if (f.slice(0, 3) === "FUZ") hit("tag-FUZ");
        if (f.slice(0, 4) === "FUZZ") {
          hit("tag-FUZZ");
          if (bugs.indexOf("fuzz") >= 0) return crash("fuzz", "tag is " + Math.min(f.length, 9) + (f.length > 9 ? "+" : "") + " bytes");
          hit("tag-FUZZ-ok");
        }
      }
      hit("v2-ok");
      return out;
    }
    hit("bad-version"); out.status = "rejected";
    return out;
  }

  // ------------------------------------------------------------------ mutation
  const PRINTABLE = [];
  for (let c = 32; c < 127; c++) PRINTABLE.push(String.fromCharCode(c));
  const INTERESTING = "0123456789:;";
  const DEFAULT_DICT = ["REC", ":", ";"];
  const MUTATORS = ["flip a byte", "insert a byte", "delete a byte", "copy a chunk", "splice two inputs", "insert a dictionary word"];

  function randChar(rng, interesting) {
    if (interesting && rng() < 0.25) return INTERESTING[randInt(rng, INTERESTING.length)];
    return PRINTABLE[randInt(rng, PRINTABLE.length)];
  }

  // one mutation; returns { s, name }
  function mutateOnce(rng, s, o) {
    o = o || {};
    const maxLen = o.maxLen || 48;
    const dict = o.dict || [];
    const others = o.others || [];
    const kinds = [0, 1, 2, 3];
    if (others.length > 1) kinds.push(4);
    if (dict.length) kinds.push(5, 5);
    const k = pick(rng, kinds);
    let r = s;
    if (k === 0 && s.length) { const i = randInt(rng, s.length); r = s.slice(0, i) + randChar(rng, true) + s.slice(i + 1); }
    else if (k === 1 || (k === 0 && !s.length)) { const i = randInt(rng, s.length + 1); r = s.slice(0, i) + randChar(rng, true) + s.slice(i); }
    else if (k === 2 && s.length) { const i = randInt(rng, s.length); r = s.slice(0, i) + s.slice(i + 1); }
    else if (k === 3 && s.length) { const i = randInt(rng, s.length), n = 1 + randInt(rng, Math.min(4, s.length - i)); const j = randInt(rng, s.length + 1); r = s.slice(0, j) + s.slice(i, i + n) + s.slice(j); }
    else if (k === 4) { const t = pick(rng, others); const i = randInt(rng, s.length + 1), j = randInt(rng, t.length + 1); r = s.slice(0, i) + t.slice(j); }
    else if (k === 5) { const w = pick(rng, dict); const i = randInt(rng, s.length + 1); r = s.slice(0, i) + w + s.slice(i); }
    if (r.length > maxLen) r = r.slice(0, maxLen);
    return { s: r, name: MUTATORS[k === 3 ? 3 : k === 4 ? 4 : k === 5 ? 5 : k] };
  }

  function havoc(rng, s, o) {
    const n = rng() < 0.65 ? 1 : 2 + randInt(rng, 3);
    const names = [];
    let cur = s;
    for (let i = 0; i < n; i++) { const m = mutateOnce(rng, cur, o); cur = m.s; names.push(m.name); }
    return { s: cur, names };
  }

  // a few light edits, for the "mutation without feedback" mode
  function blindMutate(rng, s, o) {
    const n = 1 + randInt(rng, 3);
    let cur = s;
    for (let i = 0; i < n; i++) cur = mutateOnce(rng, cur, Object.assign({}, o, { others: [] })).s;
    return cur;
  }

  function randomInput(rng, maxLen) {
    const n = randInt(rng, (maxLen || 16) + 1);
    let s = "";
    for (let i = 0; i < n; i++) s += PRINTABLE[randInt(rng, PRINTABLE.length)];
    return s;
  }

  // ------------------------------------------------------------------ the fuzzer
  // mode: "random" (new random text every time), "mutate" (edit the seeds, never learn) or "guided" (keep what is new)
  function createFuzzer(opts) {
    opts = opts || {};
    const mode = opts.mode || "guided";
    const rng = mulberry32(opts.seed == null ? 1 : opts.seed);
    const bugs = opts.bugs || ["fuzz"];
    const dict = opts.dict || [];
    const maxLen = opts.maxLen || 48;
    const seeds = (opts.seeds && opts.seeds.length ? opts.seeds : [""]).slice();
    const stopOnCrash = opts.stopOnCrash !== false;
    const learn = mode === "guided" && opts.learn !== false; // trace comparisons, like libFuzzer's value profile or AFL++'s cmplog
    const maxRaw = opts.maxRawCrashes || 400;
    const st = {
      mode, tries: 0, learned: [], cov: new Set(), corpus: [], crashes: [], rawCrashes: 0, sites: {}, firstCrashAt: 0, firstCrash: null,
      history: [{ tries: 0, cov: 0 }], done: false, bugs
    };
    const histEvery = opts.histEvery || 50;

    function run(input) {
      const r = parseRecord(input, bugs);
      st.tries++;
      let fresh = [];
      r.cov.forEach((b) => { if (!st.cov.has(b)) { st.cov.add(b); fresh.push(b); } });
      if (learn) r.cmp.forEach((w) => { if (st.learned.indexOf(w) < 0) st.learned.push(w); });
      if (r.crash) {
        st.rawCrashes++;
        const site = r.crash.site;
        if (!st.sites[site]) { st.sites[site] = { site, bug: r.crash.id, kind: r.crash.kind, line: r.crash.line, count: 0, first: input, firstAt: st.tries, shortest: input }; }
        const sc = st.sites[site];
        sc.count++;
        if (input.length < sc.shortest.length) sc.shortest = input;
        if (st.crashes.length < maxRaw) st.crashes.push({ input, site, at: st.tries });
        if (!st.firstCrash) { st.firstCrash = { input, site, at: st.tries, crash: r.crash }; st.firstCrashAt = st.tries; }
      }
      if (st.tries % histEvery === 0) st.history.push({ tries: st.tries, cov: st.cov.size });
      return { r, fresh };
    }

    // seed the corpus (guided mode learns from the seeds first)
    if (mode === "guided") {
      seeds.forEach((s) => { const x = run(s); if (x.fresh.length || !st.corpus.length) st.corpus.push({ input: s, found: x.fresh.length, at: st.tries }); });
    } else if (mode === "mutate") {
      seeds.forEach((s) => run(s));
    }

    // one try; returns details the "loop" slide shows
    function stepOnce() {
      let input, parent = null, names = [];
      if (mode === "random") {
        input = randomInput(rng, 16);
        names = ["fresh random text"];
      } else if (mode === "mutate") {
        parent = pick(rng, seeds);
        input = blindMutate(rng, parent, { maxLen, dict });
        names = ["a few random edits"];
      } else {
        const others = st.corpus.map((c) => c.input);
        // favour the newest finds, as real fuzzers favour inputs that reached something rare
        const pool = st.corpus.length > 4 && rng() < 0.5 ? st.corpus.slice(-4) : st.corpus;
        parent = pool.length ? pick(rng, pool).input : "";
        const m = havoc(rng, parent, { maxLen, dict: learn ? dict.concat(st.learned) : dict, others });
        input = m.s; names = m.names;
      }
      const x = run(input);
      let kept = false;
      if (mode === "guided" && x.fresh.length) { st.corpus.push({ input, found: x.fresh.length, at: st.tries }); kept = true; }
      return { input, parent, names, fresh: x.fresh, kept, result: x.r };
    }

    function step(n) {
      for (let i = 0; i < n && !st.done; i++) {
        stepOnce();
        if (stopOnCrash && st.firstCrash) st.done = true;
      }
      if (!st.done && opts.maxTries && st.tries >= opts.maxTries) st.done = true;
      if (st.history[st.history.length - 1].tries !== st.tries) st.history.push({ tries: st.tries, cov: st.cov.size });
      return st;
    }
    return { state: st, step, stepOnce, run };
  }

  // run to a limit and report; handy for tests and benchmarks
  function runFuzz(opts, maxTries) {
    const f = createFuzzer(Object.assign({}, opts, { maxTries }));
    f.step(maxTries);
    return f.state;
  }

  function median(a) {
    const b = a.slice().sort((x, y) => x - y);
    const m = b.length >> 1;
    return b.length % 2 ? b[m] : (b[m - 1] + b[m]) / 2;
  }

  // how many tries to the first crash of one bug, over several seeds. null = not found within the limit.
  function triesToFind(bug, cfg, seedsList, limit) {
    const res = [];
    seedsList.forEach((sd) => {
      const st = runFuzz(Object.assign({ mode: "guided", bugs: [bug], seed: sd }, cfg), limit);
      res.push(st.firstCrashAt || null);
    });
    return res;
  }

  // seeds-and-dictionary benchmark: n runs with different random seeds, coverage-only learning (no comparison tracing)
  const BENCH_CONFIGS = [
    { id: "none", label: "No seed, no dictionary", cfg: {} },
    { id: "seed", label: "One valid seed", cfg: { seeds: ["REC2:hello;world"] } },
    { id: "dict", label: "Dictionary only", cfg: { dict: ["REC1:", "REC2:", ";", "FUZZ"] } },
    { id: "both", label: "Seed and dictionary", cfg: { seeds: ["REC2:hello;world"], dict: ["REC1:", "REC2:", ";", "FUZZ"] } }
  ];
  function benchOne(id, runSeed, limit) {
    const c = BENCH_CONFIGS.filter((b) => b.id === id)[0];
    const base = Object.assign({ mode: "guided", learn: false, bugs: ["fuzz"], seed: runSeed }, c.cfg);
    const st = runFuzz(base, limit);
    const early = runFuzz(Object.assign({}, base, { stopOnCrash: false }), 1000);
    return { found: st.firstCrashAt || 0, covAt1k: early.cov.size };
  }

  // ------------------------------------------------------------------ the minimiser (delta debugging, simplified)
  // fails(s) -> true while the input still triggers the same failure
  function minimize(input, fails, maxSteps) {
    maxSteps = maxSteps || 4000;
    const steps = [];
    let cur = input;
    let tests = 0;
    function test(cand, why) {
      tests++;
      const ok = cand.length < cur.length && fails(cand);
      steps.push({ n: tests, candidate: cand, kept: ok, why });
      if (ok) cur = cand;
      return ok;
    }
    let n = 2;
    while (cur.length >= 2 && tests < maxSteps) {
      const size = Math.ceil(cur.length / n);
      let reduced = false;
      for (let i = 0; i < cur.length && tests < maxSteps; i += size) {
        const cand = cur.slice(0, i) + cur.slice(i + size);
        if (test(cand, "cut " + Math.min(size, cur.length - i) + " at " + i)) { reduced = true; n = Math.max(n - 1, 2); break; }
      }
      if (!reduced) {
        if (n >= cur.length) break;
        n = Math.min(cur.length, n * 2);
      }
    }
    // then try removing single characters, and pairs of neighbours, until nothing more can go
    let changed = true;
    while (changed && tests < maxSteps) {
      changed = false;
      for (let w = 1; w <= 2 && !changed; w++) {
        for (let i = 0; i + w <= cur.length && tests < maxSteps; i++) {
          if (test(cur.slice(0, i) + cur.slice(i + w), "drop " + w + " at " + i)) { changed = true; break; }
        }
      }
    }
    return { result: cur, steps, tests, original: input };
  }

  // ------------------------------------------------------------------ the maths of "gates"
  // A gate is something an input has to get exactly right before the next part of the code is reached.
  // Toy model: random needs all gates at once; guided can learn them one at a time.
  function gateOdds(gates, alphabet, inputLen) {
    alphabet = alphabet || 95; inputLen = inputLen || 10;
    return {
      random: Math.pow(alphabet, gates),
      guided: gates * alphabet * inputLen
    };
  }
  function humanTime(seconds) {
    if (seconds < 1) return "under a second";
    if (seconds < 60) return Math.round(seconds) + " seconds";
    if (seconds < 3600) return Math.round(seconds / 60) + " minutes";
    if (seconds < 86400) return Math.round(seconds / 3600) + " hours";
    const days = seconds / 86400;
    if (days < 365) return Math.round(days) + " days";
    const years = days / 365.25;
    if (years < 1e6) return Math.round(years).toLocaleString("en-US") + " years";
    const exp = Math.floor(Math.log10(years));
    return (years / Math.pow(10, exp)).toFixed(1) + " × 10^" + exp + " years";
  }
  const AGE_OF_UNIVERSE_YEARS = 13.8e9;

  // ------------------------------------------------------------------ Base64 with an injectable bug, and a property test
  const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  function b64encode(bytes, bug) {
    let out = "";
    for (let i = 0; i < bytes.length; i += 3) {
      const rem = bytes.length - i;
      const b0 = bytes[i], b1 = rem > 1 ? bytes[i + 1] : 0, b2 = rem > 2 ? bytes[i + 2] : 0;
      let i0 = b0 >> 2;
      if (bug && rem === 1 && b0 >= 128) i0 = (b0 - 256) >> 2; // the planted bug: the byte is treated as signed, so the index goes negative
      const i1 = ((b0 & 3) << 4) | (b1 >> 4), i2 = ((b1 & 15) << 2) | (b2 >> 6), i3 = b2 & 63;
      out += (B64[i0] === undefined ? "?" : B64[i0]) + B64[i1] + (rem > 1 ? B64[i2] : "=") + (rem > 2 ? B64[i3] : "=");
    }
    return out;
  }
  function b64decode(str) {
    if (str.length % 4 !== 0) throw new Error("length is not a multiple of 4");
    const bytes = [];
    for (let i = 0; i < str.length; i += 4) {
      const c = str.slice(i, i + 4);
      const v = [];
      let pad = 0;
      for (let j = 0; j < 4; j++) {
        if (c[j] === "=") { pad++; v.push(0); continue; }
        const x = B64.indexOf(c[j]);
        if (x < 0) throw new Error("not a Base64 character: " + JSON.stringify(c[j]));
        v.push(x);
      }
      bytes.push((v[0] << 2) | (v[1] >> 4));
      if (pad < 2) bytes.push(((v[1] & 15) << 4) | (v[2] >> 2));
      if (pad < 1) bytes.push(((v[2] & 3) << 6) | v[3]);
    }
    return bytes;
  }
  const sameBytes = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
  function roundTrip(bytes, bug) {
    try {
      const enc = b64encode(bytes, bug);
      const dec = b64decode(enc);
      return { ok: sameBytes(bytes, dec), enc, dec, err: null };
    } catch (e) { return { ok: false, enc: b64encode(bytes, bug), dec: null, err: e.message }; }
  }
  // shrink a failing byte list: drop bytes, then try smaller values
  function shrinkBytes(bytes, bug) {
    let cur = bytes.slice();
    const fails = (b) => !roundTrip(b, bug).ok;
    let changed = true;
    while (changed) {
      changed = false;
      // delete runs of 1, 2 or 3 neighbours (the failure here depends on the length modulo 3)
      for (let w = 3; w >= 1 && !changed; w--) {
        for (let i = 0; i + w <= cur.length; i++) {
          const c = cur.slice(0, i).concat(cur.slice(i + w));
          if (fails(c)) { cur = c; changed = true; break; }
        }
      }
      if (changed) continue;
      for (let i = 0; i < cur.length && !changed; i++) {
        for (const v of [0, cur[i] >> 1, cur[i] - 1]) {
          if (v >= 0 && v < cur[i]) { const c = cur.slice(); c[i] = v; if (fails(c)) { cur = c; changed = true; break; } }
        }
      }
    }
    return cur;
  }
  const EXAMPLE_TESTS = [
    { name: "empty", bytes: [] },
    { name: "\"M\"", bytes: [77] },
    { name: "\"Ma\"", bytes: [77, 97] },
    { name: "\"Man\"", bytes: [77, 97, 110] },
    { name: "\"hello\"", bytes: [104, 101, 108, 108, 111] }
  ];
  // run the round-trip property on random byte lists until it fails
  function propertyTest(opts) {
    opts = opts || {};
    const rng = mulberry32(opts.seed == null ? 7 : opts.seed);
    const runs = opts.runs || 100, bug = !!opts.bug, maxLen = opts.maxLen || 12;
    for (let t = 1; t <= runs; t++) {
      const n = randInt(rng, maxLen + 1);
      const bytes = [];
      for (let i = 0; i < n; i++) bytes.push(randInt(rng, 256));
      const r = roundTrip(bytes, bug);
      if (!r.ok) return { passed: false, ran: t, found: bytes, enc: r.enc, err: r.err, shrunk: shrinkBytes(bytes, bug) };
    }
    return { passed: true, ran: runs };
  }
  const hexBytes = (b) => b.length ? b.map((x) => (x < 16 ? "0" : "") + x.toString(16)).join(" ") : "(no bytes)";

  // ------------------------------------------------------------------ structure-aware vs byte-level mutation
  // The target reads JSON, then runs an invented schema check; "deep" means the check got past parsing and shape.
  const JSON_SEED = { user: { name: "ada", age: 36 }, items: ["a", "b", "c"], active: true };
  function jsonTarget(text) {
    let v;
    try { v = JSON.parse(text); } catch (e) { return "syntax"; }
    if (!v || typeof v !== "object" || Array.isArray(v)) return "shape";
    if (!v.user || typeof v.user.name !== "string" || typeof v.user.age !== "number") return "shape";
    if (!Array.isArray(v.items)) return "shape";
    return "deep";
  }
  function mutateJsonTree(rng, v) {
    const c = JSON.parse(JSON.stringify(v));
    const k = randInt(rng, 6);
    if (k === 0) c.user.age = pick(rng, [0, -1, 2147483647, 1e9, 3.5, 36]);
    else if (k === 1) c.user.name = pick(rng, ["", "x".repeat(40), "ada", "\u00e9", "a b"]);
    else if (k === 2) c.items = c.items.concat(["z"]);
    else if (k === 3) c.items = c.items.slice(1);
    else if (k === 4) c.active = !c.active;
    else c.items = [];
    return c;
  }
  function structureDemo(seed, n) {
    const rng = mulberry32(seed || 3);
    const base = JSON.stringify(JSON_SEED);
    const count = { byte: { syntax: 0, shape: 0, deep: 0 }, tree: { syntax: 0, shape: 0, deep: 0 }, n };
    let sample = { byte: "", tree: "" };
    for (let i = 0; i < n; i++) {
      let s = base;
      const edits = 1 + randInt(rng, 6);
      for (let j = 0; j < edits; j++) s = mutateOnce(rng, s, { maxLen: 200 }).s;
      count.byte[jsonTarget(s)]++;
      if (i === 0) sample.byte = s;
      const t = JSON.stringify(mutateJsonTree(rng, JSON_SEED));
      count.tree[jsonTarget(t)]++;
      if (i === 0) sample.tree = t;
    }
    return { count, sample };
  }

  // ------------------------------------------------------------------ quiz data
  const HARNESS_OPTIONS = [
    { id: "good", label: "Looks good" },
    { id: "random", label: "Not deterministic" },
    { id: "io", label: "Slow: files or network" },
    { id: "swallow", label: "Hides real bugs" },
    { id: "state", label: "Keeps state between runs" },
    { id: "exit", label: "Ends the process" }
  ];
  const HARNESSES = [
    {
      id: "h1", lang: "C++ (libFuzzer)", answer: "good",
      code: "extern \"C\" int LLVMFuzzerTestOneInput(\n    const uint8_t *data, size_t size) {\n  parse_record(data, size);   // any bytes, any length\n  return 0;\n}",
      why: "One call, takes the raw bytes and their length, no side effects. The parser must cope with empty, huge and malformed input: that is the job."
    },
    {
      id: "h2", lang: "C++ (libFuzzer)", answer: "random",
      code: "extern \"C\" int LLVMFuzzerTestOneInput(\n    const uint8_t *data, size_t size) {\n  srand(time(nullptr));        // seed from the clock\n  if (rand() % 2) size /= 2;   // sometimes use half the input\n  parse_record(data, size);\n  return 0;\n}",
      why: "The same input behaves differently each run, so a crash may not reproduce and the coverage signal gets noisy. Everything should be a function of the input bytes (libFuzzer's docs: be as deterministic as possible)."
    },
    {
      id: "h3", lang: "Python (Atheris)", answer: "io",
      code: "def TestOneInput(data):\n    with open(\"/tmp/in.rec\", \"wb\") as f:\n        f.write(data)\n    parse_record_file(\"/tmp/in.rec\")      # reads it back\n    requests.post(AUDIT_URL, data=data)   # report what we saw",
      why: "Disk and network make each run slow and flaky. A fuzzer wants thousands of runs a second. Feed the bytes straight to the parser and stub out anything that touches the outside world."
    },
    {
      id: "h4", lang: "Python (Atheris)", answer: "swallow",
      code: "def TestOneInput(data):\n    try:\n        parse_record(data)\n    except Exception:\n        pass          # invalid input is fine, right?",
      why: "Catching every exception hides the very bugs you want. Catch only the errors the parser documents for bad input (a ValueError, say) and let everything else escape so the fuzzer sees it."
    },
    {
      id: "h5", lang: "Go (native fuzzing)", answer: "state",
      code: "var seen = map[string]bool{}\n\nfunc FuzzParse(f *testing.F) {\n  f.Fuzz(func(t *testing.T, data []byte) {\n    if seen[string(data)] { return }   // skip repeats\n    seen[string(data)] = true\n    ParseRecord(data)\n  })\n}",
      why: "The map grows forever and changes what later runs do, so results depend on history. Go's docs ask for no state that persists between calls, because targets run in parallel in any order."
    },
    {
      id: "h6", lang: "C++ (libFuzzer)", answer: "exit",
      code: "extern \"C\" int LLVMFuzzerTestOneInput(\n    const uint8_t *data, size_t size) {\n  if (!parse_record(data, size)) {\n    fprintf(stderr, \"bad record\\n\");\n    exit(1);     // give up on invalid input\n  }\n  return 0;\n}",
      why: "Invalid input is normal, not fatal. libFuzzer's docs say the target should never call exit(); report an error by returning, and keep logging out of the hot path."
    }
  ];

  const TARGETS = [
    { name: "A PNG or JPEG image decoder", good: true, why: "Untrusted bytes in, a complicated format, a long history of bugs. A classic fuzz target." },
    { name: "A JSON, XML or YAML parser", good: true, why: "Text from outside, lots of branches, one function to call." },
    { name: "A decompressor (zlib, gzip, zstd)", good: true, why: "Attacker-controlled bytes drive complex state. Fast, deterministic, pure. Ideal." },
    { name: "A parser for your network protocol's messages", good: true, why: "The bytes arrive from outside your trust boundary. Fuzz the parser, not the socket." },
    { name: "A date and time string parser", good: true, why: "Small, fast, many odd inputs, and easy to write a harness for." },
    { name: "A function that adds two integers", good: false, why: "Not worth a fuzzer: the input space is tiny and a unit or property test covers it. (Overflow checks belong in a sanitizer run or a property test.)" },
    { name: "The whole web server, over real sockets", good: false, why: "Slow, stateful and nondeterministic. Fuzz the request parser and the handlers with bytes in memory instead." },
    { name: "A function that checks a password against the database", good: false, why: "It needs a live database and holds state. Fuzz the input parsing in front of it, with the database stubbed." },
    { name: "A function that sends an email", good: false, why: "Side effects in the outside world. Fuzz the code that builds the message, not the sending." }
  ];

  const CHECKLIST = [
    "I know which functions read untrusted bytes, and I have a harness for the riskiest one",
    "Each harness is one function: fast, deterministic, no network, no disk, no exit()",
    "The harness catches only the errors that the parser documents for bad input",
    "There are seed inputs (valid and invalid) and, if the format has keywords, a dictionary",
    "I build with sanitizers (ASan and UBSan, or the language's runtime checks) for fuzz runs",
    "Pull requests run the saved corpus and a short fuzz run on the changed targets",
    "A longer run (nightly or a continuous service) builds the corpus and finds deep bugs",
    "Every crash is deduplicated, minimised, fixed and kept as a regression test",
    "I look at coverage over time and ask why a plateau happens",
    "Structured formats get a structure-aware mutator, or a harness that builds valid input from the bytes"
  ];

  return {
    mulberry32, parseRecord, BRANCHES, BUGS, BUG_IDS, DEFAULT_DICT, MUTATORS, mutateOnce, havoc, randomInput,
    createFuzzer, runFuzz, median, triesToFind, BENCH_CONFIGS, benchOne, minimize, gateOdds, humanTime, AGE_OF_UNIVERSE_YEARS,
    b64encode, b64decode, roundTrip, shrinkBytes, propertyTest, EXAMPLE_TESTS, hexBytes,
    structureDemo, jsonTarget, HARNESS_OPTIONS, HARNESSES, TARGETS, CHECKLIST
  };
});
