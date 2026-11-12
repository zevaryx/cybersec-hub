/* memory.js - the small models behind the demos in "Memory Safety".
   Everything here is a toy: a 24-cell memory with a first-fit allocator, a mitigation table, a tag-checking model,
   a fuzzer aimed at an invented parser, and an invented codebase. There is no real memory access and no exploit code.
   It runs in the browser (window.MemLab) and in Node (module.exports) so the logic can be tested. */
(function (root) {
  "use strict";

  // --------------------------------------------------------------------------- seeded random numbers (so demos repeat)
  function rng(seed) {
    let a = seed >>> 0;
    return function () {
      a = (a + 0x6d2b79f5) >>> 0;
      let t = a;
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }

  // --------------------------------------------------------------------------- title slide: copy a string into buf[8]
  const BUF = 8, NEIGH = 4, SHOWN = BUF + NEIGH;
  function copyInto(str) {
    const bytes = Array.from(new TextEncoder().encode(String(str)));
    bytes.push(0); // the terminating NUL that C strings carry
    const cells = [];
    for (let i = 0; i < BUF; i++) cells.push({ v: null, who: "buf" });
    const neigh = [3, 0, 0, 0];
    for (let i = 0; i < NEIGH; i++) cells.push({ v: neigh[i], who: "retries" + (i ? "+" + i : ""), orig: neigh[i] });
    let written = 0;
    for (let i = 0; i < bytes.length && i < SHOWN; i++) { cells[i].v = bytes[i]; cells[i].set = true; written++; }
    for (let i = BUF; i < SHOWN; i++) cells[i].hit = cells[i].set && cells[i].v !== cells[i].orig;
    const over = Math.max(0, bytes.length - BUF);
    return {
      bytes: bytes.length, cells, over, beyondPicture: Math.max(0, bytes.length - SHOWN),
      neighbourChanged: cells.slice(BUF).some((c) => c.hit),
      overwrote: cells.slice(BUF).some((c) => c.set), // wrote into the neighbour even if the value happened to match
      retries: cells[BUF].v
    };
  }
  function heroNote(str) {
    const s = String(str), low = s.trim().toLowerCase(), r = copyInto(s);
    if (low === "heartbleed") return { level: "y", text: "CVE-2014-0160. Nothing was copied wrongly: a length field was believed, and up to 64 KB of the neighbours came back." };
    if (low === "rust") return { level: "ok", text: "In Rust this is a compile error or a panic. Boring, and that is the goal." };
    if (low === "segfault") return { level: "y", text: "At least a segfault is loud. The quiet ones are worse." };
    if (low === "ub" || low === "undefined behaviour" || low === "undefined behavior") return { level: "y", text: "Undefined behaviour: in 1992 a newsgroup joke said the compiler may make demons fly out of your nose. The compiler really may do anything." };
    if (low === "hunter2") return { level: "ok", text: "The IRC classic. Seven letters and the NUL fill the buffer exactly: it fits, with no room to spare." };
    if (s === "") return { level: "ok", text: "An empty string still costs a byte: the NUL that ends it." };
    if (r.over === 0) return { level: "ok", text: "Fits: " + s.length + " byte" + (s.length === 1 ? "" : "s") + " plus the NUL is " + r.bytes + " of 8." };
    if (r.bytes === BUF + 1) return { level: "bad", text: "Exactly 8 characters, and it still overflows: the NUL is the 9th byte. The classic off-by-one." };
    if (r.neighbourChanged) return { level: "bad", text: "The copy ran on into the next variable and retries is now " + r.retries + ". No error, no crash." };
    return { level: "bad", text: "The copy ran past the end by " + r.over + " byte" + (r.over === 1 ? "" : "s") + ". Nothing in C stopped it." };
  }

  // --------------------------------------------------------------------------- the 24-cell heap and its scenarios
  const CELLS = 24;
  const KINDS = {
    oobw: { name: "Write past the end", short: "Out-of-bounds write", cwe: "CWE-787" },
    oobr: { name: "Read past the end", short: "Out-of-bounds read", cwe: "CWE-125" },
    uaf: { name: "Use after free", short: "Use after free", cwe: "CWE-416" },
    dfree: { name: "Free twice", short: "Double free", cwe: "CWE-415" },
    uninit: { name: "Read before write", short: "Uninitialised memory", cwe: "CWE-908" },
    type: { name: "Wrong type", short: "Type confusion", cwe: "CWE-843" }
  };
  const T = (s) => Array.from(s).map((c) => c.charCodeAt(0));

  const SCENARIOS = {
    oobw: {
      lesson: "Index 4 of a 4-element array is the first cell of its neighbour. The loop bound was <= where it should have been <.",
      code: ["int *scores = malloc(4 * sizeof *scores);", "int *limit  = malloc(sizeof *limit);   // lands next door", "*limit = 100;", "for (int i = 0; i <= 4; i++)       // off by one", "    scores[i] = (i + 1) * 10;"],
      ops: [
        { t: "alloc", p: "scores", n: 4, init: [0, 0, 0, 0], line: 0, say: "scores gets cells 0 to 3" },
        { t: "alloc", p: "limit", n: 1, init: [100], line: 1, say: "limit gets the very next cell, with value 100" },
        { t: "write", p: "scores", i: 0, v: 10, line: 4, say: "scores[0] = 10" },
        { t: "write", p: "scores", i: 1, v: 20, line: 4, say: "scores[1] = 20" },
        { t: "write", p: "scores", i: 2, v: 30, line: 4, say: "scores[2] = 30" },
        { t: "write", p: "scores", i: 3, v: 40, line: 4, say: "scores[3] = 40" },
        { t: "write", p: "scores", i: 4, v: 50, line: 4, say: "scores[4] = 50  (the array only has 0 to 3)" },
        { t: "read", p: "limit", i: 0, line: 2, say: "later, the code reads limit" }
      ]
    },
    oobr: {
      lesson: "A length that came from outside was believed. The reply copied 8 cells from a 4-cell message, so the neighbour's data went out with it.",
      code: ["char *msg    = malloc(4);   // \"ping\"", "char *secret = malloc(6);   // next door", "// request says: echo back 8 cells", "reply = copy(msg, 8);       // length was never checked"],
      ops: [
        { t: "alloc", p: "msg", n: 4, init: T("ping"), text: true, line: 0, say: "msg gets cells 0 to 3: \"ping\"" },
        { t: "alloc", p: "secret", n: 6, init: T("hunt3r"), text: true, line: 1, say: "secret gets the next cells" },
        { t: "readrange", p: "msg", from: 0, len: 8, line: 3, say: "the request says len = 8, so the reply copies 8 cells starting at msg" }
      ]
    },
    uaf: {
      lesson: "The pointer outlived the memory. Once the allocator handed the cells to someone else, the old pointer was reading their data.",
      code: ["session = malloc(2);   // user id, role", "p = session;           // a second pointer", "free(session);", "token = malloc(2);     // reuses the same cells", "use(p->user);          // p is stale"],
      ops: [
        { t: "alloc", p: "session", n: 2, init: [7, 1], line: 0, say: "session gets cells 0 and 1: user 7, role 1" },
        { t: "alias", p: "p", of: "session", line: 1, say: "p points at the same cells" },
        { t: "free", p: "session", line: 2, say: "session is freed. The cells keep their old values for now" },
        { t: "alloc", p: "token", n: 2, init: [91, 91], line: 3, say: "token is allocated and reuses cells 0 and 1" },
        { t: "read", p: "p", i: 0, line: 4, say: "the code reads p->user" }
      ]
    },
    dfree: {
      lesson: "The second free() released cells that now belonged to someone else. The allocator will hand them out again, so two owners share one place.",
      code: ["a = malloc(2);", "b = a;                 // an alias nobody remembers", "free(a);", "c = malloc(2);         // reuses a's cells", "free(b);               // second free of the same cells", "d = malloc(2);         // lands on c's cells too"],
      ops: [
        { t: "alloc", p: "a", n: 2, init: [1, 1], line: 0, say: "a gets cells 0 and 1" },
        { t: "alias", p: "b", of: "a", line: 1, say: "b points at the same cells" },
        { t: "free", p: "a", line: 2, say: "a is freed" },
        { t: "alloc", p: "c", n: 2, init: [5, 5], line: 3, say: "c is allocated on the same cells" },
        { t: "free", p: "b", line: 4, say: "b is freed: the same cells, a second time" },
        { t: "alloc", p: "d", n: 2, init: [9, 9], line: 5, say: "d is allocated: where does it go?" },
        { t: "write", p: "c", i: 0, v: 42, line: 5, say: "c writes 42 to its first cell. Who else sees it?" }
      ]
    },
    uninit: {
      lesson: "malloc does not clear memory. The new block still held the previous owner's values, and the code believed they were its own.",
      code: ["old = malloc(3);  // holds 'pw' bytes", "free(old);", "buf = malloc(3);  // same cells, never written", "send(buf[0]);     // reads whatever was there"],
      ops: [
        { t: "alloc", p: "old", n: 3, init: T("pw!"), text: true, line: 0, say: "old gets cells 0 to 2: the letters p, w and !" },
        { t: "free", p: "old", line: 1, say: "old is freed, and the letters stay where they were" },
        { t: "alloc", p: "buf", n: 3, line: 2, say: "buf is allocated on the same cells. Nothing writes to them" },
        { t: "read", p: "buf", i: 0, line: 3, say: "the code reads buf[0], expecting zero" }
      ]
    },
    type: {
      lesson: "The object was a Cat, but a pointer said Dog. The write used Dog's idea of the layout and changed a Cat field.",
      code: ["Cat *c = new Cat();        // [tag=1, lives=9]", "Dog *d = (Dog *)c;           // an unchecked cast", "d->volume = 200;            // Dog's field 1 is Cat's lives"],
      ops: [
        { t: "alloc", p: "cat", n: 2, init: [1, 9], type: "Cat", line: 0, say: "cat gets cells 0 and 1: tag 1, lives 9" },
        { t: "alias", p: "dog", of: "cat", as: "Dog", line: 1, say: "dog points at the same object, but is declared a Dog" },
        { t: "write", p: "dog", i: 1, v: 200, line: 2, say: "dog writes volume = 200 into field 1" }
      ]
    }
  };

  function freshState() {
    return { cells: Array.from({ length: CELLS }, () => ({ v: 0, st: "free", who: null, text: false, stale: false })), blocks: {}, ptrs: {}, nextId: 1 };
  }
  function snapshot(s) { return s.cells.map((c) => ({ v: c.v, st: c.st, who: c.who, text: c.text, stale: c.stale })); }

  function findSpot(s, n) {
    for (let a = 0; a + n <= CELLS; a++) {
      let ok = true;
      for (let k = 0; k < n; k++) if (s.cells[a + k].st === "live") { ok = false; break; }
      if (ok) return a;
    }
    return -1;
  }

  // run one scenario in "unchecked" (C-like) or "checked" (bounds, lifetime and type checks, zeroed allocations) mode
  function frames(kind, mode) {
    const sc = SCENARIOS[kind];
    if (!sc) throw new Error("unknown scenario " + kind);
    const checked = mode === "checked";
    const s = freshState();
    const out = [{ i: -1, cells: snapshot(s), kind: "start", text: "An empty heap: 24 cells, nothing allocated.", touched: [], fault: false, line: -1 }];
    let stopped = false;
    for (let oi = 0; oi < sc.ops.length; oi++) {
      const op = sc.ops[oi];
      if (stopped) break;
      const f = { i: oi, kind: "ok", text: op.say + ".", touched: [], fault: false, line: op.line, reply: null };
      if (op.t === "alloc") {
        const a = findSpot(s, op.n);
        const id = s.nextId++;
        s.blocks[id] = { id, name: op.p, start: a, n: op.n, state: "live", type: op.type || null, text: !!op.text };
        s.ptrs[op.p] = { id, type: op.type || null };
        for (let k = 0; k < op.n; k++) {
          const c = s.cells[a + k];
          c.st = "live"; c.who = op.p; c.text = op.init ? !!op.text : (checked ? false : c.text);
          if (op.init) { c.v = op.init[k]; c.stale = false; }
          else if (checked) { c.v = 0; c.stale = false; }
          else c.stale = true; // keeps whatever was there before
          f.touched.push(a + k);
        }
        f.text = op.say + (op.init || checked ? "." : ", and its cells are not cleared" + (s.cells[a].v ? ": they still hold the old values." : "."));
      } else if (op.t === "alias") {
        const base = s.ptrs[op.of];
        s.ptrs[op.p] = { id: base.id, type: op.as || base.type };
      } else if (op.t === "free") {
        const ptr = s.ptrs[op.p], b = s.blocks[ptr.id];
        if (b.state === "freed") {
          f.kind = "double";
          if (checked) { f.fault = true; f.text = op.say + ". FAULT: this block was already freed. A checking allocator stops the program here."; stopped = true; }
          else {
            // the allocator trusts the pointer, so whatever lives there now is released
            const victim = Object.values(s.blocks).find((x) => x.state === "live" && x.start === b.start);
            if (victim) {
              victim.state = "freed";
              for (let k = 0; k < victim.n; k++) { s.cells[victim.start + k].st = "freed"; f.touched.push(victim.start + k); }
              f.text = op.say + ". The cells now belong to " + victim.name + ", and " + victim.name + " is still using them. They are marked free anyway.";
            } else f.text = op.say + ". The free list now lists the same cells twice.";
          }
        } else {
          b.state = "freed";
          for (let k = 0; k < b.n; k++) { s.cells[b.start + k].st = "freed"; f.touched.push(b.start + k); }
        }
      } else if (op.t === "write" || op.t === "read") {
        const ptr = s.ptrs[op.p], b = s.blocks[ptr.id], idx = b.start + op.i;
        let viol = null;
        if (b.state === "freed") viol = "uaf";
        else if (op.i < 0 || op.i >= b.n) viol = "oob";
        else if (ptr.type && b.type && ptr.type !== b.type) viol = "type";
        const here = idx >= 0 && idx < CELLS ? s.cells[idx] : null;
        if (viol && checked) {
          f.kind = viol; f.fault = true; stopped = true; f.touched = here ? [idx] : [];
          const why = viol === "oob" ? "index " + op.i + " is outside " + b.name + " (length " + b.n + ")" : viol === "uaf" ? b.name + " was freed, so " + op.p + " is a dangling pointer" : op.p + " is declared " + ptr.type + " but the object is a " + b.type;
          f.text = op.say + ". FAULT: " + why + ". The check stops the program before anything is read or changed.";
        } else {
          if (viol) f.kind = viol;
          if (here) {
            f.touched = [idx];
            if (op.t === "write") { here.v = op.v; here.stale = false; }
            else if (here.stale && !viol) f.kind = "uninit";
            const owner = here.who && here.who !== op.p ? here.who : null;
            if (op.t === "write" && viol === "oob") f.text = op.say + ". It lands in " + (owner ? owner + "'s cell: " + owner + " is now " + here.v : "a cell nobody owns") + ". No error.";
            else if (op.t === "write" && viol === "type") f.text = op.say + ". Cat's lives field is now " + here.v + ". No error.";
            else if (op.t === "write" && viol === "uaf") f.text = op.say + ". " + (owner ? "The cell now belongs to " + owner + ", and " + owner + "'s data just changed under it." : "The cells may belong to someone else by now.") + " No error.";
            else if (op.t === "read") {
              if (viol === "uaf") f.text = op.say + ". It reads " + here.v + ", which is " + (here.who && here.who !== b.name ? here.who + "'s data, not session's." : "whatever is there.");
              else if (f.kind === "uninit") f.text = op.say + ". It reads " + (here.text ? "'" + String.fromCharCode(here.v) + "'" : here.v) + ": leftover data from the previous owner, not zero.";
              else f.text = op.say + ". It reads " + here.v + (b.name === "limit" ? ": limit is no longer 100." : ".");
            }
          }
        }
      } else if (op.t === "readrange") {
        const ptr = s.ptrs[op.p], b = s.blocks[ptr.id];
        const reply = []; let bad = false;
        for (let k = 0; k < op.len; k++) {
          const idx = b.start + op.from + k;
          if (op.from + k >= b.n) {
            if (checked) { f.kind = "oob"; f.fault = true; stopped = true; f.text = op.say + ". FAULT at index " + (op.from + k) + ": " + b.name + " has only " + b.n + " cells. The copy is refused, so the reply is empty."; break; }
            bad = true;
          }
          const c = s.cells[idx];
          reply.push({ v: c.v, text: c.text, foreign: op.from + k >= b.n, who: c.who });
          f.touched.push(idx);
        }
        if (!f.fault) {
          f.reply = reply;
          if (bad) { f.kind = "oob"; f.text = op.say + ". The reply carries " + reply.filter((r) => r.foreign).length + " cells that were never part of msg."; }
        }
      }
      f.cells = snapshot(s);
      out.push(f);
    }
    return out;
  }

  // --------------------------------------------------------------------------- mitigations: what each does to a bug that exists
  const BUG_ORDER = ["oobw", "oobr", "uaf", "dfree", "uninit", "type"];
  const RATING = ["doesn't help", "makes it harder to use", "catches the bug"];
  const MITS = [
    { id: "canary", label: "Stack canary", what: "A guard value next to a function's return address, checked when the function returns.", r: [1, 0, 0, 0, 0, 0], limit: "Only some stack overwrites, and only when the function returns. Heap bugs and reads walk past it." },
    { id: "aslr", label: "ASLR", what: "Randomises where code, stack and heap sit in memory.", r: [1, 1, 1, 1, 1, 1], limit: "It hides addresses; it detects nothing. Any bug that leaks an address (a read past the end, say) can undo it." },
    { id: "nx", label: "NX / DEP", what: "Marks data pages as non-executable, so bytes written as data can't simply run as code.", r: [1, 0, 1, 1, 0, 1], limit: "Does nothing for a bug that only reads or corrupts data, which is most of them." },
    { id: "cfi", label: "Control-flow integrity", what: "Checks that an indirect call or return goes somewhere the program could legitimately go.", r: [1, 0, 1, 1, 0, 1], limit: "Limits where a corrupted pointer can send execution. The data corruption itself still happens." },
    { id: "alloc", label: "Hardened allocator", what: "Guard pages, delayed reuse of freed memory, checks on free, randomised placement.", r: [1, 1, 1, 2, 1, 1], limit: "Catches a lot of double frees and some stale uses. Catches an overflow inside an allocation not at all." },
    { id: "mte", label: "Memory tagging", what: "Hardware tags on memory and pointers; a mismatch on access stops the program.", r: [2, 2, 2, 2, 0, 1], limit: "Tags are small, so some mistakes slip through by chance. Misses overflows inside one 16-byte granule, and uninitialised data." },
    { id: "bounds", label: "Bounds-checked library", what: "Containers and spans that check the index (for example a hardened standard library).", r: [2, 2, 0, 0, 0, 0], limit: "Protects only code that uses them. Raw pointers still do whatever they like." },
    { id: "zero", label: "Zero-initialisation", what: "A compiler option that fills variables with zero instead of leaving leftovers.", r: [0, 0, 0, 0, 2, 0], limit: "Fixes one class, and only for variables the compiler initialises. Heap memory from malloc is a separate matter." }
  ];
  function mitigationsFor(bug) {
    const i = BUG_ORDER.indexOf(bug);
    if (i < 0) throw new Error("unknown bug " + bug);
    return MITS.map((m) => ({ id: m.id, label: m.label, what: m.what, limit: m.limit, rating: m.r[i] }));
  }
  // "same bug, different protection": rating 2 stops it at the bad access; 0 and 1 leave the corruption in place
  const PROTECTIONS = [{ id: "none", label: "None", mit: null }, { id: "aslr", label: "ASLR + NX", mit: "aslr" }, { id: "canary", label: "Stack canary", mit: "canary" }, { id: "alloc", label: "Hardened allocator", mit: "alloc" }, { id: "mte", label: "Memory tagging", mit: "mte" }, { id: "safe", label: "Checked language", mit: null, safe: true }];
  function outcome(bug, protectionId) {
    const p = PROTECTIONS.find((x) => x.id === protectionId);
    if (!p) throw new Error("unknown protection " + protectionId);
    let rating = 0;
    if (p.safe) rating = 2;
    else if (p.mit) rating = MITS.find((m) => m.id === p.mit).r[BUG_ORDER.indexOf(bug)];
    const mode = rating === 2 ? "checked" : "unchecked";
    return { rating, mode, label: RATING[rating], frames: frames(bug, mode) };
  }

  // --------------------------------------------------------------------------- memory tagging model
  function tagModel(seed, bits) {
    const r = rng(seed), mod = 1 << bits;
    const memTag = [];
    const allocs = {};
    let next = 0;
    function alloc(name, granules) {
      const start = next; next += granules;
      let t;
      do { t = Math.floor(r() * mod); } while (memTag.length && t === memTag[start - 1] && mod > 1); // neighbours get different tags
      for (let g = 0; g < granules; g++) memTag[start + g] = t;
      allocs[name] = { name, start, n: granules, tag: t, freed: false };
      return allocs[name];
    }
    function access(ptr, granuleOffset) {
      const g = ptr.start + granuleOffset;
      if (g < 0 || g >= memTag.length) return { ok: false, why: "outside the heap" };
      const m = memTag[g];
      return m === ptr.tag ? { ok: true, memTag: m } : { ok: false, memTag: m, ptrTag: ptr.tag };
    }
    function free(name) {
      const a = allocs[name]; a.freed = true;
      const t = Math.floor(r() * mod); // a fresh random tag: by chance it can equal the old one
      for (let g = 0; g < a.n; g++) memTag[a.start + g] = t; // retag on free: may by chance equal the old tag
      return t;
    }
    return { alloc, access, free, memTag, allocs, rand: r };
  }
  // how often does a stale pointer still match after the memory is retagged at random?
  function uafTrials(seed, bits, n) {
    const r = rng(seed), mod = 1 << bits;
    let miss = 0;
    for (let k = 0; k < n; k++) {
      const oldTag = Math.floor(r() * mod), newTag = Math.floor(r() * mod);
      if (oldTag === newTag) miss++;
    }
    return { trials: n, missed: miss, caught: n - miss, expected: 1 / mod };
  }

  // --------------------------------------------------------------------------- an invented parser, a random fuzzer and a coverage-guided one
  const BUFLEN = 8;
  // record format: 'R', version byte (must be 2), length, then <length> bytes copied into an 8-cell buffer.
  // the length check is written <= 16, the buffer has 8 cells: that is the planted bug.
  function parse(bytes) {
    const cov = new Set(["entry"]);
    if (bytes.length < 3) { cov.add("short"); return { cov, crash: null }; }
    if (bytes[0] !== 0x52) { cov.add("bad-magic"); return { cov, crash: null }; }
    cov.add("magic-ok");
    if (bytes[1] !== 2) { cov.add("bad-version"); return { cov, crash: null }; }
    cov.add("version-ok");
    const len = bytes[2];
    if (len > 16) { cov.add("too-long"); return { cov, crash: null }; }
    cov.add("len-ok");
    if (len > bytes.length - 3) { cov.add("truncated"); return { cov, crash: null }; }
    cov.add("copy");
    if (len > BUFLEN) { cov.add("overflow"); return { cov, crash: "out-of-bounds write of " + (len - BUFLEN) + " cell" + (len - BUFLEN === 1 ? "" : "s") + " (buffer holds " + BUFLEN + ")" }; }
    return { cov, crash: null };
  }
  const hex = (b) => Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join(" ");
  function randomBytes(r) { const n = 1 + Math.floor(r() * 20), b = []; for (let i = 0; i < n; i++) b.push(Math.floor(r() * 256)); return b; }
  function mutateOnce(r, src) {
    const b = src.slice(), kind = Math.floor(r() * 4);
    if (!b.length) return [Math.floor(r() * 256)];
    if (kind === 0) b[Math.floor(r() * b.length)] = Math.floor(r() * 256);
    else if (kind === 1) b[Math.floor(r() * b.length)] ^= 1 << Math.floor(r() * 8);
    else if (kind === 2 && b.length < 24) b.splice(Math.floor(r() * (b.length + 1)), 0, Math.floor(r() * 256));
    else if (b.length > 1) b.splice(Math.floor(r() * b.length), 1);
    return b;
  }
  // like real fuzzers, stack a handful of small changes per try
  function mutate(r, src) { let b = src; const k = 1 + Math.floor(r() * 8); for (let i = 0; i < k; i++) b = mutateOnce(r, b); return b; }
  const SEED_INPUT = [0x52, 0x02, 0x06, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66]; // a well-formed record: magic, version 2, length 6, six bytes
  function fuzz(mode, seed, maxExecs) {
    const r = rng(seed), seen = new Set(), corpus = [SEED_INPUT.slice()];
    for (const c of parse(SEED_INPUT).cov) seen.add(c); // running the seed counts as the first coverage
    const log = [];
    for (let n = 1; n <= maxExecs; n++) {
      let input;
      if (mode === "random") input = randomBytes(r);
      else input = mutate(r, corpus[Math.floor(r() * corpus.length)]);
      const res = parse(input);
      let fresh = false;
      for (const c of res.cov) if (!seen.has(c)) { seen.add(c); fresh = true; log.push({ exec: n, branch: c }); }
      if (res.crash) return { found: true, execs: n, input, hex: hex(input), crash: res.crash, coverage: seen.size, corpus: corpus.length + (fresh ? 1 : 0), log };
      if (mode === "guided" && fresh) corpus.push(input);
    }
    return { found: false, execs: maxExecs, input: null, hex: "", coverage: seen.size, corpus: corpus.length, log };
  }
  const BRANCHES = ["entry", "short", "bad-magic", "magic-ok", "bad-version", "version-ok", "too-long", "len-ok", "truncated", "copy", "overflow"];

  // --------------------------------------------------------------------------- where to start: an invented C++ codebase
  // exposure: how much untrusted input reaches it (0-3). history: past memory-safety bugs (0-3). size: thousand lines.
  const COMPONENTS = [
    { id: "imgparse", name: "Image decoder", note: "Parses files from any website or email.", exposure: 3, history: 3, kloc: 30 },
    { id: "netproto", name: "Network protocol handler", note: "Reads packets from the open internet.", exposure: 3, history: 2, kloc: 45 },
    { id: "fontrender", name: "Font and text shaping", note: "Handles fonts embedded in documents.", exposure: 2, history: 2, kloc: 60 },
    { id: "crypto", name: "Crypto routines", note: "Small, carefully reviewed, handles keys.", exposure: 1, history: 0, kloc: 8 },
    { id: "config", name: "Config file reader", note: "Reads a file only the admin can write.", exposure: 0, history: 1, kloc: 4 },
    { id: "ui", name: "Settings UI", note: "Buttons and dialogs for the signed-in user.", exposure: 0, history: 0, kloc: 120 },
    { id: "logger", name: "Logging library", note: "Formats strings from many callers.", exposure: 1, history: 1, kloc: 6 },
    { id: "driver", name: "Device driver shim", note: "Talks to hardware; input comes from a device.", exposure: 2, history: 1, kloc: 25 }
  ];
  // priority: exposure counts double, history once, small components are cheaper to move (a mild bonus)
  function priority(c) { return c.exposure * 2 + c.history + (c.kloc <= 10 ? 1 : 0); }
  function scorePicks(ids) {
    const comps = COMPONENTS.slice().sort((a, b) => priority(b) - priority(a) || a.id.localeCompare(b.id));
    const best = comps.slice(0, 3).reduce((s, c) => s + priority(c), 0);
    const picked = ids.map((id) => COMPONENTS.find((c) => c.id === id)).filter(Boolean);
    const got = picked.reduce((s, c) => s + priority(c), 0);
    return { got, best, bestIds: comps.slice(0, 3).map((c) => c.id), perfect: got === best && picked.length === 3 };
  }

  const api = { rng, BUF, NEIGH, SHOWN, copyInto, heroNote, CELLS, KINDS, SCENARIOS, frames, BUG_ORDER, RATING, MITS, mitigationsFor, PROTECTIONS, outcome, tagModel, uafTrials, BUFLEN, parse, fuzz, BRANCHES, SEED_INPUT, hex, COMPONENTS, priority, scorePicks };
  if (typeof module !== "undefined" && module.exports) module.exports = api; else root.MemLab = api;
})(typeof window !== "undefined" ? window : globalThis);
