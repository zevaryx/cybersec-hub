/* app.js - the live demos for "Memory Safety".
   Every demo is a simulation in this page, built on the small models in memory.js: a toy heap with a first-fit allocator,
   a mitigation table, a tag-checking model, a fuzzer aimed at an invented parser and an invented codebase.
   The sanitizer and compiler outputs on the slides are captured text from small test programs. Nothing is fetched or sent anywhere,
   and nothing here touches real memory. */
(function () {
  "use strict";
  const M = window.MemLab;

  // --------------------------------------------------------------------------- helpers
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const click = (id, fn) => $(id).addEventListener("click", fn);
  function store(key, val) {
    try { if (val === undefined) return localStorage.getItem(key); localStorage.setItem(key, val); } catch (e) {}
    return null;
  }
  const setPressed = (id, attr, val) => { for (const b of $(id).querySelectorAll("button")) b.setAttribute("aria-pressed", String(b.getAttribute(attr) === String(val))); };
  const verdict = (id, cls, text) => { const el = $(id); el.className = "verdict" + (cls ? " " + cls : ""); el.textContent = text; };
  const note = (id, text, cls) => { const el = $(id); el.className = "comment" + (cls ? " " + cls : ""); el.textContent = text; };
  const pips = (n) => "●".repeat(n + 1) + "○".repeat(2 - n);

  // show a cell value: text cells as characters, others as numbers
  function cellText(c) {
    if (c.st === "free" && !c.v) return "·";
    if (c.text && c.v >= 32 && c.v < 127) return String.fromCharCode(c.v);
    return String(c.v);
  }
  const OWNER_CLASSES = 4;
  function renderGrid(el, frame, owners) {
    const idx = (w) => { const i = owners.indexOf(w); return i < 0 ? 0 : i % OWNER_CLASSES; };
    el.innerHTML = frame.cells.map((c, i) => {
      const cls = ["mem-cell", "st-" + c.st];
      if (c.who) cls.push("o" + idx(c.who));
      if (frame.touched && frame.touched.indexOf(i) >= 0) cls.push(frame.kind === "ok" ? "touch" : "touch bad");
      const label = c.who ? c.who : c.st === "free" ? "free" : "";
      return `<div class="${cls.join(" ")}" title="cell ${i}${label ? ": " + esc(label) : ""}"><span class="mc-v">${esc(cellText(c))}</span><small>${esc(label)}</small></div>`;
    }).join("");
  }
  function renderKey(el, owners) {
    el.innerHTML = owners.map((w, i) => `<span><i class="o${i % OWNER_CLASSES}"></i>${esc(w)}</span>`).join("") + `<span><i class="k-free"></i>freed, old values still there</span>`;
  }
  function ownersOf(kind) {
    const out = [];
    for (const op of M.SCENARIOS[kind].ops) if (op.t === "alloc" && out.indexOf(op.p) < 0) out.push(op.p);
    return out;
  }

  // --------------------------------------------------------------------------- title: copy into buf[8]
  function hero() {
    const el = $("hero-in"), v = el.value;
    el.style.width = Math.min(22, Math.max(6, v.length + 1)) + "ch";
    const r = M.copyInto(v);
    const show = (c) => {
      if (c.v === null) return "·";
      if (c.v === 0) return "\\0";
      if (c.v >= 32 && c.v < 127) return String.fromCharCode(c.v);
      return c.v.toString(16).padStart(2, "0");
    };
    $("hero-cells").innerHTML = r.cells.map((c, i) => {
      const cls = ["hc", i < M.BUF ? "k-buf" : "k-ne"];
      if (c.hit) cls.push("k-hit");
      return `<div class="${cls.join(" ")}"><b>${esc(i < M.BUF ? show(c) : (c.set ? show(c) : c.v))}</b><small>${i < M.BUF ? i : "r" + (i - M.BUF)}</small></div>`;
    }).join("");
    const n = M.heroNote(v);
    const extra = r.beyondPicture ? ` (and ${r.beyondPicture} more byte${r.beyondPicture === 1 ? "" : "s"} past the end of this picture)` : "";
    const el2 = $("hero-note"); el2.className = "comment " + n.level; el2.textContent = "# " + n.text + extra;
  }

  // --------------------------------------------------------------------------- the toy heap: six bugs, step by step
  const MS = { kind: "oobw", mode: "unchecked", step: 0, frames: null };
  const msDone = { unchecked: new Set(), checked: new Set() };
  function msLoad() { MS.frames = M.frames(MS.kind, MS.mode); MS.step = 0; msRender(); }
  function msRender() {
    const f = MS.frames[MS.step], sc = M.SCENARIOS[MS.kind], owners = ownersOf(MS.kind);
    renderGrid($("ms-grid"), f, owners);
    renderKey($("ms-key"), owners);
    $("ms-code").innerHTML = sc.code.map((l, i) => `<span class="cl${i === f.line ? " cur" : ""}">${esc(l)}</span>`).join("");
    const last = MS.step === MS.frames.length - 1;
    const hurt = MS.frames.slice(0, MS.step + 1).some((x) => x.kind !== "ok" && x.kind !== "start" && !x.fault);
    const cls = f.fault ? "ok" : hurt ? "bad" : "";
    verdict("ms-text", cls, (f.i >= 0 ? "Step " + (f.i + 1) + ": " : "") + f.text);
    const rep = $("ms-reply");
    if (f.reply) {
      rep.innerHTML = "reply = " + f.reply.map((r) => `<span class="${r.foreign ? "rf" : ""}">${esc(r.text ? String.fromCharCode(r.v) : r.v)}</span>`).join("");
    } else rep.textContent = "";
    $("ms-step").disabled = last;
    const k = M.KINDS[MS.kind];
    if (last) {
      msDone[MS.mode].add(MS.kind);
      let msg = "# " + k.short + " (" + k.cwe + "). " + sc.lesson;
      let c = "";
      if (MS.mode === "unchecked" && MS.kind === "dfree") { msg += " The allocator is not amused."; }
      if (msDone.unchecked.size === 6) { msg = "# Six ways to corrupt memory, and not one compiler error between them. Now try them all in Checked mode."; c = "y"; }
      if (msDone.checked.size === 6) { msg = "# Six bugs, six stops, zero silent corruptions. That is a good day."; c = "ok"; }
      note("ms-note", msg, c);
    } else note("ms-note", "# " + k.short + " (" + k.cwe + "). Press Step to run the next line. Cells are not bytes: this is a teaching model.");
  }
  function heap() {
    const pick = $("ms-pick");
    pick.innerHTML = M.BUG_ORDER.map((k) => `<button type="button" data-b="${k}" aria-pressed="${k === MS.kind}">${esc(M.KINDS[k].name)}</button>`).join("");
    pick.addEventListener("click", (e) => {
      const b = e.target.closest("button[data-b]"); if (!b) return;
      MS.kind = b.dataset.b; setPressed("ms-pick", "data-b", MS.kind); msLoad();
    });
    $("ms-mode").addEventListener("click", (e) => {
      const b = e.target.closest("button[data-m]"); if (!b) return;
      MS.mode = b.dataset.m; setPressed("ms-mode", "data-m", MS.mode); msLoad();
    });
    click("ms-step", () => { if (MS.step < MS.frames.length - 1) { MS.step++; msRender(); } });
    click("ms-run", () => { MS.step = MS.frames.length - 1; msRender(); });
    click("ms-reset", () => { MS.step = 0; msRender(); });
    msLoad();
  }

  // --------------------------------------------------------------------------- the careful-reviewer quiz
  const SNIPPETS = [
    { code: "char name[8];\nstrcpy(name, user_input);", a: "spatial", why: "strcpy doesn't know how big name is, so any input longer than 7 characters runs past the end." },
    { code: "int *a = calloc(n, sizeof *a);\nif (!a) return;\nfor (size_t i = 0; i < n; i++)\n    a[i] = i;", a: "fine", why: "The loop stops at n, the allocation holds n elements, the result is checked, and calloc checks the multiplication. Nothing wrong here." },
    { code: "char *p = get_name();\nfree(p);\nlog_line(\"name=%s\", p);", a: "temporal", why: "p was freed on the line before. Reading it afterwards is a use after free." },
    { code: "int total;\nfor (int i = 0; i < n; i++)\n    total += x[i];", a: "uninit", why: "total starts with whatever the variable's memory happened to hold. Add = 0." },
    { code: "std::vector<int> v = {1, 2, 3};\nint &first = v[0];\nv.push_back(4);\nuse(first);", a: "temporal", why: "push_back may reallocate and move the elements. first still refers to the old storage, which was freed." },
    { code: "if (len <= sizeof buf)\n    memcpy(buf, src, len);", a: "fine", why: "The length is checked against the destination size before the copy (assuming buf is an array here, not a pointer)." }
  ];
  const LABEL = { fine: "fine", spatial: "an out-of-bounds bug", temporal: "a lifetime bug", uninit: "an uninitialised read" };
  function quiz() {
    let i = 0, score = 0, answered = false;
    function show() {
      const s = SNIPPETS[i];
      $("cq-n").textContent = "Snippet " + (i + 1) + " of " + SNIPPETS.length;
      $("cq-code").textContent = s.code;
      verdict("cq-fb", "", "");
      for (const b of $("cq-opts").querySelectorAll("button")) b.disabled = false;
      $("cq-next").disabled = true; answered = false;
      $("cq-score").textContent = "score " + score + " of " + i;
      $("cq-next").textContent = i === SNIPPETS.length - 1 ? "Finish" : "Next snippet ▸";
    }
    $("cq-opts").addEventListener("click", (e) => {
      const b = e.target.closest("button[data-a]"); if (!b || answered) return;
      answered = true;
      const s = SNIPPETS[i], right = b.dataset.a === s.a;
      if (right) score++;
      verdict("cq-fb", right ? "ok" : "bad", (right ? "Right: " : "Not quite: this is " + LABEL[s.a] + ". ") + s.why);
      for (const x of $("cq-opts").querySelectorAll("button")) x.disabled = true;
      $("cq-next").disabled = false;
      $("cq-score").textContent = "score " + score + " of " + (i + 1);
    });
    click("cq-next", () => {
      if (i < SNIPPETS.length - 1) { i++; show(); return; }
      verdict("cq-fb", score === SNIPPETS.length ? "ok" : "y", score === SNIPPETS.length ? "6 of 6. Now do it at ten million lines, on a Friday, after a long week." : score + " of " + SNIPPETS.length + ". Two were fine and four weren't, and they all looked reasonable. That is the problem.");
      $("cq-next").textContent = "Start again"; $("cq-next").disabled = false;
      $("cq-next").onclick = () => { i = 0; score = 0; $("cq-next").onclick = null; show(); };
    });
    show();
  }

  // --------------------------------------------------------------------------- the mitigation stack
  const BUG_LESSON = {
    oobw: "Only checks on the access itself (tagging, bounds-checked code) catch an overflow. The rest assume it happens and try to limit what comes next.",
    oobr: "A read past the end changes nothing, so defences for writes and control flow have nothing to catch. And what it reads can undo ASLR.",
    uaf: "The stale pointer looks perfectly valid. Delayed reuse and tagging help; most others only limit what can be built on it.",
    dfree: "The allocator can see that a block is already free. That's why allocator checks are the natural defence here.",
    uninit: "Nothing guards a read of leftover data except initialising it. Zero-initialisation removes the class; the others are blind to it.",
    type: "A mismatched cast often stays inside the object, so memory checks see nothing wrong. Type-aware allocators and type-safe languages are the answers."
  };
  function mitigations() {
    let bug = "oobw", sel = null;
    const pick = $("mi-pick");
    pick.innerHTML = M.BUG_ORDER.map((k) => `<button type="button" data-b="${k}" aria-pressed="${k === bug}">${esc(M.KINDS[k].short)}</button>`).join("");
    function render() {
      setPressed("mi-pick", "data-b", bug);
      const rows = M.mitigationsFor(bug);
      $("mi-grid").innerHTML = rows.map((r) => `<li class="r${r.rating}"><button type="button" class="mi-row${sel === r.id ? " sel" : ""}" data-id="${r.id}"><span>${esc(r.label)}</span><span class="tm-pips">${pips(r.rating)}<small>${esc(M.RATING[r.rating])}</small></span></button></li>`).join("");
      $("mi-lesson").textContent = BUG_LESSON[bug];
      const m = rows.find((r) => r.id === sel);
      $("mi-detail").textContent = m ? m.label + ": " + m.what + " Where it stops: " + m.limit : "Click a row to see what the mitigation does and where it stops.";
      note("mi-note", "# the dots are a rule of thumb, not a measurement.");
    }
    pick.addEventListener("click", (e) => { const b = e.target.closest("button[data-b]"); if (!b) return; bug = b.dataset.b; render(); });
    $("mi-grid").addEventListener("click", (e) => { const b = e.target.closest("button[data-id]"); if (!b) return; sel = b.dataset.id; render(); });
    render();
  }

  // --------------------------------------------------------------------------- same bug, different shields
  function sameBug() {
    const bugs = ["oobw", "uaf", "dfree", "uninit"];
    let bug = "oobw", prot = "none";
    $("sb-bug").innerHTML = bugs.map((k) => `<button type="button" data-b="${k}" aria-pressed="${k === bug}">${esc(M.KINDS[k].short)}</button>`).join("");
    $("sb-prot").innerHTML = M.PROTECTIONS.map((p) => `<button type="button" data-p="${p.id}" aria-pressed="${p.id === prot}">${esc(p.label)}</button>`).join("");
    function render() {
      setPressed("sb-bug", "data-b", bug); setPressed("sb-prot", "data-p", prot);
      const o = M.outcome(bug, prot), f = o.frames[o.frames.length - 1], owners = ownersOf(bug);
      renderGrid($("sb-grid"), f, owners); renderKey($("sb-key"), owners);
      if (o.rating === 2) verdict("sb-verdict", "ok", "Stopped at the bad access: " + o.label + ".");
      else if (o.rating === 1) verdict("sb-verdict", "bad", "Still corrupted: this protection " + o.label + ", it doesn't stop it.");
      else verdict("sb-verdict", "bad", "Nothing notices: this protection " + o.label + " for this bug.");
      note("sb-text", "# " + f.text);
    }
    $("sb-bug").addEventListener("click", (e) => { const b = e.target.closest("button[data-b]"); if (!b) return; bug = b.dataset.b; render(); });
    $("sb-prot").addEventListener("click", (e) => { const b = e.target.closest("button[data-p]"); if (!b) return; prot = b.dataset.p; render(); });
    render();
  }

  // --------------------------------------------------------------------------- memory tagging
  function tagging() {
    let bits = 4, freeCount = 0, model = null, A = null, freed = false, newTag = null;
    const hex = (n) => n.toString(16).toUpperCase();
    function fresh(seed) {
      model = M.tagModel(seed, bits);
      A = model.alloc("A", 2); model.alloc("B", 2); model.alloc("C", 1);
      freed = false; newTag = null;
    }
    function heapView(mark) {
      const owners = ["A", "A", "B", "B", "C"];
      $("tg-heap").innerHTML = model.memTag.map((t, g) => {
        const own = owners[g], cls = ["tg-g", "o" + "ABC".indexOf(own)];
        if (freed && own === "A") cls.push("freed");
        if (mark === g) cls.push("hit");
        return `<div class="${cls.join(" ")}"><b>${esc(own)}${freed && own === "A" ? " (freed)" : ""}</b><span>memory tag ${hex(t)}</span>${own === "A" ? `<small>pointer A has tag ${hex(A.tag)}</small>` : ""}</div>`;
      }).join("");
    }
    function act(a) {
      fresh(bits * 1000 + (a === "free" ? ++freeCount : 3));
      let mark = null;
      if (a === "own") {
        const r = model.access(A, 0); mark = 0;
        verdict("tg-verdict", "ok", "Allowed: the pointer's tag " + hex(A.tag) + " matches the memory's tag " + hex(r.memTag) + ".");
        note("tg-note", "# the normal case: tags agree, and the access costs almost nothing.");
      } else if (a === "past") {
        const r = model.access(A, 2); mark = 2;
        verdict("tg-verdict", r.ok ? "bad" : "ok", r.ok ? "Allowed by chance: the tags matched." : "Stopped: the pointer says " + hex(r.ptrTag) + " but that memory (B's) is tagged " + hex(r.memTag) + ".");
        note("tg-note", "# a write or read one granule past the end lands in someone else's memory, which has a different tag.");
      } else if (a === "free") {
        const old = A.tag; newTag = model.free("A"); freed = true; mark = 0;
        const r = model.access(A, 0);
        if (r.ok) {
          verdict("tg-verdict", "bad", "Missed, by chance: the memory was retagged " + hex(newTag) + ", and that happens to equal the old tag " + hex(old) + ", so the stale pointer matched.");
          note("tg-note", "# the odds were 1 in " + (1 << bits) + " with " + bits + "-bit tags. Click again for another draw.");
        } else {
          verdict("tg-verdict", "ok", "Stopped: freeing retagged the memory " + hex(newTag) + ", and the old pointer still carries " + hex(old) + ".");
          note("tg-note", "# usually caught. The chance of a match is 1 in " + (1 << bits) + ". Click again for another draw.");
        }
      } else {
        verdict("tg-verdict", "bad", "Not seen: the 3 extra bytes land inside the same 16-byte granule, so the tag matches.");
        note("tg-note", "# tags are checked per 16-byte granule. A 13-byte object leaves 3 bytes of slack that the hardware can't tell apart.", "y");
      }
      heapView(mark);
    }
    $("tg-bits").addEventListener("click", (e) => {
      const b = e.target.closest("button[data-bits]"); if (!b) return;
      bits = +b.dataset.bits; setPressed("tg-bits", "data-bits", bits); fresh(bits * 1000 + 3); heapView(null);
      verdict("tg-verdict", "", ""); note("tg-note", "# " + bits + "-bit tags: a random tag matches by chance 1 time in " + (1 << bits) + ".");
      $("tg-trials").textContent = "";
    });
    $("tg-act").addEventListener("click", (e) => { const b = e.target.closest("button[data-act]"); if (!b) return; act(b.dataset.act); });
    click("tg-run", () => {
      const r = M.uafTrials(7, bits, 1000);
      let t = r.missed + " of 1000 stale pointers matched by chance (" + (r.missed / 10).toFixed(1) + "%; expected about " + (100 * r.expected).toFixed(1) + "%).";
      if (bits === 2) t += " One in four: you wouldn't bet your phone on it.";
      if (bits === 8) t += " Under half a percent. Bigger tags catch more, but the hardware decides how many bits there are.";
      $("tg-trials").textContent = t;
    });
    fresh(bits * 1000 + 3); heapView(null);
    note("tg-note", "# 4-bit tags: a random tag matches by chance 1 time in 16.");
  }

  // --------------------------------------------------------------------------- sanitizer reports (captured text, trimmed)
  const SN = {
    oob: {
      name: "Heap overflow", file: "oob.c",
      code: ["#include <stdlib.h>", "#include <stdio.h>", "", "int main(void) {", "    int *scores = malloc(4 * sizeof(int));", "    for (int i = 0; i <= 4; i++) {   /* off by one */", "        scores[i] = i * 10;", "    }", "    printf(\"%d\\n\", scores[0]);", "    free(scores);", "    return 0;", "}"].map((l, i) => String(i + 1).padStart(2) + "  " + l),
      cmd: "clang -O1 -g -fsanitize=address -fno-omit-frame-pointer oob.c -o oob",
      plain: ["0", "", "(exit status 0: no error, no warning)"],
      san: [
        ["==…==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x7bff08fe0020 at pc 0x561efc62800c …", "err"],
        ["WRITE of size 4 at 0x7bff08fe0020 thread T0", "acc"],
        ["    #0 0x561efc62800b in main oob.c:7:19", "frame"],
        ["    #1 … in __libc_start_call_main …", ""],
        ["", ""],
        ["0x7bff08fe0020 is located 0 bytes after 16-byte region [0x7bff08fe0010,0x7bff08fe0020)", "where"],
        ["allocated by thread T0 here:", "alloc"],
        ["    #0 0x561efc5e29c4 in malloc …", ""],
        ["    #1 0x561efc627fbf in main oob.c:5:19", "allocline"],
        ["", ""],
        ["SUMMARY: AddressSanitizer: heap-buffer-overflow oob.c:7:19 in main", "sum"],
        ["Shadow bytes around the buggy address:", "shadow"],
        ["=>0x7bff08fe0000: fa fa 00 00[fa]fa fa fa fa fa fa fa fa fa fa fa", "shadow"]
      ],
      ann: {
        err: "The class of bug, named: a heap-buffer-overflow is a heap access outside its allocation. This is the line to paste into the bug.",
        acc: "What the bad access was: a WRITE, 4 bytes wide (one int). Reads and writes are reported separately.",
        frame: "The exact line: oob.c line 7, column 19, the write scores[i] = i * 10. The loop bound on line 6 is the bug.",
        where: "\"0 bytes after\" a 16-byte region: the write landed exactly at the end. Four ints are 16 bytes, so it's an off-by-one.",
        alloc: "The report also says where the memory came from, so you can see the size it was given.",
        allocline: "The malloc on line 5 of oob.c. Allocation site and bad access, side by side.",
        sum: "A one-line summary: class, line and function.",
        shadow: "How the tool knows: every 8 bytes of memory have 1 shadow byte. 00 means all 8 are valid; fa is a poisoned red zone around the allocation. The bracketed [fa] is the byte the program touched."
      }
    },
    uaf: {
      name: "Use after free", file: "uaf.c",
      code: ["#include <stdlib.h>", "#include <stdio.h>", "#include <string.h>", "", "int main(void) {", "    char *name = malloc(16);", "    strcpy(name, \"alice\");", "    free(name);", "    printf(\"%s\\n\", name);   /* used after it was freed */", "    return 0;", "}"].map((l, i) => String(i + 1).padStart(2) + "  " + l),
      cmd: "clang -O1 -g -fsanitize=address -fno-omit-frame-pointer uaf.c -o uaf",
      plain: ["(prints a few unpredictable bytes: it varies from run to run)", "", "(exit status 0: no error, no warning)"],
      san: [
        ["==…==ERROR: AddressSanitizer: heap-use-after-free on address 0x7bed02fe0010 at pc 0x55f151d2478a …", "err"],
        ["READ of size 2 at 0x7bed02fe0010 thread T0", "acc"],
        ["    #0 0x55f151d24789 in puts …", ""],
        ["    #1 0x55f151e27fe6 in main uaf.c:9:5", "frame"],
        ["", ""],
        ["0x7bed02fe0010 is located 0 bytes inside of 16-byte region [0x7bed02fe0010,0x7bed02fe0020)", "where"],
        ["freed by thread T0 here:", "freed"],
        ["    #0 0x55f151de23a9 in free …", ""],
        ["    #1 0x55f151e27fde in main uaf.c:8:5", "freedline"],
        ["", ""],
        ["previously allocated by thread T0 here:", "alloc"],
        ["    #1 0x55f151e27fbf in main uaf.c:6:18", "allocline"],
        ["", ""],
        ["SUMMARY: AddressSanitizer: heap-use-after-free … in puts", "sum"],
        ["=>0x7bed02fe0000: fa fa[fd]fd fa fa fa fa fa fa fa fa fa fa fa fa", "shadow"]
      ],
      ann: {
        err: "heap-use-after-free: the memory had been freed, then used. The class of bug, named for you.",
        acc: "A READ of 2 bytes. It happens inside puts(), called by the printf on line 9.",
        frame: "The line where the stale pointer was used: uaf.c line 9.",
        where: "\"0 bytes inside\" a freed 16-byte region: the read is exactly at the start of memory that is no longer yours.",
        freed: "The part a use-after-free needs most: who freed it.",
        freedline: "uaf.c line 8, the free(name). Both ends of the lifetime are in one report.",
        alloc: "And where it was allocated.",
        allocline: "uaf.c line 6, the malloc.",
        sum: "A one-line summary for the bug tracker.",
        shadow: "The shadow byte under the access is [fd]: freed heap memory. fa is the red zone around it."
      }
    },
    ubsan: {
      name: "Signed overflow (UBSan)", file: "ovf.c",
      code: ["#include <stdio.h>", "#include <limits.h>", "", "int main(int argc, char **argv) {", "    (void)argv;", "    int n = INT_MAX;", "    n += argc;               /* signed overflow */", "    printf(\"%d\\n\", n);", "    return 0;", "}"].map((l, i) => String(i + 1).padStart(2) + "  " + l),
      cmd: "clang -O1 -g -fsanitize=undefined -fno-omit-frame-pointer ovf.c -o ovf",
      plain: ["-2147483648", "", "(exit status 0. It looks like it wrapped, but in C signed overflow is undefined: the compiler may assume it never happens)"],
      san: [
        ["ovf.c:7:7: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'", "rt"],
        ["SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior ovf.c:7:7", "sum"],
        ["-2147483648", ""]
      ],
      ann: {
        rt: "UBSan checks the language's rules as the program runs. Here: signed integer overflow is undefined behaviour in C, and the report names the line and column, and the exact values.",
        sum: "A one-line summary. By default the program carries on afterwards and prints the same number as before: UBSan reports, it doesn't change the result."
      }
    }
  };
  function sanitizers() {
    let prog = "oob", view = "san";
    const seen = {};
    $("sn-pick").innerHTML = Object.keys(SN).map((k) => `<button type="button" data-p="${k}" aria-pressed="${k === prog}">${esc(SN[k].name)}</button>`).join("");
    function render() {
      const p = SN[prog];
      setPressed("sn-pick", "data-p", prog); setPressed("sn-view", "data-v", view);
      $("sn-code").textContent = p.code.join("\n");
      $("sn-cmd").textContent = view === "san" ? p.cmd : p.cmd.replace(/ -fsanitize=[a-z]+/, "");
      const out = $("sn-out");
      if (view === "plain") {
        out.textContent = "$ ./" + p.file.replace(".c", "") + "\n" + p.plain.join("\n");
        $("sn-ann").textContent = "The normal build says nothing. Nobody finds out until someone else does. Switch to the sanitizer build.";
        note("sn-note", "# real output from a small program, trimmed. Compiled and run on 11 November 2026.");
      } else {
        out.innerHTML = p.san.map(([t, k]) => k ? `<span class="ln key" tabindex="0" role="button" data-k="${k}">${esc(t)}</span>` : `<span class="ln">${esc(t)}</span>`).join("");
        $("sn-ann").textContent = "Click a line of the report to read it.";
        const total = Object.keys(p.ann).length, n = (seen[prog] || new Set()).size;
        note("sn-note", "# real output, trimmed: addresses shortened with …, libc frames dropped. " + n + " of " + total + " parts read.");
      }
    }
    function pickKey(el) {
      const p = SN[prog], k = el.dataset.k;
      (seen[prog] = seen[prog] || new Set()).add(k);
      for (const x of $("sn-out").querySelectorAll(".ln.key")) x.classList.toggle("sel", x === el);
      $("sn-ann").textContent = p.ann[k];
      const total = Object.keys(p.ann).length, n = seen[prog].size;
      if (n >= total) note("sn-note", "# you've read every part. You can read an ASan report now: the rest is practice.", "ok");
      else note("sn-note", "# " + n + " of " + total + " parts read.");
    }
    $("sn-pick").addEventListener("click", (e) => { const b = e.target.closest("button[data-p]"); if (!b) return; prog = b.dataset.p; render(); });
    $("sn-view").addEventListener("click", (e) => { const b = e.target.closest("button[data-v]"); if (!b) return; view = b.dataset.v; render(); });
    $("sn-out").addEventListener("click", (e) => { const l = e.target.closest(".ln.key"); if (l) pickKey(l); });
    $("sn-out").addEventListener("keydown", (e) => { if (e.key !== "Enter" && e.key !== " ") return; const l = e.target.closest(".ln.key"); if (l) { e.preventDefault(); pickKey(l); } });
    render();
  }

  // --------------------------------------------------------------------------- fuzzing the toy parser
  const FZ_CODE = [
    "// record: 'R', version (must be 2), length, then <length> bytes",
    "char buf[8];",
    "if (n < 3 || in[0] != 'R') return;",
    "if (in[1] != 2)            return;",
    "len = in[2];",
    "if (len > 16)              return;   // bug: buf holds only 8",
    "if (len > n - 3)           return;",
    "memcpy(buf, in + 3, len);            // writes past buf if len > 8"
  ].join("\n");
  function fuzzing() {
    let mode = "guided", seed = 5, ran = false;
    $("fz-code").textContent = FZ_CODE;
    function chips(res) {
      const reached = new Map();
      if (res) for (const l of res.log) reached.set(l.branch, l.exec);
      $("fz-branches").innerHTML = M.BRANCHES.map((b) => {
        const on = res && (reached.has(b) || (b === "entry") || M.parse(M.SEED_INPUT).cov.has(b));
        return `<li class="${on ? "on" : ""}${b === "overflow" ? " bug" : ""}">${esc(b)}</li>`;
      }).join("");
    }
    function render() {
      setPressed("fz-mode", "data-f", mode);
      $("fz-seedlabel").textContent = "seed " + seed;
    }
    function run() {
      const res = M.fuzz(mode, seed, 100000);
      ran = true;
      $("fz-tries").textContent = res.execs.toLocaleString("en-US");
      $("fz-cov").textContent = res.coverage + " of " + M.BRANCHES.length;
      $("fz-corpus").textContent = res.corpus;
      chips(res);
      if (res.found) {
        verdict("fz-result", "ok", "Crash found after " + res.execs.toLocaleString("en-US") + " tries: " + res.crash + ". Input: " + res.hex);
        note("fz-note", res.execs < 1000 ? "# a monkey with a map. Coverage feedback turned a search into a walk." : "# found. The input is 12 or more bytes: magic, version, a length of 9 to 16, and enough bytes behind it.");
      } else {
        verdict("fz-result", "bad", "No crash in " + res.execs.toLocaleString("en-US") + " tries.");
        note("fz-note", mode === "random" ? "# 100,000 monkeys, a budget, and no crash. Try the coverage-guided mode on this seed." : "# not this time: the search is random. Another seed may find it, and a longer run usually does.", "y");
      }
    }
    $("fz-mode").addEventListener("click", (e) => { const b = e.target.closest("button[data-f]"); if (!b) return; mode = b.dataset.f; render(); });
    click("fz-run", run);
    click("fz-seed", () => { seed++; render(); run(); });
    render(); chips(null);
    note("fz-note", "# the toy parser and the numbers are invented. Press Run.");
  }

  // --------------------------------------------------------------------------- the same bug in other languages (captured text)
  const LANG = [
    { id: "oob", label: "Index past the end",
      c: "Normal build: prints 0, exit status 0.\n\nWith ASan:\nERROR: AddressSanitizer: heap-buffer-overflow\nWRITE of size 4 …\n0 bytes after 16-byte region",
      m: "Go (documented):\npanic: runtime error:\nindex out of range [4] with length 4\n\nJava (documented):\nArrayIndexOutOf\nBoundsException:\nIndex 4 out of bounds\nfor length 4",
      r: "thread 'main' panicked at oobv2.rs:5:24:\nindex out of bounds: the len is 4\nbut the index is 4\n\n(a run-time panic: stops, with a clear message)" },
    { id: "uaf", label: "Use after free / move",
      c: "Normal build: prints a few unpredictable bytes, exit status 0.\n\nWith ASan:\nERROR: AddressSanitizer: heap-use-after-free\nREAD of size 2 …\nfreed by thread T0 here: … uaf.c:8:5",
      m: "There is no free() to call. The collector keeps an object alive for as long as anything refers to it, so a stale pointer can't exist.",
      r: "error[E0382]: borrow of moved value: `name`\n --> uaf.rs:4:20\n  |\n2 | let name = String::from(\"alice\");\n  |     ---- move occurs because `name`\n  |     has type `String`, which does not\n  |     implement the `Copy` trait\n3 | drop(name);\n  |      ---- value moved here\n4 | println!(\"{}\", name);\n  |                ^^^^ value borrowed here\n  |                after move" },
    { id: "push", label: "Reference held across a push",
      c: "Normal build: prints 1682112894 (garbage), exit status 0.\n\nWith ASan:\nERROR: AddressSanitizer: heap-use-after-free\nREAD of size 4 at … vec.cpp:8:25",
      m: "Java and C# hold object references, not raw slots, so the reference stays valid.\n\nGo (documented): a pointer into the old slice keeps the old array alive. It can show stale data but never freed memory.",
      r: "error[E0502]: cannot borrow `names` as\nmutable because it is also borrowed as\nimmutable\n --> borrow.rs:4:5\n  |\n3 | let first = &names[0];\n  |              ----- immutable borrow\n  |              occurs here\n4 | names.push(String::from(\"bob\"));\n  | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ mutable\n  | borrow occurs here\n5 | println!(\"{}\", first);\n  |                ----- immutable borrow\n  |                later used here" }
  ];
  function languages() {
    let cur = "oob";
    $("lg-pick").innerHTML = LANG.map((l) => `<button type="button" data-l="${l.id}" aria-pressed="${l.id === cur}">${esc(l.label)}</button>`).join("");
    function render() {
      const l = LANG.find((x) => x.id === cur);
      setPressed("lg-pick", "data-l", cur);
      $("lg-c").textContent = l.c; $("lg-m").textContent = l.m; $("lg-r").textContent = l.r;
      note("lg-note", "# C, C++ and Rust: real output from small programs (clang 23.1.4, rustc 1.99.1), trimmed. The middle column describes documented behaviour: not run here.");
    }
    $("lg-pick").addEventListener("click", (e) => { const b = e.target.closest("button[data-l]"); if (!b) return; cur = b.dataset.l; render(); });
    render();
  }

  // --------------------------------------------------------------------------- where to start
  function start() {
    const list = $("st-list"), dots = (n) => "●".repeat(n) + "○".repeat(3 - n);
    list.innerHTML = M.COMPONENTS.map((c) => `<label class="st-item"><input type="checkbox" data-id="${c.id}"><span><span class="st-top"><b>${esc(c.name)}</b> <em>${esc(c.note)}</em></span><small>untrusted input ${dots(c.exposure)} · bug history ${dots(c.history)} · ${c.kloc}k lines</small></span></label>`).join("");
    const boxes = Array.from(list.querySelectorAll("input"));
    function update() {
      const ids = boxes.filter((b) => b.checked).map((b) => b.dataset.id);
      for (const b of boxes) b.disabled = ids.length >= 3 && !b.checked;
      if (ids.length < 3) {
        verdict("st-result", "", ""); note("st-note", "# pick " + (3 - ids.length) + " more. My scoring: untrusted input counts double, history once, small size a bonus.");
        return;
      }
      const s = M.scorePicks(ids), nm = (id) => M.COMPONENTS.find((c) => c.id === id).name;
      if (s.perfect) { verdict("st-result", "ok", "Your three score " + s.got + " of " + s.best + ": the best possible by this rule."); note("st-note", "# you'd pass the architecture review.", "ok"); }
      else {
        verdict("st-result", "y", "Your three score " + s.got + " of " + s.best + ". Best: " + s.bestIds.map(nm).join(", ") + ".");
        note("st-note", ids.indexOf("ui") >= 0 ? "# the settings UI: bold. Nobody sends a hostile file to a button, so it can wait." : "# not wrong, just lower on this scale. Look at the untrusted-input column first.");
      }
    }
    boxes.forEach((b) => b.addEventListener("change", update));
    update();
  }

  // --------------------------------------------------------------------------- checklist
  const RV_KEY = "memory-safety-checklist";
  function checklist() {
    const boxes = Array.from(document.querySelectorAll("#rv-list input[type=checkbox]"));
    let saved = {};
    try { saved = JSON.parse(store(RV_KEY) || "{}"); } catch (e) {}
    boxes.forEach((b) => { b.checked = !!saved[b.dataset.k]; });
    const update = () => {
      const done = boxes.filter((b) => b.checked).length;
      store(RV_KEY, JSON.stringify(Object.fromEntries(boxes.map((b) => [b.dataset.k, b.checked]))));
      const n = $("rv-note"); n.className = "comment";
      if (done === boxes.length) { n.textContent = "# 10 of 10. Ship it. Slowly, behind tests."; n.classList.add("ok"); }
      else if (!done) n.textContent = "# tick what's true for your team today. Each gap is a ticket, not a failure. Saved in this browser only.";
      else n.textContent = `# ${done} of ${boxes.length}. Pick the unticked box that's cheapest to fix this week.`;
    };
    boxes.forEach((b) => b.addEventListener("change", update));
    update();
  }

  // --------------------------------------------------------------------------- easter egg: console
  function consoleHint() {
    console.log("%c" + document.title, "font: 700 24px monospace; color: #ff2e88; text-shadow: 0 0 8px #ff2e88");
    console.log("%cSegmentation fault (core dumped)", "font: 14px monospace; color: #00f0ff");
    console.log("%c...just kidding. JavaScript checks every index.", "font: 14px monospace; color: #f6e94b");
  }

  function boot() {
    consoleHint();
    $("hero-in").addEventListener("input", hero); hero();
    heap(); quiz(); mitigations(); sameBug(); tagging(); sanitizers(); fuzzing(); languages(); start(); checklist();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot); else boot();
})();
