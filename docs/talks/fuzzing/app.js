/* app.js - the live demos for "Fuzzing for Developers".
   Every demo runs the small models in fuzz.js (window.FuzzLab) against an invented record parser, a toy Base64 and a toy JSON schema check.
   The libFuzzer and AddressSanitizer output on the sanitizer slide is captured text from a small C program written for this talk.
   Nothing is fetched or sent anywhere. */
(function () {
  "use strict";
  const F = window.FuzzLab;

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
  const q = JSON.stringify;
  const fmt = (n) => n >= 1e6 ? (n / Math.pow(10, Math.floor(Math.log10(n)))).toFixed(1) + " × 10^" + Math.floor(Math.log10(n)) : Math.round(n).toLocaleString("en-US");
  const pct = (n, total) => Math.round((n / total) * 100) + "%";
  const later = (fn, ms) => setTimeout(fn, ms || 0);

  const PATIENCE_MS = Number((/[?&]patience=(\d+)/.exec(location.search) || [])[1]) || 5 * 60 * 1000;
  const SEED_REC = "REC1:5:hello";
  const TOTAL = F.BRANCHES.length;

  let toastTimer = 0;
  function toast(msg, ms) {
    const t = $("fz-toast");
    t.textContent = msg; t.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { t.hidden = true; }, ms || 4500);
  }

  // --------------------------------------------------------------------------- title slide: feed the parser
  function hero() {
    const grid = $("hero-grid");
    grid.innerHTML = F.BRANCHES.map((b) => `<i data-b="${b.id}" title="${esc(b.label)}"></i>`).join("");
    const cells = {};
    grid.querySelectorAll("i").forEach((i) => { cells[i.dataset.b] = i; });
    const input = $("hero-in");
    function update() {
      input.style.width = Math.max(6, input.value.length + 1) + "ch";
      const s = input.value;
      const r = F.parseRecord(s, ["fuzz"]);
      Object.keys(cells).forEach((id) => cells[id].classList.toggle("lit", r.cov.has(id)));
      $("hero-count").textContent = r.cov.size + " of " + TOTAL;
      let text, cls = "";
      if (r.crash) { text = "IT'S ALIVE! A 4-byte tag copied into a 3-byte buffer: the planted bug. It only fires on REC2: plus a FUZZ tag. A fuzzer can find it by itself; you just did it by hand."; cls = "y"; }
      else if (s === "") text = "An empty input: the fuzzer's favourite first try. (With no corpus, libFuzzer starts from an empty one.)";
      else if (s === "FUZZ") text = "FUZZ alone isn't enough: the parser wants REC2: in front of it. A fuzzer would work that out. So can you.";
      else if (/^REC1:9:hi$/.test(s)) text = "Declared length 9, only 2 bytes of text. This build checks the length, so it's rejected politely. (The crash-handling slide has a build where it isn't.)";
      else if (r.cov.has("bad-magic")) text = "Rejected at the front door: not a REC record. Random text mostly ends right here.";
      else if (r.status === "ok") text = "Accepted. Now find the input that reaches the FUZZ branch.";
      else text = "Rejected: it started well, then failed a check. Each branch you reach is new code the fuzzer could explore.";
      note("hero-note", text, cls);
    }
    input.addEventListener("input", update);
    update();
  }

  // --------------------------------------------------------------------------- gates: random vs guided
  const GATES = ["R", "E", "C", "2", ":", "F", "U", "Z", "Z"];
  function gates() {
    function update() {
      const n = +$("gt-n").value, speed = +$("gt-speed").value;
      $("gt-nv").textContent = n;
      const o = F.gateOdds(n, 95, 10);
      $("gt-r-tries").textContent = fmt(o.random);
      $("gt-g-tries").textContent = fmt(o.guided);
      $("gt-r-time").textContent = F.humanTime(o.random / speed);
      $("gt-g-time").textContent = F.humanTime(o.guided / speed);
      $("gt-gates").textContent = "Checks: " + GATES.slice(0, n).join(" · ") + (n > GATES.length ? " · …and " + (n - GATES.length) + " more" : "");
      const years = o.random / speed / (365.25 * 86400);
      if (years > F.AGE_OF_UNIVERSE_YEARS) verdict("gt-verdict", "bad", "Random guessing: " + F.humanTime(o.random / speed) + ". The universe is about 13.8 billion years old. Guided: " + F.humanTime(o.guided / speed) + ".");
      else if (o.random / speed > 86400 * 365) verdict("gt-verdict", "bad", "Random guessing needs years. Guided needs " + F.humanTime(o.guided / speed) + ".");
      else if (o.random / speed > 60) verdict("gt-verdict", "y", "Random is already minutes or more. Guided: " + F.humanTime(o.guided / speed) + ".");
      else verdict("gt-verdict", "ok", "With only " + n + " check" + (n === 1 ? "" : "s") + " even random guessing gets there. Add checks.");
    }
    $("gt-n").addEventListener("input", update);
    $("gt-speed").addEventListener("change", update);
    update();
  }

  // --------------------------------------------------------------------------- the loop, one step at a time
  function loop() {
    let seedN = 11, fz, base = 0;
    function reset() {
      fz = F.createFuzzer({ mode: "guided", seed: seedN, seeds: [SEED_REC], bugs: ["fuzz", "len", "empty"], stopOnCrash: false, histEvery: 1000 });
      base = fz.state.tries; // the seed record counts as a run, but not as one of "your" tries
      ["lp-parent", "lp-mutant", "lp-status", "lp-kept"].forEach((id) => { $(id).textContent = "–"; });
      $("lp-muts").textContent = ""; $("lp-fresh").textContent = "";
      ["lp-pick", "lp-mut", "lp-run", "lp-keep"].forEach((id) => { $(id).className = "lp-step"; });
      note("lp-note", "# the corpus starts with one tiny record. Press Step.");
      render();
    }
    function render() {
      const st = fz.state;
      $("lp-tries").textContent = (st.tries - base).toLocaleString("en-US");
      $("lp-cov").textContent = st.cov.size + " / " + TOTAL;
      $("lp-count").textContent = "(" + st.corpus.length + " kept)";
      $("lp-corpus").innerHTML = st.corpus.slice(-9).map((c) => `<li><code>${esc(q(c.input))}</code><small>${c.found ? "+" + c.found + " new" : "seed"}</small></li>`).join("");
    }
    function step(n) {
      let d = null;
      for (let i = 0; i < n; i++) d = fz.stepOnce();
      if (!d) return;
      $("lp-parent").textContent = q(d.parent || "");
      $("lp-mutant").textContent = q(d.input);
      $("lp-muts").textContent = d.names.join(" + ");
      const r = d.result;
      $("lp-status").textContent = r.crash ? "CRASH: " + r.crash.kind : r.status;
      $("lp-fresh").textContent = d.fresh.length ? "new: " + d.fresh.join(", ") : "nothing new";
      $("lp-kept").textContent = d.kept ? "kept: joins the corpus" : "thrown away";
      $("lp-pick").className = "lp-step on";
      $("lp-mut").className = "lp-step on";
      $("lp-run").className = "lp-step on" + (r.crash ? " bad" : "");
      $("lp-keep").className = "lp-step " + (d.kept ? "ok" : "off");
      render();
      const st = fz.state;
      if (r.crash) note("lp-note", "# a crash. A real fuzzer saves this input and keeps going.", "y");
      else if (d.kept) note("lp-note", "# new branch (" + d.fresh[0] + "): kept. It's now a parent for later tries.", "ok");
      else if (st.tries > 150 && st.cov.size < 6) note("lp-note", "# most tries find nothing new. That's normal: the loop just runs a lot of them.");
      else note("lp-note", "# nothing new this time: thrown away.");
    }
    click("lp-step", () => step(1));
    click("lp-step10", () => step(10));
    click("lp-step100", () => step(100));
    click("lp-reset", () => { seedN++; reset(); });
    reset();
  }

  // --------------------------------------------------------------------------- the race
  const RACE_CODE =
`parse(s):
  if s[0:3] != "REC":          reject          # checks 1-3
  if s[3] == "2":                              # check 4
    expect ":" at s[4]                         # check 5
    for field in s[5:].split(";"):
      if field starts with "FUZZ":             # checks 6-9
        copy_tag(field)    # BUG: 3-byte buffer, 4+ bytes copied
  elif s[3] == "1":
    ...                    # the version 1 path`;

  function race() {
    $("fz-code").textContent = RACE_CODE;
    $("fz-branches").innerHTML = F.BRANCHES.map((b) => `<li data-b="${b.id}">${esc(b.label)}</li>`).join("");
    let mode = "guided", runSeed = 1, learn = true, running = 0, patience = false;
    let patienceMs = 0, patienceShown = false;

    function paint(st) {
      $("fz-tries").textContent = st.tries.toLocaleString("en-US");
      $("fz-cov").textContent = st.cov.size + " / " + TOTAL;
      $("fz-corpus").textContent = mode === "guided" ? st.corpus.length : "–";
      document.querySelectorAll("#fz-branches li").forEach((li) => li.classList.toggle("on", st.cov.has(li.dataset.b)));
    }
    function opts() {
      return { mode, seed: runSeed, bugs: ["fuzz"], seeds: mode === "random" ? [] : [SEED_REC], learn, stopOnCrash: !patience, histEvery: patience ? 5000 : 500 };
    }
    function finish(st) {
      paint(st);
      if (st.firstCrash) {
        verdict("fz-result", "y", "IT'S ALIVE! Crash after " + st.firstCrashAt.toLocaleString("en-US") + " tries: " + q(st.firstCrash.input) + " (" + st.firstCrash.crash.kind + ")");
        note("fz-note", mode === "guided" ? "# every correct step reached new code, so it was kept and built on." : "# lucky. Run it again: this strategy usually can't.", "ok");
      } else {
        verdict("fz-result", "bad", "No crash in " + st.tries.toLocaleString("en-US") + " tries. " + st.cov.size + " of " + TOTAL + " branches reached.");
        if (mode === "random") note("fz-note", "# 100,000 tries and the monkeys are still typing. Random text never gets past the magic bytes.", "y");
        else if (mode === "mutate") note("fz-note", "# it edits a valid record but never learns from what it finds, so it can't climb.", "y");
        else note("fz-note", "# not found this time. Try another run, or turn comparison tracing back on.", "y");
      }
    }
    function start() {
      const my = ++running;
      const fz = F.createFuzzer(opts());
      verdict("fz-result", "", ""); note("fz-note", "");
      const limit = 100000, chunk = 1000;
      let last = performance.now();
      (function tick() {
        if (my !== running) return;
        const now = performance.now();
        if (patience) {
          patienceMs += now - last;
          if (!patienceShown && patienceMs >= PATIENCE_MS) { patienceShown = true; toast("Achievement unlocked: Patience of a Fuzzer. Five minutes of fuzzing, and it never complained."); }
        }
        last = now;
        fz.step(patience ? 2000 : chunk);
        paint(fz.state);
        if (patience) {
          const st = fz.state;
          const left = Math.max(0, Math.ceil((PATIENCE_MS - patienceMs) / 1000));
          verdict("fz-result", st.rawCrashes ? "y" : "", "Still fuzzing: " + st.tries.toLocaleString("en-US") + " tries, " + st.rawCrashes.toLocaleString("en-US") + " crashing inputs" + (st.rawCrashes ? " (first at try " + st.firstCrashAt.toLocaleString("en-US") + ")" : "") + (patienceShown ? "" : ". Patience of a Fuzzer in " + left + " s."));
          requestAnimationFrame(tick);
          return;
        }
        if (fz.state.done || fz.state.tries >= limit) { finish(fz.state); return; }
        requestAnimationFrame(tick);
      })();
    }
    for (const b of $("fz-mode").querySelectorAll("button")) b.addEventListener("click", () => { mode = b.dataset.f; setPressed("fz-mode", "data-f", mode); });
    click("fz-run", () => { patience = false; $("fz-patience").setAttribute("aria-pressed", "false"); start(); });
    click("fz-again", () => { runSeed++; patience = false; $("fz-patience").setAttribute("aria-pressed", "false"); start(); });
    click("fz-learn", () => {
      learn = !learn;
      $("fz-learn").setAttribute("aria-pressed", String(learn));
      $("fz-learn").textContent = "Comparison tracing: " + (learn ? "on" : "off");
    });
    click("fz-patience", () => {
      patience = !patience;
      $("fz-patience").setAttribute("aria-pressed", String(patience));
      if (patience) start(); else { running++; note("fz-note", "# stopped. " + (patienceMs >= 1000 ? Math.round(patienceMs / 1000) + " s of fuzzing so far." : "")); }
    });
    paint({ tries: 0, cov: new Set(), corpus: [] });
    $("fz-tries").textContent = "–"; $("fz-cov").textContent = "–"; $("fz-corpus").textContent = "–";
  }

  // --------------------------------------------------------------------------- sanitizers: real captured output
  const SN_LOG =
`$ clang -g -O0 -fsanitize=fuzzer,address record.c -o fuzz_record
$ ./fuzz_record -seed=1 -max_len=32 corpus/
INFO: Seed: 1
INFO: A corpus is not provided, starting from an empty corpus
#2     INITED cov: 3 ft: 4 corp: 1/1b
#206   NEW    cov: 4 ft: 5 corp: 2/6b MS: 4 ChangeBit-…
#2888  NEW    cov: 5 ft: 6 corp: 3/25b MS: 2 …CMP- DE: "REC"-
#9628  NEW    cov: 9 ft: 10 corp: 5/21b MS: 1 ChangeByte-
#9784  NEW    cov: 14 ft: 15 corp: 6/27b MS: 1 InsertByte-
#9910  NEW    cov: 15 ft: 18 corp: 7/36b MS: 1 PersAutoDict-
  … more NEW and REDUCE lines …
#11786 REDUCE cov: 15 ft: 33 corp: 15/181b MS: 4 CMP-…
=====================================================
ERROR: AddressSanitizer: heap-buffer-overflow …
  … the crash is next: see "The report" …`;
  const SN_REPORT =
`ERROR: AddressSanitizer: heap-buffer-overflow on address 0x7ba4…
WRITE of size 4 at 0x7ba47202b893 thread T0
    #0 … in __asan_memcpy
    #1 … in parse_record record.c:18:7
    #2 … in LLVMFuzzerTestOneInput record.c:27:3
    …
0x…893 is located 0 bytes after 3-byte region [0x…890,0x…893)
allocated by thread T0 here:
    #0 … in malloc
    #1 … in parse_record record.c:17:19
    #2 … in LLVMFuzzerTestOneInput record.c:27:3
    …
SUMMARY: AddressSanitizer: heap-buffer-overflow … in __asan_memcpy
MS: 1 CMP- DE: "FUZZ"-; base unit: f9846f49…
REC2:FUZZ\\006\\006\\006\\006…\\321;\\000HC2:\\006
artifact_prefix='./'; Test unit written to ./crash-3e569d89…`;
  const SN_MIN =
`$ ./fuzz_record -minimize_crash=1 -runs=20000 \\
    -exact_artifact_path=min.bin crash-3e569d89…
CRASH_MIN: minimizing crash input: 'crash-3e569d89…' (30 bytes)
  … each round tries removing or changing bytes …
  … and keeps any change that still crashes …
CRASH_MIN: 'min.bin' (9 bytes) caused a crash.
INFO: Done MinimizeCrashInputInternalStep, no crashes found
CRASH_MIN: failed to minimize beyond min.bin (9 bytes), exiting
$ xxd min.bin
00000000: 5245 4332 3a46 555a 5a      REC2:FUZZ`;
  const SN_VIEWS = {
    log: { text: SN_LOG, say: "# cov counts code reached; NEW means an input reached something new and joined the corpus. CMP and PersAutoDict: it tried words the code compared against." },
    report: { text: SN_REPORT, say: "# what, where, and who allocated it: heap-buffer-overflow, record.c line 18, a 3-byte region from line 17. The input is saved as a crash file." },
    min: { text: SN_MIN, say: "# libFuzzer's own minimiser shrank the saved crash to REC2:FUZZ: nine bytes. Our toy will land on the same nine." }
  };
  function sanitizers() {
    const seen = {};
    function show(k) {
      $("sn-term").textContent = SN_VIEWS[k].text;
      setPressed("sn-pick", "data-s", k);
      $("sn-out").textContent = SN_VIEWS[k].say;
      seen[k] = true;
    }
    for (const b of $("sn-pick").querySelectorAll("button")) b.addEventListener("click", () => {
      show(b.dataset.s);
      if (seen.log && seen.report && seen.min && !seen.all) { seen.all = true; toast("You can read a libFuzzer run now. The numbers go up; the crash goes boom."); }
    });
    show("log");
  }

  // --------------------------------------------------------------------------- property-based testing
  const PB_CODE =
`def encode(data: bytes) -> str: ...
def decode(text: str) -> bytes: ...

# a property: it must hold for EVERY input
@given(binary())
def test_round_trip(data):
    assert decode(encode(data)) == data`;
  function property() {
    $("pb-code").textContent = PB_CODE;
    let impl = "good", pbSeed = 7, shownSmug = false;
    const bug = () => impl === "bug";
    function examples() {
      $("pb-examples-out").innerHTML = F.EXAMPLE_TESTS.map((t) => {
        const r = F.roundTrip(t.bytes, bug());
        return `<li class="${r.ok ? "ok" : "bad"}"><span>${r.ok ? "PASS" : "FAIL"}</span> ${esc(t.name)} <code>${esc(r.enc)}</code></li>`;
      }).join("");
      const all = F.EXAMPLE_TESTS.every((t) => F.roundTrip(t.bytes, bug()).ok);
      if (bug() && all) verdict("pb-result", "y", "All 5 hand-written tests pass. The bug is still in there: nobody thought to try a byte above 127.");
      else if (all) verdict("pb-result", "ok", "All 5 hand-written tests pass.");
      else verdict("pb-result", "bad", "A hand-written test failed.");
    }
    function prop() {
      const r = F.propertyTest({ bug: bug(), seed: pbSeed, runs: 100 });
      if (r.passed) { verdict("pb-result", "ok", "100 random inputs passed. (That's the correct encoder.)"); return; }
      const small = r.shrunk;
      verdict("pb-result", "bad", "Failed on try " + r.ran + ": [" + F.hexBytes(r.found) + "] encoded as " + q(r.enc) + ". Shrunk to [" + F.hexBytes(small) + "] (" + small.length + " byte" + (small.length === 1 ? "" : "s") + "). The decoder says: " + r.err + ".");
      if (small.length === 1 && !shownSmug) { shownSmug = true; toast("One byte. One. The shrinker is smug, and right."); }
    }
    for (const b of $("pb-impl").querySelectorAll("button")) b.addEventListener("click", () => {
      impl = b.dataset.i; setPressed("pb-impl", "data-i", impl);
      $("pb-examples-out").innerHTML = ""; verdict("pb-result", "", "");
    });
    click("pb-examples", examples);
    click("pb-prop", prop);
    click("pb-again", () => { pbSeed += 3; prop(); });
  }

  // --------------------------------------------------------------------------- picking targets
  function targets() {
    const order = [0, 5, 1, 6, 2, 7, 3, 8, 4];
    let i = 0, score = 0, done = false;
    function render() {
      const t = F.TARGETS[order[i]];
      $("tg-pos").textContent = "Candidate " + (i + 1) + " of " + order.length;
      $("tg-name").textContent = t.name;
      $("tg-fb").textContent = ""; $("tg-fb").className = "verdict";
      $("tg-next").hidden = true;
      for (const b of $("tg-pick").querySelectorAll("button")) b.disabled = false;
    }
    for (const b of $("tg-pick").querySelectorAll("button")) b.addEventListener("click", () => {
      if (done) return;
      const t = F.TARGETS[order[i]];
      const saidYes = b.dataset.a === "yes";
      const right = saidYes === t.good;
      if (right) score++;
      let extra = "";
      if (saidYes && /web server/.test(t.name)) extra = " Great product. Terrible fuzz target. ";
      verdict("tg-fb", right ? "ok" : "bad", (right ? "Right. " : "Not quite. ") + extra + t.why);
      for (const bb of $("tg-pick").querySelectorAll("button")) bb.disabled = true;
      $("tg-next").hidden = false;
      $("tg-next").textContent = i === order.length - 1 ? "See the score" : "Next one";
    });
    click("tg-next", () => {
      if (i === order.length - 1) {
        done = true;
        $("tg-name").textContent = "Score: " + score + " of " + order.length;
        $("tg-pos").textContent = "";
        $("tg-fb").className = "verdict"; $("tg-fb").textContent = "";
        $("tg-next").hidden = true;
        for (const bb of $("tg-pick").querySelectorAll("button")) bb.disabled = true;
        note("tg-note", score === order.length ? "# a perfect score. Now find the equivalent in your codebase." : "# the pattern: untrusted bytes in, fast and side-effect free means a good target.", score === order.length ? "ok" : "");
        return;
      }
      i++; render();
    });
    render();
  }

  // --------------------------------------------------------------------------- anatomy of a harness
  const HARNESS_CODE = {
    cpp:
`#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(
    const uint8_t *data, size_t size) {
  parse_record(data, size);   // any bytes, any length
  return 0;                   // always 0
}`,
    go:
`func FuzzParseRecord(f *testing.F) {
    f.Add([]byte("REC2:hello;world"))   // a seed

    f.Fuzz(func(t *testing.T, data []byte) {
        ParseRecord(data)               // a panic is a failure
    })
}`,
    rust:
`#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = parse_record(data);   // a panic is a failure
});`,
    py:
`import sys
import atheris

with atheris.instrument_imports():
    import recparse

def TestOneInput(data):
    try:
        recparse.parse(data)
    except recparse.RecordError:    # only the documented error
        pass

atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()`
  };
  const HARNESS_RUN = {
    cpp: "$ clang++ -g -fsanitize=fuzzer,address harness.cc parser.cc -o fuzz_parser && ./fuzz_parser corpus/",
    go: "$ go test -fuzz=FuzzParseRecord -fuzztime=60s",
    rust: "$ cargo fuzz run parse_record      # needs a nightly compiler",
    py: "$ python3 fuzz_recparse.py corpus/"
  };
  function harness() {
    function show(l) {
      $("hn-code").textContent = HARNESS_CODE[l];
      $("hn-run").textContent = HARNESS_RUN[l];
      setPressed("hn-tabs", "data-l", l);
    }
    for (const b of $("hn-tabs").querySelectorAll("button")) b.addEventListener("click", () => show(b.dataset.l));
    show("cpp");
  }

  // --------------------------------------------------------------------------- harness doctor
  function doctor() {
    let i = 0, score = 0, answered = false;
    $("hd-opts").innerHTML = F.HARNESS_OPTIONS.map((o) => `<button type="button" data-o="${o.id}">${esc(o.label)}</button>`).join("");
    function render() {
      const h = F.HARNESSES[i];
      answered = false;
      $("hd-lang").textContent = "Harness " + (i + 1) + " of " + F.HARNESSES.length + " · " + h.lang;
      $("hd-code").textContent = h.code;
      verdict("hd-fb", "", ""); $("hd-next").hidden = true;
      for (const b of $("hd-opts").querySelectorAll("button")) { b.disabled = false; b.setAttribute("aria-pressed", "false"); }
      $("hd-score").textContent = "Score so far: " + score;
    }
    for (const b of $("hd-opts").querySelectorAll("button")) b.addEventListener("click", () => {
      if (answered) return;
      answered = true;
      const h = F.HARNESSES[i], right = b.dataset.o === h.answer;
      if (right) score++;
      const ans = F.HARNESS_OPTIONS.filter((o) => o.id === h.answer)[0].label;
      verdict("hd-fb", right ? "ok" : "bad", (right ? "Yes. " : "The answer is \"" + ans + "\". ") + h.why);
      for (const bb of $("hd-opts").querySelectorAll("button")) bb.disabled = true;
      b.setAttribute("aria-pressed", "true");
      $("hd-next").hidden = false;
      $("hd-next").textContent = i === F.HARNESSES.length - 1 ? "See the score" : "Next harness";
      $("hd-score").textContent = "Score so far: " + score;
    });
    click("hd-next", () => {
      if (i === F.HARNESSES.length - 1) {
        $("hd-code").textContent = "Final score: " + score + " of " + F.HARNESSES.length;
        $("hd-lang").textContent = "";
        verdict("hd-fb", "", ""); $("hd-next").hidden = true;
        for (const bb of $("hd-opts").querySelectorAll("button")) bb.disabled = true;
        note("hd-note", score === F.HARNESSES.length ? "# six for six. Harness doctor, you're hired." : "# the usual suspects: clocks, files, catch-alls, memory between runs and exit().", score === F.HARNESSES.length ? "ok" : "");
        return;
      }
      i++; render();
    });
    render();
  }

  // --------------------------------------------------------------------------- seeds and dictionary benchmark
  function seeds() {
    const RUNS = 10, LIMIT = 20000;
    let busy = false;
    function row(c) { return `<tr data-id="${c.id}"><th scope="row">${esc(c.label)}</th><td>–</td><td>–</td><td>–</td></tr>`; }
    $("sd-body").innerHTML = F.BENCH_CONFIGS.map(row).join("");
    click("sd-run", () => {
      if (busy) return;
      busy = true; $("sd-run").disabled = true;
      $("sd-body").innerHTML = F.BENCH_CONFIGS.map(row).join("");
      note("sd-note", "# running…");
      let ci = 0, ri = 0, results = [];
      (function next() {
        const c = F.BENCH_CONFIGS[ci];
        results.push(F.benchOne(c.id, ri + 1, LIMIT));
        ri++;
        const tr = $("sd-body").querySelector(`tr[data-id="${c.id}"]`);
        const found = results.filter((r) => r.found);
        tr.children[1].textContent = found.length + " / " + ri;
        tr.children[2].textContent = found.length ? Math.round(F.median(found.map((r) => r.found))).toLocaleString("en-US") : "not found";
        tr.children[3].textContent = F.median(results.map((r) => r.covAt1k));
        tr.classList.toggle("best", found.length === ri && ri === RUNS);
        if (ri >= RUNS) { ci++; ri = 0; results = []; }
        if (ci < F.BENCH_CONFIGS.length) later(next, 0);
        else {
          busy = false; $("sd-run").disabled = false;
          note("sd-note", "# even a tiny dictionary helps: fuzzers love vocabulary. A seed teaches the shape; the words teach the vocabulary.", "ok");
        }
      })();
    });
  }

  // --------------------------------------------------------------------------- structure-aware vs byte-level
  function structure() {
    let seed = 3;
    function bar(id, c, total) {
      $(id).innerHTML = `<i class="bad" style="width:${(c.syntax / total) * 100}%"></i><i class="y" style="width:${(c.shape / total) * 100}%"></i><i class="ok" style="width:${(c.deep / total) * 100}%"></i>`;
    }
    function list(id, c, total) {
      $(id).innerHTML = `<li class="bad">syntax error: ${pct(c.syntax, total)}</li><li class="y">wrong shape: ${pct(c.shape, total)}</li><li class="ok">reached the logic: ${pct(c.deep, total)}</li>`;
    }
    function run() {
      const r = F.structureDemo(seed, 1000);
      bar("st-byte", r.count.byte, r.count.n); bar("st-tree", r.count.tree, r.count.n);
      list("st-byte-l", r.count.byte, r.count.n); list("st-tree-l", r.count.tree, r.count.n);
      $("st-byte-s").textContent = "e.g. " + r.sample.byte.slice(0, 60);
      $("st-tree-s").textContent = "e.g. " + r.sample.tree.slice(0, 60);
      note("st-note", "# garbage in: " + pct(r.count.byte.syntax, r.count.n) + " of the byte-level inputs never got past the syntax check. But the structure-aware side never sends malformed JSON, so use both.", "y");
    }
    click("st-run", run);
    click("st-again", () => { seed += 5; run(); });
    run();
  }

  // --------------------------------------------------------------------------- walkthrough: find, shrink, fix, keep
  const WK_BUGGY =
`tag = malloc(3)             // room for 3 bytes...
memcpy(tag, field, 4)       // ...but a FUZZ tag is 4`;
  const WK_FIXED =
`-tag = malloc(3)
-memcpy(tag, field, 4)
+tag = malloc(len)          // size the buffer from the data
+memcpy(tag, field, len)`;
  function walkthrough() {
    let crashInput = null, minimal = null;
    function code(fixed) { $("wk-code").textContent = (fixed ? WK_FIXED : WK_BUGGY); }
    function log(line, cls) { const li = document.createElement("li"); if (cls) li.className = cls; li.textContent = line; $("wk-log").appendChild(li); $("wk-log").scrollTop = 1e6; }
    function reset() {
      crashInput = minimal = null;
      $("wk-log").innerHTML = ""; $("wk-keepbox").hidden = true; $("wk-title").textContent = "Log";
      $("wk-find").disabled = false;
      ["wk-min", "wk-fix", "wk-keep"].forEach((id) => { $(id).disabled = true; });
      verdict("wk-result", "", ""); note("wk-note", "# press 1 to run the fuzzer on the code above.");
      code(false);
    }
    click("wk-find", () => {
      $("wk-find").disabled = true;
      const fz = F.createFuzzer({ mode: "guided", seed: 12, seeds: [SEED_REC], bugs: ["fuzz"], stopOnCrash: true, histEvery: 500 });
      log("fuzzing…");
      (function tick() {
        fz.step(500);
        if (!fz.state.done && fz.state.tries < 100000) { requestAnimationFrame(tick); return; }
        const st = fz.state;
        if (!st.firstCrash) { log("no crash found: press Start over and try again", "bad"); $("wk-find").disabled = false; return; }
        crashInput = st.firstCrash.input;
        log("try " + st.firstCrashAt.toLocaleString("en-US") + ": CRASH " + q(crashInput), "bad");
        verdict("wk-result", "y", "Found after " + st.firstCrashAt.toLocaleString("en-US") + " tries: " + q(crashInput) + " (" + crashInput.length + " bytes)");
        note("wk-note", "# it crashes, but what part of it matters? Shrink it.");
        $("wk-min").disabled = false;
      })();
    });
    click("wk-min", () => {
      $("wk-min").disabled = true;
      const m = F.minimize(crashInput, (s) => { const r = F.parseRecord(s, ["fuzz"]); return !!(r.crash && r.crash.site === "copy_tag"); });
      let k = 0;
      log("shrinking " + q(crashInput) + "…");
      (function tick() {
        const end = Math.min(k + 3, m.steps.length);
        for (; k < end; k++) { const s = m.steps[k]; log((s.kept ? "kept " : "put back ") + q(s.candidate) + "  (" + s.why + ")", s.kept ? "ok" : "m"); }
        if (k < m.steps.length) { later(tick, 35); return; }
        minimal = m.result;
        log("result: " + q(minimal) + " (" + minimal.length + " bytes, " + m.tests + " tries)", "ok");
        verdict("wk-result", "ok", "Shrunk to " + q(minimal) + ": " + minimal.length + " bytes after " + m.tests + " tries.");
        note("wk-note", minimal === "REC2:FUZZ" ? "# nine bytes. The smallest thing that still says FUZZ." : "# short enough to read. Now fix the code.", "ok");
        $("wk-fix").disabled = false;
      })();
    });
    click("wk-fix", () => {
      $("wk-fix").disabled = true;
      code(true);
      log("fix applied: the buffer is sized from the data", "ok");
      const still = F.parseRecord(minimal, []);
      log("the saved input now: " + (still.crash ? "STILL CRASHES" : "passes"), still.crash ? "bad" : "ok");
      const fz = F.createFuzzer({ mode: "guided", seed: 12, seeds: [SEED_REC], bugs: [], stopOnCrash: true, histEvery: 1000 });
      log("fuzzing the fixed code…");
      (function tick() {
        fz.step(2000);
        if (!fz.state.done && fz.state.tries < 100000) { requestAnimationFrame(tick); return; }
        const st = fz.state;
        log(st.tries.toLocaleString("en-US") + " tries: " + (st.firstCrash ? "CRASH " + q(st.firstCrash.input) : "no crash") + "; " + st.cov.size + " of " + TOTAL + " branches" + (st.cov.has("tag-FUZZ-ok") ? ", including the FUZZ tag handled safely" : ""), st.firstCrash ? "bad" : "ok");
        verdict("wk-result", st.firstCrash ? "bad" : "ok", st.firstCrash ? "Still crashing." : "No crash in " + st.tries.toLocaleString("en-US") + " tries on the fixed code, and the FUZZ branch is being exercised safely.");
        note("wk-note", "# fixed. Now make sure it stays fixed.");
        $("wk-keep").disabled = false;
      })();
    });
    click("wk-keep", () => {
      $("wk-keep").disabled = true;
      $("wk-title").textContent = "Keep the input as a regression test";
      const box = $("wk-keepbox");
      box.textContent =
`# libFuzzer: commit the saved input, replay it in CI
corpus/regress/crash-<sha1>    # holds ${minimal}
./fuzz_record corpus/regress/* # re-runs each file

# Go: testdata/fuzz/FuzzParseRecord/<hash>
go test fuzz v1
[]byte(${q(minimal)})

# or a plain unit test, in any language
def test_fuzz_tag_overflow():
    assert parse_record(b${q(minimal)}) == ACCEPTED`;
      box.hidden = false;
      log("kept: the shrunken input is now a test", "ok");
      note("wk-note", "# the bug can never quietly come back. That's the whole loop: find, shrink, fix, keep.", "ok");
    });
    click("wk-reset", reset);
    reset();
  }

  // --------------------------------------------------------------------------- CI: time to find each bug
  function ci() {
    const BUGS = [
      { id: "len", name: "Declared length too big (shallow)", tries: [], found: 0 },
      { id: "empty", name: "Empty field (medium)", tries: [], found: 0 },
      { id: "fuzz", name: "FUZZ tag (deep)", tries: [], found: 0 }
    ];
    const RUNS = 12, LIMIT = 60000;
    let ran = false, busy = false;
    const BUDGETS = [{ n: "a PR (10 min)", s: 600 }, { n: "nightly (1 h)", s: 3600 }, { n: "continuous (24 h)", s: 86400 }];
    function render() {
      const speed = +$("ci-speed").value;
      $("ci-body").innerHTML = BUGS.map((b) => {
        if (!ran) return `<tr><th scope="row">${esc(b.name)}</th><td>–</td><td>–</td><td>–</td></tr>`;
        if (!b.found) return `<tr><th scope="row">${esc(b.name)}</th><td>over ${LIMIT.toLocaleString("en-US")}</td><td>over ${F.humanTime(LIMIT / speed)}</td><td>needs luck or a longer run</td></tr>`;
        const med = F.median(b.tries), t = med / speed;
        const fit = BUDGETS.filter((x) => t <= x.s)[0];
        return `<tr><th scope="row">${esc(b.name)}</th><td>${Math.round(med).toLocaleString("en-US")}${b.found < RUNS ? " (" + b.found + "/" + RUNS + " runs)" : ""}</td><td>${F.humanTime(t)}</td><td class="${fit ? (fit.s <= 600 ? "ok" : "y") : "bad"}">${fit ? esc(fit.n) : "longer than a day"}</td></tr>`;
      }).join("");
    }
    click("ci-run", () => {
      if (busy) return;
      busy = true; $("ci-run").disabled = true;
      BUGS.forEach((b) => { b.tries = []; b.found = 0; });
      ran = false; render();
      note("ci-note", "# running…");
      let bi = 0, ri = 0;
      (function next() {
        const b = BUGS[bi];
        const r = F.triesToFind(b.id, { mode: "guided", learn: false, seeds: [SEED_REC] }, [ri + 1], LIMIT)[0];
        if (r) { b.tries.push(r); b.found++; }
        ri++;
        if (ri >= RUNS) { bi++; ri = 0; }
        note("ci-note", "# running… " + (bi * RUNS + ri) + " of " + BUGS.length * RUNS);
        if (bi < BUGS.length) later(next, 0);
        else {
          busy = false; $("ci-run").disabled = false; ran = true; render();
          note("ci-note", "# shallow bugs fall to a short run; deep ones need more tries, so faster harnesses and a kept corpus matter.", "ok");
        }
      })();
    });
    $("ci-speed").addEventListener("change", render);
    render();
  }

  // --------------------------------------------------------------------------- triage: dedupe, shrink
  function triage() {
    let res = null;
    click("tr-run", () => {
      $("tr-run").disabled = true;
      const fz = F.createFuzzer({ mode: "guided", seed: 5, seeds: [SEED_REC], bugs: F.BUG_IDS, stopOnCrash: false, histEvery: 1000 });
      note("tr-note", "# fuzzing…");
      (function tick() {
        fz.step(2000);
        if (fz.state.tries < 20000) { requestAnimationFrame(tick); return; }
        res = fz.state;
        const sites = Object.keys(res.sites).map((k) => res.sites[k]);
        $("tr-raw").textContent = res.rawCrashes.toLocaleString("en-US");
        $("tr-uniq").textContent = sites.length;
        $("tr-body").innerHTML = sites.map((s) => `<tr data-site="${s.site}"><th scope="row"><code>${esc(s.site)}</code><br><small class="m">${esc(s.kind)}</small></th><td>${s.count.toLocaleString("en-US")}</td><td><code>${esc(q(s.first))}</code></td><td class="tr-min">–</td></tr>`).join("");
        $("tr-min").disabled = false; $("tr-run").disabled = false;
        note("tr-note", "# " + res.rawCrashes.toLocaleString("en-US") + " crashes, " + sites.length + " causes. Now shrink one from each group.");
      })();
    });
    click("tr-min", () => {
      if (!res) return;
      $("tr-min").disabled = true;
      Object.keys(res.sites).forEach((k) => {
        const s = res.sites[k];
        const m = F.minimize(s.first, (x) => { const r = F.parseRecord(x, F.BUG_IDS); return !!(r.crash && r.crash.site === s.site); });
        const row = $("tr-body").querySelector(`tr[data-site="${s.site}"] .tr-min`);
        row.innerHTML = `<code>${esc(q(m.result))}</code> <small class="m">${m.tests} tries</small>`;
      });
      note("tr-note", "# short enough to read, report and keep as tests. Fix each cause, then keep these three inputs.", "ok");
    });
  }

  // --------------------------------------------------------------------------- coverage over time
  function measuring() {
    const SERIES = [
      { id: "random", label: "Random text", color: "var(--pink)", opts: { mode: "random" } },
      { id: "mutate", label: "Mutation only", color: "var(--yellow)", opts: { mode: "mutate", seeds: [SEED_REC] } },
      { id: "guided", label: "Coverage-guided", color: "var(--cyan)", opts: { mode: "guided", seeds: [SEED_REC], learn: false } },
      { id: "learn", label: "Guided + comparison tracing", color: "var(--ok)", opts: { mode: "guided", seeds: [SEED_REC], learn: true } }
    ];
    const N = 20000;
    let seed = 2, drawn = false;
    const X0 = 44, X1 = 548, Y0 = 264, Y1 = 12;
    const sx = (t) => X0 + (t / N) * (X1 - X0), sy = (c) => Y0 - (c / TOTAL) * (Y0 - Y1);
    function axes() {
      let s = "";
      [0, 6, 12, 18, 24].forEach((c) => { s += `<line x1="${X0}" x2="${X1}" y1="${sy(c)}" y2="${sy(c)}" style="stroke:var(--line)" stroke-width="1"/><text x="${X0 - 6}" y="${sy(c) + 4}" text-anchor="end" font-size="10" style="fill:var(--muted)">${c}</text>`; });
      [0, 5000, 10000, 15000, 20000].forEach((t) => { s += `<text x="${sx(t)}" y="${Y0 + 16}" text-anchor="middle" font-size="10" style="fill:var(--muted)">${t === 0 ? "0" : t / 1000 + "k"}</text>`; });
      s += `<text x="${(X0 + X1) / 2}" y="${Y0 + 32}" text-anchor="middle" font-size="10" style="fill:var(--muted)">tries</text>`;
      s += `<text x="12" y="${(Y0 + Y1) / 2}" text-anchor="middle" font-size="10" style="fill:var(--muted)" transform="rotate(-90 12 ${(Y0 + Y1) / 2})">branches reached</text>`;
      return s;
    }
    function draw() {
      const out = SERIES.map((s) => {
        const st = F.runFuzz(Object.assign({ seed, bugs: ["fuzz"], stopOnCrash: false, histEvery: 100 }, s.opts), N);
        let lastNew = 0;
        for (let i = 1; i < st.history.length; i++) if (st.history[i].cov > st.history[i - 1].cov) lastNew = st.history[i].tries;
        return { s, st, lastNew };
      });
      let svg = axes();
      out.forEach((o) => {
        let d = "";
        o.st.history.forEach((p, i) => { d += (i ? "L" : "M") + sx(p.tries).toFixed(1) + " " + sy(p.cov).toFixed(1) + " "; });
        svg += `<path d="${d}" fill="none" stroke-width="2.5" style="stroke:${o.s.color}"/>`;
      });
      $("cv-chart").innerHTML = svg;
      $("cv-legend").innerHTML = out.map((o) => `<li><span class="sw" style="background:${o.s.color}"></span>${esc(o.s.label)}: <b>${o.st.cov.size}</b> branches, last new at try ${o.lastNew.toLocaleString("en-US")}</li>`).join("");
      drawn = true;
      const rnd = out[0];
      note("cv-note", rnd.st.cov.size <= 8
        ? "# the flat pink line isn't a bug in the chart. That's the point: it stopped learning almost at once."
        : "# random got " + rnd.st.cov.size + " branches; the guided runs keep climbing.", "y");
    }
    click("cv-run", draw);
    click("cv-again", () => { seed += 7; draw(); });
    draw();
  }

  // --------------------------------------------------------------------------- checklist
  const RV_KEY = "fuzzing-checklist";
  function checklist() {
    $("rv-list").innerHTML = F.CHECKLIST.map((t, i) => `<label><input type="checkbox" data-k="k${i}"> ${esc(t)}</label>`).join("");
    const boxes = Array.from(document.querySelectorAll("#rv-list input[type=checkbox]"));
    let saved = {};
    try { saved = JSON.parse(store(RV_KEY) || "{}"); } catch (e) {}
    boxes.forEach((b) => { b.checked = !!saved[b.dataset.k]; });
    const update = () => {
      const done = boxes.filter((b) => b.checked).length;
      store(RV_KEY, JSON.stringify(Object.fromEntries(boxes.map((b) => [b.dataset.k, b.checked]))));
      const n = $("rv-note"); n.className = "comment";
      if (done === boxes.length) { n.textContent = "# 10 of 10. Go and find the bug before someone else does."; n.classList.add("ok"); }
      else if (!done) n.textContent = "# tick what's true for your team today. Each gap is a ticket, not a failure. Saved in this browser only.";
      else n.textContent = "# " + done + " of " + boxes.length + ". Pick the unticked box that's cheapest to fix this week.";
    };
    boxes.forEach((b) => b.addEventListener("change", update));
    update();
  }

  // --------------------------------------------------------------------------- easter egg: console
  function consoleHint() {
    console.log("%c" + document.title, "font: 700 24px monospace; color: #ff2e88; text-shadow: 0 0 8px #ff2e88");
    console.log("%cWe fuzzed this deck's Base64 code before the talk. Probably.", "font: 14px monospace; color: #00f0ff");
  }

  function boot() {
    consoleHint();
    hero(); gates(); loop(); race(); sanitizers(); property(); targets(); harness(); doctor(); seeds(); structure(); walkthrough(); ci(); triage(); measuring(); checklist();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot); else boot();
})();
