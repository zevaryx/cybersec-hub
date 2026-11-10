/* app.js - the live demos for "Zero-Knowledge Proofs".
   The maths is real (Schnorr proofs on P-256 and a toy curve, Fiat-Shamir with SHA-256, salted commitments, a graph 3-colouring proof,
   Merkle membership, an ECDSA-signed credential; see zk.js and ../../shared/crypto.js), but it is teaching code: never use it for real
   secrets. The zero-knowledge proofs on the membership and age slides are stand-ins and say so. Everything runs in your browser and
   nothing you type is stored or sent (only the checklist's ticks are kept in this browser). */
(function () {
  "use strict";

  // --------------------------------------------------------------------------- helpers
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  function click(id, fn) { $(id).addEventListener("click", fn); }
  function store(key, val) {
    try { if (val === undefined) return localStorage.getItem(key); localStorage.setItem(key, val); } catch (e) {}
    return null;
  }
  function press(group, value) {
    for (const b of group.querySelectorAll("button")) b.setAttribute("aria-pressed", String(b.getAttribute("data-v") === value));
  }
  function seg(id, fn) {
    const g = $(id);
    g.addEventListener("click", (e) => { const b = e.target.closest("button"); if (b && g.contains(b)) { press(g, b.getAttribute("data-v")); fn(b.getAttribute("data-v"), b); } });
  }
  const val = (id) => $(id).querySelector('button[aria-pressed="true"]').getAttribute("data-v");
  const L = window.Lab, Z = window.ZK;
  const TOY = Z.CURVES.toy, P256 = Z.CURVES.p256;
  const nf = (n) => Number(n).toLocaleString("en-US");
  const comment = (id, text, cls) => { const el = $(id); el.textContent = text; el.className = "comment" + (cls ? " " + cls : ""); };
  const rnd = (n) => Number(L.randBelow(BigInt(n)));
  const sp = (cls, t) => `<span class="${cls}">${esc(t)}</span>`;
  const OK = "✓", NO = "✗";
  const short = (v) => { const s = v.toString(16); return s.length > 12 ? s.slice(0, 6) + "…" + s.slice(-4) : s; };
  const num = (C, v) => (C === TOY ? String(v) : "0x" + short(v));
  const pt = (C, P) => (P === null ? "∞" : C === TOY ? `(${P[0]}, ${P[1]})` : `(0x${short(P[0])}, …)`);
  const hx = (b, n = 4) => L.hex(b.subarray(0, n)) + (b.length > n ? "…" : "");
  const pow2 = (n) => 2 ** n;
  const commas = (s) => String(s).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  const fit = (input, min = 4) => { input.style.width = Math.max(min, input.value.length + 1) + "ch"; };

  // --------------------------------------------------------------------------- title terminal: how fast a cheater's odds vanish
  function hero() {
    const input = $("hero-in"), out = $("hero-out");
    const sci = (n) => { const l = n * Math.log10(2), e = Math.floor(l); return `${Math.pow(10, l - e).toFixed(2)} × 10<sup>${nf(e)}</sup>`; };
    const odds = (n) => (n <= 60 ? commas((2n ** BigInt(n)).toString()) : sci(n));
    const conf = (n) => (n > 40 ? "over 99.9999999999%" : (100 * (1 - Math.pow(2, -n))).toFixed(Math.min(12, Math.max(2, Math.ceil(n * 0.30103) + 1))) + "%");
    function render() {
      const raw = input.value.trim(), t = raw.toLowerCase();
      let note = "# type a number of rounds (try 1, 20, 128), or a phrase like 'open sesame'.";
      if (/^-?\d+$/.test(raw) && Math.abs(Number(raw)) <= 100000 && Number(raw) >= 0) {
        const n = Number(raw);
        out.innerHTML =
          `<span class="hl"><b>cheater passes</b>1 in ${n === 0 ? "1" : odds(n)}</span>` +
          `<span class="hl"><b>same as</b>${n === 0 ? "no coin flips" : n === 1 ? "1 coin flip, heads" : nf(n) + " coin flips, all heads"}</span>` +
          `<span class="hl"><b>confidence</b>${n === 0 ? "0%" : conf(n)}</span>` +
          `<span class="hl del"><b>honest prover</b>accepted every time</span>`;
        note = `# ${n} rounds: 1 in 2^${n}. Each extra round halves the cheater's odds.`;
        if (n === 0) note = "# zero rounds: nothing proven, and a cheater passes every time. Even one round changes that.";
        else if (n === 1) note = "# one round: a cheater gets away with it half the time. That's a coin flip, not a proof.";
        else if (n === 10) note = "# ten rounds: about 1 in a thousand (1,024, to be exact).";
        else if (n === 20) note = "# 20 rounds: about 1 in a million. Add 20 more and it's about 1 in a trillion.";
        else if (n === 42) note = "# 42 rounds: about 1 in 4.4 trillion. A good answer to a lot of things.";
        else if (n === 64) note = "# 64 rounds: smaller than 1 in 18 quintillion (2^64 = 18,446,744,073,709,551,616).";
        else if (n === 128) note = "# 128 rounds: 2^128. Cryptographers treat odds this small as never: it's the chance of guessing a given AES-128 key in one try.";
        else if (n === 1000) note = "# a thousand rounds is overkill, but the arithmetic doesn't mind: about 1 in 10^301.";
      } else {
        out.innerHTML = `<span class="hl"><b>cheater passes</b>—</span><span class="hl"><b>same as</b>—</span><span class="hl"><b>confidence</b>—</span><span class="hl del"><b>honest prover</b>—</span>`;
        if (/^-\d+$/.test(raw)) note = "# negative rounds would un-prove things. This terminal only runs forwards.";
        else if (/^\d+$/.test(raw)) note = "# that many rounds would take a while, and the answer wouldn't change.";
        else if (/^\d*\.\d+$/.test(raw)) note = "# half a round isn't a thing: either the verifier asks a question or it doesn't.";
        else if (t === "open sesame") note = "# the password from the story. Say it out loud and it's no longer a secret: that's the problem proofs solve.";
        else if (t === "waldo" || t === "wally") note = "# found him: the one in the striped shirt. Proving that without showing where is slide 5.";
        else if (t === "schnorr") note = "# Schnorr's 1989 identification scheme: the protocol in part 2. Its signature form is used in Bitcoin's BIP340.";
        else if (t === "alice" || t === "bob" || t === "peggy" || t === "victor") note = "# Alice proves, Bob verifies: cryptography's cast. (In zero-knowledge, the traditional names are Peggy, the prover, and Victor, the verifier.)";
      }
      comment("hero-note", note);
    }
    input.addEventListener("input", () => { fit(input, 6); render(); });
    fit(input, 6); render();
  }

  // --------------------------------------------------------------------------- slide 4: the cave
  function cave() {
    let st, lines;
    const reset = () => { st = { streak: 0, rounds: 0, caught: 0 }; lines = []; draw(null); comment("cv-note", ""); $("cv-log").innerHTML = ""; };
    function draw(tok) {
      $("cv-tokA").hidden = tok !== 0; $("cv-tokB").hidden = tok !== 1; $("cv-q").style.visibility = tok === null ? "visible" : "hidden";
      $("cv-bar").style.width = (100 * (1 - Math.pow(2, -st.streak))) + "%";
      $("cv-stat").textContent = `rounds ${st.rounds} · caught ${st.caught} · clean streak ${st.streak}` + (st.streak ? ` · a bluffer would pass ${st.streak} in a row about 1 time in ${nf(pow2(Math.min(st.streak, 50)))}` : "");
    }
    function round(call) {
      const entered = rnd(2), know = val("cv-who") === "know", ok = know || entered === call, L2 = "AB";
      st.rounds++;
      if (ok) st.streak++; else { st.streak = 0; st.caught++; }
      lines.push(`round ${st.rounds}: called ${L2[call]}. ` + (ok
        ? (know ? `Out came the prover from ${L2[call]}` + (entered !== call ? ` (entered ${L2[entered]}, crossed the door)` : "") : `Out came the prover from ${L2[call]} (a lucky guess: entered ${L2[call]})`) + " " + sp("ok", OK)
        : `Nobody came out of ${L2[call]}: the prover had entered ${L2[entered]} and is stuck behind the door ` + sp("bad", NO + " caught")));
      if (lines.length > 40) lines.shift();
      $("cv-log").innerHTML = lines.join("\n"); $("cv-log").scrollTop = $("cv-log").scrollHeight;
      draw(ok ? call : entered);
      let note = "";
      if (!ok) note = "# caught: a bluffer fails here half the time, so the verifier rejects and starts again.";
      else if (know && st.streak === 10) note = "# ten in a row. A bluffer manages that about once in 1,024 tries.";
      else if (!know && st.streak >= 5) note = `# a lucky bluffer: ${st.streak} in a row happens about 1 time in ${nf(pow2(st.streak))}. Keep asking.`;
      comment("cv-note", note, !ok ? "bad" : "");
    }
    click("cv-a", () => round(0)); click("cv-b", () => round(1)); click("cv-rand", () => round(rnd(2)));
    click("cv-ten", () => { for (let i = 0; i < 10; i++) round(rnd(2)); });
    click("cv-reset", reset);
    seg("cv-who", reset);
    reset();
  }

  // --------------------------------------------------------------------------- slide 5: Where's Waldo, with cardboard
  function waldo() {
    const COLS = 12, ROWS = 6, GL = ["+", "x", "o", "#", "%", "&", "@", "*", "~", "="], HUES = ["#00f0ff", "#ff2e88", "#ffd400", "#8affc8", "#b18cff", "#ff9a4a"];
    let pos = 0, shuffles = 0, peek = false, decoy = "o";
    const cell = (g, i, waldoCell) => `<span class="wd-c${waldoCell ? " waldo" : ""}" style="color:${HUES[i % HUES.length]}">${waldoCell ? "W" : g}</span>`;
    function build() {
      pos = rnd(COLS * ROWS);
      let h = "";
      for (let i = 0; i < COLS * ROWS; i++) h += cell(GL[rnd(GL.length)], rnd(6), i === pos);
      $("wd-pic").innerHTML = h;
      decoy = GL[rnd(GL.length)];
      show();
    }
    function show() {
      const found = val("wd-who") === "found";
      $("wd-pic").classList.toggle("covered", !peek);
      $("wd-hole").innerHTML = found ? '<span class="wd-c waldo big">W</span>' : `<span class="wd-c big" style="color:#00f0ff">${decoy}</span>`;
      const v = $("wd-verdict");
      v.className = "verdict " + (found ? "ok" : "bad");
      v.textContent = found ? "The verifier sees the striped figure: accepted. They can't tell where in the picture it was." : "The verifier sees a decoy, not the striped figure: rejected.";
      $("wd-peek").textContent = peek ? "Cover the picture again" : "Peek at the picture (what the verifier must NOT see)";
    }
    click("wd-shuffle", () => {
      shuffles++; build();
      comment("wd-note", shuffles >= 10 ? "# ten shuffles: Waldo has moved house ten times and the verifier's window never changed." : "");
    });
    click("wd-peek", () => { peek = !peek; show(); });
    seg("wd-who", () => { decoy = GL[rnd(GL.length)]; show(); });
    build();
  }

  // --------------------------------------------------------------------------- slide 6: which property is broken?
  function properties() {
    const OPT = ["Completeness", "Soundness", "Zero-knowledge", "None"];
    const Q = [
      ["A prover who really knows the password is turned away one time in ten, because the verifier's equipment glitches.", 0, "An honest prover with a true statement was rejected: completeness failed."],
      ["A bluffer, who doesn't know the password, convinces the verifier every single time.", 1, "A cheater got through: soundness failed."],
      ["After the proof, the verifier can recite the password to a friend.", 2, "The verifier learned the secret itself: zero-knowledge failed."],
      ["Honest provers always pass, a bluffer is caught half the time per round, and the verifier ends up knowing only that the prover knows the word.", 3, "Nothing is broken: that's exactly the cave."],
    ];
    const answered = new Array(Q.length).fill(null);
    $("pr-quiz").innerHTML = Q.map((q, i) => `<div class="q"><p>${esc(q[0])}</p><div class="seg-pick" data-q="${i}" role="group" aria-label="Answer">${OPT.map((o, j) => `<button type="button" data-v="${j}" aria-pressed="false">${o}</button>`).join("")}</div><p class="why" id="pr-why-${i}"></p></div>`).join("");
    $("pr-quiz").addEventListener("click", (e) => {
      const b = e.target.closest("button"), g = b && b.closest("[data-q]");
      if (!g) return;
      const i = Number(g.getAttribute("data-q")), j = Number(b.getAttribute("data-v"));
      press(g, String(j)); answered[i] = j;
      const right = j === Q[i][1], w = $("pr-why-" + i);
      w.className = "why " + (right ? "ok" : "bad"); w.textContent = (right ? "Right. " : "Not quite. ") + Q[i][2];
      const done = answered.filter((a) => a !== null).length, good = answered.filter((a, k) => a === Q[k][1]).length;
      $("pr-score").textContent = `${good} of ${Q.length} right` + (done < Q.length ? ` so far (${done} answered)` : "");
      let note = "";
      if (done === Q.length && good === Q.length) note = "# all four: complete, sound, zero-knowledge, and quiz-proof.";
      else if (done === Q.length && good === 0) note = "# zero: they're easy to mix up. Completeness is about honest provers, soundness about cheaters, zero-knowledge about what the verifier learns.";
      comment("pr-note", note);
    });
    $("pr-score").textContent = "";
  }

  // --------------------------------------------------------------------------- slide 7: repeat the round
  function repeating() {
    const run = (n, mode) => {
      const k = Math.ceil(n / 8), N = 1000; let survived = 0;
      for (let b = 0; b < N; b++) {
        if (mode === "guess") { survived++; continue; }
        const e = L.randBytes(k), c = L.randBytes(k); let same = true;
        for (let i = 0; i < n && same; i++) if (((e[i >> 3] ^ c[i >> 3]) >> (i & 7)) & 1) same = false;
        if (same) survived++;
      }
      return survived;
    };
    function odds(n) { return n <= 60 ? "1 in " + commas((2n ** BigInt(n)).toString()) : "1 in 2^" + n; }
    function show(res) {
      const n = Number($("rp-n").value), mode = val("rp-mode");
      $("rp-n-out").textContent = n;
      let t = `rounds                 ${n}\n` + `a bluffer passes all   ${mode === "guess" ? sp("bad", "every time: the calls are predictable") : odds(n)}`;
      if (res !== undefined) t += `\n1,000 bluffers        ${sp(res > 100 ? "bad" : "ok", nf(res) + " passed")} ${mode === "guess" ? "" : `(expected about ${(1000 / Math.pow(2, n)).toFixed(n > 10 ? 6 : 2)})`}`;
      $("rp-out").innerHTML = t;
    }
    $("rp-n").addEventListener("input", () => { show(); comment("rp-note", ""); });
    seg("rp-mode", () => { show(); comment("rp-note", ""); });
    click("rp-run", () => {
      const n = Number($("rp-n").value), mode = val("rp-mode"), res = run(n, mode);
      show(res);
      let note = "";
      if (mode === "guess") note = "# the verifier's calls were predictable, so every bluffer passed. That's the gap Fiat-Shamir has to close (slide 12).";
      else if (n === 40 && res === 0) note = "# 1,000 bluffers, 40 rounds each: none made it. You'd expect one survivor per 1.1 trillion bluffers.";
      comment("rp-note", note);
    });
    show();
  }

  // --------------------------------------------------------------------------- slide 9: Schnorr, step by step
  function schnorr() {
    let S;
    const C = () => S.C;
    function reset() {
      S = { C: val("sc-curve") === "toy" ? TOY : P256, who: val("sc-who"), step: 0 };
      for (let i = 1; i <= 5; i++) { $("sc-" + i).disabled = i !== 1; $("sc-" + i).className = "btn btn-sm" + (i === 1 ? "" : " btn-ghost"); }
      comment("sc-note", ""); $("sc-stat").textContent = "";
      render();
    }
    function enable(next) {
      for (let i = 1; i <= 5; i++) { $("sc-" + i).disabled = i !== next; $("sc-" + i).className = "btn btn-sm" + (i === next ? "" : " btn-ghost"); }
    }
    function render() {
      const c = S.C, bluff = S.who === "bluff", r = [];
      const row = (name, a, b) => `<tr><th>${name}</th><td>${a}</td><td>${b}</td></tr>`;
      r.push(row("Set up", S.step >= 1 ? (bluff ? "no secret (bluffing)" : `<b>x</b> = ${num(c, S.x)} ${sp("mid", "(secret)")}`) : "", S.step >= 1 ? `<b>Y</b> = x·G = ${pt(c, S.Y)}` : ""));
      r.push(row("Commit", S.step >= 2 ? (bluff ? "guesses the challenge c′ and builds R backwards" : `k = ${num(c, S.k)} ${sp("mid", "(random, used once)")}`) : "", S.step >= 2 ? `<b>R</b> = ${pt(c, S.R)}` : ""));
      r.push(row("Challenge", S.step >= 3 ? `c = ${num(c, S.c)}` : "", S.step >= 3 ? `<b>c</b> = ${num(c, S.c)} ${sp("mid", "(random: the verifier's coin flip)")}` : ""));
      r.push(row("Respond", S.step >= 4 ? (bluff ? `s = ${num(c, S.s)} ${S.c === S.wanted ? "(the guess was right)" : "(a wild guess)"}` : `s = k + c·x mod n = ${num(c, S.s)}`) : "", S.step >= 4 ? `<b>s</b> = ${num(c, S.s)}` : ""));
      r.push(row("Check", "", S.step >= 5 ? `s·G = ${pt(c, S.lhs)}<br>R + c·Y = ${pt(c, S.rhs)}<br>${S.ok ? sp("ok", OK + " accepted") : sp("bad", NO + " rejected")}` : ""));
      $("sc-rows").innerHTML = r.join("");
    }
    function step(n) {
      const c = C();
      if (n === 1) { S.who = val("sc-who"); const kp = Z.keygen(c); S.x = kp.x; S.Y = kp.Y; }
      if (n === 2) {
        if (S.who === "bluff") { const b = Z.bluff(c, S.Y); S.R = b.R; S.wanted = b.wanted; S.answer = b.answer; S.k = null; }
        else { const cm = Z.commit(c); S.k = cm.k; S.R = cm.R; }
      }
      if (n === 3) S.c = Z.challenge(c);
      if (n === 4) S.s = S.who === "bluff" ? (S.c === S.wanted ? S.answer : L.randBelow(c.n)) : Z.respond(c, S.x, S.k, S.c);
      if (n === 5) {
        S.lhs = Z.mul(c, S.s); S.rhs = c.add(S.R, Z.mul(c, S.c, S.Y)); S.ok = Z.eq(S.lhs, S.rhs);
        let note = S.ok ? "# s·G equals R + c·Y: accepted." : "# the two sides differ: rejected.";
        if (S.ok && S.who === "bluff") note = "# accepted, but only because the bluffer guessed the challenge (1 chance in " + nf(c.n) + " on this curve).";
        else if (!S.ok && S.who === "bluff") note = "# rejected: the bluffer guessed the wrong challenge, and can't answer the one actually asked.";
        comment("sc-note", note, S.ok && S.who === "know" ? "ok" : S.ok ? "" : "bad");
      }
      S.step = n; render(); enable(n < 5 ? n + 1 : 0);
    }
    for (let i = 1; i <= 5; i++) click("sc-" + i, () => step(i));
    click("sc-reset", reset);
    seg("sc-curve", reset); seg("sc-who", reset);
    click("sc-bluff", () => {
      const c = val("sc-curve") === "toy" ? TOY : P256, N = 200, kp = Z.keygen(c);
      let pass = 0;
      for (let i = 0; i < N; i++) {
        const guess = Z.challenge(c), asked = Z.challenge(c);
        if (c === TOY) {                               // cheap enough to build and verify every attempt for real
          const b = Z.simulate(c, kp.Y, guess), s = asked === guess ? b.s : L.randBelow(c.n);
          if (Z.verify(c, kp.Y, b.R, asked, s)) pass++;
        } else if (asked === guess) {                  // on P-256 a lucky guess is the only way through, so only then build the proof (it never happens)
          const b = Z.simulate(c, kp.Y, guess);
          if (Z.verify(c, kp.Y, b.R, asked, b.s)) pass++;
        }
      }
      $("sc-stat").textContent = `${pass} of ${N} bluffing provers got through` + (c === TOY ? ` (about ${(N / 19).toFixed(1)} expected: 1 in 19)` : " (about 0 expected: 1 in 2²⁵⁶)");
      let note = "";
      if (c === P256 && pass === 0) note = "# 200 bluffing provers, none through. The odds per attempt are 1 in 2^256, a number with 78 digits.";
      comment("sc-note", note);
    });
    reset();
  }

  // --------------------------------------------------------------------------- slide 10: two answers reveal the secret
  function extract() {
    let S;
    const C = P256, out = () => $("ex-out");
    const reset = () => { S = { step: 0, lines: [] }; enable(1); out().innerHTML = ""; comment("ex-note", ""); };
    function enable(n) { for (let i = 1; i <= 4; i++) { $("ex-" + i).disabled = i !== n; $("ex-" + i).className = "btn btn-sm" + (i === n ? "" : " btn-ghost"); } }
    const draw = () => { out().innerHTML = S.lines.join("\n"); };
    click("ex-1", () => {
      const kp = Z.keygen(C), cm = Z.commit(C); S.x = kp.x; S.Y = kp.Y; S.k = cm.k; S.R = cm.R;
      S.lines = [`prover's secret   x  = ${num(C, S.x)}  ${sp("mid", "(hidden from everyone)")}`, `public            Y  = ${pt(C, S.Y)}`, `commitment        R  = ${pt(C, S.R)}  ${sp("s", "(one R, used for both questions)")}`];
      draw(); enable(2);
    });
    click("ex-2", () => { S.c1 = Z.challenge(C); S.s1 = Z.respond(C, S.x, S.k, S.c1); S.lines.push(`question 1        c₁ = ${num(C, S.c1)}   answer s₁ = ${num(C, S.s1)}   ${sp("ok", OK + " verifies")}`); draw(); enable(3); });
    click("ex-3", () => { S.c2 = Z.challenge(C); S.s2 = Z.respond(C, S.x, S.k, S.c2); S.lines.push(`rewind: question 2  c₂ = ${num(C, S.c2)}   answer s₂ = ${num(C, S.s2)}   ${sp("ok", OK + " verifies")}`); draw(); enable(4); });
    click("ex-4", () => {
      const rec = Z.extract(C, S.c1, S.s1, S.c2, S.s2);
      S.lines.push(`x = (s₁ − s₂) / (c₁ − c₂) = ${num(C, rec)}`, rec === S.x ? sp("ok", `${OK} equals the prover's secret x: two answers to one commitment give it away`) : sp("bad", NO + " mismatch"));
      draw(); enable(0); comment("ex-note", "# the secret, rebuilt from two answers. A prover who can answer both must know it: that's soundness.");
    });
    click("ex-reuse", () => {
      const kp = Z.keygen(C), k = Z.randScalar(C), m1 = "pay Alice 5", m2 = "pay Bob 500";
      const a = Z.sign(C, "strong", kp.x, m1, k), b = Z.sign(C, "strong", kp.x, m2, k), rec = Z.extract(C, a.c, a.s, b.c, b.s);
      S = { step: 9, lines: [
        `a signer signs two different messages with the SAME k:`,
        `"${m1}"   R = ${pt(C, a.R)}   s = ${num(C, a.s)}   ${Z.checkSig(C, "strong", kp.Y, m1, a.R, a.s) ? sp("ok", OK + " valid") : sp("bad", NO)}`,
        `"${m2}"   R = ${pt(C, b.R)}   s = ${num(C, b.s)}   ${Z.checkSig(C, "strong", kp.Y, m2, b.R, b.s) ? sp("ok", OK + " valid") : sp("bad", NO)}`,
        `same R? ${sp("bad", Z.eq(a.R, b.R) ? "yes: k was reused" : "no")}`,
        `anyone computes x = (s₁ − s₂) / (c₁ − c₂) = ${num(C, rec)}`,
        rec === kp.x ? sp("ok", `${OK} that is the private key`) : sp("bad", NO),
      ] };
      draw(); enable(0); comment("ex-note", "# one repeated nonce, one recoverable key: the arithmetic fail0verflow showed on the PS3 in 2010.");
    });
    click("ex-reset", reset);
    reset();
  }

  // --------------------------------------------------------------------------- slide 11: a transcript you can fake
  function simulator() {
    const C = P256, kp = Z.keygen(C);
    let pair, tries = 0, right = 0, run = 0, answered;
    function box(t, i, reveal, real) {
      const ok = Z.verify(C, kp.Y, t.R, t.c, t.s);
      return `<b>Transcript ${"AB"[i]}</b>` + (reveal ? `<span class="pill ${real ? "ok" : "mid"}">${real ? "REAL: prover knew x" : "SIMULATED: no secret"}</span>` : "") +
        `<code>R = ${pt(C, t.R)}</code><code>c = ${num(C, t.c)}</code><code>s = ${num(C, t.s)}</code><span class="${ok ? "ok" : "bad"}">verifier's check: ${ok ? OK + " accepted" : NO + " rejected"}</span>`;
    }
    function draw(reveal) {
      $("sm-a").innerHTML = box(pair[0], 0, reveal, pair[0].real); $("sm-b").innerHTML = box(pair[1], 1, reveal, pair[1].real);
      $("sm-score").textContent = tries ? `your guesses: ${right} of ${tries} right (${Math.round(100 * right / tries)}%) · pure guessing would be about 50%` : "make a guess to start the tally";
    }
    function fresh() {
      const cm = Z.commit(C), c = Z.challenge(C), real = { R: cm.R, c, s: Z.respond(C, kp.x, cm.k, c), real: true }, sim = Object.assign(Z.simulate(C, kp.Y), { real: false });
      pair = rnd(2) === 0 ? [real, sim] : [sim, real]; answered = false; draw(false);
      $("sm-ga").disabled = $("sm-gb").disabled = false;
    }
    function guess(i) {
      if (answered) return; answered = true; tries++;
      const ok = pair[i].real; if (ok) { right++; run++; } else run = 0;
      draw(true); $("sm-ga").disabled = $("sm-gb").disabled = true;
      let note = ok ? "# right this time, but both transcripts have the same distribution: it was a coin flip." : "# wrong: and nothing in the numbers could have told you.";
      if (run >= 5) note = `# ${run} right in a row by chance happens about 1 time in ${nf(pow2(run))}. Both transcripts have the same distribution, so you're lucky, not clever.`;
      else if (tries >= 10 && Math.abs(right / tries - 0.5) <= 0.2) note = "# about half right: exactly what zero knowledge predicts. Nobody can do better than guessing.";
      comment("sm-note", note);
    }
    click("sm-ga", () => guess(0)); click("sm-gb", () => guess(1)); click("sm-new", () => { fresh(); comment("sm-note", ""); });
    fresh();
  }

  // --------------------------------------------------------------------------- slide 12: Fiat-Shamir and its traps
  function fiatShamir() {
    const C = P256, kp = Z.keygen(C);
    let sig = null, sigMode = null, lines = [];
    const hashDesc = { strong: "H(G, Y, R, message)", noR: "H(G, Y, message)   " + "← forgot R", noY: "H(G, R, message)   " + "← forgot Y" };
    const msg = () => $("fs-msg").value;
    const draw = () => { $("fs-out").innerHTML = lines.join("\n"); };
    const reset = () => { sig = null; sigMode = null; lines = []; $("fs-edit").disabled = true; draw(); comment("fs-note", ""); };
    function doSign() {
      const mode = val("fs-mode"), m = msg();
      sig = Z.sign(C, mode, kp.x, m); sigMode = mode;
      lines = [
        `public key  Y = ${pt(C, kp.Y)}`,
        `message     "${esc(m)}"`,
        `commitment  R = ${pt(C, sig.R)}`,
        `challenge   c = ${hashDesc[mode]} = ${num(C, sig.c)}`,
        `response    s = k + c·x = ${num(C, sig.s)}`,
        `anyone checks s·G = R + c·Y:  ${Z.checkSig(C, mode, kp.Y, m, sig.R, sig.s) ? sp("ok", OK + " valid") : sp("bad", NO)}`,
      ];
      draw(); $("fs-edit").disabled = false;
    }
    click("fs-sign", () => {
      doSign();
      const m = msg();
      let note = "# a valid signature: anyone with Y can check it, now or in ten years. No verifier needed.";
      if (!m.length) note = "# an empty message signs fine: the proof is still tied to your key and this commitment.";
      else if (m.trim().toLowerCase() === "attack at dawn") note = "# 'attack at dawn' is signed with a hash of everything: change one letter and the signature dies.";
      comment("fs-note", note);
    });
    click("fs-edit", () => {
      if (!sig) return;
      const m2 = msg() + "0", ok = Z.checkSig(C, sigMode, kp.Y, m2, sig.R, sig.s);
      lines.push("", `edited      "${esc(m2)}"   (same R and s)`, `check:  ${ok ? sp("ok", OK + " valid") : sp("bad", NO + " invalid")}`);
      draw(); comment("fs-note", "# one extra character, so the hash, so the challenge, so the check, all change.");
    });
    click("fs-forge", () => {
      const mode = val("fs-mode"), m = msg();
      if (!sig || sigMode !== mode) doSign();
      const f = Z.forge(C, mode, kp.Y, m), ok1 = Z.checkSig(C, mode, kp.Y, m, f.R, f.s);
      const tw = Z.randScalar(C), tp = Z.transplant(C, mode, kp.Y, m, sig, tw), ok2 = Z.checkSig(C, mode, tp.Y2, m, tp.R, tp.s);
      lines.push("", sp("s", "an attacker with no secret tries two recipes:"),
        `1. pick s first, solve R = s·G − c·Y        ${ok1 ? sp("bad", NO + " FORGED: accepted for Y") : sp("ok", OK + " rejected")}`,
        `2. move your signature to Y′ = Y + t·G      ${ok2 ? sp("bad", NO + " FORGED: valid for the related key Y′") : sp("ok", OK + " rejected")}`);
      draw();
      let note = "# no forgery works against the full hash: the attacker would need an R that fits a challenge that depends on R.";
      if (mode === "noR") note = "# bug A: the challenge doesn't depend on R, so the attacker picks s first and solves for R. That's the simulator from the last slide, now in an attacker's hands.";
      else if (mode === "noY") note = "# bug B: the signature moved to a related key without the secret. This is why Bitcoin's BIP340 puts the public key inside the hash.";
      comment("fs-note", note, mode === "strong" ? "ok" : "bad");
    });
    seg("fs-mode", reset);
    $("fs-msg").addEventListener("input", () => { if (lines.length) reset(); });
    reset();
  }

  // --------------------------------------------------------------------------- slide 14: a sealed envelope
  function commitments() {
    const NONE = new Uint8Array(0), WORDS = ["yes", "no", "maybe", "true", "false", "heads", "tails", "rock", "paper", "scissors", "red", "green", "blue"];
    for (let i = 0; i < 1000; i++) WORDS.push(String(i));
    let cm = null, lines = [];
    const draw = () => { $("cm-out").innerHTML = lines.join("\n"); };
    const need = () => { if (!cm) { lines = [sp("mid", "commit to a value first")]; draw(); return false; } return true; };
    click("cm-commit", () => {
      const v = $("cm-val").value, salted = val("cm-salt") === "salt", c = Z.commitValue(v, salted ? undefined : NONE);
      cm = { v, salted, salt: c.salt, digest: c.digest };
      lines = [`commit to "${esc(v)}"`, `salt     ${salted ? L.hex(c.salt) : sp("bad", "(none)")}`, `digest   ${L.hex(c.digest)}`, sp("s", "# the digest is all the other side sees")];
      draw();
      const t = v.trim().toLowerCase();
      let note = "";
      if (["rock", "paper", "scissors"].includes(t)) note = "# rock-paper-scissors by commitment: both players seal a move, then open them. Nobody can peek or change.";
      comment("cm-note", note);
    });
    click("cm-reveal", () => {
      if (!need()) return;
      const ok = Z.openCommit(cm.digest, cm.v, cm.salt);
      lines.push("", `reveal   "${esc(cm.v)}"${cm.salted ? " + the salt" : ""}`, `SHA-256(salt ‖ value) = digest?  ${ok ? sp("ok", OK + " yes: the envelope opens") : sp("bad", NO)}`);
      draw();
    });
    click("cm-change", () => {
      if (!need()) return;
      const alt = cm.v.trim().toLowerCase() === "rock" ? "paper" : cm.v + "!", ok = Z.openCommit(cm.digest, alt, cm.salt);
      lines.push("", `try to open it as "${esc(alt)}" instead`, `SHA-256(salt ‖ value) = digest?  ${ok ? sp("bad", NO + " yes (broken!)") : sp("ok", OK + " no: the envelope is binding")}`);
      draw();
    });
    click("cm-guess", () => {
      if (!need()) return;
      let found = null, tries = 0;
      for (const w of WORDS) { tries++; if (Z.openCommit(cm.digest, w, NONE)) { found = w; break; } }
      lines.push("", `a guesser hashes ${nf(WORDS.length)} likely values (yes, no, rock, 0 to 999, ...) with no salt`,
        found !== null ? `${sp("bad", NO + " found")} "${esc(found)}" after ${nf(tries)} ${tries === 1 ? "try" : "tries"}: the commitment hid nothing` : `${sp("ok", OK + " no match")} in ${nf(tries)} tries${cm.salted ? ": the 16-byte salt makes guessing hopeless (2^128 salts)" : ": the value wasn't one of the likely ones"}`);
      draw();
      let note = "";
      if (found !== null) note = `# found in ${nf(tries)} ${tries === 1 ? "try" : "tries"}: few possible values and no salt means the envelope was see-through.` + (found === "yes" ? " 'yes' with no salt: anyone finds it in a couple of tries." : "");
      comment("cm-note", note, found !== null ? "bad" : "");
    });
    seg("cm-salt", () => { cm = null; lines = []; draw(); comment("cm-note", ""); });
    $("cm-val").addEventListener("input", () => { cm = null; lines = []; draw(); });
    draw();
  }

  // --------------------------------------------------------------------------- slide 15: proving a puzzle (3-colouring)
  function colouring() {
    const G = Z.GRAPH, CX = 150, CY = 124, R = 96, NS = "http://www.w3.org/2000/svg", NAME = ["cyan", "pink", "yellow"], HUE = ["#00f0ff", "#ff2e88", "#ffd400"];
    const V = G.edges.length, svg = $("gc-svg"), P = [];
    for (let i = 0; i < G.n; i++) { const a = (-90 + (360 / G.n) * i) * Math.PI / 180; P.push([CX + R * Math.cos(a), CY + R * Math.sin(a)]); }
    const mk = (tag, attrs, parent = svg) => { const e = document.createElementNS(NS, tag); for (const k in attrs) e.setAttribute(k, attrs[k]); parent.appendChild(e); return e; };
    G.edges.forEach(([u, v], i) => {
      mk("line", { class: "gc-edge", id: "gc-e" + i, x1: P[u][0], y1: P[u][1], x2: P[v][0], y2: P[v][1] });
      const hit = mk("line", { class: "gc-hit", "data-e": i, x1: P[u][0], y1: P[u][1], x2: P[v][0], y2: P[v][1], tabindex: 0, role: "button", "aria-label": `Challenge the line between circle ${u} and circle ${v}` });
      hit.addEventListener("click", () => round(i));
      hit.addEventListener("keydown", (ev) => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); round(i); } });
    });
    for (let i = 0; i < G.n; i++) { mk("circle", { class: "gc-v", id: "gc-v" + i, cx: P[i][0], cy: P[i][1], r: 14 }); const t = mk("text", { class: "gc-n", id: "gc-t" + i, x: P[i][0], y: P[i][1] + 4, "text-anchor": "middle" }); t.textContent = i; }
    $("gc-rounds").textContent = Z.roundsFor(V, 20);
    let st, lines;
    const clear = () => { for (let i = 0; i < G.n; i++) { const c = $("gc-v" + i); c.style.fill = ""; c.style.stroke = ""; $("gc-t" + i).style.fill = ""; } for (let i = 0; i < V; i++) $("gc-e" + i).classList.remove("on", "bad"); };
    const colouringNow = () => (val("gc-who") === "valid" ? G.colouring : G.cheat);
    function stat() {
      const p = Math.pow(1 - 1 / V, st.rounds), q = p >= 0.01 ? (100 * p).toFixed(1) + "%" : "about 1 in " + (1 / p < 1e15 ? nf(Math.round(1 / p)) : (1 / p).toExponential(1));
      $("gc-stat").textContent = `rounds ${st.rounds} · passed ${st.passed} · caught ${st.caught} · a one-slip cheater survives ${st.rounds} rounds with probability ${q}`;
    }
    function once(ei) {
      const r = Z.colourRound(colouringNow()), e = G.edges[ei], o = Z.openEdge(r, e), res = Z.checkEdge(r, e, o);
      st.rounds++; if (res.ok) st.passed++; else st.caught++;
      if (res.ok && val("gc-who") === "valid") st.seen.add(ei);
      return { r, e, o, res, ei };
    }
    function draw(x) {
      clear();
      const { r, e, o, res, ei } = x;
      $("gc-e" + ei).classList.add(res.ok ? "on" : "bad");
      for (const [i, c] of [[e[0], o.cu], [e[1], o.cv]]) { const el = $("gc-v" + i); el.style.fill = HUE[c]; el.style.stroke = HUE[c]; $("gc-t" + i).style.fill = "#07060f"; }
      lines.push(`round ${st.rounds}: sealed ${r.commits.slice(0, 4).map((c) => hx(c.digest, 2).replace("…", "")).join(" ")} … (8 envelopes)  you picked ${e[0]}-${e[1]}: ${NAME[o.cu]}, ${NAME[o.cv]}  ${res.ok ? sp("ok", OK + " different") : sp("bad", NO + " " + res.why + ": CAUGHT")}`);
      if (lines.length > 30) lines.shift();
      $("gc-log").innerHTML = lines.join("\n"); $("gc-log").scrollTop = $("gc-log").scrollHeight;
      stat();
    }
    function round(ei) {
      const x = once(ei); draw(x);
      let note = "";
      if (!x.res.ok) note = `# caught: line ${x.e[0]}-${x.e[1]} joins two circles of the same colour. A cheater survives each round with probability ${V - 1}/${V}.`;
      else if (val("gc-who") === "valid" && st.seen.size === V && !st.fired) { st.fired = true; note = "# every edge checked, and the colouring still isn't revealed: each round used fresh random colour names."; }
      comment("gc-note", note, !x.res.ok ? "bad" : "");
    }
    function many(max, untilCaught) {
      let last = null, firstCaught = 0, done = 0;
      for (let i = 0; i < max; i++) {
        const x = once(rnd(V)); last = x; done++;
        if (!x.res.ok && !firstCaught) { firstCaught = st.rounds; if (untilCaught) break; }
      }
      draw(last);
      const msg = untilCaught
        ? (firstCaught ? `caught in round ${firstCaught}` : `never caught in ${done} rounds` + (val("gc-who") === "valid" ? ": there was nothing to catch" : ` (a cheater survives that long with probability ${(Math.pow(1 - 1 / V, done)).toExponential(1)})`))
        : `${done} rounds run: ${st.passed} passed, ${st.caught} caught` + (firstCaught ? ` (first catch in round ${firstCaught})` : "");
      lines.push(sp("s", "# " + msg)); $("gc-log").innerHTML = lines.join("\n"); $("gc-log").scrollTop = $("gc-log").scrollHeight;
      comment("gc-note", firstCaught ? "# caught: a cheater survives each round with probability " + (V - 1) + "/" + V + ", so it can take a while." : "", firstCaught ? "bad" : "");
    }
    function reset() { st = { rounds: 0, passed: 0, caught: 0, seen: new Set(), fired: false }; lines = []; clear(); $("gc-log").innerHTML = ""; comment("gc-note", ""); stat(); }
    click("gc-next", () => round(rnd(V))); click("gc-20", () => many(20, false)); click("gc-until", () => many(300, true));
    click("gc-reset", reset); seg("gc-who", reset);
    reset();
  }

  // --------------------------------------------------------------------------- slide 16: prove you're on the list
  function membership() {
    const NAMES = ["Ada", "Bo", "Cy", "Dee", "Eli", "Fay", "Gus", "Hal"], secrets = NAMES.map(() => L.randBytes(16)), commits = secrets.map((s) => L.sha256(s)), tree = Z.merkleTree(commits);
    const g = $("mb-who"); NAMES.forEach((n, i) => { const b = document.createElement("button"); b.type = "button"; b.setAttribute("data-v", i); b.setAttribute("aria-pressed", String(i === 3)); b.textContent = n; g.appendChild(b); });
    let seen = {}, last = null;
    const root = () => hx(tree.root, 5);
    function draw(v) {
      if (!v) { $("mb-plain").textContent = "press a vote button"; $("mb-zk").textContent = "press a vote button"; return; }
      const path = Z.merklePath(tree, v.who), ok = Z.merkleCheck(commits[v.who], path, tree.root);
      $("mb-plain").innerHTML = `root   ${root()}\nleaf   #${v.who} ${hx(commits[v.who], 5)}  ${sp("bad", "= " + NAMES[v.who])}\npath   ${path.map((p) => (p.right ? "R " : "L ") + hx(p.sib, 3)).join("  ")}\ncheck  hashing up the path gives the root  ${ok ? sp("ok", OK) : sp("bad", NO)}\n${sp("bad", "→ the verifier now knows: " + NAMES[v.who] + " voted in " + v.poll)}`;
      $("mb-zk").innerHTML = `root       ${root()}  (public)\npoll       ${v.poll}\nnullifier  ${hx(v.nul, 5)}  ${sp("mid", "H(secret, poll)")}\nproof π    ${v.pi}  ${sp("mid", "(stand-in bytes)")}\ncheck      π is valid for this root  ${sp("ok", OK + " (stand-in)")}\n` +
        (v.dup ? sp("bad", `${NO} REJECTED: this nullifier was already used in ${v.poll}. Second vote refused, voter still unknown.`) : sp("ok", `→ the verifier knows: a list member voted in ${v.poll}. Not who.`));
    }
    function vote(poll) {
      const who = Number(val("mb-who")), nul = Z.nullifier(secrets[who], poll), key = L.hex(nul);
      seen[poll] = seen[poll] || new Set();
      const dup = seen[poll].has(key); seen[poll].add(key);
      const pi = "0x" + L.hex(L.randBytes(5)) + "… (192 bytes)";
      const prev = last; last = { who, poll, nul, pi, dup, key };
      draw(last);
      let note = dup ? "# same secret, same poll, same nullifier: double vote caught, voter still unknown." : "";
      if (!dup && prev && prev.who === who && prev.poll !== poll && prev.key !== key) note = "# new poll, new nullifier: nobody can link the two votes.";
      comment("mb-note", note, dup ? "bad" : "");
    }
    click("mb-v1", () => vote("poll-1")); click("mb-v2", () => vote("poll-2"));
    click("mb-reset", () => { seen = {}; last = null; draw(null); comment("mb-note", ""); });
    seg("mb-who", () => {});
    draw(null);
  }

  // --------------------------------------------------------------------------- slide 17: over 18, without showing your birthday
  function age() {
    const issuer = Z.makeIssuer();
    let cred = null, shown = { A: null, B: null }, years = 34;
    const fp = (sig) => L.hex(L.fromBig ? L.fromBig(sig[0], 32).subarray(0, 4) : new Uint8Array(4));
    function issueNow() {
      years = Math.max(0, Math.min(120, Math.round(Number($("ag-age").value)) || 0));
      const d = new Date(); d.setFullYear(d.getFullYear() - years); d.setDate(d.getDate() - 90);
      cred = Z.issue(issuer, { name: "Sam Example", birthdate: d.toISOString().slice(0, 10), address: "1 Example Street", age_over_18: years >= 18 ? "true" : "false" });
      shown = { A: null, B: null };
    }
    const item = (n) => cred.items.find((i) => i.name === n);
    function learn(rows) { $("ag-learn").innerHTML = rows.map(([ok, t]) => `<li class="${ok ? "ok" : "no"}"><b>${ok ? "learns" : "doesn't learn"}</b> ${esc(t)}</li>`).join(""); }
    function present(shop, cheat) {
      const level = val("ag-level"); let note = "", recv = "", link = "";
      if (level === "1") {
        recv = cred.items.map((i) => `${i.name.padEnd(12)} ${i.value}`).join("\n") + "\n" + sp("mid", "(the shop reads the whole card)");
        learn([[true, "your name"], [true, "your exact birth date"], [true, "your address"], [true, "that you're over 18 (and every shop can keep all of it)"]]);
        shown[shop] = { level, fp: "name + birth date" };
        link = "shops can link you by your name and birth date";
        if (cheat) note = "# on a plain ID the shop just trusts what it sees. Real cards add holograms; a digital version needs a signature (level 2).";
      } else if (level === "2") {
        const pres = Z.present(cred, ["age_over_18"]);
        if (cheat) {
          if (years >= 18) { note = "# you're already over 18, so there's nothing to cheat: the claim is true."; }
          else pres.revealed[0].value = "true";
        }
        const res = Z.checkPresentation(issuer.Q, pres), r0 = pres.revealed[0];
        recv = `claim      ${r0.name} = ${r0.value}   salt ${hx(r0.salt, 4)}\ndigests    ${pres.digests.map((d) => hx(d, 3).replace("…", "")).join(" ")}  (${pres.digests.length} signed digests)\nsignature  r ${num(P256, pres.sig[0])}\nshop checks  signature ${res.sigOk ? sp("ok", OK + " valid") : sp("bad", NO)}  ·  digest ${res.claims[0].ok ? sp("ok", OK + " matches") : sp("bad", NO + " does not match")}`;
        if (res.ok) learn([[true, "that you are over 18: " + r0.value], [false, "your name, birth date or address"], [true, "a signature and digest list that are the same at every shop (a fingerprint)"]]);
        else learn([[false, "anything: the claim was rejected"]]);
        shown[shop] = res.ok ? { level, fp: fp(pres.sig) } : null;
        link = res.ok ? "fingerprint (first bytes of the signature) is the same at every shop" : "";
        if (!note) note = res.ok ? (years >= 18 ? "# one claim, one fact. But the signature is a fingerprint: compare shops A and B." : "# the shop learns the true answer: under 18.") : "# the edited claim doesn't match its signed digest: rejected.";
      } else {
        if (years < 18) {
          recv = sp("bad", "no proof can be made: the statement \"a valid credential says I'm over 18\" is false for this credential.") + "\n" + sp("mid", "(a prover can't satisfy a false statement)");
          learn([[false, "anything: there is nothing to send"]]);
          note = "# no proof exists: a prover can't satisfy a false statement. That's soundness doing its job.";
          shown[shop] = null;
        } else {
          const pi = L.hex(L.randBytes(6));
          recv = `statement  "a credential signed by the issuer says I'm over 18"\nproof π    0x${pi}… (stand-in bytes, fresh every time)\nshop checks  π is valid for this statement and issuer key  ${sp("ok", OK + " (stand-in)")}`;
          learn([[true, "that you are over 18"], [false, "your name, birth date, address, the credential or its signature"]]);
          shown[shop] = { level, fp: pi };
          link = "each proof is different, so there's no fingerprint to compare";
          note = cheat ? "# nothing to cheat with: the proof is either valid or it doesn't exist." : "";
        }
      }
      if (years === 18) note = "# exactly 18: you made it, and the proof says nothing about how recently.";
      else if (years === 0 && level !== "1") note = "# zero years old: congratulations, and no proof for you.";
      $("ag-recv").innerHTML = recv;
      const a = shown.A, b = shown.B;
      let l = link;
      if (a && b) l = level === "3" ? `shop A's proof starts ${a.fp.slice(0, 8)}, shop B's ${b.fp.slice(0, 8)}: nothing in common to compare (stand-in bytes)` : (a.fp === b.fp ? `shop A saw ${a.fp}, shop B saw ${b.fp}: the same, so they can compare notes and tell it's you` : l);
      $("ag-link").textContent = l;
      comment("ag-note", note);
    }
    function refreshAfterChange() { issueNow(); $("ag-recv").innerHTML = ""; $("ag-learn").innerHTML = ""; $("ag-link").textContent = ""; comment("ag-note", ""); }
    click("ag-a", () => present("A", false)); click("ag-b", () => present("B", false)); click("ag-cheat", () => present("A", true));
    $("ag-age").addEventListener("change", refreshAfterChange);
    $("ag-age").addEventListener("input", () => { if ($("ag-age").value !== "") refreshAfterChange(); });
    seg("ag-level", () => { shown = { A: null, B: null }; $("ag-recv").innerHTML = ""; $("ag-learn").innerHTML = ""; $("ag-link").textContent = ""; comment("ag-note", ""); });
    issueNow();
  }

  // --------------------------------------------------------------------------- slide 18: what's the catch?
  function systems() {
    const ROWS = [
      { n: "Schnorr proof (this talk)", setup: false, setupT: "none", size: "tiny: about 512 bits as a signature", tiny: true, pq: false, pqT: "no (discrete logs)" },
      { n: "Groth16 (a SNARK)", setup: true, setupT: "yes, for each program", size: "3 group elements", tiny: true, pq: false, pqT: "no (pairings)" },
      { n: "PLONK-style (a SNARK)", setup: true, setupT: "yes, but one that many programs can share", size: "small: hundreds of bytes", tiny: true, pq: false, pqT: "no (pairings)" },
      { n: "STARK", setup: false, setupT: "none (transparent)", size: "large: tens of KB or more", tiny: false, pq: true, pqT: "believed yes (hash functions only)" },
      { n: "Bulletproofs", setup: false, setupT: "none", size: "674 bytes for a 64-bit range proof, growing slowly", tiny: true, pq: false, pqT: "no (discrete logs)" },
    ];
    function draw() {
      const c1 = $("sy-c1").checked, c2 = $("sy-c2").checked, c3 = $("sy-c3").checked, any = c1 || c2 || c3; let hits = 0;
      $("sy-tbody").innerHTML = ROWS.map((r) => {
        const m = (!c1 || !r.setup) && (!c2 || r.tiny) && (!c3 || r.pq); if (m) hits++;
        return `<tr class="${any ? (m ? "hit" : "dim") : ""}"><th>${esc(r.n)}</th><td>${esc(r.setupT)}</td><td>${esc(r.size)}</td><td>${esc(r.pqT)}</td></tr>`;
      }).join("");
      let note = any ? `# ${hits} of ${ROWS.length} systems fit.` : "";
      if (c1 && c2 && c3) note = "# no setup, small proofs and quantum-safe: pick two. No row has all three (STARKs: no setup and quantum-safe but large; Bulletproofs: no setup and small but not quantum-safe).";
      comment("sy-note", note);
    }
    for (const id of ["sy-c1", "sy-c2", "sy-c3"]) $(id).addEventListener("change", draw);
    draw();
  }

  // --------------------------------------------------------------------------- slide 21: what a proof does not tell you
  function limits() {
    const OPT = ["Yes", "No", "Depends"];
    const Q = [
      ["A valid proof means the statement is true (up to the system's tiny error).", 0, "That's soundness: a false statement is accepted only with negligible probability, assuming the maths holds and the implementation is right."],
      ["The statement is the one you actually care about.", 1, "A proof of \"age is at least 18\" doesn't say whose age. Choosing and checking the statement is a design job."],
      ["The data that went into the statement was honest.", 1, "A proof that a computation ran correctly says nothing about whether its inputs were true."],
      ["The program or circuit that encodes the statement has no bugs.", 1, "A proof is about the encoded statement, bugs included. Frozen Heart and Zcash's 2018 flaw are the same lesson in different places."],
      ["Nobody can tell who you are.", 1, "Network address, timing, how small the crowd is and what else you send can still identify you."],
      ["It will stay secure once large quantum computers exist.", 2, "Discrete-log and pairing-based systems would not; hash-based STARKs are believed to."],
    ];
    const answered = new Array(Q.length).fill(null);
    $("lm-quiz").innerHTML = Q.map((q, i) => `<div class="q" id="lm-q-${i}"><p>${esc(q[0])}</p><div class="seg-pick" data-q="${i}" role="group" aria-label="Answer">${OPT.map((o, j) => `<button type="button" data-v="${j}" aria-pressed="false">${o}</button>`).join("")}</div></div>`).join("");
    $("lm-quiz").addEventListener("click", (e) => {
      const b = e.target.closest("button"), g = b && b.closest("[data-q]");
      if (!g) return;
      const i = Number(g.getAttribute("data-q")), j = Number(b.getAttribute("data-v"));
      press(g, String(j)); answered[i] = j;
      const right = j === Q[i][1], w = $("lm-why");
      $("lm-q-" + i).className = "q " + (right ? "ok" : "bad");
      w.className = "why " + (right ? "ok" : "bad"); w.textContent = (right ? "Right. " : "Not quite. ") + Q[i][2];
      const done = answered.filter((a) => a !== null).length, good = answered.filter((a, k) => a === Q[k][1]).length;
      $("lm-score").textContent = `${good} of ${Q.length} right` + (done < Q.length ? ` so far (${done} answered)` : "");
      comment("lm-note", done === Q.length && good === Q.length ? "# all six: a proof tells you the statement is true, not that it was the right one to ask." : "");
    });
  }

  // --------------------------------------------------------------------------- slide 22: eight questions to ask
  function askList() {
    const Q = [
      "What exactly is the statement being proved, in one plain sentence?",
      "Who is the verifier, and what do they learn besides \"true\"?",
      "Is it interactive? If it uses Fiat-Shamir, does the hash cover the whole statement and every commitment?",
      "Is there a trusted setup? Who ran it, and what happens if its secret leaked?",
      "Which proof system and library is it, and has it been independently reviewed?",
      "What does it assume (discrete logs, pairings, hashes), and does it matter if quantum computers arrive?",
      "Who produced the inputs, and could the prover lie about them?",
      "What still leaks around the proof: network address, timing, linkability between uses?",
    ];
    let ticked = [];
    try { ticked = JSON.parse(store("zk-questions") || "[]"); if (!Array.isArray(ticked)) ticked = []; } catch (e) { ticked = []; }
    $("ask-list").innerHTML = Q.map((q, i) => `<li><label class="chk-line"><input type="checkbox" data-i="${i}"${ticked.includes(i) ? " checked" : ""}> ${esc(q)}</label></li>`).join("");
    function count() {
      const n = $("ask-list").querySelectorAll("input:checked").length;
      $("ask-count").textContent = `${n} of ${Q.length} ticked`;
      comment("ask-note", n === Q.length ? "# all eight. Ask these before trusting any 'zero-knowledge' badge." : "");
    }
    $("ask-list").addEventListener("change", () => {
      ticked = Array.from($("ask-list").querySelectorAll("input:checked")).map((el) => Number(el.getAttribute("data-i")));
      store("zk-questions", JSON.stringify(ticked)); count();
    });
    count();
  }

  // --------------------------------------------------------------------------- easter egg: the console
  function consoleHint() {
    console.log("%cZero-Knowledge Proofs", "font: 700 24px monospace; color: #ff2e88; text-shadow: 0 0 8px #ff2e88");
    console.log("%cThe maths in this page is real. window.ZK holds it: try  const k = ZK.keygen(ZK.CURVES.p256)  then  ZK.sign(ZK.CURVES.p256, 'strong', k.x, 'hi')  and check it with ZK.checkSig(...).", "font: 14px monospace; color: #00f0ff");
  }

  function start() {
    consoleHint();
    for (const f of [hero, cave, waldo, properties, repeating, schnorr, extract, simulator, fiatShamir, commitments, colouring, membership, age, systems, limits, askList]) {
      try { f(); } catch (e) { console.error(f.name, e); }
    }
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
})();
