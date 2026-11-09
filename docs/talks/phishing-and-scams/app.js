/* app.js - the live demos for "Phishing and Scams in the Age of AI".
   Everything here is a simulation in your browser: no link is opened, no message is sent, nothing you type leaves the page. */
(function () {
  "use strict";

  // --------------------------------------------------------------------------- helpers
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const sp = (cls, s) => `<span class="${cls}">${esc(s)}</span>`;
  function click(id, fn) { $(id).addEventListener("click", fn); }
  function store(key, val) {
    try { if (val === undefined) return localStorage.getItem(key); localStorage.setItem(key, val); } catch (e) {}
    return null;
  }

  // --------------------------------------------------------------------------- reading a link (a teaching toy, not a browser)
  const TWO_PART = new Set(["co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "co.jp", "co.in", "co.za", "com.br", "com.mx", "com.cn", "com.sg"]);
  const BRANDS = ["acmebank", "google", "microsoft", "apple", "amazon", "paypal", "github", "netflix", "facebook", "dropbox"];
  const SUSPECT_WORDS = /(secure|verify|login|signin|support|account|update|review|recover)/;
  const SHORTENERS = new Set(["bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rebrand.ly"]);

  function readLink(raw) {
    let s = String(raw).trim();
    if (!s) return null;
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = "https://" + s;
    let u;
    try { u = new URL(s); } catch (e) { return { bad: true }; }
    const host = u.hostname.toLowerCase();
    const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith("[");
    const labels = host.split(".");
    let site = host, sub = "";
    if (!isIp && labels.length >= 2) {
      const n = TWO_PART.has(labels.slice(-2).join(".")) && labels.length >= 3 ? 3 : 2;
      site = labels.slice(-n).join(".");
      sub = labels.slice(0, -n).join(".");
    }
    const sld = isIp ? host : site.split(".")[0];
    const warns = [];
    if (u.username || u.password) warns.push(["bad", "Everything before the @ is only a username. The site you'd reach is " + host + "."]);
    if (isIp) warns.push(["bad", "A raw number instead of a name. Real services almost never ask you to sign in at one."]);
    if (/[^\x00-\x7f]/.test(raw) || host.includes("xn--")) warns.push(["bad", "Look-alike letters: the name uses characters from another alphabet. Browsers show them as xn-- in the real address."]);
    if (u.protocol === "http:") warns.push(["y", "Plain http: no encryption. (A padlock on its own doesn't prove a site is honest, though.)"]);
    if (SHORTENERS.has(host)) warns.push(["y", "A short link hides where it goes. Don't tap it: ask for the full address, or go to the site yourself."]);
    const flat = host.replace(/rn/g, "m").replace(/vv/g, "w").replace(/0/g, "o").replace(/1/g, "l");
    for (const b of BRANDS) {
      if (sld === b) continue;
      if (host.includes(b)) { warns.push(["bad", `The name "${b}" appears, but the real site is ${site}.`]); break; }
      if (flat.includes(b)) { warns.push(["bad", `Looks like "${b}" with letters swapped (rn for m, 1 for l, 0 for o…). The real site is ${site}.`]); break; }
    }
    if (!isIp && sld.includes("-") && SUSPECT_WORDS.test(sld)) warns.push(["y", "Words like secure, verify or login inside the site's own name are a common disguise."]);
    const rest = u.pathname + u.search + u.hash;
    return { u, host, site, sub, isIp, warns, rest: rest === "/" && !/\/$/.test(s.replace(/[?#].*$/, "")) ? "" : rest, port: u.port };
  }

  // the link, split and coloured: the site is what counts
  function lineHtml(r) {
    const user = r.u.username ? r.u.username + (r.u.password ? ":" + r.u.password : "") + "@" : "";
    return sp("lr-dim", r.u.protocol + "//") + (user ? sp("lr-bad", user) : "")
      + (r.sub ? sp("lr-dim", r.sub + ".") : "") + sp("lr-site", r.site) + (r.port ? sp("lr-dim", ":" + r.port) : "") + sp("lr-dim", r.rest);
  }
  function showLink(r, line, real, warn) {
    if (!r) { line.innerHTML = ""; real.textContent = ""; if (warn) warn.innerHTML = ""; return; }
    if (r.bad) { line.innerHTML = sp("lr-bad", "That doesn't parse as a link."); real.textContent = ""; if (warn) warn.innerHTML = ""; return; }
    line.innerHTML = lineHtml(r);
    real.innerHTML = "The site you'd actually reach: " + sp("lr-site", r.site);
    if (warn) warn.innerHTML = r.warns.length
      ? r.warns.map(([k, m]) => `<li class="${k}"><b>${k === "bad" ? "✗" : "!"}</b>${esc(m)}</li>`).join("")
      : `<li class="m"><b>·</b>No warning signs in the address itself. That isn't proof it's safe: the page behind it could still be a copy, or compromised. When in doubt, go to the site yourself.</li>`;
  }

  // --------------------------------------------------------------------------- title: whose link is this?
  function hero() {
    const el = $("hero-in"), v = el.value.trim();
    el.style.width = Math.max(10, el.value.length + 1) + "ch";
    const out = $("hero-out");
    if (!v) { out.innerHTML = sp("m", "usage: whose-link <address>"); $("hero-note").textContent = "# nothing to read. The easiest link to get right."; return; }
    const r = readLink(v);
    if (!r || r.bad) { out.innerHTML = sp("bad", "can't read that as a link"); $("hero-note").textContent = "# try something like accounts.example.org/login"; return; }
    out.innerHTML = `${sp("k", "real site:")} ${sp("lr-site", r.site)}<br>${sp("k", "warnings:")} ${r.warns.length ? sp("bad", String(r.warns.length)) : sp("ok", "none")}`;
    const t = v.toLowerCase().replace(/^https?:\/\//, "").replace(/\/$/, "");
    let note = r.warns.length ? "# the first part says one thing; the part before the first slash says another."
      : "# nothing odd in the address. Still: did you expect this link?";
    if (t === "example.com" || t === "www.example.com") note = "# example.com is reserved for documentation, so it's the one domain nobody can own. Safe to type in any talk.";
    else if (t === "127.0.0.1" || t === "localhost") note = "# home sweet home: this address always points at your own computer.";
    else if (/^(www\.)?youtu\.be\/dqw4w9wgxcq/.test(t) || /^(www\.)?youtube\.com\/watch\?v=dqw4w9wgxcq/.test(t)) note = "# not phishing: a different, much older, prank. Never gonna warn you about this one.";
    else if (/^(www\.)?(google|github|apple|amazon|microsoft)\.com$/.test(t)) note = "# the real one. Even so, a bookmark beats a link in a message.";
    $("hero-note").textContent = note;
  }

  // --------------------------------------------------------------------------- the link reader slide
  function reader() {
    showLink(readLink($("lr-in").value), $("lr-line"), $("lr-real"), $("lr-warn"));
  }
  let longTaps = 0;
  function longLink() {
    longTaps++;
    $("lr-in").value = "https://account-security.acmebank.com." + "secure.review.login.".repeat(Math.min(longTaps + 1, 8)) + "verify-now.net/signin?session=ab12cd34";
    reader();
    if (longTaps >= 3) $("lr-real").innerHTML += " " + sp("m", "(still reading from the right. Long doesn't mean clever.)");
  }

  // --------------------------------------------------------------------------- real or fake quiz
  const QUIZ = [
    { u: "https://accounts.google.com/signin", fake: false, why: "accounts.google.com is a subdomain of google.com. Real." },
    { u: "https://accounts.google.com.security-check.net/signin", fake: true, why: "Read from the right: the site is security-check.net. \"accounts.google.com.\" is only decoration." },
    { u: "https://www.amazon.com/gp/css/order-history", fake: false, why: "www.amazon.com: the site is amazon.com, the path is just a page on it." },
    { u: "https://amazon.com-orders.top/review", fake: true, why: "There's no slash after amazon.com: the whole of \"amazon.com-orders.top\" is the host. The site is com-orders.top." },
    { u: "https://github.com@gist-login.io/session", fake: true, why: "\"github.com@\" is just a username. The host is gist-login.io." },
    { u: "https://rnicrosoft.com/account", fake: true, why: "\"rn\" squeezed together looks like \"m\". It spells rnicrosoft, not microsoft." },
    { u: "https://аpple.com/support", fake: true, why: "The first letter is a Cyrillic \"a\", not a Latin one. The browser shows the real host as xn--pple-43d.com." },
    { u: "https://login.microsoftonline.com/", fake: false, why: "Odd-looking but genuine: microsoftonline.com is where Microsoft's own sign-in lives. Real can look strange: that's why we read the host and don't go by looks." },
    { u: "https://support.apple.com/apple-id", fake: false, why: "support.apple.com: a subdomain of apple.com. Real." },
  ];
  let qi = 0, qscore = 0, qdone = false;
  function quizShow() {
    const q = QUIZ[qi];
    $("lq-count").textContent = `Link ${qi + 1} of ${QUIZ.length}`;
    $("lq-url").textContent = q.u;
    $("lq-verdict").hidden = true; $("lq-next").hidden = true;
    $("lq-line").innerHTML = ""; $("lq-real").textContent = ""; $("lq-why").textContent = "";
    for (const b of $("lq-btns").querySelectorAll("[data-a]")) b.disabled = false;
    qdone = false;
  }
  function quizAnswer(a) {
    if (qdone) return; qdone = true;
    const q = QUIZ[qi], ok = (a === "fake") === q.fake;
    if (ok) qscore++;
    for (const b of $("lq-btns").querySelectorAll("[data-a]")) b.disabled = true;
    const v = $("lq-verdict"); v.hidden = false;
    v.className = "verdict " + (ok ? "ok" : "bad");
    v.textContent = (ok ? "Correct" : "Not quite") + ": it's " + (q.fake ? "fake" : "real") + ".";
    const r = readLink(q.u);
    showLink(r, $("lq-line"), $("lq-real"), null);
    $("lq-why").textContent = "# " + q.why;
    $("lq-score").textContent = `Score: ${qscore} / ${qi + 1}`;
    $("lq-next").hidden = false;
    $("lq-next").textContent = qi === QUIZ.length - 1 ? "See score" : "Next ›";
  }
  function quizNext() {
    if (qi < QUIZ.length - 1) { qi++; quizShow(); return; }
    const n = QUIZ.length;
    let m = `Final score: ${qscore} / ${n}.`;
    if (qscore === n) m += " # perfect. Eagle eyes. Now remember it only has to go wrong once, so keep the bookmarks.";
    else if (qscore === 0) m += " # zero. Someone has to be the control group, and everyone starts here. The rule is right-to-left: try again.";
    else if (qscore >= n - 2) m += " # very good. The ones that slip past are the ones the scammers hope for.";
    else m += " # a good start: scammers are practised at exactly this. Try again with the right-to-left rule.";
    $("lq-score").textContent = m;
    $("lq-url").textContent = "Round over";
    $("lq-count").textContent = "";
    $("lq-verdict").hidden = true; $("lq-line").innerHTML = ""; $("lq-real").textContent = ""; $("lq-why").textContent = "";
    $("lq-btns").querySelector("[data-a=real]").hidden = true; $("lq-btns").querySelector("[data-a=fake]").hidden = true;
    $("lq-next").textContent = "Play again"; $("lq-next").onclick = () => {
      qi = 0; qscore = 0;
      for (const b of $("lq-btns").querySelectorAll("[data-a]")) b.hidden = false;
      $("lq-next").onclick = null; $("lq-score").textContent = ""; quizShow();
    };
  }

  // --------------------------------------------------------------------------- the pressure-trick highlighter (a toy: ~60 phrases)
  const TRICKS = {
    urg: { name: "Urgency", re: /\b(urgent(ly)?|immediately|right (now|away)|asap|within \d+ (minutes?|hours?|days?)|expires?|expiring|last chance|final notice|act now|today only|before it'?s too late|deadline|quickly|hurry)\b/gi },
    auth: { name: "Authority", re: /\b(your bank|the bank|police|tax office|irs|government|security team|it department|help ?desk|ceo|cfo|your (boss|manager)|support team|official|court|officer|microsoft|amazon|apple)\b/gi },
    fear: { name: "Fear", re: /\b(suspended|suspend|closed|locked|arrest(ed)?|warrant|legal action|unauthori[sz]ed|unusual (sign-?in|activity)|suspicious activity|compromised|hacked|virus|penalty|fine|lose access|deleted|frozen|blocked)\b/gi },
    sec: { name: "Secrecy", re: /\b(don'?t tell( anyone)?|do not tell|keep (this|it) (between us|secret|confidential)|confidential|private matter|don'?t call|do not (call|contact|discuss)|tell no one|between us|don'?t hang up|handle this)\b/gi },
    rew: { name: "Reward", re: /\b(congratulations|winner|you'?ve won|you have won|prize|free|refund|reward|bonus|claim your|selected|lottery|inheritance|cash)\b/gi },
    ask: { name: "The ask", re: /\b(gift cards?|wire|bitcoin|crypto(currency)?|western union|zelle|pay (now|a small)|shipping fee|one-?time code|verify( now| your)?|click( the| this)? link|download|install|remote access|password|send me the codes?|codes?)\b/gi },
  };
  const SAMPLES = {
    bank: "URGENT: Unusual sign-in detected on your Acme Bank account. Your account will be suspended within 2 hours unless you verify now. Click the secure link and enter the one-time code we send you. Do not call the branch: our security team will handle this.",
    boss: "Hi, it's your manager. I'm in a meeting and can't talk. I need you to buy 5 gift cards for a client today. It's confidential, don't tell anyone yet. I'll reimburse you. Send me the codes right away.",
    prize: "Congratulations! You've been selected as a winner of a free $500 gift card. Claim your reward today only, before it expires. Just pay a small shipping fee.",
    boring: "Hi Sam, the printer on floor 2 is fixed. Lunch is at noon on Thursday; reply if you can't make it. Thanks!",
  };
  let sampleKey = "";
  function highlight() {
    const text = $("tk-in").value;
    const hits = [];
    for (const [k, t] of Object.entries(TRICKS)) {
      t.re.lastIndex = 0; let m;
      while ((m = t.re.exec(text))) { hits.push({ k, s: m.index, e: m.index + m[0].length }); if (m[0].length === 0) t.re.lastIndex++; }
    }
    hits.sort((a, b) => a.s - b.s || b.e - a.e);
    const kept = []; let end = 0;
    for (const h of hits) if (h.s >= end) { kept.push(h); end = h.e; }
    let html = "", pos = 0;
    for (const h of kept) { html += esc(text.slice(pos, h.s)) + `<mark class="m-${h.k}">${esc(text.slice(h.s, h.e))}</mark>`; pos = h.e; }
    html += esc(text.slice(pos));
    $("tk-out").innerHTML = html || sp("m", "(nothing yet)");
    const counts = {}; for (const h of kept) counts[h.k] = (counts[h.k] || 0) + 1;
    $("tk-chips").innerHTML = Object.entries(TRICKS).map(([k, t]) => `<span class="chip m-${k}${counts[k] ? " on" : ""}">${t.name}${counts[k] ? " · " + counts[k] : ""}</span>`).join("");
    const kinds = Object.keys(counts).filter((k) => k !== "ask").length;
    let note;
    if (!text.trim()) note = "# paste a message, or pick a sample. (Invented examples only.)";
    else if (!kept.length) note = sampleKey === "boring" ? "# no tricks found. Boring is good: an ordinary message asks for nothing and rushes no one." : "# no known phrases found. That doesn't make it safe: this toy only knows about sixty. Check what's being asked.";
    else if (kinds >= 3) note = `# ${kinds} different pressure tricks in one message. Scammers stack them, because each one makes the others harder to resist.`;
    else if (counts.ask && !kinds) note = "# no pressure, but there's an ask. Still worth checking who is asking, and how.";
    else note = "# that's the pattern: a feeling first, then a request.";
    $("tk-note").textContent = note;
  }
  function pickSample(k) {
    sampleKey = k; $("tk-in").value = SAMPLES[k];
    for (const b of $("tk-samples").querySelectorAll("button")) b.setAttribute("aria-pressed", String(b.dataset.s === k));
    highlight();
  }

  // --------------------------------------------------------------------------- who is it really from?
  function mail() {
    const on = $("mail-toggle").getAttribute("aria-pressed") !== "true";
    $("mail-toggle").setAttribute("aria-pressed", String(on));
    $("mail-toggle").textContent = on ? "Hide the real sender" : "Show the real sender";
    for (const r of document.querySelectorAll("#mail .mail-more")) r.hidden = !on;
    $("mail-note").textContent = on
      ? "# acmebank-notices.net isn't acmebank.com, and replies go to a third domain. The display name is just text the sender typed."
      : "";
  }

  // --------------------------------------------------------------------------- password manager vs a fake site
  const SAVED = "acmebank.com";
  let handTaps = 0;
  function manager() {
    const r = readLink($("pm-site").value);
    $("pm-bar").innerHTML = lineHtml(r);
    const match = r.site === SAVED;
    $("pm-user").value = ""; $("pm-pass").value = "";
    $("pm-fill").hidden = !match;
    $("pm-status").innerHTML = match
      ? sp("ok", "Match found") + `: a saved login for ${esc(SAVED)}. It can fill the form.`
      : sp("bad", "No saved login for this site") + `. It knows ${esc(SAVED)}; this page is ${esc(r.site)}.`;
    $("pk-status").innerHTML = match
      ? sp("ok", "Passkey available") + ": made for " + esc(SAVED) + "."
      : sp("bad", "No passkey offered") + ": passkeys only work on the site they were made for.";
    $("pm-note").textContent = match ? "# both tools agree: this is the site you registered with." : "# the logo and wording on the page look identical. The tools don't read those. They compare the real address.";
    handTaps = 0;
  }
  function byHand() {
    const r = readLink($("pm-site").value);
    handTaps++;
    if (r.site === SAVED) { $("pm-note").textContent = "# this is the real site: typing here is fine. (The manager would have done it for you.)"; return; }
    $("pm-note").textContent = handTaps >= 3
      ? "# third time. The password manager is now just looking at you."
      : `# whatever you type here goes to ${r.site}, not your bank. That's exactly what a fake page collects. If you've done it, part 3 is for you.`;
  }
  function fill() { $("pm-user").value = "sam.rivera"; $("pm-pass").value = "••••••••••••"; $("pm-note").textContent = "# filled, on the real site only. That refusal elsewhere is the feature."; }

  // --------------------------------------------------------------------------- family code phrase
  const WORDS = ("teapot lantern walrus meadow cobalt biscuit orbit pepper harbor violin marble thistle comet puddle saffron anchor " +
    "bramble quill hammock juniper pebble velvet maple cricket lagoon tulip nutmeg beacon cactus gadget willow ember copper " +
    "sparrow mitten canyon radish pickle compass bobbin walnut zephyr doodle cinder paddle sundial rooster kettle tangle meringue " +
    "otter lemon fiddle glacier poncho turnip yonder button muffin raven oyster cobweb galaxy barley").split(" ");
  let rolls = 0;
  function phrase() {
    const idx = new Uint32Array(3); crypto.getRandomValues(idx);
    $("cp-out").textContent = Array.from(idx, (n) => WORDS[n % WORDS.length]).join(" ");
    rolls++;
    $("cp-note").textContent = rolls >= 10 ? "# picky! Good: a phrase you'll actually remember beats a perfect one you won't." : "";
  }

  // --------------------------------------------------------------------------- what would you do?
  const DRILL = [
    { s: "Your manager's name appears on a text from an unknown number: \"Quick favour, are you at your desk?\" Then: \"I'm in a meeting. Can you buy 4 gift cards for a client? I'll pay you back.\"",
      o: [["Buy them. It's the boss.", "bad", "Authority and urgency, with gift cards as the ask. Gift cards are the payment method scammers prefer, because they're hard to trace and recover."],
          ["Reply asking where to send the receipt.", "bad", "You're still talking inside the scammer's channel. Any reply tells them the number is live."],
          ["Don't reply there. Contact your manager on a number or app you already use, and tell the security team.", "ok", "The call-back rule. A real manager will understand, and the security team gets a heads-up for others."]] },
    { s: "A phone call, in a voice that sounds just like your grandchild: \"Gran, I'm in trouble. Please don't tell Mum. I need money for bail, today.\"",
      o: [["Send the money. It's their voice.", "bad", "A short audio clip is enough to clone a voice. Panic plus secrecy is the script."],
          ["Ask a question only they'd know.", "meh", "Better than nothing, but answers can be found online or guessed, and the caller can bluff. It's a weaker check than a call-back."],
          ["Hang up, ring them or their parent on the number you have, and use the family code phrase.", "ok", "Exactly: you start the contact, and the phrase is something a clone can't know."]] },
    { s: "An email that looks like it's from your IT team: \"Your mailbox is full. Sign in within 24 hours to keep your account.\" The link goes to acmecorp-mail.help.",
      o: [["Sign in quickly before it closes.", "bad", "Urgency and fear, and the link's real site is acmecorp-mail.help, not your company."],
          ["Reply to ask if it's real.", "meh", "The reply goes to whoever sent it, so you'd be asking the scammer. Check another way."],
          ["Don't click. Open your mail from your bookmark and press Report phishing.", "ok", "You went yourself, and reporting protects colleagues who got the same message."]] },
  ];
  let di = 0, dscore = 0, ddone = false;
  function drillShow() {
    const d = DRILL[di];
    $("dr-count").textContent = `Scene ${di + 1} of ${DRILL.length}`;
    $("dr-story").textContent = d.s;
    $("dr-opts").innerHTML = d.o.map((o, i) => `<button type="button" class="btn btn-ghost dr-opt" data-i="${i}">${esc(o[0])}</button>`).join("");
    $("dr-verdict").hidden = true; $("dr-why").textContent = ""; $("dr-next").hidden = true; ddone = false;
  }
  function drillPick(i) {
    if (ddone) return; ddone = true;
    const o = DRILL[di].o[i];
    for (const b of $("dr-opts").querySelectorAll("button")) b.disabled = true;
    $("dr-opts").children[i].classList.add("picked");
    if (o[1] === "ok") dscore++;
    const v = $("dr-verdict"); v.hidden = false;
    v.className = "verdict " + (o[1] === "ok" ? "ok" : o[1] === "meh" ? "y" : "bad");
    v.textContent = o[1] === "ok" ? "Good call" : o[1] === "meh" ? "Better than nothing" : "That's what they're counting on";
    $("dr-why").textContent = o[2];
    $("dr-next").hidden = false; $("dr-next").textContent = di === DRILL.length - 1 ? "See score" : "Next ›";
  }
  function drillNext() {
    if (di < DRILL.length - 1) { di++; drillShow(); return; }
    $("dr-score").textContent = dscore === DRILL.length ? "# 3 of 3: every time, you moved the conversation to a channel you control. That's the whole skill." : `# ${dscore} of ${DRILL.length} first choices were the strongest. The strongest answer is always the same: leave the thread, contact them yourself.`;
    $("dr-opts").innerHTML = ""; $("dr-story").textContent = "That's all three."; $("dr-count").textContent = "";
    $("dr-verdict").hidden = true; $("dr-why").textContent = ""; $("dr-next").textContent = "Play again"; $("dr-next").onclick = () => { di = 0; dscore = 0; $("dr-next").onclick = null; $("dr-score").textContent = ""; drillShow(); };
  }

  // --------------------------------------------------------------------------- the first hour (kept in this browser only)
  const FH_KEY = "phishing-first-hour";
  function firstHour() {
    const boxes = Array.from(document.querySelectorAll("#fh-plan input[type=checkbox]"));
    let saved = {};
    try { saved = JSON.parse(store(FH_KEY) || "{}"); } catch (e) {}
    boxes.forEach((b) => { b.checked = !!saved[b.dataset.k]; });
    const update = () => {
      const done = boxes.filter((b) => b.checked).length;
      store(FH_KEY, JSON.stringify(Object.fromEntries(boxes.map((b) => [b.dataset.k, b.checked]))));
      const note = $("fh-note"); note.className = "comment";
      if (done === boxes.length) { note.textContent = "# all done. Now go and drink some water: reporting fast beat being flawless, and you just did it."; note.classList.add("ok"); }
      else if (done === 0) note.textContent = "# tick them off as you go. They're saved in this browser only.";
      else note.textContent = `# ${done} of ${boxes.length} done. The first few matter most.`;
    };
    boxes.forEach((b) => b.addEventListener("change", update));
    update();
  }

  // --------------------------------------------------------------------------- console hint
  function consoleHint() {
    console.log("%cPhishing and Scams in the Age of AI", "font: 700 24px monospace; color: #ff2e88; text-shadow: 0 0 8px #ff2e88");
    console.log("%cThe real site in any link is just before the first slash, read from the right. Try a link with an @ in it, or a very long one.", "font: 14px monospace; color: #00f0ff");
  }

  function start() {
    consoleHint();
    $("hero-in").addEventListener("input", hero); hero();
    $("lr-in").addEventListener("input", reader);
    for (const b of $("lr-presets").querySelectorAll("button[data-u]")) b.addEventListener("click", () => { $("lr-in").value = b.dataset.u; reader(); });
    click("lr-long", longLink); reader();
    for (const b of $("lq-btns").querySelectorAll("[data-a]")) b.addEventListener("click", () => quizAnswer(b.dataset.a));
    $("lq-next").addEventListener("click", () => { if (!$("lq-next").onclick) quizNext(); });
    quizShow();
    for (const b of $("tk-samples").querySelectorAll("button")) b.addEventListener("click", () => pickSample(b.dataset.s));
    $("tk-in").addEventListener("input", () => { sampleKey = ""; for (const b of $("tk-samples").querySelectorAll("button")) b.setAttribute("aria-pressed", "false"); highlight(); });
    pickSample("bank");
    click("mail-toggle", mail);
    $("pm-site").addEventListener("change", manager); click("pm-hand", byHand); click("pm-fill", fill); manager();
    click("cp-go", phrase);
    $("dr-opts").addEventListener("click", (e) => { const b = e.target.closest("[data-i]"); if (b) drillPick(+b.dataset.i); });
    $("dr-next").addEventListener("click", () => { if (!$("dr-next").onclick) drillNext(); });
    drillShow();
    firstHour();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
})();
