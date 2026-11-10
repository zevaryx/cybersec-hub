/* app.js - the live demos for "Privacy Tools Explained".
   Everything here is a simulation in your browser: no real network traffic, and nothing you type is stored or sent.
   The onion layers and the "who holds the key" lab use real AES-128-GCM from ../../shared/crypto.js (teaching code, never for real data). */
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
  function press(group, attr, value) {
    for (const b of group.querySelectorAll("button")) b.setAttribute("aria-pressed", String(b.getAttribute(attr) === value));
  }
  const L = window.Lab;
  const hexp = (b, n = 10) => L.hex(b.subarray(0, n)) + (b.length > n ? "…" : "");

  // --------------------------------------------------------------------------- the nine tools (used by the terminal and the explorer)
  const TOOLS = [
    { id: "https", label: "HTTPS", name: "HTTPS (the padlock)",
      alias: ["https", "padlock", "tls", "ssl", "http"],
      hide: "The pages you read and anything you type, from everyone on the path: the café, your provider, whoever shares the network.",
      trust: "The website you're talking to, and the certificate system that proves who it is.",
      still: "That you connected to this site (its name and address), when, and how much data moved.",
      s: ["pages and passwords, from the café and your provider", "the website and the certificate system", "that you went to the site, and when"] },
    { id: "dns", label: "Private DNS + ECH", name: "Private DNS and Encrypted ClientHello",
      alias: ["dns", "private dns", "encrypted dns", "doh", "dot", "ech", "encrypted clienthello", "sni"],
      hide: "The site names your device looks up (and, with ECH, the name in the handshake), from the network between you and the resolver.",
      trust: "The resolver you chose: it sees every lookup, instead of your provider.",
      still: "The addresses you connect to, and how much data moves.",
      s: ["site names, from the network on the path", "the resolver you chose", "the addresses you connect to"] },
    { id: "vpn", label: "VPN", name: "A VPN",
      alias: ["vpn", "virtual private network"],
      hide: "Which sites you visit, from the network you're on (the café) and from your internet provider: they see one encrypted tunnel.",
      trust: "The VPN company: it sees what your provider used to see.",
      still: "Everything the websites and trackers see: your logins, cookies and browser fingerprint.",
      s: ["your sites, from the café and your provider", "the VPN company", "what websites and trackers see"] },
    { id: "tor", label: "Tor", name: "Tor",
      alias: ["tor", "tor browser", "onion routing"],
      hide: "Who you are from the website, and where you're going from each relay: no single relay knows both.",
      trust: "That the relays you got aren't watched at both ends, and that you don't identify yourself some other way.",
      still: "That you use Tor (to your provider), anything you sign in to, and plain HTTP at the exit. It's slower.",
      s: ["who you are, from the site; where you go, from each relay", "the relays, and your own habits", "that you use Tor; what you sign in to"] },
    { id: "incognito", label: "Private window", name: "A private window",
      alias: ["incognito", "private window", "private browsing", "private mode", "inprivate"],
      hide: "Your history, cookies and form entries, from other people who use the same device.",
      trust: "The browser, to forget what it says it forgets.",
      still: "Everything on the network: your provider, your employer and the sites themselves can still see.",
      s: ["your history, from the next person on this device", "the browser, to forget", "everything on the network"] },
    { id: "messenger", label: "E2E messenger", name: "An end-to-end encrypted messenger",
      alias: ["signal", "whatsapp", "imessage", "messenger", "e2ee", "end-to-end", "end to end", "encrypted messenger"],
      hide: "What you write, from the app's company, the network and anyone who intercepts it.",
      trust: "The app's code, and the person at the other end (and their phone).",
      still: "Metadata: who, when and how often, to a degree that depends on the app.",
      s: ["what you write, from the company and the network", "the app, and the person you write to", "who, when and how often (metadata)"] },
    { id: "backup", label: "E2E backup", name: "An end-to-end encrypted backup",
      alias: ["backup", "icloud", "adp", "encrypted backup", "e2ee backup", "advanced data protection"],
      hide: "Your backup's contents, from the cloud company and from anyone who gets into it or makes it comply.",
      trust: "Yourself: lose the key and the backup is gone for good.",
      still: "That a backup exists, how big it is, and when it changes.",
      s: ["your backup, from the cloud company", "you, and your key", "that it exists, its size, when it changes"] },
    { id: "disk", label: "Disk encryption", name: "Disk encryption",
      alias: ["disk", "bitlocker", "filevault", "full disk", "luks", "disk encryption", "encryption"],
      hide: "Everything on a lost or stolen device that's off or locked.",
      trust: "The lock and the key: if a company holds a copy, it can be asked for it.",
      still: "Anything on a device you're signed in to: malware and anyone at the unlocked screen see it all.",
      s: ["a lost laptop's contents", "the lock, and whoever holds the key", "everything while you're signed in"] },
    { id: "blocker", label: "Tracker blocking", name: "A tracker blocker in your browser",
      alias: ["blocker", "tracker blocker", "adblock", "ad blocker", "privacy badger", "ublock", "tracking protection", "gpc"],
      hide: "Your browsing across sites, from the advertisers and data brokers that use cross-site cookies and trackers.",
      trust: "Your browser, and the list of trackers it uses.",
      still: "What the site you're on, and the company behind it, can see. Sites you sign in to know who you are.",
      s: ["your browsing across sites, from trackers", "your browser, and its tracker list", "what the site you're on sees"] },
  ];
  function findTool(v) {
    const t = v.trim().toLowerCase();
    if (!t) return null;
    return TOOLS.find((x) => x.alias.includes(t)) ||
      TOOLS.find((x) => x.alias.some((a) => t.startsWith(a + " ") || t.endsWith(" " + a) || t.includes(" " + a + " "))) || null;
  }

  // --------------------------------------------------------------------------- the title terminal
  function hero() {
    const raw = $("hero-in").value, v = raw.trim().toLowerCase();
    const out = $("hero-out"), note = $("hero-note");
    note.className = "comment";
    if (!v || ["nothing", "none", "no tool", "nada"].includes(v)) {
      out.innerHTML = [["tool", "none"], ["hides", "nothing"], ["trust now", "no one new"], ["still sees", "everything the path always saw"]].map(hl).join("");
      note.textContent = "# no tool, no change: everyone along the path sees what they always saw. That's where the talk starts.";
      return;
    }
    const egg = {
      "curtains": "# the original privacy tool: it hides you from the street and trusts everyone inside the house. The same question applies.",
      "curtain": "# the original privacy tool: it hides you from the street and trusts everyone inside the house. The same question applies.",
      "envelope": "# an envelope hides the letter and shows the address. That's content versus metadata, and it comes back in part 3.",
      "tinfoil hat": "# the classic privacy tool for a threat that isn't there. A threat model starts with who is really watching.",
      "onion": "# Tor's logo is an onion because the traffic is wrapped in layers. Slide 8 peels them.",
    }[v];
    if (egg) {
      out.innerHTML = [["tool", v], ["hides", "that's the joke"], ["trust now", "whoever is looking"], ["still sees", "see the note below"]].map(hl).join("");
      note.textContent = egg; note.classList.add("ok");
      return;
    }
    const t = findTool(v);
    if (!t) {
      out.innerHTML = [["tool", v.slice(0, 32)], ["hides", "?"], ["trust now", "?"], ["still sees", "?"]].map(hl).join("");
      note.textContent = "# not in my short list. Ask the same question anyway: hidden from whom, and who do I trust now? Try https, dns, vpn, tor, signal, backup, disk or incognito.";
      return;
    }
    out.innerHTML = [["tool", t.name], ["hides", t.s[0]], ["trust now", t.s[1]], ["still sees", t.s[2]]].map(hl).join("");
    note.textContent = "# every tool answers the same question. Click through all nine on slide 5.";
  }
  function hl([k, text]) {
    const cls = k === "trust now" ? "trust" : k === "still sees" ? "still" : "";
    return `<span class="hl ${cls}"><b>${esc(k)}</b> ${esc(text)}</span>`;
  }

  // --------------------------------------------------------------------------- slide 5: the tool explorer
  let toolSel = "vpn";
  function toolDraw() {
    const g = $("tp-tools");
    if (!g.children.length) {
      for (const t of TOOLS) {
        const b = document.createElement("button");
        b.type = "button"; b.textContent = t.label; b.dataset.id = t.id;
        b.addEventListener("click", () => { toolSel = t.id; toolDraw(); });
        g.appendChild(b);
      }
    }
    press(g, "data-id", toolSel);
    const t = TOOLS.find((x) => x.id === toolSel);
    $("tp-name").textContent = t.name;
    $("tp-hide").textContent = t.hide; $("tp-trust").textContent = t.trust; $("tp-still").textContent = t.still;
  }

  // --------------------------------------------------------------------------- slide 6: who sees what on the way
  const li = (c, t) => ({ c, t });
  function pathBoxes(conn, route) {
    const http = conn === "http";
    const net = [], isp = [], mid = [], site = [], trk = [];
    // the network you are on (café) and your provider
    if (route === "direct") {
      if (http) { net.push(li("bad", "Every page, form and password, in plain text.")); isp.push(li("bad", "Every page, form and password, in plain text, and it may keep a record.")); }
      else {
        net.push(li("mid", "That you connected to this site (its name and address), when, and how much data. Not the pages or passwords."));
        isp.push(li("mid", "Which sites you visit, when and how much. Not the pages."), li("mid", "An FTC study found many providers collect and use more data than people expect."));
      }
    } else if (route === "vpn") {
      net.push(li("ok", "One encrypted tunnel to the VPN's server, and how much data. Not the sites, pages or passwords."));
      isp.push(li("ok", "One encrypted tunnel to the VPN, not the sites."));
    } else {
      net.push(li("ok", "An encrypted connection to a Tor relay, and how much data. Not the sites or pages."), li("mid", "That you're using Tor: the list of relays is public."));
      isp.push(li("ok", "Connections to Tor relays, not the sites."), li("mid", "That you use Tor."));
    }
    // the middle of the route
    let midBox;
    if (route === "direct") midBox = { off: true, title: "No middleman", role: "You connect straight to the site", items: [li("mid", "No VPN or relays on this route.")] };
    else if (route === "vpn") {
      mid.push(http ? li("bad", "Everything, in plain text: the sites, the pages, the passwords.") : li("mid", "Which sites you visit, when and how much. Not the pages or passwords."));
      mid.push(li("mid", "Your real address."), li("mid", "It sees what your provider used to see."));
      midBox = { title: "The VPN company", role: "End of the tunnel", items: mid };
    } else {
      mid.push(li("ok", "Guard: your address, not the site."), li("ok", "Middle: neither."));
      mid.push(http ? li("bad", "Exit: the site and the page, in plain text. Not your address.") : li("mid", "Exit: the site's name. Not the pages, and not your address."));
      midBox = { title: "Tor relays", role: "Guard · middle · exit", items: mid };
    }
    // the website
    if (route === "direct") site.push(li("mid", "Your real address, roughly where you are, and every page you ask for."));
    else if (route === "vpn") site.push(li("mid", "The VPN's address instead of yours."));
    else site.push(li("ok", "An exit relay's address, not yours."));
    site.push(li("mid", "Who you sign in as, and everything you tell it."));
    // trackers
    trk.push(li("bad", "Cookies and your browser's fingerprint. The route doesn't change these."), li("mid", "Only a tracker blocker in your browser stops them."));
    return [
      { title: "Café or hotel Wi-Fi", role: "The network you're on", items: net },
      { title: "Your internet provider", role: "Carries all your traffic", items: isp },
      midBox,
      { title: "The website", role: "The far end", items: site },
      { title: "Trackers on the page", role: "Ads, analytics, widgets", items: trk },
    ];
  }
  const PM_NOTES = {
    "http-direct": "# plain HTTP on shared Wi-Fi: a postcard. Anyone who handles it can read it.",
    "https-direct": "# the padlock hid the pages. It didn't hide that you went there.",
    "http-vpn": "# the tunnel hides plain HTTP from the café, but the VPN company, and everyone past it, can read it.",
    "https-vpn": "# a tunnel carrying a tunnel: the café sees one encrypted stream, the VPN company sees the site names.",
    "http-tor": "# the exit relay can read plain HTTP. Tor's layers end at the exit; HTTPS protects the last hop.",
    "https-tor": "# HTTPS plus Tor: the exit can't read your pages and no relay knows both ends. Slow, and it still can't hide what you sign in to.",
  };
  let pmConn = "https", pmRoute = "direct";
  function pathDraw() {
    press($("pm-conn"), "data-v", pmConn); press($("pm-route"), "data-v", pmRoute);
    $("pm").innerHTML = pathBoxes(pmConn, pmRoute).map((b) =>
      `<div class="pm-box${b.off ? " off" : ""}"><b>${esc(b.title)}</b><small>${esc(b.role)}</small><ul>${b.items.map((i) => `<li class="${i.c}">${esc(i.t)}</li>`).join("")}</ul></div>`).join("");
    $("pm-note").textContent = PM_NOTES[pmConn + "-" + pmRoute];
  }

  // --------------------------------------------------------------------------- claim checkers (VPN adverts and private windows)
  function claimChecker(p, items, msgs) {
    let i = 0, score = 0, done = false;
    const g = (s) => $(p + "-" + s), btns = () => g("btns").querySelectorAll("[data-a]");
    function show() {
      const m = items[i];
      g("count").textContent = `Claim ${i + 1} of ${items.length}`;
      g("claim").textContent = m.c;
      g("verdict").hidden = true; g("next").hidden = true; g("why").textContent = "";
      for (const b of btns()) { b.disabled = false; b.hidden = false; }
      done = false;
    }
    function answer(a) {
      if (done) return; done = true;
      const m = items[i], ok = a === m.a;
      if (ok) score++;
      for (const b of btns()) b.disabled = true;
      const v = g("verdict"); v.hidden = false;
      v.className = "verdict " + (ok ? "ok" : "bad");
      v.textContent = (ok ? "Right: " : "Not quite: ") + m.v + ".";
      g("why").textContent = m.why;
      g("score").textContent = `Score: ${score} / ${i + 1}`;
      g("next").hidden = false;
      g("next").textContent = i === items.length - 1 ? "See score" : "Next ›";
    }
    function next() {
      if (i < items.length - 1) { i++; show(); return; }
      const n = items.length;
      let s = `Final score: ${score} / ${n}.`;
      if (score === n) s += " " + msgs.all; else if (score === 0) s += " " + msgs.none; else s += " " + msgs.some;
      g("score").textContent = s;
      g("claim").textContent = `That's all ${n}.`;
      g("count").textContent = ""; g("verdict").hidden = true; g("why").textContent = "";
      for (const b of btns()) b.hidden = true;
      g("next").textContent = "Play again";
      g("next").onclick = () => { i = 0; score = 0; g("next").onclick = null; g("score").textContent = ""; show(); };
    }
    for (const b of btns()) b.addEventListener("click", () => answer(b.dataset.a));
    g("next").addEventListener("click", () => { if (!g("next").onclick) next(); });
    show();
  }
  const VPN_CLAIMS = [
    { c: "Military-grade encryption.", a: "partly", v: "Partly true",
      why: "The tunnel uses ordinary strong encryption, the same kind behind HTTPS. That isn't the weak point. The question that matters is who is at the other end of the tunnel." },
    { c: "Hides your browsing from your internet provider.", a: "true", v: "True",
      why: "Your provider sees one encrypted tunnel. But, as the EFF puts it, \"it's all visible to the VPN provider\". You moved the view; you didn't remove it." },
    { c: "We keep no logs.", a: "partly", v: "Partly true: a promise, not a proof",
      why: "The EFF: \"a claim is not a guarantee\". Look for independent audits, and for what a company actually did when asked for data. Mullvad says that when Swedish police searched its office in April 2023 they left without customer data, because it keeps none. That's the company's own account." },
    { c: "Makes you anonymous online.", a: "no", v: "Misleading",
      why: "The EFF: \"A VPN is not a tool for anonymity\". Sites still know you by cookies, tracking pixels, fingerprinting, and whatever you sign in to. For anonymity the EFF points to Tor instead." },
    { c: "Blocks trackers and malware.", a: "partly", v: "Partly true: only if the app adds a blocker",
      why: "The tunnel itself blocks neither. Some VPN apps bundle a tracker blocker you can switch on (the EFF mentions this), and then the blocker is doing the work. A tunnel doesn't stop you installing malware or signing in to a fake page." },
    { c: "Keeps you safe on public Wi-Fi.", a: "partly", v: "Partly true",
      why: "HTTPS already protects the pages and passwords on nearly every site: Google reports 95 to 99 percent of Chrome page loads have been HTTPS since about 2020. A VPN adds hiding which sites you visit from the network owner. The FTC says VPN apps can help shield information on public Wi-Fi, if the app really encrypts and you trust it." },
  ];
  const BROWSER_CLAIMS = [
    { c: "A private window hides my browsing from my internet provider.", a: "no", v: "Misleading",
      why: "Mozilla: private browsing doesn't make you anonymous to \"websites, your internet provider, your employer, or search engines\". Google says the same about Incognito." },
    { c: "A private window deletes my history and cookies when I close it.", a: "true", v: "True",
      why: "Mozilla and Google both say the browser doesn't keep the history or site data after the session. Downloads and bookmarks you save stay." },
    { c: "A private window stops websites from tracking me.", a: "no", v: "Misleading",
      why: "Mozilla lists \"Stop websites from identifying or tracking you\" as something private browsing does not do. If you sign in, the site knows who you are anyway." },
    { c: "All the big browsers block third-party cookies by default.", a: "partly", v: "Partly true",
      why: "Safari has blocked cross-site cookies by default since 2020 (WebKit), and Firefox confines cookies to the site that made them (Total Cookie Protection). Chrome kept third-party cookies and left the choice to you (Google, 2025), though Incognito blocks them by default." },
    { c: "There's a browser setting that tells sites not to sell or share my data.", a: "true", v: "True",
      why: "Global Privacy Control is an opt-out preference signal. California says businesses are required to honour such signals, and that all browsers must include one by 1 January 2027. Other places differ." },
    { c: "Sites I'm signed in to still know who I am in a private window.", a: "true", v: "True",
      why: "A private window forgets afterwards; it doesn't hide you from a site you sign in to. That's what signing in means." },
  ];

  // --------------------------------------------------------------------------- slide 8: onion layers (real AES-GCM)
  const on = { step: 0, k: [], b1: null, b2: null, b3: null, n2: 0, n3: 0, rest1: null, rest2: null, body: "", site: "", https: false, notes: "" };
  const wrap = (key, data) => { const n = L.randBytes(12), r = L.gcmEncrypt(key, n, data); return L.concat(n, r.tag, r.ct); };
  const unwrap = (key, blob) => L.gcmDecrypt(key, blob.subarray(0, 12), blob.subarray(28), blob.subarray(12, 28));
  function splitHeader(bytes) { const i = bytes.indexOf(10); return { head: L.text(bytes.subarray(0, i)), rest: bytes.subarray(i + 1) }; }
  function onReset() {
    on.step = 0; on.notes = "";
    $("on-next").textContent = "1 · Wrap in three layers"; $("on-next").disabled = false; $("on-wrong").disabled = true;
    onDraw();
    $("on-note").textContent = "# press the button to wrap your message in three layers.";
    $("on-note").className = "comment";
  }
  function onStep() {
    if (on.step === 0) {
      on.site = ($("on-site").value.trim() || "site.example").slice(0, 24);
      const msg = $("on-msg").value; on.https = $("on-https").checked;
      on.body = on.https ? `[HTTPS: ${L.hex(L.randBytes(10))}…]` : msg;
      on.k = [L.randBytes(16), L.randBytes(16), L.randBytes(16)];
      const payload = L.utf8(`TO ${on.site}\n${on.body}`);
      on.b3 = wrap(on.k[2], payload);
      on.b2 = wrap(on.k[1], L.concat(L.utf8("NEXT exit\n"), on.b3));
      on.b1 = wrap(on.k[0], L.concat(L.utf8("NEXT middle\n"), on.b2));
      on.step = 1;
      let n = "# wrapped: three layers, innermost for the exit. Now each relay opens only its own.";
      if (/shrek|ogre|layers/i.test(msg)) n = "# onions have layers. Ogres have layers. Tor has three.";
      else if (!msg.trim()) n = "# an empty message still travels in three sealed layers: the layers protect it, not the words.";
      $("on-note").textContent = n; $("on-note").className = "comment ok";
      $("on-next").textContent = "2 · Guard opens its layer"; $("on-wrong").disabled = false;
    } else if (on.step === 1) {
      const p = splitHeader(unwrap(on.k[0], on.b1)); on.rest1 = p.rest; on.step = 2;
      $("on-note").textContent = "# the guard opened its layer: it knows who sent it and where it goes next, and nothing else.";
      $("on-next").textContent = "3 · Middle opens its layer";
    } else if (on.step === 2) {
      const p = splitHeader(unwrap(on.k[1], on.rest1)); on.rest2 = p.rest; on.step = 3;
      $("on-note").textContent = "# the middle opened its layer: it knows the relays on each side, and nothing about you or the site.";
      $("on-next").textContent = "4 · Exit opens its layer";
    } else if (on.step === 3) {
      on.step = 4;
      $("on-note").textContent = on.https
        ? "# the exit saw only a scrambled HTTPS request and the site's name; no relay saw both who and what."
        : "# the exit saw your plain message. Tor's layers end at the exit; that's why HTTPS matters.";
      $("on-next").textContent = "Done"; $("on-next").disabled = true;
    }
    onDraw();
  }
  function onWrong() {
    let m;
    try { unwrap(L.randBytes(16), on.b1); m = "opened"; } catch (e) { m = e.message; }
    $("on-note").textContent = `# the outer layer, tried with another relay's key: ✗ ${m}. A layer only opens for the key it was made for.`;
    $("on-note").className = "comment";
  }
  function onDraw() {
    const s = on.step, todo = (a) => (s < a ? " todo" : ""), now = (a) => (s === a ? " now" : "");
    const exitLearns = on.https ? `The site: <b>${esc(on.site)}</b>. A scrambled HTTPS request: <span class="ok">it can't read the message</span>. Not your address.`
      : `The site: <b>${esc(on.site)}</b>. Your message: <span class="bad">${esc(on.body || "(empty)")}</span>. Not your address.`;
    const rows = [
      ["You", s >= 1 ? "Your message and the three keys" : "Your message", "Everything. You hold all three keys.", ""],
      ["Guard", s >= 1 ? `${on.b1.length} bytes<br>${hexp(on.b1)}` : "—", s >= 2 ? `<span class="bad">Your address</span> (you connected). Next hop: <b>middle</b>. The rest, ${on.rest1.length} bytes, is still scrambled.` : "—", todo(1) + now(2)],
      ["Middle", s >= 2 ? `${on.rest1.length} bytes<br>${hexp(on.rest1)}` : "—", s >= 3 ? `Only the relays on each side. Next hop: <b>exit</b>. <span class="ok">Not your address, not the site.</span>` : "—", todo(2) + now(3)],
      ["Exit", s >= 3 ? `${on.rest2.length} bytes<br>${hexp(on.rest2)}` : "—", s >= 4 ? exitLearns : "—", todo(3) + now(4)],
      ["Website", s >= 4 ? "A request from the exit relay's address" : "—", s >= 4 ? "<span class=\"ok\">It never sees your address.</span>" : "—", todo(4)],
    ];
    $("on-rows").innerHTML = rows.map(([w, r, l, c]) => `<tr class="${c.trim()}"><th>${w}</th><td class="hex">${r}</td><td>${l}</td></tr>`).join("");
    $("on-keys").textContent = s >= 1 ? `Keys (random, made in this page): guard ${hexp(on.k[0], 4)}  middle ${hexp(on.k[1], 4)}  exit ${hexp(on.k[2], 4)}` : "";
  }

  // --------------------------------------------------------------------------- slide 9: private DNS and ECH
  const dn = { dns: "plain", ech: "off" };
  const DN_NOTES = {
    "plain-off": "# the name is visible twice: once in the lookup and once in the handshake.",
    "enc-off": "# the lookup is hidden, but the handshake still announces the name.",
    "plain-on": "# without encrypted DNS the lookup still announces the name; ECH works best together with it.",
    "enc-on": "# both on: a watcher on the network sees an address and some volume, not the name you wanted. The resolver you picked still knows.",
  };
  function dnDraw() {
    press($("dn-dns"), "data-v", dn.dns); press($("dn-ech"), "data-v", dn.ech);
    const row = (step, cls, text) => `<tr><th>${step}</th><td class="${cls}">${text}</td></tr>`;
    $("dn-rows").innerHTML =
      row("1 · Your device asks where the site is (DNS)", dn.dns === "plain" ? "bad" : "ok", dn.dns === "plain" ? "Visible: the site's name." : "Hidden from the network. The resolver you chose still sees it.") +
      row("2 · Your browser says which site it wants (the handshake)", dn.ech === "off" ? "bad" : "ok", dn.ech === "off" ? "Visible: the site's name." : "Hidden behind a shared name, if the site or its host supports ECH.") +
      row("3 · Your device connects to an address", "", "Visible: the address. A big host may serve thousands of sites from one.") +
      row("4 · The conversation", "ok", "Hidden by HTTPS. Its size and timing are still visible.");
    $("dn-note").textContent = DN_NOTES[dn.dns + "-" + dn.ech];
    $("dn-note").className = "comment" + (dn.dns === "enc" && dn.ech === "on" ? " ok" : "");
  }

  // --------------------------------------------------------------------------- slide 12: who holds the key (real AES-GCM)
  const kl = { mode: "provider", key: null, nonce: null, ct: null, tag: null, note: "" };
  function klSeal() {
    kl.note = $("kl-note").value;
    kl.nonce = L.randBytes(12);
    const r = L.gcmEncrypt(kl.key, kl.nonce, L.utf8(kl.note)); kl.ct = r.ct; kl.tag = r.tag;
  }
  function klNew() { kl.key = L.randBytes(16); klSeal(); klDraw(); $("kl-out").innerHTML = ""; $("kl-comment").textContent = "# a new note and new keys. Pick a scenario."; $("kl-comment").className = "comment"; }
  function klDraw() {
    press($("kl-mode"), "data-m", kl.mode);
    const stored = hexp(L.concat(kl.nonce, kl.tag, kl.ct), 24);
    const provider = kl.mode === "provider";
    const saved = $("kl-saved").checked;
    $("kl-keys").innerHTML =
      `<div class="wide"><b>Stored on the company's disks (scrambled)</b><code>${stored}</code></div>` +
      (provider
        ? `<div><b>The company keeps</b><span>the key <code>${hexp(kl.key, 6)}</code></span></div><div><b>You keep</b><span>a password, not the key</span></div>`
        : `<div><b>The company keeps</b><span>scrambled data only. No key.</span></div><div><b>You keep</b><span>a recovery key <code>${hexp(kl.key, 6)}</code>${saved ? " (saved somewhere safe)" : " (not saved anywhere)"}</span></div>`);
  }
  function klTry(k) { try { return { ok: true, text: L.text(L.gcmDecrypt(k, kl.nonce, kl.ct, kl.tag)) }; } catch (e) { return { ok: false, text: e.message }; } }
  function klScenario(s) {
    if (s === "new") return klNew();
    const provider = kl.mode === "provider", saved = $("kl-saved").checked, junk = L.randBytes(16);
    let intro, r, comment, egg = false;
    if (s === "disk") {
      intro = "A thief with a stolen server disk tries a guessed key…"; r = klTry(junk);
      comment = "# encrypted at rest does its job here: a stolen disk is useless without the key.";
    } else if (s === "order") {
      if (provider) { intro = "The provider is ordered to hand over the note. It has the key, so it opens it…"; r = klTry(kl.key); comment = "# the provider can open it, so it can be ordered to. A key it holds is a key it can be asked for."; }
      else { intro = "The provider is ordered to hand over the note. It has no key, so it tries anyway…"; r = klTry(junk); comment = "# the provider can only hand over scrambled data and account details. It has no key."; }
    } else if (s === "inside") {
      if (provider) { intro = "Someone gets into the provider's key system and finds the key…"; r = klTry(kl.key); comment = "# whoever reaches the key can read the note. A well-run provider makes that very hard; the point is that it's possible."; }
      else { intro = "Someone gets into the provider's systems and looks for a key…"; r = klTry(junk); comment = "# there's no key there to find."; }
    } else {
      if (provider) { intro = "You forget your password. The provider checks it's you and resets your access…"; r = klTry(kl.key); comment = "# a reset is possible because the provider can still open your data."; }
      else if (saved) { intro = "You forget your password, and open the note with the recovery key you saved…"; r = klTry(kl.key); comment = "# recovered with the key you saved. Keep it somewhere that isn't the same phone."; }
      else { intro = "You forget your password, and you didn't save the recovery key…"; r = klTry(junk); comment = "# no reset: that's the price and the point. Keep the recovery key somewhere that isn't the same phone."; egg = true; }
    }
    $("kl-out").innerHTML = `${esc(intro)}\n<span class="${r.ok ? "ok" : "bad"}">${r.ok ? "✓" : "✗"} ${r.ok ? esc(`"${r.text}"`) : esc(r.text)}</span>`;
    $("kl-comment").textContent = comment;
    $("kl-comment").className = "comment" + (egg ? " ok" : "");
  }

  // --------------------------------------------------------------------------- slide 13: the envelope
  const ENV = {
    plain: { rows: [["What you wrote", "bad", "Seen"], ["Who sent it", "bad", "Seen"], ["Who it's for", "bad", "Seen"], ["When, and how big", "bad", "Seen"], ["Where you are", "bad", "Seen: roughly, from the carrier"]],
      note: "# a postcard: the company reads the message and the envelope." },
    e2ee: { rows: [["What you wrote", "ok", "Hidden"], ["Who sent it", "bad", "Seen"], ["Who it's for", "bad", "Seen"], ["When, and how big", "bad", "Seen"], ["Where you are", "bad", "Seen: your network address"]],
      note: "# the message is sealed. The envelope (who, to whom, when, how big, from where) is still readable by the company." },
    sealed: { rows: [["What you wrote", "ok", "Hidden"], ["Who sent it", "ok", "Hidden from the service"], ["Who it's for", "bad", "Seen"], ["When, and how big", "bad", "Seen"], ["Where you are", "mid", "Seen, unless a VPN or Tor hides your address"]],
      note: "# sealed sender: the 'from' address is gone from the envelope. The 'to' address, the postmark and the size are still there." },
  };
  let envMode = "plain";
  function envDraw() {
    press($("env-mode"), "data-m", envMode);
    $("env-rows").innerHTML = ENV[envMode].rows.map(([w, c, t]) => `<tr><th>${esc(w)}</th><td class="${c}">${esc(t)}</td></tr>`).join("");
    $("env-note").textContent = ENV[envMode].note;
    $("env-note").className = "comment" + (envMode === "sealed" ? " ok" : "");
  }

  // --------------------------------------------------------------------------- slide 14: the backup gap
  const BK = {
    off: [["Who can read my old chats?", "ok", "Only me and the people in the chat."], ["If I lose my phone and password", "bad", "The history is gone: there's no backup."], ["If the company is ordered to hand it over", "ok", "Nothing readable to hand over."], ["What it costs me", "mid", "The history, if the phone is lost."]],
    company: [["Who can read my old chats?", "bad", "The company can open the backup too, or anyone it's made to help."], ["If I lose my phone and password", "ok", "Restored: the company can help me back in."], ["If the company is ordered to hand it over", "bad", "It can open the backup and hand it over."], ["What it costs me", "mid", "Nothing extra, if I chose it on purpose."]],
    mine: [["Who can read my old chats?", "ok", "Only me."], ["If I lose my phone and password", "mid", "Restored with my key. No key, no backup: the company can't help."], ["If the company is ordered to hand it over", "ok", "It can only hand over scrambled data."], ["What it costs me", "mid", "I must keep a key safe, somewhere that isn't the phone."]],
  };
  const BK_NOTES = {
    off: "# the chat stays end-to-end: nothing outside the two phones can read it. The price is losing it with the phone.",
    company: "# the chat was end-to-end, and the backup undid that. It's a convenience: pick it on purpose.",
    mine: "# only you can read it, and only you can restore it.",
  };
  let bkMode = "company";
  function bkDraw() {
    press($("bk-mode"), "data-m", bkMode);
    $("bk-rows").innerHTML = BK[bkMode].map(([q, c, t]) => `<tr><th>${esc(q)}</th><td class="${c}">${esc(t)}</td></tr>`).join("");
    $("bk-note").textContent = BK_NOTES[bkMode];
    $("bk-note").className = "comment" + (bkMode === "mine" ? " ok" : "");
  }

  // --------------------------------------------------------------------------- slide 17: pick a tool for a worry
  const WHAT = [["sites", "which sites I visit"], ["content", "what I say in messages"], ["files", "files I store in the cloud"], ["identity", "who I am, from the site I'm visiting"], ["device", "everything on my device, if it's lost"]];
  const WHOM = [["network", "the café or hotel Wi-Fi"], ["isp", "my internet provider"], ["site", "the website itself"], ["ads", "advertisers and trackers"], ["company", "the service's company"], ["thief", "a thief"], ["court", "a court or government"]];
  const E2E_MSG = { use: "An end-to-end encrypted messenger (and HTTPS for web chat).", trust: "the app's code and the person you write to", still: "metadata, and that you use the app" };
  const CH = {
    "sites:network": { use: "HTTPS (already on for nearly every site) hides the pages. A VPN or Tor also hides which sites you visit.", trust: "the VPN company, or Tor's relays", still: "that you're using a VPN or Tor, and how much data moves" },
    "sites:isp": { use: "Private DNS plus ECH (where the site supports it), or a VPN, or Tor.", trust: "your DNS resolver, the VPN company, or Tor's relays", still: "the addresses you connect to and how much data moves; with Tor, that you use it" },
    "sites:site": { use: "Not hidden: the site knows what you ask it for. Tor, or a VPN, can hide your address.", trust: "the VPN company or Tor's relays, if you use one", still: "your pages, and your account if you sign in" },
    "sites:ads": { use: "Tracker blocking in your browser, Global Privacy Control, and signing out. A VPN doesn't stop cookie-based tracking.", trust: "your browser", still: "what the site you're on sees, and anything you sign in to" },
    "sites:company": { use: "Choose services you trust. Tor hides who you are, but not what you ask for.", trust: "the service", still: "your requests" },
    "sites:thief": { use: "A private window forgets your history on the device. The device lock protects the rest.", trust: "the browser, and the lock", still: "everything, if the device is unlocked" },
    "sites:court": { use: "Neither tool is a guarantee: a VPN company can be ordered to hand over what it keeps, and Tor doesn't defend against an observer who sees both ends.", trust: "the company or relays you chose", still: "what they keep, and what an observer who sees both ends can match" },
    "content:network": E2E_MSG, "content:isp": E2E_MSG,
    "content:ads": { use: "An end-to-end encrypted messenger: the company relays scrambled data it can't read.", trust: "the app", still: "metadata" },
    "content:company": { use: "An end-to-end encrypted app: the company relays scrambled data it can't read. Check the backup setting too.", trust: "the app's code, and whoever holds the backup key", still: "metadata, and anything not end-to-end (SMS, some group chats, backups)" },
    "content:thief": { use: "A device lock and disk encryption. Disappearing messages remove old chats from the phone.", trust: "the lock", still: "anything on an unlocked phone" },
    "content:court": { use: "End-to-end encryption means the company can only hand over scrambled data and what it keeps about you. It can't hide what's on the phones at either end.", trust: "the app, and the people you write to", still: "metadata the app keeps, and the contents on either phone" },
    "files:network": { use: "HTTPS, which is already on for transfers.", trust: "the service", still: "that you uploaded, and how much" },
    "files:isp": { use: "HTTPS, which is already on for transfers.", trust: "the service", still: "that you uploaded, and how much" },
    "files:company": { use: "End-to-end encrypted storage or backup, with a key you keep.", trust: "yourself: lose the key, lose the files", still: "that files exist, their size, and when they change" },
    "files:thief": { use: "Disk encryption with a strong lock, and a recovery key stored away from the device.", trust: "the lock, and whoever holds the recovery key", still: "your files while you're signed in" },
    "files:court": { use: "End-to-end storage: the company can only hand over scrambled data. A court can still order you directly.", trust: "yourself", still: "that files exist, their size, and when they change" },
    "files:ads": { use: "Advertisers rarely see your files; they see what you click and browse. Try \"who I am\" or \"which sites I visit\".", trust: "", still: "", egg: "# advertisers rarely see your files; they see what you click." },
    "identity:site": { use: "Tor hides your address; a VPN swaps it for the VPN's. Neither hides what you sign in to, or your browser's fingerprint.", trust: "Tor's relays, or the VPN company", still: "your account, cookies and fingerprint" },
    "identity:ads": { use: "Tracker blocking, Global Privacy Control, separate browser profiles, and signing out.", trust: "your browser", still: "what you sign in to" },
    "identity:network": { use: "HTTPS: the network sees which site you went to, but not your account.", trust: "the website", still: "which site, when, and how much" },
    "identity:isp": { use: "HTTPS: your provider sees which site you went to, but not your account.", trust: "the website", still: "which site, when, and how much" },
    "identity:company": { use: "Use a separate account or email address for the service, and share only what it needs.", trust: "the service", still: "what you tell it" },
    "device:thief": { use: "Disk encryption (on by default on most phones; check laptops), a strong lock, and a recovery key stored away from the device.", trust: "the lock, and whoever holds the recovery key", still: "everything, if you're signed in and it's unlocked" },
    "device:company": { use: "Know where your recovery key is. A copy with a company is a copy it can be asked for.", trust: "whoever holds the recovery key", still: "that the device exists, and who owns it" },
    "device:court": { use: "Disk encryption protects a device that's off or locked. A recovery key held by a company can be requested from it.", trust: "whoever holds the key", still: "everything on a device you've unlocked" },
  };
  const CH_NONE = { use: "No single tool covers this one. Say the worry as \"I don't want X to see Y\", then find where Y actually travels or sits.", trust: "", still: "" };
  function chDraw() {
    const c = CH[$("ch-what").value + ":" + $("ch-whom").value] || CH_NONE;
    $("ch-use").textContent = c.use;
    $("ch-trust").innerHTML = c.trust ? `<b>You now trust:</b> ${esc(c.trust)}` : "";
    $("ch-still").innerHTML = c.still ? `<b>Still visible:</b> ${esc(c.still)}` : "";
    $("ch-note").textContent = c.egg || "";
    $("ch-note").className = "comment" + (c.egg ? " ok" : "");
  }
  function chInit() {
    for (const [id, list] of [["ch-what", WHAT], ["ch-whom", WHOM]]) {
      $(id).innerHTML = list.map(([v, t]) => `<option value="${v}">${esc(t)}</option>`).join("");
      $(id).addEventListener("change", chDraw);
    }
    $("ch-what").value = "sites"; $("ch-whom").value = "network";
    chDraw();
  }

  // --------------------------------------------------------------------------- the checklist (kept in this browser only)
  const PT_KEY = "privacy-tools-checklist";
  function checklist() {
    const boxes = Array.from(document.querySelectorAll("#pt-plan input[type=checkbox]"));
    let saved = {};
    try { saved = JSON.parse(store(PT_KEY) || "{}"); } catch (e) {}
    boxes.forEach((b) => { b.checked = !!saved[b.dataset.k]; });
    const update = () => {
      const done = boxes.filter((b) => b.checked).length;
      store(PT_KEY, JSON.stringify(Object.fromEntries(boxes.map((b) => [b.dataset.k, b.checked]))));
      const note = $("pt-note"); note.className = "comment";
      if (done === boxes.length) { note.textContent = "# all twelve. Privacy is a habit, not a purchase."; note.classList.add("ok"); }
      else if (done === 0) note.textContent = "# tick what's already true for you. Ticks are saved in this browser only.";
      else note.textContent = `# ${done} of ${boxes.length} ticked. The gaps are your to-do list: start with group 2, the recovery keys.`;
    };
    boxes.forEach((b) => b.addEventListener("change", update));
    update();
  }

  // --------------------------------------------------------------------------- console hint
  function consoleHint() {
    console.log("%cPrivacy Tools Explained", "font: 700 24px monospace; color: #ff2e88; text-shadow: 0 0 8px #ff2e88");
    console.log("%cYou opened the developer console on a talk about who can see what. Bonus tip: this page runs entirely in your browser, and the console is one of the places you can check that nothing is sent anywhere: open the Network tab, then use a demo.", "font: 14px monospace; color: #00f0ff");
  }

  function start() {
    consoleHint();
    $("hero-in").addEventListener("input", hero); hero();
    toolDraw();

    for (const b of $("pm-conn").querySelectorAll("button")) b.addEventListener("click", () => { pmConn = b.dataset.v; pathDraw(); });
    for (const b of $("pm-route").querySelectorAll("button")) b.addEventListener("click", () => { pmRoute = b.dataset.v; pathDraw(); });
    pathDraw();

    claimChecker("vc", VPN_CLAIMS, { all: "# all six. You could read VPN adverts for a living.", none: "# zero: adverts are written to be believed. Now you know which claims to ask about.", some: "# the pattern: the safe-sounding part of a claim is usually true, and the missing part is who now sees it." });
    claimChecker("bc", BROWSER_CLAIMS, { all: "# all six. You know more about private windows than most browser menus tell you.", none: "# zero: the word 'private' is doing a lot of work in that menu. Now you know what it covers.", some: "# the pattern: a private window is about this device, and tracking is about everything else." });

    click("on-next", onStep); click("on-wrong", onWrong); click("on-reset", onReset);
    for (const id of ["on-msg", "on-site"]) $(id).addEventListener("input", onReset);
    $("on-https").addEventListener("change", onReset);
    onReset();

    for (const b of $("dn-dns").querySelectorAll("button")) b.addEventListener("click", () => { dn.dns = b.dataset.v; dnDraw(); });
    for (const b of $("dn-ech").querySelectorAll("button")) b.addEventListener("click", () => { dn.ech = b.dataset.v; dnDraw(); });
    dnDraw();

    for (const b of $("kl-mode").querySelectorAll("button")) b.addEventListener("click", () => { kl.mode = b.dataset.m; klDraw(); $("kl-out").innerHTML = ""; $("kl-comment").textContent = ""; });
    $("kl-note").addEventListener("input", () => { klSeal(); klDraw(); });
    $("kl-saved").addEventListener("change", klDraw);
    $("kl-btns").addEventListener("click", (e) => { const b = e.target.closest("[data-s]"); if (b) klScenario(b.dataset.s); });
    kl.key = L.randBytes(16); klSeal(); klDraw();

    for (const b of $("env-mode").querySelectorAll("button")) b.addEventListener("click", () => { envMode = b.dataset.m; envDraw(); });
    envDraw();
    for (const b of $("bk-mode").querySelectorAll("button")) b.addEventListener("click", () => { bkMode = b.dataset.m; bkDraw(); });
    bkDraw();

    chInit();
    checklist();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
})();
