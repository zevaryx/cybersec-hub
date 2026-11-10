/* app.js - the live demos for "Securing Your Home Network".
   Everything here is a simulation in your browser: nothing you type is stored or sent.
   Random passphrases use crypto.getRandomValues. The word list is the EFF short wordlist #1
   (1,296 words, CC BY 3.0 US, https://www.eff.org/dice). */
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
  function press(group, attr, value) {
    for (const b of group.querySelectorAll("button")) b.setAttribute("aria-pressed", String(b.getAttribute(attr) === value));
  }
  // an unbiased random whole number from 0 to n-1
  function rint(n) {
    const lim = Math.floor(4294967296 / n) * n, a = new Uint32Array(1);
    do { crypto.getRandomValues(a); } while (a[0] >= lim);
    return a[0] % n;
  }

  // --------------------------------------------------------------------------- passphrases
  const WORDS = "acid acorn acre acts afar affix aged agent agile aging agony ahead aide aids aim ajar alarm alias alibi alien alike alive aloe aloft aloha alone amend amino ample amuse angel anger angle ankle apple april apron aqua area arena argue arise armed armor army aroma array arson art ashen ashes atlas atom attic audio avert avoid awake award awoke axis bacon badge bagel baggy baked baker balmy banjo barge barn bash basil bask batch bath baton bats blade blank blast blaze bleak blend bless blimp blink bloat blob blog blot blunt blurt blush boast boat body boil bok bolt boned boney bonus bony book booth boots boss botch both boxer breed bribe brick bride brim bring brink brisk broad broil broke brook broom brush buck bud buggy bulge bulk bully bunch bunny bunt bush bust busy buzz cable cache cadet cage cake calm cameo canal candy cane canon cape card cargo carol carry carve case cash cause cedar chain chair chant chaos charm chase cheek cheer chef chess chest chew chief chili chill chip chomp chop chow chuck chump chunk churn chute cider cinch city civic civil clad claim clamp clap clash clasp class claw clay clean clear cleat cleft clerk click cling clink clip cloak clock clone cloth cloud clump coach coast coat cod coil coke cola cold colt coma come comic comma cone cope copy coral cork cost cot couch cough cover cozy craft cramp crane crank crate crave crawl crazy creme crepe crept crib cried crisp crook crop cross crowd crown crumb crush crust cub cult cupid cure curl curry curse curve curvy cushy cut cycle dab dad daily dairy daisy dance dandy darn dart dash data date dawn deaf deal dean debit debt debug decaf decal decay deck decor decoy deed delay denim dense dent depth derby desk dial diary dice dig dill dime dimly diner dingy disco dish disk ditch ditzy dizzy dock dodge doing doll dome donor donut dose dot dove down dowry doze drab drama drank draw dress dried drift drill drive drone droop drove drown drum dry duck duct dude dug duke duo dusk dust duty dwarf dwell eagle early earth easel east eaten eats ebay ebony ebook echo edge eel eject elbow elder elf elk elm elope elude elves email emit empty emu enter entry envoy equal erase error erupt essay etch evade even evict evil evoke exact exit fable faced fact fade fall false fancy fang fax feast feed femur fence fend ferry fetal fetch fever fiber fifth fifty film filth final finch fit five flag flaky flame flap flask fled flick fling flint flip flirt float flock flop floss flyer foam foe fog foil folic folk food fool found fox foyer frail frame fray fresh fried frill frisk from front frost froth frown froze fruit gag gains gala game gap gas gave gear gecko geek gem genre gift gig gills given giver glad glass glide gloss glove glow glue goal going golf gong good gooey goofy gore gown grab grain grant grape graph grasp grass grave gravy gray green greet grew grid grief grill grip grit groom grope growl grub grunt guide gulf gulp gummy guru gush gut guy habit half halo halt happy harm hash hasty hatch hate haven hazel hazy heap heat heave hedge hefty help herbs hers hub hug hula hull human humid hump hung hunk hunt hurry hurt hush hut ice icing icon icy igloo image ion iron islam issue item ivory ivy jab jam jaws jazz jeep jelly jet jiffy job jog jolly jolt jot joy judge juice juicy july jumbo jump junky juror jury keep keg kept kick kilt king kite kitty kiwi knee knelt koala kung ladle lady lair lake lance land lapel large lash lasso last latch late lazy left legal lemon lend lens lent level lever lid life lift lilac lily limb limes line lint lion lip list lived liver lunar lunch lung lurch lure lurk lying lyric mace maker malt mama mango manor many map march mardi marry mash match mate math moan mocha moist mold mom moody mop morse most motor motto mount mouse mousy mouth move movie mower mud mug mulch mule mull mumbo mummy mural muse music musky mute nacho nag nail name nanny nap navy near neat neon nerd nest net next niece ninth nutty oak oasis oat ocean oil old olive omen onion only ooze opal open opera opt otter ouch ounce outer oval oven owl ozone pace pagan pager palm panda panic pants panty paper park party pasta patch path patio payer pecan penny pep perch perky perm pest petal petri petty photo plank plant plaza plead plot plow pluck plug plus poach pod poem poet pogo point poise poker polar polio polka polo pond pony poppy pork poser pouch pound pout power prank press print prior prism prize probe prong proof props prude prune pry pug pull pulp pulse puma punch punk pupil puppy purr purse push putt quack quake query quiet quill quilt quit quota quote rabid race rack radar radio raft rage raid rail rake rally ramp ranch range rank rant rash raven reach react ream rebel recap relax relay relic remix repay repel reply rerun reset rhyme rice rich ride rigid rigor rinse riot ripen rise risk ritzy rival river roast robe robin rock rogue roman romp rope rover royal ruby rug ruin rule runny rush rust rut sadly sage said saint salad salon salsa salt same sandy santa satin sauna saved savor sax say scale scam scan scare scarf scary scoff scold scoop scoot scope score scorn scout scowl scrap scrub scuba scuff sect sedan self send sepia serve set seven shack shade shady shaft shaky sham shape share sharp shed sheep sheet shelf shell shine shiny ship shirt shock shop shore shout shove shown showy shred shrug shun shush shut shy sift silk silly silo sip siren sixth size skate skew skid skier skies skip skirt skit sky slab slack slain slam slang slash slate slaw sled sleek sleep sleet slept slice slick slimy sling slip slit slob slot slug slum slurp slush small smash smell smile smirk smog snack snap snare snarl sneak sneer sniff snore snort snout snowy snub snuff speak speed spend spent spew spied spill spiny spoil spoke spoof spool spoon sport spot spout spray spree spur squad squat squid stack staff stage stain stall stamp stand stank stark start stash state stays steam steep stem step stew stick sting stir stock stole stomp stony stood stool stoop stop storm stout stove straw stray strut stuck stud stuff stump stung stunt suds sugar sulk surf sushi swab swan swarm sway swear sweat sweep swell swept swim swing swipe swirl swoop swore syrup tacky taco tag take tall talon tamer tank taper taps tarot tart task taste tasty taunt thank thaw theft theme thigh thing think thong thorn those throb thud thumb thump thus tiara tidal tidy tiger tile tilt tint tiny trace track trade train trait trap trash tray treat tree trek trend trial tribe trick trio trout truce truck trump trunk try tug tulip tummy turf tusk tutor tutu tux tweak tweet twice twine twins twirl twist uncle uncut undo unify union unit untie upon upper urban used user usher utter value vapor vegan venue verse vest veto vice video view viral virus visa visor vixen vocal voice void volt voter vowel wad wafer wager wages wagon wake walk wand wasp watch water wavy wheat whiff whole whoop wick widen widow width wife wifi wilt wimp wind wing wink wipe wired wiry wise wish wispy wok wolf womb wool woozy word work worry wound woven wrath wreck wrist xerox yahoo yam yard year yeast yelp yield yo-yo yodel yoga yoyo yummy zebra zero zesty zippy zone zoom".split(" ");
  const WORDSET = new Set(WORDS);
  const CHARS = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789"; // no look-alikes (i l o I L O 0 1)
  const RATE = 1e8; // guesses a second we assume: generous (see the slide's notes)

  function generate(kind) {
    if (kind === "c16") return Array.from({ length: 16 }, () => CHARS[rint(CHARS.length)]).join("");
    const n = kind === "w6" ? 6 : 5;
    return Array.from({ length: n }, () => WORDS[rint(WORDS.length)]).join("-");
  }

  // a tiny stand-in for the lists guessers try first
  const COMMON = ["password", "passw0rd", "p@ssw0rd", "12345678", "123456789", "1234567890", "qwertyuiop", "qwerty", "iloveyou",
    "welcome", "sunshine", "football", "baseball", "letmein", "dragon", "monkey", "princess", "superman", "trustno1", "changeme",
    "admin", "administrator", "wifi", "wifipassword", "internet", "router", "family", "guest", "home", "house", "hello", "secret",
    "summer", "winter", "master", "shadow", "freedom", "whatever", "starwars", "computer", "login"];

  function analyze(p) {
    const v = String(p), len = [...v].length;
    if (/^[0-9a-f]{64}$/i.test(v)) return { len, hex64: true, log10: 64 * Math.log10(16), popular: false };
    const parts = v.split(/[\s-]+/).filter(Boolean);
    if (parts.length >= 4 && parts.every((w) => WORDSET.has(w.toLowerCase()))) {
      return { len, words: parts.length, log10: parts.length * Math.log10(WORDS.length), popular: false };
    }
    let pool = 0;
    if (/\d/.test(v)) pool += 10;
    if (/[a-z]/.test(v)) pool += 26;
    if (/[A-Z]/.test(v)) pool += 26;
    if (/[^a-zA-Z0-9]/.test(v)) pool += 33;
    const log10 = len && pool ? len * Math.log10(pool) : 0;
    const t = v.toLowerCase(), s = t.replace(/[^a-z0-9]/g, "");
    let why = "";
    if (COMMON.includes(t) || COMMON.includes(s)) why = "one of the most common passwords";
    else if (/^\d+$/.test(v) && len <= 12) why = "only digits";
    else if (/(qwert|asdf|zxcv|1qaz|12345|09876|abcde)/.test(s)) why = "a keyboard or number run";
    else if (len >= 2 && /^(.{1,6})\1+$/.test(v)) why = "a short chunk repeated";
    else if (/^[a-z]{3,}(19|20)\d\d[^a-z0-9]?$/i.test(v)) why = "a word and a year";
    else if (/^[a-z]{3,}\d{1,6}[^a-z0-9]?$/i.test(v)) why = "a word with digits on the end";
    else if (COMMON.some((w) => w.length >= 4 && s.includes(w))) why = "built around a very common password";
    return { len, pool, log10, popular: !!why, why };
  }

  function fmtBig(log10) {
    if (log10 < 15) return Math.round(10 ** log10).toLocaleString("en-US");
    const e = Math.floor(log10), m = 10 ** (log10 - e);
    return `${m.toFixed(1)} × 10^${e}`;
  }
  function fmtTime(sec) {
    if (!isFinite(sec) || sec > 4.4e17) return "longer than the age of the universe";
    const units = [["year", 31557600], ["day", 86400], ["hour", 3600], ["minute", 60], ["second", 1]];
    for (const [u, n] of units) if (sec >= n) {
      const v = sec / n;
      const t = v >= 1e6 ? fmtBig(Math.log10(v)) : v >= 100 ? Math.round(v).toLocaleString("en-US") : v.toFixed(v < 10 ? 1 : 0);
      return `${t} ${u}${t === "1" || t === "1.0" ? "" : "s"}`;
    }
    return "under a second";
  }
  const bits = (log10) => (log10 * Math.log2(10)).toFixed(0);
  const size = (a) => (a.hex64 ? "64 hex digits" : a.words ? `${a.words} words` : `${a.len} character${a.len === 1 ? "" : "s"}`);

  // --------------------------------------------------------------------------- title: wifi-check
  const HERO_EGGS = {
    "password": "# the world's most famous bad password, and a very good reason to retire it.",
    "12345678": "# eight characters, the shortest a router will accept, and a number run that sits near the top of common-password lists.",
    "hunter2": "# hunter2: an old internet joke about a password that shows up as stars. Too short for Wi-Fi anyway.",
    "admin": "# 'admin' is a very common factory login on routers. This box is for Wi-Fi passphrases, but the lesson applies to both.",
    "wifi password": "# naming it 'wifi password' is honest, at least. It's also an easy guess.",
  };
  function hero() {
    const el = $("hero-in"), v = el.value;
    el.style.width = Math.max(8, [...v].length + 1) + "ch";
    const out = $("hero-out"), note = $("hero-note");
    if (!v) {
      out.innerHTML = `${sp("k", "length:")} ${sp("bad", "0 (no passphrase)")}`;
      note.textContent = "# an open network: anyone in range can join, and anyone nearby can read along on sites without HTTPS. Cafés do it on purpose. A home shouldn't.";
      return;
    }
    const a = analyze(v), t = v.trim().toLowerCase();
    const timeTxt = a.hex64 ? "a raw key, not a passphrase" : a.popular ? "minutes at most: tried first" : fmtTime(10 ** (a.log10 - Math.log10(RATE)));
    out.innerHTML = `${sp("k", "length:")} ${sp("y", size(a))}<br>${sp("k", "popular or patterned:")} ${a.popular ? sp("bad", "yes: " + a.why) : sp("ok", "no")}<br>${sp("k", "try them all at 100 million a second:")} ${a.popular ? sp("bad", timeTxt) : sp("ok", timeTxt)}`;
    let n;
    if (HERO_EGGS[t]) n = HERO_EGGS[t];
    else if (a.hex64) n = "# 64 hex digits: WPA2 takes either 8 to 63 characters or exactly this, a raw key. Nobody types those on a TV remote.";
    else if (a.words) n = `# ${a.words} words from a list of 1,296, about ${bits(a.log10)} bits: strong if they were picked at random, and typeable on a TV remote.`;
    else if (a.len < 8) n = "# too short: WPA2 passphrases are 8 to 63 characters, so your router would refuse this one.";
    else if (a.len > 63) n = "# too long: WPA2 passphrases stop at 63 characters.";
    else if (a.popular) n = `# ${a.why}: near the top of guess lists. On WPA2, someone in range who records a device joining can try guesses at home.`;
    else n = "# not on a popular list. Long and random is better still; the Wi-Fi slide makes some.";
    note.textContent = n;
  }

  // --------------------------------------------------------------------------- the Wi-Fi slide
  let wmode = "wpa2", lastGen = "", lastKind = "";
  function wifi() {
    const v = $("wf-in").value, stats = $("wf-stats"), note = $("wf-note");
    if (!v) { stats.innerHTML = ""; note.textContent = "# no passphrase: an open network. Anyone in range can join."; return; }
    const a = analyze(v), wpa2 = wmode === "wpa2";
    if (v === lastGen && lastKind === "c16") a.log10 = 16 * Math.log10(CHARS.length); // we know the real alphabet of a generated one
    const secs = a.popular ? 0 : 10 ** (a.log10 - Math.log10(RATE));
    const bad = a.popular || (wpa2 && secs < 31557600 * 10) || a.len < 8;
    stats.innerHTML =
      `<div class="stat"><b>${esc(fmtBig(a.log10))}</b><span>possible passphrases (about ${bits(a.log10)} bits, ${esc(size(a))})</span></div>` +
      `<div class="stat${a.popular ? " stat-bad" : " stat-ok"}"><b>${a.popular ? "yes" : "no"}</b><span>${a.popular ? esc(a.why) : "popular or patterned?"}</span></div>` +
      (wpa2
        ? `<div class="stat${bad ? " stat-bad" : " stat-ok"}"><b>${a.popular ? "minutes" : esc(fmtTime(secs))}</b><span>to try them all offline at 100 million a second</span></div>`
        : `<div class="stat stat-ok"><b>live tries only</b><span>a recording of someone joining doesn't help</span></div>`);
    let n;
    if (a.len < 8 && !a.hex64) n = "# too short: WPA2 passphrases are 8 to 63 characters, so your router would refuse this.";
    else if (a.popular) n = `# ${a.why}: a guesser tries these first. ${wpa2 ? "On WPA2, someone in range who records a device joining can try guesses at home." : "WPA3 forces live tries, which helps a lot, but pick a better one anyway."}`;
    else if (wpa2 && bad) n = "# not on a popular list, but small enough to be tried in full by a well-funded guesser. Make it longer.";
    else if (wpa2) n = `# strong: even trying 100 million a second against a recording, trying all of them would take ${fmtTime(secs)}.`;
    else n = "# WPA3: each guess has to be a live try against your router, and a recording of someone joining gives a listener nothing to test offline. Length still matters.";
    if (v === lastGen) n += " Made in this page with crypto.getRandomValues; it isn't stored or sent.";
    note.textContent = n;
  }

  const SSID_BRANDS = /(netgear|linksys|tp-?link|d-?link|asus|xfinity|spectrum|verizon|comcast|virgin|belkin|arris|technicolor|huawei|fritz)/i;
  const SSID_ADDRESS = /\b(apt|apartment|flat|unit|suite)\b\s*#?\d|\b\d{1,5}\s+[a-z]+\s+(st|street|rd|road|ave|avenue|ln|lane|dr|drive)\b/i;
  function ssid() {
    const v = $("wf-ssid").value.trim(), t = v.toLowerCase(), note = $("wf-ssid-note");
    if (!v) note.textContent = "# a name that says who lives here, or which router you own, helps a stranger.";
    else if (t === "fbi surveillance van") note.textContent = "# the classic joke name. And a fair rule: a name that says nothing about who lives here.";
    else if (/^pretty fly for a wi-?fi$/.test(t)) note.textContent = "# a classic. A name that says nothing about who lives here or what you own is exactly right.";
    else if (SSID_ADDRESS.test(v)) note.textContent = "# that looks like an address: the FTC says to keep addresses and names out of the network name.";
    else if (SSID_BRANDS.test(v)) note.textContent = "# that looks like a factory name. It tells a stranger which router you own (the FTC says to avoid router brands): pick something neutral.";
    else note.textContent = "# a neutral name: it says nothing about who lives here or what router you own.";
  }

  // --------------------------------------------------------------------------- UPnP
  const UPNP = [
    { k: "game", who: "Game console", ask: "Open port 3074 for online play", why: "A device you trust, with a reason. Leave it closed if play works without." },
    { k: "cam", who: "Doorbell camera", ask: "Open port 8080 so I can be reached from outside", why: "Risky: use the maker's app with two-step sign-in, not a direct door." },
    { k: "media", who: "Old media player", ask: "Open port 5000 for streaming", why: "Rarely needed. Turn it off unless something breaks." },
    { k: "mystery", who: "Unknown device", ask: "Open port 23 (Telnet) to the internet", why: "Alarm: nothing at home needs this. It's the remote-login door Mirai-style malware seeks." },
  ];
  let umode = "on";
  const uopen = {};
  function upnpDraw() {
    press($("up-mode"), "data-m", umode);
    const isOpen = (u) => umode === "on" || (umode === "hand" && !!uopen[u.k]);
    $("up-list").innerHTML = UPNP.map((u) => {
      const o = isOpen(u);
      const state = umode === "hand"
        ? `<button type="button" class="btn btn-sm${o ? "" : " btn-ghost"}" data-k="${u.k}" aria-pressed="${o}">${o ? "Close it" : "Open it"}</button>`
        : `<b class="chip ${o ? "bad" : "ok"}">${o ? "open" : "refused"}</b>`;
      return `<li class="upnp-item${o ? " open" : ""}"><div><b>${esc(u.who)}</b><span>asks: ${esc(u.ask)}</span><small>${esc(u.why)}</small></div>${state}</li>`;
    }).join("");
    const n = UPNP.filter(isOpen).length;
    $("up-count").innerHTML = `<b class="${n ? "bad" : "ok"}">${n} of ${UPNP.length}</b> doors open to the internet, decided by ${umode === "on" ? "the devices" : umode === "off" ? "no one" : "you"}.`;
    let note;
    if (umode === "on") note = "# UPnP on: four devices opened four doors and nobody asked you, including the one no one in the house should trust.";
    else if (umode === "off") note = "# UPnP off: every request refused. If a game complains, open its one port by hand.";
    else if (!n) note = "# you decide: closed unless you say so. Open only what you can explain.";
    else if (uopen.mystery) note = "# you opened the telnet door. Nothing at home needs it: close it, then find out which device asked.";
    else if (n === 1 && uopen.game) note = "# one door, one reason, chosen by you. That's port forwarding done sensibly.";
    else note = `# ${n} door${n === 1 ? "" : "s"} open, each one chosen by you. Ask of each: what is it for, and is there a safer way?`;
    $("up-note").textContent = note;
  }

  // --------------------------------------------------------------------------- fix this router
  const RF = [
    { k: "login", label: "Admin login", opts: ["admin / admin (factory)", "A unique admin password"], ok: [1], best: 1,
      why: "The factory login is on the label and in lists online. Mirai-style malware tries lists of them (CISA)." },
    { k: "fw", label: "Firmware", opts: ["2019 version, no auto-update", "Latest, auto-update on"], ok: [1], best: 1,
      why: "Updates close known holes. The FBI says criminals use old routers that no longer get them." },
    { k: "remote", label: "Remote management", opts: ["On: reachable from the internet", "Off"], ok: [1], best: 1,
      why: "It puts the settings page on the internet. Turn it off unless you truly need it (FTC, FBI)." },
    { k: "wps", label: "WPS setup PIN", opts: ["On", "Off"], ok: [1], best: 1,
      why: "The 8-digit PIN can be guessed in about 11,000 tries (CERT/CC). Join devices with the passphrase." },
    { k: "upnp", label: "UPnP", opts: ["On", "Off"], ok: [1], best: 1,
      why: "It lets any device open a door in your firewall. Off, unless something truly needs it (FTC, CISA)." },
    { k: "wifi", label: "Wi-Fi security", opts: ["Open (no password)", "WPA / TKIP (old)", "WPA2 / AES", "WPA3"], ok: [2, 3], best: 3,
      why: "WPA3 is best; WPA2 with AES is fine if a device needs it. Open, WEP and old WPA/TKIP are not (Apple, FTC)." },
    { k: "pass", label: "Wi-Fi passphrase", opts: ["sunshine2020", "Six random words"], ok: [1], best: 1,
      why: "A word and a year is near the top of guess lists. Long and random is not." },
    { k: "guest", label: "Guest network", opts: ["Off: guests use your network", "On: own passphrase, kept apart"], ok: [1], best: 1,
      why: "Guests and their devices stay off your main network, and your main passphrase stays private (FTC)." },
  ];
  let rfState = RF.map(() => 0), rfChecked = false;
  function rfDraw() {
    $("rf-list").innerHTML = RF.map((r, i) => {
      const s = rfState[i], good = r.ok.includes(s);
      const mark = rfChecked ? (good ? " ok" : " bad") : "";
      return `<li><button type="button" class="perm${mark}" data-i="${i}"><span>${esc(r.label)}</span><b>${esc(r.opts[s])}</b></button></li>`;
    }).join("");
    const why = $("rf-why");
    why.hidden = !rfChecked;
    $("rf-help").hidden = rfChecked;
    why.innerHTML = rfChecked ? RF.map((r, i) => {
      const s = rfState[i], good = r.ok.includes(s);
      const label = !good ? "Fix" : s === r.best ? "Best" : "OK";
      return `<li class="${good ? "ok" : "bad"}"><b>${label}</b><span>${esc(r.label)}: ${esc(r.why)}</span></li>`;
    }).join("") : "";
  }
  function rfToggle(i) {
    rfState[i] = (rfState[i] + 1) % RF[i].opts.length;
    rfChecked = false;
    rfDraw();
    $("rf-note").textContent = "Tap each setting to change it, then check your router.";
  }
  function rfCheck() {
    rfChecked = true;
    rfDraw();
    const n = RF.filter((r, i) => r.ok.includes(rfState[i])).length;
    const unchanged = rfState.every((s) => s === 0);
    const allBest = RF.every((r, i) => rfState[i] === r.best);
    let t;
    if (allBest) t = "# a model router: every door locked, every setting boring. Boring is the goal.";
    else if (n === RF.length) t = "# 8 of 8. WPA2 with AES is fine; WPA3 is the bonus if your devices can manage it.";
    else if (unchanged) t = "# factory settings, every one. That's how most routers start out, and nobody's judging: this list is what the evening is for.";
    else if (rfState[RF.findIndex((r) => r.k === "wifi")] === 0) t = `# an open network: anyone in range can join, and anyone nearby can read along on sites without HTTPS. Cafés do it on purpose. A home shouldn't. (${n} of ${RF.length} right.)`;
    else t = `# ${n} of ${RF.length}. Start with what's left among the first four settings: they're the big wins.`;
    $("rf-note").textContent = t;
  }
  function rfReset() {
    rfState = RF.map(() => 0); rfChecked = false; rfDraw();
    $("rf-note").textContent = "";
  }

  // --------------------------------------------------------------------------- the house: what can each device reach?
  const HM = [
    { k: "laptop", n: "Laptop", z: "main" }, { k: "phone", n: "Phone", z: "main" }, { k: "nas", n: "Backup drive", z: "main" },
    { k: "tv", n: "Smart TV", z: "smart" }, { k: "cam", n: "Doorbell camera", z: "smart" }, { k: "plug", n: "Smart plug", z: "smart" },
    { k: "vac", n: "Robot vacuum", z: "smart" }, { k: "guest", n: "Visitor's phone", z: "guest" },
  ];
  const ZN = { main: "Main network", smart: "Smart network", guest: "Guest network" };
  let hmMode = "flat", hmSel = "plug";
  function hmDraw() {
    press($("hm-mode"), "data-m", hmMode);
    const cur = HM.find((d) => d.k === hmSel);
    const reach = HM.filter((o) => o.k !== cur.k && (hmMode === "flat" || o.z === cur.z));
    const out = HM.filter((o) => o.k !== cur.k && !reach.includes(o));
    $("hm-house").innerHTML = HM.map((d) => {
      const cls = ["dev", hmMode === "split" ? "z-" + d.z : "z-flat"];
      if (d.k === cur.k) cls.push("sel"); else if (reach.includes(d)) cls.push("reach"); else cls.push("blocked");
      return `<button type="button" class="${cls.join(" ")}" data-k="${d.k}" aria-pressed="${d.k === cur.k}"><b>${esc(d.n)}</b><small>${hmMode === "split" ? ZN[d.z] : "same network"}</small></button>`;
    }).join("");
    const names = reach.map((d) => d.n);
    $("hm-out").innerHTML = `<b>${esc(cur.n)}</b> can reach: ${names.length ? esc(names.join(", ")) + " and the internet" : "only the internet"}.` +
      (out.length ? `<br><span class="muted">Out of reach: ${esc(out.map((d) => d.n).join(", "))}.</span>` : "");
    $("hm-note").textContent = hmMode === "flat"
      ? `# one network: if the ${cur.n.toLowerCase()} were hacked, every other device would be within its reach.`
      : reach.length ? `# ${reach.length} other device${reach.length === 1 ? "" : "s"} in reach, instead of ${HM.length - 1}. The rest stay out of its way.`
      : "# nothing else in the house in reach: it can only talk to the internet.";
  }

  // --------------------------------------------------------------------------- sorter: which network?
  const SO = [
    { k: "laptop", n: "Your laptop", ok: ["main"], why: "It holds your accounts and files, and you keep it updated." },
    { k: "phone", n: "Your phone", ok: ["main"], why: "Same as the laptop: your accounts live on it, and it updates itself." },
    { k: "nas", n: "Backup drive with family photos", ok: ["main"], why: "What you most want to protect belongs with the devices you trust and keep updated." },
    { k: "tv", n: "Smart TV", ok: ["smart"], why: "It collects viewing data, may stop getting updates, and has no need to see your laptop." },
    { k: "cam", n: "Doorbell camera", ok: ["smart"], why: "A camera is a window into your home. Keep it apart from your devices, and lock its account too." },
    { k: "vac", n: "Robot vacuum", ok: ["smart"], why: "It may hold a map of your home, and it won't get updates for ever." },
    { k: "kettle", n: "Smart kettle", ok: ["smart"], why: "It needs the internet, not your other devices." },
    { k: "printer", n: "Printer", ok: ["main", "smart"], why: "A judgement call: printing may need the same network as your computers, but printers rarely update." },
    { k: "visitor", n: "A visitor's tablet", ok: ["guest"], why: "It isn't yours, so you can't know what's on it." },
  ];
  const soPick = {};
  let soChecked = false;
  function soDraw() {
    $("so-list").innerHTML = SO.map((d) => {
      const c = soPick[d.k];
      const mark = soChecked && c ? (d.ok.includes(c) ? " ok" : " bad") : "";
      const btns = ["main", "smart", "guest"].map((z) => `<button type="button" data-k="${d.k}" data-z="${z}" aria-pressed="${c === z}">${z}</button>`).join("");
      return `<li class="so-row${mark}"><span>${esc(d.n)}</span><div class="seg-pick" role="group" aria-label="Network for ${esc(d.n)}">${btns}</div></li>`;
    }).join("");
    const why = $("so-why");
    why.hidden = !soChecked;
    $("so-help").hidden = soChecked;
    why.innerHTML = soChecked ? SO.map((d) => {
      const c = soPick[d.k], good = c && d.ok.includes(c);
      return `<li class="${good ? "ok" : "bad"}"><b>${good ? "Right" : d.ok.join(" / ")}</b><span>${esc(d.n)}: ${esc(d.why)}</span></li>`;
    }).join("") : "";
  }
  function soCheck() {
    soChecked = true;
    soDraw();
    const answered = SO.filter((d) => soPick[d.k]).length;
    const right = SO.filter((d) => soPick[d.k] && d.ok.includes(soPick[d.k])).length;
    let t;
    if (!answered) t = "# nothing sorted yet. Pick a network for each device.";
    else if (right === SO.length) t = "# a tidy network. Even the kettle approves.";
    else t = `# ${right} of ${SO.length}. The test: would I mind if this were hacked, and can I keep it updated? Yes and yes is Main; no and no is Smart.`;
    $("so-note").textContent = t;
  }
  function soReset() {
    for (const k of Object.keys(soPick)) delete soPick[k];
    soChecked = false; soDraw(); $("so-note").textContent = "";
  }

  // --------------------------------------------------------------------------- an old device lost its updates
  const eo = { sens: null, off: null };
  function eoDraw() {
    for (const g of document.querySelectorAll(".eo [data-q]")) press(g, "data-v", eo[g.dataset.q] || "");
    const o = $("eo-out");
    if (eo.sens === null || eo.off === null) { o.textContent = "Answer both questions."; return; }
    if (eo.sens === "y") o.textContent = "Replace it soon: cameras, microphones and locks are what you most want updated. Until then, keep it on the smart or guest network, switch off remote access, and lock its account with two-step sign-in.";
    else if (eo.off === "y") o.textContent = "Take it off the internet (or keep it on the smart network with cloud features off). It can keep doing its job.";
    else o.textContent = "Keep it on the smart or guest network while it works, and plan to replace it: when its cloud service ends, it won't do its job anyway.";
  }

  // --------------------------------------------------------------------------- who can see what?
  const DNS_ROWS = [
    { what: "The website names your devices look up", plain: "Your provider, and anyone on the path: it isn't encrypted.", enc: "Only the resolver you chose, which still sees every one." },
    { what: "Which servers you connect to, and when", plain: "Your provider, which carries the traffic.", enc: "Your provider, which still carries the traffic." },
    { what: "A website's name in the connection setup", plain: "Your provider, usually.", enc: "Your provider, usually, unless the site uses Encrypted Client Hello." },
    { what: "The pages you read, what you type, your passwords (HTTPS sites)", plain: "Only you and the site.", enc: "Only you and the site.", good: true },
  ];
  let dmode = "plain";
  function dnsDraw() {
    press($("dn-mode"), "data-m", dmode);
    $("dn-rows").innerHTML = DNS_ROWS.map((r) => `<tr><th>${esc(r.what)}</th><td class="${r.good ? "ok" : ""}">${esc(dmode === "plain" ? r.plain : r.enc)}</td></tr>`).join("");
    $("dn-note").textContent = dmode === "plain"
      ? "# plain DNS: your provider carries your traffic and sees each name your devices look up."
      : "# encrypted DNS: one fewer way for your provider to learn site names. The resolver you chose knows them instead.";
  }

  // --------------------------------------------------------------------------- myth or real?
  const MYTHS = [
    { c: "Hiding my Wi-Fi network's name makes it secure.", a: "myth", v: "Myth",
      why: "Apple's router guidance says hiding the name \"doesn't conceal the network from detection or secure it against unauthorized access\". Your own devices still look for it by name. The mode and the passphrase are what protect you." },
    { c: "Filtering by device address (MAC filtering) keeps strangers out.", a: "myth", v: "Myth",
      why: "Apple says you shouldn't rely on it: device addresses can be copied, spoofed or changed. It mostly locks out your own new devices." },
    { c: "My smart TV can't tell anyone what I watch.", a: "myth", v: "Myth, on many TVs",
      why: "In 2017 the FTC said Vizio's TVs captured second-by-second viewing data without informed consent. The FTC still tells people to review a smart TV's tracking settings." },
    { c: "A guest network keeps a visitor's infected phone away from my own devices.", a: "real", v: "Real",
      why: "That's what it's for: the FTC says it keeps guest devices that might carry malware off your primary network, and keeps your main passphrase private." },
    { c: "A router that no longer gets updates is a risk even though it still works.", a: "real", v: "Real",
      why: "The FBI warned in May 2025 that old routers without updates were being taken over through known flaws and used to hide criminals' traffic." },
  ];
  let mi = 0, mscore = 0, mdone = false;
  function mythShow() {
    const m = MYTHS[mi];
    $("mq-count").textContent = `Claim ${mi + 1} of ${MYTHS.length}`;
    $("mq-claim").textContent = m.c;
    $("mq-verdict").hidden = true; $("mq-next").hidden = true; $("mq-why").textContent = "";
    for (const b of $("mq-btns").querySelectorAll("[data-a]")) { b.disabled = false; b.hidden = false; }
    mdone = false;
  }
  function mythAnswer(a) {
    if (mdone) return; mdone = true;
    const m = MYTHS[mi], ok = a === m.a;
    if (ok) mscore++;
    for (const b of $("mq-btns").querySelectorAll("[data-a]")) b.disabled = true;
    const v = $("mq-verdict"); v.hidden = false;
    v.className = "verdict " + (ok ? "ok" : "bad");
    v.textContent = (ok ? "Right: " : "Not quite: ") + m.v + ".";
    $("mq-why").textContent = m.why;
    $("mq-score").textContent = `Score: ${mscore} / ${mi + 1}`;
    $("mq-next").hidden = false;
    $("mq-next").textContent = mi === MYTHS.length - 1 ? "See score" : "Next ›";
  }
  function mythNext() {
    if (mi < MYTHS.length - 1) { mi++; mythShow(); return; }
    const n = MYTHS.length;
    let s = `Final score: ${mscore} / ${n}.`;
    if (mscore === n) s += " # all five. You could give this slide yourself.";
    else if (mscore === 0) s += " # zero, so the folk wisdom did its job. Now you know which to drop.";
    else s += " # the pattern: advice that feels clever (hide, filter) is weaker than advice that feels boring (update, separate, encrypt).";
    $("mq-score").textContent = s;
    $("mq-claim").textContent = `That's all ${n}.`;
    $("mq-count").textContent = ""; $("mq-verdict").hidden = true; $("mq-why").textContent = "";
    for (const b of $("mq-btns").querySelectorAll("[data-a]")) b.hidden = true;
    $("mq-next").textContent = "Play again";
    $("mq-next").onclick = () => { mi = 0; mscore = 0; $("mq-next").onclick = null; $("mq-score").textContent = ""; mythShow(); };
  }

  // --------------------------------------------------------------------------- the evening checklist (kept in this browser only)
  const HN_KEY = "home-network-checklist";
  function checklist() {
    const boxes = Array.from(document.querySelectorAll("#hn-plan input[type=checkbox]"));
    let saved = {};
    try { saved = JSON.parse(store(HN_KEY) || "{}"); } catch (e) {}
    boxes.forEach((b) => { b.checked = !!saved[b.dataset.k]; });
    const update = () => {
      const done = boxes.filter((b) => b.checked).length;
      store(HN_KEY, JSON.stringify(Object.fromEntries(boxes.map((b) => [b.dataset.k, b.checked]))));
      const note = $("hn-note"); note.className = "comment";
      if (done === boxes.length) { note.textContent = "# all twelve. Your network is now boring in the best possible way."; note.classList.add("ok"); }
      else if (done === 0) note.textContent = "# tick off what's already done on your own router. Ticks are saved in this browser only.";
      else note.textContent = `# ${done} of ${boxes.length} done. What's left is tonight's homework: start with group 1.`;
    };
    boxes.forEach((b) => b.addEventListener("change", update));
    update();
  }

  // --------------------------------------------------------------------------- console hint
  function consoleHint() {
    console.log("%cSecuring Your Home Network", "font: 700 24px monospace; color: #ff2e88; text-shadow: 0 0 8px #ff2e88");
    console.log("%cYou opened the developer console on a talk about home networks. Bonus tip: your router's admin address and factory login are often printed on a label on the router itself. That's one more reason to change the login.", "font: 14px monospace; color: #00f0ff");
  }

  function start() {
    consoleHint();
    $("hero-in").addEventListener("input", hero); hero();

    $("wf-in").addEventListener("input", wifi);
    for (const b of $("wf-presets").querySelectorAll("button")) b.addEventListener("click", () => {
      if (b.dataset.gen) { lastGen = generate(b.dataset.gen); lastKind = b.dataset.gen; $("wf-in").value = lastGen; } else { $("wf-in").value = b.dataset.v; lastGen = ""; lastKind = ""; }
      wifi();
    });
    for (const b of $("wf-mode").querySelectorAll("button")) b.addEventListener("click", () => { wmode = b.dataset.m; press($("wf-mode"), "data-m", wmode); wifi(); });
    $("wf-ssid").addEventListener("input", ssid);
    wifi(); ssid();

    for (const b of $("up-mode").querySelectorAll("button")) b.addEventListener("click", () => { umode = b.dataset.m; upnpDraw(); });
    $("up-list").addEventListener("click", (e) => { const b = e.target.closest("[data-k]"); if (b) { uopen[b.dataset.k] = !uopen[b.dataset.k]; upnpDraw(); } });
    upnpDraw();

    $("rf-list").addEventListener("click", (e) => { const b = e.target.closest("[data-i]"); if (b) rfToggle(+b.dataset.i); });
    click("rf-check", rfCheck); click("rf-reset", rfReset);
    rfDraw();

    for (const b of $("hm-mode").querySelectorAll("button")) b.addEventListener("click", () => { hmMode = b.dataset.m; hmDraw(); });
    $("hm-house").addEventListener("click", (e) => { const b = e.target.closest("[data-k]"); if (b) { hmSel = b.dataset.k; hmDraw(); } });
    hmDraw();

    $("so-list").addEventListener("click", (e) => {
      const b = e.target.closest("[data-z]");
      if (b) { soPick[b.dataset.k] = b.dataset.z; soChecked = false; soDraw(); $("so-note").textContent = ""; }
    });
    click("so-check", soCheck); click("so-reset", soReset);
    soDraw();

    for (const g of document.querySelectorAll(".eo [data-q]")) g.addEventListener("click", (e) => {
      const b = e.target.closest("[data-v]"); if (b) { eo[g.dataset.q] = b.dataset.v; eoDraw(); }
    });
    eoDraw();

    for (const b of $("dn-mode").querySelectorAll("button")) b.addEventListener("click", () => { dmode = b.dataset.m; dnsDraw(); });
    dnsDraw();

    for (const b of $("mq-btns").querySelectorAll("[data-a]")) b.addEventListener("click", () => mythAnswer(b.dataset.a));
    $("mq-next").addEventListener("click", () => { if (!$("mq-next").onclick) mythNext(); });
    mythShow();

    checklist();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
})();
