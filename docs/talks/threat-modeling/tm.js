/* tm.js - the logic behind the demos in "Threat Modeling in Practice".
   It models a system as a data-flow diagram (elements, flows, trust zones), lists the STRIDE prompts each element and flow
   earns, keeps a small threat log, ranks and answers threats, writes tickets, and evaluates a toy attack tree.
   Pure functions, no DOM: it runs in the browser (window.TMLab) and in Node (module.exports) so it can be tested.
   Everything here is a teaching model: the systems, threats and numbers are invented for the workshop. */
(function (root) {
  "use strict";

  // --------------------------------------------------------------------------- STRIDE
  const STRIDE = [
    { k: "S", name: "Spoofing", prop: "Authenticity", defence: "Authentication", ask: "Can someone pretend to be this?", ex: "Using a stolen session token to act as another user." },
    { k: "T", name: "Tampering", prop: "Integrity", defence: "Integrity checks and permissions", ask: "Can someone change this when they shouldn't?", ex: "Editing the price in a request, or a file on a shared drive." },
    { k: "R", name: "Repudiation", prop: "Non-repudiation (accountability)", defence: "Logging and audit trails", ask: "Could someone do this and later deny it, with nothing to show otherwise?", ex: "An admin action with no log line saying who did it." },
    { k: "I", name: "Information disclosure", prop: "Confidentiality", defence: "Encryption and access control", ask: "Can someone read this who shouldn't?", ex: "A response that includes fields the caller never needed." },
    { k: "D", name: "Denial of service", prop: "Availability", defence: "Rate limits, quotas and redundancy", ask: "Can someone make this slow, full or unavailable?", ex: "One caller asking for a million rows, again and again." },
    { k: "E", name: "Elevation of privilege", prop: "Authorization", defence: "Least privilege and checks on every request", ask: "Can someone do something their role shouldn't allow?", ex: "A normal user calling an admin-only function directly." },
  ];
  const STRIDE_KEYS = STRIDE.map((s) => s.k);
  const strideByKey = (k) => STRIDE.find((s) => s.k === k) || null;

  // Which letters apply to which kind of element (the usual "STRIDE per element" chart).
  // Data stores that hold logs also earn Repudiation. Data-flow spoofing is usually handled at the endpoints.
  const ELEMENT_TYPES = ["entity", "process", "store", "flow"];
  const TYPE_LABEL = { entity: "External entity", process: "Process", store: "Data store", flow: "Data flow" };
  function perElement(type, isLog) {
    let letters;
    if (type === "entity") letters = "SR";
    else if (type === "process") letters = "STRIDE";
    else if (type === "store") letters = isLog ? "TRID" : "TID";
    else if (type === "flow") letters = "TID";
    else return [];
    return STRIDE_KEYS.filter((k) => letters.indexOf(k) >= 0);
  }

  // Guess an element's kind from its name (used by the title-slide toy and as a hint in the builder).
  const RE_LOG = /\b(audit|access|event|security)?\s*(logs?|audit trail)\b/i;
  const RE_STORE = /\b(database|db|datastore|store|bucket|storage|cache|queue|logs?|audit trail|file|files|disk|vault|keystore|key store|table|s3|blob|backup)\b/i;
  const RE_ENTITY = /\b(user|users|customer|admin|administrator|person|people|provider|partner|vendor|third.?party|bank|dns|resolver|external|visitor|attendee)\b/i;
  const RE_PROCESS = /\b(app|application|api|server|service|worker|function|lambda|gateway|proxy|processor|job|backend|site|website|login|form|page|code|script|handler|endpoint|browser)\b/i;
  const RE_FLOW = /(->|→|\bflow\b|\brequest\b|\bresponse\b|\bcall\b|\bwebhook\b|\bupload\b|\bdownload\b|\bconnection\b)/i;
  function classify(name) {
    const s = String(name == null ? "" : name).trim();
    if (!s) return { type: null, log: false };
    if (RE_FLOW.test(s)) return { type: "flow", log: false };
    if (RE_STORE.test(s)) return { type: "store", log: RE_LOG.test(s) };
    if (RE_ENTITY.test(s)) return { type: "entity", log: false };
    if (RE_PROCESS.test(s)) return { type: "process", log: false };
    return { type: null, log: false };
  }

  // --------------------------------------------------------------------------- the data-flow model
  const ZONES = [
    { id: "device", name: "User's device", short: "Device" },
    { id: "cloud", name: "Our cloud", short: "Our cloud" },
    { id: "third", name: "Third party", short: "Third party" },
  ];
  const zoneById = (id) => ZONES.find((z) => z.id === id) || null;

  function createModel() { return { nodes: [], flows: [], seq: 1 }; }
  const nodeById = (m, id) => m.nodes.find((n) => n.id === id) || null;
  const nodeByName = (m, name) => m.nodes.find((n) => n.name.toLowerCase() === String(name).trim().toLowerCase()) || null;

  function addNode(m, o) {
    const name = String(o && o.name != null ? o.name : "").trim().slice(0, 32);
    if (!name) return { ok: false, error: "Give the element a name." };
    if (ELEMENT_TYPES.indexOf(o.type) < 0 || o.type === "flow") return { ok: false, error: "Pick what kind of element it is." };
    if (!zoneById(o.zone)) return { ok: false, error: "Pick which side of the line it lives on." };
    if (nodeByName(m, name)) return { ok: false, error: "There's already an element called \"" + name + "\"." };
    const node = { id: "n" + m.seq++, name, type: o.type, zone: o.zone, log: o.type === "store" && !!o.log };
    m.nodes.push(node);
    return { ok: true, node };
  }
  function removeNode(m, id) {
    const i = m.nodes.findIndex((n) => n.id === id);
    if (i < 0) return false;
    m.nodes.splice(i, 1);
    m.flows = m.flows.filter((f) => f.from !== id && f.to !== id);
    return true;
  }
  function addFlow(m, o) {
    const a = nodeById(m, o && o.from), b = nodeById(m, o && o.to);
    const label = String(o && o.label != null ? o.label : "").trim().slice(0, 28);
    if (!a || !b) return { ok: false, error: "Pick both ends of the flow." };
    if (a.id === b.id) return { ok: false, error: "A flow needs two different ends." };
    if (a.type !== "process" && b.type !== "process")
      return { ok: false, error: "In a data-flow diagram, data moves through a process: " + TYPE_LABEL[a.type].toLowerCase() + " to " + TYPE_LABEL[b.type].toLowerCase() + " skips the code that handles it. Add or pick a process." };
    if (m.flows.some((f) => f.from === a.id && f.to === b.id && f.label.toLowerCase() === label.toLowerCase()))
      return { ok: false, error: "That flow is already on the diagram." };
    const flow = { id: "f" + m.seq++, from: a.id, to: b.id, label: label || "data" };
    m.flows.push(flow);
    return { ok: true, flow };
  }
  const flowKey = (m, f) => nodeById(m, f.from).name + "→" + nodeById(m, f.to).name;
  const crosses = (m, f) => nodeById(m, f.from).zone !== nodeById(m, f.to).zone;
  const crossings = (m) => m.flows.filter((f) => crosses(m, f));

  // Every element and flow with the STRIDE letters it earns, crossing flows first.
  function enumerate(m) {
    const rows = [];
    for (const f of m.flows) rows.push({ id: f.id, kind: "flow", label: flowKey(m, f) + " (" + f.label + ")", type: "flow", letters: perElement("flow"), crossing: crosses(m, f) });
    for (const n of m.nodes) rows.push({ id: n.id, kind: "node", label: n.name, type: n.type, letters: perElement(n.type, n.log), crossing: false });
    rows.sort((x, y) => (y.crossing ? 1 : 0) - (x.crossing ? 1 : 0));
    return rows;
  }
  const promptCount = (m) => enumerate(m).reduce((n, r) => n + r.letters.length, 0);

  // Common drawing mistakes, as a coach would point them out.
  function lint(m) {
    const out = [];
    if (!m.nodes.length) return ["Add a few elements: who uses the system, what runs, and where data rests."];
    for (const n of m.nodes) {
      const ins = m.flows.filter((f) => f.to === n.id).length, outs = m.flows.filter((f) => f.from === n.id).length;
      if (!ins && !outs) out.push("\"" + n.name + "\" has no flows. If nothing talks to it, why is it on the diagram?");
      else if (n.type === "process" && ins && !outs) out.push("\"" + n.name + "\" only receives data: a black hole. What does it send, store or return?");
      else if (n.type === "process" && !ins && outs) out.push("\"" + n.name + "\" only sends data: a miracle. What triggers it or feeds it?");
    }
    if (m.nodes.length >= 3 && new Set(m.nodes.map((n) => n.zone)).size < 2)
      out.push("Everything sits in one zone, so there's no trust boundary to cross. Who runs each part, and who controls it?");
    else if (m.flows.length && !crossings(m).length)
      out.push("No flow crosses a boundary. Where does data move from less trusted to more trusted?");
    return out;
  }

  // Two invented systems for the workshop. Zones: device, cloud, third.
  function buildPhoto() {
    const m = createModel(), A = (name, type, zone, log) => addNode(m, { name, type, zone, log }).node;
    const user = A("User", "entity", "device"), app = A("Mobile app", "process", "device");
    const api = A("API", "process", "cloud"), proc = A("Image processor", "process", "cloud");
    const photos = A("Photo storage", "store", "cloud"), db = A("User database", "store", "cloud"), log = A("Audit log", "store", "cloud", true);
    const pay = A("Payment provider", "entity", "third");
    const F = (a, b, label) => addFlow(m, { from: a.id, to: b.id, label });
    F(user, app, "taps"); F(app, api, "HTTPS requests"); F(api, db, "accounts"); F(api, photos, "photos"); F(photos, proc, "new uploads");
    F(proc, photos, "thumbnails"); F(api, log, "events"); F(api, pay, "checkout"); F(pay, api, "webhook");
    return m;
  }
  function buildWebsite() {
    const m = createModel(), A = (name, type, zone, log) => addNode(m, { name, type, zone, log }).node;
    const visitor = A("Visitor", "entity", "device"), browser = A("Browser", "process", "device");
    const dns = A("DNS resolver", "entity", "third"), ca = A("Certificate authority", "entity", "third");
    const web = A("Web server", "process", "cloud"), keys = A("Key store", "store", "cloud"), db = A("Orders database", "store", "cloud");
    const F = (a, b, label) => addFlow(m, { from: a.id, to: b.id, label });
    F(visitor, browser, "types a URL"); F(browser, dns, "name lookup"); F(browser, web, "HTTPS"); F(web, keys, "private key use");
    F(web, db, "orders"); F(web, ca, "certificate renewal");
    return m;
  }
  const SAMPLES = { photo: { name: "Photo-sharing app", build: buildPhoto }, website: { name: "The Crypto 101 secure website", build: buildWebsite } };

  // A reference answer per sample: target is a node name or a "From→To" flow key. l and i are 1 to 3.
  const REFERENCE = {
    photo: [
      { target: "API", cat: "S", text: "A stolen session token lets someone act as another user.", fix: "Short-lived tokens, device binding where you can, and a way to sign out everywhere.", l: 2, i: 3 },
      { target: "Mobile app→API", cat: "T", text: "A request edited in transit or by a modified app changes someone else's photo.", fix: "TLS everywhere, and the server checks ownership on every request instead of trusting the app.", l: 2, i: 2 },
      { target: "API", cat: "E", text: "Changing a photo ID in a request returns another user's private photo.", fix: "An ownership check on every object, scoped queries, and tests that try another user's IDs.", l: 3, i: 3 },
      { target: "API", cat: "D", text: "One caller uploads huge files or asks for thousands of photos at a time.", fix: "Size limits, page-size caps, per-user rate limits and quotas.", l: 3, i: 2 },
      { target: "API", cat: "R", text: "A support agent deletes an album and nothing records who did it.", fix: "An audit event for every privileged action, with who, what and when.", l: 2, i: 2 },
      { target: "Photo storage", cat: "I", text: "A storage bucket is public, or its links never expire.", fix: "Private by default, short-lived signed links, and a policy check in the pipeline.", l: 2, i: 3 },
      { target: "Photo storage", cat: "T", text: "Anyone with write access can replace a photo with something else.", fix: "Separate read and write roles, versioning, and a content hash recorded at upload.", l: 1, i: 2 },
      { target: "Image processor", cat: "D", text: "A crafted image makes the processor use all its memory and fall over.", fix: "Run it isolated with memory and time limits, and cap image dimensions.", l: 2, i: 2 },
      { target: "Image processor", cat: "E", text: "A bug in an image library lets a bad file run code with the processor's permissions.", fix: "Least-privilege role, no network access from the processor, and keep the library updated.", l: 1, i: 3 },
      { target: "User database", cat: "I", text: "Backups and exports copy every user's details to places with weaker controls.", fix: "Encrypt backups, limit who can export, and keep fewer fields in the first place.", l: 2, i: 3 },
      { target: "Audit log", cat: "T", text: "Someone with admin access edits the log to hide their own activity.", fix: "Ship logs to a separate, append-only place the same admins can't change.", l: 1, i: 2 },
      { target: "Audit log", cat: "R", text: "Logs don't record which user an action was for, so nobody can reconstruct events.", fix: "Log a user ID and request ID on every event, and test that the fields arrive.", l: 2, i: 2 },
      { target: "API", cat: "S", text: "A fake \"payment succeeded\" message is sent to the webhook address.", fix: "Verify the provider's signature on every webhook and check the payment's state with the provider.", l: 2, i: 3 },
      { target: "Payment provider→API", cat: "I", text: "Webhook bodies are written to logs with customer details inside.", fix: "Log IDs, not bodies, and scrub known fields before anything is stored.", l: 2, i: 2 },
      { target: "API→Payment provider", cat: "D", text: "The provider has an outage and checkout can't complete.", fix: "A clear error, a retry queue, and a plan for what the app does while it waits.", l: 2, i: 2 },
      { target: "User", cat: "R", text: "A user disputes a purchase and the app can't show what they agreed to.", fix: "Record the confirmation step and its timestamp with the order.", l: 2, i: 1 },
    ],
    website: [
      { target: "Browser", cat: "S", text: "A forged answer sends visitors to the wrong server.", fix: "The certificate must match the name: HTTPS catches a wrong server even when the lookup lies.", l: 2, i: 2 },
      { target: "Browser→Web server", cat: "T", text: "Someone on the path changes the page on its way to the visitor.", fix: "TLS with a valid certificate, and HSTS so the browser won't fall back to plain HTTP.", l: 2, i: 3 },
      { target: "Browser→Web server", cat: "I", text: "Someone on the same network reads what the visitor sends.", fix: "TLS 1.3 with forward secrecy, which Crypto 101 and How HTTPS Really Works walk through.", l: 2, i: 3 },
      { target: "Key store", cat: "I", text: "The private key is copied out of the server.", fix: "Keep it in a key service or hardware module where the server can use it but not read it.", l: 1, i: 3 },
      { target: "Certificate authority", cat: "S", text: "A certificate is issued for the site's name to someone who doesn't own it.", fix: "CAA records, Certificate Transparency monitoring and short-lived certificates.", l: 1, i: 3 },
      { target: "Web server→Certificate authority", cat: "D", text: "Renewal fails silently and the certificate expires.", fix: "Automated renewal with an alert well before expiry.", l: 2, i: 2 },
      { target: "Web server", cat: "E", text: "The web server's database account can drop tables.", fix: "A narrow account for the app and a separate one for migrations.", l: 1, i: 3 },
      { target: "Web server", cat: "R", text: "Nothing records who changed an order's status.", fix: "An audit event for each state change.", l: 2, i: 2 },
    ],
  };

  // --------------------------------------------------------------------------- scoping a threat model
  const SIZES = {
    skip: { name: "Skip it, with a note", mins: "0", who: "The author", what: "No new boundary, data, party or permission: write one line in the pull request saying so." },
    quick: { name: "A quick pass", mins: "15 to 30", who: "The author and one reviewer", what: "Sketch the one flow that changed, run STRIDE on what crosses a boundary, and file anything you find." },
    session: { name: "A short session", mins: "60 to 90", who: "Author, a teammate and someone who runs it in production", what: "Draw the diagram, mark the boundaries, walk every element and flow, rank and assign." },
    deep: { name: "A workshop", mins: "Half a day, in more than one sitting", who: "The team, plus security, operations and anyone who owns the data", what: "Full diagram, STRIDE and privacy prompts, attack trees for the crown jewels, and a follow-up date." },
  };
  const TRIGGERS = [
    { k: "boundary", label: "It crosses a trust boundary that's new" },
    { k: "data", label: "It handles a kind of data you haven't held before" },
    { k: "third", label: "It adds a third party or a new dependency" },
    { k: "authz", label: "It changes who is allowed to do what" },
  ];
  function advise(flags) {
    const n = TRIGGERS.filter((t) => flags && flags[t.k]).length;
    const key = n === 0 ? "skip" : n === 1 ? "quick" : n === 2 ? "session" : "deep";
    return Object.assign({ key, count: n }, SIZES[key]);
  }
  const PRESETS = [
    { label: "Change a button's colour", flags: {} },
    { label: "Add a field to an existing form", flags: { data: true } },
    { label: "Add an analytics SDK", flags: { third: true, data: true } },
    { label: "New public API for partners", flags: { boundary: true, authz: true, third: true } },
    { label: "Let admins impersonate users", flags: { authz: true } },
    { label: "Move to a new cloud account", flags: { boundary: true, authz: true } },
  ];

  // --------------------------------------------------------------------------- the threat log: record, rank, respond, ticket
  const CATS = STRIDE.concat([{ k: "P", name: "Privacy (LINDDUN)", prop: "Privacy", defence: "Data minimisation and transparency", ask: "", ex: "" }]);
  const catName = (k) => (CATS.find((c) => c.k === k) || { name: "Other" }).name;
  function createLog() { return { items: [], seq: 1 }; }
  function addThreat(log, o) {
    const text = String(o && o.text != null ? o.text : "").trim().slice(0, 160);
    const cat = o && o.cat;
    if (text.length < 8) return { ok: false, error: "Describe the threat in a sentence: who does what, and what goes wrong." };
    if (!CATS.some((c) => c.k === cat)) return { ok: false, error: "Pick a category." };
    const clampLI = (v) => Math.min(3, Math.max(1, Math.round(Number(v) || 2)));
    const t = {
      id: "t" + log.seq++, target: String(o.target || "").trim().slice(0, 48), cat, text,
      l: clampLI(o.l), i: clampLI(o.i), fix: String(o.fix || "").trim().slice(0, 160),
      response: o.response || "", owner: String(o.owner || "").trim().slice(0, 32), review: String(o.review || "").trim(),
    };
    log.items.push(t);
    return { ok: true, threat: t };
  }
  function removeThreat(log, id) { const i = log.items.findIndex((t) => t.id === id); if (i < 0) return false; log.items.splice(i, 1); return true; }
  function coverage(log, goal) {
    const g = goal || 2, counts = {};
    for (const k of STRIDE_KEYS) counts[k] = 0;
    for (const t of log.items) if (counts[t.cat] !== undefined) counts[t.cat]++;
    const missing = STRIDE_KEYS.filter((k) => counts[k] < g);
    return { counts, missing, done: missing.length === 0, goal: g };
  }
  const score = (t) => t.l * t.i;
  const band = (s) => (s >= 6 ? "high" : s >= 3 ? "medium" : "low");
  const LEVELS = { 1: "Low", 2: "Medium", 3: "High" };
  function ranked(log) {
    return log.items.slice().sort((a, b) => score(b) - score(a) || b.i - a.i || a.id.localeCompare(b.id, undefined, { numeric: true }));
  }
  const RESPONSES = {
    mitigate: "Mitigate: add a control that makes it harder or less harmful",
    eliminate: "Eliminate: change the design so the threat can't happen",
    transfer: "Transfer: someone better placed takes it on (a provider, insurance, a contract)",
    accept: "Accept: knowingly live with it, written down",
  };
  function validResponse(t, now) {
    const errs = [];
    if (!RESPONSES[t.response]) { errs.push("Pick a response."); return errs; }
    if (!t.owner) errs.push("Every response needs an owner: a name, not a team that doesn't exist yet.");
    if (t.response === "accept") {
      if (!/^\d{4}-\d{2}-\d{2}$/.test(t.review) || isNaN(Date.parse(t.review))) errs.push("Accepting a risk needs a date to look at it again (YYYY-MM-DD).");
      else if (now && Date.parse(t.review) <= Date.parse(now)) errs.push("The review date has to be in the future.");
    } else if (!t.fix) errs.push("Say what the " + t.response + " is, in a few words.");
    return errs;
  }

  const TESTS = {
    S: "Given a request with no credentials, or another user's token, when it calls {t}, then it's rejected and the attempt is logged.",
    T: "Given a request whose body or ID has been changed, when {t} receives it, then the change is refused or has no effect.",
    R: "Given a privileged action on {t}, when it completes, then an audit event records who did it, what changed and when.",
    I: "Given a caller who isn't allowed to see the data, when they reach {t}, then the response contains none of it.",
    D: "Given a caller sending far more than normal to {t}, when the limit is reached, then it answers with a clear refusal and other users are unaffected.",
    E: "Given a user without the role, when they call the privileged function on {t}, then the server refuses it, whatever the client shows.",
    P: "Given a user who asks to delete their data, when the job finishes, then {t} no longer holds it, including in copies and backups.",
  };
  function ticket(t) {
    const target = t.target || "the system";
    const sc = score(t), r = RESPONSES[t.response] ? t.response : "";
    const test = (TESTS[t.cat] || TESTS.S).replace("{t}", target);
    const title = "[" + catName(t.cat) + "] " + t.text.replace(/\.$/, "");
    const body = [
      "**Threat:** " + t.text, "**Where:** " + target, "**Category:** " + catName(t.cat),
      "**Risk:** " + LEVELS[t.l] + " likelihood x " + LEVELS[t.i] + " impact = " + sc + " (" + band(sc) + ")",
      "**Response:** " + (r ? r + (t.fix ? ": " + t.fix : "") : "(not decided yet)" + (t.fix ? ", idea: " + t.fix : "")), "**Owner:** " + (t.owner || "(unassigned)"),
      t.review ? "**Revisit:** " + t.review : "",
      "**Done when:** " + test,
    ].filter(Boolean).join("\n");
    return { title, body, test };
  }

  // --------------------------------------------------------------------------- threat cards
  const CARDS = [
    ["S", "A sign-in step is skipped, replayed or borrowed. Which step is that here?"],
    ["S", "Something trusts a name, address or header that the sender picks. What is it?"],
    ["S", "A service calls another service. How does the second know who is really calling?"],
    ["S", "A webhook arrives from \"the provider\". How would we know it was?"],
    ["T", "Data crosses a boundary. What stops it changing on the way, or in storage?"],
    ["T", "A client sends a price, a role or an ID. What does the server do if it's different from what the client was shown?"],
    ["T", "A file, config or pipeline step can be edited by more people than should. Which one?"],
    ["T", "Something is loaded from outside the system and trusted. What checks it?"],
    ["R", "A person with admin rights changes something. Where is that written down, and who can edit that record?"],
    ["R", "Two parties disagree about what happened. What evidence does the system hold?"],
    ["R", "A log line is missing the who, what or when. Which one, and where?"],
    ["R", "What happens to the logs if the machine that wrote them is compromised?"],
    ["I", "A response, an error or a log line includes more than the caller needed. What?"],
    ["I", "Data rests in a place with weaker controls than where it started: a backup, an export, an analytics tool."],
    ["I", "Data is readable on the wire between two of our own components. Which two?"],
    ["I", "Someone can guess or count their way to a record that isn't theirs. How?"],
    ["D", "One caller asks for something that costs a thousand times what it costs them. What is it?"],
    ["D", "A dependency is slow or gone. What does our system do while it waits?"],
    ["D", "A limit, quota or certificate runs out. Who gets the alert, and when?"],
    ["D", "An upload, a query or a message is far larger than anyone planned. What stops it?"],
    ["E", "A normal user reaches an admin function by calling it directly. What checks the role?"],
    ["E", "A service runs with far more permission than it uses. What could that permission do?"],
    ["E", "A low-trust input ends up in a high-trust place: a command, a query, a template. Where?"],
    ["E", "One compromised account, key or build step. How far could it get from there?"],
  ].map(([k, text], i) => ({ id: "c" + (i + 1), suit: k, text }));

  const LINDDUN = [
    { k: "L", name: "Linking", ask: "Can someone join two records or actions to the same person?", ex: "An ad ID in a photo app joins the same person across two services." },
    { k: "I", name: "Identifying", ask: "Can someone work out who the data is about?", ex: "\"Anonymous\" ratings plus a postcode and a birth date point at one person." },
    { k: "N", name: "Non-repudiation", ask: "Is a person unable to deny something they'd reasonably want to?", ex: "A signed log proves who reported a problem, and chills reporting." },
    { k: "D", name: "Detecting", ask: "Can someone tell that a person is involved, without seeing their data?", ex: "The fact that an account exists in a support-group app is itself sensitive." },
    { k: "D2", name: "Data disclosure", ask: "Is personal data exposed to more people or systems than needed?", ex: "Every analytics tool receives the full profile." },
    { k: "U", name: "Unawareness", ask: "Are people unaware of what's collected, or unable to intervene?", ex: "A setting is buried, or there's no way to see or fix what's held." },
    { k: "C", name: "Non-compliance", ask: "Does handling break a law, a policy or a promise made to users?", ex: "Data is kept after a user asks for deletion." },
  ];
  const ABUSE = [
    "Used out of order: can someone jump to the last step without the first?",
    "Used again and again: what if they repeat a step a thousand times?",
    "Used at the same moment: what if two requests race each other?",
    "Used for the wrong purpose: a discount code as a lookup tool, a feature as a tracker?",
    "Used by a genuine user with bad intent: what could a customer, a member of staff or a partner do with what they're legitimately allowed to?",
  ];

  // --------------------------------------------------------------------------- an attack tree, with costs that propagate
  // Types: goal and "or" nodes take their cheapest possible child; "and" nodes need every child and add costs; leaves carry an effort cost.
  // Effort points are an invented unit. Blocked leaves are impossible.
  function photoTree() {
    return {
      id: "goal", type: "or", label: "Read another user's private photos", children: [
        { id: "session", type: "or", label: "Act as that user", children: [
          { id: "phish", type: "leaf", label: "Trick them into signing in on a look-alike page", cost: 30, fix: "Passkeys, which only work on the real site" },
          { id: "device", type: "leaf", label: "Take a token from their device", cost: 60, fix: "Short-lived tokens bound to the device" },
        ] },
        { id: "api", type: "or", label: "Ask the API for it", children: [
          { id: "idor", type: "leaf", label: "Change the photo ID in a request", cost: 5, fix: "An ownership check on every object" },
          { id: "links", type: "leaf", label: "Guess share links", cost: 40, fix: "Long random link tokens that expire" },
        ] },
        { id: "store", type: "and", label: "Go to storage directly", children: [
          { id: "key", type: "leaf", label: "Find a credential that was left somewhere", cost: 15, fix: "Scan for secrets and use short-lived roles" },
          { id: "list", type: "leaf", label: "Use it against a storage bucket that allows listing", cost: 5, fix: "Private buckets, with listing off" },
        ] },
        { id: "staff", type: "and", label: "Go through the people who run the service", children: [
          { id: "find", type: "leaf", label: "Find a support agent with broad access", cost: 10, fix: "Narrow, time-limited access to customer data" },
          { id: "persuade", type: "leaf", label: "Persuade them to look and share", cost: 50, fix: "Break-glass access that's logged and reviewed" },
        ] },
      ],
    };
  }
  function evalTree(node, blocked) {
    const isBlocked = (id) => !!(blocked && (blocked.has ? blocked.has(id) : blocked[id]));
    if (node.type === "leaf") {
      if (isBlocked(node.id)) return { possible: false, cost: Infinity, path: [] };
      return { possible: true, cost: node.cost, path: [node.id] };
    }
    const kids = node.children.map((c) => evalTree(c, blocked));
    if (node.type === "or") {
      let best = null;
      for (const k of kids) if (k.possible && (!best || k.cost < best.cost)) best = k;
      return best ? { possible: true, cost: best.cost, path: best.path.slice() } : { possible: false, cost: Infinity, path: [] };
    }
    if (kids.every((k) => k.possible)) return { possible: true, cost: kids.reduce((s, k) => s + k.cost, 0), path: [].concat(...kids.map((k) => k.path)) };
    return { possible: false, cost: Infinity, path: [] };
  }
  function treeLeaves(node) { return node.type === "leaf" ? [node] : [].concat(...node.children.map(treeLeaves)); }

  const api = {
    STRIDE, STRIDE_KEYS, strideByKey, ELEMENT_TYPES, TYPE_LABEL, perElement, classify, ZONES, zoneById,
    createModel, nodeById, nodeByName, addNode, removeNode, addFlow, flowKey, crosses, crossings, enumerate, promptCount, lint,
    SAMPLES, REFERENCE, SIZES, TRIGGERS, PRESETS, advise,
    CATS, catName, createLog, addThreat, removeThreat, coverage, score, band, LEVELS, ranked, RESPONSES, validResponse, ticket,
    CARDS, LINDDUN, ABUSE, photoTree, evalTree, treeLeaves,
  };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.TMLab = api;
})(typeof window !== "undefined" ? window : globalThis);
