/* sdlc.js - the models behind the demos in "Security in Your Development Process".
   Everything is invented teaching data: teams, findings, services, policies and numbers. Nothing is fetched or sent.
   Runs in the browser (window.SdlcLab) and in Node (module.exports) for the logic tests. */
(function (root) {
  "use strict";

  const escapeHtml = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const plural = (n, one, many) => n + " " + (n === 1 ? one : many);
  const DAY = 86400000;

  // ------------------------------------------------------------------ security.txt (RFC 9116)
  const FIELDS = ["Acknowledgments", "Canonical", "Contact", "Encryption", "Expires", "Hiring", "Policy", "Preferred-Languages"];
  const URI_FIELDS = ["Acknowledgments", "Canonical", "Contact", "Encryption", "Hiring", "Policy"];
  const RFC3339 = /^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$/;

  /** Parse and check a security.txt. Returns { fields, errors, warnings, infos, ok, egg }.
      `now` is a Date (or ms) so tests are deterministic. */
  function lintSecurityTxt(text, now) {
    const nowMs = now instanceof Date ? now.getTime() : (now === undefined ? Date.now() : now);
    const out = { fields: {}, errors: [], warnings: [], infos: [], ok: false, egg: "" };
    const src = String(text || "");
    if (!src.trim()) { out.errors.push("The file is empty. A researcher who finds nothing here has to guess where to send the report."); out.egg = "No file, no front door. Researchers will try your support@ address and hope."; return out; }
    if (/-----BEGIN PGP SIGNED MESSAGE-----/.test(src)) out.infos.push("Signed with an OpenPGP cleartext signature: recommended by the RFC. This checker reads the fields and does not verify the signature.");
    const lines = src.split(/\r?\n/);
    let inSig = false;
    lines.forEach((raw, i) => {
      const line = raw.replace(/\s+$/, "");
      if (/^-----BEGIN PGP SIGNATURE-----/.test(line)) inSig = true;
      if (inSig) { if (/^-----END PGP SIGNATURE-----/.test(line)) inSig = false; return; }
      if (!line.trim() || /^-----BEGIN PGP SIGNED MESSAGE-----/.test(line) || /^Hash:/i.test(line)) return;
      if (line[0] === "#") return; // comment
      const m = /^([A-Za-z][A-Za-z0-9-]*):[ \t]*(.*)$/.exec(line);
      if (!m) { out.warnings.push(`Line ${i + 1} isn't a field or a comment: "${line.slice(0, 40)}". Researchers should ignore it, but it may be a typo.`); return; }
      const canon = FIELDS.find((f) => f.toLowerCase() === m[1].toLowerCase());
      if (!canon) { out.infos.push(`Line ${i + 1}: "${m[1]}" isn't a field the RFC defines. Tools should ignore fields they don't know, so it does no harm, but nobody will read it.`); return; }
      (out.fields[canon] = out.fields[canon] || []).push({ value: m[2], line: i + 1 });
    });

    // Contact: required, repeatable, URI
    const contacts = out.fields.Contact || [];
    if (!contacts.length) out.errors.push("Contact is missing. It's required, and it's the whole point of the file.");
    contacts.forEach((c) => {
      if (!/^(mailto:|tel:|https:\/\/)/i.test(c.value)) {
        if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(c.value)) out.errors.push(`Contact "${c.value}" needs a scheme: write mailto:${c.value}. Contact values are URIs.`);
        else if (/^http:\/\//i.test(c.value)) out.errors.push(`Contact "${c.value}" uses http. Web URIs in this file must use https.`);
        else out.errors.push(`Contact "${c.value}" isn't a URI. Use mailto:, tel: or an https:// link.`);
      }
    });
    // Expires: required, exactly once, RFC 3339
    const exp = out.fields.Expires || [];
    if (!exp.length) out.errors.push("Expires is missing. It's required, so a stale file can't look current.");
    else if (exp.length > 1) out.errors.push("Expires appears more than once. It must appear exactly once.");
    if (exp.length) {
      const v = exp[0].value;
      if (!RFC3339.test(v)) out.errors.push(`Expires "${v}" isn't an RFC 3339 date-time, such as 2027-06-30T23:59:59Z.`);
      else {
        const t = Date.parse(v);
        if (isNaN(t)) out.errors.push(`Expires "${v}" isn't a real date.`);
        else if (t < nowMs) { out.errors.push(`Expires (${v}) is in the past: the file says it is stale. Renew it.`); out.egg = out.egg || "An expired security.txt is a polite way of saying nobody is home."; }
        else if (t > nowMs + 366 * DAY) out.warnings.push("Expires is more than a year away. The RFC recommends less than a year, so a file that nobody maintains goes stale on its own.");
        out.expiresMs = isNaN(t) ? null : t;
      }
    }
    // single-instance fields
    if ((out.fields["Preferred-Languages"] || []).length > 1) out.errors.push("Preferred-Languages appears more than once. Put every language in one comma-separated list.");
    // https for web URIs
    URI_FIELDS.forEach((f) => (out.fields[f] || []).forEach((e) => { if (/^http:\/\//i.test(e.value) && f !== "Contact") out.errors.push(`${f} "${e.value}" uses http. Web URIs in this file must use https.`); }));
    // Encryption: a URI to a key, never the key itself
    (out.fields.Encryption || []).forEach((e) => { if (/BEGIN PGP/.test(e.value) || !/^(https:\/\/|dns:|openpgp4fpr:)/i.test(e.value)) out.errors.push(`Encryption "${e.value.slice(0, 40)}" must be a URI that points to your key (https://, dns: or openpgp4fpr:), never the key itself.`); });
    // soft advice
    if (contacts.length && !(out.fields.Policy || []).length) out.infos.push("No Policy link. A short disclosure policy tells researchers what's in scope and whether testing is allowed.");
    if (contacts.length && !(out.fields.Canonical || []).length) out.infos.push("No Canonical link. It's optional, and useful when the file is signed or served from several places.");
    if (contacts.some((c) => /cat@example\.com/i.test(c.value))) out.egg = "# hacker cat approves";
    out.ok = out.errors.length === 0;
    return out;
  }

  const pad = (n) => String(n).padStart(2, "0");
  function isoUtc(ms) { const d = new Date(ms); return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}T23:59:59Z`; }

  /** Build a security.txt from form values. `now` makes the default expiry deterministic. */
  function buildSecurityTxt(v, now) {
    const nowMs = now instanceof Date ? now.getTime() : (now === undefined ? Date.now() : now);
    const lines = [];
    const list = (s) => String(s || "").split(/[\n,]/).map((x) => x.trim()).filter(Boolean);
    const contacts = list(v.contact).map((c) => (/^[^\s:@]+@[^\s:@]+\.[^\s:@]+$/.test(c) ? "mailto:" + c : c));
    if (contacts.some((c) => /cat@example\.com$/i.test(c))) lines.push("# hacker cat approves");
    if (v.comment) lines.push("# " + String(v.comment).replace(/[\r\n]+/g, " "));
    contacts.forEach((c) => lines.push("Contact: " + c));
    lines.push("Expires: " + (v.expires && RFC3339.test(v.expires) ? v.expires : isoUtc(nowMs + Math.max(1, Math.min(365, +v.days || 330)) * DAY)));
    if (v.encryption) lines.push("Encryption: " + v.encryption);
    if (v.policy) lines.push("Policy: " + v.policy);
    if (v.ack) lines.push("Acknowledgments: " + v.ack);
    if (v.hiring) lines.push("Hiring: " + v.hiring);
    const langs = list(v.languages); if (langs.length) lines.push("Preferred-Languages: " + langs.join(", "));
    if (v.canonical) lines.push("Canonical: " + v.canonical);
    return lines.join("\n") + "\n";
  }

  // ------------------------------------------------------------------ lifecycle board
  const STAGES = [
    { id: "req", name: "Requirements", step: "Write security acceptance criteria next to the functional ones, per story.", time: "10 to 15 min per story",
      catches: "Missing controls: no rate limit, no expiry, no audit trail, no ownership check.",
      later: "Found in code review, it's a rework. Found in production, it's an incident and a redesign. The requirement was a sentence.",
      talks: [["web-app-security", "Web app security"], ["secure-apis", "Secure APIs"]] },
    { id: "design", name: "Design", step: "Threat-model changes that add a trust boundary, a new data store or a new way in. Skip the rest.", time: "30 to 60 min per significant change",
      catches: "Flaws in the shape of the system: a boundary nobody drew, a trust that was never earned.",
      later: "A design flaw can't be patched with a line of code. Each week it ships, more code leans on it.",
      talks: [["threat-modeling", "Threat modeling in practice"], ["privacy-engineering", "Privacy engineering"]] },
    { id: "code", name: "Code", step: "Secure defaults in the paved road, a review checklist, secrets kept out of the repo, memory-safe languages where you can.", time: "minutes per pull request",
      catches: "Injection, broken access control, hard-coded secrets, unsafe crypto, memory bugs.",
      later: "Found by a scanner after merge, it costs a context switch. Found by a stranger, it costs a disclosure.",
      talks: [["secure-code-review", "Secure code review"], ["crypto-in-code", "Crypto in code"], ["secrets-management", "Secrets management"], ["memory-safety", "Memory safety"], ["elliptic-curves", "Elliptic curves properly"]] },
    { id: "test", name: "Build and test", step: "Automated checks in CI: dependency and secret scanning, static analysis, security unit tests, fuzzing for parsers.", time: "set up once, then free",
      catches: "Known-vulnerable dependencies, leaked tokens, regressions in authorization, parser crashes.",
      later: "The same bug found in staging is a ticket. Found after release it's a patch, a notice and a customer email.",
      talks: [["security-testing", "Security testing in your workflow"], ["dependencies-and-ci", "Dependencies and CI/CD"], ["fuzzing", "Fuzzing for developers"], ["git-github-security", "Git and GitHub security"]] },
    { id: "release", name: "Release", step: "Pinned, signed, reproducible artefacts; least-privilege deploy credentials; hardened images.", time: "set up once per pipeline",
      catches: "Tampered builds, over-powered tokens, images that run as root with everything installed.",
      later: "A compromised release process turns every customer into a victim of the same incident.",
      talks: [["containers", "Container and Kubernetes security"], ["hashing-beyond-passwords", "Hashing beyond passwords"], ["dependencies-and-ci", "Dependencies and CI/CD"]] },
    { id: "operate", name: "Operate and respond", step: "Logs worth reading, a disclosure policy and security.txt, a rehearsed response, blameless reviews.", time: "ongoing, a few hours a month",
      catches: "What got through: you learn about it from a log, a customer or a researcher, not a stranger.",
      later: "There's no later. This is the stage where everything you skipped arrives at once, and the clock is somebody else's.",
      talks: [["building-login", "Building login and accounts safely"], ["secure-apis", "Secure APIs"]] },
  ];

  // ------------------------------------------------------------------ requirements as acceptance criteria
  const REQ_FEATURES = [
    { id: "reset", name: "Password reset", criteria: [
      ["A reset link works once.", "test_reset_link_second_use_is_refused"],
      ["The link expires, and a new request cancels the old one.", "test_reset_link_expires_after_30_minutes"],
      ["The response is the same whether or not the email has an account.", "test_reset_response_identical_for_unknown_email"],
      ["Requests are rate limited per address and per source.", "test_reset_requests_are_rate_limited"],
      ["Every session is signed out when the password changes.", "test_password_change_revokes_sessions"]], talk: ["building-login", "Building login"] },
    { id: "upload", name: "File upload", criteria: [
      ["Files over the size limit are refused before they are stored.", "test_upload_over_limit_is_rejected"],
      ["The type is checked from the content, not only the extension.", "test_upload_type_checked_from_content"],
      ["Files are stored under generated names, never the one the user chose.", "test_upload_filename_is_generated"],
      ["Files are served as downloads, from a different origin or with a safe type.", "test_upload_served_as_attachment"],
      ["A user can fetch only their own files.", "test_upload_other_users_file_is_403"]], talk: ["web-app-security", "Web app security"] },
    { id: "export", name: "CSV export", criteria: [
      ["Only the caller's own organisation's rows are exported.", "test_export_excludes_other_tenants"],
      ["Cells that start with =, +, - or @ are neutralised.", "test_export_neutralises_formula_cells"],
      ["Large exports are rate limited and logged with who and how much.", "test_export_is_logged_and_limited"],
      ["The download link expires.", "test_export_link_expires"]], talk: ["secure-apis", "Secure APIs"] },
    { id: "admin", name: "Admin page", criteria: [
      ["Every admin route refuses non-admins on the server, not just in the menu.", "test_admin_routes_deny_by_default"],
      ["Admin sign-in needs a second factor.", "test_admin_requires_mfa"],
      ["Each admin action writes an audit entry with who, what and when.", "test_admin_actions_are_audited"],
      ["No admin action can be triggered by a plain GET.", "test_admin_changes_need_post_and_csrf_token"]], talk: ["identity-and-access", "Identity and access"] },
    { id: "webhook", name: "Webhook receiver", criteria: [
      ["The signature is checked over the raw body with a constant-time compare.", "test_webhook_bad_signature_is_401"],
      ["Old timestamps are refused.", "test_webhook_old_timestamp_is_refused"],
      ["The same delivery ID is processed once.", "test_webhook_replay_is_ignored"],
      ["Handlers never call out to URLs taken from the payload without checking them.", "test_webhook_does_not_fetch_payload_urls"]], talk: ["secure-apis", "Secure APIs"] },
  ];

  // ------------------------------------------------------------------ frameworks to borrow from
  const FRAMEWORKS = [
    { id: "samm", name: "OWASP SAMM", kind: "Maturity model", status: "Version 2. Free and open.",
      what: "Five business functions (Governance, Design, Implementation, Verification, Operations), each with three practices, each practice scored on three maturity levels.",
      use: "Score where you are, pick two practices to raise this quarter, score again. It's built for exactly that loop.",
      avoid: "Treating level 3 everywhere as the goal. Raise what your risks need." },
    { id: "ssdf", name: "NIST SSDF (SP 800-218)", kind: "Practices catalogue", status: "Version 1.1 is final (February 2022). Version 1.2 (Rev. 1) was an initial public draft on 17 December 2025.",
      what: "Four groups of practices: Prepare the Organization, Protect the Software, Produce Well-Secured Software and Respond to Vulnerabilities.",
      use: "Answer a customer or government questionnaire, and map your own steps onto a shared vocabulary.",
      avoid: "Reading it as a checklist to bolt on. It describes outcomes, and you choose how to get there." },
    { id: "bsimm", name: "BSIMM", kind: "Benchmark", status: "Published by Black Duck; descriptive, built from observing real programmes.",
      what: "A catalogue of activities seen in security programmes at 100+ organisations, to compare your own against.",
      use: "Ask \"what do firms like ours actually do?\" and spot an activity you've never tried.",
      avoid: "Copying everyone else's list. It records what firms do, not what they should." },
    { id: "sbd", name: "CISA Secure by Design", kind: "Principles and pledge", status: "Voluntary pledge with seven goals; hundreds of signers.",
      what: "Manufacturers own customers' security outcomes. The pledge's goals: MFA, default passwords, reducing classes of vulnerability, security patches, a vulnerability disclosure policy, CVEs, and evidence of intrusions.",
      use: "A ready-made list of promises to make about your product, and a standard to hold suppliers to.",
      avoid: "Signing anything you don't intend to measure." },
    { id: "iso", name: "ISO/IEC 29147 and 30111", kind: "Standards for disclosure and handling", status: "29147:2018 and 30111:2019; paid standards.",
      what: "29147 covers receiving reports and publishing advisories. 30111 covers what happens inside the company between a report and a fix.",
      use: "A reference for the shape of a process when a customer or regulator asks for \"alignment\".",
      avoid: "Buying them before writing a one-page policy. Start with the page." },
  ];
  // lifecycle stage -> where each framework speaks to it
  const FW_MAP = [
    ["Requirements", "SAMM: Security Requirements", "SSDF: Produce Well-Secured Software"],
    ["Design", "SAMM: Threat Assessment, Secure Architecture", "SSDF: Produce Well-Secured Software"],
    ["Code and test", "SAMM: Secure Build, Requirements-driven Testing, Security Testing", "SSDF: Produce Well-Secured Software"],
    ["Release", "SAMM: Secure Deployment", "SSDF: Protect the Software"],
    ["Operate and respond", "SAMM: Incident Management, Defect Management", "SSDF: Respond to Vulnerabilities"],
    ["Culture and process", "SAMM: Strategy & Metrics, Education & Guidance", "SSDF: Prepare the Organization"],
  ];

  // ------------------------------------------------------------------ security champions
  /** Plan a champions programme. Returns the numbers and the warnings. */
  function championPlan(o) {
    const devs = Math.max(1, Math.round(+o.devs || 1));
    const teams = Math.max(1, Math.round(+o.teams || 1));
    const hours = Math.max(0, +o.hours || 0);
    const ratio = Math.max(1, Math.round(+o.ratio || 1));
    const champions = Math.max(1, Math.ceil(devs / ratio));
    const covered = Math.min(teams, champions);
    const coverage = Math.round((covered / teams) * 100);
    const totalHours = Math.round(champions * hours * 10) / 10;
    const fte = Math.round((totalHours / 40) * 100) / 100;
    const support = (o.support || []).length;
    const warnings = [];
    if (hours < 1) warnings.push("Under an hour a week is a title, not a role: nothing will change.");
    else if (hours > 8) warnings.push("More than a day a week is a second job. Either fund it as one or shrink the scope.");
    if (coverage < 100) warnings.push(`${teams - covered} of ${teams} teams have no champion. Teams without one stay on the old process.`);
    if (champions === 1 && devs > 15) warnings.push("One champion for a large group is a single point of failure, and a bottleneck on the first holiday.");
    if (support < 3) warnings.push("Fewer than three support items ticked: champions without training, access and recognition burn out within a year.");
    let verdict = "ok";
    if (hours < 1 || support < 3) verdict = "bad"; else if (warnings.length) verdict = "y";
    return { devs, teams, champions, covered, coverage, hours, totalHours, fte, support, warnings, verdict };
  }
  const CHAMPION_SUPPORT = [
    ["time", "Protected time in the sprint, agreed with their manager"],
    ["train", "Training and a budget for it"],
    ["line", "A direct line to the security team"],
    ["voice", "A say in the paved road and the checklists"],
    ["credit", "Recognition in reviews and promotion, not extra unpaid work"],
  ];

  // ------------------------------------------------------------------ paved roads
  const ROADS = [
    { id: "http", task: "Call another service", diy: 25, paved: 5, what: "A shared client with timeouts, TLS and retries built in vs hand-rolled calls.", risk: "Disabled certificate checks, no timeouts." },
    { id: "secrets", task: "Read a secret", diy: 40, paved: 5, what: "One helper that reads from the secrets service vs a file, an env var or a constant.", risk: "Keys in the repo or in image layers." },
    { id: "render", task: "Show user content", diy: 30, paved: 5, what: "The template engine's escaping on by default vs string concatenation.", risk: "Stored and reflected XSS." },
    { id: "auth", task: "Check who may do this", diy: 60, paved: 10, what: "A policy decorator, deny by default, vs ad-hoc if-statements.", risk: "A route that forgot the check." },
    { id: "deploy", task: "Ship a service", diy: 120, paved: 20, what: "A template repo with CI, scanning, a hardened image and a deploy role vs starting from nothing.", risk: "Everything on this list, at once." },
  ];
  /** Adoption model for one road: teams pick the easier path. `fit` is the share of real cases the paved road covers (0..100). */
  function adoption(o) {
    const diy = Math.max(1, +o.diy || 1), paved = Math.max(1, +o.paved || 1);
    const fit = Math.max(0, Math.min(100, +o.fit)) / 100;
    const easier = diy / (diy + paved); // 0.5 when equally easy, near 1 when the paved road is much easier
    let rate = fit * easier * 100;
    let note = "";
    if (o.mandate) { rate = Math.min(100, rate + 15); note = "A mandate adds adoption on paper. It also adds workarounds when the road doesn't fit."; }
    rate = Math.round(rate);
    let verdict = "ok";
    if (rate < 40) verdict = "bad"; else if (rate < 70) verdict = "y";
    const advice = paved >= diy ? "The paved road is harder than going alone. Fix the road before asking people to use it." : fit < 0.6 ? "Most real cases don't fit. Widen the road: add the option teams keep needing." : rate >= 70 ? "Teams take it because it's the easy path. That's the goal." : "Easier than going alone, but not by enough. Cut a step.";
    return { rate, verdict, advice, note, easier: Math.round(easier * 100) };
  }

  // ------------------------------------------------------------------ the report clock
  function addBusinessDays(ms, n) {
    let d = new Date(ms), left = n;
    while (left > 0) { d = new Date(d.getTime() + DAY); const w = d.getUTCDay(); if (w !== 0 && w !== 6) left--; }
    return d.getTime();
  }
  const SEV = { critical: { name: "Critical", triage: 2, fix: 7 }, high: { name: "High", triage: 5, fix: 30 }, medium: { name: "Medium", triage: 10, fix: 90 }, low: { name: "Low", triage: 15, fix: 180 } };
  /** What is due when, for a vulnerability report that arrived at `received` (ms, UTC).
      Our own targets are invented examples. The 3 business days is the figure in CISA's VDP template.
      Project Zero's 90 days (7 if actively exploited) is the researcher's side. CRA: early warning 24 h, notification 72 h,
      final report 14 days after a corrective measure is available (actively exploited vulnerabilities, manufacturers). */
  function reportClock(o) {
    const sev = SEV[o.severity] || SEV.high;
    const t0 = +o.received;
    const items = [];
    items.push({ key: "ack", label: "Acknowledge the report", at: addBusinessDays(t0, 3), basis: "3 business days is the figure in CISA's VDP template. Faster is kinder.", who: "you" });
    items.push({ key: "triage", label: "Confirm it, or say why not", at: addBusinessDays(t0, sev.triage), basis: `Example target for ${sev.name}: ${plural(sev.triage, "business day", "business days")}. Your policy sets its own.`, who: "you" });
    const fixDays = o.exploited ? Math.min(sev.fix, 7) : sev.fix;
    const fixAt = t0 + fixDays * DAY;
    items.push({ key: "fix", label: "Fix available", at: fixAt, basis: `Example target: ${plural(fixDays, "day", "days")}${o.exploited ? " because it is being exploited" : ` for ${sev.name}`}.`, who: "you" });
    items.push({ key: "publish", label: "Researcher may go public", at: t0 + (o.exploited ? 7 : 90) * DAY, basis: o.exploited ? "Google Project Zero's policy: 7 days if actively exploited." : "Google Project Zero's policy: 90 days (details 30 days after a patch if you ship in time). Other researchers set their own.", who: "researcher" });
    if (o.exploited && o.euProduct) {
      items.push({ key: "cra24", label: "EU early warning", at: t0 + 24 * 3600000, basis: "CRA: early warning within 24 hours of becoming aware of an actively exploited vulnerability.", who: "you (CRA)" });
      items.push({ key: "cra72", label: "EU full notification", at: t0 + 72 * 3600000, basis: "CRA: a full notification within 72 hours.", who: "you (CRA)" });
      items.push({ key: "cra14", label: "EU final report", at: fixAt + 14 * DAY, basis: "CRA: no later than 14 days after a corrective measure is available.", who: "you (CRA)" });
    }
    items.sort((a, b) => a.at - b.at);
    return { items, sev: sev.name, exploited: !!o.exploited, eu: !!o.euProduct };
  }
  function fmtWhen(ms, t0) {
    const d = new Date(ms), diff = ms - t0;
    const day = `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())} UTC`;
    const h = diff / 3600000;
    const rel = h < 48 ? `+${Math.round(h)} h` : `+${Math.round(diff / DAY)} d`;
    return { day, rel };
  }

  // ------------------------------------------------------------------ bug bounty readiness
  const BOUNTY_CHECKS = [
    ["vdp", "A disclosure policy and a security.txt are live and monitored"],
    ["replies", "For six months, every report got a reply within the time you promised"],
    ["owner", "A named person triages, with a backup"],
    ["capacity", "You can fix a critical within your own target, today"],
    ["scope", "Scope is written down: what's in, what's out, what's off limits"],
    ["legal", "A lawyer has reviewed the safe-harbour wording"],
    ["budget", "There is money for payouts, including duplicates and low-severity reports"],
    ["easy", "You've already run scanners and fixed the easy findings yourselves"],
  ];
  function bountyReadiness(done) {
    const n = BOUNTY_CHECKS.filter((c) => done.includes(c[0])).length;
    const core = ["vdp", "replies", "owner", "capacity"].every((k) => done.includes(k));
    let level, text;
    if (n === BOUNTY_CHECKS.length) { level = "ok"; text = "Ready for a pilot, ideally private and invite-only first. Public comes after the pilot survives."; }
    else if (core && n >= 6) { level = "y"; text = "Close. Fix the remaining gaps, then run a small private pilot."; }
    else if (!core) { level = "bad"; text = "Not yet. A bounty multiplies reports, so the basics (policy, replies, triage, capacity to fix) come first."; }
    else { level = "y"; text = "The basics are there. Fill the rest before you pay for volume."; }
    return { n, total: BOUNTY_CHECKS.length, core, level, text };
  }

  // ------------------------------------------------------------------ blameless reviews
  const BLAME = [
    { blame: "Sam forgot to validate the input.", better: "Nothing in the pipeline checks input validation, and the validating helper isn't the default.", fix: "Make the safe helper the default and add a test that fails without it." },
    { blame: "The reviewer should have caught it.", better: "The pull request was 1,400 lines and the review checklist doesn't mention authorization on new routes.", fix: "Smaller changes, a checklist line and an automated check for routes with no policy." },
    { blame: "The on-call engineer was too slow to respond.", better: "The alert went to a shared channel at 3 a.m., and the runbook named a tool nobody could access.", fix: "Page a person, test the runbook, check access in advance." },
    { blame: "Someone committed the key.", better: "A long-lived key was easy to get, easy to paste and nothing stopped it entering the repo.", fix: "Short-lived credentials and push protection, so the mistake can't land." },
    { blame: "The team ignored the scanner.", better: "The scanner raised 340 findings a week with no ranking, so nothing could be acted on.", fix: "Tune it to fewer, ranked findings, and give each one an owner and a date." },
    { blame: "The vendor was careless.", better: "We gave the integration broad access and had no way to notice when it misbehaved.", fix: "Least-privilege tokens, an inventory of integrations and alerts on their activity." },
  ];

  // ------------------------------------------------------------------ metrics (invented data)
  // Findings across two quarters. open/fixed are day numbers within the quarter; fixed null = still open at quarter end.
  const FINDINGS = [
    { id: "F1", q: 1, sev: "critical", cls: "authz", open: 5, fixed: 21 }, { id: "F2", q: 1, sev: "critical", cls: "injection", open: 20, fixed: 33 },
    { id: "F3", q: 1, sev: "high", cls: "authz", open: 8, fixed: 52 }, { id: "F4", q: 1, sev: "high", cls: "secrets", open: 14, fixed: 49 },
    { id: "F5", q: 1, sev: "high", cls: "xss", open: 30, fixed: 75 }, { id: "F6", q: 1, sev: "medium", cls: "xss", open: 11, fixed: 80 },
    { id: "F7", q: 1, sev: "medium", cls: "config", open: 25, fixed: null }, { id: "F8", q: 1, sev: "medium", cls: "deps", open: 40, fixed: null },
    { id: "F9", q: 1, sev: "low", cls: "config", open: 3, fixed: 12 }, { id: "F10", q: 1, sev: "low", cls: "xss", open: 9, fixed: 15 },
    { id: "F11", q: 1, sev: "low", cls: "deps", open: 16, fixed: 22 }, { id: "F12", q: 1, sev: "low", cls: "config", open: 28, fixed: 31 },
    { id: "F13", q: 2, sev: "critical", cls: "secrets", open: 10, fixed: 14 }, { id: "F14", q: 2, sev: "high", cls: "authz", open: 6, fixed: 31 },
    { id: "F15", q: 2, sev: "high", cls: "authz", open: 22, fixed: 38 }, { id: "F16", q: 2, sev: "high", cls: "deps", open: 35, fixed: 55 },
    { id: "F17", q: 2, sev: "medium", cls: "xss", open: 4, fixed: 41 }, { id: "F18", q: 2, sev: "medium", cls: "config", open: 18, fixed: 44 },
    { id: "F19", q: 2, sev: "medium", cls: "authz", open: 29, fixed: 62 }, { id: "F20", q: 2, sev: "low", cls: "config", open: 7, fixed: 11 },
    { id: "F21", q: 2, sev: "low", cls: "deps", open: 12, fixed: 16 }, { id: "F22", q: 2, sev: "low", cls: "xss", open: 24, fixed: null },
    { id: "F23", q: 2, sev: "low", cls: "config", open: 33, fixed: 40 }, { id: "F24", q: 2, sev: "medium", cls: "injection", open: 50, fixed: null },
  ];
  // Share of the 10 services that use the paved road, by quarter
  const PAVED = { 1: 3, 2: 6 };
  function median(a) { if (!a.length) return null; const s = a.slice().sort((x, y) => x - y), m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; }
  /** The numbers worth watching, for quarter q. */
  function usefulMetrics(q) {
    const f = FINDINGS.filter((x) => x.q === q);
    const ttf = {};
    Object.keys(SEV).forEach((s) => { const d = f.filter((x) => x.sev === s && x.fixed != null).map((x) => x.fixed - x.open); ttf[s] = { median: median(d), n: d.length, openNow: f.filter((x) => x.sev === s && x.fixed == null).length }; });
    const prev = q > 1 ? FINDINGS.filter((x) => x.q === q - 1).map((x) => x.cls) : [];
    const classes = {}; f.forEach((x) => { classes[x.cls] = (classes[x.cls] || 0) + 1; });
    const repeat = Object.keys(classes).filter((c) => prev.includes(c)).sort((a, b) => (classes[b] - classes[a]) || a.localeCompare(b));
    return { ttf, classes, repeat, paved: PAVED[q], services: 10, total: f.length };
  }
  /** Metrics that tempt, what they reward and how teams game them. `better` is what to track instead. */
  const GOODHART = [
    { id: "found", name: "Findings reported", rewards: "Reporting a lot.", gamed: "Split one bug into five tickets. Scan more. Nobody wants a clean result.", rating: "bad", better: "Time to fix by severity: it's about what happens next." },
    { id: "closed", name: "Findings closed", rewards: "Closing a lot.", gamed: "Close the easy lows first and let the critical wait. The count looks great.", rating: "bad", better: "Median time to fix for critical and high findings." },
    { id: "zero", name: "\"Zero open criticals\"", rewards: "Not having criticals on the dashboard.", gamed: "Re-rate them as high. Risk-accept them with no owner. Stop scanning.", rating: "y", better: "Zero is fine as a target if re-rating needs a second pair of eyes and every acceptance has an expiry date." },
    { id: "lines", name: "Lines of code scanned", rewards: "Pointing the scanner at more code.", gamed: "Scan generated code and vendored libraries. The number soars, the risk doesn't move.", rating: "bad", better: "Coverage of the services that handle sensitive data." },
    { id: "ttf", name: "Median time to fix, by severity", rewards: "Fixing important things quickly.", gamed: "Close tickets without fixing. Guard with a re-test or a recurrence check.", rating: "ok", better: "Keep it, and pair it with how many are past their target." },
    { id: "paved", name: "Services on the paved road", rewards: "Making the safe way the easy way.", gamed: "Declare services \"on it\" with a stub config. Check the real checks run.", rating: "ok", better: "Keep it. It measures the cause, not the symptom." },
    { id: "repeat", name: "Repeat bug classes", rewards: "Fixing the cause, not the instance.", gamed: "Rename the class. Agree class names in advance.", rating: "ok", better: "Keep it. It's the one that shows whether you're learning." },
  ];
  /** Gaming demo: with capacity for `cap` closures, the team picks the easiest (lowest severity) first or the worst first. */
  function closureGame(cap, strategy) {
    const q1 = FINDINGS.filter((x) => x.q === 1);
    const rank = { critical: 0, high: 1, medium: 2, low: 3 };
    const order = q1.slice().sort((a, b) => strategy === "easy" ? (rank[b.sev] - rank[a.sev]) || (a.open - b.open) : (rank[a.sev] - rank[b.sev]) || (a.open - b.open));
    const closed = order.slice(0, cap);
    const left = order.slice(cap);
    const count = (arr, s) => arr.filter((x) => x.sev === s).length;
    return { closed: closed.length, criticalLeft: count(left, "critical"), highLeft: count(left, "high"), leftBySev: { critical: count(left, "critical"), high: count(left, "high"), medium: count(left, "medium"), low: count(left, "low") } };
  }

  // ------------------------------------------------------------------ maturity self-check
  const AREAS = [
    { id: "req", name: "Requirements", qs: [
      ["Stories carry security acceptance criteria where the feature needs them.", "Add three criteria to the next story that touches sign-in, uploads, exports or money."],
      ["Those criteria become automated tests.", "Turn the criteria from your last story into tests with names a human can read."]] },
    { id: "design", name: "Design", qs: [
      ["Significant changes get a short threat-modelling session.", "Pick one upcoming change that adds a trust boundary and run a 45-minute session."],
      ["Findings from those sessions become tracked work with owners.", "Give each threat a ticket, an owner and a \"done when\" test."]] },
    { id: "code", name: "Code", qs: [
      ["Reviews use a short security checklist, and a champion can be pulled in.", "Add five lines to the pull-request template and name a champion per team."],
      ["The easy, safe way is a paved road: templates, libraries, defaults.", "Pick the task teams repeat most and make the safe version one line."]] },
    { id: "test", name: "Build and test", qs: [
      ["CI scans dependencies, secrets and code on every change.", "Turn on dependency and secret scanning first: they're cheap and well-tuned."],
      ["Findings are triaged, ranked and owned, with suppressions that expire.", "Add a rule: no suppression without a reason, an owner and a date."]] },
    { id: "release", name: "Release", qs: [
      ["Builds are pinned and reproducible, and deploy credentials are short-lived.", "Replace one long-lived deploy key with short-lived credentials."],
      ["You can say what is in each release (a bill of materials) and who built it.", "Generate an SBOM and a build attestation for one service."]] },
    { id: "ops", name: "Operate and respond", qs: [
      ["A disclosure policy and a security.txt are live, and reports get a reply.", "Publish a security.txt and a half-page policy this week."],
      ["Incidents and security bugs get blameless reviews that produce changes.", "Hold a review for the last security bug, using \"what let this happen?\" instead of \"who?\"."]] },
  ];
  const ANSWERS = [["No", 0], ["Partly", 1], ["Yes", 2]];
  /** answers: { "req.0": 0..2, ... }. Returns per-area percent, total percent, the first unmet step per area and a headline. */
  function maturity(ans) {
    const areas = AREAS.map((a) => {
      let sum = 0, answered = 0, next = null;
      a.qs.forEach((q, i) => { const v = ans[a.id + "." + i]; if (v !== undefined) { answered++; sum += v; if (v < 2 && !next) next = q[1]; } });
      return { id: a.id, name: a.name, pct: Math.round((sum / (a.qs.length * 2)) * 100), answered, total: a.qs.length, next };
    });
    const answeredAll = areas.reduce((s, a) => s + a.answered, 0), totalQs = areas.reduce((s, a) => s + a.total, 0);
    const sum = AREAS.reduce((s, a) => s + a.qs.reduce((t, _, i) => t + (ans[a.id + "." + i] || 0), 0), 0);
    const pct = Math.round((sum / (totalQs * 2)) * 100);
    const complete = answeredAll === totalQs;
    const weakest = areas.filter((a) => a.answered === a.total).sort((x, y) => x.pct - y.pct)[0] || null;
    return { areas, pct, complete, answered: answeredAll, total: totalQs, weakest, perfect: complete && pct === 100 };
  }

  // ------------------------------------------------------------------ the whole track
  const TRACK = [
    ["security-habits", "Security habits for new developers", ["code"]],
    ["git-github-security", "Git and GitHub security", ["code", "test"]],
    ["crypto-in-code", "Using crypto correctly in code", ["code"]],
    ["web-app-security", "Web application security", ["req", "code"]],
    ["secure-apis", "Building secure APIs", ["req", "code"]],
    ["building-login", "Building login and accounts safely", ["req", "operate"]],
    ["secrets-management", "Secrets management", ["code", "release"]],
    ["dependencies-and-ci", "Securing dependencies and CI/CD", ["test", "release"]],
    ["hashing-beyond-passwords", "Hashing beyond passwords", ["release"]],
    ["containers", "Container and Kubernetes security", ["release"]],
    ["security-testing", "Security testing in your workflow", ["test"]],
    ["threat-modeling", "Threat modeling in practice", ["design"]],
    ["secure-code-review", "Secure code review workshop", ["code"]],
    ["memory-safety", "Memory safety", ["code"]],
    ["ai-application-security", "Securing AI and LLM applications", ["design", "code"]],
    ["elliptic-curves", "Elliptic curves properly", ["code"]],
    ["fuzzing", "Fuzzing for developers", ["test"]],
    ["privacy-engineering", "Privacy engineering", ["design", "operate"]],
  ];

  root.SdlcLab = {
    escapeHtml, plural, FIELDS, lintSecurityTxt, buildSecurityTxt, isoUtc,
    STAGES, REQ_FEATURES, FRAMEWORKS, FW_MAP,
    championPlan, CHAMPION_SUPPORT, ROADS, adoption,
    addBusinessDays, SEV, reportClock, fmtWhen, BOUNTY_CHECKS, bountyReadiness, BLAME,
    FINDINGS, PAVED, median, usefulMetrics, GOODHART, closureGame,
    AREAS, ANSWERS, maturity, TRACK,
  };
  if (typeof module !== "undefined" && module.exports) module.exports = root.SdlcLab;
})(typeof window !== "undefined" ? window : globalThis);
