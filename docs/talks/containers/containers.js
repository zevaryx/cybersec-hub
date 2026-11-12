/* containers.js - the logic behind this talk's demos, kept apart from the page so it can be tested in Node.
   EDUCATIONAL ONLY. Nothing here talks to Docker or Kubernetes: every image, registry, cluster and finding is a small made-up
   model so you can see the idea. Digests are real SHA-256 and signatures are real (from-scratch) ECDSA P-256 from ../../shared/crypto.js,
   but all keys are invented on the spot and never leave the page. */
(function (root) {
  "use strict";
  const L = root.Lab || (typeof require !== "undefined" ? require("../../shared/crypto.js") : null);
  const digestOf = (text) => "sha256:" + L.hex(L.sha256(L.utf8(text)));
  const short = (d) => d.slice(0, 7 + 8) + "…";

  // --------------------------------------------------------------------------- 1. the shared-kernel quiz
  // [name, shared with the host?, one-line answer]
  const ISOLATION = [
    ["The kernel", true, "Shared. Every container on a host runs on the host's one kernel, so a kernel or runtime bug is a bug for all of them."],
    ["The process list", false, "Its own. A PID namespace gives a container its own view of processes (unless you ask for hostPID)."],
    ["The filesystem", false, "Its own view: the image's layers plus a thin writable layer, unless you mount host paths in."],
    ["The network stack and IP address", false, "Its own network namespace (unless you ask for host networking). What it can reach is a separate question: see network policies."],
    ["CPU and memory", true, "Shared hardware. Limits only exist if you set them (cgroups), so a container with no limit can use whatever the node has."],
    ["User ID 0 (root)", true, "Shared by default. Root in the container is UID 0 on the host too, just with fewer privileges, unless user namespaces remap it."],
  ];

  // --------------------------------------------------------------------------- 2. grading a FROM line (title demo)
  /** Split "registry/name:tag@sha256:..." into parts. */
  function parseRef(ref) {
    let s = ref.trim(), digest = "", tag = "";
    const at = s.indexOf("@"); if (at >= 0) { digest = s.slice(at + 1); s = s.slice(0, at); }
    const slash = s.lastIndexOf("/"), colon = s.lastIndexOf(":");
    if (colon > slash) { tag = s.slice(colon + 1); s = s.slice(0, colon); }
    return { name: s, tag, digest };
  }
  const BIG_OS = /^(?:docker\.io\/library\/|library\/)?(ubuntu|debian|centos|fedora|rockylinux|almalinux|amazonlinux|oraclelinux)$/;
  /** Grade a base image reference. Returns { kind, lines: [[level, text]], egg }. */
  function gradeBase(ref) {
    const p = parseRef(ref), lines = [];
    if (!p.name) return { kind: "empty", lines: [["y", "nothing to grade"]], egg: "# an empty FROM is a build error, and also a philosophy." };
    const n = p.name.toLowerCase();
    if (n === "scratch") return { kind: "scratch", lines: [["ok", "scratch: an empty image. Nothing in it but what you copy in"]], egg: "# Respect. Minimalism level: monk." };
    const distroless = /distroless|chainguard|wolfi|static/.test(n);
    if (!p.tag && !p.digest) lines.push(["bad", "no tag: this means :latest, which is a moving target, not a version"]);
    else if (p.tag === "latest" && !p.digest) lines.push(["bad", ":latest changes whenever the publisher pushes; the same Dockerfile builds different images"]);
    else if (p.digest) lines.push(["ok", "pinned by digest: a content fingerprint, so you get exactly these bytes"]);
    else lines.push(["y", "a tag is a label the publisher can move; pin the digest too"]);
    if (p.digest && !/^sha256:[0-9a-f]{64}$/.test(p.digest)) lines.push(["bad", "that doesn't look like a sha256 digest (sha256: and 64 hex characters)"]);
    if (BIG_OS.test(n) && !/slim|minimal/.test(p.tag)) lines.push(["y", "a full OS image: shell, package manager and many tools you don't ship to production"]);
    else if (distroless) lines.push(["ok", "minimal: little more than your app's runtime"]);
    else if (/alpine|slim|busybox|minimal/.test(n + ":" + p.tag)) lines.push(["ok", "small base: fewer packages to patch"]);
    let egg = "";
    if (p.tag === "latest" || (!p.tag && !p.digest)) egg = "# latest is a mood, not a version.";
    else if (p.digest && /^sha256:[0-9a-f]{64}$/.test(p.digest)) egg = "# a digest: the one kind of tag that can't be quietly repainted.";
    else if (n.endsWith("ubuntu")) egg = "# Ubuntu is a fine desktop and a roomy base. Your service probably wants a smaller room.";
    else if (distroless) egg = "# no shell to land in. Debugging gets harder; so does attacking.";
    return { kind: lines.some((l) => l[0] === "bad") ? "bad" : lines.some((l) => l[0] === "y") ? "y" : "ok", lines, egg };
  }

  // --------------------------------------------------------------------------- 3. base images: what is inside
  const BASES = [
    { id: "debian", ref: "debian:stable", size: "about 124 MiB", sizeNote: "(the distroless README's comparison)", shell: true, pkg: "apt", libc: "glibc", tools: "bash, coreutils, and a lot more", note: "Familiar and compatible. Also the most to patch and the most for an intruder to use." },
    { id: "alpine", ref: "alpine:3", size: "about 5 MiB", sizeNote: "(the distroless README's comparison)", shell: true, pkg: "apk", libc: "musl", tools: "busybox: one small binary, many commands", note: "Small and handy. It uses musl instead of glibc, which a few programs notice." },
    { id: "distroless", ref: "gcr.io/distroless/static-debian13", size: "around 2 MiB", sizeNote: "(its own README)", shell: false, pkg: "none", libc: "none (static binaries only)", tools: "none", note: "CA certificates, time zone data and a nonroot user, and no shell or package manager. Debug with a debug tag or an ephemeral debug container." },
    { id: "scratch", ref: "scratch", size: "0", sizeNote: "(an empty image)", shell: false, pkg: "none", libc: "none", tools: "none", note: "Only what you COPY in: usually one static binary. You bring anything else you need, such as CA certificates and a user entry." },
  ];

  // --------------------------------------------------------------------------- 4. tags are labels, digests are fingerprints
  const manifestText = (rev) => JSON.stringify({ layers: ["base-os", "runtime", "app-build-" + rev], created: "rev " + rev });
  function makeRegistry() {
    const r = { tags: {}, history: [], rev: 0, pins: {} };
    push(r, "shop/api:1.4");
    r.pins.dockerfile = r.tags["shop/api:1.4"];          // the digest your Dockerfile pinned
    return r;
  }
  /** The publisher pushes a new build under an existing tag. */
  function push(r, tag) { r.rev++; const d = digestOf(manifestText(r.rev)); r.tags[tag] = d; r.history.push({ tag, digest: d, rev: r.rev }); return d; }
  /** What `FROM shop/api:1.4` and `FROM shop/api@sha256:...` pull today. */
  function resolveRef(r, mode) { return mode === "tag" ? r.tags["shop/api:1.4"] : r.pins.dockerfile; }
  /** An update bot opens a pull request that moves the pin to the tag's current digest. */
  function bumpPin(r) { r.pins.dockerfile = r.tags["shop/api:1.4"]; return r.pins.dockerfile; }

  // --------------------------------------------------------------------------- 5. multi-stage builds: what ships
  // [item, why it is there, needed at run time?]
  const STAGE_ITEMS = [
    ["The compiled program", "What you actually want to run", true],
    ["A runtime base (certificates, a user)", "The small floor the program stands on", true],
    ["The compiler and build tools", "Needed to build, never to run. Also useful to an intruder", false],
    ["A package manager", "Lets anyone who gets in install more tools", false],
    ["Your source code", "Not needed to run, and not something you meant to publish", false],
    ["Test files and fixtures", "Dead weight, sometimes with fake credentials that look real", false],
    ["The .git folder", "The whole history, including anything you ever committed by mistake", false],
    ["Build caches", "Hundreds of megabytes of things nobody will read", false],
  ];
  function stageContents(multi) { return STAGE_ITEMS.filter((it) => multi ? it[2] : true); }
  const DOCKERFILES = {
    single: ["FROM golang:1.25", "WORKDIR /src", "COPY . .", "RUN go build -o /app ./cmd/server", "CMD [\"/app\"]"],
    multi: ["FROM golang:1.25 AS build", "WORKDIR /src", "COPY . .", "RUN CGO_ENABLED=0 go build -o /app ./cmd/server", "", "FROM gcr.io/distroless/static-debian13:nonroot", "COPY --from=build /app /app", "CMD [\"/app\"]"],
  };

  // --------------------------------------------------------------------------- 6. what code that got in can do
  /** opts: { user: "root"|"nonroot", ro: bool, caps: "default"|"none", nnp: bool }. Returns [[action, allowed, why]]. */
  function intruder(o) {
    const root_ = o.user === "root", rw = !o.ro, defaultCaps = o.caps === "default";
    return [
      ["Replace the program file with a trojan", root_ && rw, !rw ? "The filesystem is read-only." : root_ ? "Root can write to files the image owns." : "The program files belong to root, and this user isn't root."],
      ["Install more tools with the package manager", root_ && rw, !rw ? "Read-only: nothing can be written." : root_ ? "Root can install packages (if the image has a package manager and network)." : "Installing needs root."],
      ["Drop a file into /tmp", rw, rw ? "The filesystem is writable. (Mount a small tmpfs there if the app really needs scratch space.)" : "Read-only. Mount a tmpfs or emptyDir only where the app truly needs to write."],
      ["Read a file that only root may read", root_, root_ ? "Root ignores most file permissions." : "Ordinary permissions apply."],
      ["Craft raw network packets (the NET_RAW capability)", root_ && defaultCaps, root_ && defaultCaps ? "NET_RAW is in Docker's default capability list, and root holds it." : root_ ? "All capabilities were dropped." : "A non-root process doesn't get the container's capabilities in its effective set."],
      ["Become root through a setuid program in the image", !root_ && !o.nnp, root_ ? "Already root: nothing to escalate to." : o.nnp ? "no_new_privileges stops setuid programs from adding privileges." : "A setuid binary that ships in a full OS image can raise privileges. (Assumes this image has one.)"],
    ];
  }

  // --------------------------------------------------------------------------- 7. layers: delete is a new layer, not an erase
  const SECRET_VALUE = "API_KEY=sk_live_EXAMPLE_not_a_real_key";
  /** Build a toy image. mode: "rm" (COPY .env then rm), "multi" (multi-stage), "mount" (build secret mount). */
  function layersFor(mode) {
    const base = { n: 1, cmd: "FROM debian:stable", add: ["bin/sh", "usr/bin/env", "etc/os-release"], del: [] };
    if (mode === "rm") return [
      base,
      { n: 2, cmd: "COPY .env /app/.env", add: ["app/.env"], del: [], secrets: { "app/.env": SECRET_VALUE } },
      { n: 3, cmd: "RUN npm ci && npm run build", add: ["app/node_modules/", "app/dist/server.js"], del: [] },
      { n: 4, cmd: "RUN rm /app/.env", add: [], del: ["app/.env"] },
      { n: 5, cmd: "CMD [\"node\", \"dist/server.js\"]", add: [], del: [] },
    ];
    if (mode === "multi") return [
      { n: 1, cmd: "FROM gcr.io/distroless/nodejs22-debian13:nonroot", add: ["usr/bin/node", "etc/passwd"], del: [] },
      { n: 2, cmd: "COPY --from=build /app/dist /app/dist", add: ["app/dist/server.js"], del: [] },
      { n: 3, cmd: "CMD [\"/app/dist/server.js\"]", add: [], del: [] },
    ];
    return [
      base,
      { n: 2, cmd: "RUN --mount=type=secret,id=npmtoken npm ci", add: ["app/node_modules/"], del: [] },
      { n: 3, cmd: "COPY dist /app/dist", add: ["app/dist/server.js"], del: [] },
      { n: 4, cmd: "CMD [\"node\", \"dist/server.js\"]", add: [], del: [] },
    ];
  }
  /** The filesystem a running container sees: apply each layer in order, whiteouts remove earlier entries. */
  function unionView(layers) {
    const fs = new Set();
    for (const l of layers) { for (const d of l.del) fs.delete(d); for (const a of l.add) fs.add(a); }
    return Array.from(fs).sort();
  }
  /** The tar entries of one layer: additions, plus whiteout files (.wh.<name>) for deletions. */
  function layerEntries(l) {
    return l.add.map((p) => ({ path: p, kind: "file" })).concat(l.del.map((p) => {
      const i = p.lastIndexOf("/"); return { path: (i < 0 ? "" : p.slice(0, i + 1)) + ".wh." + p.slice(i + 1), kind: "whiteout", hides: p };
    }));
  }
  /** Can someone who pulls the image get the secret by reading one layer on its own? */
  function secretInLayers(layers) { return layers.filter((l) => l.secrets).map((l) => ({ n: l.n, path: Object.keys(l.secrets)[0], value: Object.values(l.secrets)[0] })); }

  // --------------------------------------------------------------------------- 8. grading a Dockerfile
  const SECRET_NAME = /(pass(?:word|wd)?|secret|token|api[_-]?key|private[_-]?key|credential|auth)/i;
  const SECRET_FILE = /(?:^|[/\s])(\.env(?:\.[\w-]+)?|id_(?:rsa|ed25519|ecdsa)|[\w.-]+\.(?:pem|key|p12|pfx)|\.npmrc|\.pypirc|\.netrc|\.aws|credentials(?:\.json)?|kubeconfig|\.kube)(?:\s|$|\/)/i;
  /** Join continued lines (trailing backslash), drop comments and blanks. Returns [{n, op, args, raw}]. */
  function parseDockerfile(text) {
    const out = []; const rows = text.split(/\r?\n/);
    for (let i = 0; i < rows.length; i++) {
      let line = rows[i]; const start = i + 1;
      if (/^\s*#/.test(line) || !line.trim()) continue;
      while (/\\\s*$/.test(line) && i + 1 < rows.length) { i++; const nxt = rows[i]; line = line.replace(/\\\s*$/, " ") + (/^\s*#/.test(nxt) ? "" : nxt); }
      const m = /^\s*([A-Za-z]+)\s*(.*)$/.exec(line); if (!m) continue;
      out.push({ n: start, op: m[1].toUpperCase(), args: m[2].trim(), raw: line.trim() });
    }
    return out;
  }
  /** Grade a Dockerfile. Returns { findings: [{id, level, line, title, why}], eggs: [..], stages }. */
  function gradeDockerfile(text) {
    const ins = parseDockerfile(text), F = [], eggs = [];
    const add = (id, level, line, title, why) => F.push({ id, level, line, title, why });
    const froms = ins.filter((i) => i.op === "FROM");
    if (!froms.length) return { findings: [{ id: "nofrom", level: "bad", line: 0, title: "No FROM line", why: "A Dockerfile starts from a base image." }], eggs, stages: 0 };
    const stageNames = new Set(); let finalFrom = null;
    froms.forEach((f, idx) => {
      const m = /^(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?/i.exec(f.args); const ref = m ? m[1] : ""; const stage = m && m[2] ? m[2].toLowerCase() : "";
      const internal = stageNames.has(ref.toLowerCase()); if (stage) stageNames.add(stage); finalFrom = { f, ref, internal };
      if (internal || /^\$\{?\w+\}?$/.test(ref)) return;
      const g = gradeBase(ref);
      if (g.kind === "scratch") { eggs.push("scratch"); add("base-scratch", "ok", f.n, "FROM scratch", "An empty base: only your own files are in the image."); return; }
      for (const [lv, tx] of g.lines) {
        if (lv === "bad" && /tag|latest/.test(tx)) add("base-latest", "bad", f.n, "Unpinned base image (" + ref + ")", "No version, or :latest. Builds aren't repeatable and the base can change under you. Use a specific version, and a digest.");
        else if (lv === "y" && /a tag is a label/.test(tx)) { if (idx === froms.length - 1 || froms.length === 1) add("base-digest", "y", f.n, "Base pinned by tag, not by digest", "Tags can be moved. Add @sha256:… and let an update bot move it."); }
        else if (lv === "ok" && /digest/.test(tx)) add("base-digest", "ok", f.n, "Base pinned by digest", "You get exactly these bytes. Keep it fresh with an update bot.");
        else if (lv === "y" && /full OS/.test(tx) && idx === froms.length - 1) add("base-big", "y", f.n, "A full OS image as the runtime base (" + ref + ")", "Shell, package manager and a lot to patch. Consider a slim or distroless base for the final stage.");
      }
    });
    // final stage = instructions after the last FROM
    const lastFromLine = froms[froms.length - 1].n; const final = ins.filter((i) => i.n > lastFromLine);
    const users = final.filter((i) => i.op === "USER");
    const lastUser = users.length ? users[users.length - 1].args.split(/\s+/)[0].toLowerCase() : "";
    const userBase = lastUser.split(":")[0];
    if (!users.length) add("user", "bad", 0, "No USER: runs as root", "Without a USER line the process runs as root inside the container. Add a numeric non-root user.");
    else if (userBase === "root" || userBase === "0") add("user", "bad", users[users.length - 1].n, "USER root", "The container's process runs as root. Switch to a non-root user.");
    else add("user", "ok", users[users.length - 1].n, "Runs as a non-root user (" + lastUser + ")", "A compromised process has fewer rights. A numeric ID lets Kubernetes verify it.");
    // multi-stage vs build tools
    const BUILDS = /\b(?:build-essential|gcc|g\+\+|make|cmake|go build|cargo build|mvn|gradle|npm (?:ci|install|run build)|yarn|pip install|dotnet (?:build|publish))\b/i;
    const buildsInFinal = final.some((i) => i.op === "RUN" && BUILDS.test(i.args));
    if (froms.length === 1 && ins.some((i) => i.op === "RUN" && BUILDS.test(i.args)) && !/scratch|distroless/i.test(froms[0].args)) add("multistage", "y", 0, "Single-stage build", "The compiler, package manager and source stay in the final image. A second stage can copy only the result.");
    else if (froms.length > 1 && ins.some((i) => i.op === "COPY" && /--from/i.test(i.args))) add("multistage", "ok", 0, "Multi-stage build", "Build tools stay in an earlier stage and don't ship.");
    else if (froms.length > 1 && buildsInFinal) add("multistage", "y", 0, "Build steps in the final stage", "Do the building in an earlier stage and copy only the result.");
    // secrets
    for (const i of ins) {
      if (i.op === "ENV" || i.op === "ARG") {
        const pairs = i.args.split(/\s+(?=[A-Za-z_][\w]*=)/); const list = pairs.length > 1 || i.args.includes("=") ? pairs : [i.args.replace(/\s+/, "=")];
        for (const p of list) {
          const [k, ...rest] = p.split("="); const v = rest.join("=").replace(/^["']|["']$/g, "").trim();
          if (SECRET_NAME.test(k) && (i.op === "ARG" || v) && !/^\$\{?\w+\}?$/.test(v)) add("secret-env", "bad", i.n, i.op + " " + k + " holds a secret", i.op === "ENV" ? "Environment values are stored in the image and visible in its history to anyone who can pull it. Pass secrets at run time." : "Build arguments are recorded in the image history. Use a build secret mount (RUN --mount=type=secret).");
        }
      }
      if ((i.op === "COPY" || i.op === "ADD") && SECRET_FILE.test(" " + i.args + " ")) add("secret-file", "bad", i.n, "A secret-looking file is copied in (" + (SECRET_FILE.exec(" " + i.args + " ")[1]) + ")", "Deleting it later doesn't remove it from the layer that added it. Keep it out of the build context (.dockerignore) or use a build secret mount.");
      if (i.op === "COPY" && /^(?:--\S+\s+)*\.\s+\S+/.test(i.args) && !/--from/i.test(i.args)) add("copy-dot", "y", i.n, "COPY . … copies the whole build context", "Make sure a .dockerignore keeps out .git, .env, keys and local config.");
      if (i.op === "ADD" && /^(?:--\S+\s+)*https?:\/\//i.test(i.args)) add("add-url", "y", i.n, "ADD from a URL", "The download isn't checked. Fetch with a checksum, or COPY a file you've verified.");
      if (i.op === "RUN" && /(?:curl|wget)[^|;&]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b/i.test(i.args)) add("curl-pipe", "bad", i.n, "curl | sh", "Runs whatever the server sends, unchecked, as part of your build. Download, verify a checksum, then run.");
      if (/chmod\s+(?:-[A-Za-z]+\s+)?0?777\b/.test(i.args)) { eggs.push("777"); add("chmod-777", "bad", i.n, "chmod 777", "World-writable means any process in the container can change it. Give the app's user exactly what it needs."); }
      if (i.op === "EXPOSE" && /(?:^|\s)22(?:\/|\s|$)/.test(i.args)) add("ssh", "bad", i.n, "EXPOSE 22: an SSH server in a container", "Use your platform's exec or debug tools instead of running sshd.");
      if (i.op === "RUN" && /openssh-server|sshd\b/.test(i.args)) add("ssh", "bad", i.n, "An SSH server in the image", "Use your platform's exec or debug tools instead of running sshd.");
      if (i.op === "RUN" && /\bsudo\b/.test(i.args) && !/apt|apk|yum|dnf/.test(i.args)) add("sudo", "y", i.n, "sudo in a build step", "If a step needs root, run it as root in the build, then drop to USER at the end.");
    }
    const aptRun = ins.filter((i) => i.op === "RUN" && /apt-get\s+install/.test(i.args));
    if (aptRun.length) {
      const noRec = aptRun.every((i) => /--no-install-recommends/.test(i.args)), clean = aptRun.every((i) => /rm\s+-rf\s+\/var\/lib\/apt\/lists/.test(i.args));
      if (!noRec || !clean) add("apt", "y", aptRun[0].n, "apt-get install without trimming", "Add --no-install-recommends and remove /var/lib/apt/lists in the same RUN, so the image carries fewer packages.");
      else add("apt", "ok", aptRun[0].n, "apt-get install is trimmed", "Fewer packages and no leftover package lists.");
    }
    // de-duplicate by id+line
    const seen = new Set(), findings = F.filter((f) => { const k = f.id + ":" + f.line + ":" + f.title; if (seen.has(k)) return false; seen.add(k); return true; });
    const order = { bad: 0, y: 1, ok: 2 }; findings.sort((a, b) => order[a.level] - order[b.level] || a.line - b.line);
    return { findings, eggs, stages: froms.length };
  }
  const DIGEST_EXAMPLE = digestOf("example base image, the one your update bot pinned");
  const DF_PRESETS = {
    bad: ["FROM ubuntu:latest", "", "ENV DB_PASSWORD=hunter2", "ARG NPM_TOKEN", "", "RUN apt-get update && apt-get install -y build-essential nodejs npm", "RUN curl -fsSL https://example.com/setup.sh | bash", "", "WORKDIR /app", "COPY . .", "COPY .env /app/.env", "RUN npm ci && npm run build", "RUN chmod -R 777 /app", "", "EXPOSE 3000", "CMD [\"node\", \"dist/server.js\"]"].join("\n"),
    better: ["FROM node:22 AS build", "WORKDIR /src", "COPY package*.json ./", "RUN --mount=type=secret,id=npmrc,target=/root/.npmrc npm ci", "COPY src ./src", "RUN npm run build", "", "FROM gcr.io/distroless/nodejs22-debian13:nonroot@" + DIGEST_EXAMPLE, "WORKDIR /app", "COPY --from=build /src/dist ./dist", "USER 65532:65532", "EXPOSE 3000", "CMD [\"dist/server.js\"]"].join("\n"),
    scratch: ["FROM golang:1.25 AS build", "WORKDIR /src", "COPY go.mod go.sum ./", "COPY cmd ./cmd", "RUN CGO_ENABLED=0 go build -o /app ./cmd/server", "", "FROM scratch", "COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/", "COPY --from=build /app /app", "USER 10001", "ENTRYPOINT [\"/app\"]"].join("\n"),
  };

  // --------------------------------------------------------------------------- 9. scan triage (made-up findings)
  // sev: 3 critical, 2 high, 1 medium, 0 low; where: "final" or "build"; fix: a fix exists; base: a rebuilt base would pick it up
  const FINDINGS = [
    { id: "EX-0001", pkg: "libssl", sev: 3, where: "final", fix: true, base: true },
    { id: "EX-0002", pkg: "zlib", sev: 2, where: "final", fix: true, base: true },
    { id: "EX-0003", pkg: "gcc", sev: 2, where: "build", fix: true, base: false },
    { id: "EX-0004", pkg: "git", sev: 3, where: "build", fix: true, base: false },
    { id: "EX-0005", pkg: "libxml-lib", sev: 1, where: "final", fix: false, base: false },
    { id: "EX-0006", pkg: "app dependency: left-padder", sev: 2, where: "final", fix: true, base: false },
    { id: "EX-0007", pkg: "perl-base", sev: 1, where: "final", fix: true, base: true },
    { id: "EX-0008", pkg: "tzdata", sev: 0, where: "final", fix: true, base: true },
    { id: "EX-0009", pkg: "make", sev: 1, where: "build", fix: false, base: false },
    { id: "EX-0010", pkg: "curl", sev: 2, where: "final", fix: true, base: true },
  ];
  const SEV = ["low", "medium", "high", "critical"];
  /** f: { finalOnly, fixable, highUp, rebuilt }. Returns the findings that remain on the to-do list. */
  function triage(f) {
    return FINDINGS.filter((x) => (!f.finalOnly || x.where === "final") && (!f.fixable || x.fix) && (!f.highUp || x.sev >= 2) && (!f.rebuilt || !x.base));
  }

  // --------------------------------------------------------------------------- 10. signing and admission
  function newKey() { const d = L.randBelow(L.P256.n - 1n) + 1n; return { d, Q: L.P256.mul(d) }; }
  function signDigest(key, digest) { const h = L.hashInt("image:" + digest), k = L.randBelow(L.P256.n - 1n) + 1n; return L.ecdsaSign(key.d, h, k); }
  function verifyDigest(Q, digest, sig) { return !!sig && L.ecdsaVerify(Q, L.hashInt("image:" + digest), sig); }
  const OUR_REGISTRY = "registry.example.com/";
  /** Build the demo's five pod images with a CI key, a laptop key and a tampered copy. */
  function makeFleet() {
    const ci = newKey(), laptop = newKey();
    const dA = digestOf("shop/api build 1.4.2 from CI"), dB = digestOf("shop/api build from a laptop"), dC = digestOf("some random tool"), dD = digestOf("shop/api build 1.4.2 from CI, after somebody edited a layer");
    const sigA = signDigest(ci, dA);
    const pods = [
      { id: "good", label: "shop/api by digest, signed by CI", ref: OUR_REGISTRY + "shop/api@" + dA, digest: dA, byDigest: true, sig: sigA },
      { id: "tag", label: "shop/api:1.4.2 by tag, signed by CI", ref: OUR_REGISTRY + "shop/api:1.4.2", digest: dA, byDigest: false, sig: sigA },
      { id: "laptop", label: "shop/api built on a laptop and signed with another key", ref: OUR_REGISTRY + "shop/api@" + dB, digest: dB, byDigest: true, sig: signDigest(laptop, dB) },
      { id: "random", label: "A random image from a public registry, unsigned", ref: "docker.io/random/tool@" + dC, digest: dC, byDigest: true, sig: null },
      { id: "edited", label: "shop/api with a layer edited after signing", ref: OUR_REGISTRY + "shop/api@" + dD, digest: dD, byDigest: true, sig: sigA },
    ];
    return { ci, laptop, pods };
  }
  /** policy: { registry, digest, signature }. Returns { admit, checks: [[ok, text]] }. */
  function admit(fleet, pod, policy) {
    const checks = [];
    if (policy.registry) checks.push([pod.ref.startsWith(OUR_REGISTRY), pod.ref.startsWith(OUR_REGISTRY) ? "comes from our registry" : "not from our registry"]);
    if (policy.digest) checks.push([pod.byDigest, pod.byDigest ? "referenced by digest" : "referenced by a tag, which can move"]);
    if (policy.signature) { const ok = verifyDigest(fleet.ci.Q, pod.digest, pod.sig); checks.push([ok, ok ? "signature verifies against the CI key" : !pod.sig ? "no signature" : "signature does not verify for this digest with the CI key"]); }
    return { admit: checks.every((c) => c[0]), checks };
  }

  // --------------------------------------------------------------------------- 11. flags that end the boundary
  // [name, what it hands over, safer way]
  const THIN = [
    ["privileged: true  (--privileged)", "Every capability, and access to the host's devices. Docker's docs say it gives the container almost the same access as a host process.", "Add only the one capability you need, or none. Ask what the workload really needs."],
    ["Mounting the container engine's socket", "Whoever can talk to /var/run/docker.sock can start any container, including one that mounts the host's root. The socket is root on the host.", "Use a build service or rootless builder that doesn't need the host engine."],
    ["A hostPath volume (especially /)", "Reads and writes on the node's own filesystem: its config, other pods' data, sometimes its credentials.", "Use emptyDir, a persistent volume or a CSI driver."],
    ["hostPID, hostNetwork, hostIPC", "Sees the node's processes or shares its network. Sniffing and tampering become possible.", "Keep them false. Use a Service or an ingress for traffic."],
    ["The SYS_ADMIN capability", "Close to a skeleton key: mounts, namespaces and much of what makes isolation work.", "Drop ALL capabilities and add back one at a time."],
    ["An old container runtime on the node", "A runtime bug breaks every wall at once. runc had breakouts in January 2024 and November 2025.", "Patch the runtime and the node image routinely, and turn on user namespaces where you can."],
  ];

  // --------------------------------------------------------------------------- 12. Pod Security Standards
  const BASELINE_CAPS = new Set(["AUDIT_WRITE", "CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL", "MKNOD", "NET_BIND_SERVICE", "SETFCAP", "SETGID", "SETPCAP", "SETUID", "SYS_CHROOT"]);
  /** spec: { privileged, hostNetwork, hostPID, hostPath, runAsNonRoot, runAsUser: ""|"0"|"10001", allowPE: ""|"true"|"false", seccomp: ""|"Unconfined"|"RuntimeDefault", drop: ""|"ALL", add: ""|"NET_BIND_SERVICE"|"SYS_ADMIN", ro }
      Returns { level: "privileged"|"baseline"|"restricted", baseline: [..], restricted: [..] } (a subset of the Pod Security Standards). */
  function podSecurity(s) {
    const base = [], rest = [];
    if (s.privileged) base.push("privileged containers are not allowed");
    if (s.hostNetwork) base.push("hostNetwork is not allowed");
    if (s.hostPID) base.push("hostPID is not allowed");
    if (s.hostPath) base.push("hostPath volumes are not allowed");
    if (s.add && !BASELINE_CAPS.has(s.add)) base.push("capability " + s.add + " is not in the allowed list");
    if (s.seccomp === "Unconfined") base.push("seccomp must not be Unconfined");
    if (s.runAsNonRoot !== true) rest.push("runAsNonRoot must be true");
    if (s.runAsUser === "0") rest.push("runAsUser must not be 0");
    if (s.allowPE !== "false") rest.push("allowPrivilegeEscalation must be set to false");
    if (s.seccomp !== "RuntimeDefault") rest.push("seccompProfile.type must be RuntimeDefault or Localhost");
    if (s.drop !== "ALL") rest.push("capabilities.drop must include ALL");
    if (s.add && s.add !== "NET_BIND_SERVICE") rest.push("only NET_BIND_SERVICE may be added back");
    if (s.hostPath) rest.push("volume type hostPath is not allowed");
    return { level: base.length ? "privileged" : rest.length ? "baseline" : "restricted", baseline: base, restricted: rest };
  }
  /** The container's securityContext (and pod-level host fields) as YAML text. */
  function podYaml(s) {
    const y = ["spec:"];
    if (s.hostNetwork) y.push("  hostNetwork: true");
    if (s.hostPID) y.push("  hostPID: true");
    if (s.hostPath) y.push("  volumes: [{ name: node, hostPath: { path: / } }]");
    y.push("  containers:", "  - name: app");
    const sc = [];
    if (s.privileged) sc.push("      privileged: true");
    if (s.runAsNonRoot === true) sc.push("      runAsNonRoot: true");
    if (s.runAsUser) sc.push("      runAsUser: " + s.runAsUser);
    if (s.allowPE) sc.push("      allowPrivilegeEscalation: " + s.allowPE);
    if (s.ro) sc.push("      readOnlyRootFilesystem: true");
    if (s.seccomp) sc.push("      seccompProfile:", "        type: " + s.seccomp);
    if (s.drop || s.add) { sc.push("      capabilities:"); if (s.drop) sc.push("        drop: [\"" + s.drop + "\"]"); if (s.add) sc.push("        add: [\"" + s.add + "\"]"); }
    if (sc.length) y.push("    securityContext:", ...sc); else y.push("    # no securityContext: every default applies");
    return y.join("\n");
  }
  const PSS_START = { privileged: false, hostNetwork: false, hostPID: false, hostPath: false, runAsNonRoot: false, runAsUser: "", allowPE: "", seccomp: "", drop: "", add: "", ro: false };
  const PSS_RESTRICTED = { privileged: false, hostNetwork: false, hostPID: false, hostPath: false, runAsNonRoot: true, runAsUser: "10001", allowPE: "false", seccomp: "RuntimeDefault", drop: "ALL", add: "", ro: true };

  // --------------------------------------------------------------------------- 13. resource limits
  /** A node with 8 GiB. Four pods use 5 GiB; a leaky worker starts at 0.5 GiB and grows 0.5 GiB a step. limit: GiB number, or 0 for none. */
  function leak(limit) {
    const node = 8, others = 5, steps = []; let w = 0.5, outcome = "", t = 0;
    while (t < 16) {
      t++; w += 0.5;
      if (limit && w > limit) { steps.push({ t, worker: limit, total: others + limit, event: "worker is OOM-killed at its " + limit + " GiB limit and restarts" }); outcome = "limit"; break; }
      if (others + w > node) { steps.push({ t, worker: w, total: others + w, event: "node memory exhausted" }); outcome = "node"; break; }
      steps.push({ t, worker: w, total: others + w, event: "" });
    }
    return { node, others, steps, outcome, victims: outcome === "node" ? "The kernel's OOM killer or the kubelet's eviction picks a victim. It is chosen by memory use and priority, not by blame, so a neighbour can be the one that dies." : "Only the leaky worker is killed. Its neighbours never notice." };
  }

  // --------------------------------------------------------------------------- 14. blast radius of one compromised pod
  /** o: { net: "open"|"deny", sa: "default"|"broad"|"none", pod: "loose"|"restricted" }. Returns [[target, reachable(bool), detail]]. */
  function blast(o) {
    const netOpen = o.net === "open", loose = o.pod === "loose", tok = o.sa !== "none";
    return [
      ["The api service it is meant to call", true, "Intended: the policy allows web to api, nothing else."],
      ["The database pod, in the same namespace", netOpen, netOpen ? "No NetworkPolicy: every pod can reach every pod." : "Blocked by default-deny; only api may reach it."],
      ["Pods in another namespace (payments)", netOpen, netOpen ? "A flat network: namespaces don't separate traffic." : "Blocked: no policy allows it."],
      ["The Kubernetes API, as this pod", tok && o.sa === "broad", !tok ? "No token mounted, so the pod can't authenticate." : o.sa === "broad" ? "The token carries a broad role: it can list Secrets across namespaces." : "A token is mounted, but the default account has next to no rights. (Check yours for stray bindings.)"],
      ["The cloud provider's metadata endpoint", netOpen, netOpen ? "Egress is open: it can ask for the node's cloud credentials (depends on the provider)." : "Egress is denied except to named services."],
      ["The internet (to download tools or send data out)", netOpen, netOpen ? "Egress is open." : "Egress is denied except to named services."],
      ["The node itself", loose, loose ? "Privileged or hostPath reaches the host's files and processes." : "Restricted settings: no host access."],
    ];
  }

  // --------------------------------------------------------------------------- 15. Kubernetes Secrets: who can read one
  /** o: { enc: bool (encryption at rest), rbac: "broad"|"least", create: "anyone"|"few" }. */
  function secretReaders(o) {
    return [
      ["Someone who copies etcd or its backups", !o.enc, o.enc ? "Encrypted at rest: ciphertext only, with the key held elsewhere (ideally a KMS)." : "Stored as plain data. Base64 is not encryption."],
      ["A user or app with \"get secrets\" through the API", true, "Encryption at rest doesn't help: the API decrypts for anyone it authorises." + (o.rbac === "least" ? " The list is short." : " With broad roles, that is most of the team.")],
      ["Someone allowed to create a Pod (or Deployment) in the namespace", o.create === "anyone", o.create === "anyone" ? "They can mount any Secret in that namespace into a pod they control. Kubernetes's docs warn of this." : "Limited to a pipeline and a few reviewers."],
      ["Someone who can exec into a pod that uses the Secret", o.rbac !== "least", o.rbac === "least" ? "pods/exec isn't granted broadly." : "pods/exec is often granted widely for debugging."],
      ["A pod that doesn't mount it", false, "Secrets only reach pods that reference them."],
      ["Anyone who can read the Git repo, if the manifest was committed", true, "A Secret manifest in Git holds base64: a costume, not a lock."],
    ];
  }
  const b64 = (s) => (typeof btoa !== "undefined" ? btoa(unescape(encodeURIComponent(s))) : Buffer.from(s, "utf8").toString("base64"));
  const unb64 = (s) => { try { return typeof atob !== "undefined" ? decodeURIComponent(escape(atob(s))) : Buffer.from(s, "base64").toString("utf8"); } catch (e) { return null; } };

  // --------------------------------------------------------------------------- 16. spot the problems in a manifest
  // each: [text, riskId|null, why]
  const MANIFEST = [
    ["kind: Deployment", null, ""],
    ["spec:", null, ""],
    ["  replicas: 3", null, ""],
    ["  template:", null, ""],
    ["    spec:", null, ""],
    ["      hostNetwork: true", "hostnet", "Shares the node's network. Ordinary services don't need it; it makes sniffing and bypassing network policies possible."],
    ["      containers:", null, ""],
    ["      - name: api", null, ""],
    ["        image: shop/api:latest", "latest", "A moving tag from the default registry. Pin a version and a digest, from your own registry."],
    ["        ports: [{ containerPort: 8080 }]", null, ""],
    ["        env: [{ name: DB_PASSWORD, value: \"s3cr3t-prod\" }]", "envsecret", "A password written into a manifest that lives in Git. Reference a Secret or an external store instead."],
    ["        securityContext:", null, ""],
    ["          privileged: true", "priv", "Every capability and the host's devices. Almost nothing needs this."],
    ["          runAsUser: 0", "root", "Runs as root. Use a numeric non-root user and runAsNonRoot: true."],
    ["        volumeMounts: [{ name: docker, mountPath: /var/run/docker.sock }]", "sock", "The container engine's socket is root on the node. Anything that can reach it can start any container."],
    ["        resources: {}", "limits", "No requests or limits: one runaway process can starve the node, and the scheduler is guessing."],
    ["      serviceAccountName: platform-admin", "sa", "A powerful account for a web service. If the pod is compromised, so is whatever that account can do. Give it its own minimal account."],
    ["      volumes: [{ name: docker, hostPath: { path: /var/run/docker.sock } }]", "sockvol", "The other half of the same mistake: a hostPath volume pointing at the engine's socket."],
  ];
  const RISKS = MANIFEST.filter((m) => m[1]).length;

  const api = { ISOLATION, parseRef, gradeBase, BASES, makeRegistry, push, resolveRef, bumpPin, manifestText, digestOf, short,
    STAGE_ITEMS, stageContents, DOCKERFILES, intruder, SECRET_VALUE, layersFor, unionView, layerEntries, secretInLayers,
    parseDockerfile, gradeDockerfile, DF_PRESETS, DIGEST_EXAMPLE, FINDINGS, SEV, triage, newKey, signDigest, verifyDigest, makeFleet, admit, OUR_REGISTRY,
    THIN, BASELINE_CAPS, podSecurity, podYaml, PSS_START, PSS_RESTRICTED, leak, blast, secretReaders, b64, unb64, MANIFEST, RISKS };
  root.ContainersLab = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof window !== "undefined" ? window : globalThis);
