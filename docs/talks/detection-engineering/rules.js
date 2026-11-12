/* rules.js - the rule engine behind the demos in "Detection Engineering".
   A small YAML reader plus a Sigma-style rule evaluator, with no DOM, so it runs in the browser (window.Rules) and in Node (module.exports) for testing.
   It follows the Sigma specification 2.1.0 (rules + modifiers appendix) for the parts it supports, and says so loudly when it doesn't support something.
   It is a teaching tool, not a converter: it matches rules against made-up events in your browser. Real rules are converted to a SIEM's query language
   by tools such as pySigma and sigma-cli. Nothing here is sent anywhere. */
(function (root) {
  "use strict";

  class RuleError extends Error {
    constructor(msg, line) { super(line ? "line " + line + ": " + msg : msg); this.name = "RuleError"; this.line = line || 0; this.plain = msg; }
  }

  // =========================================================================== 1. a small YAML reader
  // Supports what Sigma rules use: nested maps, lists ("- x" and "- key: value"), plain / 'single' / "double" quoted scalars, [a, b] lists of scalars,
  // | and > block scalars, comments. It does not support anchors, aliases, tags, flow maps or multi-document files, and says so.
  function stripComment(s) {
    let q = null;
    for (let i = 0; i < s.length; i++) {
      const c = s[i];
      if (q) {
        if (c === q) { if (q === "'" && s[i + 1] === "'") { i++; continue; } q = null; }
        else if (q === '"' && c === "\\") i++;
      } else if ((c === "'" || c === '"') && (i === 0 || /[\s:[,{-]/.test(s[i - 1]))) q = c;
      else if (c === "#" && (i === 0 || /\s/.test(s[i - 1]))) return s.slice(0, i);
    }
    return s;
  }
  function tokenize(text) {
    if (typeof text !== "string") throw new RuleError("the rule must be text");
    const raw = text.replace(/\r\n?/g, "\n").split("\n");
    const out = [];
    for (let n = 0; n < raw.length; n++) {
      const line = raw[n];
      if (/^ *\t/.test(line)) throw new RuleError("tabs aren't allowed for indentation: use spaces", n + 1);
      const noc = stripComment(line);
      if (!noc.trim()) { out.push({ blank: true, raw: line, no: n + 1 }); continue; }
      out.push({ indent: noc.length - noc.trimStart().length, text: noc.trim(), raw: line, no: n + 1 });
    }
    return out;
  }
  const DASH = /^-(\s|$)/;
  function skipBlank(st) { while (st.i < st.lines.length && st.lines[st.i].blank) st.i++; }

  function unesc(ch, n) {
    const m = { "\\": "\\", '"': '"', "/": "/", n: "\n", t: "\t", r: "\r", "0": "\0", " ": " " };
    if (ch in m) return m[ch];
    throw new RuleError("unknown escape '\\" + ch + "' in a double-quoted string: use 'single quotes' for Windows paths and regular expressions, where a backslash is just a backslash", n);
  }
  function readQuoted(text, n) {
    const q = text[0];
    let s = "", j = 1;
    for (; j < text.length; j++) {
      const c = text[j];
      if (c === q) { if (q === "'" && text[j + 1] === "'") { s += "'"; j++; continue; } break; }
      if (q === '"' && c === "\\") {
        j++;
        if (j >= text.length) throw new RuleError("the string ends with a lone backslash", n);
        const k = text[j] === "x" ? 2 : text[j] === "u" ? 4 : text[j] === "U" ? 8 : 0;
        if (k) {
          const hex = text.slice(j + 1, j + 1 + k);
          if (hex.length !== k || !/^[0-9a-fA-F]+$/.test(hex)) throw new RuleError("'\\" + text[j] + "' needs " + k + " hex digits in a double-quoted string", n);
          s += String.fromCodePoint(parseInt(hex, 16)); j += k; continue;
        }
        s += unesc(text[j], n); continue;
      }
      s += c;
    }
    if (j >= text.length) throw new RuleError("a " + (q === "'" ? "single" : "double") + "-quoted string is never closed", n);
    return { value: s, end: j + 1 };
  }
  function splitKey(text, n) {
    if (text[0] === "'" || text[0] === '"') {
      let r;
      try { r = readQuoted(text, n); } catch (e) { return null; }
      let j = r.end;
      while (text[j] === " ") j++;
      if (text[j] !== ":" || (j + 1 < text.length && text[j + 1] !== " ")) return null;
      return { key: r.value, rest: text.slice(j + 1).trim() };
    }
    const m = /:(\s|$)/.exec(text);
    if (!m) return null;
    const k = text.slice(0, m.index).trim();
    if (!k || /^[[{]/.test(k)) return null;
    return { key: k, rest: text.slice(m.index + 1).trim() };
  }
  function plainScalar(t, n) {
    if (/^[&!%@`]/.test(t)) throw new RuleError("a value can't start with '" + t[0] + "' unless it is quoted (YAML anchors, tags and reserved characters aren't supported here)", n);
    if (t[0] === "*") throw new RuleError("a value starting with * must be quoted: plain YAML reads it as an alias. Write '" + t.replace(/'/g, "''") + "' with single quotes", n);
    if (/^(null|Null|NULL|~)$/.test(t)) return null;
    if (/^(true|True|TRUE)$/.test(t)) return true;
    if (/^(false|False|FALSE)$/.test(t)) return false;
    if (/^[-+]?(0|[1-9]\d*)$/.test(t)) { const v = Number(t); if (Number.isSafeInteger(v)) return v; }
    return t;
  }
  function scalarText(rest, n) {
    if (rest[0] === "'" || rest[0] === '"') {
      const r = readQuoted(rest, n);
      if (rest.slice(r.end).trim()) throw new RuleError("unexpected text after the closing quote", n);
      return r.value;
    }
    return plainScalar(rest, n);
  }
  function flowList(rest, n) {
    if (rest[rest.length - 1] !== "]") throw new RuleError("a [ ] list must close on the same line", n);
    const inner = rest.slice(1, -1).trim();
    if (!inner) return [];
    const items = [];
    let cur = "", q = null;
    for (let i = 0; i < inner.length; i++) {
      const c = inner[i];
      if (q) { cur += c; if (c === q) { if (q === "'" && inner[i + 1] === "'") { cur += "'"; i++; } else q = null; } else if (q === '"' && c === "\\") { cur += inner[++i] || ""; } }
      else if (c === "'" || c === '"') { q = c; cur += c; }
      else if (c === ",") { items.push(cur.trim()); cur = ""; }
      else cur += c;
    }
    items.push(cur.trim());
    return items.map((t) => { if (!t) throw new RuleError("an empty item in a [ ] list", n); return scalarText(t, n); });
  }
  function blockScalar(rest, st, parentIndent) {
    const style = rest[0], chomp = /[+-]/.exec(rest);
    const body = [];
    let bi = -1;
    while (st.i < st.lines.length) {
      const l = st.lines[st.i];
      const lead = l.raw.length - l.raw.trimStart().length;
      if (l.raw.trim() === "") { body.push(""); st.i++; continue; }
      if (lead <= parentIndent) break;
      if (bi < 0) bi = lead;
      body.push(l.raw.slice(Math.min(bi, lead)));
      st.i++;
    }
    while (body.length && body[body.length - 1] === "") body.pop();
    let s = style === "|" ? body.join("\n") : body.join("\n").replace(/([^\n])\n(?=[^\n])/g, "$1 ");
    if (!chomp || chomp[0] === "+") s += "\n";
    return s;
  }
  function parseScalar(rest, n, st, parentIndent) {
    if (/^[|>][+-]?$/.test(rest)) return blockScalar(rest, st, parentIndent);
    if (rest[0] === "[") return flowList(rest, n);
    if (rest[0] === "{") throw new RuleError("{ } maps aren't supported in this mini YAML reader: write the map on separate indented lines", n);
    if (rest[0] === "'" || rest[0] === '"') return scalarText(rest, n);
    // a plain scalar may continue on the following, more-indented lines (YAML folds them with spaces)
    let t = rest;
    for (;;) {
      let j = st.i;
      while (j < st.lines.length && st.lines[j].blank) j++;
      const nx = st.lines[j];
      if (!nx || nx.indent <= parentIndent) break;
      if (splitKey(nx.text, nx.no)) throw new RuleError("unexpected indentation: this line looks like a new 'key: value' but is indented further than the line above it", nx.no);
      st.i = j + 1; t += " " + nx.text;
    }
    return plainScalar(t, n);
  }
  function parseSeq(st, indent) {
    const arr = [];
    for (;;) {
      skipBlank(st);
      const cur = st.lines[st.i];
      if (!cur || cur.indent !== indent || !DASH.test(cur.text)) break;
      const m = /^-\s*/.exec(cur.text);
      const rest = cur.text.slice(m[0].length);
      if (rest === "") {
        st.i++; skipBlank(st);
        const nx = st.lines[st.i];
        arr.push(nx && nx.indent > indent ? parseBlock(st, nx.indent) : null);
      } else if (DASH.test(rest)) {
        throw new RuleError("a list inside a list on one line isn't supported here", cur.no);
      } else if (splitKey(rest, cur.no)) {
        const off = indent + m[0].length;
        st.lines[st.i] = { indent: off, text: rest, raw: " ".repeat(off) + rest, no: cur.no };
        arr.push(parseMap(st, off));
      } else { st.i++; arr.push(parseScalar(rest, cur.no, st, indent)); }
    }
    return arr;
  }
  function parseMap(st, indent) {
    const obj = Object.create(null);
    for (;;) {
      skipBlank(st);
      const cur = st.lines[st.i];
      if (!cur || cur.indent < indent) break;
      if (cur.indent > indent) throw new RuleError("unexpected indentation", cur.no);
      if (DASH.test(cur.text) || cur.text === "---" || cur.text === "...") break;
      const kv = splitKey(cur.text, cur.no);
      if (!kv) throw new RuleError("expected 'key: value' here, found: " + cur.text.slice(0, 60), cur.no);
      if (kv.key in obj) throw new RuleError("the key '" + kv.key + "' appears twice in the same map", cur.no);
      st.i++;
      let v;
      if (kv.rest === "") {
        skipBlank(st);
        const nx = st.lines[st.i];
        if (nx && nx.indent > indent) v = parseBlock(st, nx.indent);
        else if (nx && nx.indent === indent && DASH.test(nx.text)) v = parseSeq(st, indent);
        else v = null;
      } else v = parseScalar(kv.rest, cur.no, st, indent);
      obj[kv.key] = v;
    }
    return obj;
  }
  function parseBlock(st, indent) {
    skipBlank(st);
    const cur = st.lines[st.i];
    if (!cur) return null;
    if (DASH.test(cur.text)) return parseSeq(st, indent);
    if (splitKey(cur.text, cur.no)) return parseMap(st, indent);
    st.i++;
    return parseScalar(cur.text, cur.no, st, indent - 1);
  }
  function parseYaml(text) {
    const st = { lines: tokenize(text), i: 0 };
    skipBlank(st);
    if (st.i < st.lines.length && st.lines[st.i].text === "---") { st.i++; skipBlank(st); }
    if (st.i >= st.lines.length) return null;
    const v = parseBlock(st, st.lines[st.i].indent);
    skipBlank(st);
    if (st.i < st.lines.length) {
      const l = st.lines[st.i];
      if (l.text === "---" || l.text === "...") throw new RuleError("only one YAML document per file is supported", l.no);
      throw new RuleError("unexpected content: check the indentation", l.no);
    }
    return v;
  }

  // =========================================================================== 2. values, wildcards and modifiers
  const STRING_MODS = ["contains", "startswith", "endswith"];
  const KNOWN_MODS = ["all", "contains", "startswith", "endswith", "exists", "cased", "neq", "windash", "re", "i", "m", "s", "cidr", "lt", "lte", "gt", "gte", "fieldref"];
  const UNSUPPORTED_MODS = ["base64", "base64offset", "utf16le", "utf16be", "utf16", "wide", "expand", "minute", "hour", "day", "week", "month", "year"];
  const NUMERIC_MODS = ["lt", "lte", "gt", "gte"];
  const LEVELS = ["informational", "low", "medium", "high", "critical"];
  const STATUSES = ["stable", "test", "experimental", "deprecated", "unsupported"];

  function lev(a, b) {
    const d = Array.from({ length: a.length + 1 }, (_, i) => [i]);
    for (let j = 1; j <= b.length; j++) d[0][j] = j;
    for (let i = 1; i <= a.length; i++) for (let j = 1; j <= b.length; j++) {
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);   // a swapped pair counts as one slip
    }
    return d[a.length][b.length];
  }
  function closest(word, list) {
    let best = null, bd = 3;
    for (const w of list) { const d = lev(word.toLowerCase(), w); if (d < bd) { bd = d; best = w; } }
    return best;
  }
  const escRe = (c) => c.replace(/[.*+?^${}()|[\]\\\/]/g, "\\$&");

  // Sigma string escaping: * and ? are wildcards, a backslash escapes them. A run of n backslashes before a wildcard:
  // n even -> n/2 plain backslashes + wildcard; n odd -> (n-1)/2 plain backslashes + a plain wildcard character. Elsewhere a run of n is ceil(n/2).
  function globTokens(s) {
    const toks = [];
    for (let i = 0; i < s.length;) {
      if (s[i] === "\\") {
        let n = 0;
        while (s[i + n] === "\\") n++;
        const nx = s[i + n];
        if (nx === "*" || nx === "?") {
          for (let k = 0; k < Math.floor(n / 2); k++) toks.push({ lit: "\\" });
          if (n % 2) toks.push({ lit: nx }); else toks.push(nx === "*" ? { star: true } : { qm: true });
          i += n + 1;
        } else { for (let k = 0; k < Math.ceil(n / 2); k++) toks.push({ lit: "\\" }); i += n; }
      } else if (s[i] === "*") { toks.push({ star: true }); i++; }
      else if (s[i] === "?") { toks.push({ qm: true }); i++; }
      else { toks.push({ lit: s[i] }); i++; }
    }
    return toks;
  }
  function globRegex(value, mode, opt) {
    let src = "";
    for (const t of globTokens(String(value))) {
      if (t.star) src += "[\\s\\S]*";
      else if (t.qm) src += "[\\s\\S]";
      else if (opt.windash && /[-/–—―]/.test(t.lit)) src += "[-/–—―]";
      else src += escRe(t.lit);
    }
    if (mode === "equals") src = "^" + src + "$"; else if (mode === "startswith") src = "^" + src; else if (mode === "endswith") src = src + "$";
    return new RegExp(src, opt.cased ? "" : "i");
  }
  function ipToInt(s) {
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(s).trim());
    if (!m) return null;
    const p = m.slice(1).map(Number);
    if (p.some((x) => x > 255)) return null;
    return ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0;
  }
  function ip6ToBig(s) {
    s = String(s).trim().toLowerCase();
    if (!s.includes(":") || /[^0-9a-f:.]/.test(s) || (s.match(/::/g) || []).length > 1) return null;
    const parts = s.split("::");
    const groups = (str) => {
      if (str === "") return [];
      const g = str.split(":");
      const last = g[g.length - 1];
      if (last.includes(".")) { const v4 = ipToInt(last); if (v4 === null) return null; g.splice(g.length - 1, 1, (v4 >>> 16).toString(16), (v4 & 0xffff).toString(16)); }
      return g.every((x) => /^[0-9a-f]{1,4}$/.test(x)) ? g : null;
    };
    const head = groups(parts[0]);
    if (!head) return null;
    let all;
    if (parts.length === 2) {
      const tail = groups(parts[1]);
      if (!tail) return null;
      const fill = 8 - head.length - tail.length;
      if (fill < 1) return null;
      all = head.concat(Array(fill).fill("0"), tail);
    } else { all = head; if (all.length !== 8) return null; }
    let v = 0n;
    for (const x of all) v = (v << 16n) | BigInt(parseInt(x, 16));
    return v;
  }
  function cidrMatcher(spec) {
    const m = /^(.+)\/(\d{1,3})$/.exec(String(spec).trim());
    if (!m) throw new RuleError("'" + spec + "' isn't a CIDR range like 10.0.0.0/8");
    const bits = Number(m[2]);
    if (String(spec).includes(":")) {
      const base = ip6ToBig(m[1]);
      if (base === null || bits > 128) throw new RuleError("'" + spec + "' isn't a valid IPv6 CIDR range");
      const mask = ((1n << 128n) - 1n) ^ ((1n << BigInt(128 - bits)) - 1n);
      return (v) => { const x = ip6ToBig(v); return x !== null && (x & mask) === (base & mask); };
    }
    const base = ipToInt(m[1]);
    if (base === null || bits > 32) throw new RuleError("'" + spec + "' isn't a valid IPv4 CIDR range");
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return (v) => { const x = ipToInt(v); return x !== null && ((x & mask) >>> 0) === ((base & mask) >>> 0); };
  }
  const regexWarnings = (p) => {
    const w = [];
    if (/\\[dDwWsSbB]/.test(p)) w.push("the regular expression uses a shorthand like \\d, \\w, \\s or \\b: the Sigma spec's portable regex list doesn't include them, so some SIEMs may read it differently");
    if (/\(\?/.test(p)) w.push("the regular expression uses (?...) groups or lookarounds: not in the Sigma spec's portable regex list");
    if (/\\[1-9]/.test(p)) w.push("the regular expression uses a back-reference: not in the Sigma spec's portable regex list");
    return w;
  };

  // one "field|modifier: values" entry -> a function(event) -> boolean
  function compileEntry(key, value, ctx) {
    const parts = String(key).split("|");
    const field = parts[0];
    const mods = parts.slice(1);
    const where = "'" + key + "'";
    for (const m of mods) {
      if (UNSUPPORTED_MODS.includes(m)) throw new RuleError("the modifier '" + m + "' (in " + where + ") is valid Sigma, but this toy evaluator doesn't implement it");
      if (!KNOWN_MODS.includes(m)) {
        const c = closest(m, KNOWN_MODS);
        throw new RuleError("unknown modifier '" + m + "' in " + where + (c ? ". Did you mean '" + c + "'?" : ""));
      }
    }
    const has = (m) => mods.includes(m);
    const re = has("re");
    for (const m of ["i", "m", "s"]) if (has(m) && !re) throw new RuleError("'" + m + "' only works after 're' (in " + where + ")");
    const strMod = mods.filter((m) => STRING_MODS.includes(m));
    if (strMod.length > 1) throw new RuleError("use only one of contains, startswith and endswith in " + where);
    if (re && (strMod.length || has("windash") || has("cidr") || has("cased") || NUMERIC_MODS.some(has))) throw new RuleError("'re' can't be combined with the other string modifiers in " + where + " (a regular expression is already case-sensitive unless you add 'i')");
    if (has("cidr") && (strMod.length || re || NUMERIC_MODS.some(has))) throw new RuleError("'cidr' can't be combined with other value modifiers in " + where);
    const num = NUMERIC_MODS.find(has);
    if (num && (strMod.length || re || has("windash") || has("cidr"))) throw new RuleError("'" + num + "' is a numeric modifier and can't be combined with string modifiers in " + where);
    if (has("exists")) {
      if (mods.length > 1) throw new RuleError("'exists' can't be combined with other modifiers in " + where);
      if (typeof value !== "boolean") throw new RuleError("'exists' needs true or false in " + where);
      if (!field) throw new RuleError("'exists' needs a field name");
      ctx.fields.add(field);
      return (ev) => ((ev[field] !== undefined) === value);
    }
    const list = Array.isArray(value) ? value : [value];
    if (!list.length) throw new RuleError("the value list for " + where + " is empty");
    if (has("all") && list.length < 2) throw new RuleError("'all' needs a list of at least two values in " + where + " (the spec doesn't allow it on a single value)");
    if (field) ctx.fields.add(field);
    const nulls = list.filter((v) => v === null).length;
    if (nulls && list.length > 1) throw new RuleError("null can't be one item in a list of values (" + where + "): put it in its own selection and combine them in the condition");
    if (list.some((v) => typeof v === "object" && v !== null)) throw new RuleError("the values for " + where + " must be plain values, not maps or lists");
    if (has("fieldref")) {
      if (list.some((v) => typeof v !== "string")) throw new RuleError("'fieldref' needs field names as values in " + where);
      const eq = (ev, name) => { const a = ev[field], b = ev[name]; if (a === undefined || b === undefined) return false; return has("cased") ? String(a) === String(b) : String(a).toLowerCase() === String(b).toLowerCase(); };
      for (const v of list) ctx.fields.add(v);
      const fn = (ev) => (has("all") ? list.every((n) => eq(ev, n)) : list.some((n) => eq(ev, n)));
      return has("neq") ? (ev) => !fn(ev) : fn;
    }
    // build one predicate per value, on the (string) field value
    let preds;
    if (num) {
      preds = list.map((v) => {
        if (typeof v !== "number") throw new RuleError("'" + num + "' needs a number as its value in " + where);
        return (x) => { const n = Number(x); if (x === "" || x === null || Number.isNaN(n)) return false; return num === "lt" ? n < v : num === "lte" ? n <= v : num === "gt" ? n > v : n >= v; };
      });
    } else if (has("cidr")) {
      preds = list.map((v) => cidrMatcher(v));
    } else if (re) {
      const flags = (has("i") ? "i" : "") + (has("m") ? "m" : "") + (has("s") ? "s" : "");
      preds = list.map((v) => {
        let p = String(v), f = flags;
        const inline = /^\(\?([ims]+)\)/.exec(p);          // PCRE-style inline flags, common in real rules
        if (inline) {
          p = p.slice(inline[0].length);
          for (const c of inline[1]) if (!f.includes(c)) f += c;
          ctx.warnings.push("the regular expression starts with (?" + inline[1] + "): the Sigma spec's way is a sub-modifier, such as re|i, not an inline flag");
        }
        if (p.length > 300) throw new RuleError("that regular expression is longer than this toy evaluator allows (300 characters)");
        // a guard against the classic runaway shapes such as (a+)+ or (\w*)*; it is a toy check, not a regex safety analyser
        if (/\((?:\?:)?(?:\\.|\[[^\]]*\]|[^()\\|[\]])[+*]\)[+*{]/.test(p)) throw new RuleError("that regular expression repeats a group that is itself a repeated item, like (a+)+, which can take exponential time on some inputs: simplify it");
        let rx;
        try { rx = new RegExp(p, f); } catch (e) { throw new RuleError("the regular expression " + JSON.stringify(p) + " isn't valid: " + e.message.replace(/^Invalid regular expression: /, "")); }
        for (const w of regexWarnings(p)) ctx.warnings.push(w);
        return (x) => rx.test(String(x));
      });
    } else {
      const mode = strMod[0] || "equals";
      preds = list.map((v) => {
        if (v === null) return (x) => x === null || x === undefined;
        const s = String(v);
        if (s === "" && mode === "equals") return (x) => x !== undefined && x !== null && String(x) === "";
        const rx = globRegex(s, mode, { cased: has("cased"), windash: has("windash") });
        return (x) => x !== undefined && x !== null && rx.test(String(x));
      });
    }
    const neq = has("neq");
    if (!field) {                                   // keyword search across the whole event
      const anyField = (p) => (ev) => Object.keys(ev).some((k) => k[0] !== "_" && ev[k] !== undefined && ev[k] !== null && p(ev[k]));
      const kw = list.map((v, i) => {
        if (typeof v !== "string" && typeof v !== "number") throw new RuleError("keywords must be text");
        const rx = globRegex(String(v), "contains", { cased: has("cased"), windash: has("windash") });
        return anyField((x) => rx.test(String(x)));
      });
      return has("all") ? (ev) => kw.every((f) => f(ev)) : (ev) => kw.some((f) => f(ev));
    }
    const test = (ev) => {
      const x = ev[field];
      const hit = (p) => p(x);
      const r = has("all") ? preds.every(hit) : preds.some(hit);
      return r;
    };
    if (neq) {
      if (strMod.length || re || has("cidr")) throw new RuleError("'neq' only combines with plain values, 'all', 'cased' and the numeric modifiers in " + where);
      return (ev) => ev[field] !== undefined && !(has("all") ? preds.every((p) => p(ev[field])) : preds.some((p) => p(ev[field])));
    }
    return test;
  }

  // a "selection": list of keywords, list of maps (OR), or a map (AND)
  function compileSelection(name, node, ctx) {
    if (Array.isArray(node)) {
      if (!node.length) throw new RuleError("the search identifier '" + name + "' is an empty list");
      const maps = node.filter((x) => x && typeof x === "object" && !Array.isArray(x));
      if (maps.length === node.length) {
        const fns = node.map((m) => compileMap(name, m, ctx));
        return (ev) => fns.some((f) => f(ev));
      }
      if (maps.length) throw new RuleError("the list '" + name + "' mixes keywords and field maps: a list holds one or the other");
      const rest = node.filter((v) => v === null || typeof v === "object");
      if (rest.length) throw new RuleError("the keyword list '" + name + "' has a value that isn't text");
      return compileEntry("", node, ctx);
    }
    if (node && typeof node === "object") return compileMap(name, node, ctx);
    throw new RuleError("the search identifier '" + name + "' must be a map of field: value pairs or a list, not a single value");
  }
  function compileMap(name, m, ctx) {
    const keys = Object.keys(m);
    if (!keys.length) throw new RuleError("the search identifier '" + name + "' is an empty map");
    const fns = keys.map((k) => {
      if (m[k] !== null && typeof m[k] === "object" && !Array.isArray(m[k])) throw new RuleError("'" + k + "' in '" + name + "' has a map as its value: values must be plain values or lists");
      return compileEntry(k, m[k], ctx);
    });
    return (ev) => fns.every((f) => f(ev));
  }

  // =========================================================================== 3. the condition
  // precedence, least to most binding: or, and, not, "x of pattern", ( )
  function tokenizeCond(s) {
    const toks = [];
    const re = /\s*(\(|\)|\||[A-Za-z0-9_.*-]+)/y;
    let pos = 0;
    s = String(s);
    while (pos < s.length) {
      if (/^\s*$/.test(s.slice(pos))) break;
      re.lastIndex = pos;
      const m = re.exec(s);
      if (!m) throw new RuleError("can't read the condition near: " + s.slice(pos, pos + 20));
      toks.push(m[1]); pos = re.lastIndex;
    }
    return toks;
  }
  function parseCondition(text, names) {
    if (String(text).includes("|")) throw new RuleError("a condition with | (count(), near, aggregations) is the legacy Sigma 1 syntax, replaced by correlation rules in Sigma 2: this toy evaluator doesn't support either");
    const toks = tokenizeCond(text);
    if (!toks.length) throw new RuleError("the condition is empty");
    let p = 0;
    const used = new Set();
    const peek = () => toks[p];
    const eat = (t) => { if (toks[p] !== t) throw new RuleError("the condition expected '" + t + "' but found " + (toks[p] === undefined ? "the end" : "'" + toks[p] + "'")); p++; };
    function matchNames(pat) {
      if (pat === "them") return names.filter((n) => !n.startsWith("_"));
      const rx = new RegExp("^" + pat.split("*").map(escRe).join(".*") + "$");
      return names.filter((n) => rx.test(n));
    }
    function orE() { let l = andE(); while (peek() === "or") { p++; l = { t: "or", a: l, b: andE() }; } return l; }
    function andE() { let l = notE(); while (peek() === "and") { p++; l = { t: "and", a: l, b: notE() }; } return l; }
    function notE() { if (peek() === "not") { p++; return { t: "not", x: notE() }; } return atom(); }
    function atom() {
      const t = peek();
      if (t === undefined) throw new RuleError("the condition ends too early");
      if (t === "(") { p++; const e = orE(); eat(")"); return e; }
      if (t === "and" || t === "or" || t === "not" || t === ")") throw new RuleError("the condition has '" + t + "' where a search identifier was expected");
      if ((t === "1" || t === "all") && toks[p + 1] === "of") {
        p += 2;
        const pat = peek();
        if (pat === undefined || pat === "(" || pat === ")" || pat === "and" || pat === "or" || pat === "not") throw new RuleError("'" + t + " of' needs 'them' or a pattern such as selection_*");
        p++;
        const ns = matchNames(pat);
        if (!ns.length) throw new RuleError("'" + t + " of " + pat + "' matches no search identifier");
        ns.forEach((n) => used.add(n));
        return { t: "of", q: t, names: ns, pat };
      }
      if (/^\d+$/.test(t) && toks[p + 1] === "of") throw new RuleError("only '1 of' and 'all of' are defined in the Sigma spec, not '" + t + " of'");
      p++;
      if (!names.includes(t)) {
        const c = closest(t, names);
        throw new RuleError("the condition uses '" + t + "', but no search identifier has that name" + (c ? ". Did you mean '" + c + "'?" : ""));
      }
      used.add(t);
      return { t: "id", name: t };
    }
    const ast = orE();
    if (p < toks.length) throw new RuleError("the condition has something left over after a complete expression: '" + toks[p] + "'");
    return { ast, used };
  }
  function evalAst(a, v) {
    switch (a.t) {
      case "id": return v(a.name);
      case "not": return !evalAst(a.x, v);
      case "and": return evalAst(a.a, v) && evalAst(a.b, v);
      case "or": return evalAst(a.a, v) || evalAst(a.b, v);
      case "of": return a.q === "all" ? a.names.every(v) : a.names.some(v);
    }
    return false;
  }

  // =========================================================================== 4. compile a rule
  function compile(input) {
    const rule = typeof input === "string" ? parseYaml(input) : input;
    if (!rule || typeof rule !== "object" || Array.isArray(rule)) throw new RuleError("a rule is a map of fields such as title, logsource and detection");
    const det = rule.detection;
    if (det === undefined || det === null) throw new RuleError("the rule has no 'detection' section (it is mandatory)");
    if (typeof det !== "object" || Array.isArray(det)) throw new RuleError("'detection' must be a map of search identifiers and a condition");
    if (det.condition === undefined || det.condition === null) throw new RuleError("the detection has no 'condition' (it is mandatory)");
    const ctx = { fields: new Set(), warnings: [] };
    const names = Object.keys(det).filter((k) => k !== "condition" && k !== "timeframe");
    if (!names.length) throw new RuleError("'detection' needs at least one search identifier such as 'selection'");
    if (det.timeframe !== undefined) ctx.warnings.push("'timeframe' is legacy Sigma 1 syntax (used with count()); Sigma 2 does time-based logic in correlation rules, which this toy evaluator doesn't run");
    const sels = Object.create(null);
    for (const n of names) {
      if (!/^[A-Za-z0-9_.-]+$/.test(n)) throw new RuleError("'" + n + "' isn't a valid search identifier name (letters, digits, underscores, dots and hyphens). If a modifier such as |endswith is in the name, it belongs on a field inside the map, not on the identifier");
      sels[n] = compileSelection(n, det[n], ctx);
    }
    const condList = Array.isArray(det.condition) ? det.condition : [det.condition];
    if (!condList.length) throw new RuleError("the condition list is empty");
    const parsed = condList.map((c) => {
      if (typeof c !== "string") throw new RuleError("each condition must be text");
      return parseCondition(c, names);
    });
    const used = new Set();
    parsed.forEach((p) => p.used.forEach((u) => used.add(u)));
    for (const n of names) if (!used.has(n)) ctx.warnings.push("the search identifier '" + n + "' is never used in the condition, so it has no effect");
    if (condList.some((c) => /\ball of them\b/.test(c))) ctx.warnings.push("'all of them' is discouraged by the spec: it stops other people adding filters to your rule. Prefer 'all of selection*'");
    if (rule.level !== undefined && !LEVELS.includes(rule.level)) ctx.warnings.push("'level' should be one of " + LEVELS.join(", "));
    const cache = new WeakMap();
    function run(ev) {
      const memo = Object.create(null);
      const v = (n) => (n in memo ? memo[n] : (memo[n] = !!sels[n](ev)));
      const hits = {};
      const fired = parsed.some((p) => evalAst(p.ast, v));
      for (const n of names) hits[n] = v(n);
      return { fired, hits };
    }
    return {
      rule, names, warnings: ctx.warnings, fields: [...ctx.fields],
      match: (ev) => { let r = cache.get(ev); if (!r) { r = run(ev).fired; cache.set(ev, r); } return r; },
      explain: (ev) => run(ev),
    };
  }

  // =========================================================================== 5. metadata checks ("lint") for the CI demo
  const UUID4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  function validIsoDate(s) {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(String(s))) return false;
    const d = new Date(s + "T00:00:00Z");
    return !Number.isNaN(d.getTime()) && d.toISOString().slice(0, 10) === String(s);
  }
  function lintRule(rule, ctx) {
    ctx = ctx || {};
    const out = [];
    const bad = (msg) => out.push({ level: "error", msg });
    const warn = (msg) => out.push({ level: "warn", msg });
    if (!rule || typeof rule !== "object") { bad("the rule isn't a map"); return out; }
    if (!rule.title) bad("missing 'title' (mandatory in the spec)"); else if (String(rule.title).length > 256) bad("'title' is longer than 256 characters (the spec's limit)");
    if (!rule.logsource || typeof rule.logsource !== "object" || !(rule.logsource.category || rule.logsource.product || rule.logsource.service)) bad("missing 'logsource' with a category, product or service (mandatory in the spec)");
    if (!rule.id) bad("missing 'id': team policy, and the spec recommends a random UUIDv4"); // the spec says optional
    else if (!UUID4.test(String(rule.id))) bad("'id' isn't a UUIDv4 (the spec recommends a random one)");
    else if (ctx.existingIds && ctx.existingIds.includes(String(rule.id).toLowerCase())) bad("'id' " + rule.id + " is already used by another rule: IDs must be unique (give a changed rule a new id, or relate it with 'related')");
    if (!rule.status) bad("missing 'status': team policy (the spec lists " + STATUSES.join(", ") + ")");
    else if (!STATUSES.includes(rule.status)) bad("'status' must be one of " + STATUSES.join(", "));
    if (!rule.description) bad("missing 'description': team policy, so the person on call knows what fired");
    if (!rule.author) bad("missing 'author': team policy, so there is someone to ask");
    if (!rule.date) bad("missing 'date': team policy"); else if (!validIsoDate(rule.date)) bad("'date' must be an ISO date like 2026-11-09");
    if (!rule.level) bad("missing 'level': how urgent is this?"); else if (!LEVELS.includes(rule.level)) bad("'level' must be one of " + LEVELS.join(", "));
    if (!Array.isArray(rule.falsepositives) || !rule.falsepositives.length) bad("missing 'falsepositives': write down what benign activity you expect, even if it's 'Unknown'");
    const tags = Array.isArray(rule.tags) ? rule.tags.map(String) : [];
    const techs = tags.filter((t) => /^attack\.t\d{4}(\.\d{3})?$/i.test(t));
    if (!techs.length) bad("no ATT&CK technique tag such as attack.t1059.001, so the rule can't be placed on a coverage map");
    else if (ctx.techniqueIds) for (const t of techs) { const id = t.slice(7).toUpperCase(); if (!ctx.techniqueIds.includes(id)) bad("the tag " + t + " isn't a technique in the ATT&CK version this team tracks (" + (ctx.attackVersion || "?") + ")"); }
    if (tags.some((t) => t.toLowerCase() === "attack.defense-evasion")) warn("attack.defense-evasion: ATT&CK v19 (April 2026) replaced that tactic with Stealth and Defense Impairment. The Sigma tags appendix (v2.1.0) still lists it, so check what your tooling expects");
    if (rule.level === "critical" && rule.status === "experimental") warn("level 'critical' on an 'experimental' rule: the spec reserves critical for \"cases in which probability borders certainty\"");
    if (rule.status === "stable" && !(ctx.testsCount > 0)) warn("'stable' with no tests: promote a rule only when its tests exist");
    return out;
  }

  // run a rule over events (filtered to its logsource category when events carry one)
  function evaluate(compiled, events) {
    const cat = compiled.rule && compiled.rule.logsource && compiled.rule.logsource.category;
    const rows = [];
    for (const e of events) {
      if (cat && e._category && e._category !== cat) continue;
      rows.push({ event: e, fired: compiled.match(e) });
    }
    return rows;
  }
  function score(rows) {
    let tp = 0, fp = 0, fn = 0, tn = 0;
    for (const r of rows) {
      const a = r.event._label === "attack";
      if (r.fired && a) tp++; else if (r.fired) fp++; else if (a) fn++; else tn++;
    }
    return { tp, fp, fn, tn, fired: tp + fp, attacks: tp + fn };
  }

  const API = { RuleError, parseYaml, compile, lintRule, evaluate, score, globTokens, ipToInt, KNOWN_MODS, UNSUPPORTED_MODS, LEVELS, STATUSES, UUID4, validIsoDate, closest };
  root.Rules = Object.assign(root.Rules || {}, API);
  if (typeof module !== "undefined" && module.exports) module.exports = root.Rules;
})(typeof window !== "undefined" ? window : globalThis);
