// Attribute-vector cost benchmark for QuickJS (proxy for Caido's rquickjs backend runtime).
// Compares: naive string-based feature extraction vs single-pass byte scan (with and without
// multi-needle keyword matching), plus bigram-profile construction cost.

const now = (typeof performance !== "undefined" && performance.now)
  ? () => performance.now()
  : () => Date.now();

// ---------------------------------------------------------------- synthetic bodies

function makeMinifiedJson(targetBytes) {
  const parts = [];
  let n = 0;
  let i = 0;
  parts.push('{"ok":true,"count":4213,"items":[');
  n += 34;
  while (n < targetBytes) {
    const chunk = '{"id":' + i + ',"sku":"AB-' + i + '-XZ","name":"Widget ' + i +
      '","price":' + (i % 997) + '.99,"tags":["a","b"],"active":' + (i % 2 === 0) + '},';
    parts.push(chunk);
    n += chunk.length;
    i++;
  }
  parts.push('{"id":0}]}');
  return parts.join("");
}

function makeHtml(targetBytes) {
  const parts = [];
  let n = 0;
  let i = 0;
  const head = '<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n' +
    '<title>Catalogue</title>\n<script src="/static/app.js"></script>\n</head>\n<body>\n' +
    '<div id="root" class="page">\n';
  parts.push(head);
  n += head.length;
  while (n < targetBytes) {
    const chunk = '  <div class="card" data-id="' + i + '">\n' +
      '    <h3 class="card-title">Product number ' + i + '</h3>\n' +
      '    <p class="desc">A description of the item, with some words in it.</p>\n' +
      '    <span class="price">' + (i % 997) + '.99</span>\n' +
      '    <a href="/item/' + i + '?ref=list">details</a>\n' +
      '  </div>\n';
    parts.push(chunk);
    n += chunk.length;
    i++;
  }
  parts.push('</div>\n</body>\n</html>\n');
  return parts.join("");
}

function toBytes(str) {
  // Bodies are ASCII by construction, so a byte-per-char copy is faithful and avoids
  // depending on TextEncoder being present in the host.
  const out = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) out[i] = str.charCodeAt(i) & 0xff;
  return out;
}

const KEYWORDS = [
  "error", "exception", "invalid", "warning", "stack", "sql syntax", "divisor",
  "divide", "division", "infinity", "ora-", "<script", "<div", "true", "false",
  "null", '","', "[]", '""', "</html>",
];

// ---------------------------------------------------------------- A: naive string approach

function naiveAttributes(bytes) {
  // Mirrors the shape of the prior Java implementation: decode whole body, lowercase it,
  // then run one substring scan per keyword.
  let s = "";
  const CHUNK = 32768;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, Math.min(i + CHUNK, bytes.length)));
  }
  const lower = s.toLowerCase();

  const attrs = {};
  attrs.length = lower.length;

  let newlines = 0, spaces = 0, tags = 0, equals = 0;
  for (let i = 0; i < lower.length; i++) {
    const c = lower.charCodeAt(i);
    if (c === 10) newlines++;
    else if (c === 32) spaces++;
    else if (c === 60) tags++;
    else if (c === 61) equals++;
  }
  attrs.newlines = newlines;
  attrs.spaces = spaces;
  attrs.tags = tags;
  attrs.equals = equals;

  for (let k = 0; k < KEYWORDS.length; k++) {
    const needle = KEYWORDS[k];
    let count = 0, idx = 0;
    for (;;) {
      idx = lower.indexOf(needle, idx);
      if (idx === -1) break;
      count++;
      idx += needle.length;
    }
    attrs["kw:" + needle] = count;
  }
  return attrs;
}

// ---------------------------------------------------------------- Aho-Corasick automaton

function buildAutomaton(patterns) {
  // goto[state] is a 256-wide Int32Array of next-state or -1.
  const goto_ = [new Int32Array(256).fill(-1)];
  const fail = [0];
  const out = [null];

  for (let p = 0; p < patterns.length; p++) {
    const pat = patterns[p];
    let s = 0;
    for (let i = 0; i < pat.length; i++) {
      const c = pat.charCodeAt(i) & 0xff;
      if (goto_[s][c] === -1) {
        goto_.push(new Int32Array(256).fill(-1));
        fail.push(0);
        out.push(null);
        goto_[s][c] = goto_.length - 1;
      }
      s = goto_[s][c];
    }
    if (out[s] === null) out[s] = [];
    out[s].push(p);
  }

  // BFS to build failure links and complete the goto function (DFA form).
  const queue = [];
  for (let c = 0; c < 256; c++) {
    const t = goto_[0][c];
    if (t === -1) {
      goto_[0][c] = 0;
    } else {
      fail[t] = 0;
      queue.push(t);
    }
  }
  let qi = 0;
  while (qi < queue.length) {
    const s = queue[qi++];
    // merge outputs along failure link
    if (out[fail[s]] !== null) {
      if (out[s] === null) out[s] = [];
      const inherited = out[fail[s]];
      for (let i = 0; i < inherited.length; i++) out[s].push(inherited[i]);
    }
    for (let c = 0; c < 256; c++) {
      const t = goto_[s][c];
      if (t === -1) {
        goto_[s][c] = goto_[fail[s]][c];
      } else {
        fail[t] = goto_[fail[s]][c];
        queue.push(t);
      }
    }
  }

  // Flatten to one Int32Array for cache friendliness.
  const flat = new Int32Array(goto_.length * 256);
  for (let s = 0; s < goto_.length; s++) flat.set(goto_[s], s * 256);
  return { next: flat, out: out, nStates: goto_.length };
}

const AUTOMATON = buildAutomaton(KEYWORDS);

// ---------------------------------------------------------------- B: single-pass byte scan

function bytePassAttributes(bytes, automaton) {
  const len = bytes.length;
  let newlines = 0, spaces = 0, tags = 0, equals = 0, quotes = 0, commas = 0;
  const kwCounts = new Int32Array(KEYWORDS.length);
  const next = automaton.next;
  const out = automaton.out;
  let state = 0;

  for (let i = 0; i < len; i++) {
    let c = bytes[i];
    // structural counters on the raw byte
    if (c === 10) newlines++;
    else if (c === 32) spaces++;
    else if (c === 60) tags++;
    else if (c === 61) equals++;
    else if (c === 34) quotes++;
    else if (c === 44) commas++;
    // case-fold for the keyword automaton
    if (c >= 65 && c <= 90) c += 32;
    state = next[(state << 8) | c];
    const hits = out[state];
    if (hits !== null) {
      for (let h = 0; h < hits.length; h++) kwCounts[hits[h]]++;
    }
  }

  const attrs = {
    length: len,
    newlines: newlines,
    spaces: spaces,
    tags: tags,
    equals: equals,
    quotes: quotes,
    commas: commas,
  };
  for (let k = 0; k < KEYWORDS.length; k++) attrs["kw:" + KEYWORDS[k]] = kwCounts[k];
  return attrs;
}

// ---------------------------------------------------------------- C: byte scan, no keywords

function bytePassStructuralOnly(bytes) {
  const len = bytes.length;
  let newlines = 0, spaces = 0, tags = 0, equals = 0, quotes = 0, commas = 0;
  for (let i = 0; i < len; i++) {
    const c = bytes[i];
    if (c === 10) newlines++;
    else if (c === 32) spaces++;
    else if (c === 60) tags++;
    else if (c === 61) equals++;
    else if (c === 34) quotes++;
    else if (c === 44) commas++;
  }
  return { length: len, newlines, spaces, tags, equals, quotes, commas };
}

// ---------------------------------------------------------------- D: bigram similarity profile

function bigramProfile(bytes) {
  // 16-bit bigram histogram over folded bytes. Fixed 65536-slot Int32Array: no hashing,
  // no string allocation, and cosine/Jaccard similarity is then a fixed-cost array walk.
  const hist = new Int32Array(65536);
  const len = bytes.length;
  if (len < 2) return hist;
  let prev = bytes[0];
  if (prev >= 65 && prev <= 90) prev += 32;
  for (let i = 1; i < len; i++) {
    let c = bytes[i];
    if (c >= 65 && c <= 90) c += 32;
    hist[(prev << 8) | c]++;
    prev = c;
  }
  return hist;
}

function bigramCosine(a, b) {
  let dot = 0, na = 0, nb = 0;
  for (let i = 0; i < 65536; i++) {
    const x = a[i], y = b[i];
    if (x !== 0 || y !== 0) {
      dot += x * y;
      na += x * x;
      nb += y * y;
    }
  }
  if (na === 0 || nb === 0) return na === nb ? 1 : 0;
  return dot / Math.sqrt(na * nb);
}

// ---------------------------------------------------------------- E: tag-sequence structure hash

function tagSequenceHash(bytes) {
  // FNV-1a over the sequence of lowercased tag names, ignoring attributes and text.
  let h = 0x811c9dc5;
  const len = bytes.length;
  let i = 0;
  while (i < len) {
    if (bytes[i] === 60) { // '<'
      i++;
      if (i < len && bytes[i] === 47) { // '</'
        h ^= 47; h = (h * 0x01000193) >>> 0;
        i++;
      }
      while (i < len) {
        let c = bytes[i];
        if (c === 32 || c === 62 || c === 10 || c === 13 || c === 9 || c === 47) break;
        if (c >= 65 && c <= 90) c += 32;
        h ^= c; h = (h * 0x01000193) >>> 0;
        i++;
      }
      h ^= 62; h = (h * 0x01000193) >>> 0;
    } else {
      i++;
    }
  }
  return h >>> 0;
}

// ---------------------------------------------------------------- harness

function bench(label, fn, iterations) {
  // one warm-up to let the JIT-less interpreter touch the code path and caches
  fn();
  const t0 = now();
  for (let i = 0; i < iterations; i++) fn();
  const t1 = now();
  const total = t1 - t0;
  return { label, iterations, totalMs: total, perCallMs: total / iterations };
}

const CASES = [
  { name: "json-minified-50KB", body: makeMinifiedJson(50 * 1024) },
  { name: "html-500KB", body: makeHtml(500 * 1024) },
  { name: "html-2MB", body: makeHtml(2 * 1024 * 1024) },
];

const results = [];

for (const c of CASES) {
  const bytes = toBytes(c.body);
  const iters = bytes.length > 1024 * 1024 ? 5 : 20;

  results.push(Object.assign({ case: c.name, bytes: bytes.length },
    bench("A naive-string+20x-indexOf", () => naiveAttributes(bytes), iters)));
  results.push(Object.assign({ case: c.name, bytes: bytes.length },
    bench("B single-pass+aho-corasick", () => bytePassAttributes(bytes, AUTOMATON), iters)));
  results.push(Object.assign({ case: c.name, bytes: bytes.length },
    bench("C single-pass structural-only", () => bytePassStructuralOnly(bytes), iters)));
  results.push(Object.assign({ case: c.name, bytes: bytes.length },
    bench("D bigram-profile-build", () => bigramProfile(bytes), iters)));
  results.push(Object.assign({ case: c.name, bytes: bytes.length },
    bench("E tag-sequence-hash", () => tagSequenceHash(bytes), iters)));
}

// bigram comparison cost is independent of body size (fixed 65536 walk)
{
  const a = bigramProfile(toBytes(CASES[1].body));
  const b = bigramProfile(toBytes(CASES[1].body.replace("Widget", "Gadget")));
  results.push(Object.assign({ case: "n/a", bytes: 0 },
    bench("F bigram-cosine-compare", () => bigramCosine(a, b), 50)));
}

// correctness cross-check between A and B on the shared counters
{
  const bytes = toBytes(CASES[0].body);
  const a = naiveAttributes(bytes);
  const b = bytePassAttributes(bytes, AUTOMATON);
  const mismatches = [];
  for (const k of ["newlines", "spaces", "tags", "equals"]) {
    if (a[k] !== b[k]) mismatches.push(k + ": " + a[k] + " vs " + b[k]);
  }
  for (const kw of KEYWORDS) {
    const key = "kw:" + kw;
    if (a[key] !== b[key]) mismatches.push(key + ": " + a[key] + " vs " + b[key]);
  }
  print("CROSSCHECK " + (mismatches.length === 0 ? "OK" : "MISMATCH " + mismatches.join("; ")));
  print("AUTOMATON states=" + AUTOMATON.nStates);
}

print("");
print(["case", "bytes", "impl", "iters", "perCallMs"].join("\t"));
for (const r of results) {
  print([r.case, r.bytes, r.label, r.iterations, r.perCallMs.toFixed(4)].join("\t"));
}
