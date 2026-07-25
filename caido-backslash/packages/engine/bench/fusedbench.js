// Round 2: validate the actual proposed hot path.
//  - fuse every per-byte feature into ONE loop (vs the separate passes measured in round 1)
//  - measure the cost/benefit of a scan cap
//  - size the bigram histogram (65536 vs 4096 buckets) for build AND compare cost

const now = (typeof performance !== "undefined" && performance.now)
  ? () => performance.now()
  : () => Date.now();

function makeHtml(targetBytes) {
  const parts = [];
  let n = 0, i = 0;
  const head = '<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n<title>C</title>\n</head>\n<body>\n';
  parts.push(head); n += head.length;
  while (n < targetBytes) {
    const chunk = '  <div class="card" data-id="' + i + '">\n    <h3>Product ' + i +
      '</h3>\n    <p>A description with words.</p>\n    <span>' + (i % 997) +
      '.99</span>\n    <a href="/item/' + i + '?ref=list">details</a>\n  </div>\n';
    parts.push(chunk); n += chunk.length; i++;
  }
  parts.push('</body>\n</html>\n');
  return parts.join("");
}

function makeMinifiedJson(targetBytes) {
  const parts = ['{"ok":true,"items":['];
  let n = 20, i = 0;
  while (n < targetBytes) {
    const chunk = '{"id":' + i + ',"sku":"AB-' + i + '","name":"Widget ' + i +
      '","price":' + (i % 997) + '.99,"active":' + (i % 2 === 0) + '},';
    parts.push(chunk); n += chunk.length; i++;
  }
  parts.push('{"id":0}]}');
  return parts.join("");
}

function toBytes(str) {
  const out = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) out[i] = str.charCodeAt(i) & 0xff;
  return out;
}

const KEYWORDS = [
  "error", "exception", "invalid", "warning", "stack", "sql syntax", "divisor",
  "divide", "division", "infinity", "ora-", "<script", "<div", "true", "false",
  "null", '","', "[]", '""', "</html>",
];

function buildAutomaton(patterns) {
  const goto_ = [new Int32Array(256).fill(-1)];
  const fail = [0];
  const out = [null];
  for (let p = 0; p < patterns.length; p++) {
    const pat = patterns[p];
    let s = 0;
    for (let i = 0; i < pat.length; i++) {
      const c = pat.charCodeAt(i) & 0xff;
      if (goto_[s][c] === -1) {
        goto_.push(new Int32Array(256).fill(-1)); fail.push(0); out.push(null);
        goto_[s][c] = goto_.length - 1;
      }
      s = goto_[s][c];
    }
    if (out[s] === null) out[s] = [];
    out[s].push(p);
  }
  const queue = [];
  for (let c = 0; c < 256; c++) {
    const t = goto_[0][c];
    if (t === -1) goto_[0][c] = 0; else { fail[t] = 0; queue.push(t); }
  }
  let qi = 0;
  while (qi < queue.length) {
    const s = queue[qi++];
    if (out[fail[s]] !== null) {
      if (out[s] === null) out[s] = [];
      const inh = out[fail[s]];
      for (let i = 0; i < inh.length; i++) out[s].push(inh[i]);
    }
    for (let c = 0; c < 256; c++) {
      const t = goto_[s][c];
      if (t === -1) goto_[s][c] = goto_[fail[s]][c];
      else { fail[t] = goto_[fail[s]][c]; queue.push(t); }
    }
  }
  const flat = new Int32Array(goto_.length * 256);
  for (let s = 0; s < goto_.length; s++) flat.set(goto_[s], s * 256);
  // outFlat: -1 when a state emits nothing, else index into outLists
  const outFlat = new Int32Array(goto_.length).fill(-1);
  const outLists = [];
  for (let s = 0; s < out.length; s++) {
    if (out[s] !== null) { outFlat[s] = outLists.length; outLists.push(Int32Array.from(out[s])); }
  }
  return { next: flat, outFlat: outFlat, outLists: outLists, nStates: goto_.length };
}

const AC = buildAutomaton(KEYWORDS);

// ---------------------------------------------------------------- fused scan

// Everything per-byte in a single loop: structural counters, keyword automaton,
// bigram histogram, and the HTML tag-name sequence hash.
function fusedScan(bytes, from, to, bigramBits, withBigram, withTagHash) {
  const next = AC.next, outFlat = AC.outFlat, outLists = AC.outLists;
  const kw = new Int32Array(KEYWORDS.length);
  const bigramSize = 1 << bigramBits;
  const bigramMask = bigramSize - 1;
  const hist = withBigram ? new Int32Array(bigramSize) : null;

  let newlines = 0, spaces = 0, tags = 0, equals = 0, quotes = 0, commas = 0, digits = 0;
  let state = 0;
  let prev = 0;
  let tagHash = 0x811c9dc5;
  let inTag = 0;

  for (let i = from; i < to; i++) {
    const raw = bytes[i];
    let c = raw;

    if (raw === 10) newlines++;
    else if (raw === 32) spaces++;
    else if (raw === 60) tags++;
    else if (raw === 61) equals++;
    else if (raw === 34) quotes++;
    else if (raw === 44) commas++;
    else if (raw >= 48 && raw <= 57) digits++;

    if (c >= 65 && c <= 90) c += 32;

    state = next[(state << 8) | c];
    const oi = outFlat[state];
    if (oi !== -1) {
      const hits = outLists[oi];
      for (let h = 0; h < hits.length; h++) kw[hits[h]]++;
    }

    if (withBigram) {
      hist[((prev * 31 + c) & bigramMask)]++;
      prev = c;
    }

    if (withTagHash) {
      if (raw === 60) { inTag = 1; }
      else if (inTag === 1) {
        if (raw === 32 || raw === 62 || raw === 10 || raw === 13 || raw === 9) {
          inTag = 0;
          tagHash ^= 62; tagHash = (tagHash * 0x01000193) >>> 0;
        } else {
          tagHash ^= c; tagHash = (tagHash * 0x01000193) >>> 0;
        }
      }
    }
  }

  return {
    newlines, spaces, tags, equals, quotes, commas, digits,
    kw: kw, hist: hist, tagHash: tagHash >>> 0,
  };
}

function histCosine(a, b, size) {
  let dot = 0, na = 0, nb = 0;
  for (let i = 0; i < size; i++) {
    const x = a[i], y = b[i];
    if (x !== 0 || y !== 0) { dot += x * y; na += x * x; nb += y * y; }
  }
  if (na === 0 || nb === 0) return na === nb ? 1 : 0;
  return dot / Math.sqrt(na * nb);
}

function bench(label, fn, iterations) {
  fn();
  const t0 = now();
  for (let i = 0; i < iterations; i++) fn();
  const t1 = now();
  return { label, iterations, perCallMs: (t1 - t0) / iterations };
}

const rows = [];
const BODIES = [
  { name: "html-500KB", bytes: toBytes(makeHtml(500 * 1024)) },
  { name: "html-2MB", bytes: toBytes(makeHtml(2 * 1024 * 1024)) },
  { name: "json-min-500KB", bytes: toBytes(makeMinifiedJson(500 * 1024)) },
];
const CAPS = [16 * 1024, 32 * 1024, 64 * 1024, 128 * 1024, 256 * 1024, Infinity];

for (const b of BODIES) {
  for (const cap of CAPS) {
    const to = Math.min(b.bytes.length, cap === Infinity ? b.bytes.length : cap);
    if (cap !== Infinity && cap > b.bytes.length) continue;
    const iters = to > 512 * 1024 ? 5 : 20;
    const capName = cap === Infinity ? "uncapped(" + b.bytes.length + ")" : (cap / 1024) + "KB";
    rows.push(Object.assign({ body: b.name, cap: capName, scanned: to },
      bench("fused all (bigram12)", () => fusedScan(b.bytes, 0, to, 12, true, true), iters)));
  }
}

// incremental cost breakdown at the candidate cap
{
  const b = BODIES[0].bytes;
  const to = Math.min(b.length, 64 * 1024);
  rows.push(Object.assign({ body: "html", cap: "64KB", scanned: to },
    bench("fused struct+kw only", () => fusedScan(b, 0, to, 12, false, false), 50)));
  rows.push(Object.assign({ body: "html", cap: "64KB", scanned: to },
    bench("fused +tagHash", () => fusedScan(b, 0, to, 12, false, true), 50)));
  rows.push(Object.assign({ body: "html", cap: "64KB", scanned: to },
    bench("fused +bigram12", () => fusedScan(b, 0, to, 12, true, false), 50)));
  rows.push(Object.assign({ body: "html", cap: "64KB", scanned: to },
    bench("fused +bigram16", () => fusedScan(b, 0, to, 16, true, false), 50)));
  rows.push(Object.assign({ body: "html", cap: "64KB", scanned: to },
    bench("fused all (bigram12)", () => fusedScan(b, 0, to, 12, true, true), 50)));
  rows.push(Object.assign({ body: "html", cap: "64KB", scanned: to },
    bench("fused all (bigram16)", () => fusedScan(b, 0, to, 16, true, true), 50)));
}

// compare cost by histogram size
{
  const b = BODIES[0].bytes;
  const to = Math.min(b.length, 64 * 1024);
  const a12 = fusedScan(b, 0, to, 12, true, false).hist;
  const b12 = fusedScan(b, 1, to, 12, true, false).hist;
  const a16 = fusedScan(b, 0, to, 16, true, false).hist;
  const b16 = fusedScan(b, 1, to, 16, true, false).hist;
  rows.push(Object.assign({ body: "-", cap: "-", scanned: 0 },
    bench("cosine 4096", () => histCosine(a12, b12, 4096), 200)));
  rows.push(Object.assign({ body: "-", cap: "-", scanned: 0 },
    bench("cosine 65536", () => histCosine(a16, b16, 65536), 50)));
  print("similarity sanity: 4096-bucket cosine of near-identical bodies = " +
    histCosine(a12, b12, 4096).toFixed(6));
  print("similarity sanity: 65536-bucket cosine of near-identical bodies = " +
    histCosine(a16, b16, 65536).toFixed(6));
  // discrimination check: HTML vs minified JSON must score low
  const j12 = fusedScan(BODIES[2].bytes, 0, Math.min(BODIES[2].bytes.length, 64 * 1024), 12, true, false).hist;
  print("discrimination: html vs json 4096-bucket cosine = " + histCosine(a12, j12, 4096).toFixed(6));
}

print("");
print(["body", "cap", "scannedBytes", "impl", "iters", "perCallMs"].join("\t"));
for (const r of rows) {
  print([r.body, r.cap, r.scanned, r.label, r.iterations, r.perCallMs.toFixed(4)].join("\t"));
}
