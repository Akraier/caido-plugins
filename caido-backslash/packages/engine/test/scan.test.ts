import { describe, expect, it } from "vitest";

import {
  KEYWORDS,
  buildKeywordAutomaton,
  defaultKeywordAutomaton,
} from "../src/response/keywords.ts";
import {
  BIGRAM_BUCKETS,
  bigramCosine,
  findBodyStart,
  scanBody,
  scanWindows,
} from "../src/response/scan.ts";

function ascii(text: string): Uint8Array {
  const out = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) out[i] = text.charCodeAt(i) & 0xff;
  return out;
}

/** Scan a bare body with no header prefix. */
function scanText(text: string, capBytes = Number.POSITIVE_INFINITY) {
  const bytes = ascii(text);
  return scanBody(bytes, 0, bytes.length, { capBytes });
}

function keywordCount(scan: { keywords: Int32Array }, needle: string): number {
  const index = KEYWORDS.indexOf(needle);
  if (index === -1) throw new Error(`not a keyword: ${needle}`);
  return scan.keywords[index]!;
}

/**
 * Independent reference implementation: lowercase the whole string, then count ALL start
 * positions of each needle including overlapping ones. Aho-Corasick reports every match,
 * so a reference that advances by needle length would disagree on self-overlapping needles
 * such as '""' inside '"""'.
 */
function referenceKeywordCounts(text: string): number[] {
  const lower = text.toLowerCase();
  return KEYWORDS.map((needle) => {
    let count = 0;
    let from = 0;
    for (;;) {
      const at = lower.indexOf(needle, from);
      if (at === -1) return count;
      count++;
      from = at + 1;
    }
  });
}

const HTML_SAMPLE = [
  "<!DOCTYPE html>",
  '<html lang="en"><head><title>Catalogue</title>',
  '<script src="/a.js"></script></head><body>',
  '<div class="card" data-id="17"><h3>Widget 17</h3>',
  "<p>A description, with a comma and \"quotes\".</p>",
  "<span>12.99</span></div>",
  "<div>Warning: an ERROR occurred; invalid syntax</div>",
  "</body></html>",
].join("\n");

const JSON_SAMPLE =
  '{"ok":true,"count":3,"items":[{"id":1,"name":"a","tags":[],"meta":{}},' +
  '{"id":2,"name":"","tags":["x"],"meta":null},{"id":3,"name":"c","extra":false}]}';

describe("keyword automaton", () => {
  it("agrees with an independent reference implementation on HTML", () => {
    const scan = scanText(HTML_SAMPLE);
    expect(Array.from(scan.keywords)).toEqual(referenceKeywordCounts(HTML_SAMPLE));
  });

  it("agrees with an independent reference implementation on minified JSON", () => {
    const scan = scanText(JSON_SAMPLE);
    expect(Array.from(scan.keywords)).toEqual(referenceKeywordCounts(JSON_SAMPLE));
  });

  it("counts a needle that is a suffix of a longer needle", () => {
    // "syntax" is contained in "sql syntax". Failure-link output merging must report both,
    // otherwise the shorter needle is silently lost whenever the longer one matches.
    const scan = scanText("You have an error in your SQL syntax near line 1");
    expect(keywordCount(scan, "sql syntax")).toBe(1);
    expect(keywordCount(scan, "syntax")).toBe(1);
    expect(keywordCount(scan, "error")).toBe(1);
  });

  it("folds case", () => {
    const scan = scanText("ERROR Error error ErRoR");
    expect(keywordCount(scan, "error")).toBe(4);
  });

  it("counts overlapping occurrences of a self-overlapping needle", () => {
    // '""' occurs at offsets 0 and 1 of '"""'.
    const scan = scanText('{"a":"""}');
    expect(keywordCount(scan, '""')).toBe(2);
  });

  it("builds a total DFA so every state has 256 transitions", () => {
    const automaton = defaultKeywordAutomaton();
    expect(automaton.next.length).toBe(automaton.stateCount * 256);
    for (let i = 0; i < automaton.next.length; i++) {
      expect(automaton.next[i]).toBeGreaterThanOrEqual(0);
      expect(automaton.next[i]).toBeLessThan(automaton.stateCount);
    }
  });

  it("supports a custom pattern set", () => {
    const automaton = buildKeywordAutomaton(["ab", "b", "bc"]);
    const bytes = ascii("xabcx");
    const scan = scanBody(bytes, 0, bytes.length, { automaton });
    // "ab" at 1, "b" at 2, "bc" at 2
    expect(Array.from(scan.keywords)).toEqual([1, 1, 1]);
  });
});

describe("scanWindows", () => {
  it("returns a single window when the body fits", () => {
    expect(scanWindows(100, 1000)).toEqual([{ from: 0, to: 100 }]);
    expect(scanWindows(1000, 1000)).toEqual([{ from: 0, to: 1000 }]);
  });

  it("splits into non-overlapping head and tail when over cap", () => {
    const windows = scanWindows(10_000, 1000);
    expect(windows).toHaveLength(2);
    expect(windows[0]).toEqual({ from: 0, to: 500 });
    expect(windows[1]).toEqual({ from: 9500, to: 10_000 });
    expect(windows[0]!.to).toBeLessThanOrEqual(windows[1]!.from);
  });

  it("never overlaps even at the boundary case bodyLength = cap + 1", () => {
    const windows = scanWindows(1001, 1000);
    const total = windows.reduce((n, w) => n + (w.to - w.from), 0);
    expect(total).toBe(1000);
    expect(windows[0]!.to).toBeLessThanOrEqual(windows[1]!.from);
  });

  it("handles odd caps without losing or double counting a byte", () => {
    const windows = scanWindows(10_000, 999);
    const total = windows.reduce((n, w) => n + (w.to - w.from), 0);
    expect(total).toBe(999);
    expect(windows[0]!.to).toBeLessThanOrEqual(windows[1]!.from);
  });

  it("returns nothing for a non-positive cap", () => {
    expect(scanWindows(100, 0)).toEqual([]);
  });
});

describe("scanBody truncation behaviour", () => {
  const filler = "x".repeat(4096);

  it("reports the true body length even when truncated", () => {
    const body = filler + "MIDDLE" + filler;
    const scan = scanText(body, 1024);
    expect(scan.bodyLength).toBe(body.length);
    expect(scan.scannedBytes).toBe(1024);
    expect(scan.truncated).toBe(true);
  });

  it("sees a keyword in the tail, which a head-only cap would miss", () => {
    const body = filler + filler + "fatal error";
    const scan = scanText(body, 1024);
    expect(keywordCount(scan, "error")).toBe(1);
  });

  it("does not see a keyword that falls in the elided middle", () => {
    const body = filler + "error" + filler;
    const scan = scanText(body, 512);
    expect(scan.truncated).toBe(true);
    expect(keywordCount(scan, "error")).toBe(0);
  });

  it("does not manufacture a match spanning the elided middle", () => {
    // Head ends with "sql sy" and tail begins with "ntax". Concatenated they would spell
    // "sql syntax", which must not be counted: automaton state resets per window.
    const cap = 20;
    const head = "aaaaaaasql sy"; // 13 chars; head window is ceil(20/2) = 10
    const tail = "ntaxaaaaaa";
    const body = head + "M".repeat(500) + tail;
    const scan = scanText(body, cap);
    expect(scan.truncated).toBe(true);
    expect(keywordCount(scan, "sql syntax")).toBe(0);
    expect(keywordCount(scan, "syntax")).toBe(0);
  });

  it("is not truncated when exactly at the cap", () => {
    const scan = scanText("y".repeat(1024), 1024);
    expect(scan.truncated).toBe(false);
    expect(scan.scannedBytes).toBe(1024);
  });
});

describe("structural counters", () => {
  it("counts bytes it claims to count", () => {
    const scan = scanText('a\nb c<d>=e"f,g;h{i}');
    expect(scan.newlines).toBe(1);
    expect(scan.spaces).toBe(1);
    expect(scan.tags).toBe(1);
    expect(scan.equals).toBe(1);
    expect(scan.quotes).toBe(1);
    expect(scan.commas).toBe(1);
    expect(scan.semicolons).toBe(1);
    expect(scan.braces).toBe(2);
  });

  it("counts digits", () => {
    expect(scanText("a1b22c333").digits).toBe(6);
  });

  it("handles an empty body without throwing", () => {
    const scan = scanText("");
    expect(scan.bodyLength).toBe(0);
    expect(scan.scannedBytes).toBe(0);
    expect(scan.truncated).toBe(false);
    expect(scan.tagHash).toBe(0);
    expect(scan.tagNameCount).toBe(0);
  });
});

describe("tag sequence hash", () => {
  it("is zero when there is no markup", () => {
    expect(scanText(JSON_SAMPLE).tagHash).toBe(0);
    expect(scanText(JSON_SAMPLE).tagNameCount).toBe(0);
  });

  it("ignores text content and attribute values", () => {
    const a = scanText('<div class="x">hello</div>');
    const b = scanText('<div class="y">goodbye world</div>');
    expect(a.tagHash).toBe(b.tagHash);
  });

  it("changes when the tag sequence changes", () => {
    const a = scanText("<div><span></span></div>");
    const b = scanText("<div><p></p></div>");
    expect(a.tagHash).not.toBe(b.tagHash);
  });

  it("changes when a tag is added", () => {
    const a = scanText("<div></div>");
    const b = scanText("<div><br></div>");
    expect(a.tagHash).not.toBe(b.tagHash);
    expect(b.tagNameCount).toBe(a.tagNameCount + 1);
  });

  it("is an unsigned 32-bit value", () => {
    const scan = scanText(HTML_SAMPLE);
    expect(scan.tagHash).toBeGreaterThanOrEqual(0);
    expect(scan.tagHash).toBeLessThanOrEqual(0xffffffff);
    expect(Number.isInteger(scan.tagHash)).toBe(true);
  });
});

describe("bigram similarity", () => {
  it("scores identical bodies as 1", () => {
    const a = scanText(HTML_SAMPLE).bigrams;
    const b = scanText(HTML_SAMPLE).bigrams;
    expect(bigramCosine(a, b)).toBeCloseTo(1, 10);
  });

  it("scores structurally different bodies low", () => {
    const html = scanText(HTML_SAMPLE).bigrams;
    const json = scanText(JSON_SAMPLE).bigrams;
    expect(bigramCosine(html, json)).toBeLessThan(0.5);
  });

  it("scores a small edit high but below 1", () => {
    const a = scanText(HTML_SAMPLE).bigrams;
    const b = scanText(HTML_SAMPLE.replace("Widget", "Gadget")).bigrams;
    const score = bigramCosine(a, b);
    expect(score).toBeGreaterThan(0.9);
    expect(score).toBeLessThan(1);
  });

  it("treats two empty histograms as identical and empty-vs-nonempty as disjoint", () => {
    const empty = new Int32Array(BIGRAM_BUCKETS);
    const other = scanText(HTML_SAMPLE).bigrams;
    expect(bigramCosine(empty, new Int32Array(BIGRAM_BUCKETS))).toBe(1);
    expect(bigramCosine(empty, other)).toBe(0);
  });

  it("is symmetric", () => {
    const a = scanText(HTML_SAMPLE).bigrams;
    const b = scanText(JSON_SAMPLE).bigrams;
    expect(bigramCosine(a, b)).toBeCloseTo(bigramCosine(b, a), 12);
  });
});

describe("findBodyStart", () => {
  it("finds the body after CRLFCRLF", () => {
    const raw = ascii("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi");
    expect(findBodyStart(raw)).toBe(raw.length - 2);
  });

  it("finds the body after bare LFLF", () => {
    const raw = ascii("HTTP/1.1 200 OK\nX: 1\n\nhi");
    expect(findBodyStart(raw)).toBe(raw.length - 2);
  });

  it("returns the length when there is no terminator", () => {
    const raw = ascii("HTTP/1.1 200 OK\r\nX: 1\r\n");
    expect(findBodyStart(raw)).toBe(raw.length);
  });

  it("is not confused by a blank line inside the body", () => {
    const raw = ascii("HTTP/1.1 200 OK\r\n\r\nfirst\r\n\r\nsecond");
    expect(findBodyStart(raw)).toBe(19);
  });

  it("handles an empty input", () => {
    expect(findBodyStart(new Uint8Array(0))).toBe(0);
  });
});

describe("scanBody with a header prefix", () => {
  it("scans only the body region", () => {
    const raw = ascii("HTTP/1.1 200 OK\r\nX-Error: yes\r\n\r\nno keyword here");
    const bodyStart = findBodyStart(raw);
    const scan = scanBody(raw, bodyStart, raw.length);
    // "error" appears in the header, which is outside the scanned region.
    expect(keywordCount(scan, "error")).toBe(0);
    expect(scan.bodyLength).toBe("no keyword here".length);
  });
});
