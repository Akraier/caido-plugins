/**
 * Multi-pattern keyword matching for response fingerprinting.
 *
 * The keyword counts are one component of the response feature vector. They exist because
 * purely structural features (byte counts, length) are nearly blind on low-entropy bodies
 * such as minified single-line JSON, while an interpreter error almost always introduces
 * one of a small set of tell-tale tokens.
 *
 * Implementation note: this is an Aho-Corasick DFA rather than N independent substring
 * searches. Measured under QuickJS-ng 0.15.1 (the closest available proxy for Caido's
 * rquickjs backend), scanning 512 KB with 20 needles cost 27.8 ms via the automaton versus
 * 43.9 ms for a decode-lowercase-then-20x-indexOf approach, and the automaton avoids
 * allocating a full lowercased copy of the body. See bench/attrbench.js.
 */

/**
 * Needles are matched case-insensitively against ASCII-folded bytes, so every pattern here
 * MUST be lowercase or it can never match.
 *
 * Chosen to cover: generic error vocabulary, interpreter/database specific error vocabulary,
 * arithmetic faults (the divide-by-zero probe family depends on these), and a few cheap
 * structural markers that survive on minified JSON where byte counters carry little signal.
 */
export const KEYWORDS: readonly string[] = [
  // generic error vocabulary
  "error",
  "exception",
  "invalid",
  "warning",
  "unexpected",
  "syntax",
  "stack",
  "traceback",
  // database / interpreter specific
  "sql syntax",
  "ora-",
  "odbc",
  "sqlstate",
  "psql",
  "sqlite",
  // arithmetic faults, needed by the divide-by-zero and arithmetic probe families
  "divisor",
  "divide",
  "division",
  "infinity",
  "nan",
  // structural markers: the only real signal on low-entropy bodies
  '","',
  '""',
  "[]",
  "{}",
  "null",
  "true",
  "false",
  "</html>",
  "<script",
  "<div",
] as const;

if (KEYWORDS.some((k) => k !== k.toLowerCase())) {
  throw new Error("KEYWORDS must be lowercase: matching folds input bytes to lowercase");
}

export const KEYWORD_COUNT = KEYWORDS.length;

/**
 * A flattened Aho-Corasick automaton over 8-bit symbols.
 *
 * `next` is a dense (states * 256) transition table already closed over failure links, so
 * stepping is a single array index with no failure-following loop at scan time.
 * `outIndex[state]` is -1 when the state emits nothing, else an index into `outLists`.
 */
export interface KeywordAutomaton {
  readonly next: Int32Array;
  readonly outIndex: Int32Array;
  readonly outLists: readonly Int32Array[];
  readonly stateCount: number;
  readonly patternCount: number;
}

export function buildKeywordAutomaton(
  patterns: readonly string[] = KEYWORDS,
): KeywordAutomaton {
  // Build the trie with sparse rows first; densify at the end.
  const rows: Int32Array[] = [newRow()];
  const fail: number[] = [0];
  const out: (number[] | null)[] = [null];

  for (let p = 0; p < patterns.length; p++) {
    const pattern = patterns[p]!;
    let state = 0;
    for (let i = 0; i < pattern.length; i++) {
      const c = pattern.charCodeAt(i) & 0xff;
      if (rows[state]![c] === -1) {
        rows.push(newRow());
        fail.push(0);
        out.push(null);
        rows[state]![c] = rows.length - 1;
      }
      state = rows[state]![c]!;
    }
    (out[state] ??= []).push(p);
  }

  // BFS: set failure links and convert the goto function into a total DFA.
  const queue: number[] = [];
  for (let c = 0; c < 256; c++) {
    const target = rows[0]![c]!;
    if (target === -1) {
      rows[0]![c] = 0;
    } else {
      fail[target] = 0;
      queue.push(target);
    }
  }

  for (let head = 0; head < queue.length; head++) {
    const state = queue[head]!;
    // A state must also emit everything its failure state emits, otherwise a needle that
    // ends inside a longer needle is missed.
    const inherited = out[fail[state]!];
    if (inherited !== null && inherited !== undefined) {
      const own = (out[state] ??= []);
      for (const p of inherited) {
        if (!own.includes(p)) own.push(p);
      }
    }
    for (let c = 0; c < 256; c++) {
      const target = rows[state]![c]!;
      if (target === -1) {
        rows[state]![c] = rows[fail[state]!]![c]!;
      } else {
        fail[target] = rows[fail[state]!]![c]!;
        queue.push(target);
      }
    }
  }

  const stateCount = rows.length;
  const next = new Int32Array(stateCount * 256);
  for (let s = 0; s < stateCount; s++) next.set(rows[s]!, s * 256);

  const outIndex = new Int32Array(stateCount).fill(-1);
  const outLists: Int32Array[] = [];
  for (let s = 0; s < stateCount; s++) {
    const emitted = out[s];
    if (emitted !== null && emitted !== undefined && emitted.length > 0) {
      outIndex[s] = outLists.length;
      outLists.push(Int32Array.from(emitted));
    }
  }

  return {
    next,
    outIndex,
    outLists,
    stateCount,
    patternCount: patterns.length,
  };
}

function newRow(): Int32Array {
  return new Int32Array(256).fill(-1);
}

/**
 * Which patterns occur at least once in `bytes[from..to)`, as pattern indices.
 *
 * Used for presence tests (firewall and bot-challenge fingerprints) where counts are
 * irrelevant, so it can stop tracking a pattern once seen. Case-folds ASCII, matching the
 * convention that all patterns are lowercase.
 */
export function matchPatterns(
  bytes: Uint8Array,
  from: number,
  to: number,
  automaton: KeywordAutomaton,
): Set<number> {
  const found = new Set<number>();
  const { next, outIndex, outLists } = automaton;
  let state = 0;
  const end = Math.min(to, bytes.length);
  for (let i = Math.max(0, from); i < end; i++) {
    const raw = bytes[i]!;
    const folded = raw >= 0x41 && raw <= 0x5a ? raw + 32 : raw;
    state = next[(state << 8) | folded]!;
    const emit = outIndex[state]!;
    if (emit !== -1) {
      const hits = outLists[emit]!;
      for (let h = 0; h < hits.length; h++) found.add(hits[h]!);
      if (found.size === automaton.patternCount) return found;
    }
  }
  return found;
}

let defaultAutomaton: KeywordAutomaton | undefined;

/**
 * The automaton for {@link KEYWORDS}, built once per runtime. Building is ~100 states and
 * is not on the hot path, but there is no reason to repeat it per response.
 */
export function defaultKeywordAutomaton(): KeywordAutomaton {
  return (defaultAutomaton ??= buildKeywordAutomaton(KEYWORDS));
}
