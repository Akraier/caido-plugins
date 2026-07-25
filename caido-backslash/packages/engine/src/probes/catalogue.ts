/**
 * The probe catalogue, ported from PortSwigger's Backslash Powered Scanner.
 *
 * Payloads were extracted mechanically from the Java source and decoded from Java string
 * literals rather than transcribed by hand (see docs/analysis/extract_probes.py), because
 * these are dense backslash-escape sequences where a single transcription slip silently
 * changes what is being tested. Every literal below is the true character sequence.
 *
 * Defects corrected during the port are recorded in each pair's `notes` so the divergence
 * from the original is auditable rather than accidental.
 */

import type {
  ConcatParams,
  DelimiterParams,
  LanguageProbe,
  ProbePair,
  ProbeTemplate,
  ValueParams,
  WrapParams,
} from "./types.ts";

/** Inert filler used to equalise payload lengths. Chosen to be alphanumeric and boring. */
export const FILLER = "z";

// ---------------------------------------------------------------------------------------
// Stage: triage
// ---------------------------------------------------------------------------------------

/**
 * A single hostile string used to decide whether a parameter reacts to anything at all.
 * If the response is indistinguishable from baseline, the parameter is skipped entirely.
 * This is the request-economy gate: on most parameters it is the only probe ever sent.
 */
export const TRIAGE_FUZZ = "`z'z\"${{%{{\\";

/** Second triage string, sent only when the first is inconclusive. */
export const TRIAGE_FUZZ_ALT = "\\z`z'z\"${{%{{\\";

// ---------------------------------------------------------------------------------------
// Stage: delimiter identification
// ---------------------------------------------------------------------------------------

export const DELIMITER_PROBES: readonly ProbePair[] = [
  {
    id: "delim.backslash",
    name: "Backslash",
    stage: "delimiter",
    breaks: ["\\\\\\", "\\"],
    escapeSets: [["\\\\\\\\"], ["\\\\"]],
    mode: "append",
    parity: "impossible",
    delimiter: "\\",
    anchor: true,
    weight: 1,
    notes:
      "The canonical probe. An odd number of trailing backslashes leaves an escape " +
      "sequence unterminated; an even number does not. Lengths cannot be equalised " +
      "without changing the parity that carries the meaning, so length-derived features " +
      "must be neutralised by the decision rule instead.",
  },
  {
    id: "delim.apostrophe",
    name: "String delimiter: apostrophe",
    stage: "delimiter",
    breaks: ["z'z", "\\zz'z", "z/'z"],
    escapeSets: [
      ["z\\'z", "z''z"],
      ["z\\\\\\'z", "z\\''z"],
    ],
    mode: "append",
    parity: "pad-filler",
    delimiter: "'",
    anchor: true,
    weight: 3,
    notes:
      "Two interchangeable escape idioms per set: backslash-escaping and quote-doubling. " +
      "Which one works is itself diagnostic, so the engine must record the member used.",
  },
  {
    id: "delim.doublequote",
    name: "String delimiter: double quote",
    stage: "delimiter",
    breaks: ["\"", "\\zz\""],
    escapeSets: [["\\\""]],
    mode: "append",
    parity: "pad-filler",
    delimiter: '"',
    anchor: true,
    weight: 3,
  },
  {
    id: "delim.backtick",
    name: "String delimiter: backtick",
    stage: "delimiter",
    breaks: ["`", "\\z`"],
    escapeSets: [["\\`"]],
    mode: "append",
    parity: "pad-filler",
    delimiter: "`",
    anchor: true,
    weight: 2,
  },
];

/**
 * Fallbacks tried only when no single delimiter is identified. These mix a quote with a
 * slash to catch contexts where the quote alone is filtered but the pair still confuses a
 * parser.
 */
export const DELIMITER_FALLBACK_PROBES: readonly ProbePair[] = [
  {
    id: "delim.doublequote-slash",
    name: "Double quote plus slash",
    stage: "delimiter",
    breaks: ['"z\\', 'z"z\\'],
    escapeSets: [['"a\\zz'], ["z\\z"], ['z"z/']],
    mode: "append",
    parity: "pad-filler",
    anchor: true,
    weight: 4,
  },
  {
    id: "delim.singlequote-slash",
    name: "Single quote plus slash",
    stage: "delimiter",
    breaks: ["'z\\", "z'z\\"],
    escapeSets: [["'a\\zz"], ["z\\z"], ["z'z/"]],
    mode: "append",
    parity: "pad-filler",
    anchor: true,
    weight: 4,
  },
];

// ---------------------------------------------------------------------------------------
// Stage: escape sequences and regex metacharacters
// Only reached when the backslash probe fired, since all of these presuppose that a
// backslash is meaningful.
// ---------------------------------------------------------------------------------------

export const ESCAPE_SEQUENCE_PROBES: readonly ProbePair[] = [
  {
    id: "escape.unicode",
    name: "Escape sequence: unicode",
    stage: "escape-sequence",
    breaks: ["\\g0041", "\\z0041"],
    escapeSets: [["\\u0041"], ["\\u0042"]],
    mode: "append",
    parity: "equal",
    anchor: true,
    weight: 3,
    notes: "All members are six characters, so this family is length-clean as written.",
  },
  {
    id: "escape.regex",
    name: "Escape sequence: regex",
    stage: "escape-sequence",
    breaks: ["\\g0041", "\\z0041"],
    escapeSets: [["\\s0041"], ["\\n0041"]],
    mode: "append",
    parity: "equal",
    anchor: true,
    weight: 4,
  },
  {
    id: "escape.regex-breakout-at",
    name: "Regex breakout: @",
    stage: "escape-sequence",
    breaks: ["z@", "\\@z@"],
    escapeSets: [["z\\@"], ["\\@z\\@"]],
    mode: "append",
    parity: "pad-filler",
    anchor: true,
    weight: 5,
  },
  {
    id: "escape.regex-breakout-slash",
    name: "Regex breakout: /",
    stage: "escape-sequence",
    breaks: ["z/", "\\/z/"],
    escapeSets: [["z\\/"], ["\\/z\\/"]],
    mode: "append",
    parity: "pad-filler",
    anchor: true,
    weight: 5,
  },
];

// ---------------------------------------------------------------------------------------
// Stage: interpolation
// ---------------------------------------------------------------------------------------

export const INTERPOLATION_TRIAGE: ProbePair = {
  id: "interp.fuzz",
  name: "Interpolation fuzz",
  stage: "interpolation",
  breaks: ["%{{z${{z", "z%{{zz${{z"],
  escapeSets: [["%}}$}}"], ["}}%z}}$z"], ["z%}}zz$}}z"]],
  mode: "append",
  parity: "pad-filler",
  anchor: true,
  weight: 2,
  notes:
    "Prone to false positives from web application firewalls that rewrite brace sequences. " +
    "Gate this family behind explicit opt-in and require the follow-up probes to agree.",
};

export const INTERPOLATION_PROBES: readonly ProbePair[] = [
  {
    id: "interp.curly",
    name: "Interpolation: curly",
    stage: "interpolation",
    breaks: ["{{z", "z{{z"],
    escapeSets: [["z}}z"], ["}}z"], ["z}}"]],
    mode: "append",
    parity: "pad-filler",
    anchor: true,
    weight: 5,
  },
  {
    id: "interp.dollar",
    name: "Interpolation: dollar",
    stage: "interpolation",
    breaks: ["${{z", "z${{z"],
    escapeSets: [["$}}"], ["}}$z"], ["z$}}z"]],
    mode: "append",
    parity: "pad-filler",
    anchor: true,
    weight: 5,
  },
  {
    id: "interp.percent",
    name: "Interpolation: percent",
    stage: "interpolation",
    breaks: ["%{{41", "41%{{41"],
    escapeSets: [["%}}"], ["}}%41"], ["41%}}41"]],
    mode: "append",
    parity: "pad-filler",
    anchor: true,
    weight: 5,
  },
];

/** Interpolation wrappers, tried in this order once the matching probe above fires. */
export const INTERPOLATION_WRAPPERS: Readonly<Record<string, WrapParams>> = {
  "interp.curly": { prefix: "{{", suffix: "}}" },
  "interp.dollar": { prefix: "${", suffix: "}" },
  "interp.percent": { prefix: "%{", suffix: "}" },
};

// ---------------------------------------------------------------------------------------
// Stage: concatenation (templated on the discovered delimiter)
// ---------------------------------------------------------------------------------------

/** Operators tried as string concatenators, cheapest and most common first. */
export const CONCATENATORS: readonly string[] = ["||", "+", " ", ".", "&", ","];

export const CONCATENATION_TEMPLATE: ProbeTemplate<ConcatParams> = {
  id: "concat",
  name: "Concatenation",
  stage: "concatenation",
  build: ({ delimiter: d, concat: c }): ProbePair => ({
    id: `concat.${encodeURIComponent(d)}${encodeURIComponent(c)}`,
    name: `Concatenation: ${d}${c}`,
    stage: "concatenation",
    breaks: [`z${c}${d}z(z${d}z`],
    escapeSets: [[`z(z${d}${c}${d}z`], [`zx${d}${c}${d}zy`]],
    mode: "append",
    parity: "pad-filler",
    delimiter: d,
    anchor: true,
    weight: 7,
    notes:
      "The break carries one filler character more than either escape (9 versus 8 bytes " +
      "for a single-character delimiter and a two-character operator), so the escape is " +
      "padded at runtime. Verified by test rather than assumed: the same claim was " +
      "asserted here as already-equal and was false.",
  }),
};

export const JSON_VALUE_TEMPLATE: ProbeTemplate<DelimiterParams> = {
  id: "json.value",
  name: "JSON injection (value)",
  stage: "structural",
  build: ({ delimiter: d }): ProbePair => ({
    id: `json.value.${encodeURIComponent(d)}`,
    name: "JSON injection (value)",
    stage: "structural",
    breaks: [
      `z${d},${d}z${d}z${d}z`,
      `z${d},${d}z${d};${d}z`,
      `z${d},${d}z${d}.${d}z`,
    ],
    escapeSets: [[`z${d},${d}z${d}:${d}z`]],
    mode: "append",
    parity: "equal",
    delimiter: d,
    anchor: true,
    weight: 6,
  }),
};

export const JSON_KEY_TEMPLATE: ProbeTemplate<DelimiterParams> = {
  id: "json.key",
  name: "JSON injection (key)",
  stage: "structural",
  build: ({ delimiter: d }): ProbePair => ({
    id: `json.key.${encodeURIComponent(d)}`,
    name: "JSON injection (key)",
    stage: "structural",
    breaks: [
      `z${d}:${d}z${d}z${d}`,
      `z${d}:${d}z${d}:${d}`,
      `z${d}:${d}z${d}.${d}`,
    ],
    escapeSets: [[`z${d}:${d}z${d},${d}`]],
    mode: "append",
    parity: "equal",
    delimiter: d,
    anchor: true,
    weight: 6,
  }),
};

/**
 * MongoDB detection via $where. Only meaningful after a JSON injection probe fired, because
 * it needs to know whether it is injecting into a value or a key position.
 */
export const MONGO_TEMPLATE: ProbeTemplate<WrapParams> = {
  id: "mongo.where",
  name: "MongoDB injection",
  stage: "structural",
  build: ({ prefix, suffix }): ProbePair => ({
    id: "mongo.where",
    name: "MongoDB injection",
    stage: "structural",
    breaks: [`${prefix}0z41${suffix}`, `${prefix}0v41${suffix}`],
    escapeSets: [[`${prefix}0x41${suffix}`], [`${prefix}0x42${suffix}`]],
    mode: "append",
    parity: "equal",
    anchor: true,
    weight: 9,
  }),
};

// ---------------------------------------------------------------------------------------
// Stage: function evaluation, per language
// ---------------------------------------------------------------------------------------

/**
 * Language probes, ordered so the cheap generic gate comes FIRST.
 *
 * In the original this ordering was wrong: the "Basic function injection" entry that aborts
 * the whole cascade when no function call evaluates sat at index 5, so Ruby, Python,
 * JavaScript and shell were each fully probed before the gate could fire. Moving it to the
 * front makes the abort actually cheap.
 */
export const LANGUAGE_PROBES: readonly LanguageProbe[] = [
  {
    id: "fn.basic",
    language: "Basic function evaluation",
    valid: "abs(1)",
    invalid: ["abz(1)", "abf(1)"],
    padNumeric: false,
  },
  {
    id: "fn.ruby",
    language: "Ruby",
    valid: "1.to_s",
    invalid: ["1.to_z", "1.tz_s"],
    padNumeric: false,
    requiresAnchor: true,
  },
  {
    id: "fn.ruby-abs",
    language: "Ruby",
    valid: "1.abs",
    invalid: ["1.abz", "1.abf"],
    padNumeric: false,
  },
  {
    id: "fn.javascript",
    language: "JavaScript",
    valid: "isFinite(1)",
    invalid: ["isFinitd(1)", "isFinitee(1)"],
    padNumeric: true,
  },
  {
    id: "fn.shell",
    language: "Shell",
    valid: "$((10/10))",
    invalid: ["$((10/00))", "$((1/0))"],
    padNumeric: true,
  },
  {
    id: "fn.python",
    language: "Python",
    valid: "unichr(49)",
    invalid: ["unichrr(49)", "unichn(97)"],
    padNumeric: true,
    requiresAnchor: true,
  },
  {
    id: "fn.python-int",
    language: "Python",
    valid: "int(unichr(49))",
    invalid: ["int(unichrr(49))", "int(unichz(49))"],
    padNumeric: true,
  },
  {
    id: "fn.mysql",
    language: "MySQL",
    valid: "power(unix_timestamp(),0)",
    invalid: ["power(unix_timestampp(),0)", "power(unix_timestanp(),0)"],
    padNumeric: true,
  },
  {
    id: "fn.oracle",
    language: "Oracle SQL",
    valid: "to_number(1)",
    invalid: ["to_numberr(1)", "to_numbez(1)"],
    padNumeric: true,
  },
  {
    id: "fn.mssql",
    language: "SQL Server",
    valid: "power(current_request_id(),0)",
    invalid: ["power(current_request_ids(),0)", "power(current_request_ic(),0)"],
    padNumeric: true,
  },
  {
    id: "fn.postgres",
    language: "PostgreSQL",
    valid: "power(inet_server_port(),0)",
    invalid: ["power(inet_server_por(),0)", "power(inet_server_pont(),0)"],
    padNumeric: true,
  },
  {
    id: "fn.sqlite",
    language: "SQLite",
    valid: "min(sqlite_version(),1)",
    invalid: ["min(sqlite_versionn(),1)", "min(sqlite_versipn(),1)"],
    padNumeric: true,
  },
  {
    id: "fn.php",
    language: "PHP",
    valid: "pow((int)phpversion(),0)",
    invalid: ["pow((int)phpversionn(),0)", "pow((int)phpversiom(),0)"],
    padNumeric: true,
  },
  {
    id: "fn.perl",
    language: "Perl",
    valid: "(getppid()**0)",
    invalid: ["(getppidd()**0)", "(getppif()**0)"],
    padNumeric: true,
  },
];

// ---------------------------------------------------------------------------------------
// Stage: arithmetic, for parameters whose value is numeric
// ---------------------------------------------------------------------------------------

export const ARITHMETIC_PROBES: readonly ProbePair[] = [
  {
    id: "arith.divide-zero",
    name: "Divide by zero",
    stage: "arithmetic",
    breaks: ["/0", "/00", "/000"],
    escapeSets: [["/1"], ["-0"], ["/01"], ["-00"]],
    mode: "append",
    parity: "pad-numeric",
    anchor: false,
    weight: 4,
    notes:
      "Breaks and escapes must be paired by length: /0 with /1, /00 with /01 or -00. " +
      "The original rotated independent counters over both lists, so it could compare a " +
      "two-character break against a three-character escape and attribute the resulting " +
      "length difference to the division.",
  },
  {
    id: "arith.divide-expression",
    name: "Divide by expression",
    stage: "arithmetic",
    breaks: ["/(2-2)", "/(3-3)"],
    escapeSets: [["/(2-1)"], ["/(1*1)"]],
    mode: "append",
    parity: "equal",
    anchor: false,
    weight: 5,
    notes: "All members are six characters. Length-clean as written.",
  },
];

// ---------------------------------------------------------------------------------------
// Stage: SQL ORDER BY
// ---------------------------------------------------------------------------------------

export const ORDER_BY_PROBES: readonly ProbePair[] = [
  {
    id: "orderby.comment",
    name: "Comment injection",
    stage: "order-by",
    breaks: ["/'z*/**/", "/*/*/z'*/", "/*z'/"],
    escapeSets: [["/*'z*/"], ["/**z'*/"], ["/*//z'//*/"]],
    mode: "append",
    parity: "pad-filler",
    anchor: false,
    weight: 3,
  },
  {
    id: "orderby.html-tag-strip",
    name: "HTML tag stripping (firewall fingerprint)",
    stage: "order-by",
    breaks: [">zz<", "z>z<z", "z>><z"],
    escapeSets: [["<zz>"], ["<-zz->"], ["<xyz>"]],
    mode: "append",
    parity: "pad-filler",
    anchor: false,
    weight: 4,
    notes:
      "This pair exists to CLASSIFY a firewall rewriting tags, not to report a finding. " +
      "When it fires alongside comment injection, the comment result is a firewall " +
      "artefact and must be suppressed rather than reported.",
  },
  {
    id: "orderby.html-comment",
    name: "HTML comment injection (firewall fingerprint)",
    stage: "order-by",
    breaks: ["<!-zz-->", "<--zz-->", "<!--zz->"],
    escapeSets: [["<!--zz-->"], ["<!--z-z-->"], ["<!-->z<-->"]],
    mode: "append",
    parity: "pad-filler",
    anchor: false,
    weight: 4,
  },
  {
    id: "orderby.mysql-procedure",
    name: "MySQL order-by",
    stage: "order-by",
    breaks: [" procedure analyse (0,0,0)-- -", " procedure analyze (0,0)-- -"],
    escapeSets: [[" procedure analyse (0,0)-- -"], [" procedure analyse (0,0)-- -z"]],
    mode: "append",
    parity: "pad-filler",
    anchor: false,
    weight: 7,
  },
  {
    id: "orderby.function",
    name: "Order-by function injection",
    stage: "order-by",
    breaks: [",abz(1)", ",abs(0,1)", ",abs()", "abs(z)"],
    escapeSets: [[",ABS(1)"], [",abs(1)"], [",abs(01)"]],
    mode: "append",
    parity: "pad-numeric",
    anchor: false,
    weight: 5,
  },
];

// ---------------------------------------------------------------------------------------
// Stage: path handling
// ---------------------------------------------------------------------------------------

export const PATH_PROBES: readonly ProbePair[] = [
  {
    id: "path.dotslash",
    name: "File path manipulation",
    stage: "path",
    breaks: ["../", "z/", "_/", "./../"],
    escapeSets: [["./"], ["././"], ["./././"]],
    mode: "prepend",
    parity: "pad-filler",
    anchor: false,
    weight: 3,
  },
  {
    id: "path.dotslash-normalised",
    name: "File path manipulation (normalised)",
    stage: "path",
    breaks: ["../", "z/", "_/", "./../"],
    escapeSets: [["./cow/../"], ["./foo/bar/../../"], ["./z/../"]],
    mode: "prepend",
    parity: "impossible",
    anchor: false,
    weight: 4,
    notes:
      "Worst length skew in the catalogue: breaks are 2 to 5 characters, escapes 7 to 16. " +
      "On a reflected parameter this pair cannot be trusted without length neutralisation.",
  },
  {
    id: "path.proxy-semicolon",
    name: "Proxy subfolder escape",
    stage: "path",
    breaks: ["..;/", "..;foo/", "..;bar/"],
    escapeSets: [["../"], [".;/"], ["..:/"], ["..:bar/"], ["..#/"]],
    mode: "replace",
    parity: "pad-filler",
    anchor: false,
    weight: 4,
  },
];

export const NGINX_ALIAS_TEMPLATE: ProbeTemplate<ValueParams> = {
  id: "path.nginx-alias",
  name: "Possible nginx alias escape",
  stage: "path",
  build: ({ baseValue }): ProbePair => {
    // The original derived two "different" escapes by mutating the first and last character
    // of the value. For a value of length 1 both mutations produce the same string, so the
    // pair silently degenerated to a single escape. Fall back to explicit distinct escapes.
    const head = baseValue.length > 1 ? FILLER + baseValue.slice(1) : FILLER + baseValue;
    const tail =
      baseValue.length > 1 ? baseValue.slice(0, -1) + FILLER : baseValue + FILLER;
    const escapes =
      head === tail
        ? [[`${head}..`], [`${baseValue}/../${FILLER}${FILLER}${FILLER}`]]
        : [[`${head}..`], [`${tail}..`], [`${baseValue}/../xyz`]];
    return {
      id: "path.nginx-alias",
      name: "Possible nginx alias escape",
      stage: "path",
      breaks: [`${baseValue}..`, `${baseValue}../.`],
      escapeSets: escapes,
      mode: "replace",
      parity: "pad-filler",
      anchor: false,
      weight: 4,
      notes:
        "Escapes are derived from the parameter value; for single-character values the " +
        "original produced two identical escapes.",
    };
  },
};

// ---------------------------------------------------------------------------------------
// Stage: magic values
// ---------------------------------------------------------------------------------------

export const MAGIC_VALUES: readonly string[] = [
  "undefined",
  "null",
  "empty",
  "none",
  "COM1",
  "c!C123449477",
  "aA1537368460!",
];

/**
 * Build the corrupted counterparts of a magic value.
 *
 * The original wrote a filler at index `i % value.length` for i in 0..3, which produced
 * duplicate corruptions for values shorter than four characters and divided by zero for an
 * empty value. Since the magic list is user-editable and its own setting description invites
 * additions, an empty entry from a trailing comma crashed the scan.
 */
export function corruptMagicValue(value: string): string[] {
  if (value.length === 0) return [];
  const seen = new Set<string>();
  for (let i = 0; i < Math.min(4, value.length); i++) {
    seen.add(value.slice(0, i) + FILLER + value.slice(i + 1));
  }
  // A real word, to filter contexts where the magic value is a plausible user input such as
  // a username or hostname rather than a sentinel.
  seen.add("help");
  return [...seen];
}

// ---------------------------------------------------------------------------------------
// Transformation scan payloads
// ---------------------------------------------------------------------------------------

/** Escape forms whose decoded result reveals the interpreter, e.g. \x41 becoming A. */
export const TRANSFORM_DECODE_PAYLOADS: readonly string[] = [
  "101",
  "x41",
  "u0041",
  "0",
  "1",
  "x0",
];

/**
 * Metacharacters probed for suspicious transformation.
 *
 * The original list contained ";" twice, costing one wasted probe round per parameter.
 * Deduplicated here.
 */
export const TRANSFORM_METACHARACTERS: readonly string[] = [
  "'",
  '"',
  "{",
  "}",
  "(",
  ")",
  "[",
  "]",
  "$",
  "`",
  "/",
  "@",
  "#",
  ";",
  "%",
  "&",
  "|",
  "^",
  "?",
];

// ---------------------------------------------------------------------------------------
// Invariants
// ---------------------------------------------------------------------------------------

/** Every static pair in the catalogue, for iteration and validation. */
export const ALL_STATIC_PROBES: readonly ProbePair[] = [
  ...DELIMITER_PROBES,
  ...DELIMITER_FALLBACK_PROBES,
  ...ESCAPE_SEQUENCE_PROBES,
  INTERPOLATION_TRIAGE,
  ...INTERPOLATION_PROBES,
  ...ARITHMETIC_PROBES,
  ...ORDER_BY_PROBES,
  ...PATH_PROBES,
];
