import { type ReflectionContext, classifyHit, isJsonContentType } from "./classify";

export type TestChar =
  | "LT"
  | "GT"
  | "DQ"
  | "SQ"
  | "BT"
  | "BS"
  | "SL"
  | "CO"
  | "PA"
  | "PB"
  | "CB"
  | "CC"
  | "DL"
  | "SC"
  | "AM";

export type CharStatus =
  | "raw"
  | "html_entity"
  | "url_encode"
  | "js_escape"
  | "unicode_escape"
  | "stripped"
  | "unknown";

export type State = "NO_REFLECTION" | "REFLECTED" | "ATTEMPT" | "CONFIRMED";

export const CHAR_LITERAL: Record<TestChar, string> = {
  LT: "<",
  GT: ">",
  DQ: '"',
  SQ: "'",
  BT: "`",
  BS: "\\",
  SL: "/",
  CO: ":",
  PA: "(",
  PB: ")",
  CB: "{",
  CC: "}",
  DL: "$",
  SC: ";",
  AM: "&",
};

const HTML_ENTITIES: Record<string, string[]> = {
  "<": ["&lt;", "&LT;", "&#60;", "&#x3c;", "&#x3C;"],
  ">": ["&gt;", "&GT;", "&#62;", "&#x3e;", "&#x3E;"],
  '"': ["&quot;", "&QUOT;", "&#34;", "&#x22;"],
  "'": ["&#39;", "&apos;", "&#x27;"],
  "&": ["&amp;", "&AMP;", "&#38;", "&#x26;"],
  "/": ["&#47;", "&#x2f;", "&sol;"],
  "\\": ["&#92;", "&#x5c;"],
  "`": ["&#96;", "&#x60;"],
  ":": ["&#58;", "&#x3a;", "&colon;"],
  "(": ["&#40;", "&#x28;", "&lpar;"],
  ")": ["&#41;", "&#x29;", "&rpar;"],
  "{": ["&#123;", "&#x7b;"],
  "}": ["&#125;", "&#x7d;"],
  $: ["&#36;", "&#x24;", "&dollar;"],
  ";": ["&#59;", "&#x3b;"],
};

export type CanaryMarkers = Record<TestChar, { left: string; right: string }>;
export type CanaryBundle = {
  value: string;
  markers: CanaryMarkers;
  salt: string;
  head: string;
};

function randomSalt(): string {
  const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
  let s = "";
  for (let i = 0; i < 6; i++) s += alphabet[Math.floor(Math.random() * alphabet.length)];
  return s;
}

export function buildCanary(salt: string = randomSalt()): CanaryBundle {
  const head = `cAiDo${salt}`;
  const tail = `${salt}cAiDo`;
  const markers = {} as CanaryMarkers;
  const parts: string[] = [head];
  for (const tc of Object.keys(CHAR_LITERAL) as TestChar[]) {
    const left = `X${tc}Z`;
    const right = `ZY${tc}`;
    markers[tc] = { left, right };
    parts.push(left + CHAR_LITERAL[tc] + right);
  }
  parts.push(tail);
  return { value: parts.join(""), markers, salt, head };
}

function urlEncode(c: string): string {
  return "%" + c.charCodeAt(0).toString(16).toUpperCase().padStart(2, "0");
}

function unicodeEscape(c: string): string {
  return "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0");
}

function hexEscape(c: string): string {
  return "\\x" + c.charCodeAt(0).toString(16).padStart(2, "0");
}

export function analyseSurvival(body: string, markers: CanaryMarkers): Record<TestChar, CharStatus> {
  const out = {} as Record<TestChar, CharStatus>;
  const lowerBody = body.toLowerCase();
  for (const tc of Object.keys(markers) as TestChar[]) {
    const { left, right } = markers[tc];
    const ch = CHAR_LITERAL[tc];

    if (body.includes(left + ch + right)) {
      out[tc] = "raw";
      continue;
    }
    let matched: CharStatus | null = null;
    for (const ent of HTML_ENTITIES[ch] ?? []) {
      if (body.includes(left + ent + right) || lowerBody.includes((left + ent + right).toLowerCase())) {
        matched = "html_entity";
        break;
      }
    }
    if (matched) {
      out[tc] = matched;
      continue;
    }
    if (body.includes(left + urlEncode(ch) + right) || lowerBody.includes((left + urlEncode(ch) + right).toLowerCase())) {
      out[tc] = "url_encode";
      continue;
    }
    if (body.includes(left + "\\" + ch + right)) {
      out[tc] = "js_escape";
      continue;
    }
    if (body.includes(left + unicodeEscape(ch) + right) || body.includes(left + hexEscape(ch) + right)) {
      out[tc] = "unicode_escape";
      continue;
    }
    if (body.includes(left + right)) {
      out[tc] = "stripped";
      continue;
    }
    out[tc] = "unknown";
  }
  return out;
}

export function canaryReflected(body: string, canary: CanaryBundle): boolean {
  return body.includes(canary.head);
}

export function findCanaryIndex(body: string, canary: CanaryBundle): number {
  return body.indexOf(canary.head);
}

export function detectContext(
  probeBody: string,
  canary: CanaryBundle,
  responseContentType: string,
): { context: ReflectionContext; index: number } {
  const idx = findCanaryIndex(probeBody, canary);
  if (isJsonContentType(responseContentType)) {
    return { context: "JSON_BODY", index: idx };
  }
  return { context: classifyHit(probeBody, idx), index: idx };
}

const BREAKOUT_REQUIREMENTS: Record<ReflectionContext, TestChar[][]> = {
  HTML_BODY: [["LT", "GT"]],
  HTML_ATTR_DQ: [["DQ"]],
  HTML_ATTR_SQ: [["SQ"]],
  HTML_ATTR_UNQ: [["GT"], ["SC"]],
  URL_ATTR_DQ: [["CO"]],
  URL_ATTR_SQ: [["CO"]],
  JS_STRING_DQ: [["DQ"], ["LT", "SL"]],
  JS_STRING_SQ: [["SQ"], ["LT", "SL"]],
  JS_TEMPLATE: [["BT"], ["DL", "CB"]],
  JS_CODE: [["SC"], ["PA"]],
  HTML_COMMENT: [["LT", "GT"]],
  CSS_BLOCK: [["LT"], ["CC"]],
  JSON_BODY: [],
};

export function rawSet(survival: Record<TestChar, CharStatus>): Set<TestChar> {
  const s = new Set<TestChar>();
  for (const tc of Object.keys(survival) as TestChar[]) {
    if (survival[tc] === "raw") s.add(tc);
  }
  return s;
}

export type StateEvaluation = {
  state: State;
  breakoutSet: TestChar[] | null;
  rationale: string;
};

export function evaluateState(
  context: ReflectionContext,
  survival: Record<TestChar, CharStatus>,
): StateEvaluation {
  const raw = rawSet(survival);

  if (raw.size === 0) {
    return {
      state: "REFLECTED",
      breakoutSet: null,
      rationale: "Canary reflected but every special character is filtered or stripped.",
    };
  }

  const reqs = BREAKOUT_REQUIREMENTS[context];
  for (const set of reqs) {
    if (set.every((tc) => raw.has(tc))) {
      const chars = set.map((tc) => CHAR_LITERAL[tc]).join(" + ");
      return {
        state: "CONFIRMED",
        breakoutSet: set,
        rationale: `Context ${context} broken: ${chars} survive raw — context-relevant break-out possible.`,
      };
    }
  }

  return {
    state: "ATTEMPT",
    breakoutSet: null,
    rationale: `Some special characters survive raw, but none of them satisfy ${context} break-out requirements.`,
  };
}

export function suggestedPayload(context: ReflectionContext, breakoutSet: TestChar[] | null): string | null {
  if (!breakoutSet) return null;
  const setKey = breakoutSet.slice().sort().join(",");
  switch (context) {
    case "HTML_BODY":
      return "<svg/onload=alert(1)>";
    case "HTML_ATTR_DQ":
      return '" onmouseover="alert(1)" x="';
    case "HTML_ATTR_SQ":
      return "' onmouseover='alert(1)' x='";
    case "HTML_ATTR_UNQ":
      return setKey === "GT" ? " onmouseover=alert(1) x=" : "; onmouseover=alert(1);";
    case "URL_ATTR_DQ":
    case "URL_ATTR_SQ":
      return "javascript:alert(1)";
    case "JS_STRING_DQ":
      return setKey === "DQ" ? '";alert(1);//' : "</script><svg/onload=alert(1)>";
    case "JS_STRING_SQ":
      return setKey === "SQ" ? "';alert(1);//" : "</script><svg/onload=alert(1)>";
    case "JS_TEMPLATE":
      return setKey === "BT" ? "`;alert(1);`" : "${alert(1)}";
    case "JS_CODE":
      return setKey === "SC" ? ";alert(1);" : "(alert(1))";
    case "HTML_COMMENT":
      return "--><svg/onload=alert(1)>";
    case "CSS_BLOCK":
      return setKey === "LT" ? "</style><svg/onload=alert(1)>" : "}*{background:url(//attacker)}";
    default:
      return null;
  }
}

export type SurvivalSummary = {
  raw: TestChar[];
  encoded: TestChar[];
  stripped: TestChar[];
  unknown: TestChar[];
};

export function summarise(survival: Record<TestChar, CharStatus>): SurvivalSummary {
  const out: SurvivalSummary = { raw: [], encoded: [], stripped: [], unknown: [] };
  for (const tc of Object.keys(survival) as TestChar[]) {
    const status = survival[tc];
    if (status === "raw") out.raw.push(tc);
    else if (status === "stripped") out.stripped.push(tc);
    else if (status === "unknown") out.unknown.push(tc);
    else out.encoded.push(tc);
  }
  return out;
}
