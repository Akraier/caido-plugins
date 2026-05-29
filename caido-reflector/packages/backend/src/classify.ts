export type ReflectionContext =
  | "HTML_BODY"
  | "HTML_ATTR_DQ"
  | "HTML_ATTR_SQ"
  | "HTML_ATTR_UNQ"
  | "URL_ATTR_DQ"
  | "URL_ATTR_SQ"
  | "JS_STRING_DQ"
  | "JS_STRING_SQ"
  | "JS_TEMPLATE"
  | "JS_CODE"
  | "HTML_COMMENT"
  | "CSS_BLOCK"
  | "JSON_BODY";

export function isJsonContentType(ct: string): boolean {
  const lower = ct.toLowerCase();
  return /(^|[\s;])application\/(?:[a-z0-9.+-]*\+)?json\b/.test(lower) || /\/json\b/.test(lower);
}

export type Reflection = {
  context: ReflectionContext;
  index: number;
  before: string;
  after: string;
  attrName?: string;
};

const URL_ATTRS = new Set(["href", "src", "action", "formaction", "data", "poster", "manifest", "ping"]);

function inEnclosing(body: string, hit: number, openTag: string, closeTag: string): boolean {
  const openIdx = body.lastIndexOf(openTag, hit);
  if (openIdx === -1) return false;
  const closeIdx = body.lastIndexOf(closeTag, hit);
  return closeIdx < openIdx;
}

function inScript(body: string, hit: number): boolean {
  const openRe = /<script\b[^>]*>/gi;
  let openIdx = -1;
  let m: RegExpExecArray | null;
  while ((m = openRe.exec(body)) !== null) {
    if (m.index >= hit) break;
    openIdx = m.index + m[0].length;
  }
  if (openIdx === -1 || openIdx > hit) return false;
  const closeIdx = body.toLowerCase().lastIndexOf("</script>", hit);
  return closeIdx < openIdx - 1;
}

function inStyle(body: string, hit: number): boolean {
  const openRe = /<style\b[^>]*>/gi;
  let openIdx = -1;
  let m: RegExpExecArray | null;
  while ((m = openRe.exec(body)) !== null) {
    if (m.index >= hit) break;
    openIdx = m.index + m[0].length;
  }
  if (openIdx === -1 || openIdx > hit) return false;
  const closeIdx = body.toLowerCase().lastIndexOf("</style>", hit);
  return closeIdx < openIdx - 1;
}

function classifyJs(body: string, hit: number): ReflectionContext {
  let q: '"' | "'" | "`" | null = null;
  let escaped = false;
  const scriptStart = body.toLowerCase().lastIndexOf("<script", hit);
  const tagEnd = body.indexOf(">", scriptStart);
  const start = tagEnd === -1 ? scriptStart : tagEnd + 1;
  for (let i = start; i < hit; i++) {
    const c = body[i];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (c === "\\") {
      escaped = true;
      continue;
    }
    if (q) {
      if (c === q) q = null;
    } else if (c === '"' || c === "'" || c === "`") {
      q = c as '"' | "'" | "`";
    }
  }
  if (q === '"') return "JS_STRING_DQ";
  if (q === "'") return "JS_STRING_SQ";
  if (q === "`") return "JS_TEMPLATE";
  return "JS_CODE";
}

function classifyTag(body: string, hit: number): ReflectionContext | null {
  const tagOpen = body.lastIndexOf("<", hit);
  const tagClose = body.lastIndexOf(">", hit);
  if (tagOpen === -1 || tagOpen < tagClose) return null;
  const segment = body.slice(tagOpen, hit);
  const attrMatch = segment.match(/([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(["']?)[^"']*$/);
  if (!attrMatch) return null;
  const attrName = attrMatch[1].toLowerCase();
  const quote = attrMatch[2];
  const isUrl = URL_ATTRS.has(attrName);
  if (quote === '"') return isUrl ? "URL_ATTR_DQ" : "HTML_ATTR_DQ";
  if (quote === "'") return isUrl ? "URL_ATTR_SQ" : "HTML_ATTR_SQ";
  return "HTML_ATTR_UNQ";
}

export function classifyHit(body: string, hit: number): ReflectionContext {
  if (inEnclosing(body, hit, "<!--", "-->")) return "HTML_COMMENT";
  if (inScript(body, hit)) return classifyJs(body, hit);
  if (inStyle(body, hit)) return "CSS_BLOCK";
  const attr = classifyTag(body, hit);
  if (attr) return attr;
  return "HTML_BODY";
}

export function findReflections(body: string, value: string): Reflection[] {
  if (!value || !body) return [];
  const out: Reflection[] = [];
  let from = 0;
  while (true) {
    const hit = body.indexOf(value, from);
    if (hit === -1) break;
    const context = classifyHit(body, hit);
    const before = body.slice(Math.max(0, hit - 40), hit);
    const after = body.slice(hit + value.length, hit + value.length + 40);
    out.push({ context, index: hit, before, after });
    from = hit + value.length;
    if (out.length >= 5) break;
  }
  return out;
}
