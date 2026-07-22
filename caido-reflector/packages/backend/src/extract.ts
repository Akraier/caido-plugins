export type ParamSource = "query" | "form" | "json" | "cookie" | "header";

export type Param = {
  source: ParamSource;
  name: string;
  value: string;
};

const MIN_VALUE_LEN = 4;
const STOPLIST = new Set([
  "true",
  "false",
  "null",
  "undefined",
  "none",
  "1",
  "0",
  "yes",
  "no",
  "on",
  "off",
]);

const HEADER_ALLOWLIST = new Set([
  "referer",
  "x-forwarded-for",
  "x-forwarded-host",
  "x-real-ip",
  "x-original-url",
  "x-rewrite-url",
  "x-custom-ip-authorization",
  "x-host",
  "x-remote-ip",
]);

function safeDecode(s: string): string {
  try {
    return decodeURIComponent(s.replace(/\+/g, " "));
  } catch {
    return s;
  }
}

export function eligible(value: string): boolean {
  if (value.length < MIN_VALUE_LEN) return false;
  const lower = value.toLowerCase();
  if (STOPLIST.has(lower)) return false;
  if (/^[0-9]+$/.test(value) && value.length < 6) return false;
  return true;
}

function parseUrlencoded(body: string, source: ParamSource, skipEligible?: boolean): Param[] {
  const out: Param[] = [];
  for (const part of body.split("&")) {
    const i = part.indexOf("=");
    if (i === -1) continue;
    const name = safeDecode(part.slice(0, i));
    const value = safeDecode(part.slice(i + 1));
    if (name && (skipEligible || eligible(value))) out.push({ source, name, value });
  }
  return out;
}

function walkJson(node: unknown, path: string, out: Param[], skipEligible?: boolean): void {
  if (node === null || node === undefined) return;
  if (typeof node === "string") {
    if (skipEligible || eligible(node)) out.push({ source: "json", name: path || "$", value: node });
    return;
  }
  if (typeof node === "number" || typeof node === "boolean") return;
  if (Array.isArray(node)) {
    node.forEach((v, i) => walkJson(v, `${path}[${i}]`, out, skipEligible));
    return;
  }
  if (typeof node === "object") {
    for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
      walkJson(v, path ? `${path}.${k}` : k, out, skipEligible);
    }
  }
}

function parseCookies(header: string, skipEligible?: boolean): Param[] {
  const out: Param[] = [];
  for (const part of header.split(";")) {
    const trimmed = part.trim();
    const i = trimmed.indexOf("=");
    if (i === -1) continue;
    const name = trimmed.slice(0, i);
    const value = safeDecode(trimmed.slice(i + 1));
    if (skipEligible || eligible(value)) out.push({ source: "cookie", name, value });
  }
  return out;
}

export type ExtractInput = {
  query: string;
  contentType: string;
  body: string;
  headers: Record<string, string[]>;
};

export type ExtractOpts = {
  skipEligible?: boolean;
};

export function extractParams(input: ExtractInput, opts?: ExtractOpts): Param[] {
  const skip = opts?.skipEligible;
  const params: Param[] = [];

  if (input.query) {
    params.push(...parseUrlencoded(input.query, "query", skip));
  }

  const ct = input.contentType.toLowerCase();
  if (input.body) {
    if (ct.includes("application/x-www-form-urlencoded")) {
      params.push(...parseUrlencoded(input.body, "form", skip));
    } else if (ct.includes("application/json") || ct.includes("+json")) {
      try {
        walkJson(JSON.parse(input.body), "", params, skip);
      } catch {
        /* ignore non-JSON */
      }
    }
  }

  for (const [rawName, values] of Object.entries(input.headers)) {
    const name = rawName.toLowerCase();
    if (name === "cookie") {
      for (const v of values) params.push(...parseCookies(v, skip));
      continue;
    }
    if (HEADER_ALLOWLIST.has(name)) {
      for (const v of values) {
        if (skip || eligible(v)) params.push({ source: "header", name: rawName, value: v });
      }
    }
  }

  return params;
}
