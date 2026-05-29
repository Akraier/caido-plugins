import type { Param } from "./extract";

function encodeQueryComponent(s: string): string {
  return encodeURIComponent(s).replace(/'/g, "%27");
}

export function substituteInQuery(query: string, paramName: string, newValue: string): string {
  const parts = query.split("&");
  const out: string[] = [];
  let replaced = false;
  for (const part of parts) {
    const eq = part.indexOf("=");
    if (eq === -1) {
      out.push(part);
      continue;
    }
    const name = part.slice(0, eq);
    if (decodeURIComponent(name) === paramName && !replaced) {
      out.push(`${name}=${encodeQueryComponent(newValue)}`);
      replaced = true;
    } else {
      out.push(part);
    }
  }
  return out.join("&");
}

export function substituteInForm(body: string, paramName: string, newValue: string): string {
  return substituteInQuery(body, paramName, newValue);
}

function setAtPath(obj: unknown, path: string, value: string): unknown {
  if (!path) return value;
  const segments: Array<string | number> = [];
  const re = /([^.\[\]]+)|\[(\d+)\]/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(path)) !== null) {
    if (m[1] !== undefined) segments.push(m[1]);
    else if (m[2] !== undefined) segments.push(Number(m[2]));
  }
  const root = obj as Record<string, unknown> | unknown[];
  let cur: Record<string, unknown> | unknown[] = root as Record<string, unknown> | unknown[];
  for (let i = 0; i < segments.length - 1; i++) {
    const k = segments[i] as keyof typeof cur;
    cur = (cur as Record<string, unknown>)[k as string] as Record<string, unknown> | unknown[];
    if (cur === null || cur === undefined) return obj;
  }
  const last = segments[segments.length - 1];
  (cur as Record<string, unknown>)[last as string] = value;
  return root;
}

export function substituteInJson(body: string, jsonPath: string, newValue: string): string {
  try {
    const parsed = JSON.parse(body);
    const updated = setAtPath(parsed, jsonPath, newValue);
    return JSON.stringify(updated);
  } catch {
    return body;
  }
}

export type SubstitutionTarget =
  | { kind: "query"; newQuery: string }
  | { kind: "form"; newBody: string }
  | { kind: "json"; newBody: string }
  | { kind: "cookie"; newCookieHeader: string }
  | { kind: "header"; headerName: string; newValue: string }
  | { kind: "unsupported" };

export function buildSubstitution(param: Param, current: {
  query: string;
  body: string;
  cookieHeader: string;
}, newValue: string): SubstitutionTarget {
  switch (param.source) {
    case "query":
      return { kind: "query", newQuery: substituteInQuery(current.query, param.name, newValue) };
    case "form":
      return { kind: "form", newBody: substituteInForm(current.body, param.name, newValue) };
    case "json":
      return { kind: "json", newBody: substituteInJson(current.body, param.name, newValue) };
    case "cookie": {
      const parts = current.cookieHeader.split(";").map((p) => p.trim());
      const updated = parts.map((p) => {
        const eq = p.indexOf("=");
        if (eq === -1) return p;
        const name = p.slice(0, eq);
        if (name === param.name) return `${name}=${encodeQueryComponent(newValue)}`;
        return p;
      });
      return { kind: "cookie", newCookieHeader: updated.join("; ") };
    }
    case "header":
      return { kind: "header", headerName: param.name, newValue };
    default:
      return { kind: "unsupported" };
  }
}
