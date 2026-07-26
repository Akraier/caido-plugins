/**
 * Just enough URL handling to follow a redirect.
 *
 * Deliberately hand-written rather than using `URL`. That is a WHATWG host API, not an ECMAScript
 * one, and the backend runs under rquickjs where it is not guaranteed to exist -- the same reason the
 * engine has its own JSON span scanner instead of calling `JSON.parse`. Writing it out also keeps one
 * property that matters more here than convenience: **nothing is ever decoded or re-encoded**. A
 * `Location` containing `%2e%2e` or a raw backslash is followed exactly as the server wrote it,
 * because normalising it would change the request under test.
 *
 * Scope: origin-form targets and absolute/relative redirect targets. No userinfo, no fragments
 * (stripped, they are not sent), no IDN, no percent-decoding.
 */

export interface Origin {
  readonly host: string;
  readonly port: number;
  readonly tls: boolean;
}

export interface Located {
  readonly origin: Origin;
  /** Origin-form request target: path plus optional `?query`. Always starts with `/`. */
  readonly target: string;
}

export function sameOrigin(a: Origin, b: Origin): boolean {
  return a.host === b.host && a.port === b.port && a.tls === b.tls;
}

export function formatOrigin(origin: Origin): string {
  const scheme = origin.tls ? "https" : "http";
  const isDefault = (origin.tls && origin.port === 443) || (!origin.tls && origin.port === 80);
  return isDefault ? `${scheme}://${origin.host}` : `${scheme}://${origin.host}:${origin.port}`;
}

export function formatLocated(located: Located): string {
  return `${formatOrigin(located.origin)}${located.target}`;
}

/**
 * Remove `.` and `..` segments, per RFC 3986 section 5.2.4.
 *
 * Applied only to a path we are about to re-send, and only to segments that are literally "." or
 * "..". An encoded `%2e%2e` is NOT a dot segment and is left alone: servers disagree about whether
 * they collapse it, and that disagreement is frequently the vulnerability, so the scanner must not
 * silently pick a side.
 */
export function removeDotSegments(path: string): string {
  const out: string[] = [];
  const trailing = path.endsWith("/") || path.endsWith("/.") || path.endsWith("/..");
  for (const segment of path.split("/")) {
    if (segment === "" || segment === ".") continue;
    if (segment === "..") {
      out.pop();
      continue;
    }
    out.push(segment);
  }
  const joined = `/${out.join("/")}`;
  if (trailing && joined !== "/") return `${joined}/`;
  return joined;
}

/** Split an origin-form target into its path and its `?query` (query kept with the leading `?`). */
function splitTarget(target: string): { path: string; query: string } {
  const q = target.indexOf("?");
  if (q === -1) return { path: target, query: "" };
  return { path: target.slice(0, q), query: target.slice(q) };
}

/**
 * Parse the authority of an absolute URL: `host`, `host:port`, or an IPv6 `[::1]:port`.
 *
 * Returns undefined for an authority that is empty or whose port is not a plain integer. A refusal
 * is always preferable to a guess here: guessing wrong means sending probe traffic somewhere the
 * operator did not authorise.
 */
function parseAuthority(authority: string, tls: boolean): Origin | undefined {
  if (authority === "") return undefined;
  // Userinfo would change who we authenticate as; refuse rather than strip it.
  if (authority.includes("@")) return undefined;

  let host = authority;
  let portText = "";
  if (authority.startsWith("[")) {
    const close = authority.indexOf("]");
    if (close === -1) return undefined;
    host = authority.slice(0, close + 1);
    const rest = authority.slice(close + 1);
    if (rest !== "") {
      if (!rest.startsWith(":")) return undefined;
      portText = rest.slice(1);
    }
  } else {
    const colon = authority.indexOf(":");
    if (colon !== -1) {
      host = authority.slice(0, colon);
      portText = authority.slice(colon + 1);
    }
  }
  if (host === "") return undefined;

  let port = tls ? 443 : 80;
  if (portText !== "") {
    if (!/^[0-9]+$/.test(portText)) return undefined;
    port = Number.parseInt(portText, 10);
    if (port < 1 || port > 65535) return undefined;
  }
  return { host, port, tls };
}

export type ResolveResult = { readonly kind: "ok"; readonly located: Located } | {
  readonly kind: "unsupported";
  readonly detail: string;
};

/**
 * Resolve a `Location` value against the request that produced it.
 *
 * Anything that is not an http(s) target resolves to `unsupported` rather than being coerced:
 * `javascript:`, `mailto:`, `data:` and friends are not things to fetch, and a redirect to one is
 * information about the application, not a place to keep probing.
 */
export function resolveLocation(base: Located, location: string): ResolveResult {
  // A fragment is never sent to the server.
  const hashAt = location.indexOf("#");
  const raw = (hashAt === -1 ? location : location.slice(0, hashAt)).trim();
  if (raw === "") return { kind: "unsupported", detail: "empty Location" };

  // Protocol-relative: //host/path, inheriting the scheme.
  if (raw.startsWith("//")) {
    const rest = raw.slice(2);
    const slash = rest.indexOf("/");
    const authority = slash === -1 ? rest : rest.slice(0, slash);
    const origin = parseAuthority(authority, base.origin.tls);
    if (origin === undefined) {
      return { kind: "unsupported", detail: `unparseable authority in ${raw}` };
    }
    const target = slash === -1 ? "/" : rest.slice(slash);
    return { kind: "ok", located: { origin, target: normaliseTarget(target) } };
  }

  // Absolute.
  const schemeEnd = raw.indexOf("://");
  if (schemeEnd !== -1) {
    const scheme = raw.slice(0, schemeEnd).toLowerCase();
    if (scheme !== "http" && scheme !== "https") {
      return { kind: "unsupported", detail: `non-http scheme "${scheme}"` };
    }
    const rest = raw.slice(schemeEnd + 3);
    const slash = rest.indexOf("/");
    const authority = slash === -1 ? rest : rest.slice(0, slash);
    const origin = parseAuthority(authority, scheme === "https");
    if (origin === undefined) {
      return { kind: "unsupported", detail: `unparseable authority in ${raw}` };
    }
    const target = slash === -1 ? "/" : rest.slice(slash);
    return { kind: "ok", located: { origin, target: normaliseTarget(target) } };
  }

  // A bare scheme with no authority: mailto:, javascript:, data:, tel:.
  const colon = raw.indexOf(":");
  const slashBeforeColon = raw.indexOf("/");
  if (colon !== -1 && (slashBeforeColon === -1 || colon < slashBeforeColon)) {
    const maybeScheme = raw.slice(0, colon);
    if (/^[A-Za-z][A-Za-z0-9+.-]*$/.test(maybeScheme)) {
      return { kind: "unsupported", detail: `non-http scheme "${maybeScheme.toLowerCase()}"` };
    }
  }

  // Root-relative.
  if (raw.startsWith("/")) {
    return { kind: "ok", located: { origin: base.origin, target: normaliseTarget(raw) } };
  }

  // Relative to the base path's directory.
  const { path } = splitTarget(base.target);
  const lastSlash = path.lastIndexOf("/");
  const dir = lastSlash === -1 ? "/" : path.slice(0, lastSlash + 1);
  const { path: relPath, query } = splitTarget(raw);
  return {
    kind: "ok",
    located: {
      origin: base.origin,
      target: `${removeDotSegments(`${dir}${relPath}`)}${query}`,
    },
  };
}

/** Ensure an origin-form target starts with `/` and carries no fragment. */
function normaliseTarget(target: string): string {
  const hashAt = target.indexOf("#");
  const clean = hashAt === -1 ? target : target.slice(0, hashAt);
  if (clean === "") return "/";
  return clean.startsWith("/") ? clean : `/${clean}`;
}

/**
 * Parse an operator-supplied observation URL.
 *
 * Accepts an absolute URL, or a path which is taken against the scanned request's own origin. The
 * operator typing a full URL is an explicit act, so a different host is permitted -- but the caller
 * is expected to surface which host it resolved to, because sending probe-derived traffic to an
 * unintended host during an engagement is a scope incident, not a bug.
 */
export function parseObservationUrl(input: string, fallback: Origin): ResolveResult {
  const text = input.trim();
  if (text === "") return { kind: "unsupported", detail: "empty URL" };
  return resolveLocation({ origin: fallback, target: "/" }, text);
}
