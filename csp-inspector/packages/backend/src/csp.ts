// Pure CSP parsing / host+IP classification logic.
// No Caido SDK imports here so it can be unit-tested in isolation.
import { getDomain } from "tldts";

// Response headers that can carry a Content-Security-Policy (matched case-insensitively).
export const CSP_HEADERS = new Set([
  "content-security-policy",
  "content-security-policy-report-only",
  "x-content-security-policy",
  "x-content-security-policy-report-only",
  "x-webkit-csp",
]);

// CSP keyword sources that are never hosts.
const KEYWORD_RE =
  /^'(self|none|unsafe-inline|unsafe-eval|unsafe-hashes|strict-dynamic|report-sample|wasm-unsafe-eval|nonce-.*|sha(?:256|384|512)-.*)'$/i;

// Scheme-only sources (no host component).
const SCHEME_ONLY = new Set([
  "https:",
  "http:",
  "data:",
  "blob:",
  "mediastream:",
  "filesystem:",
  "ws:",
  "wss:",
]);

const OCTET = "(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)";
const IPV4_RE = new RegExp(`^${OCTET}\\.${OCTET}\\.${OCTET}\\.${OCTET}$`);

function classifyIPv4(ip: string): "internal" | "public" {
  const [a = 0, b = 0] = ip.split(".").map(Number);
  if (a === 10) return "internal"; // 10.0.0.0/8
  if (a === 172 && b >= 16 && b <= 31) return "internal"; // 172.16.0.0/12
  if (a === 192 && b === 168) return "internal"; // 192.168.0.0/16
  if (a === 127) return "internal"; // loopback
  if (a === 169 && b === 254) return "internal"; // link-local
  if (a === 100 && b >= 64 && b <= 127) return "internal"; // CGNAT 100.64.0.0/10
  if (ip === "0.0.0.0") return "internal";
  return "public"; // candidate origin IP
}

// CSP requires bracketed IPv6 in a host-source; brackets are already stripped here.
function isIPv6(host: string): boolean {
  return host.includes(":") && /^[0-9a-f:]+(?:\.\d{1,3}){0,3}$/i.test(host);
}

function classifyIPv6(ip: string): "internal" | "public" {
  const a = ip.toLowerCase();
  if (a === "::1") return "internal"; // loopback
  if (/^fe[89ab]/.test(a)) return "internal"; // fe80::/10 link-local
  if (/^f[cd]/.test(a)) return "internal"; // fc00::/7 unique-local
  if (a.startsWith("::ffff:")) {
    // IPv4-mapped — classify the embedded v4 address.
    const v4 = a.slice(7);
    if (IPV4_RE.test(v4)) return classifyIPv4(v4);
  }
  return "public";
}

// A single CSP source token -> "host" or "host:port"; undefined for tokens with no host.
function normalizeToken(tok: string): string | undefined {
  let t = tok.trim();
  if (t === "" || t === "*") return undefined;
  if (KEYWORD_RE.test(t)) return undefined;
  t = t.replace(/^['"]|['"]$/g, "");
  if (SCHEME_ONLY.has(t.toLowerCase())) return undefined;
  t = t.replace(/^[a-z][a-z0-9+.-]*:\/\//i, ""); // strip scheme://
  t = t.split("/")[0] ?? ""; // strip path/query
  if (t === "" || t === "*") return undefined;
  return t; // host[:port], may be *.x or [v6]:port
}

function splitHostPort(hp: string): { host: string; port?: string } {
  const bracket = hp.match(/^\[(.+)\](?::(\d+))?$/); // [v6]:port
  if (bracket) return { host: bracket[1]!, port: bracket[2] };
  const i = hp.lastIndexOf(":");
  if (
    i > -1 &&
    /^\d+$/.test(hp.slice(i + 1)) &&
    !hp.slice(0, i).includes(":")
  ) {
    return { host: hp.slice(0, i), port: hp.slice(i + 1) }; // host:port (not a bare IPv6)
  }
  return { host: hp };
}

// Brand label = leftmost label of the registrable domain, e.g. "target" from "target.com".
function sld(domain: string | undefined): string | undefined {
  if (domain === undefined) return undefined;
  return domain.split(".")[0];
}

type Buckets = {
  subdomains: Set<string>; // same registrable domain as the request host
  brandTld: Set<string>; // same brand label, different TLD
  internalIp: Set<string>; // RFC1918 / loopback / link-local / CGNAT / ULA / v6 LL
  originIp: Set<string>; // public IPv4/IPv6 — possible origin
  thirdParty: Set<string>; // unrelated hosts
};

// Parse CSP header value(s) and classify every host/IP relative to the request host.
export function extractCspHosts(cspValues: string[], reqHost: string): Buckets {
  const reqDomain = getDomain(reqHost) ?? undefined; // registrable domain
  const reqBrand = sld(reqDomain);

  const buckets: Buckets = {
    subdomains: new Set<string>(),
    brandTld: new Set<string>(),
    internalIp: new Set<string>(),
    originIp: new Set<string>(),
    thirdParty: new Set<string>(),
  };

  for (const raw of cspValues) {
    for (const tok of raw.split(/[;\s]+/)) {
      const norm = normalizeToken(tok);
      if (norm === undefined) continue;
      const { host, port } = splitHostPort(norm);
      const suffix = port === undefined ? "" : ":" + port;

      if (IPV4_RE.test(host)) {
        const set =
          classifyIPv4(host) === "internal"
            ? buckets.internalIp
            : buckets.originIp;
        set.add(host + suffix);
        continue;
      }
      if (isIPv6(host)) {
        const set =
          classifyIPv6(host) === "internal"
            ? buckets.internalIp
            : buckets.originIp;
        set.add(`[${host}]${suffix}`);
        continue;
      }

      // Hostname (may be a *.example.com wildcard).
      const bare = host.replace(/^\*\./, "");
      if (!bare.includes(".")) continue;
      const d = getDomain(bare) ?? undefined;
      const label = host + suffix;
      if (d !== undefined && reqDomain !== undefined && d === reqDomain) {
        buckets.subdomains.add(label);
      } else if (reqBrand !== undefined && sld(d) === reqBrand) {
        buckets.brandTld.add(label);
      } else {
        buckets.thirdParty.add(label);
      }
    }
  }

  return buckets;
}

const SECTION_ORDER: Array<[string, keyof Buckets]> = [
  ["Subdomains / same-domain hosts", "subdomains"],
  ["Same-brand, different TLD", "brandTld"],
  ["Internal IPs", "internalIp"],
  ["Public / possible origin IPs", "originIp"],
  ["Third-party hosts", "thirdParty"],
];

// Build the Finding body + dedupe key from extracted buckets. Returns undefined if nothing found.
export function buildFinding(
  reqHost: string,
  buckets: Buckets,
): { title: string; description: string; dedupeKey: string } | undefined {
  const sections = SECTION_ORDER.map(
    ([title, key]) => [title, buckets[key]] as const,
  );
  const total = sections.reduce((n, [, s]) => n + s.size, 0);
  if (total === 0) return undefined;

  const description = sections
    .filter(([, s]) => s.size > 0)
    .map(([title, s]) => `${title}:\n  ${[...s].sort().join("\n  ")}`)
    .join("\n\n");

  // dedupeKey = host + sorted extracted set: a Finding re-fires only when the set changes.
  const all = sections.flatMap(([, s]) => [...s]).sort();

  return {
    title: `CSP host/IP disclosure — ${reqHost}`,
    description,
    dedupeKey: `${reqHost}|${all.join(",")}`,
  };
}
