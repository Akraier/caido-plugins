export const DEFAULT_HEADERS: string[] = [
  "X-Forwarded-For",
  "X-Forwarded-Host",
  "X-Forwarded-Proto",
  "X-Forwarded-Server",
  "X-Forwarded-Scheme",
  "X-Real-IP",
  "X-Originating-IP",
  "X-Remote-IP",
  "X-Remote-Addr",
  "X-Client-IP",
  "X-Host",
  "X-Custom-IP-Authorization",
  "X-HTTP-Host-Override",
  "X-Forwarded-Server-Name",
  "X-Original-URL",
  "X-Rewrite-URL",
  "X-Override-URL",
  "X-Original-Remote-Addr",
  "X-Cluster-Client-IP",
  "True-Client-IP",
  "CF-Connecting-IP",
  "Fastly-Client-IP",
  "X-ProxyUser-IP",
  "Via",
  "Forwarded",
  "Client-IP",
  "Proxy-Client-IP",
  "WL-Proxy-Client-IP",
  "X-Backend-Server",
  "Referer",
];

export const DEFAULT_IPS: string[] = [
  "127.0.0.1",
  "localhost",
  "127.1",
  "127.0.0.0",
  "0.0.0.0",
  "0",
  "10.0.0.1",
  "172.16.0.1",
  "192.168.0.1",
  "192.168.1.1",
  "[::1]",
  "[::]",
  "169.254.169.254",
  "metadata.google.internal",
  "internal",
];

export type PathMutation = {
  id: string;
  label: string;
  transform: (path: string) => string;
};

export const DEFAULT_PATH_MUTATIONS: PathMutation[] = [
  { id: "double-slash-prefix", label: "//<path>", transform: (p) => "/" + p },
  { id: "double-slash-suffix", label: "<path>//", transform: (p) => p + "/" },
  { id: "dot-slash", label: "/./<path>", transform: (p) => "/." + p },
  { id: "encoded-dot-slash", label: "/%2e/<path>", transform: (p) => "/%2e" + p },
  { id: "trailing-slash", label: "<path>/", transform: (p) => (p.endsWith("/") ? p : p + "/") },
  { id: "trailing-dot", label: "<path>/.", transform: (p) => (p.endsWith("/") ? p + "." : p + "/.") },
  { id: "trailing-semicolon", label: "<path>;", transform: (p) => p + ";" },
  { id: "trailing-encoded-slash", label: "<path>%2f", transform: (p) => p + "%2f" },
  { id: "trailing-space", label: "<path>%20", transform: (p) => p + "%20" },
  { id: "trailing-null", label: "<path>%00", transform: (p) => p + "%00" },
  { id: "trailing-hash", label: "<path>%23", transform: (p) => p + "%23" },
  { id: "trailing-tab", label: "<path>%09", transform: (p) => p + "%09" },
  { id: "case-toggle", label: "case-toggle", transform: (p) => toggleCase(p) },
  { id: "extension-html", label: "<path>.html", transform: (p) => p + ".html" },
  { id: "extension-json", label: "<path>.json", transform: (p) => p + ".json" },
];

function toggleCase(path: string): string {
  let out = "";
  for (const ch of path) {
    if (ch >= "a" && ch <= "z") out += ch.toUpperCase();
    else if (ch >= "A" && ch <= "Z") out += ch.toLowerCase();
    else out += ch;
  }
  return out;
}

export const MARKER_HEADER = "X-Bypass-403-Probe";
