import type { SDK } from "caido:plugin";

import { buildFinding, CSP_HEADERS, extractCspHosts } from "./csp";

export function init(sdk: SDK) {
  // Optional scope filter: comma-separated registrable domains. Empty => process all responses.
  const scope = (sdk.env.getVar("CSP_INSPECTOR_SCOPE") ?? "")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);

  sdk.events.onInterceptResponse(async (sdk, request, response) => {
    // 1. Fast bail — collect CSP header values (case-insensitive), stop if none.
    const cspValues: string[] = [];
    for (const [name, values] of Object.entries(response.getHeaders())) {
      if (CSP_HEADERS.has(name.toLowerCase())) cspValues.push(...values);
    }
    if (cspValues.length === 0) return;

    const reqHost = request.getHost().toLowerCase();
    if (!reqHost) return;

    // 2. Optional scope gate.
    if (
      scope.length &&
      !scope.some((d) => reqHost === d || reqHost.endsWith("." + d))
    ) {
      return;
    }

    // 3. Parse + classify, then emit a single Finding if anything was extracted.
    const buckets = extractCspHosts(cspValues, reqHost);
    const finding = buildFinding(reqHost, buckets);
    if (!finding) return;

    try {
      await sdk.findings.create({
        reporter: "CSP Inspector",
        request,
        title: finding.title,
        description: finding.description,
        dedupeKey: finding.dedupeKey,
      });
    } catch (err) {
      sdk.console.warn(
        `[csp-inspector] failed to create finding: ${String(err)}`,
      );
    }
  });
}
