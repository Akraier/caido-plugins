import type { Request, Response } from "caido:utils";

import type { ReflectorConfig, ReflectorSDK } from "./api";
import { extractParams, type Param } from "./extract";
import { findPassiveHits } from "./reflect";
import {
  buildCanary,
  analyseSurvival,
  canaryReflected,
  detectAllContexts,
  evaluateState,
} from "./probe";
import { buildSubstitution } from "./substitute";
import { reportFinding } from "./finding";
import { ScanCache, pageKey } from "./scan-cache";
import {
  getConfig,
  isEnabled,
  isVerbose,
  loadConfig,
  setConfig,
  setEnabled,
} from "./settings";

const scanCache = new ScanCache();

// Mirror a log line to the frontend feed. Always attempts the send; the console
// side respects the verbose flag at the call site.
function feed(sdk: ReflectorSDK, line: string): void {
  try {
    sdk.api.send("reflector:log", line);
  } catch {
    // frontend not listening — non-fatal
  }
}

// Verbose log: console only when verbose is on, but always forwarded to the feed.
function vlog(sdk: ReflectorSDK, line: string): void {
  if (isVerbose()) sdk.console.log(line);
  feed(sdk, line);
}

// Important log: always to console and the feed.
function ilog(sdk: ReflectorSDK, line: string): void {
  sdk.console.log(line);
  feed(sdk, line);
}

function getHeader(headers: Record<string, string[]>, name: string): string {
  const lower = name.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === lower) return v.join(", ");
  }
  return "";
}

function shouldAnalyse(response: Response): boolean {
  const cfg = getConfig();
  const ct = getHeader(response.getHeaders(), "content-type").toLowerCase();
  if (!cfg.contentTypeAllow.some((t) => ct.includes(t))) return false;
  const body = response.getBody();
  if (!body) return false;
  if (body.length > cfg.maxBodyBytes) return false;
  return true;
}

async function probeAndReport(
  sdk: ReflectorSDK,
  request: Request,
  param: Param,
): Promise<void> {
  const canary = buildCanary();
  const spec = request.toSpec();
  const headers = request.getHeaders();
  const cookieHeader = getHeader(headers, "cookie");
  const sub = buildSubstitution(
    param,
    {
      query: request.getQuery(),
      body: request.getBody()?.toText() ?? "",
      cookieHeader,
    },
    canary.value,
  );

  switch (sub.kind) {
    case "query":
      spec.setQuery(sub.newQuery);
      break;
    case "form":
    case "json":
      spec.setBody(sub.newBody);
      break;
    case "cookie":
      spec.setHeader("Cookie", sub.newCookieHeader);
      break;
    case "header":
      spec.setHeader(sub.headerName, sub.newValue);
      break;
    case "unsupported":
      return;
  }

  let probeBody = "";
  let probeCT = "";
  try {
    const payload = await sdk.requests.send(spec);
    const respBody = payload.response?.getBody();
    if (!respBody) return;
    probeBody = respBody.toText();
    probeCT = payload.response ? getHeader(payload.response.getHeaders(), "content-type") : "";
  } catch (e) {
    vlog(sdk, `[reflector] probe send failed for ${param.name}: ${String(e)}`);
    return;
  }

  if (!canaryReflected(probeBody, canary)) {
    vlog(sdk, `[reflector] NO_REFLECTION ${param.name} — canary not in probe response (suppressed)`);
    return;
  }

  const contexts = detectAllContexts(probeBody, canary, probeCT);
  if (contexts.length === 0) return;

  const survival = analyseSurvival(probeBody, canary.markers);

  for (const { context, index } of contexts) {
    const evalResult = evaluateState(context, survival);

    ilog(
      sdk,
      `[reflector] ${evalResult.state} ${param.name} ctx=${context} idx=${index} (${request.getMethod()} ${request.getHost()}${request.getPath()})`,
    );

    await reportFinding(sdk, request, {
      state: evalResult.state,
      context,
      param,
      canary,
      probeBody,
      canaryIndex: index,
      survival,
      rationale: evalResult.rationale,
      breakoutSet: evalResult.breakoutSet,
    });
  }
}

async function onResponse(sdk: ReflectorSDK, request: Request, response: Response): Promise<void> {
  try {
    if (!isEnabled()) return;
    const where = `${request.getMethod()} ${request.getHost()}${request.getPath()}`;
    const ct = getHeader(response.getHeaders(), "content-type") || "(none)";
    const bodyLen = response.getBody()?.length ?? 0;

    if (!shouldAnalyse(response)) {
      vlog(sdk, `[reflector] skip ${where} — CT=${ct}, len=${bodyLen}`);
      return;
    }
    const reqHeaders = request.getHeaders();
    const reqContentType = getHeader(reqHeaders, "content-type");
    const reqBody = request.getBody()?.toText() ?? "";
    const extractInput = {
      query: request.getQuery(),
      contentType: reqContentType,
      body: reqBody,
      headers: reqHeaders,
    };
    const params = extractParams(extractInput, { skipEligible: true });
    if (params.length === 0) {
      vlog(sdk, `[reflector] no-params ${where}`);
      return;
    }

    const key = pageKey(request.getMethod(), request.getHost(), request.getPath(), params);
    if (scanCache.has(key)) {
      vlog(sdk, `[reflector] cache-hit ${where} (params=${params.length})`);
      return;
    }
    scanCache.mark(key);

    const body = response.getBody()?.toText() ?? "";
    if (!body) return;

    const hits = findPassiveHits(params, body);
    if (hits.length > 0) {
      vlog(sdk, `[reflector] ${hits.length} passive match(es) for ${where}`);
    }

    const probedKey = new Set<string>();
    ilog(sdk, `[reflector] PROBE ${where} ${params.length} param(s)`);
    for (const param of params) {
      const k = `${param.source}:${param.name}`;
      if (probedKey.has(k)) continue;
      probedKey.add(k);
      await probeAndReport(sdk, request, param);
    }
  } catch (e) {
    ilog(sdk, `[reflector] handler error: ${String(e)}`);
  }
}

export type { API } from "./api";

export function init(sdk: ReflectorSDK): void {
  sdk.console.log("[reflector] backend loaded (v2 state machine: NO_REFLECTION / REFLECTED / ATTEMPT / CONFIRMED)");

  sdk.api.register("getConfig", () => getConfig());
  sdk.api.register("setConfig", (sdk, patch: Partial<ReflectorConfig>) => {
    const next = setConfig(sdk, patch);
    ilog(sdk, `[reflector] config updated: ${JSON.stringify(next)}`);
    return next;
  });

  sdk.api.register("getEnabled", () => isEnabled());
  sdk.api.register("setEnabled", (sdk, value: boolean) => {
    const next = setEnabled(sdk, value);
    ilog(sdk, `[reflector] ${next ? "ENABLED" : "DISABLED"} via toggle`);
    return next;
  });

  sdk.api.register("getCacheSize", () => scanCache.size());
  sdk.api.register("clearCache", (sdk) => {
    scanCache.clear();
    ilog(sdk, "[reflector] scan cache cleared");
    return scanCache.size();
  });

  // Restore persisted config (defaults preserve original behaviour) without blocking init.
  void loadConfig(sdk).then((cfg) =>
    sdk.console.log(`[reflector] config restored: ${JSON.stringify(cfg)}`),
  );

  sdk.events.onInterceptResponse(onResponse);
}
