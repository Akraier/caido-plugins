import type { SDK } from "caido:plugin";
import type { Request, Response } from "caido:utils";

import { extractParams, type Param } from "./extract";
import { findPassiveHits, type PassiveHit } from "./reflect";
import {
  buildCanary,
  analyseSurvival,
  canaryReflected,
  detectContext,
  evaluateState,
  findCanaryIndex,
} from "./probe";
import { buildSubstitution } from "./substitute";
import { reportFinding } from "./finding";
import { ScanCache, pageKey } from "./scan-cache";

const MAX_BODY_BYTES = 2 * 1024 * 1024;
const VERBOSE = true;

const CONTENT_TYPE_ALLOW = [
  "text/html",
  "application/xhtml",
  "application/xml",
  "text/xml",
  "application/json",
  "text/plain",
  "application/javascript",
  "text/javascript",
];

const scanCache = new ScanCache();

function getHeader(headers: Record<string, string[]>, name: string): string {
  const lower = name.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === lower) return v.join(", ");
  }
  return "";
}

function shouldAnalyse(response: Response): boolean {
  const ct = getHeader(response.getHeaders(), "content-type").toLowerCase();
  if (!CONTENT_TYPE_ALLOW.some((t) => ct.includes(t))) return false;
  const body = response.getBody();
  if (!body) return false;
  if (body.length > MAX_BODY_BYTES) return false;
  return true;
}

async function probeAndReport(
  sdk: SDK,
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
    if (VERBOSE) sdk.console.log(`[reflector] probe send failed for ${param.name}: ${String(e)}`);
    return;
  }

  if (!canaryReflected(probeBody, canary)) {
    if (VERBOSE) sdk.console.log(`[reflector] NO_REFLECTION ${param.name} — canary not in probe response (suppressed)`);
    return;
  }

  const { context, index } = detectContext(probeBody, canary, probeCT);
  const survival = analyseSurvival(probeBody, canary.markers);
  const evalResult = evaluateState(context, survival);

  if (VERBOSE)
    sdk.console.log(
      `[reflector] ${evalResult.state} ${param.name} ctx=${context} (${request.getMethod()} ${request.getHost()}${request.getPath()})`,
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

async function onResponse(sdk: SDK, request: Request, response: Response): Promise<void> {
  try {
    const where = `${request.getMethod()} ${request.getHost()}${request.getPath()}`;
    const ct = getHeader(response.getHeaders(), "content-type") || "(none)";
    const bodyLen = response.getBody()?.length ?? 0;

    if (!shouldAnalyse(response)) {
      if (VERBOSE) sdk.console.log(`[reflector] skip ${where} — CT=${ct}, len=${bodyLen}`);
      return;
    }
    const reqHeaders = request.getHeaders();
    const reqContentType = getHeader(reqHeaders, "content-type");
    const reqBody = request.getBody()?.toText() ?? "";
    const params = extractParams({
      query: request.getQuery(),
      contentType: reqContentType,
      body: reqBody,
      headers: reqHeaders,
    });
    if (params.length === 0) {
      if (VERBOSE) sdk.console.log(`[reflector] no-params ${where}`);
      return;
    }

    const key = pageKey(request.getMethod(), request.getHost(), request.getPath(), params);
    if (scanCache.has(key)) {
      if (VERBOSE) sdk.console.log(`[reflector] cache-hit ${where} (params=${params.length})`);
      return;
    }
    scanCache.mark(key);

    const body = response.getBody()?.toText() ?? "";
    if (!body) return;

    const hits = findPassiveHits(params, body);
    if (hits.length === 0) {
      if (VERBOSE) sdk.console.log(`[reflector] no-reflection ${where} (cached)`);
      return;
    }

    const probedKey = new Set<string>();
    if (VERBOSE) sdk.console.log(`[reflector] HIT ${where} ${hits.length} passive match(es) — probing`);
    for (const hit of hits) {
      const k = `${hit.param.source}:${hit.param.name}`;
      if (probedKey.has(k)) continue;
      probedKey.add(k);
      await probeAndReport(sdk, request, hit.param);
    }
  } catch (e) {
    sdk.console.log(`[reflector] handler error: ${String(e)}`);
  }
}

export function init(sdk: SDK): void {
  sdk.console.log("[reflector] backend loaded (v2 state machine: NO_REFLECTION / REFLECTED / ATTEMPT / CONFIRMED)");
  sdk.events.onInterceptResponse(onResponse);
}
