/**
 * The Caido side of the transport seam.
 *
 * This is the only file in the plugin that knows both the engine and the Caido SDK, and it is
 * deliberately small. Everything above it is host-agnostic and unit-tested offline.
 *
 * Two SDK details do the heavy lifting here, and both were verified against the SDK types rather
 * than assumed:
 *
 * 1. `RequestSpecRaw(url)` parses only host, port and scheme; `setRaw(bytes)` then sends those bytes
 *    verbatim with no parsing, normalisation or percent-encoding, and Content-Length is entirely the
 *    caller's responsibility. That is what makes byte-exact probing possible at all. The parsed
 *    `RequestSpec` would rewrite the Host header and recompute Content-Length, which would break the
 *    permutation null the detector depends on.
 *
 * 2. **Every request is saved. Without exception.** An earlier version sent probes with
 *    `save: false` to keep the project database small, which was the wrong trade: it made the
 *    scan's actual traffic invisible to the operator, who could see counters but never the requests.
 *    For a tool that fires hundreds of requests at a third-party target during an engagement, being
 *    able to inspect and replay every single one is worth far more than a compact database. There is
 *    deliberately no option to turn this off.
 */

import type { SDK } from "caido:plugin";
import { RequestSpecRaw } from "caido:utils";

import {
  findBodyStart,
  type EngineRequest,
  type EngineResponse,
  type RequestProvider,
  type SendOptions,
  type SendOutcome,
  type TransportFailure,
} from "@caido-backslash/engine";

/**
 * Map an SDK error onto the engine's failure taxonomy.
 *
 * Classification matters rather than being cosmetic: a firewall that reliably kills the break arm
 * produces a perfectly reproducible "difference", and the original Java tool reported exactly that
 * as a confident finding because it fed null responses into feature computation. A typed failure is
 * what turns that into a correctly classified non-signal.
 */
function classify(error: unknown): { failure: TransportFailure; detail: string } {
  const detail = error instanceof Error ? error.message : String(error);
  const lower = detail.toLowerCase();
  // The SDK's own timeout messages contain the word "timeout".
  if (lower.includes("timeout")) return { failure: "timeout", detail };
  if (lower.includes("reset")) return { failure: "connection-reset", detail };
  if (lower.includes("refused")) return { failure: "connection-refused", detail };
  if (lower.includes("dns") || lower.includes("resolve")) return { failure: "dns", detail };
  if (lower.includes("certificate") || lower.includes("tls") || lower.includes("ssl")) {
    return { failure: "tls", detail };
  }
  return { failure: "unknown", detail };
}

/** The engine wants one flat byte buffer plus the offset where the body starts. */
function toEngineResponse(
  raw: Uint8Array,
  status: number,
  headerEntries: Record<string, string[]>,
  roundtripMs: number,
  requestId: string | undefined,
): EngineResponse {
  const headers = new Map<string, string[]>();
  for (const [name, values] of Object.entries(headerEntries)) {
    headers.set(name.toLowerCase(), values);
  }
  const base = {
    status,
    headers,
    raw,
    bodyStart: findBodyStart(raw),
    roundtripMs,
  };
  return requestId === undefined ? base : { ...base, requestId };
}

export function createCaidoProvider(sdk: SDK): RequestProvider {
  return {
    async send(request: EngineRequest, sendOptions?: SendOptions): Promise<SendOutcome> {
      // Only the scheme, host and port are taken from this URL; the path and everything else comes
      // from the raw bytes.
      const origin = `${request.tls ? "https" : "http"}://${request.host}:${request.port}/`;

      let spec: RequestSpecRaw;
      try {
        spec = new RequestSpecRaw(origin);
        spec.setRaw(request.raw);
      } catch (error) {
        const { failure, detail } = classify(error);
        return { kind: "failed", failure, detail };
      }

      try {
        const sent = await sdk.requests.send(spec, {
          // Always. Every request this plugin makes is inspectable and replayable in Caido.
          // `sendOptions.persist` is ignored here: it marks the evidence re-send for hosts that
          // distinguish the two, and there is no case in which we would want a probe to vanish.
          save: true,
          ...(sendOptions?.timeoutMs === undefined
            ? {}
            : { timeouts: { response: Math.ceil(sendOptions.timeoutMs / 1000) } }),
        });

        const response = sent.response;
        const raw = response.getRaw().toBytes();
        const id = sent.request.getId();

        return {
          kind: "ok",
          response: toEngineResponse(
            raw,
            response.getCode(),
            response.getHeaders(),
            response.getRoundtripTime(),
            // Everything is saved, so this should always be a real id. Guard anyway: reporting a
            // placeholder id as valid would attach a finding to nothing.
            id === "0" || id === "" ? undefined : id,
          ),
        };
      } catch (error) {
        const { failure, detail } = classify(error);
        return { kind: "failed", failure, detail };
      }
    },
  };
}
