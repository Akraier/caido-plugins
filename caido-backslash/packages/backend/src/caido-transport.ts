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
 * 2. `sdk.requests.send(spec, options)` accepts `save`. This matters more than it looks: the
 *    community scanner's wrapped SDK drops the options argument entirely, so inside that engine
 *    `save: false` type-checks and is silently ignored. Standalone, we call the SDK directly and the
 *    probe-unsaved / evidence-saved split actually works. Probe traffic runs into the thousands, so
 *    persisting all of it would flood the project database, but a finding can only cite a request
 *    the host stored.
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

export interface CaidoTransportOptions {
  /**
   * Persist probe traffic. Off by default.
   *
   * With this off, probes leave no trace in the project database and their request ids come back as
   * 0, which means they cannot be cited by a finding. That is intentional: the confirmation re-send
   * is what produces citable evidence, and it guarantees the request attached to a finding is the
   * exact exchange the claim was computed from. The prior implementation attached its *fastest*
   * request while computing evidence from its *last*, so findings could not be reproduced by hand.
   */
  readonly persistProbes?: boolean;
}

export function createCaidoProvider(
  sdk: SDK,
  options: CaidoTransportOptions = {},
): RequestProvider {
  const persistProbes = options.persistProbes ?? false;

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

      const save = sendOptions?.persist ?? persistProbes;

      try {
        const sent = await sdk.requests.send(spec, {
          save,
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
            // An unsaved request comes back with id 0, which cannot be attached to a finding.
            // Report it as absent rather than as a valid reference.
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
