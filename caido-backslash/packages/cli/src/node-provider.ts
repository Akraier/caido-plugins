/**
 * A RequestProvider over raw Node sockets.
 *
 * Deliberately not `fetch`. The engine's entire premise is that the bytes on the wire are exactly
 * the bytes it composed, and `fetch` normalises the request line, reorders and rewrites headers,
 * and refuses several of the payloads this tool exists to send. A socket write is the only way to
 * honour the contract, and it also makes this adapter a faithful stand-in for the Caido backend,
 * which sends verbatim via RequestSpecRaw.
 */

import { connect as netConnect, type Socket } from "node:net";
import { connect as tlsConnect } from "node:tls";

import type {
  EngineRequest,
  RequestProvider,
  SendOptions,
  SendOutcome,
  TransportFailure,
} from "@caido-backslash/engine";
import { findBodyStart } from "@caido-backslash/engine";

const DEFAULT_TIMEOUT_MS = 15_000;

function classifyError(error: unknown): TransportFailure {
  const code = (error as { code?: string } | undefined)?.code;
  switch (code) {
    case "ECONNRESET":
      return "connection-reset";
    case "ECONNREFUSED":
      return "connection-refused";
    case "ENOTFOUND":
    case "EAI_AGAIN":
      return "dns";
    case "ETIMEDOUT":
      return "timeout";
    default:
      break;
  }
  const message = error instanceof Error ? error.message : String(error);
  if (/timeout/i.test(message)) return "timeout";
  if (/certificate|tls|ssl/i.test(message)) return "tls";
  return "unknown";
}

/** Parse status and headers out of a raw response. Body length is not required. */
function parseHead(raw: Uint8Array): {
  status: number;
  headers: Map<string, string[]>;
  bodyStart: number;
} {
  const bodyStart = findBodyStart(raw);
  let head = "";
  for (let i = 0; i < bodyStart; i++) head += String.fromCharCode(raw[i]!);
  const lines = head.split(/\r?\n/);
  const statusLine = lines[0] ?? "";
  const status = Number.parseInt(statusLine.split(" ")[1] ?? "0", 10);

  const headers = new Map<string, string[]>();
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i]!;
    if (line === "") break;
    const colon = line.indexOf(":");
    if (colon === -1) continue;
    const name = line.slice(0, colon).trim().toLowerCase();
    const value = line.slice(colon + 1).trim();
    const existing = headers.get(name);
    if (existing === undefined) headers.set(name, [value]);
    else existing.push(value);
  }
  return { status: Number.isNaN(status) ? 0 : status, headers, bodyStart };
}

/**
 * Decide whether the response is complete.
 *
 * Content-Length is honoured when present. Chunked and close-delimited responses are read until the
 * socket ends, which is correct if slower. Guessing here would truncate a body and silently change
 * every body-derived feature.
 */
function isComplete(raw: Uint8Array): boolean {
  const bodyStart = findBodyStart(raw);
  if (bodyStart >= raw.length && bodyStart === raw.length) {
    // Head not yet terminated, or head only.
    let head = "";
    for (let i = 0; i < raw.length; i++) head += String.fromCharCode(raw[i]!);
    if (!/\r?\n\r?\n/.test(head)) return false;
  }
  const { headers } = parseHead(raw);
  const lengthHeader = headers.get("content-length")?.[0];
  if (lengthHeader !== undefined) {
    const expected = Number.parseInt(lengthHeader, 10);
    if (!Number.isNaN(expected)) return raw.length - bodyStart >= expected;
  }
  return false;
}

export interface NodeProviderOptions {
  /** Accept self-signed and mismatched certificates. Off by default. */
  readonly insecure?: boolean;
  readonly timeoutMs?: number;
}

export function createNodeProvider(options: NodeProviderOptions = {}): RequestProvider {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  return {
    send(request: EngineRequest, sendOptions?: SendOptions): Promise<SendOutcome> {
      return new Promise<SendOutcome>((resolve) => {
        const chunks: Buffer[] = [];
        let settled = false;
        const started = process.hrtime.bigint();

        const finish = (outcome: SendOutcome): void => {
          if (settled) return;
          settled = true;
          socket.destroy();
          resolve(outcome);
        };

        const succeed = (): void => {
          const raw = new Uint8Array(Buffer.concat(chunks));
          if (raw.length === 0) {
            finish({ kind: "failed", failure: "connection-reset", detail: "empty response" });
            return;
          }
          const { status, headers, bodyStart } = parseHead(raw);
          const elapsedMs = Number((process.hrtime.bigint() - started) / 1_000_000n);
          finish({
            kind: "ok",
            response: { status, headers, raw, bodyStart, roundtripMs: elapsedMs },
          });
        };

        const socket: Socket = request.tls
          ? tlsConnect({
              host: request.host,
              port: request.port,
              servername: request.host,
              rejectUnauthorized: options.insecure !== true,
            })
          : netConnect({ host: request.host, port: request.port });

        socket.setTimeout(sendOptions?.timeoutMs ?? timeoutMs);

        socket.on(request.tls ? "secureConnect" : "connect", () => {
          socket.write(Buffer.from(request.raw));
        });

        socket.on("data", (chunk: Buffer) => {
          chunks.push(chunk);
          const raw = new Uint8Array(Buffer.concat(chunks));
          if (isComplete(raw)) succeed();
        });

        socket.on("end", () => {
          if (chunks.length > 0) succeed();
          else finish({ kind: "failed", failure: "connection-reset", detail: "closed with no data" });
        });

        socket.on("timeout", () => {
          finish({ kind: "failed", failure: "timeout", detail: `no response in ${timeoutMs}ms` });
        });

        socket.on("error", (error: unknown) => {
          finish({
            kind: "failed",
            failure: classifyError(error),
            detail: error instanceof Error ? error.message : String(error),
          });
        });

        sendOptions?.signal?.addEventListener("abort", () => {
          finish({ kind: "failed", failure: "aborted" });
        });
      });
    },
  };
}
