// Minimal OOB provider + interaction types, inlined from quickssrf's `shared` / `providers`
// packages (MIT, Caido Labs Inc.) so the interactsh client is self-contained in this plugin.

export type Result<T> =
  | { ok: true; value: T }
  | { ok: false; error: string };

export function ok<T>(value: T): Result<T> {
  return { ok: true, value };
}
export function err<T>(error: string): Result<T> {
  return { ok: false, error };
}

export const INTERACTION_PROTOCOLS = [
  "dns",
  "http",
  "https",
  "smtp",
  "smtps",
  "ldap",
  "ftp",
  "responder",
  "smb",
  "unknown",
] as const;
export type InteractionProtocol = (typeof INTERACTION_PROTOCOLS)[number];

export type ProviderKind = "interactsh";

// A single OOB interaction (DNS/HTTP/… callback) seen by the server.
export type Interaction = {
  id: string;
  sessionId: string;
  index: number;
  protocol: InteractionProtocol;
  rawRequest: string;
  rawResponse: string;
  remoteAddress: string;
  timestamp: string;
  uniqueId: string;
  fullId: string;
  qType?: string;
};

export type RegisterOptions = {
  serverUrl: string;
  correlationIdLength?: number;
  correlationIdNonceLength?: number;
  token?: string;
};

export type ProviderSession = {
  providerId: string;
  providerKind: ProviderKind;
  secretKey?: string;
  correlationId?: string;
  serverUrl: string;
  metadata?: Record<string, unknown>;
};

export type RegisterResult = {
  url: string; // a payload domain for this session
  uniqueId: string; // correlationId + nonce
  providerSession: ProviderSession;
};

export type OASTProvider = {
  readonly kind: ProviderKind;
  register(options: RegisterOptions): Promise<Result<RegisterResult>>;
  poll(session: ProviderSession): Promise<Result<Interaction[]>>;
  deregister(session: ProviderSession): Promise<Result<void>>;
};
