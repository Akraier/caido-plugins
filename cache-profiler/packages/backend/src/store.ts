// In-memory bridge between the two commands. The Caido backend runs as a single
// long-lived process, so module state persists across command invocations within a
// session (it does NOT survive a Caido restart — re-run the profiler after one).
//
// This exists because the Findings SDK only supports get-by-request / get-by-dedupeKey,
// not "list findings for a host", so the delimiter detector cannot recover the cached
// extension list from findings — it reads it from here instead.
import type { CacheProfile, HostProfile } from "./types.js";

const store = new Map<string, HostProfile>();

// Record what the profiler learned about a host. Cached extensions accumulate (union)
// across runs so profiling several assets on the same host enriches the list.
export function rememberProfile(p: CacheProfile): void {
  const prev = store.get(p.host);
  const cachedExtensions = Array.from(
    new Set([...(prev?.cachedExtensions ?? []), ...p.cachedExtensions]),
  );
  store.set(p.host, {
    host: p.host,
    rule: p.rule,
    cachedExtensions,
    vary: p.vary,
  });
}

export function recallProfile(host: string): HostProfile | undefined {
  return store.get(host);
}
