# Cache Profiler — Probe State Machine

Design spec for the active cache-behaviour profiler. The plugin does **not** try to
deliver an autonomous "is this exploitable" verdict for web cache deception — that needs
victim context and shared-key proof a plugin can't own cleanly. Instead it characterises
**what the cache stores and how it keys it**, and hands the tester the cache rule, which
is the slow part of manual WCD/poisoning testing.

## The vulnerability, decomposed

Web cache deception only exists at the intersection of three independent conditions. The
profiler confirms each separately, then fuses them:

1. **Path confusion** — origin routing ignores an appended static-looking suffix, so
   `/account/x.css` still returns the dynamic `/account` body.
2. **Cacheability flip** — the cache layer decides to *store* that response (static-extension
   allowlist or path rule), even though the origin meant it to be `private`.
3. **Shared cache key** — the stored entry is not keyed on the auth cookie, so a different
   session retrieves it.

Only 1+2+3 = exploitable WCD. Any subset is a weaker, still-reportable signal.

## The single primitive

Every test is one operation: **double-request, then mutate one dimension and re-request.**

- `confirmCached(url)` — send twice. `MISS`→`HIT` (or `Age` increment) ⇒ this URL is cached.
  Generates its own HIT; never waits to observe one passively.
- `sharesEntry(seed, variant)` — populate `seed`, then send `variant` once. `variant` is
  `HIT` ⇒ it collided with `seed`'s entry ⇒ the mutated dimension is **not** in the cache key.

Rule classification and cache-key composition both fall out of these two.

## Phases

| Phase | Name | Action | Output |
| --- | --- | --- | --- |
| 0 | Calibrate | Fetch `/<rand>.<rand>` to fingerprint not-found / proxy-artifact behaviour | `ctrl404` baseline |
| 1 | Trigger (passive) | On any response, detect a cache signal header / `Cache-Control: public` | `CACHE DETECTED` |
| 2 | Confirm | `confirmCached(triggeringURL)` | cached? + origin `Cache-Control` from the MISS |
| 3 | Rule classify | Vary filename keeping ext (A); vary filename+ext keeping dir (B) | `[static extension | static directory | specific file | origin-directed]` |
| 3b | Extension sweep | `confirmCached(/dir/<rand>.<ext>)` over the static list | cached vs ignored extensions |
| 4 | Key composition | `sharesEntry` on query, on cookie; parse `Vary` | `CACHE KEY [...]  VARY [...]` + mismatch |
| 5 | Intent | origin `Cache-Control` vs actually-cached | `EDGE OVERRIDES ORIGIN \| ORIGIN OPTS IN \| EDGE HONORS ORIGIN` |
| 6 | Delimiter profiler | Append delimiter + `<rand>.css`; same body + cacheable? | delimiter set (path confusion) |
| gate | Deception confirm | Populate confused URL with cookie, fetch without | `leakConfirmed` |

### Phase 3 decision table

| A (same ext) | B (random ext, same dir) | verdict |
| --- | --- | --- |
| cached | not | `static extension` |
| cached | cached | `static directory` (dir supersedes) |
| not | cached | `static directory` |
| not | not | origin `Cache-Control: public` → `origin-directed`, else `specific file` |

### Phase 5 verdict — the router

```
origin private/no-store + cached  -> EDGE OVERRIDES ORIGIN   (WCD territory)
origin public/max-age   + cached  -> ORIGIN OPTS IN          (direct leak, no confusion needed)
origin private          + bypass  -> EDGE HONORS ORIGIN      (cache safe on this path)
```

This line tells the tester *which* attack applies before touching a sensitive URL. The
plugin only runs the Phase 6 delimiter matrix + deception gate when the triggering response
is itself not cached (a dynamic/authenticated candidate); for an already-cached static asset
it stops after Phase 5.

## Reported block

Rendered as Markdown (the Findings panel collapses raw whitespace): a **bold** section
title, every atomic item on its own bullet.

```markdown
**CACHE DETECTED**

- `cf-cache-status: MISS`
- `age: 0`

**CACHE RULES**

- `[static extension]`
- cached: `.css .js .png`
- ignored: `.json .html`

**CACHE KEY**

- `path`
- VARY: `Accept-Encoding`

**CACHE INTENT**

- origin: `private`
- edge: `cached`
- verdict: `EDGE OVERRIDES ORIGIN`
```

`CACHE KEY` lists empirically-confirmed key dimensions; `VARY` lists the server-declared
secondary key.

## Extension sweep is status-agnostic

The sweep probes `/<rand>.<ext>` and records a cache HIT regardless of status code — a cached
`404` for `.css` still proves the edge keys on the extension. The `looksLikeControl404`
baseline filter is therefore used **only** in the Scenario B path-confusion matrix (where a
real `200` body match matters), never in rule classification. Caveat: on CDNs that cache
purely by origin `Cache-Control` and only for `200`s (e.g. Fastly/Varnish, signalled by
`x-cache`), random non-existent files won't cache, so the sweep reports the result honestly
as `origin-directed` rather than inventing an extension allow-list. A declared `Vary: Cookie` that is **not** in the observed key is flagged as a
mismatch — the high-value cross-user-serving case.

## Safety rails

- Every probe uses a **random unique** segment → only URLs no real user visits get populated
  (non-destructive; no poisoning of live assets).
- Phase 0 `ctrl404` baseline guards against the Caido crafted-URL artifact and negative
  caching being read as a real cache rule.
- The active profiler is **scope-gated** (`sdk.requests.inScope`) and **manual-trigger only**.
  Passive Phase 1 sends nothing.
- Phase 3 sweep + Phase 6 matrix run sequentially. `REQUEST_DELAY_MS` (in `profiler.ts`)
  throttles when targets are rate-limited / bot-protected.

## Operator gate

The "ask for a sensitive URL" gate is realised by *which request the operator right-clicks*:
trigger on a static asset to characterise the cache rule; trigger on a sensitive/authenticated
request to additionally run the delimiter matrix and the cross-session leak confirmation.
