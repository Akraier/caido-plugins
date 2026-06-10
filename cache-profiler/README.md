# Cache Profiler

A **Caido** plugin that profiles HTTP caching behaviour for web cache deception (WCD) and
cache-rule testing. It answers the questions manual testing is slow at: **is there a cache,
what does it store, how does it key it, and where do the cache and origin disagree?**

It does **not** claim an autonomous "this is exploitable" verdict — it characterises the
cache and confirms the primitives so a human finishes the call. Full design in
[SPEC.md](./SPEC.md).

It works in two layers:

- **Passive** — read-only, sends nothing. Flags every response that looks cached.
- **Active** — four operator-invoked right-click commands that probe a selected request.

All findings render as Markdown in Caido's Findings panel (bold section titles, one atomic
item per bullet).

---

## Commands at a glance

| Command | Right-click on… | What it does |
| --- | --- | --- |
| **Profile cache behaviour** | a cached asset, or any request | Classifies the cache **rule**, **key**, and **intent**; on a dynamic/auth request also runs the embedded delimiter deception + leak check |
| **Delimiter detection** | a routable dynamic endpoint (`/profile`, not `/app.js`) | Finds delimiters the origin truncates at but the cache keeps, plus direct-extension / filename / cased-encoded suffix confusion, and a cross-session leak check |
| **Path normalization** | the cached static-directory or file-name resource | Tests the `..%2f` traversal discrepancy (origin-normalizes and cache-normalizes directions) |
| **Timing cache probe** | any request | Confirms caching by latency (MISS baseline vs steady RTT) when the CDN strips cache headers |

All four are under right-click → **Plugins → Cache Profiler**, and in the command palette.

---

## How to use it

A typical workflow:

1. **Browse the target through Caido.** Watch the Findings panel — cached responses appear as
   `CACHE DETECTED — <host>` (and `CACHE POTENTIALLY DETECTED` when a cache keyword shows up in
   a header the plugin doesn't recognise). A cached **non-200** is tagged in the title
   (`[301]`, `[403]`) — those are leads in themselves (cached redirect / sensitive error).

2. **Characterise a cached host.** Right-click a cached request → **Profile cache behaviour**.
   Read the `Cache Profile — <host>` finding: the rule (`static extension` / `static directory`
   / `specific file` / `origin-directed`), the cache key, and the origin-vs-edge intent.

3. **Follow the rule to the right deeper test:**
   - **`[static extension]`** → note the cached extensions, then right-click a **dynamic /
     authenticated** endpoint on the same host → **Delimiter detection**. It pulls the cached
     extensions from step 2 automatically.
   - **`[static directory]`** or **file-name rule** → right-click the **cached resource** where
     the rule was found → **Path normalization**.

4. **If a host seems cached but exposes no cache headers** (you suspect it from latency) →
   right-click the request → **Timing cache probe** for an evidence-backed yes/no.

5. **Confirm and report.** A confirmed cross-session leak is titled
   `WEB CACHE DECEPTION`. Each command prints the working payload shape; apply it to the real
   sensitive endpoint you care about (the plugin proves the *primitive* on throwaway URLs — the
   sensitive target is yours to choose).

> Tip: scope the passive layer to your target with `CACHE_PROFILER_SCOPE` so the panel isn't
> noisy. The active commands are always gated on Caido scope.

---

## Passive detection

On every proxied response the plugin checks for a cache signal and, if found, emits one
Finding. Read-only — it never sends a request.

**Recognised cache headers**

- **Status-bearing** (drive the HIT/MISS verdict): `cf-cache-status`, `x-cache`,
  `x-cache-hits` (numeric), `x-varnish` (two IDs = HIT), `cache-status` (RFC 9211),
  `akamai-cache-status`, `x-cache-status`, `x-cache-lookup`, `x-proxy-cache`, `x-drupal-cache`,
  `x-litespeed-cache`, `x-rack-cache`, `x-spip-cache`, `x-nginx-cache`, `x-fastcgi-cache`,
  `x-srcache-fetch-status`/`-store-status`, `x-vercel-cache`, `x-nextjs-cache`, `x-now-cache`,
  `x-cdn-cache`/`-status`, `x-edge-cache`/`-status`, `x-cacheable`, `x-magento-cache-debug`,
  `x-nc`, `x-tt-cache`, `x-bdcdn-cache-status`, `x-ws-cache-status`.
- **Presence markers** (a cache/CDN layer is in path): `age`, `x-served-by`, `x-timer`,
  `x-cache-key`, `surrogate-key`, `cdn-cache-control`, `surrogate-control`, `x-iinfo`, `x-cdn`,
  `fastly-debug-digest`, `cf-ray`, `x-amz-cf-pop`/`-id`, `x-azure-ref`, `x-msedge-ref`,
  Akamai markers, `x-fastly-request-id`, `via`, …
- **Directives**: `cache-control` (public/private/no-store/max-age) and `vary`.

**Keyword safety net** — beyond the known list, every header value is scanned for a
whole-token cache state (`HIT` / `MISS` / `EXPIRED` / `STALE` / `DYNAMIC` / `BYPASS` /
`REVALIDATED` / `UPDATING`). Whole-token matching means `TCP_HIT` and `Hit from cloudfront`
match but `whitelist` does not. If a keyword appears in an **unrecognised** header:

```markdown
**CACHE POTENTIALLY DETECTED**

- status: `200`
- `HIT` in `x-acme-edge`  (`x-acme-edge: HIT lhr-3`)
```

When known headers fire, any unknown-header keyword hit is appended as an `also:` note so you
still learn new headers.

**Status code** is captured and, for a cached non-200, annotated (cached redirect /
sensitive error / negative caching / server error) and added to the finding title.

**Dedupe granularity** (`CACHE_PROFILER_DEDUPE`):

- `smart` (default) — static assets (css/js/images/fonts, by content-type or extension)
  collapse to one finding per `host:status`; dynamic responses (html/json/xml/no-extension)
  are kept **per path** so a cached `/account` isn't masked by a cached `.css`.
- `host` — one finding per `host:status` (aggressive; for massively-cached targets).
- `path` — one finding per `host:status:path` (granular; for sparse caches, miss nothing).

---

## Command: Profile cache behaviour

Classifies the cache on the selected request and emits a structured `Cache Profile` finding.

```markdown
**CACHE DETECTED**
- status: `200`
- `cf-cache-status: HIT`
- `age: 12`
**CACHE RULES**
- `[static extension]`
- cached: `.css .js .png`
- ignored: `.json .html`
**CACHE KEY**
- `path`
- VARY: `Accept-Encoding`
- case-insensitive key: yes (differently-cased URLs collide)
**CACHE INTENT**
- origin: `private`
- edge: `cached`
- verdict: `EDGE OVERRIDES ORIGIN`
```

| Section | Meaning |
| --- | --- |
| `CACHE DETECTED` | Response status (+ non-200 note), the cache-signal headers, and `detection: timing-inferred` if the verdict came from latency rather than headers. |
| `CACHE RULES` | Why it's stored: `static extension` (with the **cached vs ignored** extension map), `static directory`, `specific file`, or `origin-directed`. |
| `CACHE KEY` | Empirically-confirmed key dimensions (`path` / `query` / `cookie`), the declared `VARY`, a `MISMATCH` flag when a declared `Cookie` isn't actually keyed (cross-user serving), and `case-insensitive key` when an upper-cased path hits the same entry. |
| `CACHE INTENT` | The router: `EDGE OVERRIDES ORIGIN` (WCD territory), `ORIGIN OPTS IN` (direct leak, no confusion needed), `EDGE HONORS ORIGIN` (safe on this path). |
| `DELIMITERS` / `DECEPTION` | If you triggered it on a **not-cached dynamic/auth** request, it also runs the delimiter matrix and the cross-session leak check inline. |

The extension sweep is **status-agnostic** (a cached 404 for `.css` still proves the edge
keys on the extension). When the triggering URL is cached, the cached-extension list is
remembered for the host and reused by Delimiter detection.

---

## Command: Delimiter detection

Run it on a **routable dynamic endpoint** (no static extension). It finds the path-confusion
primitive: delimiters the **origin** truncates the path at but the **cache** does not.

1. **Anchors** — sends `/endpoint` (base) and `/endpoint<rand>` (error). If they're
   indistinguishable (catch-all / redirect / SPA shell), or the baseline is **already cached**
   (a static resource, no dynamic content to leak), it **aborts** with the reason.
2. **Delimiters** — probes `/endpoint<delim><rand>` for each delimiter; a nearest-anchor
   classifier yields `taken` / `not-taken` / `ambiguous`. Reported grouped:

   ```markdown
   **DELIMITERS**
   - taken: `;` `%2f`
   - not taken: `%00` `%23` `:`
   ```

3. **Deception matrix** — for taken delimiters × cached extensions, plus:
   - **direct extension** `/endpoint.css` (the original 2017 WCD — origin ignores the trailing
     extension; no delimiter needed),
   - **static-filename confusion** (`robots.txt`, `sitemap.xml`, `favicon.ico`, `sw.js`,
     `manifest.json`, `crossdomain.xml`, `.well-known/security.txt`, `index.html`),
   - **cased / encoded variants** (`.CSS`, `.cs%73`, `%2ecss`) retried only when the plain
     `.ext` misses, to catch parser discrepancies (bounded to the first two extensions).

   A hit requires the response to **both** still resolve to the base content **and** get
   cached.
4. **Leak check** — if the baseline carried auth, it populates with the cookie then fetches
   without → `[LEAK CONFIRMED]`; otherwise `[CANDIDATE]`.

Anything cached as a **3xx / 401 / 403** on a confused path is flagged under
`CACHED NON-200` (cached open-redirect / sensitive error). A delimiter discrepancy is a
routing-stack property — characterise it once, apply it to a sensitive endpoint. Run **Profile
cache behaviour** on a static asset first so the cached-extension list is accurate; otherwise a
default set is used. The wordlist is `DELIMITER_PROBES` in `delimiter.ts` (tunable).

---

## Command: Path normalization

For a `[static directory]` or **file-name** cache rule. Run it on the **cached resource** where
the rule was detected. Tests both directions of the cache-vs-origin `..%2f` disagreement;
**rule type is auto-detected**.

- **Cache side** (rewrites of the same request): confirms the `/<prefix>` rule, and checks
  whether `/<prefix>/..%2f<rest>` stays cached (cache keeps the raw path) and whether the
  fully-encoded `%2f%2e%2e%2f` form stays cached (cache resolves the traversal).
- **Origin side**: tests whether the origin decodes `%2f` + resolves `..`, against a comparer
  path (default `/`, override with `CACHE_PROFILER_NORM_PATH`). Tries four encodings —
  2nd-slash, both-slashes, dots, full — and reports which the origin resolved.

**Verdict A — origin normalization** (directory rules only): origin resolves the traversal
**and** the cache keeps the raw path ⇒ `/<prefix>/..%2f<dynamic-path>`.

**Verdict B — cache normalization** (directory and file-name): cache resolves `%2f%2e%2e%2f`,
origin does not, **and** a delimiter exists that the origin truncates but the cache keeps ⇒
`/<dynamic-path><delim>%2f%2e%2e%2f<target>`. The command hunts that delimiter and confirms the
combined payload end-to-end.

- **Directory rules** resolve Direction B to a *random* path under the prefix, so it's
  poison-safe regardless of cache keying.
- **File-name rules** (`/index.html`, `/robots.txt`, …) run **Direction B only** (A can't match
  an exact name). A file name can't be randomised, so the command first checks whether the cache
  keys by the normalized path — if it does, exploiting would overwrite the real file
  (poisoning, not deception), so it **flags the risk and refuses** the confirming probe.

---

## Command: Timing cache probe

When a CDN strips `X-Cache`/`Age`, header detection is blind. The other three commands have a
**zero-extra-request** timing fallback (a HIT is faster than an origin MISS) — they read the
roundtrips of probes they already send, conservatively, and mark any timing-based verdict.
This command is the deliberate, evidence-backed version, for when you *suspect* a hidden cache:

- sends a few **cache-busted** requests (unique query each → forced origin) for a MISS baseline;
- sends the real URL repeatedly for the **steady-state** RTT;
- verdict from the ratio — steady ≤ 50% of MISS (and ≥ 15 ms faster) ⇒ **cached**; ≥ 80% ⇒
  **not cached**; between ⇒ **inconclusive**. A real `HIT` header wins outright.

```markdown
**SAMPLES (ms)**
- MISS (cache-busted): 210 198 205 220 -> median 207
- STEADY (repeated): 35 32 30 31 -> median 31
**VERDICT**
- ratio steady/miss: 0.15
- cached: cached
- confidence: timing
```

It reports every sample, both medians, the ratio, the verdict, and a confidence
(`header-confirmed` / `timing` / `low`). It is the only command whose requests exist purely to
measure latency; it is operator-invoked, never automatic, never passive.

**Timing-inferred markers** — wherever a verdict came from the fallback rather than headers,
the finding says so: `detection: timing-inferred` in the profile, and a `CONFIDENCE` block in
the delimiter / normalization findings.

---

## How it works (the one primitive)

Everything rests on: **double-request, then mutate one dimension and re-request.** Sending a
URL twice reveals caching (`MISS`→`HIT`, or `Age` increment, or — when headers are stripped — a
sharp roundtrip drop). Mutating one dimension (filename, extension, query, cookie, casing, a
path delimiter, a traversal sequence) and checking whether the mutated request still hits the
original entry reveals what the cache keys on and where it diverges from the origin. Rule
classification, key composition, delimiter confusion and normalization all reduce to that.

Every constructed probe uses a **random unique** segment, so the only URLs ever populated are
ones no real user visits — cache population is non-destructive.

---

## Settings

| Environment variable | Effect |
| --- | --- |
| `CACHE_PROFILER_SCOPE` | Comma-separated registrable domains (e.g. `target.com,target.dev`). When set, **passive** detection only processes matching hosts. Unset → all responses. |
| `CACHE_PROFILER_NORM_PATH` | Comparer path for **Path normalization** origin testing. Default `/`. Set to a stable, non-cached dynamic endpoint (e.g. `/profile`) when `/` is a poor comparer. |
| `CACHE_PROFILER_DEDUPE` | Passive finding granularity: `smart` (default), `host` (aggressive), `path` (granular). See *Passive detection*. |

The active commands are always gated on **Caido scope** (`Request out of scope` if the host
isn't in scope) regardless of these variables.

---

## Safety and rate

- Probes use **random unique** path segments → non-destructive cache population, no poisoning
  of live assets. The one exception (file-name normalization on a normalized-keying cache) is
  detected and **refused** rather than executed.
- Active commands run **sequentially**. Raise `REQUEST_DELAY_MS` in
  `packages/backend/src/probe.ts` to throttle rate-limited / bot-protected targets, and stop if
  you see uniform `429` / challenge responses.
- A full Profile / Delimiter run is ~50–80 requests; Timing cache probe ~10. Active probing is
  exploitation-adjacent — only run it on assets you are authorised to test.

---

## Build

pnpm workspace, same toolchain as the other plugins in this repo:

```bash
cd cache-profiler
pnpm install
pnpm build        # -> dist/plugin_package.zip
pnpm watch        # rebuild on change
pnpm typecheck    # type-check both packages
```

Install in Caido via **Plugins → Install Package** and select `dist/plugin_package.zip`.
(If a previous version is installed, remove it first — the plugin id is fixed.)

**Verifying the loaded build.** Every build is stamped with `PLUGIN_VERSION`. On load the
frontend shows a `Cache Profiler v<x> loaded` toast, the backend logs
`[cache-profiler] backend v<x> loaded`, the Plugins page shows the version, and every Finding
carries a `— cache-profiler v<x>` footer — so you can always confirm which build is active.
Bump `PLUGIN_VERSION` in `caido.config.ts`, `packages/backend/src/index.ts` and
`packages/frontend/src/index.ts` on each build.

---

## Layout

```
packages/backend/src/
  cache.ts       pure logic: header/status normalisation, keyword net, Cache-Control & Vary
                 parsing, content-type classifier, report formatting (no SDK — unit-testable)
  probe.ts       shared probing primitives: send + roundtrip, confirmCached (+ timing
                 fallback), sharesEntry, two-anchor classifier
  profiler.ts    Profile cache behaviour — rule / key / intent state machine + deception gate
  delimiter.ts   Delimiter detection — anchors, delimiter map, suffix-confusion matrix, leak
  normalize.ts   Path normalization — origin/cache traversal directions, file-name poison guard
  timing.ts      Timing cache probe — MISS baseline vs steady-state RTT
  store.ts       in-memory host->profile bridge (shares cached extensions between commands)
  index.ts       passive detection + command registration + Finding emission
  types.ts       shared types
packages/frontend/src/
  index.ts       right-click menu items, command palette entries, result toasts
```

---

## License

[MIT](./LICENSE)
