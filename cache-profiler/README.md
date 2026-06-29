# Cache Profiler

A **Caido** plugin that profiles HTTP caching behaviour for web cache deception (WCD) and
cache-rule testing. It answers the questions manual testing is slow at: **is there a cache,
what does it store, how does it key it, and where do the cache and origin disagree?**

It does **not** claim an autonomous "this is exploitable" verdict — it characterises the
cache and confirms the primitives so a human finishes the call. Full design in
[SPEC.md](./SPEC.md).

It works in two layers:

- **Passive** — a cache header is a *trigger*, not a verdict. Only a real cache-**state** signal
  (HIT/MISS or a live keyword) qualifies; infra presence (`cf-ray`, `via`, `age`,
  `cache-control`) and dead-negatives (`DYNAMIC`/`BYPASS`) are ignored. A qualifying trigger
  feeds an automatic confirmation machine that **probes** the resource, and a finding is raised
  only when probing proves it is genuinely served from cache. With confirmation disabled the
  layer stays fully read-only and emits one candidate lead per host.
- **Active** — five operator-invoked right-click commands that probe a selected request, plus
  the confirmation machine behind the passive layer.

All findings render as Markdown in Caido's Findings panel (bold section titles, one atomic
item per bullet). Configuration is live-editable from the **Cache Profiler** sidebar page — no
reload needed.

---

## Commands at a glance

| Command | Right-click on… | What it does |
| --- | --- | --- |
| **Profile cache behaviour** | a cached asset, or any request | Classifies the cache **rule**, **key**, and **intent**; on a dynamic/auth request also runs the embedded delimiter deception + leak check |
| **Delimiter detection** | a routable dynamic endpoint (`/profile`, not `/app.js`) | Finds delimiters the origin truncates at but the cache keeps, plus direct-extension / filename / cased-encoded suffix confusion, and a cross-session leak check |
| **Path normalization** | the cached static-directory or file-name resource | Tests the `..%2f` traversal discrepancy (origin-normalizes and cache-normalizes directions) |
| **Timing cache probe** | any request | Confirms caching by latency (MISS baseline vs steady RTT) when the CDN strips cache headers |
| **Cache poisoning: unkeyed headers** | any cacheable request | Batched Param-Miner-style scan: injects ~1,200 candidate request headers to find ones that reflect but are **not** in the cache key (web cache poisoning) |

All five are under right-click → **Plugins → Cache Profiler**, and in the command palette.

---

## How to use it

A typical workflow:

1. **Browse the target through Caido.** With confirmation enabled (a scope set, or
   `CACHE_PROFILER_CONFIRM=on`), cached responses are confirmed by an automatic probe and appear
   as `CACHE CONFIRMED — <host>` with a confidence (`HIGH`/`MEDIUM`/`LOW`). Without confirmation
   you get one read-only `CACHE CANDIDATE — <host>` lead per host instead. A cached **non-200**
   is tagged in the title (`[301]`, `[403]`) — those are leads in themselves (cached redirect /
   sensitive error).

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

> Tip: set `CACHE_PROFILER_SCOPE` (in the sidebar **Cache Profiler** page or as an env var) to
> your target. Doing so both scopes the passive layer to those hosts **and** enables active
> confirmation. The five right-click commands are always gated on Caido scope.

---

## Passive detection

A header signal is a **trigger**, not a verdict. This is the core change that keeps the panel
clean on mass-probe / heavy-traffic targets: a header that merely says "a CDN is in the path"
or "this is cacheable" no longer produces a finding.

**What triggers** (state-bearing only):

- A real **HIT/MISS** state from a status-bearing header — `cf-cache-status`, `x-cache`,
  `x-cache-hits` (numeric), `x-varnish` (two IDs = HIT), `cache-status` (RFC 9211),
  `akamai-cache-status`, `x-cache-status`, `x-cache-lookup`, `x-proxy-cache`, `x-drupal-cache`,
  `x-litespeed-cache`, `x-rack-cache`, `x-spip-cache`, `x-nginx-cache`, `x-fastcgi-cache`,
  `x-srcache-fetch-status`/`-store-status`, `x-vercel-cache`, `x-nextjs-cache`, `x-now-cache`,
  `x-cdn-cache`/`-status`, `x-edge-cache`/`-status`, `x-cacheable`, `x-magento-cache-debug`,
  `x-nc`, `x-tt-cache`, `x-bdcdn-cache-status`, `x-ws-cache-status`.
- A whole-token cache **keyword** (`HIT` / `MISS` / `EXPIRED` / `STALE` / `REVALIDATED` /
  `UPDATING`) in an **unrecognised** header. Whole-token matching means `TCP_HIT` and
  `Hit from cloudfront` match but `whitelist` does not.

**What does NOT trigger** (was the old false-positive flood):

- **Presence markers** — `cf-ray`, `via`, `age`, `x-served-by`, `x-amz-cf-pop`/`-id`,
  `x-azure-ref`, … These prove a CDN is in path, not that anything is cached. They are still
  collected as *context* and attached to a confirmed finding.
- **Directives** — `cache-control` (public/max-age) and `vary` describe cacheability/keying,
  not state.
- **Dead-negatives** — `DYNAMIC` / `BYPASS`. An identical resend cannot transition them, so
  there is nothing to confirm.

### Confirmation state machine

A trigger doesn't raise a finding — it enqueues an active probe that confirms whether the edge
*actually stores and serves* this resource. The machine is `v0 → resend → control`, sending **at
most two requests** and short-circuiting the moment the verdict is decided:

1. **v0** — the intercepted response (free). `DYNAMIC`/`BYPASS` ⇒ dropped. Already-warm
   (`HIT`/`Age`/hit-counter) ⇒ skip the resend.
2. **resend** — an identical request; looks for the transition `MISS → HIT` / `Age++` /
   `x-cache-hits++`. No transition ⇒ **not cached**, silent.
3. **control** — one request with a unique query cache-buster. A clean **MISS** ⇒ the cache
   keys on the query and stored the real URL (`HIGH`). A **HIT** ⇒ query unkeyed or catch-all,
   still detected but degraded (`MEDIUM`/`LOW`).

Only a confirmed result is emitted:

```markdown
**CACHE CONFIRMED — HIGH confidence**

- verdict: edge served this resource from cache (confirmed by active probe)
- status: `200`
- cache keys on query: yes — unique buster MISSed (clean key)
- `cf-cache-status: HIT`
```

`not-cached` and `dead` outcomes raise **nothing** — that is the flood fix.

### Bounded, controllable probe traffic

Confirmation sends traffic, so it is governed:

- **Opt-in** — runs when a scope is set, or `CACHE_PROFILER_CONFIRM=on`. No scope and no
  override ⇒ confirmation is off and the layer is read-only (candidate mode below).
- **Deduped by cache-key** — one probe per resource per session.
- **Rate-limited** — `CACHE_PROFILER_RATE` resources/min (default 30; each ≤ 2 requests).
- **Capped** — `CACHE_PROFILER_MAX` total per session (default 200).
- **Self-skipping** — probes carry an `X-Cp-Probe` header the interceptor ignores (no loop).
- **Self-halting** — three consecutive `429`/`503` halt the queue; clear it with **Resume** on
  the settings page.

### Candidate mode (confirmation disabled)

With no scope and no `CONFIRM=on`, the layer never probes. It emits **one** read-only
`CACHE CANDIDATE — <host>` lead per host, listing the trigger and context headers — enough to
know a cache exists without flooding or sending anything.

**Status code** is captured and, for a confirmed non-200, annotated (cached redirect /
sensitive error / negative caching / server error) and added to the finding title.

**Dedupe granularity** (`CACHE_PROFILER_DEDUPE`) — applies to the confirmed-finding key:

- `smart` (default) — static assets (css/js/images/fonts, by content-type or extension)
  collapse to one finding per host; dynamic responses (html/json/xml/no-extension) are kept
  **per path** so a cached `/account` isn't masked by a cached `.css`.
- `host` — one finding per host (aggressive; for massively-cached targets).
- `path` — one finding per host:path (granular; for sparse caches, miss nothing).

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

## Command: Cache poisoning — unkeyed headers

On-demand web cache poisoning (Param Miner style): finds request headers that **change the
response but are not in the cache key**, so a value injected once is stored and served to other
users. Run it on a cacheable request. Operator-invoked only — never automatic, never passive.

**Safety — every probe uses a unique `cpb=<rand>` query cache-buster**, so the only cache
entries ever populated are keyed to throwaway URLs no real user visits.

1. **Preflight** — confirms the resource is cacheable under a buster, then sends a *second*
   fresh buster and checks it isn't already served from cache. If the cache **ignores the query
   string** (so a buster cannot isolate a probe), the scan **ABORTS** rather than risk poisoning
   the live entry served to other users.
2. **Batched detection** — injects the header list **50 per request**, each header carrying its
   own canary, so one response names every reflecting header directly. A batch that reflects
   nothing is eliminated in a single request; an oversize-header rejection (`431`/`400`) splits
   the batch in half and retries (binary fallback). The full ~1,200-header list scans in **~25
   batched requests**, not ~1,200.
3. **Confirmation** — each reflecting header is re-tested **in isolation** (filters batch-context
   false positives), then a clean resend **without** the header under the same buster checks
   whether the canary persists from cache ⇒ **unkeyed + cached** = poisoning.

```markdown
**UNKEYED HEADERS — CACHE POISONING**

- target: `/`
- cacheable under buster: yes
- query buster safe (distinct key): yes
- headers tested: 1209

**UNKEYED + CACHED** (poisoning — reproduce and assess impact)
- `X-Forwarded-Host` -> reflected in header:location  (reflected in Location — open-redirect / redirect poisoning)

**REFLECTED ONLY** (keyed or not cached — leads, not confirmed poisoning)
- `X-Forwarded-Scheme` -> reflected in body
```

Reflection is searched in the **body and every response header**, and high-value sinks are
annotated (`Location` → redirect poisoning, `Access-Control-Allow-Origin` → CORS, `Set-Cookie`
→ cookie injection, body → XSS / absolute-URL lead). Results split into **UNKEYED + CACHED**
(confirmed poisoning) vs **REFLECTED ONLY** (keyed or uncached — leads). The sweep **halts after
5 consecutive `429`/`503`** (rate-limit/bot) and reports how far it got.

The header wordlist is `POISON_HEADERS` in `poison_headers.ts` — the full PortSwigger Param
Miner `resources/headers` set (deduped, request-framing headers removed), with ~33 high-value
host/URL/proto/client-IP/override vectors ordered first so an early halt still covers the best
ones.

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

### Settings page (sidebar)

The **Cache Profiler** entry in the left sidebar opens a live settings page:

- **Live status** — `mode` (active-confirm / candidate-only), `scope`, `probed / max`,
  `queued`, `halted`. Auto-refreshes while open — the quickest way to see whether confirmation
  is running or parked.
- **Five knobs** — Confirm mode, Scope, Rate, Session max, Dedupe — saved to plugin storage and
  applied to the backend **live, with no reload**.
- **Resume** — appears only when the throttle watchdog has halted probing; clears the halt.

Configuration resolves as **env vars (seed at load) → stored settings (override) → live edits**.
The env vars below still work for headless / first-run use; the page takes precedence once used.

### Environment variables

| Environment variable | Effect |
| --- | --- |
| `CACHE_PROFILER_SCOPE` | Comma-separated registrable domains (e.g. `target.com,target.dev`). Scopes **passive** processing to matching hosts **and** enables active confirmation. Unset → all hosts, confirmation off (unless `CONFIRM=on`). |
| `CACHE_PROFILER_CONFIRM` | `on` / `off` — force the confirmation machine regardless of scope. Default (unset) = auto: on when a scope is set. |
| `CACHE_PROFILER_RATE` | Resources probed per minute during confirmation (each ≤ 2 requests). Default `30`. |
| `CACHE_PROFILER_MAX` | Hard ceiling on resources probed per backend session. Default `200`. |
| `CACHE_PROFILER_NORM_PATH` | Comparer path for **Path normalization** origin testing. Default `/`. Set to a stable, non-cached dynamic endpoint (e.g. `/profile`) when `/` is a poor comparer. |
| `CACHE_PROFILER_DEDUPE` | Confirmed-finding granularity: `smart` (default), `host` (aggressive), `path` (granular). See *Passive detection*. |

The five right-click commands are always gated on **Caido scope** (`Request out of scope` if the
host isn't in scope) regardless of these variables.

---

## Safety and rate

- Probes use **random unique** path segments (or, for the poisoning scan, a unique `cpb=` query
  buster) → non-destructive cache population, no poisoning of live assets. Two cases that would
  be unsafe are **detected and refused** rather than executed: file-name normalization on a
  normalized-keying cache, and the unkeyed-header scan when the cache ignores the query string
  (so a buster cannot isolate the probe).
- **Passive confirmation traffic is bounded**: opt-in (scope / `CONFIRM=on`), deduped to one
  probe per resource per session, rate-limited (`CACHE_PROFILER_RATE`, default 30/min), capped
  (`CACHE_PROFILER_MAX`, default 200), and auto-halted after three consecutive `429`/`503`
  (clear with **Resume**). Worst case is two requests per resource.
- Active commands run **sequentially**. Raise `REQUEST_DELAY_MS` in
  `packages/backend/src/probe.ts` to throttle rate-limited / bot-protected targets, and stop if
  you see uniform `429` / challenge responses.
- A full Profile / Delimiter run is ~50–80 requests; Timing cache probe ~10; the unkeyed-header
  poisoning scan ~25–35 (batched) plus 2 per reflecting header. Active probing is
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
  cache.ts       pure logic: cacheState/cacheStatus, hitsOf, passiveTrigger (state-bearing
                 only), keyword net, Cache-Control & Vary parsing, content-type classifier
  probe.ts       shared probing primitives: send + roundtrip, confirmCached, sharesEntry,
                 two-anchor classifier, PROBE_MARKER (self-traffic header)
  confirm.ts     passive confirmation state machine (v0 -> resend -> control) + bounded
                 ConfirmQueue (dedupe, rate limit, session cap, 429/503 halt, resume, stats)
  config.ts      live mutable RuntimeConfig: env seed, merge, effectiveConfirm, scope/dedupe
  profiler.ts    Profile cache behaviour — rule / key / intent state machine + deception gate
  delimiter.ts   Delimiter detection — anchors, delimiter map, suffix-confusion matrix, leak
  normalize.ts   Path normalization — origin/cache traversal directions, file-name poison guard
  timing.ts      Timing cache probe — MISS baseline vs steady-state RTT
  poison.ts      Unkeyed-header scan — buster-safety preflight, batched distinct-canary
                 detection (split-on-oversize), isolate + unkeyed+cached confirmation
  poison_headers.ts  generated Param Miner header wordlist (high-value vectors first)
  store.ts       in-memory host->profile bridge (shares cached extensions between commands)
  index.ts       passive trigger -> confirm/candidate, command registration, settings API,
                 Finding emission
  types.ts       shared types
packages/frontend/src/
  index.ts       right-click menu items, command palette entries, result toasts, settings page
  settings.ts    sidebar Cache Profiler page — live status + config form (storage + backend)
```

---

## License

[MIT](./LICENSE)
