# ADR 001: Host-agnostic core, standalone Caido plugin as first host

Status: accepted
Date: 2026-07-25

## Decision

1. The **primary artefact is a host-agnostic detection engine** (`packages/engine`) with zero
   Caido imports, talking to an injected transport provider plus injected clock and randomness.
2. The **first host is a standalone Caido backend+frontend plugin**, not a set of checks inside
   the community `scanner` plugin.
3. The **second host is a Node fixture harness**, which is the QA strategy rather than a
   convenience.
4. Upstreaming into `caido-community/scanner` later is **explicitly not foreclosed**: the
   engine exposes a check-shaped facade that maps onto `defineCheckV2` as a thin adapter.

## Why not checks inside the community scanner

Three independent arguments were developed at full strength (upstream contribution, fully
standalone, host-agnostic core), each attacked. Upstream has genuine leverage: a shared
scheduler, cross-session dedupe, the severity workaround, staff review, store distribution,
and a multi-user test corpus. It loses on facts, not preferences.

**It is not possible as an external plugin.** `packages/backend/src/index.ts` does
`import { checks } from "./checks"` then `checksStore.register(...checks)`. Registration is an
internal call over a statically compiled array at plugin init. No cross-plugin registration API
exists. `sdk.api.register` only exposes RPC to the plugin's own frontend and the Client SDK.
Its `engine` is a private workspace package (`"name": "engine"`, `"version": "0.0.0"`,
`main: src/index.ts`), verified absent from npm. So "live inside scanner" means forking the
monorepo and shipping our own scanner build, not adding a plugin.

**Its scheduler cannot express what this algorithm requires.** Verified by grep over
`packages/engine/src` and `packages/backend/src`: zero occurrences of `429`, `Retry-After`,
`backoff`, or any rate-limit sensing. The only throttle is a static inter-request gap,
`computeDelayNeeded({now, lastRequestTime, requestsDelayMs})` in `core/request-queue.ts`.
This tool must halt on uniform 429/503/bot-challenge signatures rather than continue probing
a target that has stopped answering honestly, and must back off adaptively per host. That is
not a feature we could add locally; it is a change to a third party's shared queue.

**A high-volume adaptive check is a bad co-tenant, by construction.** `runnable/index.ts`
races the entire run against `config.scanTimeout`; on expiry it interrupts the whole session.
A single parameter costing 1500 requests can burn the shared time budget and the shared
concurrency pool on a single-threaded QuickJS backend, starving the other 71 checks and
getting the session killed as a timeout. The upstream advocate conceded this as its own
Cost C. It is structural: our workload swings 100x per parameter, and the session model
budgets globally.

Two further upstream costs are decisive for this operator specifically: every payload tweak
and false-positive fix becomes gated on a third party's review and release cadence, and there
is nothing runnable until a first merge lands.

## Why the core comes first

All three positions converged on this independently, which is the strongest signal available.
The standalone advocate arrived at it by measurement rather than principle: in the closest
prior art (`caido-community/ParamFinder` v2), the entire Caido coupling is one 88-line file
(`backend/src/engine/caido-provider.ts`) plus ~42 lines of config mapping, against 5,599 lines
of engine logic with no `caido:` imports and 4,018 lines of offline tests.

The reason this matters here more than usual: the probe catalogue we are porting is
**known to contain bugs** (verified: mismatched break/escape lengths in 23 of 42 pairs, a
cascade gate placed after the stages it was meant to skip, a corruptor that duplicates its own
output and divides by zero). Regression-testing a buggy catalogue against live third-party
bug bounty targets is both unsound and unethical. Against recorded fixtures with injected
randomness and time, it is a millisecond unit test. The offline harness is the only place
detection quality can be iterated at all, and it exists only if the core is host-agnostic.

## The interface falsifier, and how it is answered

The portable-core position named its own falsifier: if break detection needs transport-level
oracles that `send() -> {status, headers, body, time}` cannot carry, the narrow interface is a
lie.

It partly does. A connection reset or a silently dropped request **is** a signal, and the
original Java implementation's worst false-positive class came from mishandling exactly that:
it fed null responses into feature computation as though they were real, so a WAF that
consistently dropped the break payload produced a stable, confident "finding".

The interface is therefore sufficient **only if transport failures are typed values rather
than exceptions**. `send()` returns a discriminated result carrying `timeout`,
`connection-reset`, `dns`, `tls`, or `unknown`. This is a hard requirement on the seam, not a
detail: it is what converts the technique's largest false-positive source into a correctly
classified non-signal. Transport signals finer than this (socket reuse, TLS-layer timing) are
deliberately out of scope, and timing is modelled on whole-roundtrip integer milliseconds
because that is all Caido exposes.

## Consequences

- We own a scheduler with adaptive per-host backoff. Prior art to lift, both MIT and already
  Caido-native: `caido-community/crawler` `models/pool.ts` (352 lines, autoscaling slot pool)
  and `models/rateLimiter.ts` (337 lines, token bucket plus sliding window), both with tests;
  or `caido-community/autorize` `core/requests-gate.ts`, which wraps `p-queue` with combined
  concurrency and requests-per-second limiting and hot config reload.
- We own the results UI and the evidence store. Accepted deliberately: a confidence-scored
  claim ("the break set diverged from the escape set on attribute X across N interleaved
  repeats") is not renderable as a row in a generic findings list, and core Caido `FindingSpec`
  is `{title, reporter, request}` with no severity field.
- We forfeit discoverability in the scanner UI and its trace viewer. This is the real cost.
- Probe traffic sent via `sdk.requests.send()` does **not** create sitemap entries; `crawler`
  works around this with an explicit `createSitemapEntries` GraphQL mutation
  (`repositories/httpClient.ts:108`). Adopt that if scanner traffic should be visible there.
