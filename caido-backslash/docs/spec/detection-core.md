# Detection core specification

## Provenance and a gap you must know about

This document is the synthesis of a four-way adversarial design process: four complete
detection designs were produced independently from different methodological traditions
(coarse invariant sets, exact permutation testing, sequential/anytime-valid evidence,
robust multivariate distance), each was then attacked by a hostile reviewer using the others
as ammunition, and the survivors were judged from three separate lenses.

The three lenses **disagreed**, which is why the result grafts rather than picks a winner:

| Lens | Ranking |
|---|---|
| False-positive resistance | robust-distance, qualitative-invariant, sequential-bayes, permutation-test |
| False-negative resistance | permutation-test, qualitative-invariant, robust-distance, sequential-bayes |
| Implementability / cost | qualitative-invariant, robust-distance, permutation-test, sequential-bayes |

**Sections 1 to 5.3 of this document were lost.** The synthesising agent's returned text was
clipped to its tail, and the workflow's remaining phases died on a session limit. What survives
below, from section 5.4 onward, is intact and is the authority on thresholds, the request
schedule, the escalation contract, the evidence record, the test strategy, and the explicit
non-goals.

The lost sections covered: the feature vector (1), calibration (2), admission (3), length and
reflection neutralisation (4), and column binarisation plus the adjudication statistic
(5.1-5.3). They are **substantially recoverable**, because the surviving text cross-references
every mechanism by name, and because the four proposals and three judgements survive in full in
the workflow journal. `docs/spec/reconstruction.md` records what was recovered, from where, and
what remains genuinely unknown. Anything in this file is authoritative; anything in the
reconstruction is marked as inference and must not be mistaken for the agreed design.

---

```
M_MAX        = 14       // two adaptive extensions of 2 mini-pairs each
RTT_FLOOR_MS = 25
OK_FLOOR     = 0.60
```

```
verdict(pair, param, ep):
  // ---- S0 SCREEN, M=1, 2 sends -------------------------------------------------
  send mini-pair 1
  if not admitted(both): route to §3
  if no admissible column has d_1 != 0:            return BORING(cost 2)

  // ---- S1 FILTER, M=3, +4 sends -----------------------------------------------
  send mini-pairs 2,3
  C = { col : consistent(col) over M=3 }
  if C empty:                                      return BORING(cost 6)

  // ---- S2 ESTABLISH, M=6, +6 sends --------------------------------------------
  send mini-pairs 4,5,6
  C = { col : consistent(col) over M=6 }
  if C empty:                                      return BORING(cost 12)
  W = { feature(col) : col in C }
  r = maxT(allCols, 6)                             // floor 0.031, informational at this stage
  if r.diag === "NO_MEASURABLE_SURFACE":           return DIAG_NO_SURFACE(cost 12)

  // ---- S3 ATTRIBUTION, +6 sends (+2 conditional) ------------------------------
  // order interleaved and coin-shuffled: [Z0, Dz, Bd, Dz, Z0, Bd] (+ [Ds, Ds])
  Z0 x2, Dz x2, Bd x2  ; Ds x2 if reflected(param) or class(W) subset {BODY-STRUCTURE}
  if any arm response matches ep.wafProfiles:       return VETO_WAF_GUARD          -> Info lead
  // V-DRIFT: both Z0 replicates must land on the escape side for every witness
  drifted = { f in W : some Z0 replicate not on escape side of f }
  if drifted non-empty:
       re-baseline once (2 sends of Z0 folded into ep instability counts)
       if still drifted:                           return DIAG_DRIFT(cost 20-24)
  // V-LENGTH (L4): per-witness removal
  W = W minus { f : both Dz replicates on break side of f }
  if W empty:                                      return VETO_LENGTH_OR_POSITION
  // V-DELTA (L3): only unexplainable witnesses survive
  if all remaining W are DELTA_SUSPECT:            return VETO_PAYLOAD_DELTA
  // V-WAFBYTE (L?): unconditional
  W = W minus { f : both Bd replicates on break side of f }
  if W empty:                                      return VETO_WAF_BYTE_LEVEL     -> Info lead
  // V-SEMANTIC (L6), when sent
  W = W minus { f : both Ds replicates on break side of f }
  if W empty:                                      return VETO_PUNCTUATION_SENSITIVE
  // V-HOMOGENEITY: probes with >=2 break variants (magnitude-free, no noise denominator)
  if pair.breaks.length >= 2 and variantsSplitAcrossArms:
       run the same witness algebra between the two break sub-arms (already-sent responses, 0 extra sends)
       if that inner witness set is non-empty:      return VETO_HETEROGENEOUS_BREAKS

  // ---- S4 REPORT, M=10, +8 sends ----------------------------------------------
  send mini-pairs 7..10
  C = { col : consistent(col) over M=10 } ; W = W INTERSECT features(C)
  if W empty:                                      return BORING(cost 26-28)
  r = maxT(allCols, 10)
  if r.p > ALPHA_PAIR:
      // adaptive extension, at most twice, only in the near-miss band
      if exactly 1 or 2 cross pairs disagree on the strongest column and M < M_MAX:
           extend by 2 mini-pairs (+4 sends); recompute; repeat once
      else:                                        return SUBTHRESHOLD(r, W)      -> Info lead

  // ---- CONFIDENCE --------------------------------------------------------------
  strong(f) := clean(f) and not f.valueKeyed and not f.lengthSensitive
                        and not f.ARTIFACT_SUSPECT and not f.unstable
  FIRM     if |W| >= 2 and |classes(W)| >= 2 and exists f in W: strong(f)
  PROBABLE if exists f in W: strong(f)
  TENTATIVE otherwise                             // reported only at high aggressivity
  if W === {rttMs}: require M >= 10, consistent sign, crossEffect >= RTT_FLOOR_MS,
                    clean(rttMs) ; cap at PROBABLE ; finding type TIMING_ANOMALY
  if W subset {cdcNovelty, cdcMissing, bodyLenExact, maxLineLen}: cap at PROBABLE
  return INTERESTING(W, confidence, r, evidence)
```

### 5.4 Every threshold, justified

| Threshold | Value | Justification |
|---|---|---|
| `ALPHA_PAIR` | 0.01 | Attainable floor at `M=10` is `2/1024 = 0.00195`, so a perfectly separating witness clears with ~5x slack even when 2-4 correlated columns tie at the argmax (`p ~ 0.002-0.008` in that case would be marginal against 0.005, which is why 0.005 is *not* used). It is an anti-luck gate only; the FP rate is carried by S3. Expected luck-FPs are disclosed as `0.01 x (pairs reaching M=10)`, which after S3 attribution is « 0.1 per target. |
| consistency (all M pairs agree) | no threshold | BPS's signal is deterministic. This is the magnitude-free criterion that makes a 1-count comma change and a 40 ms delta equally reportable. It is also exactly BCSI per-feature set-disjointness for discrete features. |
| `M_SCREEN = 1` | 2 sends | Screen must be FN-averse: a single differing column in one pair promotes. The boring outcome is 90-95% of traffic and dominates total cost. |
| `M_FILTER = 3` | 6 sends | Cheapest point at which "consistent" means anything (`2/8 = 0.25` floor, no reporting). Kills one-off jitter promotions from S0 for 4 sends. |
| `M_ESTABLISH = 6` | 12 sends | 10 free within pairs, enough for `clean(f)`; floor `0.031`. Attribution decoys are only worth spending after this. |
| `M_REPORT = 10` | 20 arm sends | Smallest `M` whose floor (`0.00195`) clears `ALPHA_PAIR` with slack. `M=6` (0.031) cannot report at any effect size; `M=12` costs 4 more sends for no decision change. |
| `M_MAX = 14` | +4 or +8 | Covers the 9-of-10 / 11-of-12 case (one cache hit, one cluster node without the vulnerable build) which is the modal shape of a real effect. Extension is triggered by the **observed** disagreement count, never by an ideal p-floor (RANDOMISE's stage-C guard is keyed on the floor and therefore never fires when needed). |
| `RTT_FLOOR_MS = 25` | 25 | Guards ms quantisation and sub-noise dithering only; the stipulated 40 ms case clears it. Not a magnitude threshold on the *effect* (sign consistency is the criterion) but on measurability. |
| `OK_FLOOR = 0.60` | 0.60 | With `M=10` a group of 10 tolerates 4 censored sends before the arm is declared unusable; below that the surviving sample cannot reach `M_REPORT` anyway. |
| censor asymmetry `0.40 / 0.10` | | 4-of-10 vs 1-of-10 is the smallest asymmetry distinguishable from independent transport noise at these sample sizes; either direction triggers `INPUT_FILTERING`, because the catalogue's escapes add the dangerous byte as often as the breaks do. |
| `crossEffect > withinNoise` | relative | No constant. Zero on a quiet feature, so it cannot suppress a genuine 1-count witness; on a churning feature it demotes rather than deletes. |
| `CAP_SPAN = min(8*payloadLen+64, 4096)` | | 8x covers HTML-entity (max 6x) and `\uXXXX` (6x) expansion with margin; the absolute cap bounds the damage of a lost `R` canary to 4 KiB instead of the document tail. |
| decoy replicates = 2 | | One request must never adjudicate a 12-26 request measurement in either direction. Two replicates with a unanimity requirement per witness keeps the veto cheap while removing the single-blip failure in both polarities. |
| top-4 label-blind values per discrete feature | | Bounds column count; selecting values without reference to labels keeps the permutation null exact. |

---

## 6. Request schedule and exact counts

### 6.1 Send framing (every send, no exceptions)

* Fresh `L`/`R` canary pair (6 alnum chars each).
* Fresh cache-buster: random **fixed-length** name (8 chars) and **fixed-length** value (8 chars), regenerated per send.
* Byte-exact delivery: `RequestSpecRaw(url) + setRaw(bytes)` with caller-computed `Content-Length`, enqueued via `ctx.sdk.requests.send(raw)` (verified: `createWrappedSdk` accepts `RequestSpec | RequestSpecRaw` and routes into the queue, preserving `concurrentRequests`, `requestsDelayMs`, `requestTimeout`, interrupt propagation). `ctx.send` is typed to `RequestSpec` only, so raw sends use the wrapped SDK directly inside a wrapper that reproduces `ctx.send`'s `Result` semantics **and rethrows `ScanRunnableInterruptedError` unchanged**. `param.inject()` is used only to discover the injection point, never to carry a metacharacter payload (it routes through `HttpForge.upsertQueryParam` + `setQuery`).
* `ctx.interrupted` checked before every send and between every mini-pair.

### 6.2 Ordering discipline

* Mini-pair = 2 adjacent sends, one break one escape, order from a **seeded PRNG** coin; the coin sequence is the recorded design log and is the permutation reference.
* Mini-pairs are sent back-to-back; independent probe pairs may interleave under the engine's concurrency (pairing is temporal adjacency, **not** global serialisation — RANDOMISE's "never concurrently" discards the scheduler and turns one parameter into ~8 minutes of wall clock against `config.checkTimeout`).
* S3 decoys are coin-shuffled and interleaved with fresh `Z0`, never blocked.
* TIER-E/TIER-P baselines are interleaved by kind, never blocked.

### 6.3 Fixed overheads

| Phase | low | medium | high | Notes |
|---|---|---|---|---|
| TIER E (per target request) | 3 | 5 | 8 | 3/3/4 unmodified + cache-busted, 0/2/4 WAF tripwires into a **random-suffixed decoy parameter** |
| TIER P (per parameter) | 4 | 6 | 8 | 2 mini-pairs inert `A` vs inert `B` (same length, different value) + 1 mini-pair `Z0` vs `ZP`; high adds a specials-pad mini-pair |
| Family gate (per family, per parameter) | 2 | 2 | 2 | crude union payload for that family, S0 rule only |
| Corpus guard (before the language cascade only) | 2 | 2 | 2 | two same-shaped nonsense identifiers tested against **each other**; a non-empty witness set abandons the function cascade |

Families: `SYNTAX, NUMERIC, ORDERBY, PATH, MAGIC` — each with its own gate, so a crude-syntax rejection suppresses only that family. This is what keeps `?id=42` (integer context, where blind SQLi lives) testable; verified necessary against the catalogue, where 20 probes set `setRandomAnchor(false)` and `magic` (`:483`) is `setPrefix(REPLACE)` with a single payload and no escape string.

### 6.4 Per-probe-pair cost

| Outcome | Sends | Frequency |
|---|---|---|
| BORING at S0 | **2** | dominant |
| BORING at S1 | 6 | |
| BORING at S2 | 12 | |
| VETO/DRIFT at S3 | 18, or 20 with `Ds`, or 20-22 with one re-baseline | candidates only |
| BORING at S4 | 26-28 | |
| INTERESTING at `M=10` | **26**, 28 with `Ds` | rare |
| INTERESTING after 2 extensions | 34-36 | rare |

### 6.5 End-to-end

* Boring parameter, medium, 5 family gates, no promotions: `6 + 5x2 = 16` sends.
* Boring parameter where 2 families promote to root screens (4 root pairs each, all boring at S0): `16 + 8x2 = 32`.
* Parameter with one confirmed root and a full cascade at medium: `6 + 10 (gates) + 26 (root) + 4x2 (sibling roots) + 6x2 (concat screens) + 26 (one concat) + 2 (corpus guard) + 5x2 (function screens) + 26 (one function) = ~136` sends.
* 12-parameter endpoint, nothing interesting, medium: `5 + 12x16 = 197`.

### 6.6 Engine declaration

```
aggressivity: { minRequests: 9, maxRequests: "Infinity" }     // 9 = TIER E(3) + TIER P(4) + one family gate(2)
ctx.limit(FAMILIES,           { low: 2, medium: 5,  high: 5  })
ctx.limit(rootPairs(family),  { low: 2, medium: 4,  high: 7  })
ctx.limit(CONCATENATORS,      { low: 2, medium: 4,  high: 6  })
ctx.limit(LANGUAGE_FUNCTIONS, { low: 2, medium: 5,  high: 13 })
ctx.limit(WAF_TRIPWIRES,      { low: 0, medium: 2,  high: 4  })
```

`ctx.limit` is a plain `items.slice(0, n)` (verified), so **catalogue ordering by expected yield is load-bearing** and is asserted at build time (§9.3).

---

## 7. Escalation contract

### 7.1 What a successful pair hands down

```
PairResult = {
  probeId, family, verdict: INTERESTING, confidence,
  witnesses: [ { feature, class, breakValues, escapeValues, crossEffect, withinNoise, flags } ],
  p, M, disagreeingPairs, designLog, seed,
  learned: {
     delimiter?          // e.g. "'"  — set by root delimiter probes
     concatOperator?     // e.g. "||" — set by concatenation probes
     interpreter?        // set by language-function probes
     echoTransformBits, echoState,
     instabilityDelta    // per-feature within-pair disagreement counts, folded into the parameter model
     censorProfile       // any new waf profile learned during this pair
  }
}
```

Children **inherit** the parameter noise model (`instability`, `valueKeyed`, `lengthSensitive`, echo model, waf profiles, volatile headers) and therefore skip TIER P entirely — a cascade child costs 2 sends to reject. Children **never** inherit evidence: each child runs its own ladder from `M=1`.

Cascade edges: `family gate -> root delimiter/interpolation/escape probes -> (per confirmed delimiter) concatenation operators -> JSON key/value -> function-call parse -> language-specific function battery`. Each edge is materialised from `learned` (a concatenation probe is built from `learned.delimiter`; a function probe from `learned.delimiter + learned.concatOperator`).

### 7.2 When a stage does not escalate

| Condition | Action |
|---|---|
| verdict != INTERESTING | no children |
| confidence === TENTATIVE | record as a lead; **no children** (a cascade built on a demoted witness compounds the artefact) |
| `INPUT_FILTERING` | up to 3 encoding-bypass variants of the same probe; then the family stops. No children. |
| `INPUT_TRANSFORMED` (echo-only witnesses) | Info lead; no children — the value never reached an interpreter unmodified |
| `VETO_HETEROGENEOUS_BREAKS` or corpus guard non-empty | the **language-function cascade only** is abandoned; the parent finding stands |
| `DIAG_DRIFT`, `TARGET_UNSTABLE`, `RATE_LIMITED` | parameter stops; emitted findings stand |
| `ctx.limit` allowance exhausted, or `ctx.interrupted` | stop, emit diagnostics, return |
| `SUBTHRESHOLD` | Info lead naming the probe, the strongest column, the disagreeing-pair count, and the exact number of additional mini-pairs that would cross `ALPHA_PAIR`. No children. |

### 7.3 Finding taxonomy

| Type | Severity | Emitted when |
|---|---|---|
| `Anomalous input handling: <probe>` | Medium (root), High (with `learned.interpreter`) | INTERESTING, FIRM or PROBABLE |
| `Interpreter identified: <language>` | High | language-function probe INTERESTING |
| `Timing anomaly: <probe>` | Low (PROBABLE only) | `W === {rttMs}` |
| `Input filtering / WAF fingerprint` | Info | censor asymmetry, `VETO_WAF_GUARD`, `VETO_WAF_BYTE_LEVEL` (capped at 3 per target) |
| `Input transformed or stripped` | Info | witnesses confined to ECHO, or `echoTransformBits` divergence |
| `BPS scan diagnostics` | Info | **exactly one per target request**, always, on every exit path |

---

## 8. Per-pair record (reproducibility)

### 8.1 Retained for every probe pair

1. `probeId`, family, `injectMode` (`APPEND | PREPEND | REPLACE`), parameter name/source.
2. Every string actually sent — break variant per mini-pair, escape variant per mini-pair, `Dz`, `Ds`, `Bd`, `Z0`, gate payload — as literal text **and** hex, plus the full injected value including anchors and padding.
3. PRNG `seed` and the `designLog` (coin per mini-pair, shuffle of the S3 decoy order).
4. Per send: Caido `request.getId()`, `response.getId()`, canary pair `L`/`R`, cache-buster name/value, `admission` class, `code`, `rttMs`, `bodyLenExact`, `windowBytes`, `truncated`, `echoState`.
5. Per witness feature, a native-unit table over all M mini-pairs: `pair index | break value | escape value | diff | sign`, plus `crossEffect`, `withinNoise`, and the flags (`valueKeyed`, `lengthSensitive`, `ARTIFACT_SUSPECT`, `unstable`).
6. Decoy values for every witness: `Z0 x2`, `Dz x2`, `Bd x2`, `Ds x2`, with the side each landed on.
7. TIER-E medoid values for every witness feature.
8. `p`, `Zobs`, `winners`, `M`, `disagreeingPairs`, permutation `floor`, `null` mode (exact / Monte Carlo with draw count).
9. Verdict, confidence, and every veto that was evaluated with its outcome (including the ones that passed).
10. The **only retained body bytes**: for each newly-set lexeme bit (present in the break arm, absent from every escape and every baseline response), +/-80 bytes of surrounding context from one break response, ASCII-sanitised. This is the artifact an operator adjudicates by eye.

### 8.2 Finding wiring

`ctx.finding({ request })` is passed the **actual break `Request` object whose values are cited** in the evidence table. Omitting it silently defaults to `runtimeContext.target.request` (verified in `check-context.ts`), which is precisely the prior implementation's evidence-points-at-the-wrong-request bug. A unit test asserts `request !== target.request` for every non-diagnostic finding.

`artifacts` renders as `## <title>` + markdown bullets, so evidence is emitted as: one bullet per witness with native-unit break/escape values, one bullet per mini-pair for the strongest witness, one bullet per decoy, one bullet listing request ids, one bullet with `seed`/`designLog`, one bullet with `p`, `M`, window/truncation state.

### 8.3 The single aggregated diagnostic

One Info finding per target request, emitted on every exit path (normal, abort, interrupt), containing: parameters tested and skipped with reasons; the per-feature sensitivity table in **native units** (`feature | within-pair noise | valueKeyed | lengthSensitive | instability rate | applicable?`); `UNMEASURABLE_SURFACE` / `NO_MEASURABLE_SURFACE` / `CACHE_SUSPECTED` / `ALREADY_BLOCKED` / `TARGET_UNSTABLE` / `RATE_LIMITED` / `DIAG_DRIFT` markers; censor counts per arm; every `SUBTHRESHOLD` record with its "N more mini-pairs would decide this"; total sends spent; and the declared power floor (§10).

---

## 9. Deterministic offline testability

### 9.1 Injection boundary

```
type Deps = {
  send:   (raw: Uint8Array, url: string) => Promise<Admitted>   // the ONLY I/O
  rng:    () => number                                          // seeded, injected
  now:    () => number
  config: { aggressivity, concurrentRequests, requestsDelayMs, requestTimeout, headCap, tailCap }
  canary: () => { L: string, R: string }
  buster: () => { name: string, value: string }
  catalogue: Probe[]
}
```

No SDK type appears below the boundary. Pure modules, each independently unit-testable against recorded bytes with no network:

* `featurise(bytes, headers, code, rttMs, L, R, opts) -> FeatureVector` — pure, deterministic, no allocation in the hot loop.
* `admit(codeOrErr, vector, wafProfiles) -> OK|RATE|BLOCKED|ERR_TIMEOUT|ERR_OTHER`.
* `columns(features, vectors) -> Column[]` (binarisation).
* `maxT(columns, M, mode) -> { p, Zobs, winners, floor }`.
* `witnesses(vectors, design, model) -> { C, W, crossEffect, withinNoise }`.
* `vetoes(W, decoys, deltaProfile, model) -> { W', firedVetoes }`.
* `verdict(...) -> PairResult`.
* `renderFinding(PairResult) -> FindingInput`.

### 9.2 Golden corpora (recorded response sets, checked in)

One fixture set per adversarial scenario, each a list of raw HTTP responses keyed by the request that produced them, replayed through a scripted `send`:

`(a)` dynamic HTML with per-request CSRF/timestamp/ad-slot/A-B churn; `(b1)` hard 403 WAF, `(b2)` **soft 200 normaliser** with no block markers, `(b3)` WAF blocking the *escape* arm (backslash denylist); `(c)` 429 burst mid-measurement; `(d1)` CDN HIT/MISS alternation, `(d2)` path-only cache key (all responses identical); `(e)` minified single-line JSON with a one-field change and with a one-boolean change; `(f1)` verbatim echo, `(f2)` HTML-entity-escaped echo, `(f3)` **server-truncated echo losing the `R` canary**, `(f4)` multi-site echo (40 sites); `(g)` search endpoint whose result count reacts to punctuation; `(h)` `image/webp` and `application/octet-stream`; `(i)` two-backend alternation; plus `value-hash-keyed A/B bucket`, `3 MB body with the trace beyond the cap`, `timeout-asymmetry (SLEEP)`, and `+40 ms consistent delay`.

Required assertions per fixture: verdict, confidence, witness set, which vetoes fired, and the exact send count. **Determinism contract:** identical `seed` + identical fixture ⇒ byte-identical `FindingInput` including the evidence table. Any nondeterminism is a test failure.

### 9.3 Build-time catalogue assertions (unit tests, must fail the build)

```
for every probe p:
  p.breaks.length >= 1 and p.escapes.length >= 1                   (except REPLACE-mode magic-value probes,
                                                                     which must declare escapeless: true and
                                                                     supply an explicit corrupted-value escape)
  len(p.Dz) === len(p.breaks[0]) and charset(p.Dz) INTERSECT SPECIALS === {}
  len(p.Ds) === len(p.breaks[0]) and CLASS32-profile(p.Ds) === CLASS32-profile(p.breaks[0]) outside SPECIALS
  p.Bd === doublePercentEncodeSpecials(p.breaks[0]) or p.Bd is an authored case/comment variant with
       bdKind: "alt" recorded in the evidence
  p.equaliseLength implies the pad lands in the anchor region only (assert payload substring identity)
  charset(p.breaks[i]) SUBSET charset(p.escapes[j]) recorded as p.charsetSubset (informational; NOT a gate)
  p.family in {SYNTAX,NUMERIC,ORDERBY,PATH,MAGIC}
  p.children reference existing probe ids
  p.deltaProfile === computed byte-class delta of (breaks[0], escapes[0])    // frozen, asserted
catalogue ordering: within each family, probes are sorted by descending historical yield rank
                    (ctx.limit is a slice, so order is semantics)
no probe pair has p.Dz === p.escapes[0]                          // a decoy that collapses onto the escape is inert
```

### 9.4 Never-dead-code tests

Explicit tests that each of the following executes at least once against a fixture, because the prior implementation's worst defects were unreachable code paths: `withinNoise` learner invoked `>= 2(M-1)` times per pair; `V-DRIFT`, `V-LENGTH`, `V-DELTA`, `V-WAFBYTE`, `V-SEMANTIC`, `V-HOMOGENEITY` each firing on a fixture built to trip it; `TIMEOUT_ASYMMETRY`; opaque-content mode; `truncated` path; `echoUnpaired` path; the aggregated diagnostic on the interrupt path.

### 9.5 CPU budget

Head window 192 KiB at ~10 int ops/byte ~ 2 M ops ~ 8-20 ms in QuickJS; tail 64 KiB adds 1-3 ms; post-loop is O(256) (32 class sums) plus a ~400-entry chunk Map walk. `maxT` at `M=10` x ~80 columns ~ 82 k updates, 1-3 ms; Monte Carlo at `M=14` ~ 400 k updates, 5-15 ms. A 26-send accept costs ~0.4 s CPU against 26 roundtrips. `headCap` is halved above `concurrentRequests > 4`; a single macrotask yield (`setTimeout 0`) is taken **between** the head and tail passes only — never `await Promise.resolve()` inside the byte loop, which neither releases the host loop nor preserves the zero-allocation property.

---

## 10. Deliberately not doing

| Not doing | Why |
|---|---|
| Holm / Benjamini-Hochberg / any scan- or parameter-wide multiplicity correction | Makes verdicts non-local and order-dependent (classifying the interpreter unreports the root), requires buffering findings past the interrupt path, and is untestable in units. Replaced by a fixed per-pair alpha plus a disclosed expected-FP count. |
| e-processes, Jeffreys credible bounds, dual type-I/type-II martingales | Beta-quantile numerics with no oracle in QuickJS, and the published constants are self-inconsistent in the never-fires direction (weighted-average `e_I < 1` on single-attribute crossings, so `E_I` decays on real findings; `E_ctrl` decaying ~65x per block). |
| MAD-scaled effect sizes, `QUANT` floors, `D1/D2/D1H` magnitude thresholds | On integer counters `pooled >= QUANT = 1` makes `d` the raw count difference, so `d >= 6` means "differ by 6" and rejects the deterministic 1-count signal this tool exists to find. |
| Echo-slope estimation and subtraction (`slopeHat`, `mHat`, `sHat`, `bodyLenResidual`) | A 2-4 point slope has enough error to inject a constant per-arm offset with zero within-arm variance, i.e. a perfectly separated artefact created by the correction. Replaced by excision + `ZP` + `Dz` + delta-explainability. |
| Mandatory equal wire length as a catalogue admission gate | Deletes the value-preserving families (`iterable`, `div0`, `dotSlash`, `procedure`, nginx alias, `magic`) — i.e. integer-context SQLi and path manipulation. |
| Padding inside the syntactic payload | Turns `unichr(49)` into a TypeError and zeroes the language cascade. |
| Byte-multiset-rearrangement control arm | Unconstructible for single-metacharacter breaks; forces every delimiter finding to Info. |
| Re-adding the break's distinguishing character to the escape as a filter test | Reconstructs an unbalanced string and demotes true positives. |
| Nearest-medoid bimodality veto | A real effect also splits the arms perfectly by cluster label. Two-form backends are absorbed by the randomisation null instead. |
| Feature deletion / column freezing at baseline | Is the prior implementation's silent-shutdown failure. Replaced by flags that raise the bar plus a published sensitivity table. |
| Abandoning a parameter for a thin or noisy surface | Replaced by `UNMEASURABLE_SURFACE` + all findings capped at TENTATIVE. Never a silent boring, never a silent abandonment. |
| Mid-body window segment | Its anchor is length-dependent, therefore label-dependent. Head + tail only. |
| `shapeHash` (byte-class + run-length buckets) | Strictly dominated by the run-length skeleton, which collapses nonce runs to one token over the whole window with no bucket-boundary flip mode. |
| `shannonEntropy` as a decision feature | Moves in the third decimal for realistic changes and costs 256 `Math.log` calls; its only useful role (detecting an undecoded compressed body) is covered by `ctypeToken` + `bodyStartClass`. |
| WAF/block markers as decision features | Admitting them manufactures WAF findings. Triage only. |
| Any regex, `toText()`, or string slicing over a response body | Known QuickJS performance trap; all tables are flat typed arrays built at module load. |
| Workers / parallel featurisation | Single-threaded runtime, no workers. |
| Cross-target or host-level state ("stop probing the host after N aborts") | A check instance exists per target request; there is no sanctioned channel except `runtime.dependencies`. |
| `ctx.note` or any second diagnostic channel | Does not exist in the contract. |
| TTFB / connect / TLS decomposition, and any timing claim below 25 ms | The SDK exposes whole-roundtrip integer ms only. |
| HTTP/2, redirect following, TLS-verify bypass | Not available; `locationHash` compensates for no-redirect-following. |
| Translating `DiffingScan.java` / `TransformationScan.java` | The methodology is re-derived. `TransformationScan` survives only as `echoTransformBits` + the `INPUT_TRANSFORMED` finding type, not as a separate scan. |
| Exploitation, state change, or data extraction beyond the differential | Out of scope by ROE; the output is a confidence-scored claim of anomalous input handling plus whatever class the cascade reached. |
| Detecting effects present in fewer than ~100% of sends | **Declared power floor.** The consistency criterion requires every one of `M` cross pairs to agree (up to two disagreements recoverable via extension to `M=14`). Effects present in under ~85% of sends are systematically missed and surface as `SUBTHRESHOLD` leads, never as findings. Stated in the check description and in every aggregated diagnostic. |
| Detecting a value-only change invisible to `alnumFold`, `cdc*`, `lexeme*` and `bodyLenExact` | Acknowledged irreducible blind spot of differential detection (e.g. a same-length, same-alnum-sum substitution). |
| Generating the hypothesis | This design ranks and validates probe pairs; it cannot invent one. Coverage limits belong to the catalogue, not the statistics. |