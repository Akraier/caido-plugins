# Reconstruction of detection-core sections 1 to 5.3

The synthesised specification lost its first five sections (see the provenance note in
`detection-core.md`). This file records what has been recovered and how confident each item is,
so that implementation choices can be audited against evidence rather than guesswork.

Three confidence levels are used:

- **NAMED** — the surviving spec text references this by name, so its existence and role are
  certain even where its exact definition is not.
- **SOURCED** — recovered verbatim from a surviving proposal or judgement in the workflow
  journal, with the source given.
- **INFERRED** — my reconstruction. Not part of the agreed design. Flagged in code.

## 1. Feature vector

The surviving text names these features directly: `rttMs`, `bodyLenExact`, `maxLineLen`,
`cdcNovelty`, `cdcMissing`, `alnumFold`, `lexeme*`, `ctypeToken`, `bodyStartClass`,
`locationHash`, `echoState`, `echoTransformBits`, and a 32-way byte-class profile referred to as
`CLASS32` (section 9.5 confirms "32 class sums"). Section 10 confirms a **run-length skeleton**
is retained and that `shapeHash` and `shannonEntropy` were considered and rejected.

The closest surviving full feature list is the fourteen attributes of the BCSI proposal
(SOURCED, journal result 0), which the implementability lens ranked first:

| Feature | Kind | Computation |
|---|---|---|
| `transportOutcome` | categorical | OK / TIMEOUT / RESET / TLS_FAIL / EMPTY_BODY |
| `statusCode` | categorical | exact integer, never bucketed |
| `stableHeaderNameSet` | set | FNV-1a-32 over sorted lowercased header names |
| `stableHeaderValueDigest` | derived | FNV-1a-32 over sorted name:value, minus learned volatile headers (seeded with date, content-length, set-cookie, etag) |
| `contentTypeToken` | categorical | first Content-Type value, lowercased, truncated at `;` |
| `skeletonDigest` | derived | FNV-1a-32 over a run-length token stream, bytes classified through a 256-entry lookup into WORD / WS / STRUCT |
| `skeletonPrefixDigest`, `skeletonSuffixDigest` | derived | first 64 and last 64 emitted tokens, the latter via a 64-slot ring buffer |
| `structHistogram` | set | exact counts of `{ } [ ] < > ( ) " ' : , ; =` over the redacted body, compared as a tuple |
| `maxNestingDepth` | numeric | compared for exact equality, never by magnitude |
| `lexemePresenceBitmask` | set | Aho-Corasick over ~40 fixed lowercase error markers |
| `echoState` | categorical | from the `L` + payload + `R` canary frame |
| `echoTransformBits` | set | over the bytes between L-end and R-start: RAW_BACKSLASH, RAW_QUOTE, RAW_DQUOTE, HTML_ENTITY, ... |
| `bodyByteLength`, `tailDigest` | numeric | exact length; tail digest when the body exceeds the scan cap |
| `timeClass` | categorical | roundtrip bucketed against baseline-derived edges |

The final spec evolved this: `timeClass` became the raw `rttMs` with a 25 ms measurability floor
and sign-consistency rather than bucketing, and `cdcNovelty` / `cdcMissing` / `maxLineLen` /
`alnumFold` / `locationHash` / `bodyStartClass` were added. `locationHash` is explicitly
described as compensating for the absence of redirect following.

**INFERRED**: `cdcNovelty` and `cdcMissing` are content-defined chunking over the redacted body,
counting chunks present in the break arm and absent from every escape arm, and vice versa.
Section 9.5's "~400-entry chunk Map walk" fixes the order of magnitude of the chunk count.

Per-feature flags, all NAMED by the surviving decision rule: `valueKeyed`, `lengthSensitive`,
`ARTIFACT_SUSPECT`, `unstable`, and the derived predicate `clean(f)`. Feature **classes** are
NAMED as at least `SIZE`, `LOCAL`, `BODY-STRUCTURE`, `ECHO`, plus byte-class blocks; the FIRM
confidence rule requires witnesses spanning at least two classes.

## 2. Calibration

NAMED as two tiers, with exact request counts surviving in section 6.3:

- **TIER E**, per target request: 3 / 5 / 8 sends by aggressivity. Composed of 3/3/4 unmodified
  but cache-busted sends plus 0/2/4 WAF tripwires into a random-suffixed decoy parameter.
  Produces the volatile-header set, the per-feature medoid, and the WAF profiles.
- **TIER P**, per parameter: 4 / 6 / 8 sends. Two mini-pairs of inert `A` versus inert `B`
  (same length, different value) plus one mini-pair of `Z0` versus `ZP`; high aggressivity adds
  a specials-pad mini-pair. Produces `valueKeyed`, `lengthSensitive`, the per-feature
  within-pair noise, and the echo model.

Cascade children inherit the parameter noise model and skip TIER P entirely, which is why a
child costs 2 sends to reject (section 7.1).

## 3. Admission

Already implemented independently in `src/transport/admission.ts` before this spec arrived, and
the surviving text is consistent with it: outcome classes NAMED as
`OK | RATE | BLOCKED | ERR_TIMEOUT | ERR_OTHER` (section 9.1), an `OK_FLOOR` of 0.60 per arm, and
a censor-asymmetry rule at 0.40 versus 0.10 between arms that emits `INPUT_FILTERING`. The
asymmetry rule is the one part not yet implemented.

## 4. Length and reflection neutralisation

The highest-value mechanism in the design, and all three judges listed it first. SOURCED from the
false-positive judgement, quoted:

> Bracketed-canary reflected-span excision ... locate the echo by an L/R alnum canary pair and
> exclude those bytes from every structural, histogram, depth and lexeme computation. Excision is
> the single highest-value FP mechanism in the whole problem.

with the correction, also SOURCED:

> Bounded excision with an explicit unreliability flag: cap the redaction span at k*payloadLen,
> and on an unmatched R canary mask only the located L token and set `echoUnpaired` /
> `bodyAttributesUnreliable` instead of redacting the document tail. Unbounded rollback is itself
> an FP generator.

`CAP_SPAN = min(8 * payloadLen + 64, 4096)` survives in the threshold table with its
justification (8x covers HTML-entity and `\uXXXX` expansion; the absolute cap bounds the damage
of a lost `R` canary to 4 KiB rather than the document tail).

The second mechanism, SOURCED from the false-positive judgement, is the **payload-delta
explainability veto**: if every differing feature lies within the byte classes in which the two
payload strings themselves differ, the verdict is boring regardless of magnitude. The axiom is
quoted as "a difference explainable by the two payloads not being the same string is never
evidence", and it is noted to require nothing of the catalogue, unlike enforced wire-length
equality. Section 10 confirms mandatory equal wire length was **rejected** as a catalogue gate
because it would delete the value-preserving probe families, which is exactly what my own
catalogue extraction found: 23 of 42 pairs cannot be equalised without changing meaning.

Control arms, all NAMED by the surviving S3 stage:

| Arm | Role |
|---|---|
| `Z0` | inert baseline; both replicates must land on the escape side of every witness, else drift |
| `ZP` | baseline variant used in TIER P against `Z0` |
| `Dz` | same length as the break, no special characters. Removes length- and position-explainable witnesses |
| `Ds` | same length and same byte-class profile outside the specials. Removes punctuation-sensitivity witnesses |
| `Bd` | the break's specials double-percent-encoded. Removes byte-level firewall witnesses |

Each decoy is sent with **2 replicates** and vetoes a witness only unanimously, justified in the
threshold table: one request must never adjudicate a 12 to 26 request measurement in either
direction.

## 5.1 to 5.3 Columns, statistic, witnesses

- **Binarisation** NAMED: `columns(features, vectors) -> Column[]` (section 9.1), with discrete
  features expanded to at most the **top 4 label-blind values**, chosen without reference to arm
  labels so the permutation null stays exact.
- **Statistic** NAMED: `maxT(columns, M, mode) -> { p, Zobs, winners, floor }`, an exact
  blocked-randomisation max-T permutation test with a Monte Carlo mode above `M = 14`. The
  attainable floor is `2 / 2^M`, giving 0.25 at M=3, 0.031 at M=6, 0.00195 at M=10.
- **Witnesses** NAMED: `witnesses(vectors, design, model) -> { C, W, crossEffect, withinNoise }`.
  A column is **consistent** when all `M` cross pairs agree in sign; a witness is the feature
  behind a consistent column. `crossEffect > withinNoise` is a relative demotion, not a
  threshold.

Note the deliberate belt-and-braces: the permutation p-value is explicitly described as "an
anti-luck gate only; the FP rate is carried by S3", so the statistic does not do the
false-positive work. The attribution vetoes do. This matters when implementing: getting the
p-value subtly wrong degrades gracefully, whereas getting a veto wrong does not.

## Genuinely unknown

- The exact bit assignments of `echoTransformBits` beyond the first four names.
- The precise definition of `alnumFold` and `bodyStartClass`.
- The chunking parameters behind `cdcNovelty` / `cdcMissing`.
- The full 32-way byte-class partition, and the `SPECIALS` set it is measured "outside" of.
- The exact `lexeme` marker list, though roughly 40 lowercase ASCII error markers is stated and
  overlaps heavily with what is already implemented in `src/response/keywords.ts`.

These are implementation freedoms, not lost requirements: the surviving text constrains their
role and their cost, and the build-time assertions in section 9.3 plus the golden corpora in 9.2
are what actually pin the behaviour down.
