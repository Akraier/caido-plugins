# ADR 002: Raw byte-offset splicing for the request layer

Status: accepted
Date: 2026-07-25

## Decision

An insertion point is a **byte range in an immutable template**, plus a declared per-surface
codec. Building a probe request splices one contiguous range and patches `Content-Length`.
Nothing else in the request is ever re-serialised.

Rejected: parse-and-rebuild through `ts-http-forge`, and a lossless typed request AST.

## Why: the statistical argument

The detection verdict rests on a permutation null over M cross pairs, whose validity assumes the
break and escape sends are identical in **every respect except the payload bytes**. Any layer
that re-serialises the request can introduce a difference that correlates with the arm label, and
a label-dependent difference does not merely add noise: it fabricates a perfectly separated
witness with zero within-arm variance. That is indistinguishable from a real finding by
construction.

The parse-and-rebuild advocate stated the criterion better than I would have: *fidelity loss that
is identical in both arms is harmless; fidelity loss that is label-dependent is fatal.* It then
lost on its own criterion, because the losses are label-dependent.

## Why: the executed evidence

The debating agents wrote and ran verification scripts against the real library rather than
reasoning about it. The full ledger is section 9 of `docs/spec/request-layer.md`. The findings
that decide this:

| Tag | Finding | Consequence |
|---|---|---|
| V4 | `getQuery` on `?q=hello world&next=1` returns `q=hello`; `getQueryParams` returns `{"q":"hello"}` | Truncates at a space. Silently discards a parameter and most of a payload. |
| V5 | Pre-encoded catalogue text is double-encoded: a 37-char break becomes 61 wire bytes, `%3c` becomes `%253c` | Destroys the parameter-pollution family, whose payloads are already percent-encoded. |
| V2 | On a whitespace-only fold line, `findBodyStartIndex` returns 4 against a true 6; `getBody()` reports length 59 against a real 9; `getHeader('content-type')` returns null | Body location is wrong on a legal request. |
| V1 | `a\r\r\nb` does not round-trip; `getBodyType()` returns `urlencoded` for a JSON body when Content-Type says so | Not byte-preserving. |
| V9 | `build()` on an LF-only body: 67 bytes in, 69 out | Silently rewrites framing. |
| V3 | `+` and `" "` both arrive as a space on query surfaces | Two of six concatenators collapse. Wasted sends and a false negative. |
| V8 | With `/` reserved on a path segment, `../` becomes `..%2F` | Neuters the entire path family if encoded. |
| V10 | `decodeURIComponent` throws on `%zz`, `100%`, `%C0%AF`, `%FF`, `%` | Any decode-based handling needs guarding, not a try-free call. |

A tool whose payloads are a lone backslash, an unbalanced quote and a NUL byte cannot be built on
a layer that truncates at spaces and double-encodes percent signs.

## The typed AST: rejected but harvested

Both AST proposals were strong, and they cover far more surface than we will on day one:
base64-wrapped inner documents in cookies, JWT claim paths, header sub-grammars, matrix path
params. Rejected for cost, since it parses and renders per probe and QuickJS charges ~103
microseconds per KiB, paid on all 26 sends an accepted pair costs.

Two ideas adopted from it regardless:

- **Refuse integrity-protected surfaces.** AWS SigV4, `oauth_signature`, `X-Signature`, JWS-signed
  bodies: every arm invalidates the signature equally, so the surface degenerates to a stable 403
  after burning ~16 sends. Mark and skip, do not probe.
- **Two lengths, not one.** `semanticLen` is what the interpreter sees after decoding;
  `wireLen` is the rendered byte count. The catalogue's parity assertions are about the former;
  reflected-length artefacts are about the latter. Conflating them is itself a false-positive
  source.

## The blocker all four models found independently

`createWrappedSdk` in the community scanner defines `send: async (request) => requestQueue.enqueue(request, ...)`,
and `request-queue.ts` calls `sdk.requests.send(item.request)` with **no second argument**. The
`RequestSendOptions` bag is dropped, so `save`, `timeouts`, `plugins` and `connection` are all
unreachable through that path. Worse, because `ctx.sdk` is typed as the full `SDK`, writing
`ctx.sdk.requests.send(spec, { save: false })` **type-checks and is silently ignored**.

This independently re-validates ADR 001. The evidence plan — probe unsaved to keep thousands of
requests out of the project database, then re-send only the winning pair saved so a finding can
cite it — is *impossible* through the scanner engine, because every send is persisted and no
request can be unsaved. Standalone, we call `sdk.requests.send(raw, { save })` ourselves and both
lanes work.

It is also a reminder that a type-checking call is not a working call when the type is wider than
the implementation.

## Shape

```
locate(raw)      -> RequestTemplate     // one pass, records spans, never mutates
template.slots() -> Slot[]              // per surface, each a contiguous range + codec
assemble(t, [{ slot, wireBytes }]) -> Uint8Array   // splice + patch Content-Length
```

Surfaces on day one: query value and name, urlencoded body value, cookie value, arbitrary header
value, a zero-width new-header slot for the calibration tripwires, path segment and a zero-width
path suffix, JSON string / raw-span / number / bool / key, and multipart text parts.

`JSON_STRING` (payload JSON-escaped, testing the interpreter behind the parser) and
`JSON_RAW_SPAN` (payload spliced verbatim, deliberately invalid JSON, testing the parser itself)
share one byte range and cost no extra machinery. That second mode is unreachable through any
library serialiser and is exactly the JSON key/value cascade edge the detection spec calls for.

Deferred with a named diagnostic, never a silent skip: chunked and content-encoded bodies,
multipart file parts, nested codecs beyond one composition, XML, GraphQL, protobuf, WebSocket.

## Build order

From the surviving section 10 of the request-layer spec, four independently testable commits:

1. `locate()` + `RequestTemplate` + Content-Length patching, with fixtures for every V1-V4 and V9
   case plus a chunked and a binary target. No network, no probes.
2. Per-surface encoders + `admits()` + `assemble()` + identical-treatment assertions, run over the
   whole catalogue against phase-one surfaces as a build-time matrix.
3. `Transport` and `Host` ports + `FixtureTransport` + `CaidoTransport`, with a byte-assertion
   replay harness and an interrupt-propagation test.
4. Framing, parity, cache-buster policy and calibration, then the citation path with the
   `evidenceRef !== target.request` assertion.
