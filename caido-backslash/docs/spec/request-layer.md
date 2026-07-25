unit. |
| Connection pinning (`RequestSendOptions.connection`) to stabilise RTT | The wrapped SDK drops the options argument `[V13]`, and pinning would serialise the ladder against `checkTimeout`. |
| `Transfer-Encoding` rewriting, chunked bodies, request smuggling probes | Chunked targets are skipped (`CHUNKED_BODY`); desync probes are state-changing and out of ROE. |
| HTTP/2, redirect following, TLS-verify bypass | Not available in the SDK; `locationHash` compensates for no-redirect-following. |
| Sending a payload the surface cannot carry, in mangled form | `json-number-value` rejects (`SURFACE_INAPPLICABLE`) rather than coercing; the rejection is evaluated over both arms at once, so it is symmetric. |
| Silent skipping of anything | Every skipped point, deferred surface, inapplicable probe, abandoned buster and abandoned parity is a named row in the single aggregated diagnostic. Silence was the prior implementation's worst failure mode. |
| Cross-target or host-level request-layer state | A check instance exists per target request; there is no sanctioned channel except `runtime.dependencies`. |
| A second diagnostic channel (`ctx.note` or similar) | Does not exist in the contract. |

---

## 9. Fact ledger

All paths are relative to a local working copy of the reference repositories.

| Tag | Fact | Source |
|---|---|---|
| V1 | forge `trim()` blank-line predicate treats SP/TAB/VT/FF/CR/latin1 0xA0 as blank; `a\r\r\nb` does not round-trip; `getBodyType()` returns `urlencoded` for `{"a":"b&c=d"}` when `Content-Type` says so | `verify.mjs` sections 1, 3, 5 (executed) |
| V2 | whitespace-only fold line: `findBodyStartIndex` = 4 vs true 6; `getBody()` length 59 vs real 9; `getHeader('content-type')` = null | `verify.mjs` section 2 (executed) |
| V3 | `+` and `" "` concatenators both arrive as a space on query surfaces | `verify.mjs` section 7 (executed) |
| V4 | `getQuery` on `?q=hello world&next=1` returns `q=hello`; `getQueryParams` returns `{"q":"hello"}` | `verify.mjs` section 4 (executed) |
| V5 | double-encoding of pre-encoded catalogue text: break 37 chars -> 61 wire bytes, `%3c` -> `%253c` | `verify.mjs` section 6 (executed) |
| V6 | `APPEND` payload = `baseValue + anchor + payload`; `PREPEND` inserts no anchor yet registers it as the highlight; cache-busting forced for COOKIE/HEADER/EXTENSION insertion points | `bulkscan/src/burp/PayloadInjector.java` `buildAttackFromProbe` |
| V7 | probe catalogue: 42 declarations, 15 templated; per-probe `prefix` APPEND/PREPEND/REPLACE and `anchor` true/false; pervasive break/escape length mismatch; PATH breaks include `x../asdfz`, `z/`, escapes include `./cow/../`; nginx alias escapes sev 8 and 7 are REPLACE; magic value is REPLACE with one payload | `extract/full_report.txt`, `extract/catalogue_lists.json` |
| V8 | with `/` reserved on a path segment: `../` -> `..%2F`, `..;/` -> `..;%2F`, `x/../xyz` -> `x%2F..%2Fxyz` | `verify.mjs` section 8 (executed) |
| V9 | forge `build()` on an LF-only body: 67 bytes in, 69 out | `verify.mjs` section 9 (executed) |
| V10 | `encodeURIComponent` leaves `!'()*-._~` and alnum raw; `decodeURIComponent` throws on `%zz`, `100%`, `%C0%AF`, `%FF`, `%`; JSON round trip reorders int-like keys, `1.0`->`1`, 20-digit int truncated, `\u0041` and `\/` unescaped; `41 FF FE 42` -> `toText` -> 8 bytes; latin1 round trip exact | `t.mjs` (executed) |
| V11 | `RequestSpec.setRaw(bytes)` converts to `RequestSpecRaw` and sends verbatim; `RequestSpecRaw(url)` parses host/port/scheme only; `setHost` does NOT update the `Host` header; `Body.toRaw(): Uint8Array`; `Response.getRoundtripTime(): number` (whole roundtrip ms) | `caido_types.txt:347-448`, `:9-31`, `:511-515` |
| V12 | `ctx.limit` is `items.slice(0, limitMap[aggressivity])`; `ctx.finding` builds `correlation.requestID` from `input.request ?? target.request` | `ref-scanner/packages/engine/src/core/check-context.ts:56`, `:91-99` |
| V13 | wrapped SDK `send: async (request: RequestSpec \| RequestSpecRaw) => requestQueue.enqueue(...)` - no options parameter; queue calls `sdk.requests.send(item.request)` with no options; timeout enforced by `Promise.race` with message `Request timeout after N seconds`; failures reject with `ScanRunnableError` and no `Request` | `ref-scanner/.../runnable/runtime.ts` `createWrappedSdk`; `core/request-queue.ts:104-161` |
| V14 | `generateCanary()` = `randomString(4 + rnd(7)) + digit`, i.e. 5-11 chars | `awu/src/burp/Utilities.java:367` |
| V15 | `RequestSendOptions.save` defaults true; "If you do not save, the request and response IDs will be set to 0" | `caido_types.txt:711-719` |
| V16 | `ctx.send` returns `err({ error })` on failure, dropping the request; `SendErr.request` is optional and never populated | `check-context.ts:41-53`, `types/check-v2.ts:54-57` |
| V17 | omitting `request` in `ctx.finding` defaults to `runtimeContext.target.request` | `check-context.ts:56` |
| V18 | prior cache-busters: query param, `Origin: https://<canary>.com`, `Via`, path `/<canary>/..<path>`, `Accept`/`Accept-Encoding`/`User-Agent` appends, custom header | `awu/src/burp/Utilities.java:1172-1210` |
| V19 | prior `encodeParam` percent-encodes only `% NUL & # SP ; + LF CR` and bytes >0x7F, applied identically to both arms | `awu/src/burp/Utilities.java:1166` |
| V20 | `ScanConfig` fields available to the adapter: `aggressivity, scopeIDs, concurrentChecks, concurrentRequests, concurrentTargets, requestsDelayMs, scanTimeout, checkTimeout, requestTimeout?, severities` | `ref-scanner/packages/shared/src/scan.ts:20-31` |

---

## 10. Build order (four commits, each independently testable)

1. `locate()` + `RequestTemplate` + CL patching, with fixtures for every `[V1]`-`[V4]`, `[V9]` case and a chunked/binary target. No network, no probes.
2. Per-surface encoders + `admits()` + `assemble()` + the identical-treatment assertions of section 3.3, run over the full catalogue x phase-one surfaces as a build-time test matrix.
3. `Transport`/`Host` ports + `FixtureTransport` + `CaidoTransport`, with the byte-assertion replay harness and the `Interrupted` propagation test.
4. Framing, parity, buster policy and TIER E, wired to the detection ladder; then the `SendRecord`/citation/REPRO path and the `evidenceRef !== target` test.