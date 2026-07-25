# caido-backslash

A port of the detection methodology from PortSwigger's [Backslash Powered
Scanning](https://portswigger.net/research/backslash-powered-scanning-hunting-unknown-vulnerability-classes)
to TypeScript, targeting Caido.

It does not match known vulnerability signatures. For each injectable point it sends **probe
pairs**: a *break* string that should trigger a syntax error if the input reaches a server-side
interpreter, and an *escape* string that is semantically equivalent but should not. If the responses
to the break set differ consistently from the escape set, and no control arm can explain the
difference away, the input is reported as anomalously handled.

## Status

Installable as a Caido plugin, and also runnable from the command line.

| Component | State |
|---|---|
| Host-agnostic engine, zero Caido imports | working |
| Request layer: locate, splice, per-surface codecs, slot enumeration | working (multipart deferred) |
| Response admission: firewall and challenge detection, typed transport failures | working |
| Adaptive throttling with halt-on-blinded supervision | working |
| Reflection excision with bounded spans | working |
| Screening ladder S0 to S2 | working |
| Control-arm attribution and confidence grading | working |
| CLI over raw sockets | working |
| Caido plugin: backend transport, RPC, findings, context menu, results page | working |
| Permutation statistic (S4), calibration tiers, multipart surfaces | not started |

318 unit tests plus an end-to-end suite that drives the whole chain against synthetic targets.

## Install into Caido

```sh
pnpm install
pnpm run build          # -> dist/plugin.zip
```

Then in Caido: Plugins -> Install -> pick `dist/plugin.zip`. Right-click any request in HTTP History
or the request pane and choose **Backslash: scan this request**. That opens a tab showing the target
and the settings; nothing is sent until you press Start. Each scan gets its own tab, so concurrent
scans do not interfere, and each has a **Stop** button that halts it immediately — no further
requests are sent, and the partial result is kept rather than discarded.

Findings are written to Caido's own Findings page as well. Core `FindingSpec` has no severity field,
so confidence is carried in the description text — the community scanner works around the same gap
the same way.

**Every request the plugin sends is saved** to Caido's HTTP history and is inspectable and replayable
there. There is no option to turn that off. An earlier version sent probes unsaved to keep the project
database small; that was the wrong trade, because it made the scan's actual traffic invisible and left
the operator reading counters. Expect roughly 50-150 requests per parameter, so a full scan adds a few
hundred to a few thousand history entries.

The plugin also keeps its own transport log per scan, under the **Requests** tab. It shows what HTTP
history cannot: which probe and which arm each request belonged to, how the response was classified
(usable, soft-fail, hard-fail), and the reason when a firewall or rate limiter intervened. That view
holds the last 500 lines and says how many earlier ones it is not showing.

## Try it without Caido

Requires Node 23+ (for TypeScript type stripping) and pnpm.

```sh
pnpm -r test          # 318 tests
pnpm -r typecheck
```

Against the bundled deliberately-vulnerable target:

```sh
# terminal 1
MODE=vulnerable node packages/cli/testserver.ts 8099

# terminal 2
printf 'GET /search?q=widget&page=2 HTTP/1.1\r\nHost: 127.0.0.1:8099\r\nAccept: text/html\r\nConnection: close\r\n\r\n' > /tmp/req.txt
node packages/cli/src/main.ts --request /tmp/req.txt --host 127.0.0.1 --port 8099 --no-tls \
  --slot q --probe delim.backslash
```

Expected, and what the four `MODE` values demonstrate:

| MODE | Behaviour | Result |
|---|---|---|
| `vulnerable` | errors on an odd number of trailing backslashes, and echoes the input | **FIRM** finding, 22 sends |
| `clean` | echoes the input, otherwise static | no finding: differences explained by the payload delta, 12 sends |
| `noisy` | per-request nonce and random padding | no finding, 12 sends |
| `waf` | 403 with a Cloudflare marker on the break arm only | no finding: reported as **blinded**, 1 send |

The last two rows are the point. A firewall that reliably blocks the break arm produces a perfectly
reproducible difference that any statistical test would call significant; it is reported as a
blinded measurement rather than a finding. And a target that merely echoes its input differs in every
send for a reason that has nothing to do with parsing, which the payload-delta veto removes.

### Against a real target

```sh
node packages/cli/src/main.ts --request req.txt --host target.example --port 443 \
  --allow target.example --delay-ms 250 --concurrency 2
```

`--allow` is a hard allowlist enforced in the engine, not the UI. Scanning a host absent from it
fails immediately. `--delay-ms` and `--concurrency` feed the throttle; the transport backs off on
429 and `Retry-After`, and halts entirely once the recent window is mostly unusable rather than
reporting a clean bill of health it did not earn.

## Design documents

- `docs/adr/001-architecture.md` — why a standalone plugin rather than checks inside the community
  scanner, with the verified evidence.
- `docs/adr/002-request-layer.md` — why raw byte-offset splicing rather than a parse-and-rebuild
  library, including the executed verifications that decided it.
- `docs/spec/detection-core.md` — the synthesised detection specification. **Sections 1 to 5.3 were
  lost** to output truncation; see the provenance note at the top.
- `docs/spec/reconstruction.md` — recovery of those sections, with every item tagged NAMED, SOURCED
  or INFERRED so inference is not mistaken for agreed design.
- `docs/spec/request-layer.md` — the surviving request-layer spec, including a 20-entry ledger of
  executed verifications against `ts-http-forge`.
- `docs/analysis/` — the scripts that mechanically extracted and decoded the probe catalogue from
  the original Java, and their output.

## Notable divergences from the original

Found by mechanically decoding the Java catalogue rather than transcribing it, and by running the
pipeline end to end:

- **23 of 42 probe pairs, and 11 of 14 language function triples, have mismatched break/escape
  lengths.** On a reflected parameter this shifts every length-derived feature for a reason unrelated
  to parsing. Handled by excision plus a payload-delta veto, since for the backslash family equal
  length is impossible by construction.
- **The cascade's cheap abort gate sat at index 5**, so four languages were fully probed before it
  could fire. Moved to the front.
- **`corruptMagicValue` divided by zero** on an empty entry, reachable because the magic list is a
  user-editable comma-separated setting whose own description invites additions.
- **A duplicate `;`** in the transformation metacharacter list wasted one probe round per parameter.
- **The nginx-alias template produced two identical escapes** for single-character values.
- **The canary framing conflicts with end-anchored probes.** A trailing backslash is only an
  unterminated escape if nothing follows it, so those probes send no closing canary and accept
  coarser excision.
- **`echoTransformBits` cannot be a differential witness.** It describes what the server did to the
  payload, and the two arms send different payloads, so it differs by construction.

## Licence and attribution

This plugin is MIT, like the rest of the repository, **except** the probe catalogue in
`packages/engine/src/probes/catalogue.ts`, which is derived from PortSwigger's Backslash Powered
Scanner (Copyright 2016 PortSwigger Web Security, Copyright 2016 James Kettle) and is therefore
**Apache License 2.0**. The payload strings were extracted mechanically from the original Java
rather than reimplemented, so they remain substantially the original author's work.

`LICENSE-APACHE-2.0.txt` carries the licence text. `NOTICE` records what is derived, what is not,
and the significant changes made to the derived portion, as section 4(b) of that licence requires.

Everything else here — the detection engine, request layer, featurisation, admission gate,
throttling and attribution — was written from the published research and shares no code with the
Java implementation.

Reference material consulted during development (`caido-community/scanner`,
`caido-community/ParamFinder`) is MIT and no code was taken from it.
