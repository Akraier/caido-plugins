# caido-reflector

Passive + aggressive parameter-reflection detector for Caido. v0.3 ships a
new state machine:

| State | Meaning |
| ----- | ------- |
| (suppressed) `NO_REFLECTION` | Canary head not found in probe response — the original passive match was a coincidence (static page literal, dictionary lookup, etc.). No finding created. |
| `REFLECTED` | Canary reflects, but **no** special character survives raw. Likely safe but worth keeping as a watch-item. |
| `ATTEMPT` | Canary reflects, some chars survive raw, but **none of them satisfy the context's break-out requirements**. |
| `CONFIRMED` | Canary reflects, raw chars include a set that breaks the reflection context (e.g. `<` + `>` in HTML body, `"` in DQ attribute, `:` in href URL, `;` in raw JS code, etc.). |

## Pipeline

1. **Passive**: `onInterceptResponse` extracts params (query / urlencoded form /
   JSON body / cookies / allow-listed headers) and substring-searches each
   value in the response body.
2. **Scan cache** (`(method, host, path, sorted-param-names)`): a page that has
   been analysed once — reflection or not — is cached and skipped on subsequent
   visits until a new param name appears.
3. **Aggressive probe** (only when passive hit): build a 15-char canary
   (`< > " ' \` \ / : ( ) { } $ ; &`), substitute it into the request via the
   appropriate source, send via `sdk.requests.send`.
4. **Validate reflection**: check that the canary head (`cAiDo<salt>`) is in
   the probe response body. If not, **suppress** (NO_REFLECTION).
5. **Detect context from the canary's location** in the probe response. JSON
   `Content-Type` overrides to `JSON_BODY` (never confirmable — JSON isn't
   browser-rendered as HTML).
6. **Survival analysis**: each test char is classified as `raw / html_entity /
   url_encode / js_escape / unicode_escape / stripped / unknown`.
7. **State evaluation** via the per-context break-out table:

| Context | Break-out sets (any one → CONFIRMED) |
| ------- | ----------------------------------- |
| `HTML_BODY` | `{<, >}` |
| `HTML_ATTR_DQ` | `{"}` |
| `HTML_ATTR_SQ` | `{'}` |
| `HTML_ATTR_UNQ` | `{>}` or `{;}` |
| `URL_ATTR_DQ` / `URL_ATTR_SQ` | `{:}` (enables `javascript:` scheme) |
| `JS_STRING_DQ` | `{"}` or `{<, /}` (`</script>`) |
| `JS_STRING_SQ` | `{'}` or `{<, /}` |
| `JS_TEMPLATE` | `` {`} `` or `{$, {}` |
| `JS_CODE` | `{;}` or `{(}` |
| `HTML_COMMENT` | `{<, >}` |
| `CSS_BLOCK` | `{<}` or `{}}` |
| `JSON_BODY` | (none — never confirmable) |

## Finding format

- **Title**: `[REFLECTED|ATTEMPT|CONFIRMED] - <full URL>` for query reflections,
  `[STATE] - <URL>  [source.name]` for body / cookie / header reflections.
- **Body** (markdown):
  - State, method, URL, parameter, baseline value, detected context.
  - **Where it reflects**: 60-char snippet around the canary in the probe
    response with `[CANARY]` placeholder.
  - **Allowed (raw)** characters list.
  - **Filtered / encoded** characters list.
  - **Stripped** characters list.
  - **Verdict** rationale: which break-out set was satisfied (or why none).
  - **Suggested PoC payload** for the matched break-out set
    (`<svg/onload=alert(1)>`, `javascript:alert(1)`, `</script>…`, `${alert(1)}`, etc.).
  - **Full character status table** with all 15 chars.
- **Dedupe key**: `reflector:v2:<method>:<host>:<path>:<source>:<param>:<context>`.
  One finding per unique tuple — second visit with the same shape silently
  updates / no duplicate row.

## Layout

```
caido-reflector/
├── manifest.json
├── package.json
├── tsconfig.json
├── scripts/{clean,pack}.js
├── packages/backend/src/
│   ├── extract.ts       # extract params
│   ├── classify.ts      # HTML/JS context classifier + isJsonContentType
│   ├── reflect.ts       # findPassiveHits — substring match per param
│   ├── probe.ts         # canary builder, survival analysis, state machine,
│   │                    # context detection, suggested payload
│   ├── substitute.ts    # substitute canary into request spec
│   ├── scan-cache.ts    # page-level dedup
│   ├── finding.ts       # render markdown finding for sdk.findings.create
│   └── index.ts         # init + onInterceptResponse orchestration
├── test/
│   ├── classify.test.ts     # context classifier + extract + isJsonContentType
│   ├── probe.test.ts        # canary + survival + state machine
│   ├── scan-cache.test.ts   # page-level dedup
│   └── integration.ts       # drives live Flask, full pipeline
└── test-target/
    ├── app.py
    └── requirements.txt
```

## Build

```sh
npm install
npm run build      # → dist/plugin.zip
```

## Test

```sh
npm test           # 46/46 unit
```

Live integration (Flask app binds 127.0.0.1:5001):

```sh
cd test-target
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python3 app.py

# in another terminal
npm run test:integration   # 17/17
```

## Roadmap

- v0.4 — Frontend log panel (live `sdk.console.log` feed inside Caido UI).
- v0.5 — Persistent scan cache (sqlite via `sdk.meta.db()`) across restarts.
- v0.6 — OAST-based blind-reflection probe (bring-your-own interactsh).
