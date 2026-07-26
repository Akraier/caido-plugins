# Validation: second-order template injection behind a redirect

Confirmed against the PortSwigger Web Security Academy lab **"Server-side template injection using
documentation"** (FreeMarker), first as a live diagnosis and then as an offline reproduction.

This record exists because three of the guards in the detection core now look deliberately unusual,
and each of them is the way it is because of a specific failure observed here. Without this, all three
read like candidates for tidying up.

## The target shape

```
POST /product/template?productId=1
  csrf=...&template=<url-encoded template>&template-action=save
    -> 302 Location: /product?productId=1

GET /product?productId=1
    -> 200, the saved template rendered by FreeMarker
```

Three properties of that shape defeated the scanner, and it takes all three:

1. The payload is **evaluated one round trip later, on a shared page**. The 302 body is empty and
   byte-identical on every request, so measuring the probe's own response can never find anything.
2. **The error is rendered into the page at status 200.** There is no status difference to fall back
   on. Confirmed live: a break arm returning a full FreeMarker stack trace still answered `200`.
3. **FreeMarker aborts at the failing expression.** Everything after the payload is never emitted.

Property 3 verified directly against the live lab. Saving `probe1${7/0}tail1` and fetching the
product page returned:

```
probe1FreeMarker template error (DEBUG mode; use RETHROW in production!):
Arithmetic operation failed: / by zero
...
Caused by: java.lang.ArithmeticException: / by zero
```

`tail1` is absent. Rendering stopped at the payload, so the scanner's **closing canary was
destroyed**.

## Bug 1 — `body-unreliable` discarded the strongest available signal

This was the cause of the reported non-detection.

A destroyed closing canary means `echoState === "unpaired"`, which marks the reflected span
unboundable and therefore every body feature unexcisable. The ladder then kept only `status` and
`timing` witnesses — and by property 2 there were none. Result:

```
?  template / interp.dollar-eval: body-unreliable: reflected payload lost its closing canary,
   so body features cannot be excised
findings 0
```

Attribution is not inferred: reverting **only** this fix returns the reproduction to exactly that
line, with the other two fixes still in place.

An echo that loses its closing canary in *one arm only* is not a measurement problem. It is an
interpreter dying mid-output, which is the strongest evidence this technique can produce. Two changes:

- **`echoTruncated` is a witness**, classed with `status` so it stays admissible in precisely the case
  where body features do not.

  Safe to compare where raw `echoState` is not — and raw `echoState` genuinely is not, see
  `differingFeatures`. The parity step equalises payload lengths, so truncation at a byte limit hits
  both arms identically and an asymmetric loss cannot be a length artifact. The canaries are plain
  alphanumerics, so no escaping or filtering rule treats one arm's differently. And the control arms
  still adjudicate it: an application merely reacting to punctuation loses the canary on `Ds` and `Bd`
  as well, which vetoes the witness.

- **A lexeme witness survives the unreliable filter when its needle appears in neither payload.**
  Failed excision can only contaminate a count by leaving *payload* bytes in the body, so a keyword
  absent from both payloads is necessarily the application's own text. This is what keeps `error`,
  `exception`, `divide` — the entire content of the evidence. Dropping body witnesses wholesale threw
  away a complete Java stack trace and left nothing to report.

Result: **FIRM**, on `echoTruncated`, `kw:error`, `kw:exception`, `kw:stack`, `kw:divide`.

## Bug 2 — the existing parameter value was double-encoded, corrupting the target

`Slot.baseValue` comes from `sliceText` over the **recorded** request, so it is already in wire form.
`makeArmBuilder` concatenated it with the payload and passed the whole string through the codec,
re-encoding every percent sign.

Found by reading the live target rather than the code. The lab's product template, stored as
`%3Cp%3E...%24%7Bproduct.stock%7D`, had been re-sent as `%253Cp%253E...`, and the application had
stored the literal text `%3Cp%3E`. An earlier scan had silently replaced the product description with
percent-encoded gibberish and destroyed every `${...}` expression in it — so the field under test was
no longer even a template.

Two consequences, both bad:

- The probe lands in a context that no longer resembles the one being tested.
- On a save endpoint the corruption **persists after the scan ends**.

Only the canary-framed payload is encoded now; the existing value is spliced byte-for-byte.

No test covered this, which is why the whole suite passed while the bytes on the wire were wrong.
`test/armbuilder.test.ts` asserts on the wire bytes and was checked against the old builder, where it
fails with `q=a%2520b%2525c`.

## Bug 3 — a redirect target is not always "this request's own continuation"

The original justification for *not* serialising redirect-following was that the target is the
request's own continuation. That is false whenever the request mutates something first, and
save-then-redirect-to-view is the dominant stored-SSTI shape. The rendered page is shared state, so
concurrent pairs interleave as `save(break)`, `save(escape)`, `view`, `view`.

Redirect-following now serialises pairs for non-idempotent methods, `GET` and `HEAD` exempt. The rule
lives in the engine as `redirectObservationNeedsSerialisation` and is called by **both** the backend
and the CLI; the CLI previously had no such rule at all, which is the divergence ADR-002 exists to
prevent.

**Measured honestly: this was not what fixed detection.** With serialisation disabled the reproduction
still produced the same three findings, but spent 438 sends instead of 282 on ladder escalations
chasing contaminated replicates. It removes a real hazard and about a third of the wasted traffic. It
was not the blocker, and this document should not be read as claiming it was.

## Reproduction

Test-server mode `freemarker-stored` reproduces all three properties:

```sh
MODE=freemarker-stored node packages/cli/testserver.ts 8097

node packages/cli/src/main.ts --request fm.req --host 127.0.0.1 --port 8097 --no-tls \
  --slot "form-value template" --probe interp.dollar-eval --follow-redirects
```

Use a request whose `template` value is percent-encoded, so the run exercises the encoding fix at the
same time. Expected: `FIRM`, with an `observedVia` line naming `/product?productId=1`. Without the
bug-1 fix: `body-unreliable`, zero findings.

## Operational note

A scan of a save-style endpoint writes a probe payload on **every send**. When it finishes, the stored
value is whatever the last probe wrote — not the original. Re-save the original afterwards. During
this work the lab template was restored from the operator's own recorded save.
