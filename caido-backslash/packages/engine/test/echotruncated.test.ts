import { describe, expect, it } from "vitest";

import { differingFeatures, featurise } from "../src/detect/features.ts";
import { asciiBytes } from "../src/request/template.ts";
import { findBodyStart } from "../src/response/scan.ts";
import type { EngineResponse } from "../src/transport/types.ts";

/**
 * Regression: an interpreter that aborts mid-render destroys the closing canary, and that was treated
 * purely as a measurement problem. On the PortSwigger FreeMarker lab the break arm rendered
 * "...bsXXXXFreeMarker template error... / by zero" and stopped, so the closing canary never appeared,
 * every body feature was declared unreliable, and a blatant SSTI reported
 * "body-unreliable: reflected payload lost its closing canary" with zero findings. The status was 200
 * in both arms, so nothing else was admissible.
 */
const CANARY = { left: "bsab12", right: "cd34se" };

function vector(body: string, sentPayload: string) {
  const raw = asciiBytes(
    `HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: ${body.length}\r\n\r\n${body}`,
  );
  const res: EngineResponse = {
    status: 200,
    headers: new Map([["content-type", ["text/html"]]]),
    raw,
    bodyStart: findBodyStart(raw),
    roundtripMs: 7,
  };
  return featurise(res, { canary: CANARY, sentPayload });
}

describe("an echo that lost its closing canary in one arm only", () => {
  it("is a witness, and is classed with status so it survives the unreliable filter", () => {
    // Break aborted at the failing expression: nothing after the payload was emitted.
    const brk = vector(
      `<p>Hi</p>bsab12FreeMarker template error: Arithmetic operation failed: / by zero`,
      "${ 7/0 }",
    );
    // Escape rendered fully, so its closing canary is present.
    const esc = vector(`<p>Hi</p>bsab127cd34se<div>ok</div>`, "${ 7*1 }");

    expect(brk.echoState).toBe("unpaired");
    expect(esc.echoState).toBe("paired");

    const witness = differingFeatures(brk, esc).find((d) => d.name === "echoTruncated");
    expect(witness, "asymmetric truncation must be reported").toBeDefined();
    expect(witness!.breakValue).toBe("truncated");
    expect(witness!.escapeValue).toBe("intact");
    // "status" is what keeps it admissible when body features are discarded as unexcisable.
    expect(witness!.featureClass).toBe("status");
  });

  it("is NOT a witness when both arms truncate, which is an app that truncates", () => {
    const a = vector("<p>Hi</p>bsab12aaaa", "${ 7/0 }");
    const b = vector("<p>Hi</p>bsab12bbbb", "${ 7*1 }");
    expect(a.echoState).toBe("unpaired");
    expect(b.echoState).toBe("unpaired");
    expect(differingFeatures(a, b).some((d) => d.name === "echoTruncated")).toBe(false);
  });

  it("is NOT a witness when both arms echo cleanly", () => {
    const a = vector("<p>Hi</p>bsab12xcd34se", "${ 7/0 }");
    const b = vector("<p>Hi</p>bsab12ycd34se", "${ 7*1 }");
    expect(differingFeatures(a, b).some((d) => d.name === "echoTruncated")).toBe(false);
  });

  it("is NOT a witness when the value is not reflected at all", () => {
    // No opening canary anywhere: "absent", not "unpaired". A blind endpoint must not look truncated.
    const a = vector("<p>generic</p>", "${ 7/0 }");
    const b = vector("<p>generic</p>", "${ 7*1 }");
    expect(a.echoState).toBe("absent");
    expect(differingFeatures(a, b).some((d) => d.name === "echoTruncated")).toBe(false);
  });
});
