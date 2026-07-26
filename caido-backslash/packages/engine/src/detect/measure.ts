/**
 * The one place a probe arm is sent.
 *
 * Every arm -- ladder replicates, the attribution re-measure, all four control arms, and the evidence
 * re-send -- goes through `measure()`. That is a correctness requirement, not tidiness.
 *
 * When an observer is configured the ladder's witnesses describe the OBSERVED response (a redirect
 * target, a second-order sink). The control arms Z0/Dz/Ds/Bd exist to attribute those witnesses to
 * something other than the payload, and they can only do that if they describe the same response. A
 * second send path that skipped observation would leave the vetoes measuring the immediate reply while
 * the witnesses measured the redirect target, and every veto would silently stop working -- the same
 * shape of bug as the CLI's divergent copy of the suite loop, which drifted until it encoded payloads
 * differently from the engine.
 *
 * So: if you are adding a send, add it here.
 */

import { isUsable, type Admission } from "../transport/admission.ts";
import type { Observer } from "../transport/observe.ts";
import { isHalted, type ProbeTransport } from "../transport/throttle.ts";
import type { EngineRequest, EngineResponse, SendOptions } from "../transport/types.ts";
import type { Located } from "../transport/url.ts";

export interface MeasureDeps {
  readonly transport: ProbeTransport;
  /** Absent means measure the probe's own response, which is the default behaviour. */
  readonly observer?: Observer;
  /**
   * Origin and target of the probe request, so a relative `Location` can be resolved.
   *
   * An observer without a base is inert: there is nothing to resolve against, and guessing an origin
   * would risk sending probe traffic somewhere the operator never named.
   */
  readonly base?: Located;
}

export type Measurement =
  | {
      readonly kind: "ok";
      /** The response detection must featurise. The observation when there was one, else the probe. */
      readonly measured: EngineResponse;
      /** The probe's own exchange, always. Cited as evidence even when something else was measured. */
      readonly probe: EngineResponse;
      /** Hops walked to reach `measured`. Empty when the probe's own response was measured. */
      readonly via: readonly string[];
      readonly sends: number;
    }
  | { readonly kind: "halted"; readonly sends: number }
  | { readonly kind: "unusable"; readonly failure: Admission; readonly sends: number }
  /**
   * The probe was fine but the observation could not be read.
   *
   * Kept distinct from `unusable`: a target that answers probes but refuses the observation URL is a
   * configuration problem the operator can fix, whereas an unusable probe is a statement about the
   * target's tolerance. Reporting them the same way would hide a typo'd URL behind "rate limited".
   */
  | { readonly kind: "observation-unusable"; readonly detail: string; readonly sends: number };

/**
 * Send one arm and return the response to measure.
 *
 * `sends` counts every request issued, probe and observation alike, so the operator's send budget and
 * the scan's reported totals stay honest: turning observation on genuinely multiplies the traffic and
 * the counter must say so.
 */
export async function measure(
  deps: MeasureDeps,
  request: EngineRequest,
  options: SendOptions & { readonly label: string },
): Promise<Measurement> {
  const result = await deps.transport.send(request, options);
  if (isHalted(result)) return { kind: "halted", sends: 1 };
  if (!isUsable(result)) return { kind: "unusable", failure: result, sends: 1 };

  const probe = result.response;
  const base = deps.base;
  if (deps.observer === undefined || base === undefined) {
    return { kind: "ok", measured: probe, probe, via: [], sends: 1 };
  }

  const observed = await deps.observer(probe, {
    base,
    label: options.label,
    ...(options.persist === true ? { persist: true } : {}),
  });

  if (observed.kind === "halted") return { kind: "halted", sends: 2 };
  if (observed.kind === "failed") {
    return { kind: "observation-unusable", detail: observed.detail, sends: 2 };
  }
  if (observed.kind === "none") {
    // No observation applied -- e.g. this endpoint did not redirect. Measuring the probe's own
    // response is correct and keeps a mixed scan (some endpoints redirect, some do not) usable.
    return { kind: "ok", measured: probe, probe, via: [], sends: 1 };
  }
  return {
    kind: "ok",
    measured: observed.response,
    probe,
    via: observed.via,
    sends: 1 + observed.via.length,
  };
}
