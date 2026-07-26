/**
 * Measuring a response other than the probe's own.
 *
 * Template injection frequently does not render where it was injected. The payload goes into a
 * parameter, the handler stores it or bounces, and the evaluated result appears on the redirect
 * target, a profile page, a rendered preview, or a dashboard. The detector's whole premise is
 * comparing a break arm against an escape arm, and that premise holds regardless of *which* response
 * is compared -- so second-order detection needs no new statistics, only the ability to point the
 * measurement somewhere else.
 *
 * An observer therefore takes the probe's own exchange and returns the exchange that detection should
 * measure instead. Two are provided:
 *
 *   - `createRedirectObserver` follows `Location` for a bounded number of hops.
 *   - `createUrlObserver` fetches one fixed operator-supplied URL.
 *
 * ## The rule that makes this sound
 *
 * Every send site must use the SAME observer. The ladder's witnesses and the control arms
 * (Z0/Dz/Ds/Bd) that veto them have to describe the same response, or attribution compares unrelated
 * things and the vetoes stop working. That is enforced structurally: observation lives inside the one
 * `measure()` helper that every site calls, and nothing else may send a probe arm.
 *
 * ## Scope
 *
 * Redirect following is same-origin only, and not configurably otherwise. A `Location` is
 * attacker-influenceable in exactly the situations this scanner is built to find, so an automatic
 * follower that honoured a cross-host redirect would let a target redirect probe traffic -- carrying
 * the session's cookies -- to a host the operator never authorised. An operator-supplied observation
 * URL may name another host, because typing it is an explicit act, but the resolved origin is
 * reported so it can be checked against scope.
 */

import {
  asciiBytes,
  findHeader,
  rangeLength,
  sliceText,
  type RequestTemplate,
} from "../request/template.ts";
import { isUsable } from "./admission.ts";
import { isHalted, type ProbeResult } from "./throttle.ts";
import { header, type EngineRequest, type EngineResponse } from "./types.ts";
import {
  formatLocated,
  resolveLocation,
  sameOrigin,
  type Located,
  type Origin,
} from "./url.ts";

/** Status codes that carry a `Location` worth following. */
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

/**
 * Headers dropped when turning the recorded request into an observation GET.
 *
 * Body framing must go because there is no body. Conditional and range headers must go because a 304
 * or a 206 would be measured as a difference that has nothing to do with the payload.
 */
const DROP_HEADERS = new Set([
  "content-length",
  "content-type",
  "transfer-encoding",
  "content-encoding",
  "if-none-match",
  "if-modified-since",
  "if-match",
  "if-unmodified-since",
  "range",
  "expect",
]);

export type ObserveOutcome =
  | { readonly kind: "ok"; readonly response: EngineResponse; readonly via: readonly string[] }
  /** No observation applies; measure the probe's own response. */
  | { readonly kind: "none"; readonly why: string }
  /** The observation was attempted and could not be measured. Not a signal, not a finding. */
  | { readonly kind: "failed"; readonly detail: string }
  /** The transport stopped accepting work mid-observation. Must propagate, not degrade to a failure. */
  | { readonly kind: "halted" };

/** Describe a non-usable send for an operator-facing diagnostic. */
function describeUnusable(result: ProbeResult): string {
  if (result.kind === "soft-fail") {
    return result.signal === undefined
      ? `soft-fail (${result.reason})`
      : `soft-fail (${result.reason}, ${result.signal})`;
  }
  if (result.kind === "hard-fail") return `hard-fail (${result.failure})`;
  return result.kind;
}

export interface ObserveContext {
  /** Origin and target of the probe request, needed to resolve a relative `Location`. */
  readonly base: Located;
  readonly label: string;
  readonly persist?: boolean;
}

export type Observer = (
  probe: EngineResponse,
  context: ObserveContext,
) => Promise<ObserveOutcome>;

/**
 * How an observer reaches the network.
 *
 * This is the THROTTLED transport, not a raw provider. An observation is real traffic to the target:
 * it must obey the same rate limit and backoff as a probe, and it must appear in the send log, or the
 * operator's view of what the scan actually sent would understate it by half.
 */
export type ObserveSend = (
  request: EngineRequest,
  options: { label: string; persist?: boolean },
) => Promise<ProbeResult>;

/**
 * Build a GET for `to`, reusing the recorded request's headers.
 *
 * Reusing them is the point: a second-order sink is nearly always behind the session, so the Cookie
 * and Authorization headers have to come along or the observation measures a login page and every
 * arm looks identical. `Host` is rewritten when the observation is on another origin.
 */
export function buildObservationRequest(template: RequestTemplate, to: Located): EngineRequest {
  const eol = template.eol === "lf" ? "\n" : "\r\n";
  const lines: string[] = [`GET ${to.target} ${sliceText(template.raw, template.versionRange)}`];

  for (const field of template.headers) {
    const name = field.name.toLowerCase();
    if (DROP_HEADERS.has(name)) continue;
    if (name === "host") {
      lines.push(`Host: ${hostHeaderFor(to.origin)}`);
      continue;
    }
    // Folded headers are re-emitted verbatim, continuation lines included: rewriting them would
    // change bytes the operator recorded, and the fold itself is occasionally load-bearing.
    lines.push(sliceText(template.raw, field.lineRange).replace(/\r?\n$/, ""));
  }

  if (findHeader(template.headers, "host") === undefined) {
    lines.push(`Host: ${hostHeaderFor(to.origin)}`);
  }

  return {
    host: to.origin.host,
    port: to.origin.port,
    tls: to.origin.tls,
    raw: asciiBytes(`${lines.join(eol)}${eol}${eol}`),
  };
}

function hostHeaderFor(origin: Origin): string {
  const isDefault = (origin.tls && origin.port === 443) || (!origin.tls && origin.port === 80);
  return isDefault ? origin.host : `${origin.host}:${origin.port}`;
}

/**
 * Follow `Location` up to `maxHops`, measuring the final response.
 *
 * A non-redirect response yields `none`, which means "measure the probe's own response". That is what
 * lets the option stay on for a whole scan: endpoints that do not redirect are simply measured
 * normally, so enabling it never silently drops coverage.
 */
export function createRedirectObserver(options: {
  readonly template: RequestTemplate;
  readonly send: ObserveSend;
  readonly maxHops: number;
}): Observer {
  const maxHops = Math.max(1, Math.min(10, options.maxHops));

  return async (probe, context) => {
    if (!REDIRECT_STATUSES.has(probe.status)) {
      return { kind: "none", why: `status ${probe.status} is not a redirect` };
    }

    let current = probe;
    let at = context.base;
    const via: string[] = [];
    // Loop guard independent of the hop cap: a 2-cycle would otherwise burn the whole budget.
    const seen = new Set<string>([formatLocated(at)]);

    for (let hop = 0; hop < maxHops; hop++) {
      const location = header(current, "location");
      if (location === undefined || location === "") {
        return via.length === 0
          ? { kind: "none", why: `${current.status} without a Location` }
          : { kind: "ok", response: current, via };
      }

      const resolved = resolveLocation(at, location);
      if (resolved.kind !== "ok") {
        return via.length === 0
          ? { kind: "none", why: `Location not followable: ${resolved.detail}` }
          : { kind: "ok", response: current, via };
      }

      if (!sameOrigin(resolved.located.origin, context.base.origin)) {
        // Refusal, not a failure. Hops already walked are kept: they were legitimate same-origin
        // measurements, and discarding them would leave one arm measured at hop N and the other at
        // the probe response, which is not a comparison of anything.
        const why = `redirect leaves the origin (${formatLocated(resolved.located)}); not followed`;
        return via.length === 0 ? { kind: "none", why } : { kind: "ok", response: current, via };
      }

      const next = formatLocated(resolved.located);
      if (seen.has(next)) {
        return via.length === 0
          ? { kind: "none", why: `redirect loop at ${next}` }
          : { kind: "ok", response: current, via };
      }
      seen.add(next);

      const outcome = await options.send(
        buildObservationRequest(options.template, resolved.located),
        {
          label: `${context.label}:hop${hop + 1}`,
          ...(context.persist === true ? { persist: true } : {}),
        },
      );
      if (isHalted(outcome)) return { kind: "halted" };
      if (!isUsable(outcome)) {
        return { kind: "failed", detail: `hop ${hop + 1} to ${next}: ${describeUnusable(outcome)}` };
      }

      via.push(next);
      current = outcome.response;
      at = resolved.located;

      if (!REDIRECT_STATUSES.has(current.status)) {
        return { kind: "ok", response: current, via };
      }
    }

    // Ran out of hops still on a redirect. The last response is a real, comparable measurement, so
    // return it rather than discarding the work.
    return { kind: "ok", response: current, via };
  };
}

/**
 * Fetch one fixed URL after every probe and measure that.
 *
 * This is the stored / out-of-band case: inject at A, render at B. Note the ordering requirement it
 * imposes on the caller -- see `serialisesProbes` on the observer plan. Two probe pairs running
 * concurrently would interleave as inject(A1), inject(A2), observe(B), and the observation would
 * carry the other pair's payload. A shared mutable sink cannot be measured in parallel.
 */
export function createUrlObserver(options: {
  readonly template: RequestTemplate;
  readonly send: ObserveSend;
  readonly at: Located;
}): Observer {
  const request = buildObservationRequest(options.template, options.at);
  const where = formatLocated(options.at);

  return async (_probe, context) => {
    const outcome = await options.send(request, {
      label: `${context.label}:observe`,
      ...(context.persist === true ? { persist: true } : {}),
    });
    if (isHalted(outcome)) return { kind: "halted" };
    if (!isUsable(outcome)) {
      return { kind: "failed", detail: `observation of ${where}: ${describeUnusable(outcome)}` };
    }
    return { kind: "ok", response: outcome.response, via: [where] };
  };
}

/** Chain the two: follow the probe's redirects, then read the fixed observation URL. */
export function composeObservers(first: Observer, second: Observer): Observer {
  return async (probe, context) => {
    const a = await first(probe, context);
    if (a.kind === "failed" || a.kind === "halted") return a;
    const b = await second(a.kind === "ok" ? a.response : probe, context);
    if (b.kind === "failed" || b.kind === "halted") return b;
    if (b.kind === "ok") {
      return { kind: "ok", response: b.response, via: [...(a.kind === "ok" ? a.via : []), ...b.via] };
    }
    return a;
  };
}

export interface ObserverPlan {
  readonly observer: Observer;
  /**
   * Whether probe pairs must run one at a time.
   *
   * True whenever the measured response is a shared resource rather than this request's own
   * continuation, because concurrent pairs would otherwise read each other's writes.
   */
  readonly serialisesProbes: boolean;
  /** Human-readable description of what will be measured, for the scan log. */
  readonly describe: string;
}
