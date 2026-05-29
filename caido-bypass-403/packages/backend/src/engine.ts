import { RequestSpec } from "caido:utils";
import type { Request as CaidoRequest, Response as CaidoResponse } from "caido:utils";
import type { SDK } from "caido:plugin";

import { MARKER_HEADER, DEFAULT_PATH_MUTATIONS } from "./defaults.js";
import type {
  BackendEvents,
  BypassJobDone,
  BypassJobStart,
  BypassResultRow,
  BypassSettings,
} from "./types.js";

type EngineSDK = SDK<never, BackendEvents>;

type Variation = {
  kind: "header" | "path";
  variation: string;
  detail: string;
  apply: (spec: RequestSpec) => void;
};

const interestingStatus = (status: number, baseline: number): boolean => {
  if (status === baseline) return false;
  if (status >= 200 && status < 400) return true;
  if (status === 401 || status === 403 || status === 404) return false;
  return true;
};

const lengthOf = (response: CaidoResponse | undefined): number => {
  if (response === undefined) return 0;
  const body = response.getBody();
  if (body === undefined) return 0;
  return body.toRaw().length;
};

const buildSpecFromRequest = (req: CaidoRequest, jobId: string): RequestSpec => {
  const spec = req.toSpec();
  spec.setHeader(MARKER_HEADER, jobId);
  return spec;
};

const buildVariations = (
  originalPath: string,
  settings: BypassSettings,
  pathMutations: typeof DEFAULT_PATH_MUTATIONS,
): Variation[] => {
  const variations: Variation[] = [];

  for (const header of settings.headers) {
    for (const ip of settings.ips) {
      variations.push({
        kind: "header",
        variation: header,
        detail: ip,
        apply: (spec) => spec.setHeader(header, ip),
      });
    }
  }

  const enabledMutations = pathMutations.filter((m) => settings.pathMutationIds.includes(m.id));
  for (const mut of enabledMutations) {
    variations.push({
      kind: "path",
      variation: "path-mutation",
      detail: mut.label,
      apply: (spec) => {
        const newPath = mut.transform(originalPath);
        spec.setPath(newPath);
      },
    });
  }

  return variations;
};

const probeOne = async (
  sdk: EngineSDK,
  baseRequest: CaidoRequest,
  jobId: string,
  variation: Variation,
  baselineStatus: number,
  baselineLength: number,
): Promise<BypassResultRow> => {
  const spec = buildSpecFromRequest(baseRequest, jobId);
  variation.apply(spec);

  const send = await sdk.requests.send(spec);
  const response = send.response;

  const status = response !== undefined ? response.getCode() : 0;
  const length = lengthOf(response);

  return {
    jobId,
    variation: variation.kind === "header" ? variation.variation : "path",
    detail: variation.detail,
    method: baseRequest.getMethod(),
    url: baseRequest.getUrl(),
    statusCode: status,
    contentLength: length,
    baselineStatus,
    baselineLength,
    interesting: interestingStatus(status, baselineStatus),
    requestId: send.request !== undefined ? send.request.getId() : undefined,
  };
};

const runPool = async <T>(
  tasks: Array<() => Promise<T>>,
  concurrency: number,
  onResult: (value: T) => void,
): Promise<void> => {
  const queue = tasks.slice();
  const workers: Array<Promise<void>> = [];
  const width = Math.max(1, Math.min(concurrency, queue.length || 1));

  for (let i = 0; i < width; i++) {
    workers.push(
      (async () => {
        while (true) {
          const task = queue.shift();
          if (task === undefined) return;
          const value = await task();
          onResult(value);
        }
      })(),
    );
  }

  await Promise.all(workers);
};

export const runBypass = async (
  sdk: EngineSDK,
  baseRequest: CaidoRequest,
  baseResponse: CaidoResponse | undefined,
  settings: BypassSettings,
  pathMutations: typeof DEFAULT_PATH_MUTATIONS,
): Promise<BypassJobDone> => {
  const jobId = `job-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
  const baselineStatus = baseResponse !== undefined ? baseResponse.getCode() : 0;
  const baselineLength = lengthOf(baseResponse);
  const variations = buildVariations(baseRequest.getPath(), settings, pathMutations);

  const startEvent: BypassJobStart = {
    jobId,
    targetUrl: baseRequest.getUrl(),
    total: variations.length,
    baselineStatus,
    baselineLength,
  };
  sdk.api.send("bypass-403:job-start", startEvent);

  let interesting = 0;
  const tasks = variations.map((v) => async () => {
    return probeOne(sdk, baseRequest, jobId, v, baselineStatus, baselineLength);
  });

  await runPool<BypassResultRow>(tasks, settings.concurrency, (row) => {
    if (row.interesting) interesting++;
    sdk.api.send("bypass-403:result", row);
  });

  const done: BypassJobDone = {
    jobId,
    interestingCount: interesting,
    totalCount: variations.length,
  };
  sdk.api.send("bypass-403:job-done", done);
  return done;
};
