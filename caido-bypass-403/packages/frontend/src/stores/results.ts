import { reactive, readonly } from "vue";

import type { JobMeta, ResultRow } from "../types";

type State = {
  rows: ResultRow[];
  jobs: Map<string, JobMeta>;
};

const state = reactive<State>({
  rows: [],
  jobs: new Map(),
});

const MAX_ROWS = 5000;

export const resultsStore = {
  state: readonly(state),

  registerJob(meta: JobMeta): void {
    state.jobs.set(meta.jobId, meta);
  },

  finishJob(jobId: string, interestingCount: number, doneAt: number): void {
    const meta = state.jobs.get(jobId);
    if (meta === undefined) return;
    state.jobs.set(jobId, { ...meta, doneAt, interestingCount });
  },

  pushRow(row: ResultRow): void {
    state.rows.push(row);
    if (state.rows.length > MAX_ROWS) {
      state.rows.splice(0, state.rows.length - MAX_ROWS);
    }
  },

  clear(): void {
    state.rows.length = 0;
    state.jobs.clear();
  },
};
