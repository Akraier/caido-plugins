import { type Param } from "./extract";

export type PassiveHit = {
  param: Param;
  index: number;
  before: string;
  after: string;
};

const MAX_HITS_PER_PARAM = 3;

export function findPassiveHits(params: Param[], body: string): PassiveHit[] {
  if (!body) return [];
  const seen = new Set<string>();
  const out: PassiveHit[] = [];
  for (const param of params) {
    const dedup = `${param.source}:${param.name}:${param.value}`;
    if (seen.has(dedup)) continue;
    seen.add(dedup);
    let from = 0;
    let hits = 0;
    while (hits < MAX_HITS_PER_PARAM) {
      const idx = body.indexOf(param.value, from);
      if (idx === -1) break;
      out.push({
        param,
        index: idx,
        before: body.slice(Math.max(0, idx - 40), idx),
        after: body.slice(idx + param.value.length, idx + param.value.length + 40),
      });
      hits++;
      from = idx + param.value.length;
    }
  }
  return out;
}
