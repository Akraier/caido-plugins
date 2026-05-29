import type { Param, ParamSource } from "./extract";

const KEYED_SOURCES: ParamSource[] = ["query", "form", "json"];

export function pageKey(method: string, host: string, path: string, params: Param[]): string {
  const names = params
    .filter((p) => KEYED_SOURCES.includes(p.source))
    .map((p) => `${p.source}:${p.name}`)
    .sort()
    .join(",");
  return `${method.toUpperCase()}|${host.toLowerCase()}|${path}|${names}`;
}

export class ScanCache {
  private seen = new Set<string>();

  has(key: string): boolean {
    return this.seen.has(key);
  }

  mark(key: string): void {
    this.seen.add(key);
  }

  size(): number {
    return this.seen.size;
  }

  clear(): void {
    this.seen.clear();
  }
}
