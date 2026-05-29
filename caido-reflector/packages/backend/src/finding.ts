import type { SDK } from "caido:plugin";
import type { Request } from "caido:utils";
import type { Param } from "./extract";
import type { ReflectionContext } from "./classify";
import {
  type State,
  type CharStatus,
  type CanaryBundle,
  type TestChar,
  type SurvivalSummary,
  CHAR_LITERAL,
  summarise,
  suggestedPayload,
} from "./probe";

export type FindingInput = {
  state: State;
  context: ReflectionContext;
  param: Param;
  canary: CanaryBundle;
  probeBody: string;
  canaryIndex: number;
  survival: Record<TestChar, CharStatus>;
  rationale: string;
  breakoutSet: TestChar[] | null;
};

function fence(s: string): string {
  return s.replace(/`/g, "\\`");
}

function titleUrl(request: Request, param: Param): string {
  const proto = request.getTls() ? "https" : "http";
  const host = request.getHost();
  const path = request.getPath();
  const query = request.getQuery();
  const base = `${proto}://${host}${path}${query ? `?${query}` : ""}`;
  if (param.source === "query") return base;
  return `${base}  [${param.source}.${param.name}]`;
}

function snippet(body: string, index: number, canaryLen: number): string {
  const start = Math.max(0, index - 60);
  const end = Math.min(body.length, index + canaryLen + 60);
  const head = body.slice(start, index);
  const tail = body.slice(index + canaryLen, end);
  return `${head}[CANARY]${tail}`;
}

function listChars(chars: TestChar[]): string {
  if (chars.length === 0) return "(none)";
  return chars.map((c) => `\`${CHAR_LITERAL[c]}\``).join(" ");
}

function charStatusTable(survival: Record<TestChar, CharStatus>): string {
  const lines = ["| Char | Status |", "| ---- | ------ |"];
  for (const tc of Object.keys(survival) as TestChar[]) {
    lines.push(`| \`${CHAR_LITERAL[tc]}\` (${tc}) | ${survival[tc]} |`);
  }
  return lines.join("\n");
}

function buildBody(input: FindingInput, request: Request, summary: SurvivalSummary): string {
  const lines: string[] = [];
  lines.push(`**State**: ${input.state}`);
  lines.push(`**Method**: ${request.getMethod()}`);
  lines.push(`**URL**: ${titleUrl(request, input.param)}`);
  lines.push(`**Parameter**: \`${input.param.name}\` (${input.param.source})`);
  lines.push(`**Reflected value (passive)**: \`${fence(input.param.value)}\``);
  lines.push(`**Context (from canary)**: \`${input.context}\``);
  lines.push("");

  lines.push("### Where it reflects");
  lines.push("");
  lines.push("```");
  lines.push(snippet(input.probeBody, input.canaryIndex, input.canary.value.length));
  lines.push("```");
  lines.push("");

  lines.push("### Allowed (raw) characters");
  lines.push(listChars(summary.raw));
  lines.push("");
  lines.push("### Filtered / encoded");
  lines.push(listChars(summary.encoded));
  lines.push("");
  lines.push("### Stripped");
  lines.push(listChars(summary.stripped));
  lines.push("");
  if (summary.unknown.length > 0) {
    lines.push("### Not detected in probe response");
    lines.push(listChars(summary.unknown));
    lines.push("");
  }

  lines.push("### Verdict");
  lines.push(input.rationale);
  if (input.breakoutSet) {
    lines.push("");
    lines.push(`Break-out set satisfied: ${listChars(input.breakoutSet)}`);
  }
  lines.push("");

  const payload = suggestedPayload(input.context, input.breakoutSet);
  if (payload) {
    lines.push("### Suggested PoC payload");
    lines.push("```");
    lines.push(payload);
    lines.push("```");
    lines.push("");
  }

  lines.push("### Full character status");
  lines.push(charStatusTable(input.survival));
  return lines.join("\n");
}

export async function reportFinding(sdk: SDK, request: Request, input: FindingInput): Promise<void> {
  if (input.state === "NO_REFLECTION") return;
  const summary = summarise(input.survival);
  const title = `[${input.state}] - ${titleUrl(request, input.param)}`;
  const dedupeKey = `reflector:v2:${request.getMethod()}:${request.getHost()}:${request.getPath()}:${input.param.source}:${input.param.name}:${input.context}`;

  try {
    await sdk.findings.create({
      title,
      description: buildBody(input, request, summary),
      reporter: "Reflector",
      request,
      dedupeKey,
    });
    sdk.console.log(`[reflector] finding created: ${title}`);
  } catch (e) {
    sdk.console.log(`[reflector] finding create failed: ${String(e)}`);
  }
}
