import { describe, expect, it } from "vitest";

import {
  type ControlArm,
  type Side,
  applyControlVetoes,
  buildBd,
  buildControlArms,
  buildDs,
  buildDz,
  buildZ0,
  gradeConfidence,
  sideOf,
} from "../src/detect/attribution.ts";
import { CLASS_TABLE, SPECIAL_CLASSES, classProfile } from "../src/response/classes.ts";
import type { FeatureDiff } from "../src/detect/features.ts";

const fixedRandom = () => 0.5;

function diff(over: Partial<FeatureDiff> = {}): FeatureDiff {
  return {
    name: "status",
    featureClass: "status",
    lengthSensitive: false,
    sign: 0,
    breakValue: 500,
    escapeValue: 200,
    ...over,
  } as FeatureDiff;
}

function hasSpecials(text: string): boolean {
  for (const char of text) {
    if (SPECIAL_CLASSES.has(CLASS_TABLE[char.charCodeAt(0) & 0xff]!)) return true;
  }
  return false;
}

describe("control arm construction", () => {
  it("Dz matches the break's length and contains no special characters", () => {
    for (const payload of ["z'z", "\\", "${{z", ",abs(0,1)", "..;/"]) {
      const dz = buildDz(payload);
      expect(dz.length, payload).toBe(payload.length);
      expect(hasSpecials(dz), payload).toBe(false);
    }
  });

  it("Ds matches the break's length and its non-special class profile", () => {
    for (const payload of ["z'z", ",abs(0,1)", "z\\'z", "${{z"]) {
      const ds = buildDs(payload);
      expect(ds.length, payload).toBe(payload.length);

      const before = classProfile(payload);
      const after = classProfile(ds);
      for (let cls = 0; cls < before.length; cls++) {
        if (SPECIAL_CLASSES.has(cls)) continue;
        expect(after[cls], `${payload} class ${cls}`).toBe(before[cls]);
      }
    }
  });

  it("Ds still carries punctuation, which is the whole point", () => {
    // If Ds had no punctuation it would be Dz and would test nothing new.
    expect(hasSpecials(buildDs("z'z"))).toBe(true);
    expect(buildDs("z'z")).toBe("z~z");
  });

  it("Ds avoids collapsing onto the break when the break already uses the inert character", () => {
    expect(buildDs("z~z")).toBe("z^z");
    expect(buildDs("z~z")).not.toBe("z~z");
  });

  it("Bd double-percent-encodes only the specials", () => {
    expect(buildBd("z'z")).toBe("z%2527z");
    expect(buildBd("\\")).toBe("%255C");
    // Alphanumerics are untouched, so the payload shape is otherwise preserved.
    expect(buildBd("abc")).toBe("abc");
  });

  it("Z0 is inert and the same length as the break", () => {
    const z0 = buildZ0("z'z\\", fixedRandom);
    expect(z0.length).toBe(4);
    expect(hasSpecials(z0)).toBe(false);
  });

  it("builds all four arms with explanations", () => {
    const arms = buildControlArms("z'z", fixedRandom);
    expect(arms.map((a) => a.name)).toEqual(["Z0", "Dz", "Ds", "Bd"]);
    for (const arm of arms) {
      expect(arm.explains.length).toBeGreaterThan(10);
      expect(arm.payload.length).toBeGreaterThan(0);
    }
  });

  it("never produces a control identical to the break payload", () => {
    // A control that collapses onto the break arm is inert and would veto everything.
    for (const payload of ["z'z", "\\", "${{z", ",abs(1)"]) {
      for (const arm of buildControlArms(payload, fixedRandom)) {
        expect(arm.payload, `${arm.name} for ${payload}`).not.toBe(payload);
      }
    }
  });
});

describe("which side a control landed on", () => {
  it("matches a categorical witness by value", () => {
    const w = diff({ sign: 0, breakValue: 500, escapeValue: 200 });
    expect(sideOf(w, 500, 500, 200)).toBe("break");
    expect(sideOf(w, 200, 500, 200)).toBe("escape");
    expect(sideOf(w, 404, 500, 200)).toBe("neither");
  });

  it("uses direction rather than distance for a numeric witness", () => {
    // A control that overshoots the break value has still moved the same way, so it lands on the
    // break side. Judging by distance would call that "neither" and lose the veto.
    const w = diff({ name: "bodyLength", sign: 1, breakValue: 120, escapeValue: 100 });
    expect(sideOf(w, 120, 120, 100)).toBe("break");
    expect(sideOf(w, 500, 120, 100)).toBe("break");
    expect(sideOf(w, 100, 120, 100)).toBe("escape");
    expect(sideOf(w, 80, 120, 100)).toBe("neither");
  });

  it("handles a negative-direction witness", () => {
    const w = diff({ name: "bodyLength", sign: -1, breakValue: 80, escapeValue: 100 });
    expect(sideOf(w, 70, 80, 100)).toBe("break");
    expect(sideOf(w, 100, 80, 100)).toBe("escape");
    expect(sideOf(w, 130, 80, 100)).toBe("neither");
  });

  it("returns neither for an unreadable feature", () => {
    expect(sideOf(diff(), undefined, 500, 200)).toBe("neither");
  });
});

/**
 * Use the real arm definitions, so the explanation the operator sees is the one under test rather
 * than a stand-in. A stubbed explanation would let the wording rot without failing anything.
 */
const REAL_ARMS = buildControlArms("z'z", fixedRandom);

function arm(name: ControlArm["name"]): ControlArm {
  const found = REAL_ARMS.find((a) => a.name === name);
  if (found === undefined) throw new Error(`no such arm: ${name}`);
  return found;
}

function observation(name: ControlArm["name"], sides: Side[][]) {
  return { arm: arm(name), sides };
}

describe("veto application", () => {
  const witnesses = [diff({ name: "status" }), diff({ name: "kw:error", featureClass: "lexeme" })];

  it("keeps a witness no control reproduced", () => {
    const result = applyControlVetoes(witnesses, [
      observation("Z0", [["escape", "escape"], ["escape", "escape"]]),
      observation("Dz", [["escape", "escape"], ["escape", "escape"]]),
      observation("Ds", [["escape", "escape"], ["escape", "escape"]]),
      observation("Bd", [["escape", "escape"], ["escape", "escape"]]),
    ]);
    expect(result.survivors).toHaveLength(2);
    expect(result.vetoed).toHaveLength(0);
  });

  it("vetoes a witness that the length control reproduced", () => {
    const result = applyControlVetoes(witnesses, [
      observation("Z0", [["escape", "escape"], ["escape", "escape"]]),
      observation("Dz", [["break", "break"], ["escape", "escape"]]),
    ]);
    expect(result.survivors.map((w) => w.name)).toEqual(["kw:error"]);
    expect(result.vetoed).toHaveLength(1);
    expect(result.vetoed[0]!.by).toBe("Dz");
    expect(result.vetoed[0]!.explains).toMatch(/length or position/);
  });

  it("requires unanimity, so one replicate cannot veto", () => {
    // A single blip must never overturn a twelve-request measurement.
    const result = applyControlVetoes(witnesses, [
      observation("Z0", [["escape", "escape"], ["escape", "escape"]]),
      observation("Dz", [["break", "escape"], ["escape", "escape"]]),
    ]);
    expect(result.survivors).toHaveLength(2);
    expect(result.vetoed).toHaveLength(0);
  });

  it("vetoes only the witness an inert value reproduced, not the whole measurement", () => {
    // Z0 is a uniform veto arm. An earlier version treated it as a fatal drift detector that had to
    // land on the escape side for EVERY witness, which vetoed every genuine finding on any target
    // whose escape payload does something observable -- a real ERB template-injection target proved
    // it, since its escape arm renders a different page from an inert echo.
    const result = applyControlVetoes(witnesses, [
      observation("Z0", [["break", "break"], ["escape", "escape"]]),
      observation("Dz", [["escape", "escape"], ["escape", "escape"]]),
    ]);
    expect(result.survivors.map((w) => w.name)).toEqual(["kw:error"]);
    expect(result.vetoed).toHaveLength(1);
    expect(result.vetoed[0]!.by).toBe("Z0");
  });

  it("keeps a witness when the inert value did not reproduce it", () => {
    const result = applyControlVetoes(witnesses, [
      observation("Z0", [["neither", "escape"], ["neither", "neither"]]),
    ]);
    expect(result.survivors).toHaveLength(2);
  });

  it("does not let a single Z0 replicate veto, same as every other arm", () => {
    const result = applyControlVetoes(witnesses, [
      observation("Z0", [["break", "escape"], ["escape", "escape"]]),
    ]);
    expect(result.survivors).toHaveLength(2);
    expect(result.vetoed).toHaveLength(0);
  });

  it("reports which arm killed each witness, so the operator sees why", () => {
    const result = applyControlVetoes(witnesses, [
      observation("Z0", [["escape", "escape"], ["escape", "escape"]]),
      observation("Ds", [["escape", "escape"], ["break", "break"]]),
      observation("Bd", [["break", "break"], ["escape", "escape"]]),
    ]);
    expect(result.survivors).toHaveLength(0);
    const by = result.vetoed.map((v) => `${v.witness.name}:${v.by}`).sort();
    expect(by).toEqual(["kw:error:Ds", "status:Bd"]);
  });

  it("works with no controls observed at all", () => {
    const result = applyControlVetoes(witnesses, []);
    expect(result.survivors).toHaveLength(2);
  });
});

describe("confidence grading", () => {
  it("requires breadth for firm", () => {
    const firm = gradeConfidence([
      diff({ name: "status", featureClass: "status" }),
      diff({ name: "kw:error", featureClass: "lexeme" }),
    ]);
    expect(firm).toBe("firm");
  });

  it("does not grade a single witness as firm however clean it is", () => {
    // One witness is one unknown artefact away from being wrong, and the premise of the whole
    // design is that unknown artefacts exist.
    expect(gradeConfidence([diff({ name: "status" })])).toBe("probable");
  });

  it("does not grade two witnesses in the same class as firm", () => {
    expect(
      gradeConfidence([
        diff({ name: "kw:error", featureClass: "lexeme" }),
        diff({ name: "kw:syntax", featureClass: "lexeme" }),
      ]),
    ).toBe("probable");
  });

  it("caps at tentative when every witness is length-sensitive", () => {
    expect(
      gradeConfidence([
        diff({ name: "bodyLength", featureClass: "size", lengthSensitive: true }),
        diff({ name: "spaces", featureClass: "structure", lengthSensitive: true }),
      ]),
    ).toBe("tentative");
  });

  it("is tentative with no witnesses", () => {
    expect(gradeConfidence([])).toBe("tentative");
  });
});
