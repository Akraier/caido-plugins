#!/usr/bin/env python3
"""
Extract the remaining catalogue pieces that are not `new Probe(...)` declarations:

 1. exploreAvailableFunctions' language triples: new String[]{name, valid, invalid...}
    Each triple is a probe pair where the ESCAPE is a real function call and the BREAKS
    are near-miss misspellings of it. Length parity here is meaningful and checkable.
 2. TransformationScan's two flat payload arrays (decodeBasedPayloads, payloads).
 3. The magic-value list from the settings default.
"""

import json
import re
from pathlib import Path

SCRATCH = Path(__file__).resolve().parent.parent

STR_LIT = re.compile(r'"((?:[^"\\]|\\.)*)"')


def decode(lit: str) -> str:
    out, i = [], 0
    while i < len(lit):
        c = lit[i]
        if c != "\\":
            out.append(c); i += 1; continue
        i += 1
        e = lit[i]
        simple = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f",
                  "0": "\0", "'": "'", '"': '"', "\\": "\\", "s": " "}
        if e in simple:
            out.append(simple[e]); i += 1
        elif e == "u":
            out.append(chr(int(lit[i + 1:i + 5], 16))); i += 5
        else:
            raise ValueError("unknown escape \\" + e)
    return "".join(out)


def all_literals(chunk: str):
    return [decode(m.group(1)) for m in STR_LIT.finditer(chunk)]


diffing = (SCRATCH / "bps/src/burp/DiffingScan.java").read_text()
transf = (SCRATCH / "bps/src/burp/TransformationScan.java").read_text()
extender = (SCRATCH / "bps/src/burp/BurpExtender.java").read_text()

result = {}

# ---- 1. language function triples ------------------------------------------------
triples = []
for m in re.finditer(r'functions\.add\(new String\[\]\{(.*?)\}\)\s*;', diffing, re.S):
    lits = all_literals(m.group(1))
    if len(lits) < 3:
        continue
    name, valid, invalids = lits[0], lits[1], lits[2:]
    lens = sorted(set(len(x) for x in [valid] + invalids))
    triples.append({
        "language": name,
        "escape_valid": valid,
        "breaks_invalid": invalids,
        "lengths": lens,
        "lengthParity": len(lens) == 1,
    })
result["functionTriples"] = triples

# Which context each triple is registered in (guarded by useRandomAnchor)
result["functionTripleNotes"] = {
    "gateProbeName": "Basic function injection",
    "gatePositionInList": next((i for i, t in enumerate(triples)
                                if t["language"] == "Basic function injection"), None),
    "comment": ("The cheap gate that aborts the cascade is evaluated only when its own "
                "entry is reached, so every earlier language is probed first."),
}

# ---- 2. transformation payload arrays -------------------------------------------
for varname in ("decodeBasedPayloads", "payloads"):
    m = re.search(r'String\[\]\s+' + varname + r'\s*=\s*\{(.*?)\}\s*;', transf, re.S)
    if not m:
        continue
    lits = all_literals(m.group(1))
    dupes = sorted({x for x in lits if lits.count(x) > 1})
    result[varname] = {
        "payloads": lits,
        "count": len(lits),
        "distinctCount": len(set(lits)),
        "duplicates": dupes,
    }

# ---- 3. magic values -------------------------------------------------------------
m = re.search(r'settings\.register\("diff: magic values",\s*"((?:[^"\\]|\\.)*)"', extender)
if m:
    raw = decode(m.group(1))
    values = raw.split(",")
    result["magicValues"] = {
        "raw": raw,
        "values": values,
        "shortestLen": min(len(v) for v in values),
        "corruptorNote": ("The Java corruptor writes 'z' at index i%len for i in 0..3, so "
                          "any value shorter than 4 chars yields duplicate corruptions, and "
                          "an empty value (trailing comma in this user-editable setting) "
                          "divides by zero."),
        "wouldDuplicateCorruptions": [v for v in values if len(v) < 4],
    }

dest = SCRATCH / "extract" / "catalogue_lists.json"
dest.write_text(json.dumps(result, indent=2, ensure_ascii=False))

print("written %s\n" % dest)
print("=== language function triples (%d) ===" % len(triples))
for t in triples:
    flag = "OK " if t["lengthParity"] else "LEN"
    print("%s %-28s escape=%-34r breaks=%s" %
          (flag, t["language"], t["escape_valid"], t["breaks_invalid"]))
print("\nlength-parity holds for %d/%d triples" %
      (sum(1 for t in triples if t["lengthParity"]), len(triples)))
print("gate 'Basic function injection' sits at list index %s"
      % result["functionTripleNotes"]["gatePositionInList"])

for varname in ("decodeBasedPayloads", "payloads"):
    if varname in result:
        d = result[varname]
        print("\n=== %s: %d entries, %d distinct ===" % (varname, d["count"], d["distinctCount"]))
        print(json.dumps(d["payloads"], ensure_ascii=False))
        if d["duplicates"]:
            print("DUPLICATES (wasted probe rounds): %s" % d["duplicates"])

if "magicValues" in result:
    mv = result["magicValues"]
    print("\n=== magic values ===")
    print(mv["values"])
    print("values under 4 chars (duplicate corruptions): %s" % mv["wouldDuplicateCorruptions"])
