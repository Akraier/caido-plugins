#!/usr/bin/env python3
"""
Mechanically extract the Backslash Powered Scanner probe catalogue from the Java source.

Why mechanical: the probe payloads are dense Java string literals full of backslash
escapes. Hand-transcribing them into TypeScript is the single easiest place to introduce
a silent bug into the most valuable asset we are porting. This decodes the literals to
their true character sequences, groups the setter calls per probe variable, and reports
length parity between break and escape payloads (the dominant false-positive source when
the parameter is reflected).

Probes built from concatenated variables (delimiter/concat/prefix/suffix/baseValue) are
emitted as templates with their raw expression preserved, because they are parameterised
by what earlier cascade stages discovered and cannot be reduced to literals.
"""

import json
import re
import sys
from pathlib import Path

SCRATCH = Path(__file__).resolve().parent.parent


def decode_java_literal(lit: str) -> str:
    """Decode the *contents* of a Java string literal (without surrounding quotes)."""
    out = []
    i = 0
    while i < len(lit):
        c = lit[i]
        if c != "\\":
            out.append(c)
            i += 1
            continue
        i += 1
        if i >= len(lit):
            raise ValueError("trailing backslash in literal: " + lit)
        e = lit[i]
        simple = {
            "n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f",
            "0": "\0", "'": "'", '"': '"', "\\": "\\", "s": " ",
        }
        if e in simple:
            out.append(simple[e])
            i += 1
        elif e == "u":
            out.append(chr(int(lit[i + 1:i + 5], 16)))
            i += 5
        else:
            raise ValueError("unknown escape \\%s in %s" % (e, lit))
    return "".join(out)


# Matches a Java string literal, honouring escaped quotes.
STR_LIT = re.compile(r'"((?:[^"\\]|\\.)*)"')


def split_java_args(argstr: str):
    """Split a Java argument list at top-level commas, respecting strings and parens."""
    args, depth, buf, i, in_str = [], 0, [], 0, False
    while i < len(argstr):
        c = argstr[i]
        if in_str:
            buf.append(c)
            if c == "\\":
                if i + 1 < len(argstr):
                    buf.append(argstr[i + 1])
                    i += 2
                    continue
            elif c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            buf.append(c)
        elif c in "([":
            depth += 1
            buf.append(c)
        elif c in ")]":
            depth -= 1
            buf.append(c)
        elif c == "," and depth == 0:
            args.append("".join(buf).strip())
            buf = []
        else:
            buf.append(c)
        i += 1
    if buf:
        args.append("".join(buf).strip())
    return [a for a in args if a != ""]


def is_pure_literal(expr: str) -> bool:
    """True if the expression is exactly one string literal and nothing else."""
    expr = expr.strip()
    m = STR_LIT.fullmatch(expr)
    return m is not None


def literal_or_template(expr: str):
    """Return ('literal', decoded) or ('template', raw_expr)."""
    expr = expr.strip()
    if is_pure_literal(expr):
        return ("literal", decode_java_literal(STR_LIT.fullmatch(expr).group(1)))
    return ("template", expr)


def extract(path: Path):
    src = path.read_text()
    lines = src.split("\n")

    # 1. find `Probe <var> = new Probe(<args>);`  (possibly spanning lines)
    #
    # Java reuses variable names across scopes (concat_attack and functionCall are each
    # declared twice in DiffingScan). Keying by name alone silently merges two different
    # probes, so declarations are kept as a list and setters bind to the nearest
    # preceding declaration of the same name by source offset.
    decls = []
    joined = src
    ctor = re.compile(
        r'Probe\s+(\w+)\s*=\s*new\s+Probe\(\s*(.*?)\)\s*;', re.S)
    for m in ctor.finditer(joined):
        var, args = m.group(1), m.group(2)
        parts = split_java_args(args)
        if len(parts) < 2:
            continue
        name_kind, name_val = literal_or_template(parts[0])
        severity = parts[1].strip()
        breaks = [literal_or_template(p) for p in parts[2:]]
        line_no = joined[:m.start()].count("\n") + 1
        decls.append({
            "var": var,
            "offset": m.start(),
            "line": line_no,
            "nameKind": name_kind,
            "name": name_val,
            "severity": severity,
            "breaks": breaks,
            "escapeSets": [],
            "base": None,
            "prefix": "APPEND",
            "randomAnchor": True,
            "useCacheBuster": None,
            "requireConsistentEvidence": None,
            "tip": None,
        })

    def owner_of(var, offset):
        """The declaration of `var` that this call site actually refers to."""
        best = None
        for d in decls:
            if d["var"] == var and d["offset"] < offset:
                if best is None or d["offset"] > best["offset"]:
                    best = d
        return best

    # 2. attach setter calls to the declaration they actually belong to
    setter = re.compile(
        r'(\w+)\.(setEscapeStrings|addEscapePair|setBase|setPrefix|setRandomAnchor'
        r'|setUseCacheBuster|setRequireConsistentEvidence|setTip)\(\s*(.*?)\)\s*;', re.S)
    for m in setter.finditer(joined):
        var, call, args = m.group(1), m.group(2), m.group(3)
        p = owner_of(var, m.start())
        if p is None:
            continue
        parts = split_java_args(args)
        if call == "setEscapeStrings":
            # each argument becomes its own single-member alternative set
            for a in parts:
                p["escapeSets"].append([literal_or_template(a)])
        elif call == "addEscapePair":
            # one set whose members are interchangeable alternatives
            p["escapeSets"].append([literal_or_template(a) for a in parts])
        elif call == "setBase":
            p["base"] = literal_or_template(parts[0])
        elif call == "setPrefix":
            p["prefix"] = parts[0].split(".")[-1].strip()
        elif call == "setRandomAnchor":
            p["randomAnchor"] = parts[0].strip() == "true"
            # Java setter side effect: useCacheBuster = !randomAnchor
            if p["useCacheBuster"] is None:
                p["useCacheBuster"] = (parts[0].strip() == "false")
        elif call == "setUseCacheBuster":
            p["useCacheBuster"] = parts[0].strip() == "true"
        elif call == "setRequireConsistentEvidence":
            p["requireConsistentEvidence"] = parts[0].strip() == "true"
        elif call == "setTip":
            k, v = literal_or_template(parts[0])
            p["tip"] = v if k == "literal" else "<expr>"

    return sorted(decls, key=lambda d: d["offset"])


def analyse(probes):
    """Report length parity and structural observations per probe."""
    report = []
    for p in probes:
        lit_breaks = [v for k, v in p["breaks"] if k == "literal"]
        tmpl_breaks = [v for k, v in p["breaks"] if k == "template"]
        lit_escapes = []
        tmpl_escapes = []
        for s in p["escapeSets"]:
            for k, v in s:
                (lit_escapes if k == "literal" else tmpl_escapes).append(v)

        entry = {
            "name": p["name"],
            "var": p["var"],
            "line": p["line"],
            "severity": p["severity"],
            "prefix": p["prefix"],
            "randomAnchor": p["randomAnchor"],
            "useCacheBuster": p["useCacheBuster"],
            "requireConsistentEvidence": p["requireConsistentEvidence"],
            "isTemplate": bool(tmpl_breaks or tmpl_escapes) or p["nameKind"] == "template",
            "base": p["base"][1] if p["base"] else None,
            "breaks": lit_breaks,
            "breakTemplates": tmpl_breaks,
            "escapeSets": [[v for _, v in s] for s in p["escapeSets"]],
            "breakLens": sorted(set(len(b) for b in lit_breaks)),
            "escapeLens": sorted(set(len(e) for e in lit_escapes)),
        }

        issues = []
        if not p["escapeSets"]:
            issues.append("NO_ESCAPE_SET: fuzz() would index an empty list")
        set_sizes = sorted(set(len(s) for s in p["escapeSets"]))
        if len(set_sizes) > 1:
            issues.append(
                "RAGGED_ESCAPE_SETS sizes=%s: the Java loop reads its bound from one "
                "set and its payload from the next, so a ragged catalogue can index "
                "out of bounds" % set_sizes)
        if lit_breaks and lit_escapes:
            bl, el = set(len(b) for b in lit_breaks), set(len(e) for e in lit_escapes)
            if bl != el:
                issues.append(
                    "LENGTH_MISMATCH breaks=%s escapes=%s: if the value is reflected, "
                    "body-length attributes differ for a boring reason"
                    % (sorted(bl), sorted(el)))
        entry["issues"] = issues
        report.append(entry)
    return report


def main():
    out = {}
    for fname in ("DiffingScan.java", "TransformationScan.java"):
        path = SCRATCH / "bps" / "src" / "burp" / fname
        if not path.exists():
            print("missing: %s" % path, file=sys.stderr)
            continue
        probes = extract(path)
        out[fname] = analyse(probes)

    dest = SCRATCH / "extract" / "probe_catalogue_raw.json"
    dest.write_text(json.dumps(out, indent=2, ensure_ascii=False))

    total = sum(len(v) for v in out.values())
    templates = sum(1 for v in out.values() for p in v if p["isTemplate"])
    print("extracted %d probe declarations (%d are templates)" % (total, templates))
    print("written: %s" % dest)
    print()
    for fname, probes in out.items():
        print("=" * 78)
        print(fname)
        print("=" * 78)
        for p in probes:
            flag = "T" if p["isTemplate"] else " "
            print("%s L%-4s sev=%-3s prefix=%-8s anchor=%-5s base=%-4r %s"
                  % (flag, p["line"], p["severity"], p["prefix"],
                     p["randomAnchor"], p["base"], p["name"]))
            if p["breaks"]:
                print("        break : %s" % json.dumps(p["breaks"], ensure_ascii=False))
            if p["breakTemplates"]:
                print("        breakT: %s" % p["breakTemplates"])
            if p["escapeSets"]:
                print("        escape: %s" % json.dumps(p["escapeSets"], ensure_ascii=False))
            for i in p["issues"]:
                print("        !! %s" % i)
            print()


if __name__ == "__main__":
    main()
