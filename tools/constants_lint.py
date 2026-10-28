#!/usr/bin/env python3
"""Spec-constant consistency lint (ADR-047(11); ST-167 / SG-25).

Loads the canonical constants registry (tools/constants.json) and scans
specs/*.md for literals that CONFLICT with a registered value, and checks that
each owning document still states the canonical value (required patterns).

Registry entry fields:
  name, value, unit, owner_doc, adr        -- the canonical constant
  conflict_patterns   [regex]              -- a match on a spec line = divergent literal (ERROR)
  required_patterns   [{doc, regex}]       -- regex must match somewhere in doc (WARN if missing)
  exclude_line_patterns [regex] (optional) -- lines skipped for this constant only
  style_patterns      [regex] (optional)   -- same value, divergent unit/spelling (WARN)

Excluded from the scan: 00-RESEARCH.md, 39-*, DECISIONS.md, REVIEW-REPORT.md (generated
review history), and history lines
(containing "WITHDRAWN", "supersede(d/s)", "was ", "v1.0", "retired", "Resolved by ADR").

Usage:
  python3 tools/constants_lint.py            # report; exit 1 on any conflict
  python3 tools/constants_lint.py --markdown # print the registry as a Markdown table
"""
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SPECS = ROOT / "specs"
REGISTRY = pathlib.Path(__file__).resolve().parent / "constants.json"

EXCLUDED_FILES = re.compile(r"^(00-RESEARCH\.md|39-.*|DECISIONS\.md|REVIEW-REPORT\.md)$")
# Lines that record history rather than normative values.
HISTORY_LINE = re.compile(r"(?i:withdrawn|supersede|\bretired\b|resolved by ADR|\bv1\.0\b)|\bwas ")


def load_registry(path=REGISTRY):
    return json.loads(path.read_text(encoding="utf-8"))


def spec_files():
    return [p for p in sorted(list(SPECS.glob("*.md")) + list(SPECS.glob("impl/*.md"))) if not EXCLUDED_FILES.match(p.name)]


def run_lint(registry=None):
    """Return (conflicts, style, missing).

    conflicts / style: list of dicts {file, line, constant, match}
    missing: list of dicts {constant, doc, regex}
    """
    registry = registry if registry is not None else load_registry()
    compiled = []
    for c in registry:
        compiled.append((
            c,
            [re.compile(r) for r in c.get("conflict_patterns", [])],
            [re.compile(r) for r in c.get("style_patterns", [])],
            [re.compile(r) for r in c.get("exclude_line_patterns", [])],
        ))
    conflicts, style = [], []
    for path in spec_files():
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if HISTORY_LINE.search(line):
                continue
            for c, cpats, spats, excl in compiled:
                if any(e.search(line) for e in excl):
                    continue
                for bucket, pats in ((conflicts, cpats), (style, spats)):
                    for p in pats:
                        for m in p.finditer(line):
                            bucket.append({"file": path.name, "line": lineno,
                                           "constant": c["name"], "match": m.group(0).strip()})
    missing = []
    for c in registry:
        for req in c.get("required_patterns", []):
            doc = SPECS / req["doc"]
            text = doc.read_text(encoding="utf-8") if doc.exists() else ""
            if not re.search(req["regex"], text):
                missing.append({"constant": c["name"], "doc": req["doc"], "regex": req["regex"]})
    # De-duplicate identical hits from overlapping patterns.
    dedup = lambda xs: list({(x["file"], x["line"], x["constant"], x["match"]): x for x in xs}.values())
    return dedup(conflicts), dedup(style), missing


def _esc(s):
    return str(s).replace("|", "\\|")


def registry_markdown(registry=None):
    """Markdown table of the constants registry (shared with tools/traceability.py)."""
    registry = registry if registry is not None else load_registry()
    out = ["| Constant | Value | Unit | Owner document | ADR |", "|---|---|---|---|---|"]
    for c in registry:
        out.append(f"| `{c['name']}` | {_esc(c['value'])} | {_esc(c['unit'])} | {c['owner_doc']} | {_esc(c['adr'])} |")
    return "\n".join(out)


def lint_markdown(conflicts, style, missing):
    """Markdown rendering of lint results (shared with tools/traceability.py)."""
    out = [f"- Conflicts (ERROR): **{len(conflicts)}**; unit/spelling divergences (WARN): {len(style)}; "
           f"missing canonical statements in owner documents (WARN): {len(missing)}\n"]
    if conflicts or style:
        out.append("| Severity | Location | Constant | Matched text |\n|---|---|---|---|")
        for sev, rows in (("ERROR", conflicts), ("WARN", style)):
            for f in sorted(rows, key=lambda x: (x["file"], x["line"])):
                out.append(f"| {sev} | {f['file']}:{f['line']} | `{f['constant']}` | {_esc(f['match'])} |")
        out.append("")
    if missing:
        out.append("| Severity | Constant | Owner document | Expected pattern |\n|---|---|---|---|")
        for m in missing:
            out.append(f"| WARN | `{m['constant']}` | {m['doc']} | `{_esc(m['regex'])}` |")
    if not (conflicts or style or missing):
        out.append("None.")
    return "\n".join(out)


def main(argv):
    registry = load_registry()
    if "--markdown" in argv:
        print(registry_markdown(registry))
        return 0
    conflicts, style, missing = run_lint(registry)
    for f in sorted(conflicts, key=lambda x: (x["file"], x["line"])):
        print(f"CONFLICT specs/{f['file']}:{f['line']}: {f['constant']}: {f['match']!r}")
    for f in sorted(style, key=lambda x: (x["file"], x["line"])):
        print(f"WARN     specs/{f['file']}:{f['line']}: {f['constant']} (unit/spelling): {f['match']!r}")
    for m in missing:
        print(f"MISSING  specs/{m['doc']}: {m['constant']} not stated (pattern {m['regex']!r})")
    print(f"{len(registry)} constants; {len(conflicts)} conflicts, {len(style)} style warnings, "
          f"{len(missing)} missing required statements")
    return 1 if conflicts else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
