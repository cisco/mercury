#!/usr/bin/env python3
"""Render the libmerc differential-coverage summary in markdown to stdout.

Input is the top-level per-line TLA counts that genhtml's --criteria-script
dumps as JSON, e.g., {"line": {"found": 14, "GNC": 3, "UNC": 1, "CBC": 10}}.
"""
import argparse
import json
import sys

# The 12 lcov 2.x diff categories (abbr, group, transition, name, meaning)
CATEGORIES = [
    ("UNC", "New",      "+ => 0", "Uncovered New Code",          "Newly added code is not exercised."),
    ("GNC", "New",      "+ => 1", "Gained New Coverage",         "Newly added code is exercised."),
    ("UIC", "Included", "# => 0", "Uncovered Included Code",     "Previously unused code is not exercised."),
    ("GIC", "Included", "# => 1", "Gained Included Coverage",    "Previously unused code is exercised."),
    ("UBC", "Baseline", "0 => 0", "Uncovered Baseline Code",     "Unchanged code, not exercised before or now. Pre-existing debt."),
    ("LBC", "Baseline", "1 => 0", "Lost Baseline Coverage",      "Unchanged code exercised before but not now. A coverage regression."),
    ("GBC", "Baseline", "0 => 1", "Gained Baseline Coverage",    "Unchanged code exercised now that wasn't. Unexpected improvement."),
    ("CBC", "Baseline", "1 => 1", "Covered Baseline Code",       "Unchanged code exercised before and still exercised. The stable majority."),
    ("EUB", "Excluded", "0 => #", "Excluded Uncovered Baseline", "Un-exercised code is unused now."),
    ("ECB", "Excluded", "1 => #", "Excluded Covered Baseline",   "Exercised code is unused now."),
    ("DUB", "Deleted",  "0 => -", "Deleted Uncovered Baseline",  "Un-exercised code was deleted. Summary only."),
    ("DCB", "Deleted",  "1 => -", "Deleted Covered Baseline",    "Exercised code was deleted. Summary only."),
]


def parse_tla(text):
    """Validate genhtml's criteria JSON and return the per-line TLA counts.

    Absent categories are legitimate and default to 0.  A "line" map with no
    "found" is not: every count would read as 0, which can be confused with a
    patch with nothing to cover.

    >>> parse_tla('{"line": {"found": 7, "GNC": 3, "UNC": 1}}')
    {'found': 7, 'GNC': 3, 'UNC': 1}
    >>> parse_tla('{"line": {}}')
    Traceback (most recent call last):
        ...
    ValueError: unusable criteria JSON: '{"line": {}}'
    >>> parse_tla('{"line": {"found": 7, "UNC": true}}')
    Traceback (most recent call last):
        ...
    ValueError: unusable criteria JSON: '{"line": {"found": 7, "UNC": true}}'
    """
    try:
        line = json.loads(text)["line"]
        counts = (line.get(abbr, 0) for abbr in ("GNC", "UNC", "LBC"))
        # a bool is an int, and reaches bash as `True`, which reads as 0 there
        ok = "found" in line and all(type(v) is int and v >= 0 for v in counts)
    except (AttributeError, KeyError, TypeError, ValueError):
        ok = False   # JSONDecodeError is a ValueError
    if not ok:
        raise ValueError(f"unusable criteria JSON: {text!r}")
    return line


def github_output(line):
    """The counts coverage-gate needs, as `k=v` lines for $GITHUB_OUTPUT.

    >>> print(github_output({"found": 7, "GNC": 3, "UNC": 1}))
    gnc=3
    unc=1
    lbc=0
    """
    # LBC counts unchanged lines, so it is not patch coverage and is not gated.
    return "\n".join(f"{abbr.lower()}={line.get(abbr, 0)}"
                     for abbr in ("GNC", "UNC", "LBC"))


def patch_line(line):
    """Patch-coverage headline from the TLA counts.

    >>> patch_line({"GNC": 3, "UNC": 1})
    'Patch coverage: 3/4 new lines covered (75.000%)'
    >>> patch_line({"CBC": 10})  # no new/changed coverable lines
    'Patch coverage: no new/changed coverable libmerc lines'
    """
    gnc, unc = line.get("GNC", 0), line.get("UNC", 0)
    new_total = gnc + unc
    if new_total == 0:
        return "Patch coverage: no new/changed coverable libmerc lines"
    return f"Patch coverage: {gnc}/{new_total} new lines covered ({100.0 * gnc / new_total:.3f}%)"


def status_line(base_pct, cur_pct, desc):
    """Neutral one-line total-% status.

    >>> status_line(88.0, 90.0, "dev @ abc123")
    'libmerc line coverage: 88.000% → 90.000% vs dev @ abc123'
    >>> status_line(88.1234, 88.129, "dev @ abc123")
    'libmerc line coverage: 88.123% → 88.129% vs dev @ abc123'
    """
    return f"libmerc line coverage: {base_pct:.3f}% → {cur_pct:.3f}% vs {desc}"


def category_table(line):
    """Markdown table of the categories present (non-zero); "" when none.

    >>> category_table({})
    ''
    >>> print(category_table({"GNC": 3, "CBC": 10}))
    | Category | Lines | What it means |
    |----------|------:|---------------|
    | Gained New Coverage (GNC) | 3 | Newly added code is exercised. |
    | Covered Baseline Code (CBC) | 10 | Unchanged code exercised before and still exercised. The stable majority. |
    """
    rows = [f"| {name} ({abbr}) | {line[abbr]} | {meaning} |"
            for abbr, _g, _t, name, meaning in CATEGORIES if line.get(abbr, 0)]
    if not rows:
        return ""
    return ("| Category | Lines | What it means |\n"
            "|----------|------:|---------------|\n" + "\n".join(rows))


def legend():
    """Collapsible all-12 reference table, generated from CATEGORIES."""
    rows = "\n".join(f"| {g} | `{abbr}` | {name} | `{t}` | {meaning} |"
                     for abbr, g, t, name, meaning in CATEGORIES)
    return f"""<details><summary>All 12 categories (legend)</summary>

| Group | Abbrev | Name | Transition | Meaning |
|-------|--------|------|-----------|---------|
{rows}

**Line states.** Each line is in one of three states per version:

- **covered/exercised** (`1`): has a counter, run at least once.
- **uncovered/not exercised** (`0`): has a counter, run zero times.
- **unused** (`#`): has *no* counter — either excluded (e.g., `LCOV_EXCL_LINE`) or not instrumented (e.g., a C++ template never instantiated).

NOTE: lcov calls a line that gains a counter (unused -> covered/uncovered) **"included"**, hence the `GIC`/`UIC` categories.
</details>"""


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("tla_file", metavar="TLA_FILE",
                    help="JSON of per-line TLA counts from genhtml's --criteria-script")
    ap.add_argument("--cur-pct", type=float, required=True,
                    help="current libmerc line-coverage percent")
    ap.add_argument("--base-pct", type=float, required=True,
                    help="baseline libmerc line-coverage percent")
    ap.add_argument("--base-sha", required=True, help="merge-base commit of the baseline")
    ap.add_argument("--base-ref", required=True, help="branch the baseline tracks")
    ap.add_argument("--github-output", metavar="PATH",
                    help="append gnc/unc/lbc counts to PATH as k=v lines")
    args = ap.parse_args(argv)

    # File is guaranteed present by cov_report.sh.  Bad content is fatal here.
    with open(args.tla_file) as f:
        line = parse_tla(f.read().strip())

    if args.github_output:
        with open(args.github_output, "a") as f:
            f.write(github_output(line) + "\n")

    desc = f"{args.base_ref} @ {args.base_sha}"
    out = [f"### libmerc differential coverage (vs {desc})", "",
           patch_line(line), "",
           status_line(args.base_pct, args.cur_pct, desc)]
    table = category_table(line)
    if table:
        out += ["", table]
    out += ["", legend()]

    print("\n".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
