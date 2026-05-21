"""
compare-rule-apps.py — Progressive delta reports across get-rule-apps.py runs

Reads two or more CSV files produced by get-rule-apps.py, pairs each with its
*-summary.txt for query window data, and generates a progression report showing:

  - Run history with query windows and coverage gap detection
  - Delta since the last run (new apps, gone apps)
  - Cumulative view: baseline vs latest (changed rules only)

Gap detection compares each run's query_end against the next run's query_start.
Query window start dates reflect the requested range; actual log coverage may be
shorter depending on Panorama log retention.

Usage:
    python compare-rule-apps.py [CSV ...] [options]

Arguments:
    csv_files        Two or more rule-apps-*.csv files (oldest first).
                     When omitted, auto-discovers matching files in --dir.

Options:
    --dir PATH / -d PATH   Directory to auto-discover rule-apps-*-TIMESTAMP.csv
                           files in (default: Output/).  Ignored when csv_files
                           are given explicitly.
    --stem NAME            With --dir: only compare CSVs whose stem matches NAME
                           (e.g. "my-rules" if files are rule-apps-my-rules-*.csv)
    --output PATH / -o     Output report path
                           (default: Output/rule-delta-TIMESTAMP.txt)
    --gone                 Include "apps no longer seen" sections (hidden by default)
    --show-unchanged       Include rules with no changes in the delta section

Auto-discovery groups:
    Files are grouped by the stem extracted from the filename
    (rule-apps-{STEM}-{YYYYMMDD}-{HHMMSS}.csv) and reported per group.
    Files that don't match this pattern are skipped with a warning.
"""

import argparse
import csv
import datetime
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

VERSION = "1.0.0"

# Matches: rule-apps-{stem}-{YYYYMMDD}-{HHMMSS}.csv
# Greedy backtracking on (.+) ensures the LAST date-like suffix is the timestamp.
_FNAME_RE = re.compile(r"^rule-apps-(.+)-(\d{8}-\d{6})\.csv$")
_FROM_RE  = re.compile(r"From\s*:\s*(\d{4}-\d{2}-\d{2}(?:\s+\d{2}:\d{2}:\d{2})?)")
_TO_RE    = re.compile(r"\bTo\s*:\s*(\d{4}-\d{2}-\d{2}(?:\s+\d{2}:\d{2}:\d{2})?)")


# ── Data ──────────────────────────────────────────────────────────────────────

@dataclass
class RunData:
    csv_path:       str
    stem:           str
    run_dt:         datetime.datetime          # from filename timestamp
    query_start:    datetime.datetime | None   # from summary; reflects requested range
    query_end:      datetime.datetime | None   # from summary; the reliable "checked up to" point
    apps_by_rule:   dict[str, frozenset]       # {rule: frozenset(app_names)}
    status_by_rule: dict[str, str]             # {rule: 'yes'|'no'|'skipped'}
    rule_order:     list[str]                  # rules in CSV order


# ── Loaders ───────────────────────────────────────────────────────────────────

def _parse_dt(s: str) -> datetime.datetime:
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.datetime.strptime(s.strip(), fmt)
        except ValueError:
            pass
    raise ValueError(f"Cannot parse datetime: {s!r}")


def _parse_summary(summary_path: Path) -> tuple[datetime.datetime | None, datetime.datetime | None]:
    """Extract From/To datetimes from a *-summary.txt file."""
    if not summary_path.exists():
        return None, None
    text = summary_path.read_text(encoding="utf-8")
    start = end = None
    m = _FROM_RE.search(text)
    if m:
        try:
            start = _parse_dt(m.group(1))
        except ValueError:
            pass
    m = _TO_RE.search(text)
    if m:
        try:
            end = _parse_dt(m.group(1))
        except ValueError:
            pass
    return start, end


def load_run(csv_path: str) -> RunData | None:
    p = Path(csv_path)
    m = _FNAME_RE.match(p.name)
    if not m:
        print(f"  Warning: {p.name} — doesn't match rule-apps-{{STEM}}-{{YYYYMMDD}}-{{HHMMSS}}.csv, skipping")
        return None

    stem   = m.group(1)
    run_dt = datetime.datetime.strptime(m.group(2), "%Y%m%d-%H%M%S")

    summary_path = p.with_name(p.stem + "-summary.txt")
    query_start, query_end = _parse_summary(summary_path)
    if query_start is None or query_end is None:
        print(f"  Note: no summary file for {p.name} — window data unavailable (gap detection limited)")

    try:
        with open(csv_path, newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
    except Exception as exc:
        print(f"  Warning: could not read {csv_path}: {exc}")
        return None

    apps_by_rule:   dict[str, frozenset] = {}
    status_by_rule: dict[str, str]       = {}
    rule_order:     list[str]            = []

    for row in rows:
        rule = row.get("rule", "").strip()
        if not rule:
            continue
        apps_raw = row.get("apps", "").strip()
        complete = row.get("complete", "").strip().lower()
        apps = frozenset(a.strip() for a in apps_raw.split("|") if a.strip()) if apps_raw else frozenset()
        apps_by_rule[rule]   = apps
        status_by_rule[rule] = complete
        rule_order.append(rule)

    return RunData(
        csv_path       = str(csv_path),
        stem           = stem,
        run_dt         = run_dt,
        query_start    = query_start,
        query_end      = query_end,
        apps_by_rule   = apps_by_rule,
        status_by_rule = status_by_rule,
        rule_order     = rule_order,
    )


# ── Gap detection ─────────────────────────────────────────────────────────────

def detect_gap(prev: RunData, curr: RunData) -> datetime.timedelta | None:
    """
    Returns the gap between prev.query_end and curr.query_start, or None if
    there is overlap/adjacency or window data is unavailable.
    Gap detection uses query_end (reliable) vs query_start (as requested).
    """
    if prev.query_end is None or curr.query_start is None:
        return None
    delta = curr.query_start - prev.query_end
    return delta if delta.total_seconds() > 0 else None


# ── Report generation ─────────────────────────────────────────────────────────

def _window_str(run: RunData) -> str:
    if run.query_start and run.query_end:
        days = (run.query_end - run.query_start).days
        return (
            f"{run.query_start.strftime('%Y-%m-%d')} → "
            f"{run.query_end.strftime('%Y-%m-%d')}  [{days}d requested]"
        )
    return "(window unknown — no summary file)"


def _generate_group_report(
    runs:             list[RunData],
    stem:             str,
    show_gone:        bool,
    show_unchanged:   bool,
) -> list[str]:
    """Return lines for one stem group."""
    SEP  = "=" * 62
    DASH = "-" * 62

    lines: list[str] = []
    def h(s: str = "") -> None:
        lines.append(s)

    first_run = runs[0]
    last_run  = runs[-1]
    baseline_dt = first_run.query_start or first_run.run_dt

    h(SEP)
    h(f"  compare-rule-apps  v{VERSION}  —  {stem}")
    h(SEP)
    h(f"  Project baseline  : {baseline_dt.strftime('%Y-%m-%d')}  (query window start of Run 1)")
    h(f"  Report generated  : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    h(f"  Runs included     : {len(runs)}")
    h(f"  Rules tracked     : {len(first_run.rule_order)}")
    h()

    # ── Run history ───────────────────────────────────────────────────────────
    h(DASH)
    h("  Run History & Coverage")
    h(DASH)
    h("  Note: window start dates reflect the requested range; actual log")
    h("  coverage may be shorter depending on Panorama log retention.")
    h()

    gaps_found: list[tuple[int, datetime.timedelta, RunData, RunData]] = []

    for i, run in enumerate(runs, start=1):
        label = f"  Run {i:<3}  {run.run_dt.strftime('%Y-%m-%d')}  window: {_window_str(run)}"
        if i == 1:
            h(label)
        else:
            prev_run = runs[i - 2]
            gap = detect_gap(prev_run, run)
            if gap:
                gap_start = prev_run.query_end.strftime('%Y-%m-%d')   # type: ignore[union-attr]
                gap_end   = run.query_start.strftime('%Y-%m-%d')       # type: ignore[union-attr]
                h(f"{label}  ** GAP: {gap.days}d ({gap_start} to {gap_end}) **")
                gaps_found.append((i, gap, prev_run, run))
            elif prev_run.query_end and run.query_start:
                overlap = (prev_run.query_end - run.query_start).days
                note = f"  [overlap: {overlap}d]" if overlap > 0 else "  [adjacent]"
                h(f"{label}{note}")
            else:
                h(f"{label}  [gap status unknown — missing window data]")

    h()
    if gaps_found:
        h(f"  Coverage gaps     : {len(gaps_found)} gap(s) found — see ** markers above")
        for idx, gap, prev_run, curr_run in gaps_found:
            h(
                f"    Run {idx-1}→{idx}: {gap.days}d unchecked  "
                f"({prev_run.query_end.strftime('%Y-%m-%d')} to {curr_run.query_start.strftime('%Y-%m-%d')})"  # type: ignore[union-attr]
            )
    else:
        h("  Coverage gaps     : none")
    h(SEP)
    h()

    if len(runs) < 2:
        h("  Only one run loaded — need at least two runs to generate a delta.")
        h(SEP)
        return lines

    # ── Delta: latest two runs ────────────────────────────────────────────────
    prev_run = runs[-2]
    curr_run = runs[-1]

    h(SEP)
    h(f"  Delta: Run {len(runs)-1} → Run {len(runs)}")
    h(f"  {prev_run.run_dt.strftime('%Y-%m-%d')} to {curr_run.run_dt.strftime('%Y-%m-%d')}")
    h(SEP)

    # Warn if there's a gap immediately before this run
    if len(gaps_found) > 0 and gaps_found[-1][0] == len(runs):
        _, gap, _, _ = gaps_found[-1]
        h(f"  ** Note: {gap.days}-day coverage gap precedes this run — new apps in")
        h( "     that window may not appear in the list below. **")
        h()

    # Compute per-rule deltas
    rules_with_new:  list[tuple[str, frozenset, frozenset]] = []  # (rule, new_apps, gone_apps)
    rules_with_gone: list[tuple[str, frozenset]]            = []  # (rule, gone_apps)
    rules_unchanged: list[str]                              = []
    rules_skipped:   list[str]                              = []

    # Use current run's rule order as canonical; fall back to previous
    ordered = curr_run.rule_order or prev_run.rule_order

    for rule in ordered:
        prev_apps   = prev_run.apps_by_rule.get(rule, frozenset())
        curr_apps   = curr_run.apps_by_rule.get(rule, frozenset())
        prev_status = prev_run.status_by_rule.get(rule, "")
        curr_status = curr_run.status_by_rule.get(rule, "")

        new_apps  = curr_apps - prev_apps
        gone_apps = prev_apps - curr_apps

        if curr_status == "skipped" and prev_status == "skipped":
            rules_skipped.append(rule)
        elif new_apps:
            rules_with_new.append((rule, new_apps, gone_apps))
        elif gone_apps:
            rules_with_gone.append((rule, gone_apps))
        else:
            rules_unchanged.append(rule)

    h(f"  Rules with NEW apps        : {len(rules_with_new)}")
    h(f"  Rules unchanged            : {len(rules_unchanged)}")
    h(f"  Rules with apps gone       : {len(rules_with_gone)}  (likely captured by APP-ID rules)")
    h(f"  Rules skipped/inactive     : {len(rules_skipped)}")
    h()

    if rules_with_new:
        h(DASH)
        h("  New apps found since last run:")
        h(DASH)
        for rule, new_apps, gone_apps in rules_with_new:
            h(f"  Rule: {rule}")
            for app in sorted(new_apps):
                h(f"    + {app}")
            if show_gone and gone_apps:
                for app in sorted(gone_apps):
                    h(f"    - {app}  (no longer seen)")
            h()
    else:
        h(DASH)
        h("  No new apps found since last run.")
        h(DASH)
        h()

    if show_gone and rules_with_gone:
        h(DASH)
        h("  Apps no longer seen (likely captured by APP-ID rules):")
        h(DASH)
        for rule, gone_apps in rules_with_gone:
            h(f"  Rule: {rule}")
            for app in sorted(gone_apps):
                h(f"    - {app}")
            h()

    if show_unchanged and rules_unchanged:
        h(DASH)
        h("  Unchanged rules:")
        h(DASH)
        for rule in rules_unchanged:
            curr_apps = curr_run.apps_by_rule.get(rule, frozenset())
            h(f"  {rule}  ({len(curr_apps)} app(s))")
        h()

    # ── Cumulative: baseline vs latest ────────────────────────────────────────
    h(SEP)
    baseline_label = first_run.query_start.strftime('%Y-%m-%d') if first_run.query_start else first_run.run_dt.strftime('%Y-%m-%d')
    latest_label   = last_run.query_end.strftime('%Y-%m-%d') if last_run.query_end else last_run.run_dt.strftime('%Y-%m-%d')
    h(f"  Cumulative: Baseline → Latest")
    h(f"  ({baseline_label} → {latest_label})")
    h(SEP)

    expanded:   list[tuple[str, frozenset, frozenset, frozenset, frozenset]] = []
    contracted: list[tuple[str, frozenset, frozenset, frozenset]]            = []

    for rule in first_run.rule_order:
        base_apps   = first_run.apps_by_rule.get(rule, frozenset())
        latest_apps = last_run.apps_by_rule.get(rule, frozenset())
        net_new  = latest_apps - base_apps
        net_gone = base_apps - latest_apps

        if net_new:
            expanded.append((rule, base_apps, latest_apps, net_new, net_gone))
        elif net_gone:
            contracted.append((rule, base_apps, latest_apps, net_gone))

    h(f"  Rules with net NEW apps vs baseline     : {len(expanded)}")
    total_same = len(first_run.rule_order) - len(expanded) - len(contracted)
    h(f"  Rules with fewer apps vs baseline       : {len(contracted)}  (APP-ID migration progress)")
    h(f"  Rules unchanged from baseline           : {total_same}")
    h()

    if expanded:
        h(DASH)
        h("  Rules with net NEW apps vs baseline:")
        h(DASH)
        for rule, base_apps, latest_apps, net_new, net_gone in expanded:
            h(f"  Rule: {rule}")
            h(f"    Baseline  : {', '.join(sorted(base_apps)) or '(none)'}")
            h(f"    Latest    : {', '.join(sorted(latest_apps)) or '(none)'}")
            h(f"    Net new   : {', '.join(sorted(net_new))}")
            if net_gone:
                h(f"    Also gone : {', '.join(sorted(net_gone))}")
            h()

    if contracted and show_gone:
        h(DASH)
        h("  Rules with fewer apps vs baseline (APP-ID migration progress):")
        h(DASH)
        for rule, base_apps, latest_apps, net_gone in contracted:
            h(f"  Rule: {rule}")
            h(f"    Baseline  : {', '.join(sorted(base_apps)) or '(none)'}")
            h(f"    Latest    : {', '.join(sorted(latest_apps)) or '(none)'}")
            h(f"    Gone      : {', '.join(sorted(net_gone))}")
            h()
    elif contracted and not show_gone:
        h(DASH)
        h(f"  {len(contracted)} rule(s) have fewer apps vs baseline (APP-ID migration progress).")
        h(f"  Run with --gone to see details.")
        h()

    h(SEP)
    return lines


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compare consecutive get-rule-apps.py runs for delta/progression reporting."
    )
    parser.add_argument(
        "csv_files", nargs="*", metavar="CSV",
        help="Two or more rule-apps-*.csv files to compare (oldest first). "
             "When omitted, auto-discovers files in --dir.",
    )
    parser.add_argument(
        "--dir", "-d", metavar="PATH", default="Output",
        help="Directory to auto-discover rule-apps-*-TIMESTAMP.csv files (default: Output/)",
    )
    parser.add_argument(
        "--stem", metavar="NAME",
        help="With --dir: only compare CSVs whose stem matches NAME",
    )
    parser.add_argument(
        "--output", "-o", metavar="PATH",
        help="Output report path (default: Output/rule-delta-TIMESTAMP.txt)",
    )
    parser.add_argument(
        "--gone", action="store_true",
        help="Show 'apps no longer seen' sections (hidden by default)",
    )
    parser.add_argument(
        "--show-unchanged", action="store_true",
        help="Include rules with no changes in the delta section",
    )
    args = parser.parse_args()

    run_dt    = datetime.datetime.now()
    timestamp = run_dt.strftime("%Y%m%d-%H%M%S")

    # ── Load runs ─────────────────────────────────────────────────────────────
    groups: dict[str, list[RunData]] = {}

    if args.csv_files:
        for path in args.csv_files:
            run = load_run(path)
            if run:
                groups.setdefault(run.stem, []).append(run)
        # Sort each group by run_dt in case the user passed files out of order
        for stem in groups:
            groups[stem].sort(key=lambda r: r.run_dt)
    else:
        search_dir = Path(args.dir)
        if not search_dir.exists():
            print(f"Error: directory not found: {search_dir}", file=sys.stderr)
            sys.exit(1)

        found = sorted(search_dir.glob("rule-apps-*.csv"))
        if not found:
            print(f"No rule-apps-*.csv files found in {search_dir}", file=sys.stderr)
            sys.exit(1)

        for path in found:
            run = load_run(str(path))
            if run is None:
                continue
            if args.stem and run.stem != args.stem:
                continue
            groups.setdefault(run.stem, []).append(run)

        for stem in groups:
            groups[stem].sort(key=lambda r: r.run_dt)

    if not groups:
        print("No valid run files found.", file=sys.stderr)
        sys.exit(1)

    # ── Generate reports ──────────────────────────────────────────────────────
    all_lines: list[str] = []

    for stem, runs in sorted(groups.items()):
        if len(runs) < 2:
            print(f"  Stem '{stem}': only {len(runs)} run found — need at least 2 to compare, skipping.")
            continue
        print(f"  Comparing {len(runs)} run(s) for stem '{stem}' ...")
        group_lines = _generate_group_report(
            runs           = runs,
            stem           = stem,
            show_gone      = args.gone,
            show_unchanged = args.show_unchanged,
        )
        all_lines.extend(group_lines)
        all_lines.append("")

    if not all_lines:
        print("Nothing to report — all stems have fewer than 2 runs.")
        sys.exit(0)

    output_path = args.output or f"Output/rule-delta-{timestamp}.txt"
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    report_text = "\n".join(all_lines)
    print()
    print(report_text)

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(report_text + "\n")

    print()
    print(f"  Report written: {output_path}")


if __name__ == "__main__":
    main()
