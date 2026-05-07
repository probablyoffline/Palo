"""
get-rule-apps.py — identify distinct applications seen per security rule

For each rule in the input file, queries PAN-OS traffic logs across the
available window using adaptive time-sliced pagination, collects all unique
'app' values, and writes a summary CSV.

Intended workflow:
  1. Run to baseline all apps currently matching each 'any-app' rule.
  2. Build new app-id rules above the old rules.
  3. Re-run after ~1 week to catch apps not seen in the initial pass.
  4. When an old rule shows no new apps, phase it out.

Usage:
    python get-rule-apps.py <input_file> [options]

Time period (choose one):
    --days N                              Days back from now (default: 7)
    --start DATETIME [--end DATETIME]     Explicit range; --end defaults to now
                                          Format: YYYY-MM-DD or YYYY-MM-DD HH:MM:SS

Other options:
    --action allow|deny|drop|all          Filter by action (default: allow)
    --output PATH / -o PATH               Output CSV path (default: rule-apps-YYYYMMDD-HHMMSS.csv)
    --window-hours N                      Initial query window in hours (default: 24)
    --min-window-hours N                  Minimum subdivision window in hours (default: 1)

Pagination:
    Each rule's time range is sliced into --window-hours chunks. Any chunk
    that returns the 5000-entry cap is recursively halved down to
    --min-window-hours to avoid missing apps in busy windows.
    Chunks still capped at the minimum window are flagged in the output.

Before running: set MODE / VSYS / DEVICE_GROUP in ops_lib.py.
"""

import argparse
import csv
import datetime
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "libs"))
import ops_lib  # noqa: E402

# ── Configuration ─────────────────────────────────────────────────────────────
DAYS_BACK            = 7
MAX_LOGS             = 5000
POLL_INTERVAL        = 3    # seconds between job-status polls
POLL_TIMEOUT         = 120  # seconds before giving up on a single job
INITIAL_WINDOW_HOURS = 24   # starting slice size
MIN_WINDOW_HOURS     = 1    # smallest slice before giving up on subdivision

requests.packages.urllib3.disable_warnings()


# ── API helpers ───────────────────────────────────────────────────────────────

def _post(params: dict) -> str:
    r = requests.post(
        f"https://{ops_lib.TARGET_HOST}/api/",
        data=params,
        verify=False,
        timeout=30,
    )
    r.raise_for_status()
    return r.text


def _build_query(
    rule_name: str,
    start_dt: datetime.datetime,
    end_dt: datetime.datetime,
    action: str,
) -> str:
    start_str = start_dt.strftime("%Y/%m/%d %H:%M:%S")
    end_str   = end_dt.strftime("%Y/%m/%d %H:%M:%S")
    parts = [
        f"(receive_time geq '{start_str}')",
        f"(receive_time leq '{end_str}')",
        f"(rule eq '{rule_name}')",
    ]
    if action != "all":
        parts.append(f"(action eq '{action}')")
    return " and ".join(parts)


def _submit_job(query: str) -> str | None:
    params = {
        "type":     "log",
        "log-type": "traffic",
        "query":    query,
        "nlogs":    str(MAX_LOGS),
        "dir":      "backward",
        "key":      ops_lib.API_KEY,
    }
    xml_text = _post(params)
    root = ET.fromstring(xml_text)
    if root.get("status") != "success":
        return None
    return root.findtext(".//job")


def _poll_job(job_id: str) -> str | None:
    deadline = time.monotonic() + POLL_TIMEOUT
    params = {
        "type":   "log",
        "action": "get",
        "job-id": job_id,
        "key":    ops_lib.API_KEY,
    }
    while time.monotonic() < deadline:
        xml_text = _post(params)
        root = ET.fromstring(xml_text)
        if root.findtext(".//status") == "FIN":
            return xml_text
        time.sleep(POLL_INTERVAL)
    return None


def _query_window(
    rule_name: str,
    start_dt: datetime.datetime,
    end_dt: datetime.datetime,
    action: str,
) -> tuple[set[str], int, bool]:
    """
    Query one time window. Returns (apps, entry_count, capped).
    On error or timeout, returns empty results and capped=False.
    """
    try:
        query  = _build_query(rule_name, start_dt, end_dt, action)
        job_id = _submit_job(query)
        if job_id is None:
            return set(), 0, False

        result_xml = _poll_job(job_id)
        if result_xml is None:
            return set(), 0, False

        root  = ET.fromstring(result_xml)
        apps  = set()
        count = 0
        for entry in root.iter("entry"):
            app = entry.findtext("app") or ""
            if app:
                apps.add(app)
            count += 1

        return apps, count, (count >= MAX_LOGS)

    except Exception:
        return set(), 0, False


# ── Adaptive pagination ───────────────────────────────────────────────────────

def _collect_window(
    rule_name: str,
    start_dt: datetime.datetime,
    end_dt: datetime.datetime,
    action: str,
    min_hours: float,
) -> tuple[set[str], int, bool, int]:
    """
    Recursively collect apps for [start_dt, end_dt].
    Halves the window on a cap until min_hours is reached.

    Returns (apps, entries_scanned, complete, windows_queried).
    """
    apps, count, capped = _query_window(rule_name, start_dt, end_dt, action)

    window_hours = (end_dt - start_dt).total_seconds() / 3600

    if capped and window_hours > min_hours:
        mid = start_dt + (end_dt - start_dt) / 2
        apps_l, count_l, complete_l, wins_l = _collect_window(
            rule_name, start_dt, mid, action, min_hours
        )
        apps_r, count_r, complete_r, wins_r = _collect_window(
            rule_name, mid, end_dt, action, min_hours
        )
        return (
            apps_l | apps_r,
            count_l + count_r,
            complete_l and complete_r,
            wins_l + wins_r,
        )

    return apps, count, not capped, 1


def collect_all_apps(
    rule_name: str,
    start_dt: datetime.datetime,
    end_dt: datetime.datetime,
    action: str,
    initial_hours: float,
    min_hours: float,
) -> tuple[set[str], int, bool, int]:
    """
    Slice [start_dt, end_dt] into initial_hours windows, then recursively
    subdivide any that are capped.

    Returns (apps, entries_scanned, complete, windows_queried).
    """
    all_apps   = set()
    total      = 0
    complete   = True
    total_wins = 0

    step   = datetime.timedelta(hours=initial_hours)
    cursor = start_dt
    while cursor < end_dt:
        win_end = min(cursor + step, end_dt)
        apps, count, win_complete, wins = _collect_window(
            rule_name, cursor, win_end, action, min_hours
        )
        all_apps   |= apps
        total      += count
        complete    = complete and win_complete
        total_wins += wins
        cursor      = win_end

    return all_apps, total, complete, total_wins


# ── Argument parsing ──────────────────────────────────────────────────────────

def _parse_datetime(s: str) -> datetime.datetime:
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.datetime.strptime(s, fmt)
        except ValueError:
            continue
    raise argparse.ArgumentTypeError(
        f"Cannot parse datetime: {s!r}  (use YYYY-MM-DD or 'YYYY-MM-DD HH:MM:SS')"
    )


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Identify distinct applications per security rule from PAN-OS traffic logs."
    )
    parser.add_argument("input_file", help=".txt or .csv file of rule names")

    time_grp = parser.add_mutually_exclusive_group()
    time_grp.add_argument(
        "--days", type=int, default=None, metavar="N",
        help=f"Days of history back from now (default: {DAYS_BACK})",
    )
    time_grp.add_argument(
        "--start", type=_parse_datetime, metavar="DATETIME",
        help="Start of time range (YYYY-MM-DD or YYYY-MM-DD HH:MM:SS)",
    )
    parser.add_argument(
        "--end", type=_parse_datetime, metavar="DATETIME",
        help="End of time range; only valid with --start (default: now)",
    )
    parser.add_argument(
        "--action", choices=["allow", "deny", "drop", "all"], default="allow",
        help="Filter log entries by action (default: allow)",
    )
    parser.add_argument(
        "--output", "-o", metavar="PATH",
        help="Output CSV path (default: rule-apps-YYYYMMDD-HHMMSS.csv)",
    )
    parser.add_argument(
        "--window-hours", type=float, default=INITIAL_WINDOW_HOURS, metavar="N",
        help=f"Initial query window in hours (default: {INITIAL_WINDOW_HOURS})",
    )
    parser.add_argument(
        "--min-window-hours", type=float, default=MIN_WINDOW_HOURS, metavar="N",
        help=f"Minimum subdivision window in hours (default: {MIN_WINDOW_HOURS})",
    )
    args = parser.parse_args()

    if args.end and not args.start:
        parser.error("--end requires --start")

    run_dt = datetime.datetime.now()

    if args.start:
        start_dt = args.start
        end_dt   = args.end if args.end else run_dt
    else:
        days     = args.days if args.days is not None else DAYS_BACK
        start_dt = run_dt - datetime.timedelta(days=days)
        end_dt   = run_dt

    try:
        rule_names = ops_lib.load_rule_names(args.input_file)
    except FileNotFoundError:
        print(f"Error: input file not found: {args.input_file}", file=sys.stderr)
        sys.exit(1)
    if not rule_names:
        print("No rule names found in input file.", file=sys.stderr)
        sys.exit(1)

    timestamp   = run_dt.strftime("%Y%m%d-%H%M%S")
    output_path = args.output or f"rule-apps-{timestamp}.csv"

    print("=" * 62)
    print("  get-rule-apps")
    print("=" * 62)
    print(f"  Target      : {ops_lib.TARGET_HOST}  ({ops_lib.mode_summary()})")
    print(f"  From        : {start_dt.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  To          : {end_dt.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Action      : {args.action}")
    print(f"  Window      : {args.window_hours}h initial / {args.min_window_hours}h minimum")
    print(f"  Rules       : {len(rule_names)}")
    print(f"  Output      : {output_path}")
    print()

    results: list[dict] = []

    for i, rule_name in enumerate(rule_names, start=1):
        prefix = f"[{i}/{len(rule_names)}]"
        print(f"{prefix} {rule_name} ...", end=" ", flush=True)

        all_apps, total_entries, complete, windows_queried = collect_all_apps(
            rule_name, start_dt, end_dt,
            args.action, args.window_hours, args.min_window_hours,
        )

        flag = "" if complete else " !"
        print(
            f"{len(all_apps)} apps, {total_entries} entries, "
            f"{windows_queried} window{'s' if windows_queried != 1 else ''}{flag}"
        )
        if not complete:
            print(
                f"         ! one or more windows hit the {MAX_LOGS}-entry cap at "
                f"min window size — app list may be incomplete"
            )

        results.append({
            "rule":            rule_name,
            "app_count":       len(all_apps),
            "apps":            "|".join(sorted(all_apps)),
            "entries_scanned": total_entries,
            "windows_queried": windows_queried,
            "complete":        "yes" if complete else "no",
        })

    fieldnames = ["rule", "app_count", "apps", "entries_scanned", "windows_queried", "complete"]
    with open(output_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    rules_with       = sum(1 for r in results if r["app_count"] > 0)
    rules_none       = sum(1 for r in results if r["app_count"] == 0)
    rules_incomplete = sum(1 for r in results if r["complete"] == "no")
    total_entries    = sum(r["entries_scanned"] for r in results)

    print()
    print("=" * 62)
    print("  Done.")
    print(f"  Rules queried    : {len(rule_names)}")
    print(f"  With apps        : {rules_with}")
    print(f"  No traffic       : {rules_none}")
    print(f"  Incomplete (!)   : {rules_incomplete}")
    print(f"  Total entries    : {total_entries}")
    print(f"  Output           : {output_path}")
    print("=" * 62)


if __name__ == "__main__":
    main()
