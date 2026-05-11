"""
get-rule-apps.py — identify distinct applications seen per security rule

For each rule in the input file, queries PAN-OS traffic logs across the
available window using adaptive time-sliced pagination, collects all unique
'app' values, and writes a summary CSV.

Each rule is written to the CSV immediately after it completes, so a crash
or connection drop only loses the rule currently being queried.

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
    --output PATH / -o PATH               Output CSV (default: rule-apps-YYYYMMDD-HHMMSS.csv)
    --resume                              Skip rules already present in the output file
    --skip-unused                       Skip rules with no hits since the query window
                                          start (uses the hit-count API — one call for all
                                          rules before querying begins)
    --window-hours N                      Initial query window in hours (default: 24)
    --min-window-hours N                  Minimum subdivision window in hours (default: 1)
    --device-group NAME / --dg NAME        Override the device group used to fetch rule
                                          service config and hit counts (Panorama mode only;
                                          overrides DEVICE_GROUP in ops_lib.py for this run)
    --verbose / -v                        Show per-window detail, job IDs, and polling dots

Resume after interruption:
    Always specify --output so the filename is known before the run starts.
    If the run is interrupted, rerun with the same --output path and --resume.
    Rules already written to the CSV are skipped; the script picks up where
    it left off. The rule being queried when the crash happened is re-queried.

Pagination:
    Each rule's time range is sliced into --window-hours chunks. Any chunk
    that returns the 5000-entry cap is recursively halved down to
    --min-window-hours to avoid missing apps in busy windows.
    Chunks still capped at the minimum window are flagged in the output.

Before running: set MODE / VSYS / DEVICE_GROUP in ops_lib.py.
"""

import argparse
import concurrent.futures
import csv
import datetime
import sys
import threading
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
HTTP_TIMEOUT         = 90   # seconds for each HTTP request (increase if Panorama is slow)
INITIAL_WINDOW_HOURS = 24
MIN_WINDOW_HOURS     = 1
MAX_QUERIES_PER_RULE = 50   # cap per rule to avoid exhausting Panorama's job queue
QUERY_DELAY          = 0    # extra seconds to sleep between query submissions

VERBOSE  = False  # set from --verbose flag at startup
PARALLEL = False  # set to True when workers > 1; suppresses per-window prints

_print_lock = threading.Lock()
_csv_lock   = threading.Lock()

CSV_FIELDNAMES = ["rule", "app_count", "apps", "port_count", "ports", "entries_scanned", "windows_queried", "complete"]

requests.packages.urllib3.disable_warnings()


# ── API helpers ───────────────────────────────────────────────────────────────

def _post(params: dict) -> str:
    r = requests.post(
        f"https://{ops_lib.TARGET_HOST}/api/",
        data=params,
        verify=False,
        timeout=HTTP_TIMEOUT,
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
    return _submit_job_n(query, MAX_LOGS)


def _submit_job_n(query: str, nlogs: int) -> str | None:
    params = {
        "type":     "log",
        "log-type": "traffic",
        "query":    query,
        "nlogs":    str(nlogs),
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
            if VERBOSE:
                print(" done", end="", flush=True)
            return xml_text
        if VERBOSE:
            print(".", end="", flush=True)
        time.sleep(POLL_INTERVAL)
    if VERBOSE:
        print(" TIMEOUT", end="", flush=True)
    return None


def _query_window(
    rule_name: str,
    start_dt: datetime.datetime,
    end_dt: datetime.datetime,
    action: str,
    indent: int = 0,
) -> tuple[set[str], int, bool, bool]:
    """
    Query one time window. Returns (apps, entry_count, capped, ok).
    ok=False means the query failed or timed out — treat as incomplete,
    not genuine no-traffic.
    """
    pad = "  " * indent

    if VERBOSE:
        fmt = "%m-%d %H:%M"
        print(
            f"{pad}  [{start_dt.strftime(fmt)} – {end_dt.strftime(fmt)}]",
            end="  ", flush=True,
        )

    try:
        query  = _build_query(rule_name, start_dt, end_dt, action)
        job_id = _submit_job(query)
        if job_id is None:
            if VERBOSE:
                print("submission failed", flush=True)
            return set(), 0, False, False   # ok=False

        if VERBOSE:
            print(f"job:{job_id} polling", end="", flush=True)

        result_xml = _poll_job(job_id)
        if result_xml is None:
            if VERBOSE:
                print("  (timeout)", flush=True)
            return set(), 0, False, False   # ok=False

        root  = ET.fromstring(result_xml)
        apps  = set()
        count = 0
        for entry in root.iter("entry"):
            app = entry.findtext("app") or ""
            if app:
                apps.add(app)
            count += 1

        capped = count >= MAX_LOGS

        if VERBOSE:
            cap_note = "  *** CAPPED ***" if capped else ""
            print(f"  ({count} entries){cap_note}", flush=True)

        if QUERY_DELAY > 0:
            time.sleep(QUERY_DELAY)

        return apps, count, capped, True    # ok=True

    except Exception as exc:
        if VERBOSE:
            print(f"  error: {exc}", flush=True)
        else:
            fmt = "%b %d %H:%M"
            print(
                f"  error [{start_dt.strftime(fmt)}–{end_dt.strftime(fmt)}]: {exc}",
                flush=True,
            )
        return set(), set(), 0, False, False       # ok=False


# ── Adaptive pagination ───────────────────────────────────────────────────────

def _collect_window(
    rule_name: str,
    start_dt: datetime.datetime,
    end_dt: datetime.datetime,
    action: str,
    min_hours: float,
    indent: int = 0,
    budget: list[int] | None = None,
) -> tuple[set[str], int, bool, int]:
    """
    Recursively collect apps for [start_dt, end_dt].
    Halves the window on a cap until min_hours is reached or budget is exhausted.

    budget is a one-element list used as a shared mutable counter across all
    recursive calls for a single rule. When it reaches 0, subdivision stops
    and the window is marked incomplete.

    Returns (apps, entries_scanned, complete, windows_queried).
    """
    if budget is not None and budget[0] <= 0:
        return set(), 0, False, 0

    apps, count, capped, ok = _query_window(rule_name, start_dt, end_dt, action, indent)

    if budget is not None:
        budget[0] -= 1

    if not ok:
        return apps, count, False, 1   # error/timeout — mark incomplete

    window_hours = (end_dt - start_dt).total_seconds() / 3600

    if capped and window_hours > min_hours:
        if budget is not None and budget[0] <= 0:
            # Budget exhausted mid-subdivision — mark incomplete but keep what we have.
            return apps, count, False, 1

        if VERBOSE:
            pad = "  " * indent
            print(f"{pad}    subdividing...", flush=True)
        mid = start_dt + (end_dt - start_dt) / 2
        apps_l, count_l, complete_l, wins_l = _collect_window(
            rule_name, start_dt, mid, action, min_hours, indent + 1, budget
        )
        apps_r, count_r, complete_r, wins_r = _collect_window(
            rule_name, mid, end_dt, action, min_hours, indent + 1, budget
        )
        return (
            apps_l | apps_r,
            count_l + count_r,
            complete_l and complete_r,
            wins_l + wins_r,
        )

    return apps, count, not capped, 1


def _build_initial_windows(
    start_dt: datetime.datetime,
    end_dt: datetime.datetime,
    initial_hours: float,
) -> list[tuple[datetime.datetime, datetime.datetime]]:
    windows = []
    step    = datetime.timedelta(hours=initial_hours)
    cursor  = start_dt
    while cursor < end_dt:
        windows.append((cursor, min(cursor + step, end_dt)))
        cursor += step
    return windows


def collect_all_apps(
    rule_name: str,
    start_dt: datetime.datetime,
    end_dt: datetime.datetime,
    action: str,
    initial_hours: float,
    min_hours: float,
    max_queries: int,
) -> tuple[set[str], int, bool, int]:
    """
    Slice [start_dt, end_dt] into initial_hours windows, then recursively
    subdivide any that are capped.  Total API calls across all windows for
    this rule are capped at max_queries.

    Returns (apps, entries_scanned, complete, windows_queried).
    """
    windows    = _build_initial_windows(start_dt, end_dt, initial_hours)
    all_apps   = set()
    total      = 0
    complete   = True
    total_wins = 0
    budget     = [max_queries]   # shared mutable counter across all windows

    for w_idx, (win_start, win_end) in enumerate(windows, 1):
        if budget[0] <= 0:
            if not PARALLEL:
                print(
                    f"  range {w_idx:2}/{len(windows)}  "
                    f"(query limit reached — {len(windows) - w_idx + 1} range(s) skipped)",
                    flush=True,
                )
            complete = False
            break

        if not PARALLEL:
            if VERBOSE:
                print(f"  range {w_idx:2}/{len(windows)}", end="  ", flush=True)
            else:
                fmt = "%b %d"
                print(
                    f"  range {w_idx:2}/{len(windows)}  "
                    f"({win_start.strftime(fmt)}–{win_end.strftime(fmt)}) ...",
                    end="  ", flush=True,
                )

        apps, count, win_complete, wins = _collect_window(
            rule_name, win_start, win_end, action, min_hours,
            indent=1 if VERBOSE else 0,
            budget=budget,
        )

        if not PARALLEL and not VERBOSE:
            if count == 0:
                print("no traffic", flush=True)
            elif not win_complete:
                print(f"{count} entries  (capped → subdivided, incomplete)", flush=True)
            elif wins > 1:
                print(f"{count} entries  (subdivided into {wins} queries)", flush=True)
            else:
                print(f"{count} entries", flush=True)

        all_apps   |= apps
        total      += count
        complete    = complete and win_complete
        total_wins += wins

    return all_apps, total, complete, total_wins


# ── Activity checks ───────────────────────────────────────────────────────────

def fetch_hit_counts(debug_path: str | None = None) -> dict[str, int]:
    """
    Fetch last-hit timestamps for all security rules via the operational
    hit-count command.  Returns {rule_name: last_hit_unix_timestamp}.
    A timestamp of 0 means the rule has never been hit (or count was reset).

    If debug_path is given, the raw API response is written to that file.
    """
    if ops_lib.MODE == "panorama":
        rb_tag = f"{ops_lib.RULEBASE}-rulebase"
        cmd = (
            f"<show><rule-hit-count><device-group>"
            f"<entry name='{ops_lib.DEVICE_GROUP}'>"
            f"<{rb_tag}><entry name='security'><rules><all/></rules></entry></{rb_tag}>"
            f"</entry></device-group></rule-hit-count></show>"
        )
    else:
        cmd = (
            f"<show><rule-hit-count><vsys>"
            f"<entry name='{ops_lib.VSYS}'>"
            f"<rulebase><entry name='security'><rules><all/></rules></entry></rulebase>"
            f"</entry></vsys></rule-hit-count></show>"
        )

    xml_text = _post({"type": "op", "cmd": cmd, "key": ops_lib.API_KEY})

    if debug_path:
        with open(debug_path, "w", encoding="utf-8") as fh:
            fh.write(xml_text)

    root = ET.fromstring(xml_text)

    hit_counts: dict[str, int] = {}
    for entry in root.iter("entry"):
        ts_el = entry.find("last-hit-timestamp")
        if ts_el is not None:                       # rule entries have this; containers don't
            name = entry.get("name", "")
            if name:
                try:
                    hit_counts[name] = int(ts_el.text or "0")
                except ValueError:
                    hit_counts[name] = 0
    return hit_counts


def precheck_has_traffic(
    rule_name: str,
    start_dt: datetime.datetime,
    end_dt: datetime.datetime,
    action: str,
) -> bool:
    """
    Submit a single nlogs=1 query for the rule. Returns True if any log
    entry exists in the window, False if none. Returns True on any error
    so the rule is queried rather than silently skipped.
    """
    try:
        query  = _build_query(rule_name, start_dt, end_dt, action)
        job_id = _submit_job_n(query, 1)
        if job_id is None:
            return True
        result_xml = _poll_job(job_id)
        if result_xml is None:
            return True  # timeout — assume active
        root = ET.fromstring(result_xml)
        return any(True for _ in root.iter("entry"))

    except Exception:
        return True


# ── Resume helpers ────────────────────────────────────────────────────────────

def load_completed_rules(output_path: str) -> set[str]:
    """Return the set of rule names already written to an existing output CSV."""
    p = Path(output_path)
    if not p.exists():
        return set()
    completed = set()
    with open(p, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            if "rule" in row:
                completed.add(row["rule"])
    return completed


# ── Rule config helpers ───────────────────────────────────────────────────────

def fetch_rule_services(rule_names: list[str]) -> dict[str, list[str]]:
    """
    Fetch the service members configured on each security rule via the config API.
    Returns {rule_name: [member, ...]} for all rules found in config.
    Rules not found or with no service element map to an empty list.
    """
    try:
        xml_text = ops_lib.api_get(ops_lib.rules_xpath())
        root = ET.fromstring(xml_text)
    except Exception as exc:
        print(f"  Warning: could not fetch rule services from config: {exc}", flush=True)
        return {}

    wanted = set(rule_names)
    result: dict[str, list[str]] = {}
    for entry in root.iter("entry"):
        name = entry.get("name", "")
        if name not in wanted:
            continue
        svc_el  = entry.find("service")
        members = [m.text for m in svc_el.findall("member") if m.text] if svc_el is not None else []
        result[name] = sorted(members)
    return result


# ── Parallel worker ───────────────────────────────────────────────────────────

def _process_rule(
    rule_name:        str,
    rule_index:       int,
    total_rules:      int,
    start_dt:         datetime.datetime,
    end_dt:           datetime.datetime,
    action:           str,
    window_hours:     float,
    min_window_hours: float,
    max_queries:      int,
    use_precheck:     bool,
    services_map:     dict[str, list[str]],
) -> tuple[dict, str]:
    """
    Process one rule in a worker thread.
    Returns (csv_row, console_output_block).
    """
    lines: list[str] = [f"[{rule_index}/{total_rules}] {rule_name}"]
    services = services_map.get(rule_name, [])

    if use_precheck:
        lines.append("  precheck ...")
        has_traffic = precheck_has_traffic(rule_name, start_dt, end_dt, action)
        if not has_traffic:
            lines[-1] += "  no traffic — skipped"
            row = {
                "rule":            rule_name,
                "app_count":       0,
                "apps":            "",
                "port_count":      len(services),
                "ports":           "|".join(services),
                "entries_scanned": 0,
                "windows_queried": 1,
                "complete":        "skipped",
            }
            return row, "\n".join(lines)
        lines[-1] += "  traffic found — querying"

    all_apps, total_entries, complete, windows_queried = collect_all_apps(
        rule_name, start_dt, end_dt,
        action, window_hours, min_window_hours, max_queries,
    )

    flag = " !" if not complete else ""
    lines.append(
        f"  → {len(all_apps)} apps | {total_entries} entries | "
        f"{windows_queried} quer{'y' if windows_queried == 1 else 'ies'}{flag}"
    )
    if not complete:
        lines.append(
            f"  ! one or more windows hit the {MAX_LOGS}-entry cap at "
            f"min window size — app list may be incomplete"
        )

    row = {
        "rule":            rule_name,
        "app_count":       len(all_apps),
        "apps":            "|".join(sorted(all_apps)),
        "port_count":      len(services),
        "ports":           "|".join(services),
        "entries_scanned": total_entries,
        "windows_queried": windows_queried,
        "complete":        "yes" if complete else "no",
    }
    return row, "\n".join(lines)


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
    global VERBOSE, PARALLEL, QUERY_DELAY

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
        "--resume", action="store_true",
        help="Skip rules already present in the output file and append new results",
    )
    parser.add_argument(
        "--window-hours", type=float, default=INITIAL_WINDOW_HOURS, metavar="N",
        help=f"Initial query window in hours (default: {INITIAL_WINDOW_HOURS})",
    )
    parser.add_argument(
        "--min-window-hours", type=float, default=MIN_WINDOW_HOURS, metavar="N",
        help=f"Minimum subdivision window in hours (default: {MIN_WINDOW_HOURS})",
    )
    parser.add_argument(
        "--skip-unused", action="store_true",
        help="Skip rules with no hits since the query window start (hit-count API)",
    )
    parser.add_argument(
        "--max-queries-per-rule", type=int, default=MAX_QUERIES_PER_RULE, metavar="N",
        help=f"Max API queries per rule before marking incomplete (default: {MAX_QUERIES_PER_RULE})",
    )
    parser.add_argument(
        "--query-delay", type=float, default=QUERY_DELAY, metavar="SECS",
        help="Extra seconds to sleep between query submissions (default: 0)",
    )
    parser.add_argument(
        "--debug-hitcount", metavar="PATH",
        help="Write the raw hit-count API response to PATH for inspection (implies --skip-unused)",
    )
    parser.add_argument(
        "--workers", type=int, default=2, metavar="N",
        help="Parallel rules to query simultaneously (default: 2; increase carefully)",
    )
    parser.add_argument(
        "--device-group", "--dg", metavar="NAME", dest="device_group",
        help="Override the device group for rule config/hit-count lookups (Panorama mode only)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Show per-window date ranges, job IDs, and polling dots (workers=1 only)",
    )
    args = parser.parse_args()

    if args.end and not args.start:
        parser.error("--end requires --start")

    if args.resume and not args.output:
        parser.error("--resume requires --output so the filename is known")

    if args.debug_hitcount:
        args.skip_unused = True

    if args.device_group:
        ops_lib.DEVICE_GROUP = args.device_group

    VERBOSE     = args.verbose
    PARALLEL    = args.workers > 1
    QUERY_DELAY = args.query_delay

    if VERBOSE and PARALLEL:
        print("Note: --verbose is ignored when --workers > 1", flush=True)

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
    input_stem  = Path(args.input_file).stem
    output_path = args.output or f"Output/rule-apps-{input_stem}-{timestamp}.csv"
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    # Determine which rules are already done (resume mode).
    completed_rules: set[str] = set()
    if args.resume:
        completed_rules = load_completed_rules(output_path)

    remaining = [r for r in rule_names if r not in completed_rules]
    file_mode = "a" if (args.resume and completed_rules) else "w"

    print("=" * 62)
    print("  get-rule-apps")
    print("=" * 62)
    print(f"  Target      : {ops_lib.TARGET_HOST}  ({ops_lib.mode_summary()})")
    print(f"  From        : {start_dt.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  To          : {end_dt.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Action      : {args.action}")
    print(f"  Window      : {args.window_hours}h initial / {args.min_window_hours}h minimum")
    print(f"  Query cap   : {args.max_queries_per_rule} per rule")
    print(f"  Workers     : {args.workers}")
    inactive_mode = "hit-count API" if not args.debug_hitcount else "hit-count API (debug)"
    print(f"  Rules       : {len(rule_names)} total / {len(remaining)} to query")
    if args.skip_unused:
        print(f"  Inactive    : will skip via {inactive_mode} (with precheck fallback)")
    if completed_rules:
        print(f"  Resuming    : {len(completed_rules)} already complete, skipping")
    print(f"  Output      : {output_path}  ({file_mode})")
    print()

    # ── Rule service config fetch ─────────────────────────────────────────────
    print("  Fetching rule service configurations ...", end=" ", flush=True)
    services_map = fetch_rule_services(rule_names)
    found = sum(1 for n in rule_names if n in services_map)
    print(f"{found}/{len(rule_names)} rules found in config")
    print()

    # ── Activity pre-filter ───────────────────────────────────────────────────
    # active_rules: set  → batch hit-count filter succeeded; only these are queried
    # active_rules: None → no batch filter; use per-rule precheck if skip_unused
    active_rules: set[str] | None = None
    use_precheck = False

    if args.skip_unused:
        debug_path = args.debug_hitcount or None
        print("  Fetching rule hit counts ...", end=" ", flush=True)
        try:
            hit_counts = fetch_hit_counts(debug_path=debug_path)
            if debug_path:
                print(f"\n  Raw response written to: {debug_path}")
                print("  Fetching rule hit counts ...", end=" ", flush=True)

            if not hit_counts:
                raise ValueError("API returned 0 rules")

            start_epoch = int(start_dt.timestamp())
            candidate   = {name for name, ts in hit_counts.items() if ts >= start_epoch}

            if not candidate:
                raise ValueError(
                    f"all {len(hit_counts)} rules show no hits since "
                    f"{start_dt.strftime('%Y-%m-%d')} — hit counts may have been reset"
                )

            active_rules = candidate
            print(
                f"{len(hit_counts)} rules checked — "
                f"{len(active_rules)} active, "
                f"{len(hit_counts) - len(active_rules)} inactive"
            )

        except Exception as exc:
            print(
                f"hit-count API unavailable ({exc})\n"
                f"  Falling back to per-rule traffic precheck (1 query per rule)."
            )
            use_precheck = True
        print()

    run_results: list[dict] = []
    run_start = datetime.datetime.now()
    consecutive_no_traffic = 0
    CONSECUTIVE_WARN = 5

    # Worker kwargs shared across all rule submissions
    worker_kwargs = dict(
        start_dt         = start_dt,
        end_dt           = end_dt,
        action           = args.action,
        window_hours     = args.window_hours,
        min_window_hours = args.min_window_hours,
        max_queries      = args.max_queries_per_rule,
        use_precheck     = use_precheck,
        services_map     = services_map,
    )

    def _write_row(writer, fh, row: dict) -> None:
        with _csv_lock:
            writer.writerow(row)
            fh.flush()

    with open(output_path, file_mode, newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDNAMES)
        if file_mode == "w":
            writer.writeheader()
            fh.flush()

        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
            future_to_index: dict[concurrent.futures.Future, int] = {}

            for i, rule_name in enumerate(rule_names, start=1):
                total = len(rule_names)

                if rule_name in completed_rules:
                    print(f"[{i}/{total}] {rule_name}  (skipped — already complete)")
                    continue

                if active_rules is not None and rule_name not in active_rules:
                    print(
                        f"[{i}/{total}] {rule_name}  "
                        f"(skipped — no hits since {start_dt.strftime('%Y-%m-%d')})"
                    )
                    svc = services_map.get(rule_name, [])
                    row = {
                        "rule":            rule_name,
                        "app_count":       0,
                        "apps":            "",
                        "port_count":      len(svc),
                        "ports":           "|".join(svc),
                        "entries_scanned": 0,
                        "windows_queried": 0,
                        "complete":        "skipped",
                    }
                    _write_row(writer, fh, row)
                    run_results.append(row)
                    continue

                if PARALLEL:
                    print(f"[{i}/{total}] {rule_name}  → queuing...", flush=True)
                future = pool.submit(
                    _process_rule, rule_name, i, total, **worker_kwargs
                )
                future_to_index[future] = i

            # Collect results as workers finish
            for future in concurrent.futures.as_completed(future_to_index):
                try:
                    row, output = future.result()
                except Exception as exc:
                    # Unexpected worker crash — log and continue
                    with _print_lock:
                        print(f"  *** worker error: {exc}", flush=True)
                    continue

                with _print_lock:
                    print(output)
                    print()

                _write_row(writer, fh, row)
                run_results.append(row)

                if not PARALLEL:
                    # Consecutive no-traffic warning only meaningful in sequential mode
                    if row["entries_scanned"] == 0 and row["complete"] != "skipped":
                        consecutive_no_traffic += 1
                        if consecutive_no_traffic == CONSECUTIVE_WARN:
                            print(
                                f"\n  *** WARNING: {CONSECUTIVE_WARN} rules in a row "
                                f"returned no traffic. The Panorama log job queue may be "
                                f"exhausted. ***\n"
                                f"  Consider stopping, waiting a few minutes, then resuming "
                                f"with --resume.\n"
                                f"  Adding --query-delay 2 on the next run can help.\n",
                                flush=True,
                            )
                    else:
                        consecutive_no_traffic = 0

    rules_queried    = sum(1 for r in run_results if r["complete"] != "skipped")
    rules_skipped    = sum(1 for r in run_results if r["complete"] == "skipped")
    rules_with       = sum(1 for r in run_results if r["app_count"] > 0)
    rules_none       = sum(1 for r in run_results if r["complete"] not in ("skipped",) and r["app_count"] == 0)
    rules_incomplete = sum(1 for r in run_results if r["complete"] == "no")
    total_entries    = sum(r["entries_scanned"] for r in run_results)

    elapsed = datetime.datetime.now() - run_start
    elapsed_str = str(elapsed).split(".")[0]  # HH:MM:SS, no microseconds

    p            = Path(output_path)
    summary_path = str(p.with_name(p.stem + "-summary.txt"))

    summary_lines = [
        "=" * 62,
        "  Done.",
        f"  Elapsed          : {elapsed_str}",
        f"  Target           : {ops_lib.TARGET_HOST}  ({ops_lib.mode_summary()})",
        f"  Input            : {args.input_file}",
        f"  From             : {start_dt.strftime('%Y-%m-%d %H:%M:%S')}",
        f"  To               : {end_dt.strftime('%Y-%m-%d %H:%M:%S')}",
        f"  Action           : {args.action}",
        "-" * 62,
        f"  Rules queried    : {rules_queried}",
    ]
    if completed_rules:
        summary_lines.append(f"  Rules resumed    : {len(completed_rules)}  (skipped — already complete)")
    if rules_skipped:
        summary_lines.append(f"  Rules inactive   : {rules_skipped}  (skipped — no hits in window)")
    summary_lines += [
        f"  With apps        : {rules_with}",
        f"  No traffic       : {rules_none}",
        f"  Incomplete (!)   : {rules_incomplete}",
        f"  Total entries    : {total_entries}",
        "-" * 62,
        f"  Output           : {output_path}",
        f"  Summary          : {summary_path}",
        "=" * 62,
    ]

    summary_text = "\n".join(summary_lines)
    print(summary_text)

    with open(summary_path, "w", encoding="utf-8") as sf:
        sf.write(summary_text + "\n")


if __name__ == "__main__":
    main()
