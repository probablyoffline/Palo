"""
get-rule-apps.py — identify distinct applications seen per security rule

For each rule in the input file, queries PAN-OS traffic logs across the
full date range using iterative app-exclusion, collects all unique 'app'
values, and writes a summary CSV.

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
    --resume                              Skip complete/skipped rules; re-query incomplete ones
    --skip-unused                         Skip rules with no hits since the query window
                                          start (uses the hit-count API — one call for all
                                          rules before querying begins)
    --device-group NAME / --dg NAME       Override the device group used to fetch rule
                                          service config and hit counts (Panorama mode only;
                                          overrides DEVICE_GROUP in ops_lib.py for this run)
    --max-queries-per-rule N              Max API queries per rule (default: 50)
    --poll-timeout SECS                   Seconds to wait per log job (default: 120)
    --stats-window MONTHS                 App stats lookback window in months (default: 13)
    --no-stats                            Skip rule stats; always query traffic logs
    --debug-rule-stats PATH               Write raw rule app stats response to PATH
    --verbose / -v                        Show job IDs and polling dots

Pagination:
    Each rule queries the full date range. If the result is capped at 5000
    entries, all found apps are excluded and the query re-runs to surface
    the next layer of apps. This repeats until the result is empty or
    uncapped. For most rules this completes in 2-5 queries regardless of
    traffic volume.

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
import ops_lib        # noqa: E402
import log_query_lib  # noqa: E402

# ── Configuration ─────────────────────────────────────────────────────────────
VERSION              = "1.5.4"

DAYS_BACK            = 7
MAX_LOGS             = 5000
POLL_INTERVAL        = 3    # seconds between job-status polls
POLL_TIMEOUT         = 120  # seconds before giving up on a single job
HTTP_TIMEOUT         = 90   # seconds for each HTTP request (increase if Panorama is slow)
MAX_QUERIES_PER_RULE = 50   # cap per rule; most rules complete in < 10 rounds
APP_COUNT_WARN       = 20   # warn when a rule has more distinct apps than this
QUERY_DELAY          = 0    # extra seconds to sleep between query submissions

VERBOSE  = False  # set from --verbose flag at startup
PARALLEL = False  # set to True when workers > 1; suppresses per-window prints

_print_lock = threading.Lock()
_csv_lock   = threading.Lock()

CSV_FIELDNAMES = ["rule", "app_count", "apps", "port_count", "ports", "app_port_details", "entries_scanned", "windows_queried", "complete", "data_source"]

requests.packages.urllib3.disable_warnings()


# ── API helpers ───────────────────────────────────────────────────────────────
# Local _post for operational (non-log) API calls such as hit-count queries.
# Log queries and pagination are handled by log_query_lib.

def _post(params: dict) -> str:
    r = requests.post(
        f"https://{ops_lib.TARGET_HOST}/api/",
        data=params,
        verify=False,
        timeout=HTTP_TIMEOUT,
    )
    r.raise_for_status()
    return r.text


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


# ── Resume helpers ────────────────────────────────────────────────────────────

def _strip_incomplete_rows(output_path: str, fieldnames: list[str]) -> None:
    """Remove complete=no rows from an existing CSV in place."""
    p = Path(output_path)
    if not p.exists():
        return
    with open(p, newline="", encoding="utf-8") as fh:
        rows = [r for r in csv.DictReader(fh) if r.get("complete") != "no"]
    with open(p, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def load_completed_rules(output_path: str) -> set[str]:
    """
    Return the set of rule names that are already done and should be skipped.
    Includes rules with complete=yes or complete=skipped.
    Rules with complete=no are excluded so they get re-queried on resume.
    """
    p = Path(output_path)
    if not p.exists():
        return set()
    completed = set()
    with open(p, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            if "rule" in row and row.get("complete") != "no":
                completed.add(row["rule"])
    return completed


# ── Rule config helpers ───────────────────────────────────────────────────────

def fetch_rule_services(rule_names: list[str]) -> dict[str, list[str]]:
    """
    Fetch the service members configured on each security rule via the config API.
    Returns {rule_name: [member, ...]} for all rules found in config.
    Rules not found or with no service element map to an empty list.
    """
    xpath = ops_lib.rules_xpath()
    try:
        xml_text = ops_lib.api_get(xpath)
        root = ET.fromstring(xml_text)
    except Exception as exc:
        print(f"  Warning: could not fetch rule services from config: {exc}", flush=True)
        print(f"  (xpath: {xpath})", flush=True)
        return {}

    if root.get("status") == "error":
        msg = root.findtext(".//msg") or root.findtext(".//line") or "unknown error"
        print(f"  Warning: config API returned error: {msg}", flush=True)
        print(f"  (xpath: {xpath})", flush=True)
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


# ── Rule app stats ────────────────────────────────────────────────────────────

def fetch_rule_app_stats(debug_path: str | None = None) -> dict[str, dict[str, int]] | None:
    """
    Fetch per-rule, per-app last-hit timestamps via the operational API.
    Returns {rule_name: {app_name: last_hit_epoch}} or None if unavailable.
    The caller filters apps by their own time window.
    """
    if ops_lib.MODE == "panorama":
        rb_tag = f"{ops_lib.RULEBASE}-rulebase"
        cmd = (
            f"<show><rule-use><application><device-group>"
            f"<entry name='{ops_lib.DEVICE_GROUP}'>"
            f"<{rb_tag}><security><rules><all/></rules></security></{rb_tag}>"
            f"</entry></device-group></application></rule-use></show>"
        )
    else:
        cmd = (
            f"<show><rule-use><application><vsys>"
            f"<entry name='{ops_lib.VSYS}'>"
            f"<rulebase><security><rules><all/></rules></security></rulebase>"
            f"</entry></vsys></application></rule-use></show>"
        )

    try:
        xml_text = _post({"type": "op", "cmd": cmd, "key": ops_lib.API_KEY})

        if debug_path:
            with open(debug_path, "w", encoding="utf-8") as fh:
                fh.write(xml_text)

        root = ET.fromstring(xml_text)
        if root.get("status") != "success":
            msg = root.findtext(".//msg") or "unknown error"
            print(f"not supported on this PAN-OS version ({msg})", flush=True)
            print(f"  Falling back to log queries for all rules. Use --no-stats to suppress this message.", flush=True)
            return None

        result: dict[str, dict[str, int]] = {}
        for rule_entry in root.findall(".//rules/entry"):
            rule_name = rule_entry.get("name", "")
            if not rule_name:
                continue
            apps: dict[str, int] = {}
            for app_entry in rule_entry.findall(".//entry"):
                app_name = app_entry.get("name", "")
                if not app_name:
                    continue
                ts_el = app_entry.find("last-hit-timestamp")
                if ts_el is not None:
                    try:
                        apps[app_name] = int(ts_el.text or "0")
                    except ValueError:
                        apps[app_name] = 0
            if apps:
                result[rule_name] = apps

        return result if result else None

    except Exception as exc:
        print(f"not supported on this PAN-OS version ({exc})", flush=True)
        print(f"  Falling back to log queries for all rules. Use --no-stats to suppress this message.", flush=True)
        return None


# ── Parallel worker ───────────────────────────────────────────────────────────

def _process_rule(
    rule_name:      str,
    rule_index:     int,
    total_rules:    int,
    start_dt:       datetime.datetime,
    end_dt:         datetime.datetime,
    action:         str,
    max_queries:    int,
    services_map:   dict[str, list[str]],
    rule_stats:     dict[str, int] | None,
    oldest_log_dt:  datetime.datetime | None,
    stats_cutoff_dt: datetime.datetime,
) -> tuple[dict, str]:
    """
    Process one rule in a worker thread.
    Returns (csv_row, console_output_block).

    If rule_stats and oldest_log_dt are both available, uses stats when the
    rule's most recent app activity predates the log window; otherwise queries
    traffic logs via app-exclusion.
    """
    lines: list[str] = [f"[{rule_index}/{total_rules}] {rule_name}"]
    services = services_map.get(rule_name, [])

    if PARALLEL:
        with _print_lock:
            print(f"[{rule_index}/{total_rules}] {rule_name}  → running...", flush=True)

    # ── Decide data source ────────────────────────────────────────────────────
    use_stats  = False
    stats_apps: set[str] = set()

    if rule_stats is not None and oldest_log_dt is not None:
        cutoff_epoch   = int(stats_cutoff_dt.timestamp())
        max_last_seen  = max(rule_stats.values()) if rule_stats else 0
        max_last_seen_dt = (
            datetime.datetime.fromtimestamp(max_last_seen) if max_last_seen else None
        )
        if max_last_seen_dt is None or max_last_seen_dt < oldest_log_dt:
            use_stats  = True
            stats_apps = {
                app for app, ts in rule_stats.items()
                if ts >= cutoff_epoch and app
            }

    # ── Stats path ────────────────────────────────────────────────────────────
    if use_stats:
        lines.append(
            f"  → {len(stats_apps)} apps | from rule stats "
            f"(last activity predates log window)"
        )
        if len(stats_apps) > APP_COUNT_WARN:
            lines.append(
                f"  ! {len(stats_apps)} apps found (>{APP_COUNT_WARN}) — "
                f"review this rule before splitting"
            )
        row = {
            "rule":             rule_name,
            "app_count":        len(stats_apps),
            "apps":             "|".join(sorted(stats_apps)),
            "port_count":       len(services),
            "ports":            "|".join(services),
            "app_port_details": "",
            "entries_scanned":  0,
            "windows_queried":  0,
            "complete":         "yes",
            "data_source":      "stats",
        }
        return row, "\n".join(lines)

    # ── Log query path ────────────────────────────────────────────────────────
    all_apps, app_port_details, total_entries, complete, queries_used = log_query_lib.collect_apps(
        rule_name, start_dt, end_dt, action,
        max_queries  = max_queries,
        max_logs     = MAX_LOGS,
        poll_interval= POLL_INTERVAL,
        poll_timeout = POLL_TIMEOUT,
        http_timeout = HTTP_TIMEOUT,
        verbose      = VERBOSE,
        parallel     = PARALLEL,
        query_delay  = QUERY_DELAY,
    )

    flag = " !" if not complete else ""
    lines.append(
        f"  → {len(all_apps)} apps | {total_entries} entries | "
        f"{queries_used} quer{'y' if queries_used == 1 else 'ies'}{flag}"
    )
    if not complete:
        if queries_used >= max_queries:
            lines.append(
                f"  ! query budget exhausted ({queries_used} queries used) — "
                f"raise --max-queries-per-rule to allow app-exclusion to finish"
            )
        else:
            lines.append(
                f"  ! query failed on round {queries_used} — "
                f"re-run with --resume to retry (may be a transient Panorama error)"
            )
    if len(all_apps) > APP_COUNT_WARN:
        lines.append(
            f"  ! {len(all_apps)} apps found (>{APP_COUNT_WARN}) — "
            f"review this rule before splitting"
        )

    pairs = sorted(
        f"{app}:{port}"
        for app, ports in app_port_details.items()
        for port in sorted(ports)
    )
    row = {
        "rule":             rule_name,
        "app_count":        len(all_apps),
        "apps":             "|".join(sorted(all_apps)),
        "port_count":       len(services),
        "ports":            "|".join(services),
        "app_port_details": "|".join(pairs),
        "entries_scanned":  total_entries,
        "windows_queried":  queries_used,
        "complete":         "yes" if complete else "no",
        "data_source":      "logs",
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
    global VERBOSE, PARALLEL, QUERY_DELAY, POLL_TIMEOUT

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
        help="Skip rules already complete/skipped in the output file; re-query incomplete ones",
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
        "--poll-timeout", type=int, default=POLL_TIMEOUT, metavar="SECS",
        help=f"Seconds to wait for a log job to finish before timing out (default: {POLL_TIMEOUT})",
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
        "--stats-window", type=int, default=13, metavar="MONTHS",
        help="When using rule stats, only include apps seen within this many months (default: 13)",
    )
    parser.add_argument(
        "--no-stats", action="store_true",
        help="Skip rule stats lookup entirely; always query traffic logs",
    )
    parser.add_argument(
        "--debug-rule-stats", metavar="PATH",
        help="Write the raw rule app stats API response to PATH for inspection",
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
        ops_lib.MODE = "panorama"

    VERBOSE      = args.verbose
    PARALLEL     = args.workers > 1
    QUERY_DELAY  = args.query_delay
    POLL_TIMEOUT = args.poll_timeout

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

    end_from_newest_log = False

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
    # complete=no rows are excluded from completed_rules so they get re-queried.
    # Any existing incomplete rows are stripped from the CSV before appending
    # so they don't produce duplicate entries.
    completed_rules: set[str] = set()
    if args.resume:
        completed_rules = load_completed_rules(output_path)
        _strip_incomplete_rows(output_path, CSV_FIELDNAMES)

    remaining = [r for r in rule_names if r not in completed_rules]
    file_mode = "a" if (args.resume and Path(output_path).exists()) else "w"

    print("=" * 62)
    print(f"  get-rule-apps  v{VERSION}")
    print("=" * 62)
    print(f"  Target      : {ops_lib.TARGET_HOST}  ({ops_lib.mode_summary()})")
    print(f"  From        : {start_dt.strftime('%Y-%m-%d %H:%M:%S')}")

    if not args.end:
        print("  Querying end time ...", end=" ", flush=True)
        newest_log_dt = log_query_lib.fetch_newest_log_dt(
            poll_timeout=POLL_TIMEOUT,
            http_timeout=HTTP_TIMEOUT,
            verbose=True,
        )
        if newest_log_dt and newest_log_dt > start_dt:
            end_dt = newest_log_dt
            end_from_newest_log = True
        elif newest_log_dt:
            print(f"  (predates query start — using run time)", end="", flush=True)
        else:
            print("  (unavailable — using run time)", end="", flush=True)
        print(flush=True)

    to_note = "  (newest available log)" if end_from_newest_log else ""
    print(f"  To          : {end_dt.strftime('%Y-%m-%d %H:%M:%S')}{to_note}")
    print(f"  Action      : {args.action}")
    print(f"  Query cap   : {args.max_queries_per_rule} per rule")
    print(f"  Poll timeout: {POLL_TIMEOUT}s per job")
    print(f"  Workers     : {args.workers}")
    inactive_mode = "hit-count API" if not args.debug_hitcount else "hit-count API (debug)"
    print(f"  Rules       : {len(rule_names)} total / {len(remaining)} to query")
    if args.skip_unused:
        print(f"  Inactive    : will skip via {inactive_mode} (with precheck fallback)")
    if args.resume and Path(output_path).exists():
        all_in_csv = set()
        incomplete_in_csv = set()
        if Path(output_path).exists():
            with open(output_path, newline="", encoding="utf-8") as _fh:
                for _row in csv.DictReader(_fh):
                    if "rule" in _row:
                        all_in_csv.add(_row["rule"])
                        if _row.get("complete") == "no":
                            incomplete_in_csv.add(_row["rule"])
        if completed_rules or incomplete_in_csv:
            print(
                f"  Resuming    : {len(completed_rules)} skipped"
                + (f", {len(incomplete_in_csv)} incomplete — re-querying" if incomplete_in_csv else "")
            )
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
    # active_rules: None → no batch filter; all rules proceed to collect_apps
    active_rules: set[str] | None = None

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
                f"  Falling back to querying all rules — inactive rules will show app_count=0."
            )
        print()

    # ── Rule app stats + oldest log timestamp ────────────────────────────────
    all_rule_stats: dict[str, dict[str, int]] | None = None
    oldest_log_dt:  datetime.datetime | None         = None
    stats_cutoff_dt = run_dt - datetime.timedelta(days=30 * args.stats_window)

    if not args.no_stats:
        print("  Fetching rule app stats ...", end=" ", flush=True)
        all_rule_stats = fetch_rule_app_stats(
            debug_path=args.debug_rule_stats or None
        )
        if args.debug_rule_stats:
            print(f"\n  Raw response written to: {args.debug_rule_stats}")
            print("  Fetching rule app stats ...", end=" ", flush=True)

        if all_rule_stats:
            print(f"{len(all_rule_stats)} rules with app data", flush=True)
            print("  Fetching oldest log timestamp ...", end=" ", flush=True)
            oldest_log_dt = log_query_lib.fetch_oldest_log_dt(
                poll_timeout=POLL_TIMEOUT,
                http_timeout=HTTP_TIMEOUT,
                verbose=True,
            )
            if oldest_log_dt:
                print(f"  {oldest_log_dt.strftime('%Y-%m-%d')}", flush=True)
            else:
                print("  unavailable — will use log queries for all rules", flush=True)
                all_rule_stats = None
        else:
            print("unavailable — will use log queries for all rules", flush=True)
        print()

    run_results: list[dict] = []
    run_start = datetime.datetime.now()
    consecutive_no_traffic = 0
    CONSECUTIVE_WARN = 5

    # Worker kwargs shared across all rule submissions
    worker_kwargs = dict(
        start_dt        = start_dt,
        end_dt          = end_dt,
        action          = args.action,
        max_queries     = args.max_queries_per_rule,
        services_map    = services_map,
        oldest_log_dt   = oldest_log_dt,
        stats_cutoff_dt = stats_cutoff_dt,
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
                    print(f"[{i}/{total}] {rule_name}  (skipped — already done)")
                    continue

                if active_rules is not None and rule_name not in active_rules:
                    print(
                        f"[{i}/{total}] {rule_name}  "
                        f"(skipped — no hits since {start_dt.strftime('%Y-%m-%d')})"
                    )
                    svc = services_map.get(rule_name, [])
                    row = {
                        "rule":             rule_name,
                        "app_count":        0,
                        "apps":             "",
                        "port_count":       len(svc),
                        "ports":            "|".join(svc),
                        "app_port_details": "",
                        "entries_scanned":  0,
                        "windows_queried":  0,
                        "complete":         "skipped",
                        "data_source":      "",
                    }
                    _write_row(writer, fh, row)
                    run_results.append(row)
                    continue

                rule_stats = all_rule_stats.get(rule_name) if all_rule_stats else None
                if PARALLEL:
                    print(f"[{i}/{total}] {rule_name}  → queuing...", flush=True)
                future = pool.submit(
                    _process_rule, rule_name, i, total,
                    **worker_kwargs, rule_stats=rule_stats,
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
    rules_from_stats = sum(1 for r in run_results if r.get("data_source") == "stats")
    rules_from_logs  = sum(1 for r in run_results if r.get("data_source") == "logs")
    total_entries    = sum(r["entries_scanned"] for r in run_results)

    elapsed = datetime.datetime.now() - run_start
    elapsed_str = str(elapsed).split(".")[0]  # HH:MM:SS, no microseconds

    p            = Path(output_path)
    summary_path = str(p.with_name(p.stem + "-summary.txt"))

    summary_lines = [
        "=" * 62,
        f"  get-rule-apps  v{VERSION}",
        "=" * 62,
        f"  Target           : {ops_lib.TARGET_HOST}  ({ops_lib.mode_summary()})",
        f"  Input            : {args.input_file}",
        f"  From             : {start_dt.strftime('%Y-%m-%d %H:%M:%S')}",
        f"  To               : {end_dt.strftime('%Y-%m-%d %H:%M:%S')}"
        + ("  (newest available log)" if end_from_newest_log else ""),
        f"  Action           : {args.action}",
        f"  Query cap        : {args.max_queries_per_rule} per rule",
        f"  Poll timeout     : {POLL_TIMEOUT}s per job",
        f"  Workers          : {args.workers}",
        f"  Stats window     : {'disabled (--no-stats)' if args.no_stats else f'{args.stats_window} months'}",
        "-" * 62,
        "  Done.",
        f"  Elapsed          : {elapsed_str}",
        "-" * 62,
        f"  Rules queried    : {rules_queried}",
    ]
    if completed_rules:
        summary_lines.append(f"  Rules resumed    : {len(completed_rules)}  (skipped — already complete)")
    if rules_skipped:
        summary_lines.append(f"  Rules inactive   : {rules_skipped}  (skipped — no hits in window)")
    if oldest_log_dt:
        summary_lines.append(f"  Log window start : {oldest_log_dt.strftime('%Y-%m-%d')}")
    if rules_from_stats or rules_from_logs:
        summary_lines.append(f"  From stats       : {rules_from_stats}")
        summary_lines.append(f"  From logs        : {rules_from_logs}")
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
