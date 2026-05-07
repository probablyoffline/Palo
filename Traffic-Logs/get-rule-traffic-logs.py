"""
get-rule-traffic-logs.py — export traffic logs per security rule to individual CSV files

For each rule name in the input file, queries the PAN-OS traffic log API and writes
all matching log entries to a per-rule CSV file in the output directory.

Usage:
    python get-rule-traffic-logs.py <input_file> [options]

Time period (choose one):
    --days N                              Days back from now (default: 30)
    --start DATETIME [--end DATETIME]     Explicit range; --end defaults to now
                                          Format: YYYY-MM-DD or YYYY-MM-DD HH:MM:SS

Other options:
    --action allow|deny|drop|all          Filter by action (default: all)
    --output-dir PATH                     Output directory (default: traffic-logs-YYYYMMDD-HHMMSS)
    --max-logs N                          Max entries per rule query, 1-5000 (default: 5000)

Input : .txt or .csv file of rule names (same format used by Ops scripts)
Output: One CSV per rule in the output directory

Before running: set MODE / VSYS / DEVICE_GROUP in ops_lib.py to match your environment.
"""

import argparse
import csv
import datetime
import os
import re
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "libs"))
import ops_lib  # noqa: E402

# ── Configuration ─────────────────────────────────────────────────────────────
DAYS_BACK     = 30    # default days of history to search
MAX_LOGS      = 5000  # PAN-OS hard cap per query job
POLL_INTERVAL = 3     # seconds between job-status polls
POLL_TIMEOUT  = 120   # seconds before giving up on a single job

requests.packages.urllib3.disable_warnings()


# ── Log query helpers ─────────────────────────────────────────────────────────

def _post(params: dict) -> str:
    r = requests.post(
        f"https://{ops_lib.TARGET_HOST}/api/",
        data=params,
        verify=False,
        timeout=30,
    )
    r.raise_for_status()
    return r.text


def build_query(
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


def submit_log_job(query: str, max_logs: int) -> Optional[str]:
    """Submit a traffic log query; return the job ID, or None on API error."""
    params = {
        "type":     "log",
        "log-type": "traffic",
        "query":    query,
        "nlogs":    str(max_logs),
        "dir":      "backward",
        "key":      ops_lib.API_KEY,
    }
    xml_text = _post(params)
    root = ET.fromstring(xml_text)
    if root.get("status") != "success":
        return None
    return root.findtext(".//job")


def poll_job(job_id: str) -> Optional[str]:
    """Poll a log job until finished or POLL_TIMEOUT expires. Returns final XML or None."""
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


def parse_entries(xml_text: str) -> list[dict]:
    """Extract all fields from each <entry> element in a finished log job response."""
    root = ET.fromstring(xml_text)
    entries = []
    for entry in root.iter("entry"):
        row = {child.tag: (child.text or "") for child in entry}
        entries.append(row)
    return entries


# ── Output helpers ────────────────────────────────────────────────────────────

def sanitize_filename(name: str) -> str:
    """Make a rule name safe for use as a filename component."""
    safe = re.sub(r"[^\w\-]", "_", name)
    return safe[:200]


def write_rule_csv(
    rule_name: str,
    entries: list[dict],
    output_dir: str,
    timestamp: str,
) -> str:
    """Write one CSV for a rule. Returns the output file path."""
    filename = f"{sanitize_filename(rule_name)}-{timestamp}.csv"
    filepath = os.path.join(output_dir, filename)

    fieldnames: list[str] = []
    seen: set[str] = set()
    for entry in entries:
        for key in entry:
            if key not in seen:
                seen.add(key)
                fieldnames.append(key)

    with open(filepath, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(entries)

    return filepath


# ── Full query cycle ──────────────────────────────────────────────────────────

def query_rule(
    rule_name: str,
    start_dt: datetime.datetime,
    end_dt: datetime.datetime,
    action: str,
    max_logs: int,
) -> tuple[list[dict], str]:
    """
    Submit → poll → parse for one rule.

    Returns (entries, status).  Status values:
      "ok"                  — entries returned, below the cap
      "ok (capped)"         — entries returned, cap was hit; results may be incomplete
      "no_traffic"          — query succeeded but zero entries matched
      "timeout"             — job did not finish within POLL_TIMEOUT seconds
      "error: <msg>"        — submission or network failure
    """
    try:
        query  = build_query(rule_name, start_dt, end_dt, action)
        job_id = submit_log_job(query, max_logs)
        if job_id is None:
            return [], "error: job submission failed"

        result_xml = poll_job(job_id)
        if result_xml is None:
            return [], "timeout"

        entries = parse_entries(result_xml)
        if not entries:
            return [], "no_traffic"

        status = "ok (capped)" if len(entries) >= max_logs else "ok"
        return entries, status

    except Exception as exc:
        return [], f"error: {exc}"


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
        description="Export PAN-OS traffic logs per security rule to individual CSV files."
    )
    parser.add_argument("input_file", help=".txt or .csv file of rule names")

    time_grp = parser.add_mutually_exclusive_group()
    time_grp.add_argument(
        "--days", type=int, default=None, metavar="N",
        help=f"Days of traffic history back from now (default: {DAYS_BACK})",
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
        "--action", choices=["allow", "deny", "drop", "all"], default="all",
        help="Filter log entries by action (default: all)",
    )
    parser.add_argument(
        "--output-dir", "-o", metavar="PATH",
        help="Directory for per-rule CSV files (default: traffic-logs-YYYYMMDD-HHMMSS)",
    )
    parser.add_argument(
        "--max-logs", type=int, default=MAX_LOGS, metavar="N",
        help=f"Max log entries per rule, 1-{MAX_LOGS} (default: {MAX_LOGS})",
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

    max_logs = max(1, min(args.max_logs, MAX_LOGS))

    try:
        rule_names = ops_lib.load_rule_names(args.input_file)
    except FileNotFoundError:
        print(f"Error: input file not found: {args.input_file}", file=sys.stderr)
        sys.exit(1)
    if not rule_names:
        print("No rule names found in input file.", file=sys.stderr)
        sys.exit(1)

    timestamp  = run_dt.strftime("%Y%m%d-%H%M%S")
    output_dir = args.output_dir or f"traffic-logs-{timestamp}"
    os.makedirs(output_dir, exist_ok=True)

    print("=" * 62)
    print("  get-rule-traffic-logs")
    print("=" * 62)
    print(f"  Target   : {ops_lib.TARGET_HOST}  ({ops_lib.mode_summary()})")
    print(f"  From     : {start_dt.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  To       : {end_dt.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Action   : {args.action}")
    print(f"  Max logs : {max_logs} per rule")
    print(f"  Rules    : {len(rule_names)}")
    print(f"  Out dir  : {output_dir}")
    print()

    summary: list[dict] = []

    for i, rule_name in enumerate(rule_names, start=1):
        prefix = f"[{i}/{len(rule_names)}]"
        print(f"{prefix} {rule_name} ...", end=" ", flush=True)

        entries, status = query_rule(rule_name, start_dt, end_dt, args.action, max_logs)

        if entries:
            csv_path = write_rule_csv(rule_name, entries, output_dir, timestamp)
            print(f"{len(entries)} entries → {os.path.basename(csv_path)}")
            if status == "ok (capped)":
                print(f"         ! hit {max_logs}-entry cap — results may be incomplete")
        else:
            csv_path = ""
            print(f"({status})")

        summary.append({
            "rule":    rule_name,
            "entries": len(entries),
            "status":  status,
            "file":    csv_path,
        })

    total_entries  = sum(r["entries"] for r in summary)
    rules_with     = sum(1 for r in summary if r["entries"] > 0)
    rules_without  = sum(1 for r in summary if r["status"] == "no_traffic")
    rules_capped   = sum(1 for r in summary if r["status"] == "ok (capped)")
    rules_error    = sum(1 for r in summary if r["status"].startswith(("error", "timeout")))

    print()
    print("=" * 62)
    print(f"  Done.")
    print(f"  Rules queried  : {len(rule_names)}")
    print(f"  With traffic   : {rules_with}")
    print(f"  No traffic     : {rules_without}")
    print(f"  Capped results : {rules_capped}")
    print(f"  Errors/timeouts: {rules_error}")
    print(f"  Total entries  : {total_entries}")
    print(f"  Output dir     : {output_dir}")
    print("=" * 62)


if __name__ == "__main__":
    main()
