"""
query-rule-apps.py — discover applications seen in traffic for a list of security rules

For each rule name in the input file, queries the PAN-OS traffic log API (last 30 days,
allowed sessions only) and writes the unique applications to a CSV and a Markdown report.

Usage:
    python query-rule-apps.py <input_file> [--output <path>] [--days N]

Input : .txt or .csv file of rule names (same format used by Ops scripts)
Output: rule-apps-YYYYMMDD-HHMMSS.csv + rule-apps-YYYYMMDD-HHMMSS.md

Before running: set MODE / VSYS / DEVICE_GROUP in ops_lib.py to match your environment.
"""

import argparse
import csv
import datetime
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

import requests

# ── Import shared library ─────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "libs"))
import ops_lib  # noqa: E402

# ── Configuration ─────────────────────────────────────────────────────────────
DAYS_BACK     = 30    # days of traffic history to search
MAX_LOGS      = 5000  # max log entries per rule (PAN-OS hard limit: 5000)
POLL_INTERVAL = 3     # seconds between job-status polls
POLL_TIMEOUT  = 120   # seconds to wait per log job before giving up

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


def build_query(rule_name: str, since_dt: datetime.datetime) -> str:
    since_str = since_dt.strftime("%Y/%m/%d %H:%M:%S")
    return (
        f"(receive_time geq '{since_str}') "
        f"and (rule eq '{rule_name}') "
        f"and (action eq 'allow')"
    )


def submit_log_job(query: str) -> Optional[str]:
    """Submit a traffic log query; return the job ID, or None on API error."""
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


def parse_apps(xml_text: str) -> list[str]:
    """Extract sorted unique application names from a finished log job response."""
    root = ET.fromstring(xml_text)
    apps: set[str] = set()
    for entry in root.iter("entry"):
        app = entry.findtext("app")
        if app:
            apps.add(app)
    return sorted(apps)


def query_rule(rule_name: str, since_dt: datetime.datetime) -> list[str]:
    """
    Full submit → poll → parse cycle for one rule.

    Returns a list of application strings.  Sentinel values on failure:
      ["(no traffic found)"]  — zero log entries matched
      ["(query timed out)"]   — job did not finish within POLL_TIMEOUT seconds
      ["(api error)"]         — job submission or polling raised an exception
    """
    try:
        job_id = submit_log_job(build_query(rule_name, since_dt))
        if job_id is None:
            return ["(api error)"]

        result_xml = poll_job(job_id)
        if result_xml is None:
            return ["(query timed out)"]

        apps = parse_apps(result_xml)
        return apps if apps else ["(no traffic found)"]

    except Exception as exc:
        return [f"(error: {exc})"]


# ── Output ────────────────────────────────────────────────────────────────────

def write_csv(results: list[tuple[str, list[str]]], output_path: str) -> None:
    with open(output_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["rule_name", "application"])
        for rule_name, apps in results:
            for app in apps:
                writer.writerow([rule_name, app])


def write_md(
    results: list[tuple[str, list[str]]],
    output_path: str,
    input_file: str,
    days: int,
    run_dt: datetime.datetime,
) -> None:
    with_traffic   = [(r, a) for r, a in results if not a[0].startswith("(")]
    no_traffic     = [(r, a) for r, a in results if a[0] == "(no traffic found)"]
    errors         = [(r, a) for r, a in results if a[0].startswith("(") and a[0] != "(no traffic found)"]
    all_apps: set[str] = set()
    for _, apps in with_traffic:
        all_apps.update(apps)

    since_str = (run_dt - datetime.timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    run_str   = run_dt.strftime("%Y-%m-%d %H:%M:%S")

    lines: list[str] = [
        "# Application Discovery Report",
        "",
        f"**Target**  : {ops_lib.TARGET_HOST}  ({ops_lib.mode_summary()})  ",
        f"**Query**   : Allowed traffic from {since_str} to {run_str}  ",
        f"**Input**   : {input_file}  ",
        f"**Run**     : {run_str}  ",
        "",
        "---",
        "",
        "## Results",
        "",
    ]

    for rule_name, apps in results:
        lines.append(f"### {rule_name}")
        if apps[0].startswith("("):
            lines.append(f"*{apps[0]}*")
        else:
            for app in apps:
                lines.append(f"- {app}")
        lines.append("")

    lines += [
        "---",
        "",
        "## Summary",
        "",
        "| Metric | Count |",
        "|--------|-------|",
        f"| Total rules queried | {len(results)} |",
        f"| Rules with traffic | {len(with_traffic)} |",
        f"| Rules with no traffic | {len(no_traffic)} |",
        f"| Errors / timeouts | {len(errors)} |",
        f"| Unique applications (overall) | {len(all_apps)} |",
        "",
    ]

    if all_apps:
        lines += [
            "### All discovered applications",
            "",
        ]
        for app in sorted(all_apps):
            lines.append(f"- {app}")
        lines.append("")

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Query PAN-OS traffic logs to discover apps used per security rule."
    )
    parser.add_argument("input_file", help=".txt or .csv file of rule names")
    parser.add_argument(
        "--output", "-o",
        help="Output CSV path (default: rule-apps-YYYYMMDD-HHMMSS.csv)",
    )
    parser.add_argument(
        "--days", type=int, default=DAYS_BACK,
        help=f"Days of traffic history to search (default: {DAYS_BACK})",
    )
    args = parser.parse_args()

    rule_names = ops_lib.load_rule_names(args.input_file)
    if not rule_names:
        print("No rule names found in input file.")
        sys.exit(1)

    run_dt      = datetime.datetime.now()
    timestamp   = run_dt.strftime("%Y%m%d-%H%M%S")
    csv_path    = args.output or f"rule-apps-{timestamp}.csv"
    md_path     = str(Path(csv_path).with_suffix(".md"))
    since_dt    = run_dt - datetime.timedelta(days=args.days)
    total       = len(rule_names)

    print(f"Target  : {ops_lib.TARGET_HOST}  ({ops_lib.mode_summary()})")
    print(f"Query   : last {args.days} days, allowed traffic only")
    print(f"Rules   : {total}")
    print(f"Output  : {csv_path}  |  {md_path}")
    print()

    results: list[tuple[str, list[str]]] = []

    for i, rule_name in enumerate(rule_names, start=1):
        prefix = f"[{i}/{total}]"
        print(f"{prefix} {rule_name} ...", end=" ", flush=True)
        apps = query_rule(rule_name, since_dt)
        if apps[0].startswith("("):
            print(apps[0])
        else:
            print(f"{len(apps)} app(s) found")
        results.append((rule_name, apps))

    write_csv(results, csv_path)
    write_md(results, md_path, args.input_file, args.days, run_dt)
    print(f"\nDone.")
    print(f"  CSV : {csv_path}")
    print(f"  MD  : {md_path}")


if __name__ == "__main__":
    main()
