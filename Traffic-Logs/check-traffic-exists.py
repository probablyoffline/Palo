"""
check-traffic-exists.py — verify whether decommissioned hosts still have traffic

Given a list of hostnames (shortnames, FQDNs) and/or IPs, resolves all
hostnames via DNS, then queries the PAN-OS traffic log API to determine
whether any traffic exists for any of the resulting IPs.

The primary use case is decommission validation: confirm that no traffic
remains for hosts being (or already) retired.

Usage:
    python check-host-traffic.py <hosts_file> [options]

Time period (choose one):
    --days N                              Days back from now (default: 30)
    --start DATETIME [--end DATETIME]     Explicit range; --end defaults to now
                                          Format: YYYY-MM-DD or YYYY-MM-DD HH:MM:SS

Other options:
    --action allow|deny|drop|all          Filter by action (default: all)
    --batch N                             Max IPs per query (default: 50)
    --max-rounds N                        Max exhaustion rounds per batch (default: 20)
    --output FILE.csv                     Write per-IP results to CSV

Algorithm:
    1. Resolve all hostnames to IPs via DNS (IPv4 + IPv6); deduplicate.
    2. Build a combined OR filter: (addr.src in 'IP') or (addr.dst in 'IP') for
       each IP, batched if the list is large.
    3. For each batch, run an exhaustion loop: remove confirmed-traffic IPs from
       the filter each round until either no IPs remain unchecked or a round
       returns zero entries.  This mirrors the app-exclusion pattern used by
       get-rule-apps.py but shrinks the IP set rather than excluding by app name.

Before running: set MODE / VSYS / DEVICE_GROUP in ops_lib.py to match your
environment.
"""

import argparse
import csv
import datetime
import ipaddress
import os
import socket
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "libs"))
import ops_lib  # noqa: E402

VERSION = "1.0.0"

# ── Defaults ──────────────────────────────────────────────────────────────────

DAYS_BACK     = 30
MAX_LOGS      = 5000
POLL_INTERVAL = 3      # seconds between job-status polls
POLL_TIMEOUT  = 120    # seconds before giving up on a single job
HTTP_TIMEOUT  = 90     # seconds per HTTP request
BATCH_SIZE    = 50     # max IPs per query (chars budget is checked first)
MAX_QUERY_CHARS = 4000 # if all IPs fit within this, skip batching
MAX_ROUNDS    = 20     # max exhaustion rounds per batch

requests.packages.urllib3.disable_warnings()


# ── DNS resolution ────────────────────────────────────────────────────────────

def is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def resolve_host(hostname: str) -> set[str]:
    """Resolve hostname to all IPs (A + AAAA) via system DNS. Returns empty set on failure."""
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC)
        return {r[4][0] for r in results}
    except socket.gaierror:
        return set()


def load_hosts(filepath: str) -> list[str]:
    """
    Load host entries from a .txt or .csv file.

    .txt — one entry per line; '#' comment lines are skipped.
    .csv — uses a 'host' column if present, otherwise the first column.
    """
    ext = os.path.splitext(filepath)[1].lower()
    seen: set[str] = set()
    entries: list[str] = []

    def _add(s: str) -> None:
        s = s.strip()
        if s and not s.startswith("#") and s not in seen:
            seen.add(s)
            entries.append(s)

    with open(filepath, newline="", encoding="utf-8") as fh:
        if ext == ".csv":
            sample = fh.read(1024)
            fh.seek(0)
            has_header = csv.Sniffer().has_header(sample)
            reader = csv.reader(fh)
            if has_header:
                header = [h.strip().lower() for h in next(reader)]
                col = header.index("host") if "host" in header else 0
                for row in reader:
                    if len(row) > col:
                        _add(row[col])
            else:
                for row in reader:
                    if row:
                        _add(row[0])
        else:
            for line in fh:
                _add(line)

    return entries


# ── Query building ────────────────────────────────────────────────────────────

def _ip_filter_terms(ips: set[str]) -> str:
    """Build the OR block for a set of IPs (no time filter)."""
    parts = []
    for ip in sorted(ips):
        parts.append(f"(addr.src in '{ip}')")
        parts.append(f"(addr.dst in '{ip}')")
    return " or ".join(parts)


def build_ip_query(
    ips: set[str],
    start_dt: datetime.datetime,
    end_dt: datetime.datetime,
    action: str,
) -> str:
    start_str = start_dt.strftime("%Y/%m/%d %H:%M:%S")
    end_str   = end_dt.strftime("%Y/%m/%d %H:%M:%S")
    base = [
        f"(receive_time geq '{start_str}')",
        f"(receive_time leq '{end_str}')",
    ]
    if action != "all":
        base.append(f"(action eq '{action}')")
    ip_block = _ip_filter_terms(ips)
    return " and ".join(base) + f" and ({ip_block})"


def _estimate_query_chars(ips: set[str], action: str) -> int:
    time_chars = 110  # two receive_time terms
    action_chars = 20 if action != "all" else 0
    ip_chars = sum(len(f"(addr.src in '{ip}') or (addr.dst in '{ip}')") + 4 for ip in ips)
    return time_chars + action_chars + ip_chars


def make_batches(ips: list[str], batch_size: int, max_chars: int, action: str) -> list[list[str]]:
    """
    Return batches of IPs for querying.  If all IPs fit within max_chars,
    a single batch is returned regardless of batch_size.
    """
    if _estimate_query_chars(set(ips), action) <= max_chars:
        return [ips]
    return [ips[i:i + batch_size] for i in range(0, len(ips), batch_size)]


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


def _submit_job(query: str) -> Optional[str]:
    params = {
        "type":     "log",
        "log-type": "traffic",
        "query":    query,
        "nlogs":    str(MAX_LOGS),
        "dir":      "backward",
        "key":      ops_lib.API_KEY,
    }
    root = ET.fromstring(_post(params))
    if root.get("status") != "success":
        return None
    return root.findtext(".//job")


def _poll_job(job_id: str) -> Optional[str]:
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


def _run_query(query: str) -> tuple[list, int, bool, bool]:
    """
    Submit and poll one query.

    Returns (entries, count, capped, ok).
      entries — list of ET.Element
      count   — len(entries)
      capped  — True if count == MAX_LOGS
      ok      — False on submission failure or timeout
    """
    try:
        job_id = _submit_job(query)
        if job_id is None:
            return [], 0, False, False
        result_xml = _poll_job(job_id)
        if result_xml is None:
            return [], 0, False, False
        root    = ET.fromstring(result_xml)
        entries = list(root.iter("entry"))
        count   = len(entries)
        return entries, count, count >= MAX_LOGS, True
    except Exception as exc:
        print(f"  error: {exc}", flush=True)
        return [], 0, False, False


# ── Core exhaustion loop ──────────────────────────────────────────────────────

def check_batch(
    batch_ips: list[str],
    start_dt: datetime.datetime,
    end_dt: datetime.datetime,
    action: str,
    max_rounds: int,
    batch_label: str,
) -> tuple[set[str], set[str], set[str], bool]:
    """
    Check one batch of IPs for traffic using the shrinking-OR-filter pattern.

    Confirmed-traffic IPs are removed from the filter each round, narrowing
    the query until either all IPs are confirmed or a round returns no entries.

    Returns (traffic_ips, clean_ips, budget_exceeded_ips, complete).
      traffic_ips        — IPs for which traffic was found
      clean_ips          — IPs confirmed to have no traffic
      budget_exceeded_ips — IPs still unchecked when max_rounds was hit
      complete           — True if the check was exhaustive (no budget exceeded)
    """
    unchecked: set[str] = set(batch_ips)
    traffic_ips: set[str] = set()

    print(f"  {batch_label}  {len(batch_ips)} IPs")

    for rnd in range(1, max_rounds + 1):
        if not unchecked:
            break

        query = build_ip_query(unchecked, start_dt, end_dt, action)
        print(
            f"    round {rnd:2}  {len(unchecked):3} IP(s) queried ...",
            end="  ", flush=True,
        )

        entries, count, capped, ok = _run_query(query)

        if not ok:
            print("error", flush=True)
            return traffic_ips, set(), unchecked, False

        cap_marker = "  *** CAPPED ***" if capped else ""
        print(f"{count} entries{cap_marker}", flush=True)

        if count == 0:
            # All remaining unchecked IPs have no traffic.
            clean_ips = set(unchecked)
            return traffic_ips, clean_ips, set(), True

        # Identify which of our unchecked IPs appeared in this result.
        for e in entries:
            src = e.findtext("src") or ""
            dst = e.findtext("dst") or ""
            if src in unchecked:
                traffic_ips.add(src)
            if dst in unchecked:
                traffic_ips.add(dst)

        unchecked -= traffic_ips

        if not capped:
            # No more entries exist for the remaining unchecked IPs.
            clean_ips = set(unchecked)
            return traffic_ips, clean_ips, set(), True

    # Round budget exhausted before unchecked set was emptied.
    return traffic_ips, set(), unchecked, False


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
        description="Check whether hosts (by name or IP) have traffic in PAN-OS logs."
    )
    parser.add_argument("hosts_file", help=".txt or .csv file of hostnames / IPs")

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
        "--batch", type=int, default=BATCH_SIZE, metavar="N",
        help=f"Max IPs per query when batching is needed (default: {BATCH_SIZE})",
    )
    parser.add_argument(
        "--max-rounds", type=int, default=MAX_ROUNDS, metavar="N",
        help=f"Max exhaustion rounds per batch (default: {MAX_ROUNDS})",
    )
    parser.add_argument(
        "--output", metavar="FILE.csv",
        help="Write per-IP results to a CSV file",
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

    # ── Load hosts ────────────────────────────────────────────────────────────
    try:
        hosts = load_hosts(args.hosts_file)
    except FileNotFoundError:
        print(f"Error: file not found: {args.hosts_file}", file=sys.stderr)
        sys.exit(1)
    if not hosts:
        print("No hosts found in input file.", file=sys.stderr)
        sys.exit(1)

    # ── DNS resolution ────────────────────────────────────────────────────────
    SEP = "=" * 62
    print(SEP)
    print(f"  check-traffic-exists  v{VERSION}")
    print(SEP)
    print(f"  Target  : {ops_lib.TARGET_HOST}  ({ops_lib.mode_summary()})")
    print(f"  From    : {start_dt.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  To      : {end_dt.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Action  : {args.action}")
    print(f"  Hosts   : {len(hosts)}")
    print()
    print("  DNS Resolution")
    print("  " + "-" * 40)

    host_to_ips:   dict[str, set[str]] = {}
    dns_failed:    list[str]           = []
    all_ips:       set[str]            = set()
    max_name_len = max(len(h) for h in hosts)

    for h in hosts:
        if is_ip(h):
            resolved = {h}
            label = "(IP, used directly)"
        else:
            resolved = resolve_host(h)
            if resolved:
                label = ", ".join(sorted(resolved))
            else:
                label = "(FAILED — no DNS record)"
                dns_failed.append(h)

        host_to_ips[h] = resolved
        all_ips |= resolved
        print(f"  {h:<{max_name_len}}  →  {label}")

    print()
    if dns_failed:
        print(f"  Warning: {len(dns_failed)} host(s) could not be resolved and will be skipped.")
        print()

    if not all_ips:
        print("  No IPs to check after DNS resolution.  Exiting.", file=sys.stderr)
        sys.exit(1)

    ip_list = sorted(all_ips)
    print(f"  {len(hosts)} host(s) → {len(ip_list)} unique IP(s) to check")
    print()

    # ── Traffic check ─────────────────────────────────────────────────────────
    batches = make_batches(ip_list, args.batch, MAX_QUERY_CHARS, args.action)
    print("  Traffic Check")
    print("  " + "-" * 40)
    if len(batches) > 1:
        print(f"  Splitting into {len(batches)} batches of up to {args.batch} IPs each")
        print()

    all_traffic: set[str] = set()
    all_clean:   set[str] = set()
    all_exceeded: set[str] = set()
    complete = True

    for i, batch in enumerate(batches, start=1):
        label = f"[batch {i}/{len(batches)}]"
        t_ips, c_ips, e_ips, batch_complete = check_batch(
            batch, start_dt, end_dt, args.action, args.max_rounds, label,
        )
        all_traffic  |= t_ips
        all_clean    |= c_ips
        all_exceeded |= e_ips
        if not batch_complete:
            complete = False
        print()

    # ── Results ───────────────────────────────────────────────────────────────
    print(SEP)
    if all_traffic:
        # Find which original hosts contributed each traffic IP
        active_hosts = {
            h for h, ips in host_to_ips.items()
            if ips & all_traffic
        }
        print(
            f"  RESULT: TRAFFIC FOUND for {len(all_traffic)} of {len(ip_list)} IP(s)"
            f"  ({len(active_hosts)} of {len(hosts)} host(s))"
        )
    else:
        if complete:
            print(f"  RESULT: CONFIRMED CLEAN — no traffic for any of the {len(ip_list)} IP(s)")
        else:
            print(f"  RESULT: NO TRAFFIC FOUND (check incomplete — see budget-exceeded IPs below)")
    print(SEP)

    # Build reverse map: ip → originating hosts
    ip_to_hosts: dict[str, list[str]] = {}
    for h, ips in host_to_ips.items():
        for ip in ips:
            ip_to_hosts.setdefault(ip, []).append(h)

    # Print per-IP table
    all_result_ips = sorted(all_traffic | all_clean | all_exceeded)
    max_ip_len = max((len(ip) for ip in all_result_ips), default=15)

    for ip in all_result_ips:
        origin = ", ".join(sorted(ip_to_hosts.get(ip, [])))
        if ip in all_traffic:
            tag = "ACTIVE "
        elif ip in all_exceeded:
            tag = "UNKNOWN"
        else:
            tag = "clean  "
        print(f"  {tag}  {ip:<{max_ip_len}}  ← {origin}")

    if dns_failed:
        print()
        for h in dns_failed:
            print(f"  DNS-FAIL  {h}")

    if all_exceeded:
        print()
        print(
            f"  Warning: {len(all_exceeded)} IP(s) marked UNKNOWN because the "
            f"exhaustion round budget ({args.max_rounds}) was reached."
        )
        print("           Re-run with --max-rounds N to continue.")

    print(SEP)

    # ── Optional CSV output ───────────────────────────────────────────────────
    if args.output:
        rows: list[dict] = []
        for h in hosts:
            ips = host_to_ips.get(h, set())
            if not ips:
                rows.append({"host": h, "ip": "", "status": "dns-fail", "rounds": ""})
                continue
            for ip in sorted(ips):
                if ip in all_traffic:
                    status = "active"
                elif ip in all_exceeded:
                    status = "budget-exceeded"
                else:
                    status = "clean"
                rows.append({"host": h, "ip": ip, "status": status, "rounds": ""})

        with open(args.output, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=["host", "ip", "status", "rounds"])
            writer.writeheader()
            writer.writerows(rows)
        print(f"  CSV written: {args.output}")
        print(SEP)


if __name__ == "__main__":
    main()
