"""
log_query_lib.py — PAN-OS traffic log query primitives and app-exclusion pagination

Reusable building blocks for querying PAN-OS traffic logs via the Panorama /
firewall log API.  Intended for use by any ops script that needs to query or
paginate traffic logs.

Public API:
    query_window(...)       Submit and poll one log query; returns entry elements,
                            distinct apps, entry count, and cap/ok flags.
    collect_apps(...)       Iterative app-exclusion loop over a full date range;
                            finds all distinct apps regardless of traffic volume.
    fetch_oldest_log_dt()   Timestamp of the oldest available traffic log entry.
    fetch_newest_log_dt()   Timestamp of the newest available traffic log entry.

Both functions read TARGET_HOST and API_KEY from ops_lib.

Example — find all apps for a rule:

    import log_query_lib
    apps, total, complete, rounds = log_query_lib.collect_apps(
        rule_name="Allow Any",
        start_dt=datetime(2026, 5, 5),
        end_dt=datetime(2026, 5, 12),
        action="allow",
    )

Example — single raw query with full entry access:

    apps, entries, count, capped, ok = log_query_lib.query_window(
        rule_name="Allow Any",
        start_dt=datetime(2026, 5, 5),
        end_dt=datetime(2026, 5, 12),
        action="allow",
    )
    for entry in entries:
        print(entry.findtext("src"), entry.findtext("dst"), entry.findtext("app"))
"""

import datetime
import time
import xml.etree.ElementTree as ET

import requests
import ops_lib  # noqa — expected to be on sys.path by the calling script

requests.packages.urllib3.disable_warnings()


VERSION = "1.2.0"

# ── Defaults (callers may override per call) ──────────────────────────────────

MAX_LOGS      = 5000
POLL_INTERVAL = 3      # seconds between job-status polls
POLL_TIMEOUT  = 120    # seconds before a job is considered timed out
HTTP_TIMEOUT  = 90     # seconds per HTTP request


# ── Internal helpers ──────────────────────────────────────────────────────────

def _post(params: dict, http_timeout: float = HTTP_TIMEOUT) -> str:
    r = requests.post(
        f"https://{ops_lib.TARGET_HOST}/api/",
        data=params,
        verify=False,
        timeout=http_timeout,
    )
    r.raise_for_status()
    return r.text


def _build_query(
    rule_name: str,
    start_dt: datetime.datetime,
    end_dt: datetime.datetime,
    action: str,
    exclude_apps: set[str] | None = None,
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
    if exclude_apps:
        for app in sorted(exclude_apps):
            parts.append(f"(app neq '{app}')")
    return " and ".join(parts)


def _submit_job(
    query: str,
    nlogs: int = MAX_LOGS,
    http_timeout: float = HTTP_TIMEOUT,
    direction: str = "backward",
) -> str | None:
    params = {
        "type":     "log",
        "log-type": "traffic",
        "query":    query,
        "nlogs":    str(nlogs),
        "dir":      direction,
        "key":      ops_lib.API_KEY,
    }
    root = ET.fromstring(_post(params, http_timeout))
    if root.get("status") != "success":
        return None
    return root.findtext(".//job")


def _poll_job(
    job_id: str,
    poll_interval: float = POLL_INTERVAL,
    poll_timeout: float  = POLL_TIMEOUT,
    http_timeout: float  = HTTP_TIMEOUT,
    verbose: bool = False,
) -> str | None:
    deadline = time.monotonic() + poll_timeout
    params = {
        "type":   "log",
        "action": "get",
        "job-id": job_id,
        "key":    ops_lib.API_KEY,
    }
    while time.monotonic() < deadline:
        xml_text = _post(params, http_timeout)
        root = ET.fromstring(xml_text)
        if root.findtext(".//status") == "FIN":
            if verbose:
                print(" done", end="", flush=True)
            return xml_text
        if verbose:
            print(".", end="", flush=True)
        time.sleep(poll_interval)
    if verbose:
        print(" TIMEOUT", end="", flush=True)
    return None


# ── Public API ────────────────────────────────────────────────────────────────

def query_window(
    rule_name: str,
    start_dt: datetime.datetime,
    end_dt: datetime.datetime,
    action: str,
    exclude_apps: set[str] | None = None,
    max_logs: int   = MAX_LOGS,
    poll_interval: float = POLL_INTERVAL,
    poll_timeout: float  = POLL_TIMEOUT,
    http_timeout: float  = HTTP_TIMEOUT,
    verbose: bool = False,
) -> tuple[set[str], list, int, bool, bool]:
    """
    Submit and poll one PAN-OS traffic log query.

    Returns (apps, entries, count, capped, ok):
        apps    — set of distinct app names seen in this result
        entries — list of ET.Element, one per log row (access any field via findtext)
        count   — number of entries returned
        capped  — True if count == max_logs (result may be truncated)
        ok      — False if the query failed or timed out

    The full entry list lets callers extract any log fields they need, not
    just apps.  For example, to get destination IPs:

        _, entries, _, _, _ = query_window(...)
        dsts = {e.findtext("dst") for e in entries}
    """
    if verbose:
        fmt  = "%m-%d %H:%M"
        excl = f"  excl:{len(exclude_apps)}" if exclude_apps else ""
        print(
            f"  [{start_dt.strftime(fmt)} – {end_dt.strftime(fmt)}]{excl}",
            end="  ", flush=True,
        )

    try:
        query  = _build_query(rule_name, start_dt, end_dt, action, exclude_apps)
        job_id = _submit_job(query, max_logs, http_timeout)
        if job_id is None:
            if verbose:
                print("submission failed", flush=True)
            return set(), [], 0, False, False

        if verbose:
            print(f"job:{job_id} polling", end="", flush=True)

        result_xml = _poll_job(job_id, poll_interval, poll_timeout, http_timeout, verbose)
        if result_xml is None:
            if verbose:
                print("  (timeout)", flush=True)
            return set(), [], 0, False, False

        root    = ET.fromstring(result_xml)
        entries = list(root.iter("entry"))
        apps    = {e.findtext("app") for e in entries if e.findtext("app")}
        count   = len(entries)
        capped  = count >= max_logs

        if verbose:
            print(f"  ({count} entries){'  *** CAPPED ***' if capped else ''}", flush=True)

        return apps, entries, count, capped, True

    except Exception as exc:
        if verbose:
            print(f"  error: {exc}", flush=True)
        else:
            fmt = "%b %d %H:%M"
            print(
                f"  error [{start_dt.strftime(fmt)}–{end_dt.strftime(fmt)}]: {exc}",
                flush=True,
            )
        return set(), [], 0, False, False


def collect_apps(
    rule_name: str,
    start_dt: datetime.datetime,
    end_dt: datetime.datetime,
    action: str,
    max_queries: int  = 50,
    max_logs: int     = MAX_LOGS,
    poll_interval: float = POLL_INTERVAL,
    poll_timeout: float  = POLL_TIMEOUT,
    http_timeout: float  = HTTP_TIMEOUT,
    verbose: bool  = False,
    parallel: bool = False,
    query_delay: float = 0,
) -> tuple[set[str], int, bool, int]:
    """
    Find all distinct apps for a rule using iterative app-exclusion.

    Queries the full date range with no filters, then re-queries excluding
    all already-found apps each round until the result is empty or uncapped.
    For a rule with N distinct apps this typically completes in N+1 queries
    regardless of traffic volume.

    Returns (apps, total_entries, complete, queries_used).
    complete=False only if the query budget (max_queries) runs out or a
    query fails before all apps are found.
    """
    all_apps     = set()
    total        = 0
    queries_used = 0

    while True:
        if queries_used >= max_queries:
            return all_apps, total, False, queries_used

        exclude = all_apps if all_apps else None

        if not parallel and not verbose:
            excl_note = f"excl: {len(all_apps):2}" if all_apps else "no exclusions"
            print(f"  round {queries_used + 1:2}  {excl_note} ...", end="  ", flush=True)

        apps, _entries, count, capped, ok = query_window(
            rule_name, start_dt, end_dt, action,
            exclude_apps  = exclude,
            max_logs      = max_logs,
            poll_interval = poll_interval,
            poll_timeout  = poll_timeout,
            http_timeout  = http_timeout,
            verbose       = verbose,
        )
        queries_used += 1

        if not parallel and not verbose:
            print(f"{count} entries" if ok else "error", flush=True)

        if not ok:
            return all_apps, total, False, queries_used

        total    += count
        all_apps |= apps

        if count == 0 or not capped:
            return all_apps, total, True, queries_used

        if query_delay > 0:
            time.sleep(query_delay)


def fetch_newest_log_dt(
    poll_interval: float = POLL_INTERVAL,
    poll_timeout: float  = POLL_TIMEOUT,
    http_timeout: float  = HTTP_TIMEOUT,
    verbose: bool = False,
) -> datetime.datetime | None:
    """
    Return the receive_time of the newest available traffic log entry.
    Used to anchor a query's end window to actual log availability rather
    than script run time, so summary files reflect real data boundaries.
    Returns None if the query fails or no entries exist.
    """
    try:
        job_id = _submit_job(
            "(receive_time geq '2000/01/01 00:00:00')",
            nlogs=1,
            http_timeout=http_timeout,
            direction="backward",
        )
        if job_id is None:
            return None

        result_xml = _poll_job(job_id, poll_interval, poll_timeout, http_timeout, verbose)
        if result_xml is None:
            return None

        root    = ET.fromstring(result_xml)
        entries = list(root.iter("entry"))
        if not entries:
            return None

        ts_str = entries[0].findtext("receive_time")
        if not ts_str:
            return None

        for fmt in ("%Y/%m/%d %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.datetime.strptime(ts_str.strip(), fmt)
            except ValueError:
                continue
        return None

    except Exception:
        return None


def fetch_oldest_log_dt(
    poll_interval: float = POLL_INTERVAL,
    poll_timeout: float  = POLL_TIMEOUT,
    http_timeout: float  = HTTP_TIMEOUT,
    verbose: bool = False,
) -> datetime.datetime | None:
    """
    Return the receive_time of the oldest available traffic log entry.
    Used to establish the start of Panorama's log retention window so
    callers can decide whether rule app stats predate the log window.
    Returns None if the query fails or no entries exist.
    """
    try:
        job_id = _submit_job(
            "(receive_time geq '2000/01/01 00:00:00')",
            nlogs=1,
            http_timeout=http_timeout,
            direction="forward",
        )
        if job_id is None:
            return None

        result_xml = _poll_job(job_id, poll_interval, poll_timeout, http_timeout, verbose)
        if result_xml is None:
            return None

        root    = ET.fromstring(result_xml)
        entries = list(root.iter("entry"))
        if not entries:
            return None

        ts_str = entries[0].findtext("receive_time")
        if not ts_str:
            return None

        for fmt in ("%Y/%m/%d %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.datetime.strptime(ts_str.strip(), fmt)
            except ValueError:
                continue
        return None

    except Exception:
        return None
