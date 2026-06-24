"""
deploy-service-objects.py — Create service objects and service groups in Panorama

Reads the *-svc.csv file produced by design-rule-apps.py and creates any missing
service objects and service groups in Panorama.  Run this before deploy-rule-design.py
to ensure all service objects referenced in NS rule designs exist.

Supported row types in the svc CSV:
  service_object  — Creates a single service object (TCP or UDP port/range).
                    Columns used: name, device_group, protocol, port
  service_group   — Creates a static service group.
                    Columns used: name, device_group, members (pipe-separated member names)

Execution flow:
  1. Load svc CSV
  2. Pass 1 — service_object rows: check existence, create in parallel (--workers threads)
  3. Pass 2 — service_group rows: check existence, create sequentially
              (members from pass 1 must exist before groups can reference them)
  4. Print summary
  If --dry-run: print what would be created; make no changes

Changes are left in Panorama's candidate config; commit via the Panorama UI or a
separate commit step.

Usage:
    python deploy-service-objects.py <svc_csv> [options]

Options:
    --device-group NAME / --dg NAME   Override device group (Panorama mode only)
    --shared                          Create objects under /config/shared instead
                                      of the device group in each CSV row
    --dry-run                         Print what would be created; make no changes
    --workers N                       Parallel threads for service objects (default: 4)
"""

import argparse
import csv
import datetime
import os
import re
import sys
import threading
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "libs"))
import ops_lib  # noqa: E402

requests.packages.urllib3.disable_warnings()

__version__ = "1.0.8"

SEP  = "=" * 62
DASH = "-" * 62

_PRINT_LOCK = threading.Lock()

# Matches the protocol+port suffix in service object names: e.g. svc-rule-tcp-443 or svc-rule-udp-514-515
_SVC_NAME_RE = re.compile(r'-(tcp|udp)-(\d[\d\-]*)$', re.IGNORECASE)

_MISSING_CSV_FIELDS = ["type", "name", "device_group", "protocol", "port", "members"]


# ── XPath helpers ─────────────────────────────────────────────────────────────

def _service_xpath(name: str, device_group: str, use_shared: bool) -> str:
    esc_name = name.replace("'", "\\'")
    if use_shared or ops_lib.MODE != "panorama":
        if ops_lib.MODE == "panorama":
            return f"/config/shared/service/entry[@name='{esc_name}']"
        dev = f"/config/devices/entry[@name='localhost.localdomain']"
        vsys = f"/vsys/entry[@name='{ops_lib.VSYS}']"
        return f"{dev}{vsys}/service/entry[@name='{esc_name}']"
    dg = device_group or ops_lib.DEVICE_GROUP
    return (
        f"/config/devices/entry[@name='localhost.localdomain']"
        f"/device-group/entry[@name='{dg}']"
        f"/service/entry[@name='{esc_name}']"
    )


def _service_xml(protocol: str, port: str) -> str:
    proto = protocol.lower().strip()
    if proto not in ("tcp", "udp"):
        raise ValueError(f"unsupported protocol '{protocol}' — must be tcp or udp")
    return f"<protocol><{proto}><port>{port}</port></{proto}></protocol>"


def _service_group_xpath(name: str, device_group: str, use_shared: bool) -> str:
    esc_name = name.replace("'", "\\'")
    if use_shared or ops_lib.MODE != "panorama":
        if ops_lib.MODE == "panorama":
            return f"/config/shared/service-group/entry[@name='{esc_name}']"
        dev = f"/config/devices/entry[@name='localhost.localdomain']"
        vsys = f"/vsys/entry[@name='{ops_lib.VSYS}']"
        return f"{dev}{vsys}/service-group/entry[@name='{esc_name}']"
    dg = device_group or ops_lib.DEVICE_GROUP
    return (
        f"/config/devices/entry[@name='localhost.localdomain']"
        f"/device-group/entry[@name='{dg}']"
        f"/service-group/entry[@name='{esc_name}']"
    )


def _service_group_xml(members: list[str]) -> str:
    mbr = "".join(f"<member>{m}</member>" for m in members)
    return f"<members>{mbr}</members>"


# ── Existence check ───────────────────────────────────────────────────────────

def _object_exists(xpath: str) -> bool:
    try:
        xml_text = ops_lib.api_get(xpath)
        root = ET.fromstring(xml_text)
        return root.get("status") == "success" and root.find(".//entry") is not None
    except Exception:
        return False


def _fetch_existing_service_names(device_group: str, use_shared: bool) -> set[str]:
    """Fetch all existing service object names from Panorama in one API call."""
    if use_shared or ops_lib.MODE != "panorama":
        if ops_lib.MODE == "panorama":
            xpath = "/config/shared/service"
        else:
            dev  = "/config/devices/entry[@name='localhost.localdomain']"
            vsys = f"/vsys/entry[@name='{ops_lib.VSYS}']"
            xpath = f"{dev}{vsys}/service"
    else:
        dg    = device_group or ops_lib.DEVICE_GROUP
        xpath = (
            f"/config/devices/entry[@name='localhost.localdomain']"
            f"/device-group/entry[@name='{dg}']/service"
        )
    try:
        xml_text = ops_lib.api_get(xpath)
        root     = ET.fromstring(xml_text)
        return {e.get("name") for e in root.iter("entry") if e.get("name")}
    except Exception:
        return set()


# ── Per-row worker ────────────────────────────────────────────────────────────

def _process_row(row: dict, use_shared: bool, dry_run: bool) -> tuple[str, str, str]:
    """Process one CSV row. Returns (status, name, detail).
    status: 'created' | 'exists' | 'invalid' | 'failed'
    """
    name     = row.get("name", "").strip()
    dg       = ops_lib.DEVICE_GROUP
    protocol = row.get("protocol", "").strip()
    port     = row.get("port", "").strip()
    location = "shared" if use_shared else dg

    if not name or not protocol or not port:
        with _PRINT_LOCK:
            print(f"  SKIP  {name or '(no name)'}  — missing required fields")
        return "invalid", name, "missing required fields"

    xpath = _service_xpath(name, dg, use_shared)

    if _object_exists(xpath):
        with _PRINT_LOCK:
            print(f"  SKIP  {name}  — already exists")
        return "exists", name, ""

    if dry_run:
        with _PRINT_LOCK:
            print(f"  DRY-RUN  {name}  ({protocol}/{port})  in {location}")
        return "created", name, f"{protocol}/{port}"

    try:
        element = _service_xml(protocol, port)
        resp    = ops_lib.api_set(xpath, element)
        if ops_lib.is_success(resp):
            with _PRINT_LOCK:
                print(f"  CREATE  {name}  ({protocol}/{port})  in {location}  ok")
            return "created", name, f"{protocol}/{port}"
        else:
            with _PRINT_LOCK:
                print(f"  FAILED  {name}  — {resp[:120]}")
            return "failed", name, resp[:120]
    except Exception as exc:
        with _PRINT_LOCK:
            print(f"  FAILED  {name}  — {exc}")
        return "failed", name, str(exc)


# ── Per-group worker ─────────────────────────────────────────────────────────

def _process_group_row(
    row: dict,
    use_shared: bool,
    dry_run: bool,
    available_objects: set[str],
) -> tuple[str, str, str]:
    """Process one service_group CSV row. Returns (status, name, detail).
    status: 'created' | 'exists' | 'invalid' | 'blocked' | 'failed'
    """
    name        = row.get("name", "").strip()
    dg          = ops_lib.DEVICE_GROUP
    members_raw = row.get("members", "").strip()
    location    = "shared" if use_shared else dg

    if not name or not members_raw:
        with _PRINT_LOCK:
            print(f"  SKIP  {name or '(no name)'}  — missing required fields (name/members)")
        return "invalid", name, "missing required fields"

    members = [m.strip() for m in members_raw.split("|") if m.strip()]
    if not members:
        with _PRINT_LOCK:
            print(f"  SKIP  {name}  — empty members list")
        return "invalid", name, "empty members list"

    truly_missing = [m for m in members if m not in available_objects]
    if truly_missing:
        msg = f"members not in Panorama: {', '.join(truly_missing)}"
        with _PRINT_LOCK:
            print(f"  BLOCKED  {name}  — {msg}")
        return "blocked", name, msg

    xpath = _service_group_xpath(name, dg, use_shared)

    if _object_exists(xpath):
        with _PRINT_LOCK:
            print(f"  SKIP  {name}  — already exists")
        return "exists", name, ""

    if dry_run:
        with _PRINT_LOCK:
            print(f"  DRY-RUN  {name}  (service-group, {len(members)} member(s))  in {location}")
        return "created", name, f"service-group, {len(members)} member(s)"

    try:
        element = _service_group_xml(members)
        resp    = ops_lib.api_set(xpath, element)
        if ops_lib.is_success(resp):
            with _PRINT_LOCK:
                print(f"  CREATE  {name}  (service-group, {len(members)} member(s))  in {location}  ok")
            return "created", name, f"service-group, {len(members)} member(s)"
        else:
            with _PRINT_LOCK:
                print(f"  FAILED  {name}  — {resp[:120]}")
            return "failed", name, resp[:120]
    except Exception as exc:
        with _PRINT_LOCK:
            print(f"  FAILED  {name}  — {exc}")
        return "failed", name, str(exc)


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create service objects in Panorama from a design svc CSV."
    )
    parser.add_argument("input_csv", help="Service objects CSV produced by design-rule-apps.py")
    parser.add_argument(
        "--device-group", "--dg", metavar="NAME", dest="device_group",
        help="Override device group (Panorama mode only; default: value from CSV row)",
    )
    parser.add_argument(
        "--shared", action="store_true",
        help="Create all objects under /config/shared instead of the device group",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print what would be created without making any changes",
    )
    parser.add_argument(
        "--workers", metavar="N", type=int, default=4,
        help="Parallel worker threads (default: 4)",
    )
    args = parser.parse_args()

    if not args.device_group and not args.shared:
        parser.error(
            "--dg/--device-group or --shared is required.\n"
            "  Specify the target device group explicitly to avoid deploying to the wrong location."
        )

    if args.device_group:
        ops_lib.DEVICE_GROUP = args.device_group
        ops_lib.MODE = "panorama"

    run_dt = datetime.datetime.now()

    print(SEP)
    print(f"  deploy-service-objects  v{__version__}")
    print(SEP)
    print(f"  Input  : {args.input_csv}")
    print(f"  Target : {ops_lib.TARGET_HOST}  ({ops_lib.mode_summary()})")
    if args.shared:
        print("  Scope  : shared (/config/shared/service)")
    else:
        print(f"  Scope  : device group {ops_lib.DEVICE_GROUP}")
    if args.dry_run:
        print("  Mode   : dry-run (no changes will be applied)")
    print(f"  Workers: {args.workers}")
    print()

    # ── Load CSV ──────────────────────────────────────────────────────────────
    try:
        with open(args.input_csv, newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
    except FileNotFoundError:
        print(f"Error: input file not found: {args.input_csv}", file=sys.stderr)
        sys.exit(1)

    if not rows:
        print("No rows found in input CSV.")
        return

    svc_rows = [r for r in rows if r.get("type", "").strip() == "service_object"]
    grp_rows = [r for r in rows if r.get("type", "").strip() == "service_group"]

    if not svc_rows and not grp_rows:
        print("No service_object or service_group rows found — nothing to do.")
        return

    if svc_rows:
        print(f"  {len(svc_rows)} service object(s) to process")
    if grp_rows:
        print(f"  {len(grp_rows)} service group(s) to process")
    print()

    run_ts     = run_dt.strftime("%Y%m%d-%H%M%S")
    stem       = Path(args.input_csv).stem
    results_path = f"Output/deploy-{stem}-{run_ts}-results.txt"
    os.makedirs("Output", exist_ok=True)

    # ── Pre-load existing service objects (one bulk API call) ────────────────
    print("  Fetching existing service objects...", end=" ", flush=True)
    available_objects: set[str] = _fetch_existing_service_names(ops_lib.DEVICE_GROUP, args.shared)
    print(f"{len(available_objects)} found")
    print()

    # ── Pass 1: service objects (parallel) ────────────────────────────────────
    print(SEP)
    svc_results: list[tuple[str, str, str]] = []
    if svc_rows:
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futures = [ex.submit(_process_row, row, args.shared, args.dry_run) for row in svc_rows]
            for f in as_completed(futures):
                svc_results.append(f.result())

    for status, name, _ in svc_results:
        if status == "created" and name:
            available_objects.add(name)

    # ── Pass 2: service groups (sequential — depend on objects from pass 1) ───
    grp_results: list[tuple[str, str, str]] = []
    if grp_rows:
        if svc_rows:
            print(SEP)
        for row in grp_rows:
            grp_results.append(
                _process_group_row(row, args.shared, args.dry_run, available_objects)
            )

    all_results = svc_results + grp_results
    created  = [(n, d) for s, n, d in all_results if s == "created"]
    existed  = [(n, d) for s, n, d in all_results if s == "exists"]
    errors   = [(n, d) for s, n, d in all_results if s in ("failed", "blocked")]
    invalid  = [(n, d) for s, n, d in all_results if s == "invalid"]

    # ── Supplemental missing-objects CSV ─────────────────────────────────────
    BLOCKED_PREFIX = "members not in Panorama: "
    missing_names: list[str] = []
    for status, name, detail in grp_results:
        if status == "blocked" and detail.startswith(BLOCKED_PREFIX):
            missing_names.extend(
                n.strip() for n in detail.removeprefix(BLOCKED_PREFIX).split(", ") if n.strip()
            )

    missing_csv_path: str = ""
    if missing_names:
        missing_rows: list[dict] = []
        for n in missing_names:
            m = _SVC_NAME_RE.search(n)
            missing_rows.append({
                "type":         "service_object",
                "name":         n,
                "device_group": ops_lib.DEVICE_GROUP,
                "protocol":     m.group(1).lower() if m else "",
                "port":         m.group(2)         if m else "",
                "members":      "",
            })
        missing_csv_path = f"Output/deploy-{stem}-{run_ts}-missing.csv"
        with open(missing_csv_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=_MISSING_CSV_FIELDS, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(missing_rows)

    # ── Summary ───────────────────────────────────────────────────────────────
    lines: list[str] = [SEP, "  Run Summary", SEP]

    if created:
        lines.append(f"  Created ({len(created)}):")
        for name, detail in sorted(created):
            lines.append(f"    {name:<40}  {detail}")
        lines.append("")

    skipped_all = existed + invalid
    if skipped_all:
        lines.append(f"  Skipped — already existed / invalid ({len(skipped_all)}):")
        for name, detail in sorted(skipped_all):
            label = f"  ({detail})" if detail else ""
            lines.append(f"    {name}{label}")
        lines.append("")

    if errors:
        lines.append(f"  Blocked / Failed ({len(errors)}):")
        for name, detail in errors:
            lines.append(f"    {name:<40}  — {detail}")
        lines.append("")

    lines.append(
        f"  Total: {len(created)} created, {len(skipped_all)} skipped, {len(errors)} blocked/failed"
    )
    lines.append(SEP)
    if created and not args.dry_run:
        lines.append("  Objects are in Panorama's candidate config.")
        lines.append("  Commit via Panorama UI or your standard commit workflow.")
        lines.append(SEP)

    if missing_csv_path:
        lines.append(f"  Missing objects — deploy these first, then re-run ({len(missing_names)}):")
        for n in missing_names:
            lines.append(f"    {n}")
        lines.append(f"  Missing objects CSV: {missing_csv_path}")
        lines.append(SEP)

    lines.append(f"  Results saved: {results_path}")
    lines.append(SEP)

    print("\n".join(lines))
    with open(results_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
