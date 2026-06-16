"""
deploy-service-objects.py — Create service objects in Panorama from a design svc CSV

Reads the *-svc.csv file produced by design-rule-apps.py and creates any missing
service objects in Panorama.  Run this before deploy-rule-design.py to ensure all
service objects referenced in NS rule designs exist.

Execution flow:
  1. Load svc CSV
  2. For each service_object row: check if it already exists, then create it
  3. Print summary
  4. If --dry-run: exit without changes

Changes are left in Panorama's candidate config; commit via the Panorama UI or a
separate commit step.

Usage:
    python deploy-service-objects.py <svc_csv> [options]

Options:
    --device-group NAME / --dg NAME   Override device group (Panorama mode only)
    --shared                          Create objects under /config/shared instead
                                      of the device group in each CSV row
    --dry-run                         Print what would be created; make no changes
"""

import argparse
import csv
import datetime
import sys
import threading
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "libs"))
import ops_lib  # noqa: E402

requests.packages.urllib3.disable_warnings()

__version__ = "1.0.4"

SEP  = "=" * 62
DASH = "-" * 62

_PRINT_LOCK = threading.Lock()


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


# ── Per-row worker ────────────────────────────────────────────────────────────

def _process_row(row: dict, use_shared: bool, dry_run: bool) -> str:
    """Process one CSV row. Returns 'created', 'skipped', or 'failed'."""
    name     = row.get("name", "").strip()
    dg       = ops_lib.DEVICE_GROUP
    protocol = row.get("protocol", "").strip()
    port     = row.get("port", "").strip()
    location = "shared" if use_shared else dg

    if not name or not protocol or not port:
        with _PRINT_LOCK:
            print(f"  SKIP  {name or '(no name)'}  — missing required fields")
        return "skipped"

    xpath = _service_xpath(name, dg, use_shared)

    if _object_exists(xpath):
        with _PRINT_LOCK:
            print(f"  SKIP  {name}  — already exists")
        return "skipped"

    if dry_run:
        with _PRINT_LOCK:
            print(f"  DRY-RUN  {name}  ({protocol}/{port})  in {location}")
        return "created"

    try:
        element = _service_xml(protocol, port)
        resp    = ops_lib.api_set(xpath, element)
        if ops_lib.is_success(resp):
            with _PRINT_LOCK:
                print(f"  CREATE  {name}  ({protocol}/{port})  in {location}  ok")
            return "created"
        else:
            with _PRINT_LOCK:
                print(f"  FAILED  {name}  — {resp[:120]}")
            return "failed"
    except Exception as exc:
        with _PRINT_LOCK:
            print(f"  FAILED  {name}  — {exc}")
        return "failed"


# ── Per-group worker ─────────────────────────────────────────────────────────

def _process_group_row(row: dict, use_shared: bool, dry_run: bool) -> str:
    """Process one service_group CSV row. Returns 'created', 'skipped', or 'failed'."""
    name     = row.get("name", "").strip()
    dg       = ops_lib.DEVICE_GROUP
    members_raw = row.get("members", "").strip()
    location = "shared" if use_shared else dg

    if not name or not members_raw:
        with _PRINT_LOCK:
            print(f"  SKIP  {name or '(no name)'}  — missing required fields (name/members)")
        return "skipped"

    members = [m.strip() for m in members_raw.split("|") if m.strip()]
    if not members:
        with _PRINT_LOCK:
            print(f"  SKIP  {name}  — empty members list")
        return "skipped"

    xpath = _service_group_xpath(name, dg, use_shared)

    if _object_exists(xpath):
        with _PRINT_LOCK:
            print(f"  SKIP  {name}  — already exists")
        return "skipped"

    if dry_run:
        with _PRINT_LOCK:
            print(f"  DRY-RUN  {name}  (service-group, {len(members)} member(s))  in {location}")
        return "created"

    try:
        element = _service_group_xml(members)
        resp    = ops_lib.api_set(xpath, element)
        if ops_lib.is_success(resp):
            with _PRINT_LOCK:
                print(f"  CREATE  {name}  (service-group, {len(members)} member(s))  in {location}  ok")
            return "created"
        else:
            with _PRINT_LOCK:
                print(f"  FAILED  {name}  — {resp[:120]}")
            return "failed"
    except Exception as exc:
        with _PRINT_LOCK:
            print(f"  FAILED  {name}  — {exc}")
        return "failed"


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

    # ── Pass 1: service objects (parallel) ────────────────────────────────────
    print(SEP)
    statuses: list[str] = []
    if svc_rows:
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futures = [ex.submit(_process_row, row, args.shared, args.dry_run) for row in svc_rows]
            for f in as_completed(futures):
                statuses.append(f.result())

    # ── Pass 2: service groups (sequential — depend on objects from pass 1) ───
    grp_statuses: list[str] = []
    if grp_rows:
        if svc_rows:
            print(SEP)
        for row in grp_rows:
            grp_statuses.append(_process_group_row(row, args.shared, args.dry_run))

    created_count = statuses.count("created") + grp_statuses.count("created")
    skipped_count = statuses.count("skipped") + grp_statuses.count("skipped")
    failed_count  = statuses.count("failed")  + grp_statuses.count("failed")

    # ── Summary ───────────────────────────────────────────────────────────────
    print(SEP)
    if args.dry_run:
        print(f"  Dry-run: {created_count} would be created, {skipped_count} already exist")
    else:
        print(f"  Created : {created_count}")
        print(f"  Skipped : {skipped_count}  (already existed)")
        print(f"  Failed  : {failed_count}")
        if created_count:
            print()
            print("  Objects are in Panorama's candidate config.")
            print("  Commit via Panorama UI or your standard commit workflow.")
    print(SEP)


if __name__ == "__main__":
    main()
