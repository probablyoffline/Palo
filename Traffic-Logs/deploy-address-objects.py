"""
deploy-address-objects.py — Create address objects and address groups in Panorama

Reads a CSV (produced by design-rule-apps.py --host-groups or assembled manually) and
creates any missing address objects and address groups in Panorama's candidate config.

Run this before deploying rules that reference address groups produced by design-rule-apps.py.

Supported row types in the CSV:

  address_object  — Creates a single address object (host, network, or FQDN).
                    Columns used: name, device_group, address_type, value
                    address_type: ip-netmask | ip-range | fqdn
                    value:        192.168.1.2/32  |  192.168.1.0/24  |  host.example.com
                    If address_type is blank it is auto-detected from value:
                      - Contains '/' → ip-netmask
                      - Plain IP (x.x.x.x) → ip-netmask with /32 appended
                      - Otherwise → fqdn

  address_group   — Creates a static address group.
                    Columns used: name, device_group, members (pipe-separated member names)

Address object naming convention (user-defined in the name column):
  H-192.168.1.2-32        single host (/32)
  N-192.168.1.0-24        network (CIDR)
  FQDN-host.example.com   FQDN

The script does not enforce naming — the name column is authoritative.

Processing order: address objects are created first (parallel), then address groups
(sequential). This ensures group members exist before the group is created.

Changes are left in Panorama's candidate config; commit separately.

Usage:
    python deploy-address-objects.py <addr_csv> [options]

Options:
    --device-group NAME / --dg NAME   Target device group (required unless --shared)
    --shared                          Create objects under /config/shared instead
    --dry-run                         Print what would be created; make no changes
    --workers N                       Parallel threads for address objects (default: 4)
"""

import argparse
import csv
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

__version__ = "1.0.0"

SEP  = "=" * 62
DASH = "-" * 62

_PRINT_LOCK = threading.Lock()

_IP_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')


# ── XPath helpers ─────────────────────────────────────────────────────────────

def _address_xpath(name: str, device_group: str, use_shared: bool) -> str:
    esc = name.replace("'", "\\'")
    if use_shared or ops_lib.MODE != "panorama":
        if ops_lib.MODE == "panorama":
            return f"/config/shared/address/entry[@name='{esc}']"
        dev  = f"/config/devices/entry[@name='localhost.localdomain']"
        vsys = f"/vsys/entry[@name='{ops_lib.VSYS}']"
        return f"{dev}{vsys}/address/entry[@name='{esc}']"
    dg = device_group or ops_lib.DEVICE_GROUP
    return (
        f"/config/devices/entry[@name='localhost.localdomain']"
        f"/device-group/entry[@name='{dg}']"
        f"/address/entry[@name='{esc}']"
    )


def _address_group_xpath(name: str, device_group: str, use_shared: bool) -> str:
    esc = name.replace("'", "\\'")
    if use_shared or ops_lib.MODE != "panorama":
        if ops_lib.MODE == "panorama":
            return f"/config/shared/address-group/entry[@name='{esc}']"
        dev  = f"/config/devices/entry[@name='localhost.localdomain']"
        vsys = f"/vsys/entry[@name='{ops_lib.VSYS}']"
        return f"{dev}{vsys}/address-group/entry[@name='{esc}']"
    dg = device_group or ops_lib.DEVICE_GROUP
    return (
        f"/config/devices/entry[@name='localhost.localdomain']"
        f"/device-group/entry[@name='{dg}']"
        f"/address-group/entry[@name='{esc}']"
    )


# ── XML helpers ───────────────────────────────────────────────────────────────

def _detect_address_type(value: str) -> tuple[str, str]:
    """
    Auto-detect address_type from value. Returns (address_type, normalised_value).
    """
    v = value.strip()
    if "/" in v:
        return "ip-netmask", v
    if _IP_RE.match(v):
        return "ip-netmask", f"{v}/32"
    return "fqdn", v


def _address_object_xml(address_type: str, value: str) -> str:
    t = address_type.lower().strip()
    if t not in ("ip-netmask", "ip-range", "fqdn"):
        raise ValueError(f"unsupported address_type '{address_type}' — must be ip-netmask, ip-range, or fqdn")
    return f"<{t}>{value}</{t}>"


def _address_group_xml(members: list[str]) -> str:
    mbr = "".join(f"<member>{m}</member>" for m in members)
    return f"<static>{mbr}</static>"


# ── Existence check ───────────────────────────────────────────────────────────

def _object_exists(xpath: str) -> bool:
    try:
        xml_text = ops_lib.api_get(xpath)
        root = ET.fromstring(xml_text)
        return root.get("status") == "success" and root.find(".//entry") is not None
    except Exception:
        return False


# ── Per-row workers ───────────────────────────────────────────────────────────

def _process_object_row(row: dict, use_shared: bool, dry_run: bool) -> str:
    """Process one address_object CSV row. Returns 'created', 'skipped', or 'failed'."""
    name     = row.get("name", "").strip()
    dg       = ops_lib.DEVICE_GROUP
    atype    = row.get("address_type", "").strip()
    value    = row.get("value", "").strip()
    location = "shared" if use_shared else dg

    if not name or not value:
        with _PRINT_LOCK:
            print(f"  SKIP  {name or '(no name)'}  — missing required fields (name/value)")
        return "skipped"

    if not atype:
        atype, value = _detect_address_type(value)

    xpath = _address_xpath(name, dg, use_shared)

    if _object_exists(xpath):
        with _PRINT_LOCK:
            print(f"  SKIP  {name}  — already exists")
        return "skipped"

    if dry_run:
        with _PRINT_LOCK:
            print(f"  DRY-RUN  {name}  ({atype}: {value})  in {location}")
        return "created"

    try:
        element = _address_object_xml(atype, value)
        resp    = ops_lib.api_set(xpath, element)
        if ops_lib.is_success(resp):
            with _PRINT_LOCK:
                print(f"  CREATE  {name}  ({atype}: {value})  in {location}  ok")
            return "created"
        else:
            with _PRINT_LOCK:
                print(f"  FAILED  {name}  — {resp[:120]}")
            return "failed"
    except Exception as exc:
        with _PRINT_LOCK:
            print(f"  FAILED  {name}  — {exc}")
        return "failed"


def _process_group_row(row: dict, use_shared: bool, dry_run: bool) -> str:
    """Process one address_group CSV row. Returns 'created', 'skipped', or 'failed'."""
    name        = row.get("name", "").strip()
    dg          = ops_lib.DEVICE_GROUP
    members_raw = row.get("members", "").strip()
    location    = "shared" if use_shared else dg

    if not name or not members_raw:
        with _PRINT_LOCK:
            print(f"  SKIP  {name or '(no name)'}  — missing required fields (name/members)")
        return "skipped"

    members = [m.strip() for m in members_raw.split("|") if m.strip()]
    if not members:
        with _PRINT_LOCK:
            print(f"  SKIP  {name}  — empty members list")
        return "skipped"

    xpath = _address_group_xpath(name, dg, use_shared)

    if _object_exists(xpath):
        with _PRINT_LOCK:
            print(f"  SKIP  {name}  — already exists")
        return "skipped"

    if dry_run:
        with _PRINT_LOCK:
            print(f"  DRY-RUN  {name}  (address-group, {len(members)} member(s))  in {location}")
        return "created"

    try:
        element = _address_group_xml(members)
        resp    = ops_lib.api_set(xpath, element)
        if ops_lib.is_success(resp):
            with _PRINT_LOCK:
                print(f"  CREATE  {name}  (address-group, {len(members)} member(s))  in {location}  ok")
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
        description="Create address objects and address groups in Panorama from a CSV."
    )
    parser.add_argument("input_csv", help="Address CSV (from design-rule-apps.py or manually assembled)")
    parser.add_argument(
        "--device-group", "--dg", metavar="NAME", dest="device_group",
        help="Target device group (Panorama mode only; required unless --shared)",
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
        help="Parallel worker threads for address objects (default: 4)",
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

    print(SEP)
    print(f"  deploy-address-objects  v{__version__}")
    print(SEP)
    print(f"  Input  : {args.input_csv}")
    print(f"  Target : {ops_lib.TARGET_HOST}  ({ops_lib.mode_summary()})")
    if args.shared:
        print("  Scope  : shared (/config/shared/address)")
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

    obj_rows = [r for r in rows if r.get("type", "").strip() == "address_object"]
    grp_rows = [r for r in rows if r.get("type", "").strip() == "address_group"]

    if not obj_rows and not grp_rows:
        print("No address_object or address_group rows found — nothing to do.")
        return

    if obj_rows:
        print(f"  {len(obj_rows)} address object(s) to process")
    if grp_rows:
        print(f"  {len(grp_rows)} address group(s) to process")
    print()

    # ── Pass 1: address objects (parallel) ────────────────────────────────────
    print(SEP)
    statuses: list[str] = []
    if obj_rows:
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futures = [ex.submit(_process_object_row, row, args.shared, args.dry_run) for row in obj_rows]
            for f in as_completed(futures):
                statuses.append(f.result())

    # ── Pass 2: address groups (sequential — depend on objects from pass 1) ───
    grp_statuses: list[str] = []
    if grp_rows:
        if obj_rows:
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
