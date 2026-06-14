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
import xml.etree.ElementTree as ET
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "libs"))
import ops_lib  # noqa: E402

requests.packages.urllib3.disable_warnings()

__version__ = "1.0.2"

SEP  = "=" * 62
DASH = "-" * 62


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


# ── Existence check ───────────────────────────────────────────────────────────

def _object_exists(xpath: str) -> bool:
    try:
        xml_text = ops_lib.api_get(xpath)
        root = ET.fromstring(xml_text)
        return root.get("status") == "success" and root.find(".//entry") is not None
    except Exception:
        return False


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
    if not svc_rows:
        print("No service_object rows found — nothing to do.")
        return

    print(f"  {len(svc_rows)} service object(s) to process")
    print()

    # ── Process each row ──────────────────────────────────────────────────────
    created_count  = 0
    skipped_count  = 0
    failed_count   = 0

    print(SEP)
    for row in svc_rows:
        name     = row.get("name", "").strip()
        dg       = ops_lib.DEVICE_GROUP  # set from --dg; --shared rows don't use this
        protocol = row.get("protocol", "").strip()
        port     = row.get("port", "").strip()

        if not name or not protocol or not port:
            print(f"  SKIP  {name or '(no name)'}  — missing required fields")
            skipped_count += 1
            continue

        xpath = _service_xpath(name, dg, args.shared)

        # Check if already exists
        if _object_exists(xpath):
            print(f"  SKIP  {name}  — already exists")
            skipped_count += 1
            continue

        location = "shared" if args.shared else dg
        print(f"  {'DRY-RUN' if args.dry_run else 'CREATE'}  {name}  ({protocol}/{port})  in {location}", end="  ")

        if args.dry_run:
            print()
            created_count += 1
            continue

        try:
            element = _service_xml(protocol, port)
            resp    = ops_lib.api_set(xpath, element)
            if ops_lib.is_success(resp):
                print("ok")
                created_count += 1
            else:
                print(f"FAILED — {resp[:120]}")
                failed_count += 1
        except Exception as exc:
            print(f"FAILED — {exc}")
            failed_count += 1

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
