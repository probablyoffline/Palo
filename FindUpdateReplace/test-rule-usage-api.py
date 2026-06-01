#!/usr/bin/env python3
"""
test-rule-usage-api.py  — probe Panorama rule-use command formats for a DG

Fires several candidate XML commands against Panorama and prints the raw
response for each, so you can identify which format works before updating
find-server-rules.py.

Usage:
  python test-rule-usage-api.py <device-group>
"""

import sys
import os
import xml.etree.ElementTree as ET

import requests

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "libs"))
import ops_lib

requests.packages.urllib3.disable_warnings()

SEP  = "=" * 68
THIN = "-" * 68


def probe(label: str, cmd: str) -> None:
    print(f"\n{SEP}")
    print(f"  {label}")
    print(f"{THIN}")
    print(f"  CMD: {cmd}")
    print(THIN)
    try:
        r = requests.post(
            f"https://{ops_lib.TARGET_HOST}/api/",
            data={"type": "op", "cmd": cmd, "key": ops_lib.API_KEY},
            verify=False,
            timeout=30,
        )
        raw = r.text
        # Pretty-print if valid XML
        try:
            root = ET.fromstring(raw)
            status = root.get("status", "?")
            print(f"  HTTP {r.status_code}  status={status}")
            # Show first 800 chars of body
            print()
            print(raw[:800])
            if len(raw) > 800:
                print(f"  ... ({len(raw)} bytes total)")
        except ET.ParseError:
            print(f"  HTTP {r.status_code}  (non-XML response)")
            print(raw[:400])
    except Exception as exc:
        print(f"  ERROR: {exc}")


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python test-rule-usage-api.py <device-group>")
        sys.exit(1)

    dg = sys.argv[1]
    print(f"\nTarget  : {ops_lib.TARGET_HOST}")
    print(f"DG      : {dg}")

    candidates = [
        (
            "flat DG + type=unused",
            f"<show><rule-use><rule-base>security</rule-base>"
            f"<device-group>{dg}</device-group>"
            f"<type>unused</type></rule-use></show>",
        ),
        (
            "flat DG + type=used",
            f"<show><rule-use><rule-base>security</rule-base>"
            f"<device-group>{dg}</device-group>"
            f"<type>used</type></rule-use></show>",
        ),
        (
            "flat DG + type=all",
            f"<show><rule-use><rule-base>security</rule-base>"
            f"<device-group>{dg}</device-group>"
            f"<type>all</type></rule-use></show>",
        ),
        (
            "entry DG + type=unused",
            f"<show><rule-use><rule-base>security</rule-base>"
            f"<device-group><entry name='{dg}'/></device-group>"
            f"<type>unused</type></rule-use></show>",
        ),
        (
            "no DG + type=unused",
            f"<show><rule-use><rule-base>security</rule-base>"
            f"<type>unused</type></rule-use></show>",
        ),
        (
            "NAT: flat DG + type=unused",
            f"<show><rule-use><rule-base>nat</rule-base>"
            f"<device-group>{dg}</device-group>"
            f"<type>unused</type></rule-use></show>",
        ),
    ]

    for label, cmd in candidates:
        probe(label, cmd)

    print(f"\n{SEP}\n")


if __name__ == "__main__":
    main()
