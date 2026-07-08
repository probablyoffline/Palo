#!/usr/bin/env python3
"""
check-group.py — Look up members of PAN-OS group objects by name.

Usage:
    python check-group.py GROUP [GROUP ...] [--type address|service|application]
                                            [--expand] [--shared] [--dg NAME]
                                            [--format csv|txt]
                                            [--compare FILE]

Examples:
    python check-group.py "RFC-1918"
    python check-group.py "My-Servers" "My-DMZ" "My-Guests"
    python check-group.py "My-Servers" --expand
    python check-group.py "Web-Ports" --type service
    python check-group.py "Office-Apps" --type application
    python check-group.py "RFC-1918" --shared
    python check-group.py "My-Group" --dg "DG-Prod"
    python check-group.py "My-Group" --compare hosts.txt --dg "DG-Prod"
"""

import argparse
import csv
import datetime
import os
import re
import sys
import xml.etree.ElementTree as ET

# ops_lib.py lives in ../libs/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "libs"))
import ops_lib as lib  # noqa: E402

VERSION = "1.2.0"

_IP_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')

# ── XPath helpers ─────────────────────────────────────────────────────────────

_GROUP_SUFFIX = {
    "address":     "address-group",
    "service":     "service-group",
    "application": "application-group",
}


def _group_xpath(name: str, group_type: str, shared: bool) -> str:
    base = "/config/shared" if shared else lib._config_base()
    return f"{base}/{_GROUP_SUFFIX[group_type]}/entry[@name='{name}']"


def _address_xpath(name: str, shared: bool) -> str:
    if shared:
        return f"/config/shared/address/entry[@name='{name}']"
    return f"{lib._config_base()}/address/entry[@name='{name}']"


# ── Fetch helpers ─────────────────────────────────────────────────────────────

def get_group_members(name: str, group_type: str, shared: bool) -> list[str] | None:
    """Return the member list for a group, or None if the group doesn't exist."""
    xpath = _group_xpath(name, group_type, shared)
    xml_text = lib.api_get(xpath)
    if 'status="error"' in xml_text or "<entry" not in xml_text:
        return None
    try:
        root = ET.fromstring(xml_text)
        return [m.text for m in root.iter("member") if m.text]
    except ET.ParseError:
        return None


def resolve_address_object(name: str, shared: bool) -> str | None:
    """Return 'type: value' for a leaf address object, or None if not found."""
    xpath = _address_xpath(name, shared)
    xml_text = lib.api_get(xpath)
    if 'status="error"' in xml_text or "<entry" not in xml_text:
        return None
    try:
        root = ET.fromstring(xml_text)
        entry = root.find(".//entry")
        if entry is None:
            return None
        for atype in ("ip-netmask", "fqdn", "ip-range", "ip-wildcard"):
            val = entry.findtext(atype)
            if val:
                return f"{atype}: {val}"
        return None
    except ET.ParseError:
        return None


# ── Expand (recursive) ────────────────────────────────────────────────────────

def _expand(name: str, group_type: str, shared: bool, depth: int, seen: frozenset):
    """
    Yield (depth, member_name, is_group, annotation) tuples.
    `is_group=True` means this line is itself a nested group header.
    """
    members = get_group_members(name, group_type, shared)
    if members is None:
        return

    for member in members:
        if member in seen:
            yield (depth, member, False, "[circular reference — skipped]")
            continue

        sub_members = get_group_members(member, group_type, shared)
        if sub_members is not None:
            yield (depth, member, True, None)
            yield from _expand(member, group_type, shared, depth + 1, seen | {name})
        else:
            annotation = None
            if group_type == "address":
                annotation = resolve_address_object(member, shared)
            yield (depth, member, False, annotation)


# ── Data collection ───────────────────────────────────────────────────────────

def collect_members(group_name: str, group_type: str, shared: bool) -> list[dict]:
    """
    Collect all leaf members with resolved values (flat — no tree structure).
    Returns list of {group, member, addr_type, value} dicts.
    """
    rows = []
    for _depth, name, is_group, annotation in _expand(group_name, group_type, shared, 0, frozenset()):
        if is_group:
            continue
        addr_type = value = ""
        if annotation and ": " in annotation:
            addr_type, value = annotation.split(": ", 1)
        rows.append({"group": group_name, "member": name, "addr_type": addr_type, "value": value})
    return rows


# ── Console output ────────────────────────────────────────────────────────────

def print_flat(group_name: str, group_type: str, shared: bool) -> None:
    members = get_group_members(group_name, group_type, shared)
    label = group_type.capitalize() + " Group"
    print(f"{label}: {group_name}")
    if members is None:
        print("  [not found]")
        return
    if not members:
        print("  [empty group]")
        return
    rows = collect_members(group_name, group_type, shared)
    for row in rows:
        annotation = f"({row['addr_type']}: {row['value']})" if row["value"] else ""
        print(f"  {row['member']:<40} {annotation}")


def print_expanded(group_name: str, group_type: str, shared: bool) -> None:
    members = get_group_members(group_name, group_type, shared)
    label = group_type.capitalize() + " Group"
    print(f"{label}: {group_name}  [expanded]")
    if members is None:
        print("  [not found]")
        return
    if not members:
        print("  [empty group]")
        return

    for depth, name, is_group, annotation in _expand(group_name, group_type, shared, 0, frozenset()):
        indent = "  " + "    " * depth
        if is_group:
            print(f"{indent}{name}  [group]")
        elif annotation:
            print(f"{indent}{name:<40} ({annotation})")
        else:
            print(f"{indent}{name}")


# ── File output ───────────────────────────────────────────────────────────────

def write_csv(rows: list[dict], filepath: str, multi_group: bool) -> None:
    fieldnames = ["group", "member", "addr_type", "value"] if multi_group else ["member", "addr_type", "value"]
    with open(filepath, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def write_txt(rows: list[dict], filepath: str, multi_group: bool) -> None:
    with open(filepath, "w", encoding="utf-8") as fh:
        current_group = None
        for row in rows:
            if multi_group and row["group"] != current_group:
                current_group = row["group"]
                fh.write(f"# Group: {current_group}\n")
            fh.write(row["member"] + "\n")


# ── Compare mode ──────────────────────────────────────────────────────────────

def load_input_list(filepath: str) -> list[str]:
    """Load a flat list of addresses from a TXT or CSV file."""
    ext = os.path.splitext(filepath)[1].lower()
    entries: list[str] = []

    with open(filepath, newline="", encoding="utf-8") as fh:
        if ext == ".csv":
            reader = csv.DictReader(fh)
            priority = ["address", "value", "ip", "name"]
            col = None
            for p in priority:
                if reader.fieldnames and any(f.strip().lower() == p for f in reader.fieldnames):
                    col = next(f for f in reader.fieldnames if f.strip().lower() == p)
                    break
            for row in reader:
                val = (row.get(col) or next(iter(row.values()), "")).strip()
                if val and not val.startswith("#"):
                    entries.append(val)
        else:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    entries.append(line)

    return entries


def normalize_addr(v: str) -> str:
    """Normalize an address for comparison: plain IP → /32; FQDN → lowercase."""
    v = v.strip()
    if "/" in v:
        return v
    if _IP_RE.match(v):
        return f"{v}/32"
    return v.lower()


def _deploy_name(normalized_value: str) -> str:
    """Generate an address object name from a normalized IP/CIDR/FQDN value."""
    if "/" in normalized_value:
        ip, prefix = normalized_value.rsplit("/", 1)
        prefix_int = int(prefix)
        prefix_str = str(prefix_int)
        tag = "H" if prefix_int == 32 else "N"
        return f"{tag}-{ip}-{prefix_str}"
    return f"FQDN-{normalized_value}"


def _detect_addr_type(value: str) -> tuple[str, str]:
    """Return (address_type, normalized_value) suitable for the deploy CSV."""
    if "/" in value:
        return "ip-netmask", value
    if _IP_RE.match(value):
        return "ip-netmask", f"{value}/32"
    return "fqdn", value.lower()


def run_compare(
    group_name: str,
    input_list: list[str],
    group_type: str,
    shared: bool,
) -> tuple[list[tuple[str, dict]], list[str]]:
    """
    Compare input_list against the group's resolved member values.
    Returns (found, missing) where:
      found   = list of (input_entry, matched_row_dict)
      missing = list of raw input_entry strings
    """
    rows = collect_members(group_name, group_type, shared)
    value_map: dict[str, dict] = {}
    for row in rows:
        if row["value"]:
            value_map[normalize_addr(row["value"])] = row

    found: list[tuple[str, dict]] = []
    missing: list[str] = []
    for entry in input_list:
        norm = normalize_addr(entry)
        if norm in value_map:
            found.append((entry, value_map[norm]))
        else:
            missing.append(entry)

    return found, missing


def print_compare(group_name: str, found: list, missing: list) -> None:
    print(f"Address Group: {group_name}  [compare mode]")
    print()
    print(f"  FOUND     ({len(found)})")
    for entry, row in found:
        annotation = f"→ {row['member']}  ({row['addr_type']}: {row['value']})" if row["value"] else f"→ {row['member']}"
        print(f"    {entry:<30} {annotation}")
    print()
    print(f"  MISSING   ({len(missing)})")
    for entry in missing:
        print(f"    {entry}")


def write_compare_csv(found: list, missing: list, filepath: str) -> None:
    """Write the comparison report CSV (status, input, matched_member, matched_value)."""
    fieldnames = ["status", "input", "matched_member", "matched_value"]
    with open(filepath, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for entry, row in found:
            writer.writerow({
                "status": "found",
                "input": entry,
                "matched_member": row["member"],
                "matched_value": row["value"],
            })
        for entry in missing:
            writer.writerow({"status": "missing", "input": entry, "matched_member": "", "matched_value": ""})


def write_deploy_csv(missing: list[str], filepath: str, device_group: str) -> None:
    """Write missing items as address_object rows in deploy-script format."""
    fieldnames = ["type", "name", "device_group", "address_type", "value", "members", "rules"]
    with open(filepath, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for entry in missing:
            addr_type, norm_value = _detect_addr_type(entry)
            writer.writerow({
                "type": "address_object",
                "name": _deploy_name(norm_value),
                "device_group": device_group,
                "address_type": addr_type,
                "value": norm_value,
                "members": "",
                "rules": "",
            })


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Look up members of PAN-OS group objects.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("names", nargs="+", metavar="GROUP",
                        help="One or more group names to look up")
    parser.add_argument("--type", dest="group_type", default="address",
                        choices=["address", "service", "application"],
                        help="Group type to query (default: address)")
    parser.add_argument("--expand", action="store_true",
                        help="Show nested group tree structure")
    parser.add_argument("--shared", action="store_true",
                        help="Look in /config/shared instead of the configured vsys/device-group")
    parser.add_argument(
        "--device-group", "--dg", metavar="NAME", dest="device_group",
        help="Override device group and force Panorama mode",
    )
    parser.add_argument(
        "--format", choices=["csv", "txt"], default="csv",
        help="Output file format (default: csv)",
    )
    parser.add_argument(
        "--compare", metavar="FILE", dest="compare_file",
        help="Compare a host/IP list against the group and report missing entries",
    )
    args = parser.parse_args()

    if args.device_group:
        lib.DEVICE_GROUP = args.device_group
        lib.MODE = "panorama"

    if args.compare_file and len(args.names) > 1:
        print("Error: --compare requires exactly one group name.")
        sys.exit(1)

    print(f"Target : {lib.TARGET_HOST}  [{lib.mode_summary()}]  v{VERSION}")
    print(f"Type   : {args.group_type} group{'s' if len(args.names) != 1 else ''}")
    print()

    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")

    # ── Compare mode ──────────────────────────────────────────────────────────
    if args.compare_file:
        group_name = args.names[0]
        input_list = load_input_list(args.compare_file)
        found, missing = run_compare(group_name, input_list, args.group_type, args.shared)

        print_compare(group_name, found, missing)

        report_file = f"check-group-{ts}.csv"
        write_compare_csv(found, missing, report_file)
        print(f"\nReport : {report_file}  ({len(found)} found, {len(missing)} missing)")

        if missing:
            deploy_file = f"check-group-missing-{ts}.csv"
            write_deploy_csv(missing, deploy_file, lib.DEVICE_GROUP)
            print(f"Deploy : {deploy_file}  ({len(missing)} objects)")
        return

    # ── Normal lookup mode ────────────────────────────────────────────────────
    for i, name in enumerate(args.names):
        if i > 0:
            print()
        if args.expand:
            print_expanded(name, args.group_type, args.shared)
        else:
            print_flat(name, args.group_type, args.shared)

    multi_group = len(args.names) > 1
    all_rows: list[dict] = []
    for name in args.names:
        all_rows.extend(collect_members(name, args.group_type, args.shared))

    outfile = f"check-group-{ts}.{args.format}"
    if args.format == "csv":
        write_csv(all_rows, outfile, multi_group)
    else:
        write_txt(all_rows, outfile, multi_group)
    print(f"\nOutput : {outfile}  ({len(all_rows)} rows)")


if __name__ == "__main__":
    main()
