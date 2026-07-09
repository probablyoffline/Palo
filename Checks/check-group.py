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

VERSION = "1.5.0"

_IP_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')

# ── XPath helpers ─────────────────────────────────────────────────────────────

_GROUP_SUFFIX = {
    "address":     "address-group",
    "service":     "service-group",
    "application": "application-group",
}


# ── Bulk fetch helpers ────────────────────────────────────────────────────────

def _base(shared: bool) -> str:
    return "/config/shared" if shared else lib._config_base()


def fetch_all_groups(group_type: str, shared: bool) -> dict[str, list[str]]:
    """One API call — returns {group_name: [member, ...]} for every group of this type."""
    xpath = f"{_base(shared)}/{_GROUP_SUFFIX[group_type]}"
    xml_text = lib.api_get(xpath)
    if 'status="error"' in xml_text or "<entry" not in xml_text:
        return {}
    try:
        root = ET.fromstring(xml_text)
        return {
            e.get("name"): [m.text for m in e.iter("member") if m.text]
            for e in root.iter("entry") if e.get("name")
        }
    except ET.ParseError:
        return {}


def fetch_all_address_objects(shared: bool) -> dict[str, tuple[str, str]]:
    """One API call — returns {obj_name: (addr_type, value)} for every address object."""
    xpath = f"{_base(shared)}/address"
    xml_text = lib.api_get(xpath)
    if 'status="error"' in xml_text or "<entry" not in xml_text:
        return {}
    try:
        root = ET.fromstring(xml_text)
        result: dict[str, tuple[str, str]] = {}
        for entry in root.iter("entry"):
            name = entry.get("name")
            if not name:
                continue
            for atype in ("ip-netmask", "fqdn", "ip-range", "ip-wildcard"):
                val = entry.findtext(atype)
                if val:
                    result[name] = (atype, val)
                    break
        return result
    except ET.ParseError:
        return {}


# ── Expand (recursive, works from pre-fetched dicts) ─────────────────────────

def _expand(
    name: str,
    groups: dict[str, list[str]],
    objects: dict[str, tuple[str, str]],
    depth: int,
    seen: frozenset,
    verbose: bool = False,
):
    """Yield (depth, member_name, is_group, annotation) using cached bulk data."""
    members = groups.get(name)
    if members is None:
        return

    for member in members:
        if member in seen:
            if verbose:
                print(f"    {'  ' * depth}{member}  [circular reference — skipped]", flush=True)
            yield (depth, member, False, "[circular reference — skipped]")
            continue

        if member in groups:
            if verbose:
                print(f"    {'  ' * depth}{member}  [nested group — expanding]", flush=True)
            yield (depth, member, True, None)
            yield from _expand(member, groups, objects, depth + 1, seen | {name}, verbose)
        else:
            annotation = None
            if member in objects:
                atype, val = objects[member]
                annotation = f"{atype}: {val}"
            if verbose:
                val_str = f"  ({annotation})" if annotation else ""
                print(f"    {'  ' * depth}{member:<40}{val_str}", flush=True)
            yield (depth, member, False, annotation)


# ── Data collection ───────────────────────────────────────────────────────────

def collect_members(
    group_name: str,
    group_type: str,
    shared: bool,
    verbose: bool = False,
) -> list[dict] | None:
    """
    Bulk-fetch all groups and objects (2 API calls total), then resolve members locally.
    Returns None if the group doesn't exist, [] if empty, or list of resolved member dicts.
    """
    if verbose:
        print(f"  Fetching all {group_type} groups...", flush=True)
    groups = fetch_all_groups(group_type, shared)

    if group_name not in groups:
        return None

    objects: dict[str, tuple[str, str]] = {}
    if group_type == "address":
        if verbose:
            print(f"  Fetching all address objects...", flush=True)
        objects = fetch_all_address_objects(shared)

    if verbose:
        direct = len(groups[group_name])
        print(f"  Expanding {group_name} ({direct} direct member(s))...", flush=True)

    rows = []
    for _depth, name, is_group, annotation in _expand(group_name, groups, objects, 0, frozenset(), verbose):
        if is_group:
            continue
        addr_type = value = ""
        if annotation and ": " in annotation:
            addr_type, value = annotation.split(": ", 1)
        rows.append({"group": group_name, "member": name, "addr_type": addr_type, "value": value})

    if verbose:
        print(f"  {len(rows)} members resolved.", flush=True)
    return rows


# ── Console output ────────────────────────────────────────────────────────────

def print_flat(group_name: str, group_type: str, shared: bool,
               verbose: bool = False) -> list[dict]:
    """Display flat member list and return collected rows for file output."""
    label = group_type.capitalize() + " Group"
    rows = collect_members(group_name, group_type, shared, verbose)
    print(f"{label}: {group_name}")
    if rows is None:
        print("  [not found]")
        return []
    if not rows:
        print("  [empty group]")
        return []
    for row in rows:
        annotation = f"({row['addr_type']}: {row['value']})" if row["value"] else ""
        print(f"  {row['member']:<40} {annotation}")
    return rows


def print_expanded(group_name: str, group_type: str, shared: bool,
                   verbose: bool = False) -> list[dict]:
    """Display tree-structured member list and return leaf rows for file output."""
    label = group_type.capitalize() + " Group"
    print(f"{label}: {group_name}  [expanded]")

    if verbose:
        print(f"  Fetching all {group_type} groups...", flush=True)
    groups = fetch_all_groups(group_type, shared)

    if group_name not in groups:
        print("  [not found]")
        return []
    if not groups[group_name]:
        print("  [empty group]")
        return []

    objects: dict[str, tuple[str, str]] = {}
    if group_type == "address":
        if verbose:
            print(f"  Fetching all address objects...", flush=True)
        objects = fetch_all_address_objects(shared)

    leaf_rows: list[dict] = []
    for depth, name, is_group, annotation in _expand(group_name, groups, objects, 0, frozenset(), verbose):
        indent = "  " + "    " * depth
        if is_group:
            print(f"{indent}{name}  [group]")
        elif annotation:
            print(f"{indent}{name:<40} ({annotation})")
            addr_type, value = annotation.split(": ", 1) if ": " in annotation else ("", "")
            leaf_rows.append({"group": group_name, "member": name, "addr_type": addr_type, "value": value})
        else:
            print(f"{indent}{name}")
            leaf_rows.append({"group": group_name, "member": name, "addr_type": "", "value": ""})
    return leaf_rows


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
    verbose: bool = False,
) -> tuple[list[tuple[str, dict]], list[str]]:
    """
    Compare input_list against the group's resolved member values.
    Returns (found, missing) where:
      found   = list of (input_entry, matched_row_dict)
      missing = list of raw input_entry strings
    """
    if verbose:
        print(f"  {len(input_list)} input entries loaded.", flush=True)
        print(f"  Resolving group members...", flush=True)

    rows = collect_members(group_name, group_type, shared, verbose)
    if rows is None:
        print(f"Error: Group '{group_name}' not found.")
        sys.exit(1)

    value_map: dict[str, dict] = {normalize_addr(r["value"]): r for r in rows if r["value"]}

    if verbose:
        print(f"  Comparing {len(input_list)} input entries against {len(value_map)} group values...", flush=True)

    found: list[tuple[str, dict]] = []
    missing: list[str] = []
    for entry in input_list:
        norm = normalize_addr(entry)
        if norm in value_map:
            found.append((entry, value_map[norm]))
        else:
            missing.append(entry)

    if verbose:
        print(f"  Result: {len(found)} found, {len(missing)} missing.", flush=True)

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


# ── Diff mode (two-way comparison) ───────────────────────────────────────────

def run_diff(
    group_name: str,
    input_list: list[str],
    group_type: str,
    shared: bool,
    verbose: bool = False,
) -> tuple[list[tuple[str, dict]], list[str], list[dict]]:
    """
    Full two-way diff between input_list and group members.
    Returns (found, missing_from_group, extra_in_group) where:
      found              = list of (input_entry, matched_row_dict)
      missing_from_group = list of input_entry strings not in the group
      extra_in_group     = list of row dicts for group members not in input_list
    """
    if verbose:
        print(f"  {len(input_list)} input entries loaded.", flush=True)
        print(f"  Resolving group members...", flush=True)

    rows = collect_members(group_name, group_type, shared, verbose)
    if rows is None:
        print(f"Error: Group '{group_name}' not found.")
        sys.exit(1)

    value_map: dict[str, dict] = {normalize_addr(r["value"]): r for r in rows if r["value"]}
    norm_input: set[str] = {normalize_addr(e) for e in input_list}

    if verbose:
        print(f"  Comparing {len(input_list)} input entries against {len(value_map)} group values...", flush=True)

    found: list[tuple[str, dict]] = []
    missing_from_group: list[str] = []
    for entry in input_list:
        norm = normalize_addr(entry)
        if norm in value_map:
            found.append((entry, value_map[norm]))
        else:
            missing_from_group.append(entry)

    extra_in_group: list[dict] = [row for norm, row in value_map.items() if norm not in norm_input]

    if verbose:
        print(
            f"  Result: {len(found)} matched, "
            f"{len(missing_from_group)} missing from group, "
            f"{len(extra_in_group)} extra in group.",
            flush=True,
        )

    return found, missing_from_group, extra_in_group


def print_diff(group_name: str, found: list, missing_from_group: list, extra_in_group: list) -> None:
    print(f"Address Group: {group_name}  [diff mode]")
    print()
    print(f"  MATCHED            ({len(found)})")
    for entry, row in found:
        annotation = f"→ {row['member']}  ({row['addr_type']}: {row['value']})" if row["value"] else f"→ {row['member']}"
        print(f"    {entry:<30} {annotation}")
    print()
    print(f"  MISSING FROM GROUP ({len(missing_from_group)})   [in your list, not in group]")
    for entry in missing_from_group:
        print(f"    {entry}")
    print()
    print(f"  EXTRA IN GROUP     ({len(extra_in_group)})   [in group, not in your list]")
    for row in extra_in_group:
        annotation = f"({row['addr_type']}: {row['value']})" if row["value"] else ""
        print(f"    {row['member']:<40} {annotation}")


def write_diff_csv(found: list, missing_from_group: list, extra_in_group: list, filepath: str) -> None:
    """Write a full diff report CSV with a direction column."""
    fieldnames = ["direction", "input_value", "object_name", "object_value"]
    with open(filepath, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for entry, row in found:
            writer.writerow({"direction": "matched", "input_value": entry,
                             "object_name": row["member"], "object_value": row["value"]})
        for entry in missing_from_group:
            writer.writerow({"direction": "missing_from_group", "input_value": entry,
                             "object_name": "", "object_value": ""})
        for row in extra_in_group:
            writer.writerow({"direction": "extra_in_group", "input_value": "",
                             "object_name": row["member"], "object_value": row["value"]})


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
        help="Compare a host/IP list against the group — shows what's missing from the group",
    )
    parser.add_argument(
        "--diff", metavar="FILE", dest="diff_file",
        help="Two-way diff — shows what's missing from the group AND what's extra in the group",
    )
    parser.add_argument(
        "--quiet", "-q", action="store_true",
        help="Suppress progress output (only show final results)",
    )
    args = parser.parse_args()
    verbose = not args.quiet

    if args.compare_file and args.diff_file:
        print("Error: --compare and --diff cannot be used together.")
        sys.exit(1)

    if args.device_group:
        lib.DEVICE_GROUP = args.device_group
        lib.MODE = "panorama"

    if (args.compare_file or args.diff_file) and len(args.names) > 1:
        print("Error: --compare / --diff requires exactly one group name.")
        sys.exit(1)

    print(f"Target : {lib.TARGET_HOST}  [{lib.mode_summary()}]  v{VERSION}")
    print(f"Type   : {args.group_type} group{'s' if len(args.names) != 1 else ''}")
    print()

    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")

    # ── Compare mode ──────────────────────────────────────────────────────────
    if args.compare_file:
        group_name = args.names[0]
        if verbose:
            print(f"  Loading input: {args.compare_file}...", flush=True)
        try:
            input_list = load_input_list(args.compare_file)
        except FileNotFoundError:
            print(f"Error: Input file not found: {args.compare_file}")
            sys.exit(1)
        except OSError as e:
            print(f"Error: Could not read input file '{args.compare_file}': {e.strerror}")
            sys.exit(1)
        found, missing = run_compare(group_name, input_list, args.group_type, args.shared, verbose)
        print()

        print_compare(group_name, found, missing)

        report_file = f"check-group-{ts}.csv"
        write_compare_csv(found, missing, report_file)
        print(f"\nReport : {report_file}  ({len(found)} found, {len(missing)} missing)")

        if missing:
            deploy_file = f"check-group-missing-{ts}.csv"
            write_deploy_csv(missing, deploy_file, lib.DEVICE_GROUP)
            print(f"Deploy : {deploy_file}  ({len(missing)} objects)")
        return

    # ── Diff mode ─────────────────────────────────────────────────────────────
    if args.diff_file:
        group_name = args.names[0]
        if verbose:
            print(f"  Loading input: {args.diff_file}...", flush=True)
        try:
            input_list = load_input_list(args.diff_file)
        except FileNotFoundError:
            print(f"Error: Input file not found: {args.diff_file}")
            sys.exit(1)
        except OSError as e:
            print(f"Error: Could not read input file '{args.diff_file}': {e.strerror}")
            sys.exit(1)
        found, missing_from_group, extra_in_group = run_diff(
            group_name, input_list, args.group_type, args.shared, verbose
        )
        print()

        print_diff(group_name, found, missing_from_group, extra_in_group)

        report_file = f"check-group-diff-{ts}.csv"
        write_diff_csv(found, missing_from_group, extra_in_group, report_file)
        print(
            f"\nReport : {report_file}  "
            f"({len(found)} matched, {len(missing_from_group)} missing from group, "
            f"{len(extra_in_group)} extra in group)"
        )

        if missing_from_group:
            deploy_file = f"check-group-missing-{ts}.csv"
            write_deploy_csv(missing_from_group, deploy_file, lib.DEVICE_GROUP)
            print(f"Deploy : {deploy_file}  ({len(missing_from_group)} objects)")
        return

    # ── Normal lookup mode ────────────────────────────────────────────────────
    multi_group = len(args.names) > 1
    all_rows: list[dict] = []
    for i, name in enumerate(args.names):
        if i > 0:
            print()
        if args.expand:
            rows = print_expanded(name, args.group_type, args.shared, verbose)
        else:
            rows = print_flat(name, args.group_type, args.shared, verbose)
        all_rows.extend(rows)

    outfile = f"check-group-{ts}.{args.format}"
    if args.format == "csv":
        write_csv(all_rows, outfile, multi_group)
    else:
        write_txt(all_rows, outfile, multi_group)
    print(f"\nOutput : {outfile}  ({len(all_rows)} rows)")


if __name__ == "__main__":
    main()
