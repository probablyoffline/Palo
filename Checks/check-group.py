#!/usr/bin/env python3
"""
check-group.py — Look up members of PAN-OS group objects by name.

Usage:
    python check-group.py GROUP [GROUP ...] [--type address|service|application] [--expand] [--shared]

Examples:
    python check-group.py "RFC-1918"
    python check-group.py "My-Servers" "My-DMZ" "My-Guests"
    python check-group.py "My-Servers" --expand
    python check-group.py "Web-Ports" --type service
    python check-group.py "Office-Apps" --type application
    python check-group.py "RFC-1918" --shared
    python check-group.py "My-Group" --dg "DG-Prod"
"""

import argparse
import os
import sys
import xml.etree.ElementTree as ET

# ops_lib.py lives in the parent directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import ops_lib as lib  # noqa: E402

VERSION = "1.0.0"

# ── XPath helpers ─────────────────────────────────────────────────────────────

_GROUP_SUFFIX = {
    "address":     "address-group",
    "service":     "service-group",
    "application": "application-group",
}


def _group_xpath(name: str, group_type: str, shared: bool) -> str:
    if shared or lib.MODE == "panorama":
        base = "/config/shared"
    else:
        base = lib._config_base()
    return f"{base}/{_GROUP_SUFFIX[group_type]}/entry[@name='{name}']"


def _address_xpath(name: str, shared: bool) -> str:
    if shared or lib.MODE == "panorama":
        return f"/config/shared/address/entry[@name='{name}']"
    return lib.address_xpath(name)


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
            # Nested group — print its name as a sub-header then recurse
            yield (depth, member, True, None)
            yield from _expand(member, group_type, shared, depth + 1, seen | {name})
        else:
            # Leaf member
            annotation = None
            if group_type == "address":
                annotation = resolve_address_object(member, shared)
            yield (depth, member, False, annotation)


# ── Output ────────────────────────────────────────────────────────────────────

def print_flat(group_name: str, group_type: str, shared: bool) -> None:
    members = get_group_members(group_name, group_type, shared)
    label = group_type.capitalize() + " Group"
    print(f"{label}: {group_name}")
    if members is None:
        print("  [not found]")
    elif not members:
        print("  [empty group]")
    else:
        for m in members:
            print(f"  {m}")


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
            print(f"{indent}{name}  ({annotation})")
        else:
            print(f"{indent}{name}")


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
                        help="Recursively expand nested groups and resolve address objects")
    parser.add_argument("--shared", action="store_true",
                        help="Look in /config/shared instead of the configured vsys/device-group")
    parser.add_argument(
        "--device-group", "--dg", metavar="NAME", dest="device_group",
        help="Override device group and force Panorama mode",
    )
    args = parser.parse_args()

    if args.device_group:
        lib.DEVICE_GROUP = args.device_group
        lib.MODE = "panorama"

    print(f"Target : {lib.TARGET_HOST}  [{lib.mode_summary()}]  v{VERSION}")
    print(f"Type   : {args.group_type} group{'s' if len(args.names) != 1 else ''}")
    print()

    for i, name in enumerate(args.names):
        if i > 0:
            print()
        if args.expand:
            print_expanded(name, args.group_type, args.shared)
        else:
            print_flat(name, args.group_type, args.shared)


if __name__ == "__main__":
    main()
