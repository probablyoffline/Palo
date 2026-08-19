#!/usr/bin/env python3
"""
check-group-dns.py — Resolve FQDN members of PAN-OS address groups to IPv4 addresses.

Takes a list of address group names, fetches their full membership (expanding
nested groups), dedupes the resulting hosts across all groups, then resolves
every FQDN to its IPv4 address(es) (a single FQDN may return several A records).
Plain IP/subnet/range/wildcard address objects are passed through unresolved.

Usage:
    python check-group-dns.py --file groups.txt [--shared] [--dg NAME] [-q]

Examples:
    python check-group-dns.py --file groups.txt
    python check-group-dns.py --file groups.csv --shared
    python check-group-dns.py --file groups.txt --dg "DG-Prod"
"""

import argparse
import csv
import datetime
import ipaddress
import os
import socket
import sys

sys.path.insert(0, os.path.dirname(__file__))
import importlib.util

_spec = importlib.util.spec_from_file_location(
    "check_group", os.path.join(os.path.dirname(__file__), "check-group.py")
)
check_group = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check_group)

lib = check_group.lib  # ops_lib, already imported/configured inside check-group.py

VERSION = "1.0.0"


# ── DNS resolution ────────────────────────────────────────────────────────────

def resolve_host_ipv4(hostname: str) -> set[str]:
    """Resolve hostname to all IPv4 addresses via system DNS. Returns empty set on failure."""
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_INET)
        return {r[4][0] for r in results}
    except socket.gaierror:
        return set()


# ── Host classification ───────────────────────────────────────────────────────

def classify(addr_type: str, value: str) -> tuple[str, str]:
    """
    Classify an address-object value into (host_type, host_key).
    host_type: fqdn | ip | subnet | ip-range | ip-wildcard
    """
    if addr_type == "fqdn":
        return "fqdn", value.lower()
    if addr_type == "ip-netmask":
        if "/" not in value or value.endswith("/32"):
            return "ip", value.split("/", 1)[0]
        return "subnet", value
    if addr_type == "ip-range":
        return "ip-range", value
    if addr_type == "ip-wildcard":
        return "ip-wildcard", value
    return "unknown", value


# ── Collect phase ─────────────────────────────────────────────────────────────

def collect_hosts(group_names: list[str], shared: bool, verbose: bool) -> tuple[dict, list[str]]:
    """
    Fetch + expand all requested groups, classify + dedupe members.
    Returns (hosts, missing_groups) where hosts maps
    host_key -> {"type": ..., "raw_value": ..., "groups": set(...)}.
    """
    hosts: dict[str, dict] = {}
    missing: list[str] = []

    for group_name in group_names:
        if verbose:
            print(f"  Resolving group membership: {group_name}...", flush=True)
        rows = check_group.collect_members(group_name, "address", shared, verbose=False)
        if rows is None:
            missing.append(group_name)
            continue
        for row in rows:
            if not row["value"]:
                continue
            host_type, host_key = classify(row["addr_type"], row["value"])
            entry = hosts.setdefault(
                host_key, {"type": host_type, "raw_value": row["value"], "groups": set()}
            )
            entry["groups"].add(group_name)

    return hosts, missing


# ── Resolve phase ─────────────────────────────────────────────────────────────

def resolve_hosts(hosts: dict, verbose: bool) -> tuple[list[dict], list[str]]:
    """
    Resolve fqdn hosts to IPv4; pass through everything else.
    Returns (rows, failed_fqdns) where rows are ready for CSV output.
    """
    rows: list[dict] = []
    failed: list[str] = []

    for host_key in sorted(hosts):
        entry = hosts[host_key]
        groups_str = ";".join(sorted(entry["groups"]))

        if entry["type"] == "fqdn":
            if verbose:
                print(f"  Resolving {host_key}...", flush=True)
            ips = resolve_host_ipv4(host_key)
            if not ips:
                failed.append(host_key)
                rows.append({
                    "host": host_key, "host_type": "fqdn", "ip_address": "",
                    "groups": groups_str, "note": "resolution failed",
                })
            else:
                for ip in sorted(ips, key=lambda x: ipaddress.ip_address(x)):
                    rows.append({
                        "host": host_key, "host_type": "fqdn", "ip_address": ip,
                        "groups": groups_str, "note": "",
                    })
        else:
            rows.append({
                "host": host_key, "host_type": entry["type"], "ip_address": entry["raw_value"],
                "groups": groups_str, "note": "",
            })

    return rows, failed


# ── Output ─────────────────────────────────────────────────────────────────────

def write_csv(rows: list[dict], filepath: str) -> None:
    fieldnames = ["host", "host_type", "ip_address", "groups", "note"]
    with open(filepath, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Resolve FQDN members of PAN-OS address groups to IPv4 addresses.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--file", metavar="FILE", dest="group_file", required=True,
        help="TXT or CSV file listing address group names, one per line",
    )
    parser.add_argument("--shared", action="store_true",
                        help="Look in /config/shared instead of the configured vsys/device-group")
    parser.add_argument(
        "--device-group", "--dg", metavar="NAME", dest="device_group",
        help="Override device group and force Panorama mode",
    )
    parser.add_argument(
        "--quiet", "-q", action="store_true",
        help="Suppress progress output (only show final results)",
    )
    args = parser.parse_args()
    verbose = not args.quiet

    if args.device_group:
        lib.DEVICE_GROUP = args.device_group
        lib.MODE = "panorama"

    try:
        group_names = check_group.load_input_list(args.group_file)
    except FileNotFoundError:
        print(f"Error: Input file not found: {args.group_file}")
        sys.exit(1)
    except OSError as e:
        print(f"Error: Could not read input file '{args.group_file}': {e.strerror}")
        sys.exit(1)

    if not group_names:
        print(f"Error: No group names found in {args.group_file}")
        sys.exit(1)

    print(f"Target : {lib.TARGET_HOST}  [{lib.mode_summary()}]  v{VERSION}")
    print(f"Groups : {len(group_names)} requested")
    print()

    hosts, missing = collect_hosts(group_names, args.shared, verbose)

    if missing:
        print(f"Warning: {len(missing)} group(s) not found: {', '.join(missing)}")

    fqdn_count = sum(1 for h in hosts.values() if h["type"] == "fqdn")
    other_count = len(hosts) - fqdn_count
    print(f"\nUnique hosts: {len(hosts)}  ({fqdn_count} fqdn, {other_count} ip/other)")
    print()

    rows, failed = resolve_hosts(hosts, verbose)

    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    outfile = os.path.join(os.path.dirname(__file__), f"check-group-dns-{ts}.csv")
    write_csv(rows, outfile)

    print(f"\nOutput : {outfile}  ({len(rows)} rows)")
    if failed:
        print(f"\nFailed to resolve ({len(failed)}):")
        for host in failed:
            print(f"  {host}")


if __name__ == "__main__":
    main()
