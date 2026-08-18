#!/usr/bin/env python3
"""
generate_filter.py

Converts a list of IP addresses/networks into a search filter expression for
either PAN-OS / Panorama monitor-tab traffic logs or Google SecOps (Chronicle)
UDM search.

PAN-OS example (-t panos):
    ( ( addr.src in '1.2.3.4' ) or ( addr.src in '5.6.7.8' ) )

Google SecOps example (-t secops):
    principal.ip = "1.2.3.4" OR principal.ip = "5.6.7.8"

The expression is printed to stdout and also saved to a timestamped file under
output/.

Usage:
    python3 generate_filter.py -i ips.txt -f src -t panos
    python3 generate_filter.py -i ips.txt -f dst -t panos
    python3 generate_filter.py -i ips.txt -f both -t secops

Input file format:
    One IP or CIDR per line. Blank lines and lines starting with '#' are
    ignored. Duplicate entries are collapsed (order preserved).
"""

import argparse
import ipaddress
import sys
from datetime import datetime
from pathlib import Path

VERSION = "1.2.0"


def load_ips(path: Path) -> list[str]:
    """Read one IP/CIDR per line, skip comments/blanks, dedupe, validate."""
    if not path.is_file():
        print(f"ERROR: input file not found: {path}", file=sys.stderr)
        sys.exit(1)

    seen = set()
    ips = []
    for lineno, raw_line in enumerate(path.read_text().splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        try:
            ipaddress.ip_network(line, strict=False)
        except ValueError:
            print(f"WARNING: line {lineno}: invalid IP/CIDR '{line}', skipping", file=sys.stderr)
            continue

        if line in seen:
            continue
        seen.add(line)
        ips.append(line)

    if not ips:
        print("ERROR: no valid IPs found in input file", file=sys.stderr)
        sys.exit(1)

    return ips


def build_panos_filter(ips: list[str], field: str) -> str:
    """Build the outer-parenthesized, OR-joined monitor-tab filter expression."""
    if field == "src":
        template = "( addr.src in '{}' )"
    elif field == "dst":
        template = "( addr.dst in '{}' )"
    else:  # both
        template = "( addr in '{}' )"

    return "( " + " or ".join(template.format(ip) for ip in ips) + " )"


def build_secops_filter(ips: list[str], field: str) -> str:
    """Build the OR-chained Google SecOps (Chronicle) UDM search expression."""
    if field == "src":
        template = 'principal.ip = "{}"'
    elif field == "dst":
        template = 'target.ip = "{}"'
    else:  # both
        template = 'ip = "{}"'

    return " OR ".join(template.format(ip) for ip in ips)


def build_filter(ips: list[str], field: str, target: str) -> str:
    """Dispatch to the format builder for the requested target system."""
    if target == "secops":
        return build_secops_filter(ips, field)
    return build_panos_filter(ips, field)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate a search filter expression from a list of IPs (PAN-OS/Panorama or Google SecOps)."
    )
    parser.add_argument("-i", "--input", required=True, type=Path, help="Path to text file, one IP/CIDR per line")
    parser.add_argument(
        "-f", "--field", required=True, choices=["src", "dst", "both"], help="Address field to filter on"
    )
    parser.add_argument(
        "-t",
        "--target",
        default="panos",
        choices=["panos", "secops"],
        help="Output format: panos (PAN-OS/Panorama monitor-tab) or secops (Google SecOps UDM search). Default: panos",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    args = parser.parse_args()

    print(f"generate-filter.py v{VERSION}", file=sys.stderr)

    ips = load_ips(args.input)
    expression = build_filter(ips, args.field, args.target)

    print(expression)

    output_dir = Path(__file__).parent / "output"
    output_dir.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    prefix = "filter" if args.target == "panos" else "secops"
    output_path = output_dir / f"{prefix}_{args.field}_{timestamp}.txt"
    output_path.write_text(expression + "\n")

    print(f"\nSaved to: {output_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
