"""
design-rule-apps.py — Generate App-ID rule designs from get-rule-apps.py CSV output

Reads a CSV produced by get-rule-apps.py, fetches full rule config from Panorama,
and outputs:
  - A .txt file: formatted text designs for documentation and approval
  - A .csv file: structured data for future scripted implementation

Config files (auto-read from the same directory as this script):
  standard-ports.txt  — one port per line (e.g. tcp-80, tcp-443).
                        If all explicit ports in a rule are on this list, the new
                        rule uses application-default.  If the file is absent, all
                        explicit port lists are treated as non-standard.
  risky-apps.txt      — one app name per line.  Matching apps add the risky-app tag.

Usage:
    python design-rule-apps.py <input_csv> [options]

Options:
    --device-group NAME / --dg NAME   Override device group (Panorama mode only)
    --output PATH / -o PATH           Output file stem (auto-named in Output/ if omitted)
    --standard-ports FILE             Override the default standard-ports.txt path
    --risky-apps FILE                 Override the default risky-apps.txt path
    --no-csv                          Skip the structured CSV output, text only

Design logic:
  - Rules with apps observed → new APP-ID-<name> rule design above old rule
  - Rules with no traffic (skipped) or no apps found → tag update only
  - unknown-tcp / unknown-udp → excluded from app list, app-id-unknown tag added
  - incomplete / not-applicable → excluded silently
  - Risky apps → risky-app tag added
  - Non-standard ports → ports listed explicitly, app-id-non-standard tag added
  - All new rules get: app-id-new-rule
  - Old rules with new rules get: app-id-under-review
  - Old rules with no traffic get: app-id-review-unused
"""

import argparse
import csv
import datetime
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "libs"))
import ops_lib  # noqa: E402

requests.packages.urllib3.disable_warnings()

# ── Constants ─────────────────────────────────────────────────────────────────

SCRIPT_DIR = Path(__file__).resolve().parent

STANDARD_PORTS_FILE = SCRIPT_DIR / "standard-ports.txt"
RISKY_APPS_FILE     = SCRIPT_DIR / "risky-apps.txt"

DEFAULT_RISKY_APPS = frozenset({"ssh", "ms-rdp", "telnet", "ftp", "tftp"})

NON_APP_VALUES     = frozenset({"incomplete", "not-applicable"})
UNKNOWN_APP_VALUES = frozenset({"unknown-tcp", "unknown-udp"})

TAG_NEW_RULE     = "app-id-new-rule"
TAG_NON_STANDARD = "app-id-non-standard"
TAG_UNKNOWN      = "app-id-unknown"
TAG_RISKY        = "risky-app"
TAG_UNDER_REVIEW = "app-id-under-review"
TAG_UNUSED       = "app-id-review-unused"

DESIGN_CSV_FIELDNAMES = [
    "type", "device_group", "rule_name", "clone_above",
    "description", "tags",
    "source_zones", "source_addresses", "source_user",
    "dest_zones", "dest_addresses",
    "applications", "service", "action", "group_profile",
    "tags_to_add",
]

# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class RuleConfig:
    name:          str
    source_zones:  list[str] = field(default_factory=list)
    dest_zones:    list[str] = field(default_factory=list)
    source_addrs:  list[str] = field(default_factory=list)
    dest_addrs:    list[str] = field(default_factory=list)
    source_users:  list[str] = field(default_factory=list)
    existing_tags: list[str] = field(default_factory=list)
    description:   str       = ""
    action:        str       = "allow"
    group_profile: str       = ""
    found:         bool      = True


# ── Config file loaders ───────────────────────────────────────────────────────

def load_set_from_file(
    path: Path,
    default: frozenset[str] | None,
    label: str,
) -> set[str]:
    """Load a set of non-comment lines from a text file, lowercased."""
    if not path.exists():
        if default is not None:
            print(f"  Note: {label} not found ({path.name}) — using built-in defaults")
            return set(default)
        print(f"  Warning: {label} not found ({path.name}) — treating all explicit ports as non-standard")
        return set()
    result: set[str] = set()
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            s = line.strip()
            if s and not s.startswith("#"):
                result.add(s.lower())
    print(f"  Loaded {len(result)} entries from {path.name}")
    return result


# ── API helpers ───────────────────────────────────────────────────────────────

def fetch_full_rule_configs(rule_names: list[str]) -> dict[str, RuleConfig]:
    """
    Fetch the full config for each named rule from Panorama/VSYS in one API call.
    Returns a dict keyed by rule name. Rules not found get RuleConfig(found=False).
    """
    xpath = ops_lib.rules_xpath()
    try:
        xml_text = ops_lib.api_get(xpath)
        root = ET.fromstring(xml_text)
    except Exception as exc:
        print(f"  Warning: could not fetch rule configs: {exc}")
        return {name: RuleConfig(name=name, found=False) for name in rule_names}

    if root.get("status") == "error":
        msg = root.findtext(".//msg") or root.findtext(".//line") or "unknown error"
        print(f"  Warning: config API returned error: {msg}")
        return {name: RuleConfig(name=name, found=False) for name in rule_names}

    wanted = set(rule_names)
    configs: dict[str, RuleConfig] = {}

    for entry in root.iter("entry"):
        name = entry.get("name", "")
        if name not in wanted:
            continue

        def members(tag: str, _entry: ET.Element = entry) -> list[str]:
            el = _entry.find(tag)
            return [m.text for m in el.findall("member") if m.text] if el is not None else []

        group_profile = ""
        ps = entry.find("profile-setting")
        if ps is not None:
            grp = ps.find("group")
            if grp is not None:
                m = grp.find("member")
                if m is not None and m.text:
                    group_profile = m.text

        configs[name] = RuleConfig(
            name          = name,
            source_zones  = members("from"),
            dest_zones    = members("to"),
            source_addrs  = members("source"),
            dest_addrs    = members("destination"),
            source_users  = members("source-user"),
            existing_tags = members("tag"),
            description   = (entry.findtext("description") or "").strip(),
            action        = (entry.findtext("action") or "allow").strip(),
            group_profile = group_profile,
            found         = True,
        )

    for name in rule_names:
        if name not in configs:
            configs[name] = RuleConfig(name=name, found=False)

    return configs


# ── Port helpers ──────────────────────────────────────────────────────────────

def determine_port_setting(
    ports_raw: str,
    standard_ports: set[str],
) -> tuple[str, bool]:
    """
    Returns (service_string, is_non_standard).

    If all explicit ports are in standard_ports → ("application-default", False).
    Otherwise → (pipe-separated port list, True).
    """
    if not ports_raw:
        return "application-default", False

    ports = [p.strip() for p in ports_raw.split("|") if p.strip()]
    if not ports or ports == ["application-default"]:
        return "application-default", False

    if standard_ports and all(p.lower() in standard_ports for p in ports):
        return "application-default", False

    return " | ".join(ports), True


# ── App classification ────────────────────────────────────────────────────────

def classify_apps(
    apps_raw: str,
    risky_apps: set[str],
) -> tuple[list[str], bool, bool]:
    """
    Returns (usable_apps, has_unknown, has_risky).

    usable_apps: app names suitable for an app-id rule (excludes incomplete/not-applicable/unknown)
    has_unknown: True if unknown-tcp or unknown-udp was observed
    has_risky:   True if any risky app was observed
    """
    if not apps_raw:
        return [], False, False

    usable: list[str] = []
    has_unknown = False
    has_risky   = False

    for app in (a.strip() for a in apps_raw.split("|") if a.strip()):
        app_lower = app.lower()
        if app_lower in UNKNOWN_APP_VALUES:
            has_unknown = True
        elif app_lower in NON_APP_VALUES:
            pass
        else:
            usable.append(app)
            if app_lower in risky_apps:
                has_risky = True

    return usable, has_unknown, has_risky


# ── Design formatters ─────────────────────────────────────────────────────────

def _csv_list(items: list[str]) -> str:
    return ", ".join(items) if items else "(none)"


def format_new_rule_design(
    design_number:  int,
    rule_name:      str,
    config:         RuleConfig,
    usable_apps:    list[str],
    has_unknown:    bool,
    service:        str,
    new_rule_tags:  list[str],
    device_group:   str,
    run_month_year: str,
) -> str:
    lines = [f"Design {design_number}", ""]

    if not config.found:
        lines.append(f"[Warning: rule '{rule_name}' was not found in config — some fields below are empty]")
        lines.append("")

    lines += [
        f"In {device_group}",
        f"Clone Rule ABOVE: {rule_name}",
        f"New Rule Name: APP-ID-{rule_name}",
        "Description:",
    ]
    if config.description:
        lines.append(f"  {config.description}")
    lines.append(f"  DDD created {run_month_year}")

    lines.append(f"Tags: {_csv_list(new_rule_tags)}")
    lines.append("")
    lines.append(f"Source Zone: {_csv_list(config.source_zones)}")
    lines.append(f"Source Address: {_csv_list(config.source_addrs)}")

    non_any_users = [u for u in config.source_users if u.lower() != "any"]
    if non_any_users:
        lines.append(f"Source User: {_csv_list(non_any_users)}")

    lines += [
        "",
        f"Dest Zone: {_csv_list(config.dest_zones)}",
        f"Dest Address: {_csv_list(config.dest_addrs)}",
        "",
    ]

    app_display = " | ".join(usable_apps) if usable_apps else "(none — review required)"
    lines.append(f"Application: {app_display}")
    if has_unknown:
        lines.append(
            "  [Note: unknown-tcp/unknown-udp traffic was observed — these cannot be added as"
            " app-id and require further investigation before the old rule can be retired]"
        )

    lines += [
        f"Port: {service}",
        f"Action: {config.action}",
        f"Group profile: {config.group_profile or '(none)'}",
        "",
        f"Old Rule Update — {rule_name}",
        f"  Add Tag: {TAG_UNDER_REVIEW}",
    ]

    return "\n".join(lines)


def format_unused_design(design_number: int, rule_name: str) -> str:
    return "\n".join([
        f"Design {design_number}",
        "",
        f"Old Rule Update — {rule_name}",
        f"  Add Tag: {TAG_UNUSED}",
    ])


# ── CSV row builders ──────────────────────────────────────────────────────────

def build_new_rule_row(
    rule_name:      str,
    config:         RuleConfig,
    usable_apps:    list[str],
    service:        str,
    new_rule_tags:  list[str],
    device_group:   str,
    run_month_year: str,
) -> dict:
    desc_lines = []
    if config.description:
        desc_lines.append(config.description)
    desc_lines.append(f"DDD created {run_month_year}")

    non_any_users = [u for u in config.source_users if u.lower() != "any"]

    return {
        "type":             "new_rule",
        "device_group":     device_group,
        "rule_name":        f"APP-ID-{rule_name}",
        "clone_above":      rule_name,
        "description":      "\n".join(desc_lines),
        "tags":             "|".join(new_rule_tags),
        "source_zones":     "|".join(config.source_zones),
        "source_addresses": "|".join(config.source_addrs),
        "source_user":      "|".join(non_any_users),
        "dest_zones":       "|".join(config.dest_zones),
        "dest_addresses":   "|".join(config.dest_addrs),
        "applications":     "|".join(usable_apps),
        "service":          service,
        "action":           config.action,
        "group_profile":    config.group_profile,
        "tags_to_add":      "",
    }


def build_tag_update_row(rule_name: str, tag: str, device_group: str) -> dict:
    return {
        "type":             "tag_update",
        "device_group":     device_group,
        "rule_name":        rule_name,
        "clone_above":      "",
        "description":      "",
        "tags":             "",
        "source_zones":     "",
        "source_addresses": "",
        "source_user":      "",
        "dest_zones":       "",
        "dest_addresses":   "",
        "applications":     "",
        "service":          "",
        "action":           "",
        "group_profile":    "",
        "tags_to_add":      tag,
    }


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate App-ID rule designs from get-rule-apps.py CSV output."
    )
    parser.add_argument("input_csv", help="CSV file produced by get-rule-apps.py")
    parser.add_argument(
        "--device-group", "--dg", metavar="NAME", dest="device_group",
        help="Override device group for rule config lookups (Panorama mode only)",
    )
    parser.add_argument(
        "--output", "-o", metavar="PATH",
        help="Output file stem (.txt and .csv appended); default: Output/rule-design-<stem>-TIMESTAMP",
    )
    parser.add_argument(
        "--standard-ports", metavar="FILE", dest="standard_ports_file",
        help=f"Standard ports file (default: {STANDARD_PORTS_FILE.name} in script directory)",
    )
    parser.add_argument(
        "--risky-apps", metavar="FILE", dest="risky_apps_file",
        help=f"Risky apps file (default: {RISKY_APPS_FILE.name} in script directory)",
    )
    parser.add_argument(
        "--no-csv", action="store_true",
        help="Skip the structured CSV output; generate text design file only",
    )
    args = parser.parse_args()

    if args.device_group:
        ops_lib.DEVICE_GROUP = args.device_group
        ops_lib.MODE = "panorama"

    run_dt         = datetime.datetime.now()
    run_month_year = run_dt.strftime("%B %Y")
    timestamp      = run_dt.strftime("%Y%m%d-%H%M%S")
    input_stem     = Path(args.input_csv).stem
    output_stem    = args.output or f"Output/rule-design-{input_stem}-{timestamp}"
    Path(output_stem).parent.mkdir(parents=True, exist_ok=True)

    txt_path = f"{output_stem}.txt"
    csv_path = f"{output_stem}.csv"

    print("=" * 62)
    print("  design-rule-apps")
    print("=" * 62)
    print(f"  Input       : {args.input_csv}")
    print(f"  Target      : {ops_lib.TARGET_HOST}  ({ops_lib.mode_summary()})")
    print(f"  Output .txt : {txt_path}")
    if not args.no_csv:
        print(f"  Output .csv : {csv_path}")
    print()

    sp_path = Path(args.standard_ports_file) if args.standard_ports_file else STANDARD_PORTS_FILE
    ra_path = Path(args.risky_apps_file)      if args.risky_apps_file      else RISKY_APPS_FILE
    standard_ports = load_set_from_file(sp_path, default=None,             label="standard-ports")
    risky_apps     = load_set_from_file(ra_path, default=DEFAULT_RISKY_APPS, label="risky-apps")
    print()

    try:
        with open(args.input_csv, newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
    except FileNotFoundError:
        print(f"Error: input file not found: {args.input_csv}", file=sys.stderr)
        sys.exit(1)

    if not rows:
        print("No rows found in input CSV.", file=sys.stderr)
        sys.exit(1)

    rule_names = [r["rule"] for r in rows if r.get("rule")]

    print(f"  Fetching rule configs for {len(rule_names)} rules ...", end=" ", flush=True)
    configs = fetch_full_rule_configs(rule_names)
    found   = sum(1 for c in configs.values() if c.found)
    print(f"{found}/{len(rule_names)} found")
    print()

    device_group   = ops_lib.DEVICE_GROUP
    designs: list[str] = []
    csv_rows: list[dict] = []
    design_count = 0
    new_rule_count = 0
    unused_count   = 0

    for row in rows:
        rule_name = row.get("rule", "").strip()
        if not rule_name:
            continue

        complete = row.get("complete", "").strip().lower()
        apps_raw = row.get("apps", "").strip()
        ports_raw = row.get("ports", "").strip()
        config   = configs[rule_name]

        usable_apps, has_unknown, has_risky = classify_apps(apps_raw, risky_apps)

        has_no_apps = not usable_apps and not has_unknown

        if complete == "no" and has_no_apps:
            # Query incomplete and no apps found — can't generate a design; needs re-run.
            print(f"  Skipping {rule_name} — query was incomplete (complete=no) and no apps were found.")
            print(f"    Re-run get-rule-apps.py with --resume to retry this rule.")
            continue

        # Skipped (no traffic) or queried with no identifiable apps → tag-update only
        if complete == "skipped" or has_no_apps:
            design_count += 1
            unused_count += 1
            designs.append(format_unused_design(design_count, rule_name))
            if not args.no_csv:
                csv_rows.append(build_tag_update_row(rule_name, TAG_UNUSED, device_group))
            continue

        service, is_non_standard = determine_port_setting(ports_raw, standard_ports)

        # Build new rule tag list: existing tags first, then new ones
        new_rule_tags: list[str] = list(config.existing_tags)
        new_rule_tags.append(TAG_NEW_RULE)
        if is_non_standard:
            new_rule_tags.append(TAG_NON_STANDARD)
        if has_unknown:
            new_rule_tags.append(TAG_UNKNOWN)
        if has_risky:
            new_rule_tags.append(TAG_RISKY)

        design_count += 1
        new_rule_count += 1
        designs.append(format_new_rule_design(
            design_number  = design_count,
            rule_name      = rule_name,
            config         = config,
            usable_apps    = usable_apps,
            has_unknown    = has_unknown,
            service        = service,
            new_rule_tags  = new_rule_tags,
            device_group   = device_group,
            run_month_year = run_month_year,
        ))

        if not args.no_csv:
            csv_rows.append(build_new_rule_row(
                rule_name      = rule_name,
                config         = config,
                usable_apps    = usable_apps,
                service        = service,
                new_rule_tags  = new_rule_tags,
                device_group   = device_group,
                run_month_year = run_month_year,
            ))
            csv_rows.append(build_tag_update_row(rule_name, TAG_UNDER_REVIEW, device_group))

    text_output = "\n\n---\n\n".join(designs)
    with open(txt_path, "w", encoding="utf-8") as fh:
        fh.write(text_output + "\n")

    if not args.no_csv and csv_rows:
        with open(csv_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=DESIGN_CSV_FIELDNAMES)
            writer.writeheader()
            writer.writerows(csv_rows)

    print("=" * 62)
    print(f"  {design_count} design(s) total")
    print(f"  {new_rule_count} new rule design(s)  |  {unused_count} tag-update-only (no traffic)")
    print(f"  Text : {txt_path}")
    if not args.no_csv:
        print(f"  CSV  : {csv_path}")
    print("=" * 62)


if __name__ == "__main__":
    main()
