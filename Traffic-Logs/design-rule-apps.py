"""
design-rule-apps.py — Generate App-ID rule designs from get-rule-apps.py CSV output

Reads a CSV produced by get-rule-apps.py, fetches full rule config from Panorama,
and outputs:
  - A .txt file: formatted text designs for documentation and approval
  - A .csv file: structured data for future scripted implementation
  - A -pci.csv file (when flags-pci.txt is present): PCI-scoped designs only

Port standard determination (default — dynamic mode):
  For each rule, the script queries Panorama's app-id database to get the official
  standard port(s) for every observed application.  A rule's existing service config
  is compared against the union of those standard ports:
    - If all current ports are standard for the observed apps → new rule uses
      application-default, no app-id-non-standard tag.
    - If any port is not standard for any of the observed apps → new rule lists
      all ports explicitly, separate APP-ID-<name>-NONSTANDARD rule generated.
  This reflects Palo Alto's own definition of what is standard — not a static list.

  Use --static-ports to disable dynamic lookup and fall back to standard-ports.txt.
  Dynamic lookup also falls back to standard-ports.txt automatically if the API
  call fails.

PCI rule splitting:
  When flags-pci.txt is present, any rule whose existing Panorama tags include one
  of the listed tag names is treated as a PCI rule.  PCI rules are separated into
  their own numbered sequence (PCI-1, PCI-2, …) and their own sections in the .txt
  file (PCI — NEW RULES / PCI — RULE UPDATES).  Their CSV rows are written to a
  separate -pci.csv file.  If flags-pci.txt is absent, PCI splitting is silently
  disabled and the script behaves exactly as before.

Config files (auto-read from the same directory as this script):
  risky-apps.txt      — one app name per line.  Matching apps add the risky-app tag.
  standard-ports.txt  — fallback used when --static-ports is set or API is unavailable.
  flags-pci.txt       — one Panorama tag name per line.  Rules tagged with any of
                        these are separated into the PCI output stream.

Usage:
    python design-rule-apps.py <input_csv> [<input_csv> ...] [options]

    Multiple CSVs are accepted; app lists are unioned per rule across all files.
    Use this when accumulating several get-rule-apps.py runs before implementing,
    or to catch up on missed intermediate updates in one design pass.

Options:
    --device-group NAME / --dg NAME   Override device group (Panorama mode only)
    --output PATH / -o PATH           Output file stem (auto-named in Output/ if omitted)
    --static-ports                    Skip dynamic app-id lookup; use standard-ports.txt
    --standard-ports FILE             Override the default standard-ports.txt path
    --risky-apps FILE                 Override the default risky-apps.txt path
    --pci-flags FILE                  Override the default flags-pci.txt path
    --no-csv                          Skip the structured CSV output, text only
    --update-existing                 Generate app_update designs for rules where
                                      APP-ID-<name> already exists (adds new apps)
    --app-review-threshold N          Flag designs with ≥ N apps for manual review
                                      (default: 10)

Output .txt sections (in order):
    SUMMARY          — counters, file paths, PCI breakdown (if applicable)
    NOTES            — per-design warnings (inferred apps, dropped ports, etc.)
    NEW RULES        — APP-ID-*, APP-ID-*-UNKNOWN, APP-ID-*-NONSTANDARD creations
    RULE UPDATES     — tag additions to existing rules (app-id-under-review, etc.)
    PCI — NEW RULES  — same as NEW RULES, PCI-scoped rules only (if applicable)
    PCI — RULE UPDATES — same as RULE UPDATES, PCI-scoped rules only (if applicable)

Design logic:
  - Rules with apps observed → new APP-ID-<name> rule design above old rule
  - Rules with no traffic (skipped) or no apps found → tag update only
  - unknown-tcp / unknown-udp → excluded from app list, separate UNKNOWN rule
  - incomplete / not-applicable → excluded silently
  - Risky apps → risky-app tag added
  - Non-standard port traffic → separate APP-ID-<name>-NONSTANDARD rule
  - Apps inferred from observed/configured ports (≤3 apps claim that port)
  - All new rules get: app-id-new-rule
  - Old rules with new rules get: app-id-under-review
  - Old rules with no traffic get: app-id-review-unused
"""

import argparse
import csv
import datetime
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "libs"))
import ops_lib  # noqa: E402

requests.packages.urllib3.disable_warnings()

# ── Constants ─────────────────────────────────────────────────────────────────

__version__ = "1.10.1"

APP_REVIEW_THRESHOLD     = 10  # flag designs with this many or more usable apps
PORT_INFERENCE_THRESHOLD = 3   # infer app from port only when ≤ this many apps claim it

SCRIPT_DIR = Path(__file__).resolve().parent

STANDARD_PORTS_FILE = SCRIPT_DIR / "standard-ports.txt"
RISKY_APPS_FILE     = SCRIPT_DIR / "risky-apps.txt"
PCI_FLAGS_FILE      = SCRIPT_DIR / "flags-pci.txt"

DEFAULT_RISKY_APPS = frozenset({"ssh", "ms-rdp", "telnet", "ftp", "tftp"})

NON_APP_VALUES     = frozenset({"incomplete", "not-applicable", "insufficient-data"})
UNKNOWN_APP_VALUES = frozenset({"unknown-tcp", "unknown-udp"})

TAG_NEW_RULE        = "app-id-new-rule"
TAG_NON_STANDARD    = "app-id-non-standard"
TAG_NONSTANDARD_RULE = "app-id-nonstandard-port"
TAG_UNKNOWN         = "app-id-unknown"
TAG_RISKY           = "risky-app"
TAG_UNDER_REVIEW    = "app-id-under-review"
TAG_UNUSED          = "app-id-review-unused"

# Port ranges larger than this are not expanded; ports falling in them are treated
# conservatively as non-standard (avoids huge sets for apps like ftp-data).
MAX_RANGE_EXPAND = 100

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


# ── Config file loader ────────────────────────────────────────────────────────

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


# ── PCI detection ────────────────────────────────────────────────────────────

def is_pci_rule(config: RuleConfig, pci_tags: set[str]) -> bool:
    return bool(pci_tags) and bool({t.lower() for t in config.existing_tags} & pci_tags)


# ── Rule config fetch ─────────────────────────────────────────────────────────

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


# ── App default port lookup ───────────────────────────────────────────────────

def _parse_app_ports_to_set(entry: ET.Element) -> set[str]:
    """
    Extract default ports from a PAN-OS app entry element.
    Converts 'tcp/80' → 'tcp-80'.  Expands ranges up to MAX_RANGE_EXPAND ports;
    wider ranges are skipped (conservative — ports in that range stay non-standard).
    """
    result: set[str] = set()
    default_el = entry.find("default")
    if default_el is None:
        return result
    port_el = default_el.find("port")
    if port_el is None:
        return result

    for member in port_el.findall("member"):
        if not member.text or "/" not in member.text:
            continue
        proto, port_spec = member.text.strip().lower().split("/", 1)
        if "-" in port_spec:
            try:
                start_n, end_n = (int(x) for x in port_spec.split("-", 1))
                if end_n - start_n <= MAX_RANGE_EXPAND:
                    for p in range(start_n, end_n + 1):
                        result.add(f"{proto}-{p}")
            except ValueError:
                pass
        else:
            try:
                int(port_spec)
                result.add(f"{proto}-{port_spec}")
            except ValueError:
                pass

    return result


def fetch_app_default_ports(app_names: list[str]) -> tuple[dict[str, set[str]], bool]:
    """
    Query Panorama/firewall for the official standard ports of each application.

    Checks, in order:
      1. /config/predefined/application  — Palo Alto's built-in app-id database
      2. /config/shared/application      — shared custom apps (Panorama only)
      3. DG or vsys custom apps          — org-defined apps

    Returns (port_map, api_available):
      port_map:       {app_name: set of 'tcp-80' style strings}
                      Empty set means the app has no defined default ports (e.g. ident-by-ip).
      api_available:  True if at least one API source responded successfully.
    """
    wanted = {a for a in app_names
              if a and a not in NON_APP_VALUES and a not in UNKNOWN_APP_VALUES}
    if not wanted:
        return {}, True

    port_map: dict[str, set[str]] = {name: set() for name in wanted}
    api_available = False

    # Build a single XPath filter for all needed apps (one API call per source)
    if len(wanted) == 1:
        app_filter = f"@name='{next(iter(wanted))}'"
    else:
        app_filter = " or ".join(f"@name='{a}'" for a in sorted(wanted))

    # Sources to query in order; last writer wins (custom apps can override predefined)
    sources: list[str] = [f"/config/predefined/application/entry[{app_filter}]"]
    if ops_lib.MODE == "panorama":
        sources.append(f"/config/shared/application/entry[{app_filter}]")
        sources.append(
            f"/config/devices/entry[@name='localhost.localdomain']"
            f"/device-group/entry[@name='{ops_lib.DEVICE_GROUP}']"
            f"/application/entry[{app_filter}]"
        )
    else:
        sources.append(
            f"/config/devices/entry[@name='localhost.localdomain']"
            f"/vsys/entry[@name='{ops_lib.VSYS}']/application/entry[{app_filter}]"
        )

    for xpath in sources:
        try:
            xml_text = ops_lib.api_get(xpath)
            root = ET.fromstring(xml_text)
        except Exception:
            continue

        if root.get("status") == "error":
            continue

        api_available = True
        for entry in root.iter("entry"):
            name = entry.get("name", "")
            if name in wanted:
                ports = _parse_app_ports_to_set(entry)
                port_map[name] |= ports

    return port_map, api_available


def fetch_all_predefined_ports() -> dict[str, set[str]]:
    """
    Fetch the official default ports for ALL known applications without filtering.
    Used to build the reverse port→app map for app inference.
    Returns {app_name: set[port_strings]}.  Empty dict on failure.
    """
    port_map: dict[str, set[str]] = {}

    sources: list[str] = ["/config/predefined/application"]
    if ops_lib.MODE == "panorama":
        sources.append("/config/shared/application")
        sources.append(
            f"/config/devices/entry[@name='localhost.localdomain']"
            f"/device-group/entry[@name='{ops_lib.DEVICE_GROUP}']/application"
        )
    else:
        sources.append(
            f"/config/devices/entry[@name='localhost.localdomain']"
            f"/vsys/entry[@name='{ops_lib.VSYS}']/application"
        )

    for xpath in sources:
        try:
            xml_text = ops_lib.api_get(xpath)
            root = ET.fromstring(xml_text)
        except Exception:
            continue
        if root.get("status") == "error":
            continue
        for entry in root.iter("entry"):
            name = entry.get("name", "")
            if not name:
                continue
            ports = _parse_app_ports_to_set(entry)
            if name in port_map:
                port_map[name] |= ports
            else:
                port_map[name] = ports

    return port_map


# ── App inference helpers ─────────────────────────────────────────────────────

def infer_apps_from_ports(
    ports: set[str],
    port_app_map: dict[str, set[str]],
    already_known: set[str],
    threshold: int,
) -> list[str]:
    """
    For each port, look up which apps claim it as a standard port.
    If ≤ threshold apps claim it, add any not already in already_known.
    Returns sorted list of newly-inferred app names.
    """
    inferred: list[str] = []
    for port in sorted(ports):
        candidates = port_app_map.get(port.lower(), set())
        if len(candidates) <= threshold:
            for app in sorted(candidates):
                if (app not in already_known
                        and app not in NON_APP_VALUES
                        and app not in UNKNOWN_APP_VALUES
                        and app not in inferred):
                    inferred.append(app)
    return inferred


def parse_app_port_details(raw: str) -> dict[str, set[str]]:
    """
    Parse the app_port_details CSV column ('ssl:tcp-443|mssql:tcp-1433' format).
    Returns {app: set[port_strings]}.
    """
    result: dict[str, set[str]] = {}
    for pair in raw.split("|"):
        pair = pair.strip()
        if ":" not in pair:
            continue
        app, port = pair.split(":", 1)
        if app and port:
            result.setdefault(app.strip(), set()).add(port.strip().lower())
    return result


# ── Port spec validation ──────────────────────────────────────────────────────

_PORT_SPEC_RE = re.compile(r'^(tcp|udp)-\d+$', re.IGNORECASE)


def _is_raw_port_spec(s: str) -> bool:
    """Return True for bare tcp-N / udp-N specs and the two keyword values."""
    s = s.strip().lower()
    return s in ("application-default", "any") or bool(_PORT_SPEC_RE.match(s))


# ── Port helpers ──────────────────────────────────────────────────────────────

def determine_port_setting(
    ports_raw: str,
    standard_ports: set[str],
) -> tuple[str, bool]:
    """
    Returns (service_string, is_non_standard).

    standard_ports is either:
      - Dynamic mode: the union of Palo Alto's official default ports for all
        observed apps in this rule.
      - Static mode / fallback: the contents of standard-ports.txt.

    If ports_raw contains named service objects or groups → ("application-default", False).
    If all explicit ports are covered by standard_ports → ("application-default", False).
    Otherwise → (pipe-separated port list, True).
    """
    if not ports_raw:
        return "application-default", False

    ports = [p.strip() for p in ports_raw.split("|") if p.strip()]
    if not ports or ports == ["application-default"]:
        return "application-default", False

    if any(not _is_raw_port_spec(p) for p in ports):
        return "application-default", False  # named service object or group

    if standard_ports and all(p.lower() in standard_ports for p in ports):
        return "application-default", False

    return " | ".join(ports), True


# ── App classification ────────────────────────────────────────────────────────

def classify_apps(
    apps_raw: str,
    risky_apps: set[str],
) -> tuple[list[str], list[str], bool]:
    """
    Returns (usable_apps, unknown_apps, has_risky).

    usable_apps:  app names suitable for an app-id rule (excludes incomplete/not-applicable/unknown)
    unknown_apps: observed unknown values, e.g. ['unknown-tcp', 'unknown-udp']
    has_risky:    True if any risky app was observed
    """
    if not apps_raw:
        return [], [], False

    usable:  list[str] = []
    unknown: list[str] = []
    has_risky = False

    for app in (a.strip() for a in apps_raw.split("|") if a.strip()):
        app_lower = app.lower()
        if app_lower in UNKNOWN_APP_VALUES:
            if app_lower not in unknown:
                unknown.append(app_lower)
        elif app_lower in NON_APP_VALUES:
            pass
        else:
            usable.append(app)
            if app_lower in risky_apps:
                has_risky = True

    return usable, unknown, has_risky


# ── Design formatters ─────────────────────────────────────────────────────────

def _csv_list(items: list[str]) -> str:
    return ", ".join(items) if items else "(none)"


def format_new_rule_design(
    design_number:  int | str,
    rule_name:      str,
    config:         RuleConfig,
    usable_apps:    list[str],
    service:        str,
    new_rule_tags:  list[str],
    device_group:   str,
    run_month_year: str,
) -> str:
    lines = [f"Design {design_number}", ""]

    lines += [
        f"In {device_group}",
        f"Clone Rule ABOVE: {rule_name}",
        f"New Rule Name: APP-ID-{rule_name}",
    ]

    lines.append(f"Description: DDD created {run_month_year}")

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

    app_display = ", ".join(usable_apps) if usable_apps else "(none — review required)"
    lines.append(f"Application: {app_display}")

    lines += [
        f"Port: {service.replace(' | ', ', ')}",
        f"Action: {config.action}",
        f"Group profile: {config.group_profile or '(none)'}",
    ]

    return "\n".join(lines)


def format_unknown_rule_design(
    design_number:  int | str,
    rule_name:      str,
    config:         RuleConfig,
    unknown_apps:   list[str],
    ports_raw:      str,
    device_group:   str,
    run_month_year: str,
    has_known_apps: bool,
) -> str:
    new_rule_name = f"APP-ID-{rule_name}-UNKNOWN" if has_known_apps else f"APP-ID-{rule_name}"

    tags = list(config.existing_tags) + [TAG_NEW_RULE, TAG_UNKNOWN]

    ports = [p.strip() for p in ports_raw.split("|") if p.strip()]
    service = ", ".join(ports) if ports and ports != ["application-default"] else "application-default"

    lines = [f"Design {design_number}", ""]
    lines += [
        f"In {device_group}",
        f"Clone Rule ABOVE: {rule_name}",
        f"New Rule Name: {new_rule_name}",
        f"Description: DDD created {run_month_year}",
        f"Tags: {_csv_list(tags)}",
        "",
        f"Source Zone: {_csv_list(config.source_zones)}",
        f"Source Address: {_csv_list(config.source_addrs)}",
    ]

    non_any_users = [u for u in config.source_users if u.lower() != "any"]
    if non_any_users:
        lines.append(f"Source User: {_csv_list(non_any_users)}")

    lines += [
        "",
        f"Dest Zone: {_csv_list(config.dest_zones)}",
        f"Dest Address: {_csv_list(config.dest_addrs)}",
        "",
        f"Application: {', '.join(unknown_apps)}",
        f"Port: {service}",
        f"Action: {config.action}",
        f"Group profile: {config.group_profile or '(none)'}",
    ]

    return "\n".join(lines)


def format_rule_update(
    design_number:  int | str,
    rule_name:      str,
    tag:            str,
    device_group:   str,
    run_month_year: str,
) -> str:
    return "\n".join([
        f"Design {design_number}",
        "",
        f"In {device_group}",
        f"Action: Add tag",
        f"Rule Name: {rule_name}",
        f"Description: DDD updated {run_month_year}",
        f"Tag: {tag}",
    ])


def format_unused_design(
    design_number: int | str,
    rule_name:     str,
    device_group:  str,
    run_month_year: str,
) -> str:
    return "\n".join([
        f"Design {design_number}",
        "",
        f"In {device_group}",
        f"Action: Add tag",
        f"Rule Name: {rule_name}",
        f"Description: DDD updated {run_month_year}",
        f"Tag: {TAG_UNUSED}",
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


def build_app_update_row(
    rule_name:   str,
    apps:        list[str],
    device_group: str,
    rule_suffix: str = "",
) -> dict:
    return {
        "type":             "app_update",
        "device_group":     device_group,
        "rule_name":        f"APP-ID-{rule_name}{rule_suffix}",
        "clone_above":      "",
        "description":      "",
        "tags":             "",
        "source_zones":     "",
        "source_addresses": "",
        "source_user":      "",
        "dest_zones":       "",
        "dest_addresses":   "",
        "applications":     "|".join(apps),
        "service":          "",
        "action":           "",
        "group_profile":    "",
        "tags_to_add":      "",
    }


def format_nonstandard_rule_design(
    design_number:  int | str,
    rule_name:      str,
    config:         RuleConfig,
    nonst_apps:     list[str],
    nonst_ports:    list[str],
    device_group:   str,
    run_month_year: str,
) -> str:
    tags = list(config.existing_tags) + [TAG_NEW_RULE, TAG_NONSTANDARD_RULE]
    service = ", ".join(nonst_ports)

    lines = [f"Design {design_number}", ""]
    lines += [
        f"In {device_group}",
        f"Clone Rule ABOVE: {rule_name}",
        f"New Rule Name: APP-ID-{rule_name}-NONSTANDARD",
        f"Description: DDD created {run_month_year}",
        f"Tags: {_csv_list(tags)}",
        "",
        f"Source Zone: {_csv_list(config.source_zones)}",
        f"Source Address: {_csv_list(config.source_addrs)}",
    ]
    non_any_users = [u for u in config.source_users if u.lower() != "any"]
    if non_any_users:
        lines.append(f"Source User: {_csv_list(non_any_users)}")
    lines += [
        "",
        f"Dest Zone: {_csv_list(config.dest_zones)}",
        f"Dest Address: {_csv_list(config.dest_addrs)}",
        "",
        f"Application: {_csv_list(nonst_apps)}",
        f"Port: {service}",
        f"Action: {config.action}",
        f"Group profile: {config.group_profile or '(none)'}",
    ]
    return "\n".join(lines)


def format_app_update_design(
    design_number: int | str,
    rule_name:     str,
    usable_apps:   list[str],
    device_group:  str,
    rule_suffix:   str = "",
) -> str:
    return "\n".join([
        f"Design {design_number}",
        "",
        f"In {device_group}",
        f"Action: Add applications",
        f"Rule Name: APP-ID-{rule_name}{rule_suffix}",
        f"Applications: {_csv_list(usable_apps)}",
        "Note: additive — existing apps in the rule are preserved",
    ])


# ── CSV merge ─────────────────────────────────────────────────────────────────

def merge_csv_rows(all_rows: list[list[dict]]) -> list[dict]:
    """Union app/port lists per rule across multiple get-rule-apps.py CSVs.

    complete=yes if any run has complete=yes (one clean run clears the flag).
    complete=skipped only if every run reported skipped.
    entries_scanned and windows_queried are summed across runs.
    Rule order follows first appearance across the files.
    """
    merged: dict[str, dict] = {}
    rule_order: list[str] = []

    for rows in all_rows:
        for row in rows:
            rule = row.get("rule", "").strip()
            if not rule:
                continue
            if rule not in merged:
                rule_order.append(rule)
                merged[rule] = {
                    "apps":             set(),
                    "ports":            set(),
                    "app_port_details": set(),  # set of "app:port" pair strings
                    "entries_scanned":  0,
                    "windows_queried":  0,
                    "complete":         "",
                    "data_source":      set(),
                }
            m = merged[rule]

            for app in (row.get("apps", "") or "").split("|"):
                a = app.strip()
                if a:
                    m["apps"].add(a)

            for port in (row.get("ports", "") or "").split("|"):
                p = port.strip()
                if p:
                    m["ports"].add(p)

            for pair in (row.get("app_port_details", "") or "").split("|"):
                p = pair.strip()
                if p and ":" in p:
                    m["app_port_details"].add(p)

            complete = (row.get("complete", "") or "").strip().lower()
            if complete == "yes":
                m["complete"] = "yes"
            elif complete == "no" and m["complete"] != "yes":
                m["complete"] = "no"
            elif complete == "skipped" and m["complete"] == "":
                m["complete"] = "skipped"

            try:
                m["entries_scanned"] += int(row.get("entries_scanned") or 0)
            except (ValueError, TypeError):
                pass
            try:
                m["windows_queried"] += int(row.get("windows_queried") or 0)
            except (ValueError, TypeError):
                pass

            ds = (row.get("data_source", "") or "").strip()
            if ds:
                m["data_source"].add(ds)

    result = []
    for rule in rule_order:
        m = merged[rule]
        apps_sorted  = sorted(m["apps"])
        ports_sorted = sorted(m["ports"])
        result.append({
            "rule":             rule,
            "app_count":        str(len(apps_sorted)),
            "apps":             "|".join(apps_sorted),
            "port_count":       str(len(ports_sorted)),
            "ports":            "|".join(ports_sorted),
            "app_port_details": "|".join(sorted(m["app_port_details"])),
            "entries_scanned":  str(m["entries_scanned"]),
            "windows_queried":  str(m["windows_queried"]),
            "complete":         m["complete"] or "no",
            "data_source":      "|".join(sorted(m["data_source"])),
        })

    return result


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate App-ID rule designs from get-rule-apps.py CSV output."
    )
    parser.add_argument(
        "input_csvs", nargs="+", metavar="input_csv",
        help="One or more CSV files from get-rule-apps.py; app lists are unioned per rule",
    )
    parser.add_argument(
        "--device-group", "--dg", metavar="NAME", dest="device_group",
        help="Override device group for rule config lookups (Panorama mode only)",
    )
    parser.add_argument(
        "--output", "-o", metavar="PATH",
        help="Output file stem (.txt and .csv appended); default: Output/rule-design-<stem>-TIMESTAMP",
    )
    parser.add_argument(
        "--static-ports", action="store_true",
        help="Skip dynamic app-id lookup; use standard-ports.txt to classify ports instead",
    )
    parser.add_argument(
        "--standard-ports", metavar="FILE", dest="standard_ports_file",
        help=f"Standard ports fallback file (default: {STANDARD_PORTS_FILE.name} in script directory)",
    )
    parser.add_argument(
        "--risky-apps", metavar="FILE", dest="risky_apps_file",
        help=f"Risky apps file (default: {RISKY_APPS_FILE.name} in script directory)",
    )
    parser.add_argument(
        "--pci-flags", metavar="FILE", dest="pci_flags_file",
        help=f"File listing Panorama tag names that identify PCI rules"
             f" (default: {PCI_FLAGS_FILE.name} in script directory;"
             f" omit file to disable PCI splitting)",
    )
    parser.add_argument(
        "--no-csv", action="store_true",
        help="Skip the structured CSV output; generate text design file only",
    )
    parser.add_argument(
        "--update-existing", action="store_true", dest="update_existing",
        help="For rules where APP-ID-<name> already exists, generate an app_update design"
             " (adds apps from this run to the existing rule) instead of skipping",
    )
    parser.add_argument(
        "--app-review-threshold", metavar="N", type=int, dest="app_review_threshold",
        default=APP_REVIEW_THRESHOLD,
        help=f"Flag designs with this many or more apps for manual review (default: {APP_REVIEW_THRESHOLD})",
    )
    args = parser.parse_args()

    if args.device_group:
        ops_lib.DEVICE_GROUP = args.device_group
        ops_lib.MODE = "panorama"

    run_dt         = datetime.datetime.now()
    run_month_year = run_dt.strftime("%B %Y")
    timestamp      = run_dt.strftime("%Y%m%d-%H%M%S")
    if len(args.input_csvs) == 1:
        input_stem  = Path(args.input_csvs[0]).stem
        output_stem = args.output or f"Output/rule-design-{input_stem}-{timestamp}"
    else:
        output_stem = args.output or f"Output/rule-design-merged-{timestamp}"
    Path(output_stem).parent.mkdir(parents=True, exist_ok=True)

    txt_path     = f"{output_stem}.txt"
    csv_path     = f"{output_stem}.csv"
    pci_csv_path = f"{output_stem}-pci.csv"

    port_mode = "static (standard-ports.txt)" if args.static_ports else "dynamic (Panorama app-id database)"

    print("=" * 62)
    print(f"  design-rule-apps  v{__version__}")
    print("=" * 62)
    if len(args.input_csvs) == 1:
        print(f"  Input       : {args.input_csvs[0]}")
    else:
        print(f"  Inputs      : {len(args.input_csvs)} CSV files (merged)")
        for f in args.input_csvs:
            print(f"                {f}")
    print(f"  Target      : {ops_lib.TARGET_HOST}  ({ops_lib.mode_summary()})")
    print(f"  Port mode   : {port_mode}")
    print(f"  Output .txt : {txt_path}")
    if not args.no_csv:
        print(f"  Output .csv : {csv_path}")
    print()

    ra_path    = Path(args.risky_apps_file) if args.risky_apps_file else RISKY_APPS_FILE
    risky_apps = load_set_from_file(ra_path, default=DEFAULT_RISKY_APPS, label="risky-apps")

    pf_path  = Path(args.pci_flags_file) if args.pci_flags_file else PCI_FLAGS_FILE
    pci_tags = load_set_from_file(pf_path, default=frozenset(), label="pci-flags")
    if pci_tags and not args.no_csv:
        print(f"  PCI csv     : {pci_csv_path}")

    sp_path = Path(args.standard_ports_file) if args.standard_ports_file else STANDARD_PORTS_FILE
    static_standard_ports: set[str] = set()
    if args.static_ports:
        static_standard_ports = load_set_from_file(sp_path, default=None, label="standard-ports")

    print()

    all_csv_rows: list[list[dict]] = []
    for csv_path_in in args.input_csvs:
        try:
            with open(csv_path_in, newline="", encoding="utf-8") as fh:
                file_rows = list(csv.DictReader(fh))
        except FileNotFoundError:
            print(f"Error: input file not found: {csv_path_in}", file=sys.stderr)
            sys.exit(1)
        if not file_rows:
            print(f"Warning: no rows in {csv_path_in} — skipping", file=sys.stderr)
            continue
        all_csv_rows.append(file_rows)

    if not all_csv_rows:
        print("No rows found in any input CSV.", file=sys.stderr)
        sys.exit(1)

    rows = merge_csv_rows(all_csv_rows)
    if not rows:
        print("No rows found after merging input CSVs.", file=sys.stderr)
        sys.exit(1)

    rule_names = [r["rule"] for r in rows if r.get("rule")]

    # Include APP-ID names so we can detect duplicates in the same bulk call
    app_id_names = (
        [f"APP-ID-{n}" for n in rule_names]
        + [f"APP-ID-{n}-UNKNOWN" for n in rule_names]
        + [f"APP-ID-{n}-NONSTANDARD" for n in rule_names]
    )

    print(f"  Fetching rule configs for {len(rule_names)} rules ...", end=" ", flush=True)
    configs = fetch_full_rule_configs(rule_names + app_id_names)
    found            = sum(1 for n in rule_names   if configs[n].found)
    existing_app_ids = sum(1 for n in app_id_names if configs[n].found)
    dup_suffix = f"  ({existing_app_ids} existing APP-ID rule(s) — duplicates skipped)" if existing_app_ids else "  (0 existing APP-ID rules — no duplicates)"
    print(f"{found}/{len(rule_names)} found{dup_suffix}")

    # ── App default port lookup ───────────────────────────────────────────────
    # app_port_map: app_name → set of 'tcp-80' style standard port strings
    # dynamic_available: True  → use per-rule union of app default ports
    #                    False → fall back to static_standard_ports
    app_port_map: dict[str, set[str]] = {}
    dynamic_available = False

    if not args.static_ports:
        all_usable: set[str] = set()
        for row in rows:
            usable, _, _ = classify_apps(row.get("apps", ""), risky_apps)
            all_usable.update(usable)

        if all_usable:
            print(
                f"  Fetching standard ports for {len(all_usable)} unique apps ...",
                end=" ", flush=True,
            )
            app_port_map, dynamic_available = fetch_app_default_ports(list(all_usable))

            if dynamic_available:
                n_with_ports = sum(1 for v in app_port_map.values() if v)
                print(f"{n_with_ports}/{len(all_usable)} apps have defined standard ports")
            else:
                print("API unavailable — falling back to standard-ports.txt")
                static_standard_ports = load_set_from_file(
                    sp_path, default=None, label="standard-ports"
                )

    # ── Full app-port map for inference (all predefined apps, unfiltered) ─────
    full_app_port_map: dict[str, set[str]] = {}
    port_app_map:      dict[str, set[str]] = {}

    if not args.static_ports and dynamic_available:
        print("  Fetching full app-port map for inference ...", end=" ", flush=True)
        full_app_port_map = fetch_all_predefined_ports()
        n_total   = len(full_app_port_map)
        n_w_ports = sum(1 for v in full_app_port_map.values() if v)
        print(f"{n_total} apps, {n_w_ports} with defined ports")
        for app, ports in full_app_port_map.items():
            for port in ports:
                port_app_map.setdefault(port.lower(), set()).add(app)

    print()

    device_group           = ops_lib.DEVICE_GROUP
    new_rule_designs: list[str] = []
    update_designs:   list[str] = []
    csv_rows:         list[dict] = []
    new_rule_designs_pci: list[str] = []
    update_designs_pci:   list[str] = []
    csv_rows_pci:         list[dict] = []
    notes: list[str]            = []
    design_count               = 0
    new_rule_count             = 0
    unknown_rule_count         = 0
    nonstandard_rule_count     = 0
    app_update_count           = 0
    update_count               = 0
    unused_count               = 0
    named_service_count        = 0
    inferred_count             = 0
    pci_design_count           = 0
    pci_new_rule_count         = 0
    pci_update_count           = 0

    for row in rows:
        rule_name = row.get("rule", "").strip()
        if not rule_name:
            continue

        complete     = row.get("complete", "").strip().lower()
        apps_raw     = row.get("apps", "").strip()
        ports_raw    = row.get("ports", "").strip()
        app_port_raw = row.get("app_port_details", "").strip()
        config       = configs[rule_name]
        pci          = is_pci_rule(config, pci_tags)

        usable_apps, unknown_apps, has_risky = classify_apps(apps_raw, risky_apps)
        has_unknown = bool(unknown_apps)

        # ── Parse observed port data ──────────────────────────────────────────
        app_port_obs   = parse_app_port_details(app_port_raw)
        observed_ports = {p for ps in app_port_obs.values() for p in ps}

        # ── Validate configured ports (detect named service objects/groups) ───
        raw_ports = [p.strip() for p in ports_raw.split("|") if p.strip()]
        has_named_service = bool(raw_ports) and any(not _is_raw_port_spec(p) for p in raw_ports)
        valid_configured  = (
            [p.lower() for p in raw_ports if _is_raw_port_spec(p)]
            if not has_named_service else []
        )

        # ── App inference from observed (or configured) ports ─────────────────
        inferred_apps: list[str] = []
        if dynamic_available and port_app_map:
            inference_source = observed_ports if observed_ports else set(valid_configured)
            all_known = set(usable_apps) | UNKNOWN_APP_VALUES | NON_APP_VALUES
            inferred_apps = infer_apps_from_ports(
                inference_source, port_app_map, all_known, PORT_INFERENCE_THRESHOLD
            )

        # ── Classify observed apps: standard-port vs non-standard-port ────────
        std_observed_apps:   list[str] = []
        nonst_observed_apps: list[str] = []
        nonst_ports:         set[str]  = set()

        if dynamic_available and app_port_obs:
            for app in usable_apps:
                app_std     = app_port_map.get(app, set()) | full_app_port_map.get(app, set())
                obs_for_app = app_port_obs.get(app, set())
                app_nonst   = obs_for_app - app_std
                if app_nonst:
                    nonst_ports |= app_nonst
                    nonst_observed_apps.append(app)
                if obs_for_app - app_nonst:       # also seen on standard ports
                    std_observed_apps.append(app)
                elif not app_nonst:               # no observed data or fully standard
                    std_observed_apps.append(app)
        else:
            std_observed_apps = list(usable_apps)

        # main rule: standard observed + inferred (inferred are by-definition standard-port)
        main_apps  = list(dict.fromkeys(std_observed_apps + inferred_apps))
        # NONSTANDARD rule: apps seen on non-standard ports
        nonst_apps = list(dict.fromkeys(nonst_observed_apps))

        has_no_apps = not main_apps and not nonst_apps and not has_unknown

        if complete == "no" and has_no_apps:
            print(f"  Skipping {rule_name} — query incomplete (complete=no) with no apps found.")
            print( "    Re-run get-rule-apps.py with --resume to retry this rule.")
            continue

        if complete == "skipped" or has_no_apps:
            if pci:
                pci_design_count += 1
                _dnum = f"PCI-{pci_design_count}"
                pci_update_count += 1
                update_designs_pci.append(format_unused_design(_dnum, rule_name, device_group, run_month_year))
                if not args.no_csv:
                    csv_rows_pci.append(build_tag_update_row(rule_name, TAG_UNUSED, device_group))
            else:
                design_count += 1
                unused_count += 1
                update_designs.append(format_unused_design(design_count, rule_name, device_group, run_month_year))
                if not args.no_csv:
                    csv_rows.append(build_tag_update_row(rule_name, TAG_UNUSED, device_group))
            continue

        # ── Port filtering and service determination for main rule ────────────
        filtered: list[str] = []
        if has_named_service:
            effective_ports_raw = ""
            rule_std_ports: set[str] = set()
            named_service_count += 1
        elif dynamic_available and valid_configured:
            combined_std: set[str] = set()
            for app in main_apps:
                combined_std |= app_port_map.get(app, set())
                combined_std |= full_app_port_map.get(app, set())
            if observed_ports:
                filtered = [p for p in valid_configured
                            if p == "application-default" or (p in observed_ports and p not in nonst_ports)]
            else:
                filtered = [p for p in valid_configured
                            if p == "application-default" or p in combined_std]
            effective_ports_raw = " | ".join(filtered) if filtered else ""
            rule_std_ports = combined_std
        else:
            filtered = list(valid_configured)
            effective_ports_raw = ports_raw
            rule_std_ports = static_standard_ports

        service, _ = determine_port_setting(effective_ports_raw, rule_std_ports)

        # Main rule never gets TAG_NON_STANDARD — non-std traffic goes to NONSTANDARD rule
        new_rule_tags: list[str] = list(config.existing_tags) + [TAG_NEW_RULE]
        if has_risky:
            new_rule_tags.append(TAG_RISKY)

        if inferred_apps:
            inferred_count += 1

        # ── Check for existing APP-ID rules ───────────────────────────────────
        known_exists       = configs[f"APP-ID-{rule_name}"].found
        unknown_exists     = configs[f"APP-ID-{rule_name}-UNKNOWN"].found
        nonstandard_exists = configs[f"APP-ID-{rule_name}-NONSTANDARD"].found

        generate_known       = bool(main_apps)    and not known_exists
        generate_unknown     = bool(unknown_apps) and not unknown_exists
        generate_nonstandard = bool(nonst_apps) and bool(nonst_ports) and not nonstandard_exists

        # ── Pre-assign design numbers ─────────────────────────────────────────
        known_num           = None
        unknown_num         = None
        app_update_num      = None
        nonstandard_num     = None
        nonstandard_upd_num = None

        if generate_known:
            if pci:
                pci_design_count += 1; known_num = f"PCI-{pci_design_count}"
                pci_new_rule_count += 1
            else:
                design_count += 1; known_num = design_count
                new_rule_count += 1
        elif known_exists and main_apps and args.update_existing:
            if pci:
                pci_design_count += 1; app_update_num = f"PCI-{pci_design_count}"
            else:
                design_count += 1; app_update_num = design_count
                app_update_count += 1

        if generate_unknown:
            if pci:
                pci_design_count += 1; unknown_num = f"PCI-{pci_design_count}"
            else:
                design_count += 1; unknown_num = design_count
                unknown_rule_count += 1

        if generate_nonstandard:
            if pci:
                pci_design_count += 1; nonstandard_num = f"PCI-{pci_design_count}"
            else:
                design_count += 1; nonstandard_num = design_count
                nonstandard_rule_count += 1
        elif nonstandard_exists and nonst_apps and nonst_ports and args.update_existing:
            if pci:
                pci_design_count += 1; nonstandard_upd_num = f"PCI-{pci_design_count}"
            else:
                design_count += 1; nonstandard_upd_num = design_count
                app_update_count += 1

        if pci:
            pci_design_count += 1; update_num = f"PCI-{pci_design_count}"
            pci_update_count += 1
        else:
            design_count += 1; update_num = design_count
            update_count += 1

        # ── Notes ─────────────────────────────────────────────────────────────
        first_num = (known_num           if known_num           is not None else
                     app_update_num      if app_update_num      is not None else
                     unknown_num         if unknown_num         is not None else
                     nonstandard_num     if nonstandard_num     is not None else
                     update_num)

        if not config.found:
            notes.append((
                f"Design {first_num} — {rule_name}",
                "rule was not found in Panorama config — zone, address, and profile fields are empty.",
            ))
        if has_named_service:
            notes.append((
                f"Design {first_num} — {rule_name}",
                f"service config contains named objects/groups — application-default used. "
                f"Original service: {ports_raw}",
            ))
        if inferred_apps:
            src = "observed dports" if observed_ports else "configured ports"
            notes.append((
                f"Design {first_num} — {rule_name}",
                f"apps inferred from {src}: {', '.join(inferred_apps)} — verify before implementing.",
            ))
        dropped: list[str] = []
        if not has_named_service and dynamic_available and valid_configured:
            dropped = [p for p in valid_configured if p not in filtered]
        if dropped:
            notes.append((
                f"Design {first_num} — {rule_name}",
                f"ports dropped (no observed traffic): {', '.join(dropped)}",
            ))
        if known_exists and main_apps:
            if args.update_existing:
                notes.append((
                    f"Design {app_update_num} — {rule_name}",
                    f"APP-ID-{rule_name} already exists — app_update design generated to add/confirm apps.",
                ))
            else:
                notes.append((
                    f"Design {update_num} — {rule_name}",
                    f"APP-ID-{rule_name} already exists — new rule design skipped. Use --update-existing to generate an app_update.",
                ))
        if unknown_exists and unknown_apps:
            notes.append((
                f"Design {update_num} — {rule_name}",
                f"APP-ID-{rule_name}-UNKNOWN already exists — unknown-traffic rule design skipped.",
            ))
        if nonstandard_exists and nonst_apps and nonst_ports:
            if args.update_existing:
                notes.append((
                    f"Design {nonstandard_upd_num} — {rule_name}",
                    f"APP-ID-{rule_name}-NONSTANDARD already exists — app_update design generated.",
                ))
            else:
                notes.append((
                    f"Design {update_num} — {rule_name}",
                    f"APP-ID-{rule_name}-NONSTANDARD already exists — skipped. Use --update-existing to add new apps.",
                ))
        if generate_nonstandard:
            notes.append((
                f"Design {nonstandard_num} — {rule_name}",
                f"non-standard port traffic detected: {', '.join(sorted(nonst_ports))} — "
                f"separate NONSTANDARD rule generated.",
            ))
        if generate_unknown:
            has_main_design = generate_known or app_update_num is not None
            if has_main_design:
                notes.append((
                    f"Design {first_num} — {rule_name}",
                    f"unknown-tcp/unknown-udp traffic was observed. A separate unknown-traffic"
                    f" rule has been generated as Design {unknown_num}. These sessions could not"
                    " be identified by App-ID and require investigation before the old rule can"
                    " be safely retired.",
                ))
            else:
                notes.append((
                    f"Design {unknown_num} — {rule_name}",
                    "only unknown-tcp/unknown-udp traffic was observed. These sessions could not"
                    " be identified by App-ID and require investigation before the old rule can"
                    " be safely retired.",
                ))
        if generate_known and len(main_apps) >= args.app_review_threshold:
            notes.append((
                f"Design {known_num} — {rule_name}",
                f"{len(main_apps)} apps — manual review recommended before finalizing this design.",
            ))

        # ── Generate design blocks ────────────────────────────────────────────
        _new_designs = new_rule_designs_pci if pci else new_rule_designs
        _upd_designs = update_designs_pci   if pci else update_designs

        if generate_known:
            _new_designs.append(format_new_rule_design(
                design_number  = known_num,
                rule_name      = rule_name,
                config         = config,
                usable_apps    = main_apps,
                service        = service,
                new_rule_tags  = new_rule_tags,
                device_group   = device_group,
                run_month_year = run_month_year,
            ))
        elif app_update_num is not None:
            _upd_designs.append(format_app_update_design(
                design_number = app_update_num,
                rule_name     = rule_name,
                usable_apps   = main_apps,
                device_group  = device_group,
            ))

        if generate_unknown:
            _new_designs.append(format_unknown_rule_design(
                design_number  = unknown_num,
                rule_name      = rule_name,
                config         = config,
                unknown_apps   = unknown_apps,
                ports_raw      = effective_ports_raw,
                device_group   = device_group,
                run_month_year = run_month_year,
                has_known_apps = bool(main_apps),
            ))

        if generate_nonstandard:
            nonst_ports_sorted = sorted(nonst_ports)
            _new_designs.append(format_nonstandard_rule_design(
                design_number  = nonstandard_num,
                rule_name      = rule_name,
                config         = config,
                nonst_apps     = nonst_apps,
                nonst_ports    = nonst_ports_sorted,
                device_group   = device_group,
                run_month_year = run_month_year,
            ))
        elif nonstandard_upd_num is not None:
            _upd_designs.append(format_app_update_design(
                design_number = nonstandard_upd_num,
                rule_name     = rule_name,
                usable_apps   = nonst_apps,
                device_group  = device_group,
                rule_suffix   = "-NONSTANDARD",
            ))

        _upd_designs.append(format_rule_update(update_num, rule_name, TAG_UNDER_REVIEW, device_group, run_month_year))

        # ── CSV rows ──────────────────────────────────────────────────────────
        if not args.no_csv:
            _csv = csv_rows_pci if pci else csv_rows

            if generate_known and main_apps:
                _csv.append(build_new_rule_row(
                    rule_name      = rule_name,
                    config         = config,
                    usable_apps    = main_apps,
                    service        = service,
                    new_rule_tags  = new_rule_tags,
                    device_group   = device_group,
                    run_month_year = run_month_year,
                ))
            elif app_update_num is not None:
                _csv.append(build_app_update_row(rule_name, main_apps, device_group))

            if generate_unknown:
                unknown_csv_name = f"APP-ID-{rule_name}-UNKNOWN" if main_apps else f"APP-ID-{rule_name}"
                unknown_tags = list(config.existing_tags) + [TAG_NEW_RULE, TAG_UNKNOWN]
                non_any_users = [u for u in config.source_users if u.lower() != "any"]
                u_ports = [p.strip() for p in (effective_ports_raw or "").split("|") if p.strip()]
                unknown_service = (" | ".join(u_ports)
                                   if u_ports and u_ports != ["application-default"]
                                   else "application-default")
                _csv.append({
                    "type":             "new_rule",
                    "device_group":     device_group,
                    "rule_name":        unknown_csv_name,
                    "clone_above":      rule_name,
                    "description":      f"DDD created {run_month_year}",
                    "tags":             "|".join(unknown_tags),
                    "source_zones":     "|".join(config.source_zones),
                    "source_addresses": "|".join(config.source_addrs),
                    "source_user":      "|".join(non_any_users),
                    "dest_zones":       "|".join(config.dest_zones),
                    "dest_addresses":   "|".join(config.dest_addrs),
                    "applications":     "|".join(unknown_apps),
                    "service":          unknown_service,
                    "action":           config.action,
                    "group_profile":    config.group_profile,
                    "tags_to_add":      "",
                })

            if generate_nonstandard:
                nonst_tags = list(config.existing_tags) + [TAG_NEW_RULE, TAG_NONSTANDARD_RULE]
                non_any_users = [u for u in config.source_users if u.lower() != "any"]
                _csv.append({
                    "type":             "new_rule",
                    "device_group":     device_group,
                    "rule_name":        f"APP-ID-{rule_name}-NONSTANDARD",
                    "clone_above":      rule_name,
                    "description":      f"DDD created {run_month_year}",
                    "tags":             "|".join(nonst_tags),
                    "source_zones":     "|".join(config.source_zones),
                    "source_addresses": "|".join(config.source_addrs),
                    "source_user":      "|".join(non_any_users),
                    "dest_zones":       "|".join(config.dest_zones),
                    "dest_addresses":   "|".join(config.dest_addrs),
                    "applications":     "|".join(nonst_apps),
                    "service":          " | ".join(sorted(nonst_ports)),
                    "action":           config.action,
                    "group_profile":    config.group_profile,
                    "tags_to_add":      "",
                })
            elif nonstandard_upd_num is not None:
                _csv.append(build_app_update_row(rule_name, nonst_apps, device_group, rule_suffix="-NONSTANDARD"))

            _csv.append(build_tag_update_row(rule_name, TAG_UNDER_REVIEW, device_group))

    SEP = "=" * 62

    total_new     = new_rule_count + unknown_rule_count + nonstandard_rule_count
    total_designs = design_count + pci_design_count
    summary_lines = [
        "SUMMARY",
        SEP,
        f"Generated   : {run_dt.strftime('%Y-%m-%d %H:%M:%S')}",
        f"Script      : design-rule-apps.py v{__version__}",
        f"Device group: {device_group}",
        (f"Input       : {args.input_csvs[0]}" if len(args.input_csvs) == 1
         else f"Input       : {len(args.input_csvs)} files merged ({', '.join(args.input_csvs)})"),
        "",
        f"Designs     : {total_designs} total"
        f" — {total_new} new rule(s)"
        f" ({nonstandard_rule_count} NONSTANDARD)"
        f", {app_update_count} app update(s)"
        f", {update_count} tag update(s)"
        f", {unused_count} unused (no traffic)",
        f"Duplicates  : {existing_app_ids} existing APP-ID rule(s) detected"
        + (" — skipped" if existing_app_ids and not args.update_existing else (" — app_update generated" if existing_app_ids and args.update_existing else " — none")),
    ]
    if pci_tags:
        summary_lines.append(
            f"PCI         : {pci_design_count} design(s)"
            f" — {pci_new_rule_count} new rule(s)"
            f", {pci_update_count} tag update(s)"
            + (f"  →  {pci_csv_path}" if not args.no_csv else "")
        )
    if named_service_count or inferred_count:
        summary_lines.append(
            f"Inference   : {inferred_count} rule(s) with inferred apps"
            f", {named_service_count} rule(s) with named service objects (→ application-default)"
        )
    preamble = ["\n".join(summary_lines)]

    if notes:
        pad = max(len(p) for p, _ in notes)
        note_lines = ["NOTES", SEP, ""]
        for prefix, message in notes:
            note_lines.append(f"{prefix.ljust(pad)}: {message}")
        preamble.append("\n".join(note_lines))

    sections = []
    if new_rule_designs:
        sections.append(f"NEW RULES\n{SEP}\n\n" + "\n\n---\n\n".join(new_rule_designs))
    if update_designs:
        sections.append(f"RULE UPDATES\n{SEP}\n\n" + "\n\n---\n\n".join(update_designs))
    if new_rule_designs_pci:
        sections.append(f"PCI — NEW RULES\n{SEP}\n\n" + "\n\n---\n\n".join(new_rule_designs_pci))
    if update_designs_pci:
        sections.append(f"PCI — RULE UPDATES\n{SEP}\n\n" + "\n\n---\n\n".join(update_designs_pci))
    text_output = "\n\n\n".join(preamble + sections)

    with open(txt_path, "w", encoding="utf-8") as fh:
        fh.write(text_output + "\n")

    if not args.no_csv and csv_rows:
        with open(csv_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=DESIGN_CSV_FIELDNAMES)
            writer.writeheader()
            writer.writerows(csv_rows)

    if not args.no_csv and csv_rows_pci:
        with open(pci_csv_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=DESIGN_CSV_FIELDNAMES)
            writer.writeheader()
            writer.writerows(csv_rows_pci)

    print("=" * 62)
    print(f"  {total_designs} design(s) total")
    print(f"  {total_new} new rule(s) ({nonstandard_rule_count} NONSTANDARD)"
          f"  |  {app_update_count} app update(s)"
          f"  |  {update_count} tag update(s)"
          f"  |  {unused_count} unused (no traffic)")
    if pci_tags:
        print(f"  PCI: {pci_design_count} design(s)"
              f"  |  {pci_new_rule_count} new rule(s)"
              f"  |  {pci_update_count} tag update(s)")
    if named_service_count or inferred_count:
        print(f"  {inferred_count} rule(s) with inferred apps"
              f"  |  {named_service_count} rule(s) with named service objects")
    print(f"  Text : {txt_path}")
    if not args.no_csv:
        print(f"  CSV  : {csv_path}")
        if pci_tags and csv_rows_pci:
            print(f"  CSV (PCI) : {pci_csv_path}")
    print("=" * 62)


if __name__ == "__main__":
    main()
