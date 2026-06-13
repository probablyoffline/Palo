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
      all ports explicitly, separate APP-ID-<name>-NS rule generated.
  This reflects Palo Alto's own definition of what is standard — not a static list.

  Use --static-ports to disable dynamic lookup and fall back to standard-ports.txt.
  In dynamic mode, standard-ports.txt is also loaded as a supplemental floor — its
  entries prevent false non-standard flags for ports that Panorama's predefined XML
  defines incompletely (e.g. bare port numbers without protocol).  If the API call
  fails entirely, standard-ports.txt becomes the primary reference.

PCI rule splitting:
  When flags-pci.txt is present, any rule whose existing Panorama tags include one
  of the listed tag names is treated as a PCI rule.  PCI rules are separated into
  their own numbered sequence (PCI-1, PCI-2, …) and their own sections in the .txt
  file (PCI — NEW RULES / PCI — RULE UPDATES).  Their CSV rows are written to a
  separate -pci.csv file.  If flags-pci.txt is absent, PCI splitting is silently
  disabled and the script behaves exactly as before.

Config files (auto-read from the same directory as this script):
  risky-apps.txt      — one app name per line.  Matching apps add the risky-app tag.
  standard-ports.txt  — standard port definitions used in two ways:
                         • In dynamic mode: loaded as a supplement for apps whose standard
                           ports are absent or incomplete in Panorama's predefined database.
                         • In static mode (--static-ports): primary reference for all rules.
                         Supports two line formats:
                           tcp-80          global: standard for any app observed on this port
                           msrpc:tcp-135   per-app: standard only for that specific app
  flags-pci.txt       — one Panorama tag name per line.  Rules tagged with any of
                        these are separated into the PCI output stream.
  ns-split-apps.txt   — one app name per line.  Apps listed here that have 10 or more
                        NS ports for a given rule are extracted from the combined NS
                        rule and each get their own APP-ID-<rule>-NS-<app> design.
                        Apps below the threshold stay in the combined NS rule.

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
    --ns-split-apps FILE              Override the default ns-split-apps.txt path
    --no-csv                          Skip the structured CSV output, text only
    --update-existing                 Generate app_update designs for rules where
                                      APP-ID-<name> already exists (adds new apps)
    --app-review-threshold N          Flag designs with ≥ N apps for manual review
                                      (default: 10)

Output .txt sections (in order):
    SUMMARY                — counters, file paths, PCI breakdown (if applicable)
    MISSING SERVICE GROUPS — ephemeral group names used but absent from Panorama (if any)
    NOTES                  — per-design warnings (named service objects, dropped ports, etc.)
    NEW RULES              — APP-ID-*, APP-ID-*-UNKNOWN, APP-ID-*-NS creations
    RULE UPDATES           — tag additions to existing rules (app-id-under-review, etc.)
    PCI — NEW RULES        — same as NEW RULES, PCI-scoped rules only (if applicable)
    PCI — RULE UPDATES     — same as RULE UPDATES, PCI-scoped rules only (if applicable)

Design logic:
  - Rules with apps observed → new APP-ID-<name> rule design above old rule
  - Rules with no traffic (skipped) or no apps found → tag update only
  - unknown-tcp / unknown-udp → excluded from app list, separate UNKNOWN rule
  - incomplete / not-applicable → excluded silently
  - Risky apps → separate APP-ID-<name>-RISKY rule; risky-app tag
  - Non-standard port traffic → separate APP-ID-<name>-NS rule
  - All new rules get: app-id-new-rule
  - Old rules with new rules get: app-id-under-review
  - Old rules with no traffic get: app-id-review-unused

NS rule service consolidation:
  At startup the script fetches all service objects and service groups from Panorama
  (predefined, shared, and all DGs via wildcard).  When building the NS rule's service
  field, named service objects/groups from the original rule's configured service
  members are checked against the observed non-standard ports:
    - If a named object/group covers one or more observed ports, it is used directly
      in the service field and those ports are removed from the individual list.
    - Service groups are recursively expanded to their member objects.
    - Port ranges are handled via range containment (no expansion limit).
    - Any observed port not covered by a named object remains listed individually.
  This replaces long per-port lists (tcp-27199 | tcp-27201 | …) with the compact
  service object or group name that was already protecting those ports in the old rule.

  Ephemeral port threshold: after named-object matching, if total remaining ports ≥ 10
  and any are in an ephemeral range, those ports are replaced by the service group name:
    tcp-49152-65535 / udp-49152-65535  — Windows/RFC-6335 range
    tcp-32768-60999 / udp-32768-60999  — Linux default range
  Windows range is checked first; both groups can appear in the same rule.  If a group
  is absent from Panorama a MISSING SERVICE GROUPS section is prepended to the output.
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

__version__ = "1.11.13"

APP_REVIEW_THRESHOLD     = 10  # flag designs with this many or more usable apps
APP_FETCH_BATCH          = 50  # max apps per XPath filter to avoid PAN-OS XPath length limits

SCRIPT_DIR = Path(__file__).resolve().parent

STANDARD_PORTS_FILE  = SCRIPT_DIR / "standard-ports.txt"
RISKY_APPS_FILE      = SCRIPT_DIR / "risky-apps.txt"
PCI_FLAGS_FILE       = SCRIPT_DIR / "flags-pci.txt"
NS_SPLIT_APPS_FILE   = SCRIPT_DIR / "ns-split-apps.txt"

DEFAULT_RISKY_APPS = frozenset({"ssh", "ms-rdp", "telnet", "ftp", "tftp"})

NON_APP_VALUES     = frozenset({"incomplete", "not-applicable", "insufficient-data"})
UNKNOWN_APP_VALUES = frozenset({"unknown-tcp", "unknown-udp"})

TAG_NEW_RULE        = "app-id-new-rule"
TAG_NON_STANDARD    = "app-id-non-standard"
TAG_UNKNOWN         = "app-id-unknown"
TAG_RISKY           = "risky-app"
TAG_UNDER_REVIEW    = "app-id-under-review"
TAG_UNUSED          = "app-id-review-unused"

EPHEMERAL_THRESHOLD = 10          # min total remaining ports before substituting a group
NS_SPLIT_THRESHOLD  = 10          # min per-app NS ports to trigger a split rule

# Windows/RFC-6335 ephemeral range (49152–65535)
EPHEMERAL_PORT_LO   = 49152
EPHEMERAL_PORT_HI   = 65535
EPHEMERAL_TCP_GRP   = "tcp-49152-65535"
EPHEMERAL_UDP_GRP   = "udp-49152-65535"

# Linux default ephemeral range (32768–60999)
EPHEMERAL_LINUX_PORT_LO = 32768
EPHEMERAL_LINUX_PORT_HI = 60999
EPHEMERAL_LINUX_TCP_GRP = "tcp-32768-60999"
EPHEMERAL_LINUX_UDP_GRP = "udp-32768-60999"

# Ordered list of ranges to check; Windows first so the overlap zone (49152–60999)
# is claimed by the Windows group when both thresholds are met.
_EPHEMERAL_RANGES = [
    ("tcp", EPHEMERAL_TCP_GRP,       EPHEMERAL_PORT_LO,       EPHEMERAL_PORT_HI),
    ("udp", EPHEMERAL_UDP_GRP,       EPHEMERAL_PORT_LO,       EPHEMERAL_PORT_HI),
    ("tcp", EPHEMERAL_LINUX_TCP_GRP, EPHEMERAL_LINUX_PORT_LO, EPHEMERAL_LINUX_PORT_HI),
    ("udp", EPHEMERAL_LINUX_UDP_GRP, EPHEMERAL_LINUX_PORT_LO, EPHEMERAL_LINUX_PORT_HI),
]

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


def load_standard_ports_file(
    path: Path,
    require: bool,
    label: str,
) -> tuple[set[str], dict[str, set[str]]]:
    """
    Load standard-ports.txt supporting two line formats:
      tcp-80            — global: treated as standard for any app observed on this port
      msrpc:tcp-135     — per-app: treated as standard only when this specific app is
                          observed on this port
    Returns (global_ports, per_app_ports).
    If the file is missing and require=True, a warning is printed; otherwise silent.
    """
    if not path.exists():
        if require:
            print(f"  Warning: {label} not found ({path.name}) — treating all explicit ports as non-standard")
        return set(), {}
    global_ports: set[str] = set()
    per_app: dict[str, set[str]] = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            s = line.strip().lower()
            if not s or s.startswith("#"):
                continue
            if ":" in s:
                app_name, port_spec = s.split(":", 1)
                app_name = app_name.strip()
                port_spec = port_spec.strip()
                if app_name and port_spec:
                    per_app.setdefault(app_name, set()).add(port_spec)
            else:
                global_ports.add(s)
    n_global  = len(global_ports)
    n_per_app = sum(len(v) for v in per_app.values())
    print(f"  Loaded {n_global + n_per_app} entries from {path.name}"
          f" ({n_global} global, {n_per_app} per-app)")
    return global_ports, per_app


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
    Handles two member formats:
      'tcp/80'  → tcp-80  (proto/port, existing format)
      '80'      → tcp-80 and udp-80  (bare number; assumes both protocols)
    Expands ranges up to MAX_RANGE_EXPAND ports; wider ranges are skipped.
    """
    result: set[str] = set()
    default_el = entry.find("default")
    if default_el is None:
        return result
    port_el = default_el.find("port")
    if port_el is None:
        return result

    for member in port_el.findall("member"):
        if not member.text:
            continue
        text = member.text.strip().lower()
        if "/" in text:
            proto, port_spec = text.split("/", 1)
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
        elif "-" in text:
            # Bare range without protocol — add both tcp and udp
            try:
                start_n, end_n = (int(x) for x in text.split("-", 1))
                if end_n - start_n <= MAX_RANGE_EXPAND:
                    for p in range(start_n, end_n + 1):
                        result.add(f"tcp-{p}")
                        result.add(f"udp-{p}")
            except ValueError:
                pass
        elif text.isdigit():
            # Bare port number without protocol — add both tcp and udp
            result.add(f"tcp-{text}")
            result.add(f"udp-{text}")

    return result


def fetch_app_default_ports(
    app_names: list[str],
) -> tuple[dict[str, set[str]], dict[str, str], bool]:
    """
    Query Panorama/firewall for the official standard ports of each application.

    Checks, in order:
      1. /config/predefined/application  — Palo Alto's built-in app-id database
      2. /config/shared/application      — shared custom apps (Panorama only)
      3. DG or vsys custom apps          — org-defined apps

    Returns (port_map, child_to_parent, api_available):
      port_map:         {app_name: set of 'tcp-80' style strings}
                        Empty set means the app has no defined default ports (e.g. ident-by-ip).
      child_to_parent:  {child_app: parent_app} for apps that declare a parent-app element.
      api_available:    True if at least one API source responded successfully.
    """
    wanted = {a for a in app_names
              if a and a not in NON_APP_VALUES and a not in UNKNOWN_APP_VALUES}
    if not wanted:
        return {}, {}, True

    port_map: dict[str, set[str]] = {name: set() for name in wanted}
    child_to_parent: dict[str, str] = {}
    api_available = False

    # Process in batches to avoid PAN-OS XPath length limits on large app sets.
    # Last writer wins across batches (custom apps can override predefined).
    sorted_wanted = sorted(wanted)
    for i in range(0, len(sorted_wanted), APP_FETCH_BATCH):
        batch = sorted_wanted[i : i + APP_FETCH_BATCH]
        if len(batch) == 1:
            app_filter = f"@name='{batch[0]}'"
        else:
            app_filter = " or ".join(f"@name='{a}'" for a in batch)

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
                    parent_el = entry.find("parent-app")
                    if parent_el is not None and parent_el.text and name not in child_to_parent:
                        child_to_parent[name] = parent_el.text.strip()

    return port_map, child_to_parent, api_available


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



def fetch_service_port_map() -> dict[str, list[tuple[str, int, int]]]:
    """Return {service_obj_name: [(proto, lo, hi), ...]} for all accessible service objects."""
    name_to_ranges: dict[str, list[tuple[str, int, int]]] = {}
    sources = ["/config/predefined/service", "/config/shared/service"]
    if ops_lib.MODE == "panorama":
        sources.append(
            "/config/devices/entry[@name='localhost.localdomain']"
            "/device-group/entry/service"
        )
    else:
        sources.append(
            f"/config/devices/entry[@name='localhost.localdomain']"
            f"/vsys/entry[@name='{ops_lib.VSYS}']/service"
        )
    for xpath in sources:
        try:
            xml_text = ops_lib.api_get(xpath)
            root     = ET.fromstring(xml_text)
        except Exception:
            continue
        if root.get("status") == "error":
            continue
        for entry in root.iter("entry"):
            name = entry.get("name", "")
            if not name:
                continue
            ranges: list[tuple[str, int, int]] = []
            tcp_el = entry.find(".//protocol/tcp/port")
            if tcp_el is not None and tcp_el.text:
                ranges.extend(_parse_port_ranges("tcp", tcp_el.text))
            udp_el = entry.find(".//protocol/udp/port")
            if udp_el is not None and udp_el.text:
                ranges.extend(_parse_port_ranges("udp", udp_el.text))
            if ranges:
                name_to_ranges[name] = ranges
    return name_to_ranges


def fetch_service_group_map() -> dict[str, list[str]]:
    """Return {group_name: [member_service_names]} for all accessible service groups."""
    group_map: dict[str, list[str]] = {}
    sources = ["/config/predefined/service-group", "/config/shared/service-group"]
    if ops_lib.MODE == "panorama":
        sources.append(
            "/config/devices/entry[@name='localhost.localdomain']"
            "/device-group/entry/service-group"
        )
    else:
        sources.append(
            f"/config/devices/entry[@name='localhost.localdomain']"
            f"/vsys/entry[@name='{ops_lib.VSYS}']/service-group"
        )
    for xpath in sources:
        try:
            xml_text = ops_lib.api_get(xpath)
            root     = ET.fromstring(xml_text)
        except Exception:
            continue
        if root.get("status") == "error":
            continue
        for entry in root.iter("entry"):
            name = entry.get("name", "")
            if not name:
                continue
            members_el = entry.find("members")
            if members_el is None:
                continue
            members = [m.text for m in members_el.findall("member") if m.text]
            if members:
                group_map[name] = members
    return group_map


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


# ── Port range helpers ────────────────────────────────────────────────────────

def _parse_port_ranges(proto: str, spec: str) -> list[tuple[str, int, int]]:
    """Parse a PAN-OS port spec string into (proto, lo, hi) tuples. No size limit."""
    ranges: list[tuple[str, int, int]] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                lo, hi = (int(x) for x in part.split("-", 1))
                ranges.append((proto.lower(), lo, hi))
            except ValueError:
                pass
        else:
            try:
                n = int(part)
                ranges.append((proto.lower(), n, n))
            except ValueError:
                pass
    return ranges


def _port_key_in_ranges(port_key: str, ranges: list[tuple[str, int, int]]) -> bool:
    """Return True if a port key like 'tcp-27199' falls within any (proto, lo, hi) range."""
    try:
        proto, num = port_key.rsplit("-", 1)
        n = int(num)
        return any(p == proto.lower() and lo <= n <= hi for p, lo, hi in ranges)
    except (ValueError, AttributeError):
        return False


def _resolve_svc_ranges(
    name: str,
    svc_map: dict[str, list[tuple[str, int, int]]],
    grp_map: dict[str, list[str]],
    visited: set[str],
) -> list[tuple[str, int, int]]:
    """Recursively resolve a service object or group name to its port ranges."""
    if name in visited:
        return []
    visited.add(name)
    if name in svc_map:
        return svc_map[name]
    if name in grp_map:
        result: list[tuple[str, int, int]] = []
        for member in grp_map[name]:
            result.extend(_resolve_svc_ranges(member, svc_map, grp_map, visited))
        return result
    return []


def consolidate_ns_service(
    nonst_ports: set[str],
    ports_raw: str,
    svc_map: dict[str, list[tuple[str, int, int]]],
    grp_map: dict[str, list[str]],
) -> tuple[str, set[str]]:
    """
    Replace individual port specs with named service objects/groups where possible.

    Phase 1 — named objects: for each named item in the original rule's ports_raw,
    checks whether it covers any observed non-standard ports and removes covered ports
    from the remaining set.

    Phase 2 — ephemeral threshold: if 10+ remaining ports are in the ephemeral range
    (49152–65535), substitutes the standard ephemeral service group name instead of
    listing them individually.

    Returns (service_str, missing_groups) where missing_groups is the set of ephemeral
    group names used but absent from Panorama (need to be created before deploying).
    """
    named = [p.strip() for p in ports_raw.split("|")
             if p.strip() and not _is_raw_port_spec(p.strip())]

    remaining = set(nonst_ports)
    used: list[str] = []
    for item in named:
        ranges = _resolve_svc_ranges(item, svc_map, grp_map, set())
        covered = {p for p in remaining if _port_key_in_ranges(p, ranges)}
        if covered:
            used.append(item)
            remaining -= covered

    missing: set[str] = set()
    for proto, grp_name, lo, hi in _EPHEMERAL_RANGES:
        eph_ports = {
            p for p in remaining
            if p.startswith(f"{proto}-")
            and lo <= int(p.split("-", 1)[1]) <= hi
        }
        if eph_ports and len(remaining) >= EPHEMERAL_THRESHOLD:
            remaining -= eph_ports
            used.append(grp_name)
            if grp_name not in svc_map and grp_name not in grp_map:
                missing.add(grp_name)

    parts = used + sorted(remaining)
    return (" | ".join(parts) if parts else "application-default"), missing


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

    tags = [t for t in config.existing_tags if t != TAG_UNUSED] + [TAG_NEW_RULE, TAG_UNKNOWN]

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
    service:        str,
    device_group:   str,
    run_month_year: str,
    rule_suffix:    str = "-NS",
) -> str:
    tags = [t for t in config.existing_tags if t != TAG_UNUSED] + [TAG_NEW_RULE, TAG_NON_STANDARD]

    lines = [f"Design {design_number}", ""]
    lines += [
        f"In {device_group}",
        f"Clone Rule ABOVE: {rule_name}",
        f"New Rule Name: APP-ID-{rule_name}{rule_suffix}",
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
        f"Port: {service.replace(' | ', ', ')}",
        f"Action: {config.action}",
        f"Group profile: {config.group_profile or '(none)'}",
    ]
    return "\n".join(lines)


def format_risky_rule_design(
    design_number:  int | str,
    rule_name:      str,
    config:         RuleConfig,
    risky_apps:     list[str],
    device_group:   str,
    run_month_year: str,
) -> str:
    tags = [t for t in config.existing_tags if t != TAG_UNUSED] + [TAG_NEW_RULE, TAG_RISKY]

    lines = [f"Design {design_number}", ""]
    lines += [
        f"In {device_group}",
        f"Clone Rule ABOVE: {rule_name}",
        f"New Rule Name: APP-ID-{rule_name}-RISKY",
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
        f"Application: {_csv_list(risky_apps)}",
        "Port: application-default",
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
        "--ns-split-apps", metavar="FILE", dest="ns_split_apps_file",
        help=f"File listing app names to split into per-app NS rules"
             f" (default: {NS_SPLIT_APPS_FILE.name} in script directory;"
             f" omit file to disable per-app splitting)",
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

    nsa_path = Path(args.ns_split_apps_file) if args.ns_split_apps_file else NS_SPLIT_APPS_FILE
    ns_split_apps: set[str] = set()
    if nsa_path.exists():
        ns_split_apps = load_set_from_file(nsa_path, default=frozenset(), label="ns-split-apps")
    if pci_tags and not args.no_csv:
        print(f"  PCI csv     : {pci_csv_path}")

    sp_path = Path(args.standard_ports_file) if args.standard_ports_file else STANDARD_PORTS_FILE
    static_standard_ports, per_app_standard_ports = load_standard_ports_file(
        sp_path,
        require=args.static_ports,   # warn if missing only when it's the primary reference
        label="standard-ports" if args.static_ports else "standard-ports (supplement)",
    )

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
        + [f"APP-ID-{n}-NS" for n in rule_names]
        + [f"APP-ID-{n}-RISKY" for n in rule_names]
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
    child_to_parent: dict[str, str] = {}
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
            app_port_map, child_to_parent, dynamic_available = fetch_app_default_ports(list(all_usable))

            if dynamic_available:
                n_with_ports = sum(1 for v in app_port_map.values() if v)
                print(f"{n_with_ports}/{len(all_usable)} apps have defined standard ports")
            else:
                print("API unavailable — falling back to standard-ports.txt")
                static_standard_ports, per_app_standard_ports = load_standard_ports_file(
                    sp_path, require=True, label="standard-ports"
                )

    # ── Full app-port map for NS classification (all predefined apps) ──────────
    full_app_port_map: dict[str, set[str]] = {}

    if not args.static_ports and dynamic_available:
        print("  Fetching full app-port map ...", end=" ", flush=True)
        full_app_port_map = fetch_all_predefined_ports()
        n_total   = len(full_app_port_map)
        n_w_ports = sum(1 for v in full_app_port_map.values() if v)
        print(f"{n_total} apps, {n_w_ports} with defined ports")

        # Propagate parent app ports to child apps with no defined ports.
        # PAN-OS defines ports on the parent entry only; child entries inherit but
        # do not repeat the port list in the predefined XML.
        for _app, _parent in child_to_parent.items():
            if not app_port_map.get(_app):
                _inherited = full_app_port_map.get(_parent, set()) | app_port_map.get(_parent, set())
                if _inherited:
                    app_port_map[_app] = _inherited

    print("  Fetching service object map  ...", end=" ", flush=True)
    svc_port_map  = fetch_service_port_map()
    svc_group_map = fetch_service_group_map()
    print(f"{len(svc_port_map)} service objects, {len(svc_group_map)} groups")

    print()

    device_group           = ops_lib.DEVICE_GROUP
    new_rule_designs: list[str] = []
    update_designs:   list[str] = []
    csv_rows:         list[dict] = []
    new_rule_designs_pci: list[str] = []
    update_designs_pci:   list[str] = []
    csv_rows_pci:         list[dict] = []
    notes: list[str]            = []
    missing_svc_groups: set[str] = set()
    design_count               = 0
    new_rule_count             = 0
    unknown_rule_count         = 0
    nonstandard_rule_count     = 0
    risky_rule_count           = 0
    app_update_count           = 0
    update_count               = 0
    unused_count               = 0
    named_service_count        = 0
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
        config             = configs[rule_name]
        base_existing_tags = [t for t in config.existing_tags if t != TAG_UNUSED]
        pci                = is_pci_rule(config, pci_tags)

        usable_apps, unknown_apps, has_risky = classify_apps(apps_raw, risky_apps)
        risky_app_list = [a for a in usable_apps if a.lower() in risky_apps]
        clean_usable   = [a for a in usable_apps if a.lower() not in risky_apps]
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

        # ── Classify observed apps: standard-port vs non-standard-port ────────
        std_observed_apps:   list[str] = []
        nonst_observed_apps: list[str] = []
        nonst_ports:         set[str]  = set()
        nonst_app_ports:     dict[str, set[str]] = {}

        unknown_std_apps: list[str] = []  # observed apps with no standard port data
        if dynamic_available and app_port_obs:
            for app in clean_usable:
                app_std     = app_port_map.get(app, set()) | full_app_port_map.get(app, set())
                obs_for_app = app_port_obs.get(app, set())
                if not app_std and obs_for_app:
                    unknown_std_apps.append(app)
                # Supplement with observed ports that appear in the standard-ports floor.
                # Global entries apply to any app; per-app entries apply only to this app.
                supplement  = static_standard_ports | per_app_standard_ports.get(app, set())
                app_std_eff = app_std | (obs_for_app & supplement)
                # Only flag non-standard when we have a reference set to compare against.
                app_nonst   = (obs_for_app - app_std_eff) if app_std_eff else set()
                if app_nonst:
                    nonst_ports |= app_nonst
                    nonst_app_ports[app] = app_nonst
                    nonst_observed_apps.append(app)
                if obs_for_app - app_nonst:       # also seen on standard ports
                    std_observed_apps.append(app)
                elif not app_nonst:               # no observed data or fully standard
                    std_observed_apps.append(app)
        else:
            std_observed_apps = list(clean_usable)

        main_apps  = list(dict.fromkeys(std_observed_apps))
        # NONSTANDARD rule: apps seen on non-standard ports
        nonst_apps = list(dict.fromkeys(nonst_observed_apps))

        has_no_apps = not main_apps and not nonst_apps and not has_unknown and not risky_app_list

        if complete == "no" and has_no_apps:
            print(f"  Skipping {rule_name} — query incomplete (complete=no) with no apps found.")
            print( "    Re-run get-rule-apps.py with --resume to retry this rule.")
            continue

        if complete == "skipped" or has_no_apps:
            skip_unused = args.update_existing and TAG_UNUSED in config.existing_tags
            if not skip_unused:
                app_id_deployed = configs[f"APP-ID-{rule_name}"].found
                if not app_id_deployed and TAG_UNUSED not in config.existing_tags:
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
                combined_std |= per_app_standard_ports.get(app, set())
                # The NS loop classified this app as standard; its observed ports
                # are therefore standard in this rule's context.
                combined_std |= app_port_obs.get(app, set())
            combined_std |= static_standard_ports
            if observed_ports:
                filtered = [p for p in valid_configured
                            if p in observed_ports and p not in nonst_ports]
            else:
                filtered = [p for p in valid_configured
                            if p == "application-default" or p in combined_std]
            effective_ports_raw = " | ".join(filtered) if filtered else ""
            rule_std_ports = combined_std
        else:
            filtered = list(valid_configured)
            effective_ports_raw = ports_raw
            rule_std_ports = static_standard_ports

        # When per-app port attribution data exists in dynamic mode, the NS
        # classification already confirmed all main_apps are standard.
        # Skip determine_port_setting and use application-default directly.
        if observed_ports and dynamic_available:
            service = "application-default"
        else:
            service, _ = determine_port_setting(effective_ports_raw, rule_std_ports)

        # Main rule never gets TAG_NON_STANDARD or TAG_RISKY — those go to their own rules
        new_rule_tags: list[str] = list(base_existing_tags) + [TAG_NEW_RULE]

        # ── Partition per-app NS splits ───────────────────────────────────────
        split_ns_designs: list[tuple[str, set[str]]] = []  # (app_name, ns_ports)
        if ns_split_apps and nonst_apps:
            split_names = {a for a in nonst_apps if a.lower() in ns_split_apps}
            if split_names:
                split_ns_designs = [
                    (a, nonst_app_ports.get(a, set()))
                    for a in nonst_apps
                    if a in split_names
                    and len(nonst_app_ports.get(a, set())) >= NS_SPLIT_THRESHOLD
                ]
                split_app_names = {a for a, _ in split_ns_designs}
                nonst_apps  = [a for a in nonst_apps  if a not in split_app_names]
                nonst_ports = nonst_ports - {
                    p for _, ports in split_ns_designs for p in ports
                }

        # ── Check for existing APP-ID rules ───────────────────────────────────
        known_exists       = configs[f"APP-ID-{rule_name}"].found
        unknown_exists     = configs[f"APP-ID-{rule_name}-UNKNOWN"].found
        nonstandard_exists = configs[f"APP-ID-{rule_name}-NS"].found
        risky_exists       = configs[f"APP-ID-{rule_name}-RISKY"].found

        generate_known       = bool(main_apps)       and not known_exists
        generate_unknown     = bool(unknown_apps)    and not unknown_exists
        generate_nonstandard = bool(nonst_apps) and bool(nonst_ports) and not nonstandard_exists
        generate_risky       = bool(risky_app_list)  and not risky_exists

        # ── Pre-assign design numbers ─────────────────────────────────────────
        known_num           = None
        unknown_num         = None
        app_update_num      = None
        nonstandard_num     = None
        nonstandard_upd_num = None
        risky_num           = None

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

        split_ns_nums: list[tuple[str, set[str], int | str]] = []
        for sn_app, sn_ports in split_ns_designs:
            if not sn_ports:
                continue
            if pci:
                pci_design_count += 1
                split_ns_nums.append((sn_app, sn_ports, f"PCI-{pci_design_count}"))
                pci_new_rule_count += 1
            else:
                design_count += 1
                split_ns_nums.append((sn_app, sn_ports, design_count))
                nonstandard_rule_count += 1

        if generate_risky:
            if pci:
                pci_design_count += 1; risky_num = f"PCI-{pci_design_count}"
                pci_new_rule_count += 1
            else:
                design_count += 1; risky_num = design_count
                risky_rule_count += 1

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
                     risky_num          if risky_num           is not None else
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
        if unknown_std_apps:
            notes.append((
                f"Design {first_num} — {rule_name}",
                f"standard ports not found in Panorama app-id database for: "
                f"{', '.join(unknown_std_apps)} — observed ports treated as standard. "
                f"Verify manually or check Panorama connectivity.",
            ))
        dropped: list[str] = []
        if not has_named_service and dynamic_available and valid_configured:
            dropped = [p for p in valid_configured if p not in filtered]
        if dropped:
            notes.append((
                f"Design {first_num} — {rule_name}",
                f"ports dropped from main rule: {', '.join(dropped)}",
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
                    f"APP-ID-{rule_name}-NS already exists — app_update design generated.",
                ))
            else:
                notes.append((
                    f"Design {update_num} — {rule_name}",
                    f"APP-ID-{rule_name}-NS already exists — skipped. Use --update-existing to add new apps.",
                ))
        if generate_nonstandard:
            ns_detail = (f"{len(nonst_ports)}+ ports" if len(nonst_ports) > 10
                         else ', '.join(sorted(nonst_ports)))
            notes.append((
                f"Design {nonstandard_num} — {rule_name}",
                f"non-standard port traffic detected: {ns_detail} — "
                f"separate NS rule generated.",
            ))
        for sn_app, sn_ports, sn_num in split_ns_nums:
            sn_detail = (f"{len(sn_ports)}+ ports" if len(sn_ports) > 10
                         else ', '.join(sorted(sn_ports)))
            notes.append((
                f"Design {sn_num} — {rule_name}",
                f"split NS rule for {sn_app}: {sn_detail} — "
                f"separate NS-{sn_app} rule generated.",
            ))
        if risky_exists and risky_app_list:
            notes.append((
                f"Design {update_num} — {rule_name}",
                f"APP-ID-{rule_name}-RISKY already exists — risky-app rule design skipped.",
            ))
        if generate_risky:
            notes.append((
                f"Design {risky_num} — {rule_name}",
                f"risky app(s) detected: {', '.join(risky_app_list)} — "
                f"separate RISKY rule generated.",
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
            _ns_svc, _ns_missing = consolidate_ns_service(
                nonst_ports, ports_raw, svc_port_map, svc_group_map
            )
            missing_svc_groups |= _ns_missing
            _new_designs.append(format_nonstandard_rule_design(
                design_number  = nonstandard_num,
                rule_name      = rule_name,
                config         = config,
                nonst_apps     = nonst_apps,
                service        = _ns_svc,
                device_group   = device_group,
                run_month_year = run_month_year,
            ))
        elif nonstandard_upd_num is not None:
            _upd_designs.append(format_app_update_design(
                design_number = nonstandard_upd_num,
                rule_name     = rule_name,
                usable_apps   = nonst_apps,
                device_group  = device_group,
                rule_suffix   = "-NS",
            ))

        for sn_app, sn_ports, sn_num in split_ns_nums:
            _sn_svc, _sn_missing = consolidate_ns_service(
                sn_ports, ports_raw, svc_port_map, svc_group_map
            )
            missing_svc_groups |= _sn_missing
            _new_designs.append(format_nonstandard_rule_design(
                design_number  = sn_num,
                rule_name      = rule_name,
                config         = config,
                nonst_apps     = [sn_app],
                service        = _sn_svc,
                device_group   = device_group,
                run_month_year = run_month_year,
                rule_suffix    = f"-NS-{sn_app}",
            ))

        if generate_risky:
            _new_designs.append(format_risky_rule_design(
                design_number  = risky_num,
                rule_name      = rule_name,
                config         = config,
                risky_apps     = risky_app_list,
                device_group   = device_group,
                run_month_year = run_month_year,
            ))

        if TAG_UNDER_REVIEW not in config.existing_tags:
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
                unknown_tags = list(base_existing_tags) + [TAG_NEW_RULE, TAG_UNKNOWN]
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
                nonst_tags = list(base_existing_tags) + [TAG_NEW_RULE, TAG_NON_STANDARD]
                non_any_users = [u for u in config.source_users if u.lower() != "any"]
                _csv.append({
                    "type":             "new_rule",
                    "device_group":     device_group,
                    "rule_name":        f"APP-ID-{rule_name}-NS",
                    "clone_above":      rule_name,
                    "description":      f"DDD created {run_month_year}",
                    "tags":             "|".join(nonst_tags),
                    "source_zones":     "|".join(config.source_zones),
                    "source_addresses": "|".join(config.source_addrs),
                    "source_user":      "|".join(non_any_users),
                    "dest_zones":       "|".join(config.dest_zones),
                    "dest_addresses":   "|".join(config.dest_addrs),
                    "applications":     "|".join(nonst_apps),
                    "service":          _ns_svc,
                    "action":           config.action,
                    "group_profile":    config.group_profile,
                    "tags_to_add":      "",
                })
            elif nonstandard_upd_num is not None:
                _csv.append(build_app_update_row(rule_name, nonst_apps, device_group, rule_suffix="-NS"))

            for sn_app, sn_ports, sn_num in split_ns_nums:
                _sn_svc_c, _ = consolidate_ns_service(
                    sn_ports, ports_raw, svc_port_map, svc_group_map
                )
                sn_tags = list(base_existing_tags) + [TAG_NEW_RULE, TAG_NON_STANDARD]
                non_any_users = [u for u in config.source_users if u.lower() != "any"]
                _csv.append({
                    "type":             "new_rule",
                    "device_group":     device_group,
                    "rule_name":        f"APP-ID-{rule_name}-NS-{sn_app}",
                    "clone_above":      rule_name,
                    "description":      f"DDD created {run_month_year}",
                    "tags":             "|".join(sn_tags),
                    "source_zones":     "|".join(config.source_zones),
                    "source_addresses": "|".join(config.source_addrs),
                    "source_user":      "|".join(non_any_users),
                    "dest_zones":       "|".join(config.dest_zones),
                    "dest_addresses":   "|".join(config.dest_addrs),
                    "applications":     sn_app,
                    "service":          _sn_svc_c,
                    "action":           config.action,
                    "group_profile":    config.group_profile,
                    "tags_to_add":      "",
                })

            if generate_risky:
                risky_tags = list(base_existing_tags) + [TAG_NEW_RULE, TAG_RISKY]
                non_any_users = [u for u in config.source_users if u.lower() != "any"]
                _csv.append({
                    "type":             "new_rule",
                    "device_group":     device_group,
                    "rule_name":        f"APP-ID-{rule_name}-RISKY",
                    "clone_above":      rule_name,
                    "description":      f"DDD created {run_month_year}",
                    "tags":             "|".join(risky_tags),
                    "source_zones":     "|".join(config.source_zones),
                    "source_addresses": "|".join(config.source_addrs),
                    "source_user":      "|".join(non_any_users),
                    "dest_zones":       "|".join(config.dest_zones),
                    "dest_addresses":   "|".join(config.dest_addrs),
                    "applications":     "|".join(risky_app_list),
                    "service":          "application-default",
                    "action":           config.action,
                    "group_profile":    config.group_profile,
                    "tags_to_add":      "",
                })

            if TAG_UNDER_REVIEW not in config.existing_tags:
                _csv.append(build_tag_update_row(rule_name, TAG_UNDER_REVIEW, device_group))

    SEP = "=" * 62

    total_new     = new_rule_count + unknown_rule_count + nonstandard_rule_count + risky_rule_count
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
        f" ({nonstandard_rule_count} NS, {risky_rule_count} RISKY)"
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
    if named_service_count:
        summary_lines.append(
            f"Named svc   : {named_service_count} rule(s) with named service objects (→ application-default)"
        )
    preamble = ["\n".join(summary_lines)]

    if missing_svc_groups:
        msg_lines = ["MISSING SERVICE GROUPS", SEP, "",
                     "The following service groups are referenced in NS rule designs",
                     "but were not found in Panorama.  Create them before deploying:",
                     ""]
        for grp in sorted(missing_svc_groups):
            msg_lines.append(f"  {grp}")
        preamble.append("\n".join(msg_lines))

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
    print(f"  {total_new} new rule(s) ({nonstandard_rule_count} NS, {risky_rule_count} RISKY)"
          f"  |  {app_update_count} app update(s)"
          f"  |  {update_count} tag update(s)"
          f"  |  {unused_count} unused (no traffic)")
    if pci_tags:
        print(f"  PCI: {pci_design_count} design(s)"
              f"  |  {pci_new_rule_count} new rule(s)"
              f"  |  {pci_update_count} tag update(s)")
    if named_service_count:
        print(f"  {named_service_count} rule(s) with named service objects (→ application-default)")
    print(f"  Text : {txt_path}")
    if not args.no_csv:
        print(f"  CSV  : {csv_path}")
        if pci_tags and csv_rows_pci:
            print(f"  CSV (PCI) : {pci_csv_path}")
    print("=" * 62)


if __name__ == "__main__":
    main()
