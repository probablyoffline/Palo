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
  ns-split-apps.txt        — one app name per line.  Apps listed here that have 10 or more
                             NS ports for a given rule are extracted from the combined NS
                             rule and each get their own APP-ID-<rule>-NS-<app> design.
                             Apps below the threshold stay in the combined NS rule.
  exclude-new-rule-tags.txt — one Panorama tag name per line.  Tags listed here are stripped
                             from the inherited tag list on all new APP-ID-* rule designs
                             (they still apply to the original rule's tag-update design).

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
    --exclude-tags FILE               Override the default exclude-new-rule-tags.txt path
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
import fnmatch
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, replace
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "libs"))
import ops_lib  # noqa: E402

requests.packages.urllib3.disable_warnings()

# ── Constants ─────────────────────────────────────────────────────────────────

__version__ = "1.11.29"

APP_REVIEW_THRESHOLD     = 10  # flag designs with this many or more usable apps
APP_FETCH_BATCH          = 50  # max apps per XPath filter to avoid PAN-OS XPath length limits

SCRIPT_DIR = Path(__file__).resolve().parent

STANDARD_PORTS_FILE    = SCRIPT_DIR / "standard-ports.txt"
RISKY_APPS_FILE        = SCRIPT_DIR / "risky-apps.txt"
PCI_FLAGS_FILE         = SCRIPT_DIR / "flags-pci.txt"
NS_SPLIT_APPS_FILE     = SCRIPT_DIR / "ns-split-apps.txt"
EXCLUDE_NEW_RULE_TAGS_FILE = SCRIPT_DIR / "exclude-new-rule-tags.txt"
EXCLUDE_APPS_FILE          = SCRIPT_DIR / "exclude-apps.txt"
SKIP_RULE_TAGS_FILE        = SCRIPT_DIR / "skip-rule-tags.txt"

DEFAULT_RISKY_APPS = frozenset({"ssh", "ms-rdp", "telnet", "ftp", "tftp"})

NON_APP_VALUES     = frozenset({"incomplete", "not-applicable", "insufficient-data"})
UNKNOWN_APP_VALUES = frozenset({"unknown-tcp", "unknown-udp"})

TAG_NEW_RULE        = "app-id-new-rule"
TAG_NON_STANDARD    = "app-id-non-standard"
TAG_UNKNOWN         = "app-id-unknown"
TAG_RISKY           = "risky-app"
TAG_UNDER_REVIEW    = "app-id-under-review"
TAG_UNUSED          = "app-id-review-unused"

NOTE_CAT_CONFIG    = "Configuration"
NOTE_CAT_EXISTING  = "Existing rules"
NOTE_CAT_GENERATED = "New designs"
NOTE_CAT_REVIEW    = "Investigation / review"

EPHEMERAL_THRESHOLD      = 10  # min total remaining ports before substituting a group
NS_SPLIT_THRESHOLD       = 10  # min per-app NS ports to trigger a split rule
PORT_ONLY_NS_THRESHOLD   = 5   # token count above which a service group is generated
HOST_GROUP_THRESHOLD     = 10  # group when source or dest address count is >= this

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

SVC_CSV_FIELDNAMES  = ["type", "name", "device_group", "protocol", "port", "members", "rules"]
ADDR_CSV_FIELDNAMES = ["type", "name", "device_group", "address_type", "value", "members", "rules"]

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
    disabled:      bool      = False
    service:       list[str] = field(default_factory=list)
    applications:  list[str] = field(default_factory=list)


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


_RANGE_RE           = re.compile(r'^(tcp|udp)-(\d+)-(\d+)$')
_RAW_SINGLE_PORT_RE = re.compile(r'^(tcp|udp)-(\d+)$')

def _port_in_ranges(port_spec: str, ranges: list[tuple[str, int, int]]) -> bool:
    """Return True if port_spec (e.g. 'tcp-49200') falls within any of the given ranges."""
    m = re.match(r'^(tcp|udp)-(\d+)$', port_spec)
    if not m:
        return False
    proto, num = m.group(1), int(m.group(2))
    return any(proto == rp and rlo <= num <= rhi for rp, rlo, rhi in ranges)


def load_standard_ports_file(
    path: Path,
    require: bool,
    label: str,
) -> tuple[set[str], dict[str, set[str]], dict[str, list[tuple[str, int, int]]]]:
    """
    Load standard-ports.txt supporting three line formats:
      tcp-80                — global: treated as standard for any app on this port
      msrpc:tcp-135         — per-app single port: standard only for that specific app
      msrpc:tcp-49152-65535 — per-app range: any port in the range is standard for that app
    Returns (global_ports, per_app_ports, per_app_ranges).
    If the file is missing and require=True, a warning is printed; otherwise silent.
    """
    if not path.exists():
        if require:
            print(f"  Warning: {label} not found ({path.name}) — treating all explicit ports as non-standard")
        return set(), {}, {}
    global_ports: set[str] = set()
    per_app: dict[str, set[str]] = {}
    per_app_ranges: dict[str, list[tuple[str, int, int]]] = {}
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
                    rm = _RANGE_RE.match(port_spec)
                    if rm:
                        proto, lo, hi = rm.group(1), int(rm.group(2)), int(rm.group(3))
                        per_app_ranges.setdefault(app_name, []).append((proto, lo, hi))
                    else:
                        per_app.setdefault(app_name, set()).add(port_spec)
            else:
                global_ports.add(s)
    n_global  = len(global_ports)
    n_per_app = sum(len(v) for v in per_app.values())
    n_ranges  = sum(len(v) for v in per_app_ranges.values())
    print(f"  Loaded {n_global + n_per_app + n_ranges} entries from {path.name}"
          f" ({n_global} global, {n_per_app} per-app, {n_ranges} per-app range(s))")
    return global_ports, per_app, per_app_ranges


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

        svc_el = entry.find("service")
        svc_members: list[str] = []
        if svc_el is not None:
            svc_members = [m.text.strip() for m in svc_el.findall("member") if m.text]
            if not svc_members and svc_el.text and svc_el.text.strip():
                svc_members = [svc_el.text.strip()]

        app_el = entry.find("application")
        app_members: list[str] = []
        if app_el is not None:
            app_members = [m.text.strip() for m in app_el.findall("member") if m.text]
            if not app_members and app_el.text and app_el.text.strip():
                app_members = [app_el.text.strip()]

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
            disabled      = (entry.findtext("disabled") or "").strip().lower() == "yes",
            service       = svc_members,
            applications  = app_members,
        )

    for name in rule_names:
        if name not in configs:
            configs[name] = RuleConfig(name=name, found=False)

    return configs


# ── App default port lookup ───────────────────────────────────────────────────

def _parse_app_ports_to_set(entry: ET.Element) -> set[str]:
    """
    Extract default ports from a PAN-OS app entry element.
    Handles the following member formats:
      'tcp/80'       → tcp-80
      'udp/443-445'  → udp-443, udp-444, udp-445  (range with protocol)
      '80'           → tcp-80, udp-80  (bare number; assumes both protocols)
      '443,80,udp'   → udp-443, udp-80  (comma-separated ports + protocol name)
      'udp'          → skipped  (protocol-only, no port enumerable)
    Expands ranges up to MAX_RANGE_EXPAND ports; wider ranges are skipped.
    """
    result: set[str] = set()
    default_el = entry.find("default")
    if default_el is None:
        return result
    port_el = default_el.find("port")
    if port_el is None:
        return result

    _PROTOS = ("tcp", "udp")

    def _add_port_spec(proto: str, spec: str) -> None:
        if "-" in spec:
            try:
                start_n, end_n = (int(x) for x in spec.split("-", 1))
                if end_n - start_n <= MAX_RANGE_EXPAND:
                    for p in range(start_n, end_n + 1):
                        result.add(f"{proto}-{p}")
            except ValueError:
                pass
        else:
            try:
                int(spec)
                result.add(f"{proto}-{spec}")
            except ValueError:
                pass

    for member in port_el.findall("member"):
        if not member.text:
            continue
        text = member.text.strip().lower()

        if "," in text:
            # Comma-separated list of port numbers / ranges / protocol names.
            # e.g. "443,80,udp"  →  protos=["udp"], ports=["443","80"]
            tokens = [t.strip() for t in text.split(",") if t.strip()]
            protos = [t for t in tokens if t in _PROTOS]
            port_tokens = [t for t in tokens if t not in _PROTOS]
            if not protos:
                protos = list(_PROTOS)
            for pt in port_tokens:
                for proto in protos:
                    _add_port_spec(proto, pt)
        elif "/" in text:
            # proto/port or proto/start-end
            proto, port_spec = text.split("/", 1)
            if proto in _PROTOS:
                _add_port_spec(proto, port_spec)
        elif text in _PROTOS:
            # Bare protocol name with no port — can't enumerate, skip.
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


def _addr_group_name(rule_name: str, suffix: str) -> str:
    """Return a Panorama-safe address group name capped at 63 chars."""
    prefix = "hst-grp-"
    max_rule = 63 - len(prefix) - len(suffix)
    return f"{prefix}{rule_name[:max_rule]}{suffix}"


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

    lines.append(f"Description: [request_item] created {run_month_year}")

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
    design_number:     int | str,
    rule_name:         str,
    config:            RuleConfig,
    unknown_apps:      list[str],
    ports_raw:         str,
    device_group:      str,
    run_month_year:    str,
    has_known_apps:    bool,
    base_tags:         list[str],
    unknown_obs_ports: list[str] | None = None,
) -> str:
    new_rule_name = f"APP-ID-{rule_name}-UNKNOWN" if has_known_apps else f"APP-ID-{rule_name}"

    tags = list(base_tags) + [TAG_NEW_RULE, TAG_UNKNOWN]

    if unknown_obs_ports:
        service = ", ".join(unknown_obs_ports)
    else:
        ports = [p.strip() for p in ports_raw.split("|") if p.strip()]
        service = ", ".join(ports) if ports and ports != ["application-default"] else "application-default"

    lines = [f"Design {design_number}", ""]
    lines += [
        f"In {device_group}",
        f"Clone Rule ABOVE: {rule_name}",
        f"New Rule Name: {new_rule_name}",
        f"Description: [request_item] created {run_month_year}",
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
        f"Description: [request_item] updated {run_month_year}",
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
        f"Description: [request_item] updated {run_month_year}",
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
    desc_lines.append(f"[request_item] created {run_month_year}")

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
    base_tags:      list[str],
    rule_suffix:    str = "-NS",
) -> str:
    tags = list(base_tags) + [TAG_NEW_RULE, TAG_NON_STANDARD]

    lines = [f"Design {design_number}", ""]
    lines += [
        f"In {device_group}",
        f"Clone Rule ABOVE: {rule_name}",
        f"New Rule Name: APP-ID-{rule_name}{rule_suffix}",
        f"Description: [request_item] created {run_month_year}",
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
    base_tags:      list[str],
) -> str:
    tags = list(base_tags) + [TAG_NEW_RULE, TAG_RISKY]

    lines = [f"Design {design_number}", ""]
    lines += [
        f"In {device_group}",
        f"Clone Rule ABOVE: {rule_name}",
        f"New Rule Name: APP-ID-{rule_name}-RISKY",
        f"Description: [request_item] created {run_month_year}",
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


def _tag_matches_patterns(tags: list[str], patterns: list[str]) -> str | None:
    """Return the first tag matching any glob pattern, or None."""
    for tag in tags:
        for pat in patterns:
            if fnmatch.fnmatch(tag.lower(), pat):
                return tag
    return None


def format_addr_update_design(
    design_number:  int | str,
    rule_name:      str,
    device_group:   str,
    src_group:      str | None,
    dst_group:      str | None,
    orig_src_count: int,
    orig_dst_count: int,
) -> str:
    lines = [
        f"Design {design_number}", "",
        f"In {device_group}",
        "Update existing rule",
        f"Rule Name: APP-ID-{rule_name}",
    ]
    if src_group:
        lines.append(
            f"Source Address: {src_group}"
            f"  (replaces {orig_src_count} individual address object(s))"
        )
    if dst_group:
        lines.append(
            f"Dest Address: {dst_group}"
            f"  (replaces {orig_dst_count} individual address object(s))"
        )
    return "\n".join(lines)


def format_addr_group_design(name: str, device_group: str, members: list[str]) -> str:
    return "\n".join([
        "In [host_group_dg]",
        "Create address group",
        f"Address Group Name: {name}",
        f"Addresses: {', '.join(members)}",
    ])


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
        "--exclude-tags", metavar="FILE", dest="exclude_tags_file",
        help=f"File listing tag names to strip from new APP-ID-* rule designs"
             f" (default: {EXCLUDE_NEW_RULE_TAGS_FILE.name} in script directory;"
             f" omit file to use only the built-in exclusions)",
    )
    parser.add_argument(
        "--exclude-apps-file", metavar="FILE", dest="exclude_apps_file",
        help=f"File listing app names to exclude from all designs"
             f" (default: {EXCLUDE_APPS_FILE.name} in script directory;"
             f" omit file to exclude no apps)",
    )
    parser.add_argument(
        "--skip-disabled", action="store_true",
        help="Skip rules that are disabled in Panorama (no design generated).",
    )
    parser.add_argument(
        "--skip-rule-tags", metavar="FILE", dest="skip_rule_tags_file",
        help=f"File of glob patterns (one per line); rules whose existing tags match any"
             f" pattern are skipped entirely. Default: {SKIP_RULE_TAGS_FILE.name} in"
             f" script directory.",
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
    parser.add_argument(
        "--show-tags", action="store_true", dest="show_tags",
        help="Fetch rule configs from Panorama, write a CSV of each rule's existing tags, and exit"
             " (no designs generated). Useful for diagnosing which rules already have"
             " app-id-under-review or app-id-review-unused before running with --update-existing.",
    )
    parser.add_argument(
        "--host-groups", action="store_true", dest="host_groups",
        help="When source or destination has more than 5 address members, substitute a "
             "named address group ({rule}-src / {rule}-dst) in the design and write the "
             "group definition to the -addr.csv output file.",
    )
    parser.add_argument(
        "--port-only-ns", action="store_true", dest="port_only_ns",
        help="Design NS rules with Application=any (port-only matching via service objects). "
             "When a rule has more than 5 NS port tokens, a named service group "
             "svc-grp-<rule>-NS is generated so future ports can be added to the group.",
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

    txt_path      = f"{output_stem}.txt"
    csv_path      = f"{output_stem}.csv"
    pci_csv_path  = f"{output_stem}-pci.csv"
    svc_csv_path  = f"{output_stem}-svc.csv"
    addr_csv_path = f"{output_stem}-addr.csv"

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

    et_path = Path(args.exclude_tags_file) if args.exclude_tags_file else EXCLUDE_NEW_RULE_TAGS_FILE
    exclude_new_rule_tags: frozenset[str] = frozenset()
    if et_path.exists():
        exclude_new_rule_tags = frozenset(
            load_set_from_file(et_path, default=frozenset(), label="exclude-new-rule-tags")
        )

    ea_path = Path(args.exclude_apps_file) if args.exclude_apps_file else EXCLUDE_APPS_FILE
    exclude_apps: frozenset[str] = frozenset()
    if ea_path.exists():
        exclude_apps = frozenset(
            load_set_from_file(ea_path, default=frozenset(), label="exclude-apps")
        )

    skip_rule_tag_patterns: list[str] = []
    srt_path = Path(args.skip_rule_tags_file) if args.skip_rule_tags_file else SKIP_RULE_TAGS_FILE
    if srt_path.exists():
        _raw_srt = load_set_from_file(srt_path, default=frozenset(), label="skip-rule-tags")
        skip_rule_tag_patterns = [p.lower() for p in _raw_srt if p]
        if skip_rule_tag_patterns:
            print(f"  Skip-rule-tag patterns ({len(skip_rule_tag_patterns)}): "
                  f"{', '.join(skip_rule_tag_patterns)}")

    if pci_tags and not args.no_csv:
        print(f"  PCI csv     : {pci_csv_path}")
    if exclude_apps:
        print(f"  Excl apps   : {len(exclude_apps)} app(s) excluded from designs")

    sp_path = Path(args.standard_ports_file) if args.standard_ports_file else STANDARD_PORTS_FILE
    static_standard_ports, per_app_standard_ports, per_app_port_ranges = load_standard_ports_file(
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

    # ── --show-tags: dump existing Panorama tags and exit ────────────────────
    if args.show_tags:
        tags_path = f"Output/rule-tags-{timestamp}.csv"
        Path("Output").mkdir(parents=True, exist_ok=True)
        with open(tags_path, "w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=[
                "rule", "found_in_panorama", "app_id_exists",
                "has_under_review", "has_review_unused", "all_tags",
            ])
            writer.writeheader()
            for rule in rule_names:
                cfg = configs[rule]
                tags = cfg.existing_tags
                writer.writerow({
                    "rule":               rule,
                    "found_in_panorama":  cfg.found,
                    "app_id_exists":      configs[f"APP-ID-{rule}"].found,
                    "has_under_review":   TAG_UNDER_REVIEW in tags,
                    "has_review_unused":  TAG_UNUSED       in tags,
                    "all_tags":           "|".join(tags),
                })
        under_review_count = sum(1 for n in rule_names if TAG_UNDER_REVIEW in configs[n].existing_tags)
        unused_count_tags  = sum(1 for n in rule_names if TAG_UNUSED       in configs[n].existing_tags)
        print(f"\n  show-tags output  : {tags_path}")
        print(f"  {found}/{len(rule_names)} rules found in Panorama")
        print(f"  {under_review_count} rules have {TAG_UNDER_REVIEW}")
        print(f"  {unused_count_tags} rules have {TAG_UNUSED}")
        print(f"  {existing_app_ids} rules have an existing APP-ID rule")
        sys.exit(0)

    # ── Filter out rules not found in Panorama ───────────────────────────────
    # Rules that were disabled or deleted between scan runs must not generate
    # designs. Filter before app-port lookups so they are excluded everywhere.
    missing_rules = [n for n in rule_names if not configs[n].found]
    if missing_rules:
        print(f"  Skipping {len(missing_rules)} rule(s) not found in Panorama"
              f" (disabled or removed): {', '.join(missing_rules)}")
        rows       = [r for r in rows if r.get("rule") and configs[r["rule"]].found]
        rule_names = [r["rule"] for r in rows if r.get("rule")]

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
                static_standard_ports, per_app_standard_ports, per_app_port_ranges = load_standard_ports_file(
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

    # Build inverted coverage set — mirrors deploy-rule-design.py's resolve_service logic.
    # Used to detect raw port specs in NS service strings with no named service object.
    _svc_covered: set[str] = set()
    for _svc_name, _ranges in svc_port_map.items():
        _svc_covered.add(_svc_name.lower())
        for _proto, _lo, _hi in _ranges:
            if _hi - _lo <= 1000:
                for _p in range(_lo, _hi + 1):
                    _svc_covered.add(f"{_proto}-{_p}")
    for _grp_name in svc_group_map:
        _svc_covered.add(_grp_name.lower())

    print()

    device_group           = ops_lib.DEVICE_GROUP
    new_rule_designs: list[str] = []
    update_designs:   list[str] = []
    csv_rows:         list[dict] = []
    new_rule_designs_pci: list[str] = []
    update_designs_pci:   list[str] = []
    csv_rows_pci:         list[dict] = []
    notes: list[tuple[str, str, str]] = []               # (prefix, message, category)
    missing_svc_groups: set[str] = set()
    missing_svc_objects: dict[str, tuple[str, str]] = {}  # name → (protocol, port_spec)
    missing_svc_rules: dict[str, set[str]] = {}           # name → set of rule names
    svc_grp_rows: list[dict] = []                         # service_group rows for svc CSV
    addr_grp_rows: list[dict] = []                        # address_group rows for addr CSV
    design_count               = 0
    new_rule_count             = 0
    unknown_rule_count         = 0
    nonstandard_rule_count     = 0
    risky_rule_count           = 0
    app_update_count           = 0
    addr_update_count          = 0
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

        if args.skip_disabled and config.disabled:
            print(f"  Skipping {rule_name} — disabled in Panorama")
            continue

        if skip_rule_tag_patterns:
            _skip_tag = _tag_matches_patterns(config.existing_tags, skip_rule_tag_patterns)
            if _skip_tag:
                print(f"  Skipping {rule_name} — tag '{_skip_tag}' matches skip pattern")
                continue

        _tag_exclude = {TAG_UNUSED, TAG_UNDER_REVIEW} | exclude_new_rule_tags
        base_existing_tags = [t for t in config.existing_tags if t not in _tag_exclude]
        pci                = is_pci_rule(config, pci_tags)

        usable_apps, unknown_apps, has_risky = classify_apps(apps_raw, risky_apps)

        # ── Exclude apps filter ───────────────────────────────────────────────
        excluded_seen: set[str] = set()
        if exclude_apps:
            excluded_seen = {a for a in usable_apps + list(unknown_apps) if a.lower() in exclude_apps}
            usable_apps  = [a for a in usable_apps  if a.lower() not in exclude_apps]
            unknown_apps = [a for a in unknown_apps if a.lower() not in exclude_apps]

        risky_app_list = [a for a in usable_apps if a.lower() in risky_apps]
        clean_usable   = [a for a in usable_apps if a.lower() not in risky_apps]
        has_unknown = bool(unknown_apps)

        # ── Parse observed port data ──────────────────────────────────────────
        app_port_obs   = parse_app_port_details(app_port_raw)
        if exclude_apps:
            app_port_obs = {a: ps for a, ps in app_port_obs.items() if a.lower() not in exclude_apps}
        observed_ports = {p for ps in app_port_obs.values() for p in ps}

        # Ports directly observed for unknown-tcp/udp — used as the UNKNOWN rule's service
        # since those apps have no PAN-OS default port (application-default won't match).
        unknown_obs_ports: list[str] = sorted({
            p for app in unknown_apps for p in app_port_obs.get(app, set())
        })

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
                # Per-app ranges (e.g. tcp-49152-65535) cover dynamic port allocations.
                supplement   = static_standard_ports | per_app_standard_ports.get(app, set())
                app_ranges   = per_app_port_ranges.get(app, [])
                range_cover  = {p for p in obs_for_app if _port_in_ranges(p, app_ranges)}
                app_std_eff  = app_std | (obs_for_app & supplement) | range_cover
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

        # Under --port-only-ns, a named service/port group on the original rule already
        # restricts which ports are allowed. Generating a separate NS rule on top is
        # redundant — fold NS apps into the main rule so they're covered by that group.
        _ns_suppressed_named_svc = False
        if args.port_only_ns and has_named_service and nonst_apps:
            main_apps   = list(dict.fromkeys(main_apps + nonst_apps))
            nonst_apps  = []
            nonst_ports = set()
            nonst_app_ports = {}
            _ns_suppressed_named_svc = True

        has_no_apps = not main_apps and not nonst_apps and not has_unknown and not risky_app_list

        if complete == "no" and has_no_apps:
            print(f"  Skipping {rule_name} — query incomplete (complete=no) with no apps found.")
            print( "    Re-run get-rule-apps.py with --resume to retry this rule.")
            continue

        if complete == "skipped" or has_no_apps:
            app_id_deployed = configs[f"APP-ID-{rule_name}"].found
            if TAG_UNUSED not in config.existing_tags and not app_id_deployed:
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

        # ── Address group substitution ────────────────────────────────────────
        _config = config  # replaced by a dataclass copy when --host-groups groups addresses
        _addr_grp_src: str | None = None
        _addr_grp_dst: str | None = None
        if args.host_groups:
            _new_src = config.source_addrs
            _new_dst = config.dest_addrs
            if len(config.source_addrs) >= HOST_GROUP_THRESHOLD:
                _src_grp = _addr_group_name(rule_name, "-src")
                addr_grp_rows.append({
                    "type":         "address_group",
                    "name":         _src_grp,
                    "device_group": device_group,
                    "address_type": "",
                    "value":        "",
                    "members":      "|".join(config.source_addrs),
                    "rules":        rule_name,
                })
                _new_src = [_src_grp]
                _addr_grp_src = _src_grp
            if len(config.dest_addrs) >= HOST_GROUP_THRESHOLD:
                _dst_grp = _addr_group_name(rule_name, "-dst")
                addr_grp_rows.append({
                    "type":         "address_group",
                    "name":         _dst_grp,
                    "device_group": device_group,
                    "address_type": "",
                    "value":        "",
                    "members":      "|".join(config.dest_addrs),
                    "rules":        rule_name,
                })
                _new_dst = [_dst_grp]
                _addr_grp_dst = _dst_grp
            if _new_src is not config.source_addrs or _new_dst is not config.dest_addrs:
                _config = replace(config, source_addrs=_new_src, dest_addrs=_new_dst)

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
        addr_update_num     = None
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

        if args.host_groups and known_exists and (_addr_grp_src or _addr_grp_dst):
            if pci:
                pci_design_count += 1; addr_update_num = f"PCI-{pci_design_count}"
                pci_update_count += 1
            else:
                design_count += 1; addr_update_num = design_count
                addr_update_count += 1

        if pci:
            pci_design_count += 1; update_num = f"PCI-{pci_design_count}"
            pci_update_count += 1
        else:
            design_count += 1; update_num = design_count
            update_count += 1

        # ── Notes ─────────────────────────────────────────────────────────────
        first_num = (known_num           if known_num           is not None else
                     app_update_num      if app_update_num      is not None else
                     addr_update_num     if addr_update_num     is not None else
                     unknown_num         if unknown_num         is not None else
                     nonstandard_num     if nonstandard_num     is not None else
                     risky_num           if risky_num           is not None else
                     update_num)

        if not config.found:
            notes.append((
                f"Design {first_num} — {rule_name}",
                "rule was not found in Panorama config — zone, address, and profile fields are empty.",
                NOTE_CAT_CONFIG,
            ))
        if has_named_service:
            notes.append((
                f"Design {first_num} — {rule_name}",
                f"service config contains named objects/groups — application-default used. "
                f"Original service: {ports_raw}",
                NOTE_CAT_CONFIG,
            ))
        if _ns_suppressed_named_svc:
            notes.append((
                f"Design {first_num} — {rule_name}",
                f"NS rule suppressed (--port-only-ns): original rule has a named service group "
                f"({ports_raw}); NS-classified apps folded into the main APP-ID rule.",
                NOTE_CAT_CONFIG,
            ))
        if unknown_std_apps:
            notes.append((
                f"Design {first_num} — {rule_name}",
                f"standard ports not found in Panorama app-id database for: "
                f"{', '.join(unknown_std_apps)} — observed ports treated as standard. "
                f"Verify manually or check Panorama connectivity.",
                NOTE_CAT_CONFIG,
            ))
        if excluded_seen:
            notes.append((
                f"Design {first_num} — {rule_name}",
                f"excluded apps (not in design): {', '.join(sorted(excluded_seen))}",
                NOTE_CAT_CONFIG,
            ))
        if known_exists:
            _deployed_svc = configs[f"APP-ID-{rule_name}"].service
            _filtered_set = set(filtered)
            _dropped_main = [s for s in _deployed_svc
                             if s.lower() not in _filtered_set and s != "application-default"]
            if _dropped_main:
                notes.append((
                    f"Design {app_update_num or update_num} — {rule_name}",
                    f"ports in deployed APP-ID-{rule_name} not seen in current traffic: "
                    f"{', '.join(_dropped_main)}",
                    NOTE_CAT_CONFIG,
                ))
        if nonstandard_exists and nonst_ports:
            _ns_svc_chk, _ = consolidate_ns_service(
                nonst_ports, ports_raw, svc_port_map, svc_group_map
            )
            _ns_tokens = {t.strip().lower() for t in _ns_svc_chk.split(" | ") if t.strip()}
            _deployed_ns_svc = configs[f"APP-ID-{rule_name}-NS"].service
            _dropped_ns = [s for s in _deployed_ns_svc
                           if s.lower() not in _ns_tokens and s != "application-default"]
            if _dropped_ns:
                notes.append((
                    f"Design {nonstandard_upd_num or update_num} — {rule_name}",
                    f"ports in deployed APP-ID-{rule_name}-NS not seen in current traffic: "
                    f"{', '.join(_dropped_ns)}",
                    NOTE_CAT_CONFIG,
                ))
        if known_exists and main_apps:
            if args.update_existing:
                notes.append((
                    f"Design {app_update_num} — {rule_name}",
                    f"APP-ID-{rule_name} already exists — app_update design generated to add/confirm apps.",
                    NOTE_CAT_EXISTING,
                ))
            else:
                notes.append((
                    f"Design {update_num} — {rule_name}",
                    f"APP-ID-{rule_name} already exists — new rule design skipped. Use --update-existing to generate an app_update.",
                    NOTE_CAT_EXISTING,
                ))
        if unknown_exists and unknown_apps:
            notes.append((
                f"Design {update_num} — {rule_name}",
                f"APP-ID-{rule_name}-UNKNOWN already exists — unknown-traffic rule design skipped.",
                NOTE_CAT_EXISTING,
            ))
        if nonstandard_exists and nonst_apps and nonst_ports:
            if args.update_existing:
                notes.append((
                    f"Design {nonstandard_upd_num} — {rule_name}",
                    f"APP-ID-{rule_name}-NS already exists — app_update design generated.",
                    NOTE_CAT_EXISTING,
                ))
            else:
                notes.append((
                    f"Design {update_num} — {rule_name}",
                    f"APP-ID-{rule_name}-NS already exists — skipped. Use --update-existing to add new apps.",
                    NOTE_CAT_EXISTING,
                ))
        if generate_nonstandard:
            ns_detail = (f"{len(nonst_ports)}+ ports" if len(nonst_ports) > 10
                         else ', '.join(sorted(nonst_ports)))
            notes.append((
                f"Design {nonstandard_num} — {rule_name}",
                f"non-standard port traffic detected: {ns_detail} — "
                f"separate NS rule generated.",
                NOTE_CAT_GENERATED,
            ))
            if nonst_app_ports:
                _app_port_lines = "; ".join(
                    f"{app} ({', '.join(sorted(ports))})"
                    for app, ports in sorted(nonst_app_ports.items())
                )
                notes.append((
                    f"Design {nonstandard_num} — {rule_name}",
                    f"NS apps observed: {_app_port_lines}",
                    NOTE_CAT_GENERATED,
                ))
        for sn_app, sn_ports, sn_num in split_ns_nums:
            sn_detail = (f"{len(sn_ports)}+ ports" if len(sn_ports) > 10
                         else ', '.join(sorted(sn_ports)))
            notes.append((
                f"Design {sn_num} — {rule_name}",
                f"split NS rule for {sn_app}: {sn_detail} — "
                f"separate NS-{sn_app} rule generated.",
                NOTE_CAT_GENERATED,
            ))
            notes.append((
                f"Design {sn_num} — {rule_name}",
                f"NS apps observed: {sn_app} ({', '.join(sorted(sn_ports))})",
                NOTE_CAT_GENERATED,
            ))
        if risky_exists and risky_app_list:
            notes.append((
                f"Design {update_num} — {rule_name}",
                f"APP-ID-{rule_name}-RISKY already exists — risky-app rule design skipped.",
                NOTE_CAT_EXISTING,
            ))
        if generate_risky:
            notes.append((
                f"Design {risky_num} — {rule_name}",
                f"risky app(s) detected: {', '.join(risky_app_list)} — "
                f"separate RISKY rule generated.",
                NOTE_CAT_GENERATED,
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
                    NOTE_CAT_REVIEW,
                ))
            else:
                notes.append((
                    f"Design {unknown_num} — {rule_name}",
                    "only unknown-tcp/unknown-udp traffic was observed. These sessions could not"
                    " be identified by App-ID and require investigation before the old rule can"
                    " be safely retired.",
                    NOTE_CAT_REVIEW,
                ))
        if generate_known and len(main_apps) >= args.app_review_threshold:
            notes.append((
                f"Design {known_num} — {rule_name}",
                f"{len(main_apps)} apps — manual review recommended before finalizing this design.",
                NOTE_CAT_REVIEW,
            ))
        if addr_update_num is not None:
            notes.append((
                f"Design {addr_update_num} — {rule_name}",
                f"APP-ID-{rule_name} already exists — address group substitution required "
                f"(--host-groups). Update the deployed rule to use the new group(s).",
                NOTE_CAT_EXISTING,
            ))

        # ── Generate design blocks ────────────────────────────────────────────
        _new_designs = new_rule_designs_pci if pci else new_rule_designs
        _upd_designs = update_designs_pci   if pci else update_designs

        if generate_known:
            _new_designs.append(format_new_rule_design(
                design_number  = known_num,
                rule_name      = rule_name,
                config         = _config,
                usable_apps    = main_apps,
                service        = service,
                new_rule_tags  = new_rule_tags,
                device_group   = device_group,
                run_month_year = run_month_year,
            ))
        elif app_update_num is not None:
            _deployed_apps = {a.lower() for a in configs[f"APP-ID-{rule_name}"].applications}
            _new_main_apps = [a for a in main_apps if a.lower() not in _deployed_apps]
            if _new_main_apps:
                _upd_designs.append(format_app_update_design(
                    design_number = app_update_num,
                    rule_name     = rule_name,
                    usable_apps   = _new_main_apps,
                    device_group  = device_group,
                ))
            else:
                notes.append((
                    f"Design {app_update_num} — {rule_name}",
                    f"APP-ID-{rule_name} already has all observed apps — no update needed.",
                    NOTE_CAT_EXISTING,
                ))

        if addr_update_num is not None:
            _upd_designs.append(format_addr_update_design(
                design_number  = addr_update_num,
                rule_name      = rule_name,
                device_group   = device_group,
                src_group      = _addr_grp_src,
                dst_group      = _addr_grp_dst,
                orig_src_count = len(config.source_addrs),
                orig_dst_count = len(config.dest_addrs),
            ))

        if generate_unknown:
            _new_designs.append(format_unknown_rule_design(
                design_number     = unknown_num,
                rule_name         = rule_name,
                config            = _config,
                unknown_apps      = unknown_apps,
                ports_raw         = effective_ports_raw,
                device_group      = device_group,
                run_month_year    = run_month_year,
                has_known_apps    = bool(main_apps),
                base_tags         = base_existing_tags,
                unknown_obs_ports = unknown_obs_ports,
            ))

        if generate_nonstandard:
            _ns_svc, _ns_missing = consolidate_ns_service(
                nonst_ports, ports_raw, svc_port_map, svc_group_map
            )
            missing_svc_groups |= _ns_missing
            for _grp in _ns_missing:
                missing_svc_rules.setdefault(_grp, set()).add(rule_name)
            for _tok in _ns_svc.split(" | "):
                _tok = _tok.strip()
                _m = _RAW_SINGLE_PORT_RE.match(_tok)
                if _m and _tok.lower() not in _svc_covered:
                    missing_svc_objects[_tok] = (_m.group(1), _m.group(2))
                    missing_svc_rules.setdefault(_tok, set()).add(rule_name)

            # ── Port-only NS mode ─────────────────────────────────────────────
            _ns_tokens = [t.strip() for t in _ns_svc.split(" | ") if t.strip()]
            if args.port_only_ns:
                _ns_apps_for_design = ["any"]
                if len(_ns_tokens) > PORT_ONLY_NS_THRESHOLD:
                    _svc_grp_name      = f"svc-grp-{rule_name}-NS"
                    _ns_svc_for_design = _svc_grp_name
                    svc_grp_rows.append({
                        "type":         "service_group",
                        "name":         _svc_grp_name,
                        "device_group": device_group,
                        "protocol":     "",
                        "port":         "",
                        "members":      "|".join(_ns_tokens),
                        "rules":        rule_name,
                    })
                    notes.append((
                        f"Design {nonstandard_num} — {rule_name}",
                        f"port-only NS rule (Application=any); service group {_svc_grp_name} "
                        f"contains {len(_ns_tokens)} port token(s).",
                        NOTE_CAT_GENERATED,
                    ))
                else:
                    _ns_svc_for_design = _ns_svc
            else:
                _ns_apps_for_design = nonst_apps
                _ns_svc_for_design  = _ns_svc

            _new_designs.append(format_nonstandard_rule_design(
                design_number  = nonstandard_num,
                rule_name      = rule_name,
                config         = _config,
                nonst_apps     = _ns_apps_for_design,
                service        = _ns_svc_for_design,
                device_group   = device_group,
                run_month_year = run_month_year,
                base_tags      = base_existing_tags,
            ))
        elif nonstandard_upd_num is not None:
            _deployed_ns_apps = {a.lower() for a in configs[f"APP-ID-{rule_name}-NS"].applications}
            _new_ns_apps = [a for a in nonst_apps if a.lower() not in _deployed_ns_apps]
            if _new_ns_apps:
                _upd_designs.append(format_app_update_design(
                    design_number = nonstandard_upd_num,
                    rule_name     = rule_name,
                    usable_apps   = _new_ns_apps,
                    device_group  = device_group,
                    rule_suffix   = "-NS",
                ))
            else:
                notes.append((
                    f"Design {nonstandard_upd_num} — {rule_name}",
                    f"APP-ID-{rule_name}-NS already has all observed apps — no update needed.",
                    NOTE_CAT_EXISTING,
                ))

        for sn_app, sn_ports, sn_num in split_ns_nums:
            _sn_svc, _sn_missing = consolidate_ns_service(
                sn_ports, ports_raw, svc_port_map, svc_group_map
            )
            missing_svc_groups |= _sn_missing
            for _grp in _sn_missing:
                missing_svc_rules.setdefault(_grp, set()).add(rule_name)
            for _tok in _sn_svc.split(" | "):
                _tok = _tok.strip()
                _m = _RAW_SINGLE_PORT_RE.match(_tok)
                if _m and _tok.lower() not in _svc_covered:
                    missing_svc_objects[_tok] = (_m.group(1), _m.group(2))
                    missing_svc_rules.setdefault(_tok, set()).add(rule_name)

            _sn_tokens = [t.strip() for t in _sn_svc.split(" | ") if t.strip()]
            if args.port_only_ns:
                _sn_apps_for_design = ["any"]
                if len(_sn_tokens) > PORT_ONLY_NS_THRESHOLD:
                    _sn_grp_name       = f"svc-grp-{rule_name}-NS-{sn_app}"
                    _sn_svc_for_design = _sn_grp_name
                    svc_grp_rows.append({
                        "type":         "service_group",
                        "name":         _sn_grp_name,
                        "device_group": device_group,
                        "protocol":     "",
                        "port":         "",
                        "members":      "|".join(_sn_tokens),
                        "rules":        rule_name,
                    })
                    notes.append((
                        f"Design {sn_num} — {rule_name}",
                        f"port-only NS rule (Application=any); service group {_sn_grp_name} "
                        f"contains {len(_sn_tokens)} port token(s).",
                        NOTE_CAT_GENERATED,
                    ))
                else:
                    _sn_svc_for_design = _sn_svc
            else:
                _sn_apps_for_design = [sn_app]
                _sn_svc_for_design  = _sn_svc

            _new_designs.append(format_nonstandard_rule_design(
                design_number  = sn_num,
                rule_name      = rule_name,
                config         = _config,
                nonst_apps     = _sn_apps_for_design,
                service        = _sn_svc_for_design,
                device_group   = device_group,
                run_month_year = run_month_year,
                base_tags      = base_existing_tags,
                rule_suffix    = f"-NS-{sn_app}",
            ))

        if generate_risky:
            _new_designs.append(format_risky_rule_design(
                design_number  = risky_num,
                rule_name      = rule_name,
                config         = _config,
                risky_apps     = risky_app_list,
                device_group   = device_group,
                run_month_year = run_month_year,
                base_tags      = base_existing_tags,
            ))

        if TAG_UNDER_REVIEW not in config.existing_tags:
            _upd_designs.append(format_rule_update(update_num, rule_name, TAG_UNDER_REVIEW, device_group, run_month_year))

        # ── CSV rows ──────────────────────────────────────────────────────────
        if not args.no_csv:
            _csv = csv_rows_pci if pci else csv_rows

            if generate_known and main_apps:
                _csv.append(build_new_rule_row(
                    rule_name      = rule_name,
                    config         = _config,
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
                if unknown_obs_ports:
                    unknown_service = ", ".join(unknown_obs_ports)
                else:
                    u_ports = [p.strip() for p in (effective_ports_raw or "").split("|") if p.strip()]
                    unknown_service = (" | ".join(u_ports)
                                       if u_ports and u_ports != ["application-default"]
                                       else "application-default")
                _csv.append({
                    "type":             "new_rule",
                    "device_group":     device_group,
                    "rule_name":        unknown_csv_name,
                    "clone_above":      rule_name,
                    "description":      f"[request_item] created {run_month_year}",
                    "tags":             "|".join(unknown_tags),
                    "source_zones":     "|".join(_config.source_zones),
                    "source_addresses": "|".join(_config.source_addrs),
                    "source_user":      "|".join(non_any_users),
                    "dest_zones":       "|".join(_config.dest_zones),
                    "dest_addresses":   "|".join(_config.dest_addrs),
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
                    "description":      f"[request_item] created {run_month_year}",
                    "tags":             "|".join(nonst_tags),
                    "source_zones":     "|".join(_config.source_zones),
                    "source_addresses": "|".join(_config.source_addrs),
                    "source_user":      "|".join(non_any_users),
                    "dest_zones":       "|".join(_config.dest_zones),
                    "dest_addresses":   "|".join(_config.dest_addrs),
                    "applications":     "|".join(_ns_apps_for_design),
                    "service":          _ns_svc_for_design,
                    "action":           config.action,
                    "group_profile":    config.group_profile,
                    "tags_to_add":      "",
                })
            elif nonstandard_upd_num is not None:
                _csv.append(build_app_update_row(rule_name, nonst_apps, device_group, rule_suffix="-NS"))

            for sn_app, sn_ports, sn_num in split_ns_nums:
                sn_tags = list(base_existing_tags) + [TAG_NEW_RULE, TAG_NON_STANDARD]
                non_any_users = [u for u in config.source_users if u.lower() != "any"]
                # Reuse the consolidated service computed in the text-design loop above.
                # _sn_apps_for_design / _sn_svc_for_design are set per-iteration there;
                # we look them up from the last loop iteration that matches this sn_app.
                _sn_svc_c, _ = consolidate_ns_service(
                    sn_ports, ports_raw, svc_port_map, svc_group_map
                )
                _sn_tokens_c = [t.strip() for t in _sn_svc_c.split(" | ") if t.strip()]
                if args.port_only_ns:
                    _sn_apps_csv = ["any"]
                    if len(_sn_tokens_c) > PORT_ONLY_NS_THRESHOLD:
                        _sn_svc_csv = f"svc-grp-{rule_name}-NS-{sn_app}"
                    else:
                        _sn_svc_csv = _sn_svc_c
                else:
                    _sn_apps_csv = [sn_app]
                    _sn_svc_csv  = _sn_svc_c
                _csv.append({
                    "type":             "new_rule",
                    "device_group":     device_group,
                    "rule_name":        f"APP-ID-{rule_name}-NS-{sn_app}",
                    "clone_above":      rule_name,
                    "description":      f"[request_item] created {run_month_year}",
                    "tags":             "|".join(sn_tags),
                    "source_zones":     "|".join(_config.source_zones),
                    "source_addresses": "|".join(_config.source_addrs),
                    "source_user":      "|".join(non_any_users),
                    "dest_zones":       "|".join(_config.dest_zones),
                    "dest_addresses":   "|".join(_config.dest_addrs),
                    "applications":     "|".join(_sn_apps_csv),
                    "service":          _sn_svc_csv,
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
                    "description":      f"[request_item] created {run_month_year}",
                    "tags":             "|".join(risky_tags),
                    "source_zones":     "|".join(_config.source_zones),
                    "source_addresses": "|".join(_config.source_addrs),
                    "source_user":      "|".join(non_any_users),
                    "dest_zones":       "|".join(_config.dest_zones),
                    "dest_addresses":   "|".join(_config.dest_addrs),
                    "applications":     "|".join(risky_app_list),
                    "service":          "application-default",
                    "action":           config.action,
                    "group_profile":    config.group_profile,
                    "tags_to_add":      "",
                })

            if TAG_UNDER_REVIEW not in config.existing_tags:
                _csv.append(build_tag_update_row(rule_name, TAG_UNDER_REVIEW, device_group))

    SEP  = "=" * 62
    HSEP = "=" * 78

    def _section_header(title: str) -> str:
        return f"{HSEP}\n{HSEP}\n  {title}\n{HSEP}"

    total_new     = new_rule_count + unknown_rule_count + nonstandard_rule_count + risky_rule_count
    total_designs = design_count + pci_design_count
    summary_lines = [
        _section_header("SUMMARY"),
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

    # Fold missing ephemeral groups into missing_svc_objects for unified CSV output.
    for _grp in missing_svc_groups:
        _rm = _RANGE_RE.match(_grp)
        if _rm:
            missing_svc_objects[_grp] = (_rm.group(1), f"{_rm.group(2)}-{_rm.group(3)}")

    if missing_svc_objects or svc_grp_rows:
        msg_lines = [_section_header("MISSING SERVICE OBJECTS"), "",
                     "The following service objects/groups are referenced in NS rule designs",
                     "but were not found in Panorama.  Run deploy-service-objects.py",
                     f"with the -svc.csv file below before deploying rules:",
                     f"  {svc_csv_path}",
                     ""]
        for obj in sorted(missing_svc_objects):
            proto, port = missing_svc_objects[obj]
            msg_lines.append(f"  {obj}  ({proto}/{port})")
        for _grp_row in svc_grp_rows:
            _members = _grp_row.get("members", "").split("|")
            msg_lines.append(f"  {_grp_row['name']}  (service-group, {len(_members)} member(s))")
        preamble.append("\n".join(msg_lines))

    if notes:
        _cat_order = [NOTE_CAT_CONFIG, NOTE_CAT_EXISTING, NOTE_CAT_GENERATED, NOTE_CAT_REVIEW]
        _grouped: dict[str, list[tuple[str, str]]] = {c: [] for c in _cat_order}
        for _prefix, _message, _cat in notes:
            _grouped[_cat].append((_prefix, _message))
        note_lines = [_section_header("NOTES"), ""]
        _first_cat = True
        for _cat in _cat_order:
            _entries = _grouped[_cat]
            if not _entries:
                continue
            if not _first_cat:
                note_lines.append("")
            note_lines.append(f"  {_cat}")
            note_lines.append("  " + "─" * len(_cat))
            _pad = max(len(p) for p, _ in _entries)
            for _prefix, _message in _entries:
                note_lines.append(f"  {_prefix.ljust(_pad)}: {_message}")
            _first_cat = False
        preamble.append("\n".join(note_lines))

    sections = []
    if new_rule_designs:
        sections.append(_section_header("NEW RULES") + "\n\n" + "\n\n---\n\n".join(new_rule_designs))
    if update_designs:
        sections.append(_section_header("RULE UPDATES") + "\n\n" + "\n\n---\n\n".join(update_designs))
    if new_rule_designs_pci:
        sections.append(_section_header("PCI — NEW RULES") + "\n\n" + "\n\n---\n\n".join(new_rule_designs_pci))
    if update_designs_pci:
        sections.append(_section_header("PCI — RULE UPDATES") + "\n\n" + "\n\n---\n\n".join(update_designs_pci))
    if addr_grp_rows:
        _addr_designs = [
            format_addr_group_design(
                name=r["name"],
                device_group=r["device_group"],
                members=[m.strip() for m in r["members"].split("|") if m.strip()],
            )
            for r in addr_grp_rows
        ]
        sections.append(
            _section_header("ADDRESS GROUP DEFINITIONS")
            + "\n\n"
            + "\n\n---\n\n".join(_addr_designs)
        )
    text_output = "\n\n\n\n".join(preamble + sections)

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

    if missing_svc_objects or svc_grp_rows:
        with open(svc_csv_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=SVC_CSV_FIELDNAMES)
            writer.writeheader()
            for _name in sorted(missing_svc_objects):
                _proto, _port = missing_svc_objects[_name]
                _rules = ", ".join(sorted(missing_svc_rules.get(_name, set())))
                writer.writerow({
                    "type":         "service_object",
                    "name":         _name,
                    "device_group": device_group,
                    "protocol":     _proto,
                    "port":         _port,
                    "members":      "",
                    "rules":        _rules,
                })
            for _grp_row in svc_grp_rows:
                writer.writerow(_grp_row)

    if addr_grp_rows:
        with open(addr_csv_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=ADDR_CSV_FIELDNAMES)
            writer.writeheader()
            writer.writerows(addr_grp_rows)

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
    if addr_update_count:
        print(f"  {addr_update_count} address update(s) for deployed rules (--host-groups)")
    if named_service_count:
        print(f"  {named_service_count} rule(s) with named service objects (→ application-default)")
    print(f"  Text : {txt_path}")
    if not args.no_csv:
        print(f"  CSV  : {csv_path}")
        if pci_tags and csv_rows_pci:
            print(f"  CSV (PCI) : {pci_csv_path}")
    if missing_svc_objects or svc_grp_rows:
        print(f"  CSV (svc) : {svc_csv_path}  ← deploy service objects first")
    if addr_grp_rows:
        print(f"  CSV (addr): {addr_csv_path}  ← deploy address groups before rules")
    print("=" * 62)


if __name__ == "__main__":
    main()
