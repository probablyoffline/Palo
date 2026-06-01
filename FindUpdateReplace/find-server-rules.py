#!/usr/bin/env python3
"""
find-server-rules.py  — Panorama global rule search by server identifier

Given a list of servers (hostname / FQDN / IP / CIDR), DNS-resolves them,
then globally searches ALL Panorama device groups for address objects,
address groups, security rules, and NAT rules that reference any resolved
identifier.

Outputs (in Output/ subdirectory):
  find-server-rules-<stem>-<timestamp>.csv  — structured (input for script 2)
  find-server-rules-<stem>-<timestamp>.txt  — human-readable review report

Usage:
  python find-server-rules.py servers.txt
  python find-server-rules.py servers.csv --workers 12
  python find-server-rules.py servers.txt --resume              # skip API, reuse last fetch
  python find-server-rules.py servers.txt --resume data.json
  python find-server-rules.py servers.txt --debug              # log raw API responses

Configuration: set TARGET_HOST and API_KEY in ../libs/ops_lib.py
"""

__version__ = "1.0.1"

import argparse
import concurrent.futures
import csv
import dataclasses
import datetime
import ipaddress
import json
import logging
import os
import socket
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import dataclass
from typing import Optional

import requests

# ── Import connection config from ops_lib ─────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "libs"))
import ops_lib

TARGET_HOST = ops_lib.TARGET_HOST
API_KEY     = ops_lib.API_KEY

requests.packages.urllib3.disable_warnings()

log = logging.getLogger(__name__)

SCRIPT_NAME  = "find-server-rules"
DEFAULT_CACHE = "Output/find-server-rules-cache.json"
_DEV         = "entry[@name='localhost.localdomain']"
_BASE        = f"/config/devices/{_DEV}"


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class AddrObject:
    name:  str
    type:  str    # ip-netmask | fqdn | ip-range | ip-wildcard
    value: str
    dg:    str    # "shared" or device-group name


@dataclass
class AddrGroup:
    name:    str
    members: list
    dg:      str


@dataclass
class RuleMatch:
    server_input:         str
    resolved_ips:         list
    resolved_names:       list
    rule_type:            str   # security | nat
    device_group:         str
    rulebase:             str   # pre | post
    rule_name:            str
    rule_field:           str   # source | destination | both | translated-source | etc.
    matched_via:          list  # object/group names that caused the match
    match_kind:           str   # addr_object | addr_group | direct_member (or combinations)
    current_sources:      list
    current_destinations: list
    action:               str
    disabled:             str   # yes | no
    rule_usage:           str   # used | unused | unknown


# ── API helpers ───────────────────────────────────────────────────────────────

def api_get(xpath: str) -> Optional[ET.Element]:
    """GET config xpath; return the <result> element, or None on failure."""
    try:
        r = requests.post(
            f"https://{TARGET_HOST}/api/",
            data={"type": "config", "action": "get", "key": API_KEY, "xpath": xpath},
            verify=False,
            timeout=60,
        )
        r.raise_for_status()
        root = ET.fromstring(r.text)
        if root.get("status") != "success":
            log.debug("api_get non-success for %s: %s", xpath, r.text[:400])
            return None
        return root.find("result")
    except Exception as exc:
        log.warning("API call failed for %s: %s", xpath, exc)
        return None


def api_op(cmd: str) -> Optional[ET.Element]:
    """Run an operational command; return the <result> element, or None."""
    try:
        r = requests.post(
            f"https://{TARGET_HOST}/api/",
            data={"type": "op", "cmd": cmd, "key": API_KEY},
            verify=False,
            timeout=60,
        )
        r.raise_for_status()
        root = ET.fromstring(r.text)
        if root.get("status") != "success":
            log.debug("api_op non-success: %s", r.text[:400])
            return None
        return root.find("result")
    except Exception as exc:
        log.debug("api_op exception: %s", exc)
        return None


def _members(entry: ET.Element, tag: str) -> list:
    node = entry.find(tag)
    if node is None:
        return []
    return [m.text for m in node.findall("member") if m.text]


# ── Input loading ─────────────────────────────────────────────────────────────

def load_servers(filepath: str) -> list:
    """Load server identifiers from .txt or .csv. Returns deduplicated list."""
    ext = os.path.splitext(filepath)[1].lower()
    seen: set = set()
    servers: list = []

    def add(s: str) -> None:
        s = s.strip()
        if s and s not in seen:
            seen.add(s)
            servers.append(s)

    with open(filepath, newline="", encoding="utf-8") as fh:
        if ext == ".csv":
            sample = fh.read(1024)
            fh.seek(0)
            has_header = csv.Sniffer().has_header(sample)
            reader = csv.reader(fh)
            if has_header:
                header = next(reader)
                lh = [h.strip().lower() for h in header]
                col = lh.index("server") if "server" in lh else 0
            else:
                col = 0
            for row in reader:
                if len(row) > col and not row[col].strip().startswith("#"):
                    add(row[col])
        else:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    add(line)
    return servers


# ── DNS resolution ────────────────────────────────────────────────────────────

def _is_ip_like(s: str) -> bool:
    try:
        ipaddress.ip_interface(s)
        return True
    except ValueError:
        return False


def resolve_server(term: str) -> tuple:
    """
    Returns (resolved_ips, resolved_names).
    For IPs: attempt reverse lookup for hostnames, resolved_ips = [].
    For hostnames/FQDNs: forward DNS for IPs, resolved_names = [].
    """
    if _is_ip_like(term):
        try:
            name = socket.gethostbyaddr(term.split("/")[0])[0]
            return [], [name]
        except Exception:
            return [], []
    else:
        try:
            infos = socket.getaddrinfo(term, None)
            ips = list(dict.fromkeys(i[4][0] for i in infos))
            return ips, []
        except Exception:
            log.warning("DNS resolution failed for: %s", term)
            return [], []


def _build_search_terms(term: str, resolved_ips: list) -> list:
    """Original term + any resolved IPs, deduplicated, order preserved."""
    idents = [term]
    for ip in resolved_ips:
        if ip not in idents:
            idents.append(ip)
    return idents


# ── Panorama config fetching ──────────────────────────────────────────────────

def fetch_dg_names() -> list:
    result = api_get(f"{_BASE}/device-group")
    if result is None:
        return []
    dg_node = result.find("device-group")
    if dg_node is None:
        dg_node = result
    return [e.get("name", "") for e in dg_node.findall("entry") if e.get("name")]


def fetch_address_objects(dg: str) -> list:
    if dg == "shared":
        xpath = "/config/shared/address"
    else:
        xpath = f"{_BASE}/device-group/entry[@name='{dg}']/address"
    result = api_get(xpath)
    if result is None:
        return []
    container = result.find("address")
    if container is None:
        container = result
    objects = []
    for entry in container.findall("entry"):
        name = entry.get("name", "")
        for otype in ("ip-netmask", "fqdn", "ip-range", "ip-wildcard"):
            node = entry.find(otype)
            if node is not None and node.text:
                objects.append(
                    AddrObject(name=name, type=otype, value=node.text.strip(), dg=dg)
                )
                break
    return objects


def fetch_address_groups(dg: str) -> list:
    if dg == "shared":
        xpath = "/config/shared/address-group"
    else:
        xpath = f"{_BASE}/device-group/entry[@name='{dg}']/address-group"
    result = api_get(xpath)
    if result is None:
        return []
    container = result.find("address-group")
    if container is None:
        container = result
    groups = []
    for entry in container.findall("entry"):
        name = entry.get("name", "")
        static = entry.find("static")
        mems = [m.text for m in (static.findall("member") if static is not None else []) if m.text]
        groups.append(AddrGroup(name=name, members=mems, dg=dg))
    return groups


def _embedded_usage(entry: ET.Element) -> Optional[str]:
    """
    Check for rule usage data embedded in the rule XML itself.
    Some PAN-OS versions include <rule-usage> or <last-hit-timestamp> in
    the running config. Returns "used", "unused", or None.
    """
    ru = entry.find("rule-usage")
    if ru is not None and ru.text:
        val = ru.text.strip().lower()
        return "unused" if val in ("unused", "0", "no", "false") else "used"
    lh = entry.find("last-hit-timestamp")
    if lh is not None and lh.text and lh.text.strip() not in ("", "0"):
        return "used"
    return None


def _parse_security_rules(dg: str, rulebase: str, result: ET.Element) -> list:
    rules_elem = result.find("rules")
    if rules_elem is None:
        return []
    rules = []
    for entry in rules_elem.findall("entry"):
        if entry.find("source") is None and entry.find("destination") is None:
            continue  # skip nested entries (e.g. hip-profiles)
        disabled_node = entry.find("disabled")
        action_node   = entry.find("action")
        rules.append({
            "name":                entry.get("name", ""),
            "dg":                  dg,
            "rulebase":            rulebase,
            "rule_type":           "security",
            "source":              _members(entry, "source"),
            "destination":         _members(entry, "destination"),
            "from":                _members(entry, "from"),
            "to":                  _members(entry, "to"),
            "application":         _members(entry, "application"),
            "service":             _members(entry, "service"),
            "action":              (action_node.text if action_node is not None else "") or "",
            "disabled":            (disabled_node.text if disabled_node is not None else "no") or "no",
            "rule_usage_embedded": _embedded_usage(entry),
        })
    return rules


def _parse_nat_rules(dg: str, rulebase: str, result: ET.Element) -> list:
    rules_elem = result.find("rules")
    if rules_elem is None:
        return []
    rules = []
    for entry in rules_elem.findall("entry"):
        src_trans = entry.find("source-translation")
        dst_trans = entry.find("destination-translation")

        # Collect translated source addresses (multiple possible sub-types)
        trans_src: list = []
        if src_trans is not None:
            for sub in src_trans.iter():
                if sub.tag == "translated-address" and sub.text:
                    trans_src.append(sub.text.strip())
                elif sub.tag == "member" and sub.text:
                    trans_src.append(sub.text.strip())
        trans_src = list(dict.fromkeys(trans_src))

        # Collect translated destination address
        trans_dst: list = []
        if dst_trans is not None:
            ta = dst_trans.find("translated-address")
            if ta is not None and ta.text:
                trans_dst.append(ta.text.strip())

        # NAT type label from source-translation child tag
        nat_type = ""
        if src_trans is not None:
            for child in src_trans:
                nat_type = child.tag
                break
        if not nat_type and dst_trans is not None:
            nat_type = "destination"

        disabled_node = entry.find("disabled")
        rules.append({
            "name":                entry.get("name", ""),
            "dg":                  dg,
            "rulebase":            rulebase,
            "rule_type":           "nat",
            "source":              _members(entry, "source"),
            "destination":         _members(entry, "destination"),
            "from":                _members(entry, "from"),
            "to":                  _members(entry, "to"),
            "translated_source":   trans_src,
            "translated_dest":     trans_dst,
            "action":              nat_type or "nat",
            "disabled":            (disabled_node.text if disabled_node is not None else "no") or "no",
            "rule_usage_embedded": _embedded_usage(entry),
        })
    return rules


def fetch_one_rule_set(dg: str, rulebase: str, rule_type: str) -> list:
    xpath = (
        f"{_BASE}/device-group/entry[@name='{dg}']"
        f"/{rulebase}-rulebase/{rule_type}/rules"
    )
    result = api_get(xpath)
    if result is None:
        return []
    if rule_type == "security":
        return _parse_security_rules(dg, rulebase, result)
    return _parse_nat_rules(dg, rulebase, result)


# ── Rule usage ────────────────────────────────────────────────────────────────

def _parse_usage_result(result: ET.Element) -> dict:
    """Parse a show rule-use result element into {rule_name: "used"|"unused"}."""
    usage = {}
    for entry in result.iter("entry"):
        name = entry.get("name", "")
        if not name:
            continue
        for child in entry:
            if child.tag in ("used", "rule-use"):
                val = (child.text or "").strip().lower()
                usage[name] = "used" if val in ("yes", "1", "true") else "unused"
                break
    return usage


def fetch_rule_usage(dg: str) -> tuple:
    """
    Return (used_names: set[str], succeeded: bool) for a DG.

    Queries Panorama for rules marked used.  Rules NOT in the returned set
    but belonging to this DG are inferred as "unused".  On query failure,
    succeeded=False and callers should fall back to embedded data or "unknown".
    """
    cmd = (
        f"<show><rule-use><rule-base>security</rule-base>"
        f"<device-group>{dg}</device-group>"
        f"<type>used</type>"
        f"</rule-use></show>"
    )
    result = api_op(cmd)
    if result is None:
        log.debug("fetch_rule_usage: query failed for DG: %s", dg)
        return set(), False

    used: set = set()
    for entry in result.iter("entry"):
        name = entry.get("name", "")
        if name:
            used.add(name)
    return used, True


# ── Cache: save / load ────────────────────────────────────────────────────────

def save_cache(
    path: str,
    dg_names: list,
    all_objects: list,
    all_groups: list,
    all_rules: list,
    used_map: dict,     # {rule_name: "used"}
    queried_dgs: set,   # DGs where the usage query succeeded
) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    payload = {
        "fetched_at":  datetime.datetime.now().isoformat(timespec="seconds"),
        "panorama":    TARGET_HOST,
        "dg_names":    dg_names,
        "objects":     [dataclasses.asdict(o) for o in all_objects],
        "groups":      [dataclasses.asdict(g) for g in all_groups],
        "rules":       all_rules,
        "used_map":    used_map,
        "queried_dgs": sorted(queried_dgs),
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    log.info("Cache saved: %s", path)


def load_cache(path: str) -> tuple:
    """Return (dg_names, all_objects, all_groups, all_rules, unused_map, queried_dgs)."""
    with open(path, encoding="utf-8") as fh:
        payload = json.load(fh)

    fetched_at = datetime.datetime.fromisoformat(payload["fetched_at"])
    age_min    = int((datetime.datetime.now() - fetched_at).total_seconds() / 60)
    log.info(
        "Using cached data from %s  (fetched %d min ago at %s, panorama=%s)",
        path, age_min, fetched_at.strftime("%Y-%m-%d %H:%M:%S"), payload.get("panorama", "?"),
    )

    all_objects = [AddrObject(**o) for o in payload["objects"]]
    all_groups  = [AddrGroup(**g) for g in payload["groups"]]
    dg_names    = payload["dg_names"]
    all_rules   = payload["rules"]
    used_map    = payload.get("used_map", {})
    queried_dgs = set(payload.get("queried_dgs", []))
    return dg_names, all_objects, all_groups, all_rules, used_map, queried_dgs


# ── Matching logic ────────────────────────────────────────────────────────────

def _ip_addr(s: str):
    try:
        return ipaddress.ip_address(s)
    except ValueError:
        return None


def _ip_net(s: str):
    try:
        return ipaddress.ip_network(s, strict=False)
    except ValueError:
        return None


def _term_matches_object(term: str, obj: AddrObject) -> bool:
    t_ip = _ip_addr(term.split("/")[0]) if _is_ip_like(term) else None

    if obj.type == "ip-netmask":
        if t_ip is None:
            return False
        net = _ip_net(obj.value)
        return net is not None and t_ip in net

    if obj.type == "fqdn":
        return term.lower() == obj.value.lower()

    if obj.type == "ip-range":
        if t_ip is None:
            return False
        parts = obj.value.split("-")
        if len(parts) != 2:
            return False
        start = _ip_addr(parts[0].strip())
        end   = _ip_addr(parts[1].strip())
        return start is not None and end is not None and start <= t_ip <= end

    if obj.type == "ip-wildcard":
        return term == obj.value

    return False


def _term_matches_member(term: str, member: str) -> bool:
    """Match a search term against a raw string member in a rule field (no object)."""
    t_ip = _ip_addr(term.split("/")[0]) if _is_ip_like(term) else None
    if t_ip is not None:
        net = _ip_net(member)
        if net:
            return t_ip in net
        m_ip = _ip_addr(member)
        return m_ip is not None and t_ip == m_ip
    return term.lower() == member.lower()


def _build_direct_index(groups: list) -> dict:
    """Return {member_name: {group_names_that_directly_contain_it}}."""
    index: dict = defaultdict(set)
    for grp in groups:
        for m in grp.members:
            index[m].add(grp.name)
    return index


def _transitive_groups(name: str, direct_index: dict) -> set:
    """All groups that transitively contain `name`."""
    result: set = set()
    queue = list(direct_index.get(name, set()))
    while queue:
        grp = queue.pop()
        if grp not in result:
            result.add(grp)
            queue.extend(direct_index.get(grp, set()))
    return result


def _match_to_row(m: RuleMatch) -> dict:
    return {
        "server_input":         m.server_input,
        "resolved_ips":         "|".join(m.resolved_ips),
        "resolved_names":       "|".join(m.resolved_names),
        "rule_type":            m.rule_type,
        "device_group":         m.device_group,
        "rulebase":             m.rulebase,
        "rule_name":            m.rule_name,
        "rule_field":           m.rule_field,
        "matched_via":          "|".join(m.matched_via),
        "match_kind":           m.match_kind,
        "current_sources":      "|".join(m.current_sources),
        "current_destinations": "|".join(m.current_destinations),
        "action":               m.action,
        "disabled":             m.disabled,
        "rule_usage":           m.rule_usage,
    }


# ── Core search ───────────────────────────────────────────────────────────────

def search_rules(
    rules:       list,
    all_idents:  dict,   # {server_input: [term, ...]}
    objects:     list,
    groups:      list,
    used_map:    dict,   # {rule_name: "used"} — rules confirmed used by Panorama
    queried_dgs: set,    # DGs where usage query succeeded; absent rule → "unused"
    dns_info:    dict,
    csv_writer,          # csv.DictWriter — match written immediately on discovery
    csv_fh,              # file handle to flush after each write
) -> list:
    # Precompute per-DG visibility indexes (objects + groups visible = own DG + shared)
    all_dgs = list({r["dg"] for r in rules})
    dg_objects: dict = {
        dg: [o for o in objects if o.dg in (dg, "shared")]
        for dg in all_dgs
    }
    dg_groups: dict = {
        dg: [g for g in groups if g.dg in (dg, "shared")]
        for dg in all_dgs
    }
    dg_direct_index: dict = {
        dg: _build_direct_index(dg_groups[dg])
        for dg in all_dgs
    }

    matches: list = []
    seen_keys: set = set()
    total     = len(rules)
    report_at = max(50, total // 10)

    for i, rule in enumerate(rules):
        if i > 0 and i % report_at == 0:
            log.info("  ... %d / %d rules scanned (%d match(es) so far)", i, total, len(matches))

        rule_dg   = rule["dg"]
        rule_id   = (rule_dg, rule["rulebase"], rule["rule_type"], rule["name"])

        # Rule usage: used query → infer unused → embedded XML → unknown
        if rule["name"] in used_map:
            usage = "used"
        elif rule_dg in queried_dgs:
            usage = "unused"
        else:
            usage = rule.get("rule_usage_embedded") or "unknown"

        vis_objs = dg_objects.get(rule_dg, [])
        vis_idx  = dg_direct_index.get(rule_dg, {})

        src_mbrs  = rule.get("source", [])
        dst_mbrs  = rule.get("destination", [])
        tsrc_mbrs = rule.get("translated_source", [])
        tdst_mbrs = rule.get("translated_dest", [])

        rule_fields = [
            ("source",                 src_mbrs),
            ("destination",            dst_mbrs),
            ("translated-source",      tsrc_mbrs),
            ("translated-destination", tdst_mbrs),
        ]

        for server_input, terms in all_idents.items():
            key = (server_input, *rule_id)
            if key in seen_keys:
                continue

            matched_via: list = []
            match_kinds: set  = set()
            hit_fields:  set  = set()

            for term in terms:
                # 1. Direct member match (raw IP/FQDN/name in rule field)
                for field_name, mbrs in rule_fields:
                    for m in mbrs:
                        if _term_matches_member(term, m):
                            if m not in matched_via:
                                matched_via.append(m)
                            match_kinds.add("direct_member")
                            hit_fields.add(field_name)

                # 2. Address object match → also check group membership
                for obj in vis_objs:
                    if not _term_matches_object(term, obj):
                        continue
                    grps      = _transitive_groups(obj.name, vis_idx)
                    all_names = {obj.name} | grps

                    for field_name, mbrs in rule_fields:
                        for m in mbrs:
                            if m not in all_names:
                                continue
                            if m not in matched_via:
                                matched_via.append(m)
                            match_kinds.add("addr_object" if m == obj.name else "addr_group")
                            hit_fields.add(field_name)

            if not hit_fields:
                continue

            seen_keys.add(key)

            has_src = bool(hit_fields & {"source", "translated-source"})
            has_dst = bool(hit_fields & {"destination", "translated-destination"})
            if has_src and has_dst:
                rule_field = "both"
            elif len(hit_fields) == 1:
                rule_field = next(iter(hit_fields))
            else:
                rule_field = "|".join(sorted(hit_fields))

            r_ips, r_names = dns_info.get(server_input, ([], []))
            m = RuleMatch(
                server_input         = server_input,
                resolved_ips         = r_ips,
                resolved_names       = r_names,
                rule_type            = rule["rule_type"],
                device_group         = rule_dg,
                rulebase             = rule["rulebase"],
                rule_name            = rule["name"],
                rule_field           = rule_field,
                matched_via          = matched_via,
                match_kind           = "+".join(sorted(match_kinds)) if match_kinds else "",
                current_sources      = src_mbrs,
                current_destinations = dst_mbrs,
                action               = rule.get("action", ""),
                disabled             = rule.get("disabled", "no"),
                rule_usage           = usage,
            )
            matches.append(m)
            csv_writer.writerow(_match_to_row(m))
            csv_fh.flush()

    return matches


# ── Output: CSV fields ────────────────────────────────────────────────────────

CSV_FIELDS = [
    "server_input", "resolved_ips", "resolved_names",
    "rule_type", "device_group", "rulebase", "rule_name", "rule_field",
    "matched_via", "match_kind",
    "current_sources", "current_destinations",
    "action", "disabled", "rule_usage",
]


# ── Output: TXT ───────────────────────────────────────────────────────────────

def _flag_str(disabled: str, usage: str) -> str:
    flags = []
    if disabled == "yes":
        flags.append("DISABLED")
    if usage == "unused":
        flags.append("UNUSED")
    return "  *** " + " + ".join(flags) + " ***" if flags else ""


def write_txt(
    matches:    list,
    input_file: str,
    started:    datetime.datetime,
    n_inputs:   int,
    n_terms:    int,
    path:       str,
) -> None:
    SEP  = "=" * 68
    THIN = "-" * 68
    SUB  = "─" * 52

    by_input: dict = {}
    for m in matches:
        by_input.setdefault(m.server_input, []).append(m)

    seen_rules:   set = set()
    all_dgs_seen: set = set()
    n_active = n_disabled = n_unused = 0

    lines = [
        SEP,
        "  SEARCH RESULTS — find-server-rules",
        f"  Input  : {os.path.basename(input_file)}",
        f"  Target : {TARGET_HOST}  (Panorama — all device groups)",
        f"  Run    : {started.strftime('%Y-%m-%d %H:%M:%S')}",
        f"  Terms  : {n_inputs} input(s) → {n_terms} search identifier(s)",
        SEP,
    ]

    for server_input, ms in by_input.items():
        r_ips   = ms[0].resolved_ips
        r_names = ms[0].resolved_names
        dns_note = ""
        if r_ips:
            dns_note = f"  →  {', '.join(r_ips)}"
        elif r_names:
            dns_note = f"  →  {', '.join(r_names)}"

        all_via = list(dict.fromkeys(v for m in ms for v in m.matched_via))

        lines += ["", f"INPUT: {server_input}{dns_note}"]
        if all_via:
            lines.append(f"  Matched via : {', '.join(all_via)}")

        for section_label, rule_type in [("SECURITY RULES", "security"), ("NAT RULES", "nat")]:
            section_ms = [m for m in ms if m.rule_type == rule_type]
            if not section_ms:
                continue

            lines += ["  " + SUB, f"  {section_label}"]

            for m in section_ms:
                rid = (m.device_group, m.rulebase, m.rule_type, m.rule_name)
                all_dgs_seen.add(m.device_group)
                flag = _flag_str(m.disabled, m.rule_usage)

                if rid not in seen_rules:
                    seen_rules.add(rid)
                    if m.disabled == "yes":
                        n_disabled += 1
                    elif m.rule_usage == "unused":
                        n_unused += 1
                    else:
                        n_active += 1

                lines += [
                    "",
                    f"  [DG: {m.device_group} | {m.rulebase}-rulebase]{flag}",
                    f"  Rule   : {m.rule_name}",
                    f"  Action : {m.action or '–'}    Disabled: {m.disabled}    Usage: {m.rule_usage}",
                    f"  Source : {', '.join(m.current_sources) or '–'}",
                    f"  Dest   : {', '.join(m.current_destinations) or '–'}",
                    f"  Match  : field={m.rule_field}  via={', '.join(m.matched_via) or 'direct'}",
                ]

    n_total  = len(seen_rules)
    uniq_sec = len({(m.device_group, m.rulebase, m.rule_name) for m in matches if m.rule_type == "security"})
    uniq_nat = len({(m.device_group, m.rulebase, m.rule_name) for m in matches if m.rule_type == "nat"})

    lines += [
        "",
        THIN,
        "SUMMARY",
        f"  Rules found    : {n_total}  ({n_active} active, {n_disabled} disabled, {n_unused} unused)",
        f"  Security rules : {uniq_sec}",
        f"  NAT rules      : {uniq_nat}",
        f"  Device groups  : {', '.join(sorted(all_dgs_seen)) or 'none'}",
        SEP,
        "",
    ]

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Find Panorama rules referencing the given servers (global search)."
    )
    parser.add_argument("input_file", help="Text or CSV file with server list")
    parser.add_argument(
        "--workers", type=int, default=8,
        help="Parallel API worker threads (default: 8)",
    )
    parser.add_argument(
        "--resume", nargs="?", const=DEFAULT_CACHE, metavar="FILE",
        help=f"Skip API fetch; use cached Panorama data (default: {DEFAULT_CACHE})",
    )
    parser.add_argument(
        "--no-save-cache", dest="save_cache", action="store_false", default=True,
        help="Do not save a cache file after fetching",
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="Enable DEBUG logging (shows raw API responses)",
    )
    args = parser.parse_args()

    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s  %(levelname)-8s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stdout,
    )
    ops_lib.setup_file_logging(SCRIPT_NAME)

    started = datetime.datetime.now()
    stem    = os.path.splitext(os.path.basename(args.input_file))[0]
    ts      = started.strftime("%Y%m%d-%H%M%S")
    os.makedirs("Output", exist_ok=True)
    csv_path = f"Output/{SCRIPT_NAME}-{stem}-{ts}.csv"
    txt_path = f"Output/{SCRIPT_NAME}-{stem}-{ts}.txt"

    # 1. Load input
    log.info("Loading servers from %s", args.input_file)
    servers = load_servers(args.input_file)
    if not servers:
        log.error("No servers found in input file.")
        sys.exit(1)
    log.info("  %d server(s) loaded", len(servers))

    # 2. DNS resolve
    log.info("Resolving DNS (%d term(s))...", len(servers))
    dns_info:   dict = {}
    all_idents: dict = {}
    total_terms = 0
    for srv in servers:
        r_ips, r_names = resolve_server(srv)
        dns_info[srv] = (r_ips, r_names)
        idents = _build_search_terms(srv, r_ips)
        all_idents[srv] = idents
        total_terms += len(idents)
        log.info(
            "  %-40s  ips=%-22s  names=%s",
            srv,
            ", ".join(r_ips) or "(none)",
            ", ".join(r_names) or "(none)",
        )

    # 3–10. Fetch Panorama data (or load from cache)
    if args.resume:
        cache_file = args.resume
        try:
            dg_names, all_objects, all_groups, all_rules, used_map, queried_dgs = load_cache(cache_file)
        except FileNotFoundError:
            log.error("Cache file not found: %s", cache_file)
            sys.exit(1)
        except Exception as exc:
            log.error("Failed to load cache: %s", exc)
            sys.exit(1)
    else:
        # 3. Enumerate device groups
        log.info("Enumerating device groups...")
        dg_names = fetch_dg_names()
        if not dg_names:
            log.error(
                "No device groups found. Is TARGET_HOST a Panorama instance? "
                "Check ops_lib.TARGET_HOST and API_KEY."
            )
            sys.exit(1)
        log.info("  %d DG(s): %s", len(dg_names), ", ".join(dg_names))

        # 4 & 5. Fetch address objects + groups in parallel (shared + all DGs)
        log.info("Fetching address objects and groups...")
        all_objects: list = []
        all_groups:  list = []
        scopes = ["shared"] + dg_names

        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
            obj_futs = {ex.submit(fetch_address_objects, dg): dg for dg in scopes}
            grp_futs = {ex.submit(fetch_address_groups,  dg): dg for dg in scopes}
            for fut in concurrent.futures.as_completed(obj_futs):
                all_objects.extend(fut.result())
            for fut in concurrent.futures.as_completed(grp_futs):
                all_groups.extend(fut.result())
        log.info("  %d address object(s), %d address group(s)", len(all_objects), len(all_groups))

        # 6–9. Fetch all security + NAT rules in parallel (pre + post, all DGs)
        log.info("Fetching rules from %d device group(s)...", len(dg_names))
        all_rules: list = []
        tasks = [
            (dg, rb, rt)
            for dg in dg_names
            for rb in ("pre", "post")
            for rt in ("security", "nat")
        ]
        dg_counts: dict = defaultdict(int)
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
            rule_futs = {
                ex.submit(fetch_one_rule_set, dg, rb, rt): (dg, rb, rt)
                for dg, rb, rt in tasks
            }
            for fut in concurrent.futures.as_completed(rule_futs):
                rules = fut.result()
                dg, rb, rt = rule_futs[fut]
                all_rules.extend(rules)
                dg_counts[dg] += len(rules)
        for dg in sorted(dg_counts):
            log.info("  %-32s : %d rule(s)", dg, dg_counts[dg])
        log.info("  %d total rule(s)", len(all_rules))

        # 10. Fetch rule usage stats per DG
        log.info("Fetching rule usage stats...")
        used_map:    dict = {}
        queried_dgs: set  = set()
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
            usage_futs = {ex.submit(fetch_rule_usage, dg): dg for dg in dg_names}
            for fut in concurrent.futures.as_completed(usage_futs):
                dg = usage_futs[fut]
                used_names, succeeded = fut.result()
                if succeeded:
                    queried_dgs.add(dg)
                    for name in used_names:
                        used_map[name] = "used"
                else:
                    log.info(
                        "  Rule usage unavailable for DG: %s (will use embedded data or 'unknown')",
                        dg,
                    )
        log.info(
            "  %d DG(s) queried successfully, %d used rule(s) identified",
            len(queried_dgs), len(used_map),
        )

        # Save cache
        if args.save_cache:
            try:
                save_cache(
                    DEFAULT_CACHE, dg_names, all_objects, all_groups,
                    all_rules, used_map, queried_dgs,
                )
            except Exception as exc:
                log.warning("Failed to save cache: %s", exc)

    # 11. Match rules — CSV written incrementally as matches are found
    log.info("Matching rules (%d total)...", len(all_rules))
    with open(csv_path, "w", newline="", encoding="utf-8") as csv_fh:
        writer = csv.DictWriter(csv_fh, fieldnames=CSV_FIELDS)
        writer.writeheader()
        csv_fh.flush()
        matches = search_rules(
            all_rules, all_idents, all_objects, all_groups,
            used_map, queried_dgs, dns_info, writer, csv_fh,
        )
    log.info("  %d match(es) found", len(matches))

    # 12. Write TXT report
    write_txt(matches, args.input_file, started, len(servers), total_terms, txt_path)

    finished = datetime.datetime.now()
    duration = str(finished - started).split(".")[0]

    print(f"\nCompleted in {duration}.")
    print(f"  Matches : {len(matches)}")
    print(f"  CSV     : {csv_path}")
    print(f"  TXT     : {txt_path}")

    if not matches:
        print(
            "\nNo matches found. Check that:\n"
            "  - Input IPs/FQDNs match actual address object values in Panorama\n"
            "  - API key has read access to device-group config\n"
            "  - TARGET_HOST in libs/ops_lib.py points to Panorama (not a direct firewall)\n"
            "  - Try --debug to see raw API responses"
        )


if __name__ == "__main__":
    main()
