"""
ops_lib.py — shared library for ops-* rule update scripts

Configure the TARGET, MODE, and DEVICE_GROUP / VSYS below before running
any ops-* script.  All four ops scripts import this module directly.
"""

import configparser
import csv
import datetime
import logging
import os
import pathlib

import requests
import xml.etree.ElementTree as ET

requests.packages.urllib3.disable_warnings()


def _load_credentials() -> tuple[str, str]:
    cfg_path = pathlib.Path.home() / ".palo" / "credentials.conf"
    if not cfg_path.exists():
        raise FileNotFoundError(
            f"credentials.conf not found at {cfg_path}\n"
            "Create ~/.palo/credentials.conf using credentials.conf.example as a template."
        )
    cfg = configparser.ConfigParser()
    cfg.read(cfg_path)
    return cfg["palo"]["firewall"], cfg["palo"]["api_key"]


# ── Connection / targeting ────────────────────────────────────────────────────
TARGET_HOST, API_KEY = _load_credentials()

# ── Mode ──────────────────────────────────────────────────────────────────────
# "firewall"  → target is a standalone firewall or NGFW directly
# "panorama"  → target is Panorama; rules live in a device group
MODE         = "firewall"

# Firewall mode: vsys name
VSYS         = "vsys1"

# Panorama mode: device group name and which rulebase the rules are in
DEVICE_GROUP = "DG-Example"
RULEBASE     = "pre"          # "pre" or "post"

# ── XPath builders ────────────────────────────────────────────────────────────
_DEVICE = "entry[@name='localhost.localdomain']"


def _config_base() -> str:
    """Base config xpath: either vsys or device-group depending on MODE."""
    if MODE == "panorama":
        return (
            f"/config/devices/{_DEVICE}"
            f"/device-group/entry[@name='{DEVICE_GROUP}']"
        )
    return (
        f"/config/devices/{_DEVICE}"
        f"/vsys/entry[@name='{VSYS}']"
    )


def rules_xpath() -> str:
    if MODE == "panorama":
        return f"{_config_base()}/{RULEBASE}-rulebase/security/rules"
    return f"{_config_base()}/rulebase/security/rules"


def address_xpath(obj_name: str) -> str:
    """
    Address objects in Panorama live in /config/shared so all device groups
    can reference them.  On a direct firewall they live in the vsys.
    """
    if MODE == "panorama":
        return f"/config/shared/address/entry[@name='{obj_name}']"
    return f"{_config_base()}/address/entry[@name='{obj_name}']"


def address_group_xpath(group_name: str) -> str:
    if MODE == "panorama":
        return f"/config/shared/address-group/entry[@name='{group_name}']"
    return f"{_config_base()}/address-group/entry[@name='{group_name}']"


# ── Raw API helpers ───────────────────────────────────────────────────────────
log = logging.getLogger(__name__)


def _post(params: dict) -> str:
    r = requests.post(
        f"https://{TARGET_HOST}/api/",
        data=params,
        verify=False,
        timeout=30,
    )
    r.raise_for_status()
    return r.text


def api_get(xpath: str) -> str:
    return _post({"type": "config", "action": "get", "key": API_KEY, "xpath": xpath})


def api_set(xpath: str, element: str) -> str:
    """Merge/add element at xpath (does not replace siblings)."""
    return _post(
        {"type": "config", "action": "set", "key": API_KEY,
         "xpath": xpath, "element": element}
    )


def api_edit(xpath: str, element: str) -> str:
    """Replace the element AT xpath entirely with the provided XML."""
    return _post(
        {"type": "config", "action": "edit", "key": API_KEY,
         "xpath": xpath, "element": element}
    )


def is_success(xml_text: str) -> bool:
    return 'status="success"' in xml_text


def object_exists(xpath: str) -> bool:
    result = api_get(xpath)
    return 'status="error"' not in result and "<entry" in result


# ── Input file loader ─────────────────────────────────────────────────────────

def load_rule_names(filepath: str) -> list[str]:
    """
    Load rule names from a .txt or .csv file.

    .txt  — one rule name per line; lines starting with '#' are skipped.
    .csv  — looks for a 'rule_name' column header (matches detect-any-rules.py
            output).  If no such header exists, uses the first column.

    Returns a deduplicated list preserving input order.
    """
    ext = os.path.splitext(filepath)[1].lower()
    seen: set[str] = set()
    names: list[str] = []

    def _add(name: str) -> None:
        name = name.strip()
        if name and name not in seen:
            seen.add(name)
            names.append(name)

    with open(filepath, newline="", encoding="utf-8") as fh:
        if ext == ".csv":
            sample = fh.read(1024)
            fh.seek(0)
            has_header = csv.Sniffer().has_header(sample)
            reader = csv.reader(fh)
            if has_header:
                header = next(reader)
                header_lower = [h.strip().lower() for h in header]
                col = (
                    header_lower.index("rule_name")
                    if "rule_name" in header_lower
                    else 0
                )
                for row in reader:
                    if len(row) > col and not row[col].strip().startswith("#"):
                        _add(row[col])
            else:
                for row in reader:
                    if row and not row[0].strip().startswith("#"):
                        _add(row[0])
        else:
            # .txt or anything else
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    _add(line)

    return names


# ── Mode summary (used by each script's header) ───────────────────────────────

def mode_summary() -> str:
    if MODE == "panorama":
        return f"panorama  DG={DEVICE_GROUP}  rulebase={RULEBASE}-rulebase"
    return f"firewall  vsys={VSYS}"


# ── Run logging ───────────────────────────────────────────────────────────────

def setup_file_logging(script_name: str) -> str:
    """
    Add a timestamped file handler to the root logger so all log output
    (from both the calling script and ops_lib) is captured to disk.

    Returns the path of the log file created.
    """
    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    log_path  = f"{script_name}-{timestamp}.log"

    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter("%(asctime)s  %(levelname)-8s %(message)s",
                                      datefmt="%Y-%m-%d %H:%M:%S"))
    logging.getLogger().addHandler(fh)
    return log_path


def write_summary(
    log_path:    str,
    script_name: str,
    started:     datetime.datetime,
    finished:    datetime.datetime,
    input_file:  str,
    action_desc: str,
    dry_run:     bool,
    results:     list[dict],   # [{"rule": str, "result": "updated"|"skipped"|"failed"}, ...]
) -> None:
    """
    Append a structured, human-readable summary block to the log file.
    Also prints the summary to stdout so it appears on the console.
    """
    counts = {"updated": 0, "skipped": 0, "failed": 0}
    for r in results:
        counts[r["result"]] += 1
    total    = sum(counts.values())
    duration = finished - started
    sep      = "=" * 62
    thin     = "-" * 62

    lines = [
        "",
        sep,
        "  RUN SUMMARY",
        thin,
        f"  Script   : {script_name}",
        f"  Started  : {started.strftime('%Y-%m-%d %H:%M:%S')}",
        f"  Finished : {finished.strftime('%Y-%m-%d %H:%M:%S')}",
        f"  Duration : {str(duration).split('.')[0]}",
        f"  Target   : {TARGET_HOST}",
        f"  Mode     : {mode_summary()}",
        f"  Input    : {input_file}",
        f"  Action   : {action_desc}",
        f"  Dry run  : {'Yes' if dry_run else 'No'}",
        thin,
        "  RESULTS BY RULE",
    ]

    for r in results:
        status = r["result"].upper().ljust(8)
        lines.append(f"  {status}  {r['rule']}")
        if r.get("detail"):
            lines.append(f"             └─ {r['detail']}")

    lines += [
        thin,
        "  TOTALS",
        f"  Updated  : {counts['updated']}",
        f"  Skipped  : {counts['skipped']}",
        f"  Failed   : {counts['failed']}",
        f"  Total    : {total}",
        sep,
        "",
    ]

    block = "\n".join(lines)

    # Write to log file (appended alongside verbose log output)
    with open(log_path, "a", encoding="utf-8") as fh:
        fh.write(block)

    # Also print to console
    print(block)
