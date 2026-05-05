"""
test-credentials.py — verify API credentials by fetching the first few
security rules from the target host.

Usage:
    # Firewall / vsys mode (no device group needed)
    python test-credentials.py [--vsys vsys1] [--limit N]

    # Panorama / device-group mode
    python test-credentials.py --dg DEVICE_GROUP [--rulebase pre|post] [--limit N]
"""

import argparse
import configparser
import pathlib
import sys
import xml.etree.ElementTree as ET

import requests

requests.packages.urllib3.disable_warnings()

_DEVICE = "entry[@name='localhost.localdomain']"
DEFAULT_LIMIT = 5


def load_credentials() -> tuple[str, str]:
    cfg_path = pathlib.Path.home() / ".palo" / "credentials.conf"
    if not cfg_path.exists():
        sys.exit(
            f"Error: credentials file not found at {cfg_path}\n"
            "Create it using credentials.conf.example as a template."
        )
    cfg = configparser.ConfigParser()
    cfg.read(cfg_path)
    try:
        return cfg["palo"]["firewall"], cfg["palo"]["api_key"]
    except KeyError as exc:
        sys.exit(f"Error: missing key in credentials.conf — {exc}")


def api_get(host: str, api_key: str, xpath: str) -> str:
    r = requests.post(
        f"https://{host}/api/",
        data={"type": "config", "action": "get", "key": api_key, "xpath": xpath},
        verify=False,
        timeout=15,
    )
    r.raise_for_status()
    return r.text


def panorama_rules_xpath(device_group: str, rulebase: str) -> str:
    dg = f"entry[@name='{device_group}']"
    return (
        f"/config/devices/{_DEVICE}"
        f"/device-group/{dg}"
        f"/{rulebase}-rulebase/security/rules"
    )


def firewall_rules_xpath(vsys: str) -> str:
    return (
        f"/config/devices/{_DEVICE}"
        f"/vsys/entry[@name='{vsys}']"
        f"/rulebase/security/rules"
    )


def parse_rule_names(xml_text: str) -> list[str]:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        sys.exit(f"Error: could not parse API response — {exc}\n\nRaw response:\n{xml_text}")
    return [entry.get("name", "<unnamed>") for entry in root.iter("entry")]


def main() -> None:
    parser = argparse.ArgumentParser(description="Test Panorama/firewall API credentials.")
    parser.add_argument("--dg", metavar="DEVICE_GROUP",
                        help="Panorama device group (omit for firewall/vsys mode)")
    parser.add_argument("--vsys", default="vsys1",
                        help="Vsys name for firewall mode (default: vsys1)")
    parser.add_argument("--rulebase", choices=["pre", "post"], default="pre",
                        help="Rulebase for Panorama mode (default: pre)")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT,
                        help=f"Number of rules to display (default {DEFAULT_LIMIT})")
    args = parser.parse_args()

    host, api_key = load_credentials()

    if args.dg:
        mode_label = f"panorama  DG={args.dg}  {args.rulebase}-rulebase"
        xpath = panorama_rules_xpath(args.dg, args.rulebase)
    else:
        mode_label = f"firewall  vsys={args.vsys}"
        xpath = firewall_rules_xpath(args.vsys)

    print(f"\nTarget   : {host}")
    print(f"Mode     : {mode_label}")
    print(f"Fetching : first {args.limit} security rules …\n")

    try:
        response = api_get(host, api_key, xpath)
    except requests.exceptions.ConnectionError as exc:
        sys.exit(f"Connection failed: {exc}")
    except requests.exceptions.HTTPError as exc:
        sys.exit(f"HTTP error: {exc}")
    except requests.exceptions.Timeout:
        sys.exit("Error: request timed out.")

    if 'status="error"' in response:
        # Extract the error message from the XML for readability
        try:
            root = ET.fromstring(response)
            msg_el = root.find(".//msg")
            msg = msg_el.text if msg_el is not None else response
        except ET.ParseError:
            msg = response
        sys.exit(f"API error: {msg}")

    if 'status="success"' not in response:
        sys.exit(f"Unexpected response:\n{response}")

    names = parse_rule_names(response)
    total = len(names)

    if total == 0:
        print("No security rules found in this rulebase.")
    else:
        shown = names[: args.limit]
        print(f"Rules ({total} total, showing first {len(shown)}):")
        for i, name in enumerate(shown, 1):
            print(f"  {i:>3}. {name}")
        if total > args.limit:
            print(f"  … and {total - args.limit} more")

    print("\nCredentials OK.")


if __name__ == "__main__":
    main()
