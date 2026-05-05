"""
ops_detail.py — optional dry-run detail reporting for ops-* scripts

When DRY_RUN_DETAIL = True in a calling script, call fetch_details() before
the update workers to pre-fetch each rule's current field value.  The returned
dict is attached to the results list so write_summary() can print a
before → after line under each rule entry.

Import this module at the top of each ops-*.py and gate usage with the
DRY_RUN_DETAIL variable:

    import ops_detail
    DRY_RUN_DETAIL = True   # set False to skip pre-fetching

    if args.dry_run and DRY_RUN_DETAIL:
        detail_map = ops_detail.fetch_details(
            rule_names, field="destination", workers=args.workers
        )
"""

import concurrent.futures
import logging
import xml.etree.ElementTree as ET

import ops_lib as lib

log = logging.getLogger(__name__)


def get_members(xpath: str) -> list[str]:
    """
    Fetch an element at xpath and return the text of every <member> child.
    Returns an empty list on API error or parse failure.
    """
    result = lib.api_get(xpath)
    try:
        root = ET.fromstring(result)
        return [m.text for m in root.iter("member") if m.text]
    except ET.ParseError:
        return []


def fetch_details(
    rule_names: list[str],
    field: str,
    extra_note: str = "",
    workers: int = 1,
) -> dict[str, str]:
    """
    For each rule in rule_names, fetch the current members of <field>
    (either "source" or "destination") and build a before → after string.

    Args:
        rule_names:  ordered list of rule names to inspect
        field:       "source" or "destination"
        extra_note:  appended to each detail line, e.g. "  +  negate-source=yes"
        workers:     parallel threads to use for API calls

    Returns:
        dict mapping rule_name → detail string
    """
    def _fetch(name: str) -> tuple[str, str]:
        rule_xpath = f"{lib.rules_xpath()}/entry[@name='{name}']"
        current    = get_members(f"{rule_xpath}/{field}")
        was        = ", ".join(current) if current else "any"
        detail     = f"{field}: [{was}]  →  {lib.RFC1918_GROUP}{extra_note}"
        return name, detail

    detail_map: dict[str, str] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(_fetch, name): name for name in rule_names}
        for future in concurrent.futures.as_completed(futures):
            name, detail = future.result()
            detail_map[name] = detail
            log.info("  [fetched] %s", name)

    return detail_map
