"""Aggregate the raw traffic logs of every capture campaign into one results file.

Each capture produces JSON-lines logs, one line per intercepted request. A line
carries a ``PII`` field with the type of personal data found in the request
(``No-PII`` when there is none) and the ``host`` and ``port_source`` it was sent to.
"""

import json
import re
from pathlib import Path
from typing import Any

Results = dict[str, dict[str, dict[str, Any]]]

PHASES = ("dynamic", "idle")
NO_PII = "No-PII"

# Sub-directory of the logs root that holds each capture campaign.
CAMPAIGN_DIRS = {
    "case1_logging": "logging",
    "case1_loggingAppium": "loggingAppium",
    "case1_loggingManual": "loggingManual",
    "case2_loggingAuthMonkey": "loggingAuthMonkey",
    "case2_loggingAuthManual": "loggingAuthManual",
    "case3_loggingDynVsIdle": "loggingDynVsIdle",
}

_HOST = re.compile(r'"host": "([^"]+)"')
_PORT = re.compile(r'"port_source": (\d+)')


def new_app_record() -> dict[str, Any]:
    """Return the empty per-app record, with one block of fields per phase."""
    record: dict[str, Any] = {}
    for phase in PHASES:
        record[f"{phase}_no_pii_count"] = 0
        record[f"{phase}_other_pii_count"] = 0
        record[f"{phase}_other_pii_values"] = {}
        record[f"{phase}_unique_domains"] = []
        record[f"{phase}_detailed_transfers"] = []
    return record


def process_log_file(path: Path, apps: dict[str, dict[str, Any]], app: str, phase: str) -> int:
    """Add the requests logged in ``path`` to the record of ``app``.

    The record is created on the first labelled request, so an app whose logs
    contain no labelled request never appears in the results. Returns the number
    of lines that could not be decoded.
    """
    malformed = 0
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                malformed += 1
                continue
            if not isinstance(entry, dict) or "PII" not in entry:
                continue

            record = apps.setdefault(app, new_app_record())
            pii_type = entry["PII"]
            if pii_type == NO_PII:
                record[f"{phase}_no_pii_count"] += 1
                continue

            record[f"{phase}_other_pii_count"] += 1
            by_type = record[f"{phase}_other_pii_values"]
            by_type[pii_type] = by_type.get(pii_type, 0) + 1

            connections = record[f"{phase}_unique_domains"]
            for host in _HOST.findall(line):
                for port in _PORT.findall(line):
                    if [host, port] not in connections:
                        connections.append([host, port])
                    record[f"{phase}_detailed_transfers"].append(
                        {"pii_type": pii_type, "domain": host, "port": port}
                    )
    return malformed


def parse_logs(logs_root: Path) -> Results:
    """Walk every campaign directory under ``logs_root`` and aggregate its logs.

    Logs are expected at ``<campaign>/<app>/<run>/*-Results-<phase>-mitm.log``.
    """
    results: Results = {}
    for campaign, subdir in CAMPAIGN_DIRS.items():
        apps = results.setdefault(campaign, {})
        for path in sorted((logs_root / subdir).rglob("*-mitm.log")):
            app = path.parent.parent.name
            for phase in PHASES:
                if path.name.endswith(f"-Results-{phase}-mitm.log"):
                    malformed = process_log_file(path, apps, app, phase)
                    if malformed:
                        print(f"{path}: skipped {malformed} malformed line(s)")
    return results


def load_results(path: Path) -> Results:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def save_results(results: Results, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=2)
        handle.write("\n")
