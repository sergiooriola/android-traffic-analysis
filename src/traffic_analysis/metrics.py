"""Tables computed from the aggregated results, one function per analysis."""

from typing import Any

import pandas as pd

from traffic_analysis.cases import Case, Group
from traffic_analysis.parsing import Results


def _apps(results: Results, group: Group) -> dict[str, dict[str, Any]]:
    return results.get(group.campaign, {})


def summary(results: Results, case: Case) -> pd.DataFrame:
    """One row per group with the headline counts of the case.

    The port logged with each request is the client's source port, so a
    (domain, port) pair identifies a connection rather than a server endpoint:

    - ``connections`` adds up the distinct (domain, source port) pairs of each app.
    - ``unique_transfers`` counts the distinct (PII type, domain, source port)
      combinations across the whole group.
    - ``domains`` counts the distinct domains that received personal data.
    """
    rows = []
    for group in case.groups:
        apps = _apps(results, group).values()
        phase = group.phase
        transfers = sum(app[f"{phase}_other_pii_count"] for app in apps)
        connections = sum(len(app[f"{phase}_unique_domains"]) for app in apps)
        pii_types = set().union(*(app[f"{phase}_other_pii_values"] for app in apps))
        domains = {domain for app in apps for domain, _ in app[f"{phase}_unique_domains"]}
        unique_transfers = {
            (transfer["pii_type"], transfer["domain"], str(transfer["port"]))
            for app in apps
            for transfer in app[f"{phase}_detailed_transfers"]
        }
        rows.append(
            {
                "group": group.label,
                "apps": len(apps),
                "pii_transfers": transfers,
                "unique_transfers": len(unique_transfers),
                "pii_types": len(pii_types),
                "domains": len(domains),
                "connections": connections,
                "transfers_per_connection": transfers / connections if connections else 0.0,
            }
        )
    return pd.DataFrame(rows).set_index("group")


def pii_type_counts(results: Results, case: Case) -> pd.DataFrame:
    """Transfers of each PII type (rows) in each group (columns), most frequent first."""
    columns = {}
    for group in case.groups:
        counts: dict[str, int] = {}
        for app in _apps(results, group).values():
            for pii_type, count in app[f"{group.phase}_other_pii_values"].items():
                counts[pii_type] = counts.get(pii_type, 0) + count
        columns[group.label] = counts
    table = pd.DataFrame(columns).fillna(0).astype(int)
    table.index.name = "pii_type"
    order = table.sum(axis=1).sort_values(ascending=False, kind="stable").index
    return table.loc[order]


def pii_type_counts_by_app(results: Results, case: Case) -> dict[str, pd.DataFrame]:
    """Per group, transfers of each PII type (columns) by each app (rows).

    Every table shares the same apps and PII types, filled with zeros, so the
    groups of a case can be compared cell by cell.
    """
    pii_types = list(pii_type_counts(results, case).index)
    apps = sorted({app for group in case.groups for app in _apps(results, group)})
    tables = {}
    for group in case.groups:
        records = _apps(results, group)
        counts = [records.get(app, {}).get(f"{group.phase}_other_pii_values", {}) for app in apps]
        table = pd.DataFrame(
            [[by_type.get(pii_type, 0) for pii_type in pii_types] for by_type in counts],
            index=pd.Index(apps, name="app"),
            columns=pii_types,
        )
        tables[group.label] = table
    return tables
