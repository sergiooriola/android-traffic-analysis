from traffic_analysis import metrics
from traffic_analysis.cases import Case, Group
from traffic_analysis.parsing import new_app_record

CASE = Case(
    key="demo",
    title="Demo",
    factor="Phase",
    groups=(Group("Dynamic", "campaign", "dynamic"), Group("Idle", "campaign", "idle")),
)


def app_record(phase: str, transfers: list[tuple[str, str, str]]) -> dict:
    """Build a record the way the parser would from (pii_type, domain, port) requests."""
    record = new_app_record()
    for pii_type, domain, port in transfers:
        record[f"{phase}_other_pii_count"] += 1
        by_type = record[f"{phase}_other_pii_values"]
        by_type[pii_type] = by_type.get(pii_type, 0) + 1
        if [domain, port] not in record[f"{phase}_unique_domains"]:
            record[f"{phase}_unique_domains"].append([domain, port])
        record[f"{phase}_detailed_transfers"].append(
            {"pii_type": pii_type, "domain": domain, "port": port}
        )
    return record


RESULTS = {
    "campaign": {
        "app.one": app_record(
            "dynamic",
            [
                ("Google_Ad_ID", "ads.example.com", "443"),
                ("Google_Ad_ID", "ads.example.com", "443"),
                ("Device_Model", "stats.example.com", "443"),
            ],
        ),
        "app.two": app_record("dynamic", [("Google_Ad_ID", "ads.example.com", "443")]),
    }
}


def test_summary_counts_each_group() -> None:
    table = metrics.summary(RESULTS, CASE)

    dynamic = table.loc["Dynamic"]
    assert dynamic["apps"] == 2
    assert dynamic["pii_transfers"] == 4
    assert dynamic["pii_types"] == 2
    assert dynamic["domains"] == 2
    # The same (domain, port) pair seen in two apps counts once per app...
    assert dynamic["connections"] == 3
    # ...but the same (type, domain, port) is a single unique transfer.
    assert dynamic["unique_transfers"] == 2
    assert dynamic["transfers_per_connection"] == 4 / 3


def test_summary_of_a_group_without_transfers_is_all_zeros() -> None:
    idle = metrics.summary(RESULTS, CASE).loc["Idle"]

    assert idle["pii_transfers"] == 0
    assert idle["domains"] == 0
    assert idle["connections"] == 0
    assert idle["transfers_per_connection"] == 0.0


def test_pii_type_counts_are_sorted_and_zero_filled() -> None:
    table = metrics.pii_type_counts(RESULTS, CASE)

    assert list(table.index) == ["Google_Ad_ID", "Device_Model"]
    assert table["Dynamic"].tolist() == [3, 1]
    assert table["Idle"].tolist() == [0, 0]


def test_by_app_tables_share_apps_and_pii_types() -> None:
    tables = metrics.pii_type_counts_by_app(RESULTS, CASE)

    assert list(tables) == ["Dynamic", "Idle"]
    for table in tables.values():
        assert list(table.index) == ["app.one", "app.two"]
        assert list(table.columns) == ["Google_Ad_ID", "Device_Model"]
    assert tables["Dynamic"].loc["app.one"].tolist() == [2, 1]
    assert tables["Idle"].to_numpy().sum() == 0
