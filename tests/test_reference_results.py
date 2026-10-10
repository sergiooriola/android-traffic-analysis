"""Regression tests: the shipped dataset must keep producing the reference numbers."""

from pathlib import Path

import pytest

from traffic_analysis import metrics, plots
from traffic_analysis.cases import CASES, CASES_BY_KEY
from traffic_analysis.parsing import load_results

DATA = Path(__file__).resolve().parents[1] / "data" / "results.json"

# (case, group) -> (apps, PII transfers, unique transfers, PII types, connections, domains)
EXPECTED = {
    ("case1", "Exerciser Monkey"): (18, 128, 51, 6, 26, 13),
    ("case1", "Appium"): (18, 105, 52, 5, 32, 16),
    ("case1", "Manual"): (19, 242, 79, 7, 44, 18),
    ("case2", "Not authenticated"): (5, 29, 17, 4, 10, 9),
    ("case2", "Authenticated"): (5, 286, 71, 7, 37, 27),
    ("case3", "Dynamic"): (20, 194, 86, 6, 46, 23),
    ("case3", "Idle"): (20, 196, 108, 8, 55, 26),
}


@pytest.fixture(scope="module")
def results() -> dict:
    return load_results(DATA)


@pytest.mark.parametrize(("case_key", "group"), EXPECTED)
def test_summary_matches_reference_numbers(results: dict, case_key: str, group: str) -> None:
    row = metrics.summary(results, CASES_BY_KEY[case_key]).loc[group]

    columns = ["apps", "pii_transfers", "unique_transfers", "pii_types", "connections", "domains"]
    assert tuple(int(row[column]) for column in columns) == EXPECTED[(case_key, group)]


def test_email_addresses_only_leave_authenticated_sessions(results: dict) -> None:
    table = metrics.pii_type_counts(results, CASES_BY_KEY["case2"])

    assert table.loc["Email_address", "Authenticated"] == 27
    assert table.loc["Email_address", "Not authenticated"] == 0


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.key)
def test_every_figure_is_drawn(results: dict, case, tmp_path: Path) -> None:
    written = [
        plots.plot_summary(metrics.summary(results, case), case, tmp_path / "summary.png"),
        plots.plot_pii_types(
            metrics.pii_type_counts(results, case), case, tmp_path / "pii_types.png"
        ),
        plots.plot_pii_types_by_app(
            metrics.pii_type_counts_by_app(results, case), case, tmp_path / "by_app.png"
        ),
    ]

    assert all(path.stat().st_size > 0 for path in written)
