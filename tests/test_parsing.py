import json
from pathlib import Path

from traffic_analysis.parsing import load_results, parse_logs, save_results


def write_log(root: Path, campaign_dir: str, app: str, phase: str, lines: list[str]) -> None:
    run_dir = root / campaign_dir / app / "run1"
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / f"{app}-Results-{phase}-mitm.log").write_text("\n".join(lines) + "\n")


def request(pii: str, host: str = "ads.example.com", port: int = 443) -> str:
    return json.dumps({"PII": pii, "host": host, "port_source": port})


def test_counts_requests_by_phase_and_pii_type(tmp_path: Path) -> None:
    write_log(
        tmp_path,
        "logging",
        "com.example.app",
        "dynamic",
        [
            request("Google_Ad_ID"),
            request("Google_Ad_ID"),
            request("Device_Model"),
            request("No-PII"),
        ],
    )
    write_log(tmp_path, "logging", "com.example.app", "idle", [request("No-PII")])

    record = parse_logs(tmp_path)["case1_logging"]["com.example.app"]

    assert record["dynamic_no_pii_count"] == 1
    assert record["dynamic_other_pii_count"] == 3
    assert record["dynamic_other_pii_values"] == {"Google_Ad_ID": 2, "Device_Model": 1}
    assert record["idle_no_pii_count"] == 1
    assert record["idle_other_pii_count"] == 0


def test_connections_are_deduplicated_but_transfers_are_not(tmp_path: Path) -> None:
    write_log(
        tmp_path,
        "loggingAppium",
        "com.example.app",
        "dynamic",
        [
            request("Google_Ad_ID", "ads.example.com", 443),
            request("Google_Ad_ID", "ads.example.com", 443),
            request("Device_Model", "stats.example.com", 8443),
        ],
    )

    record = parse_logs(tmp_path)["case1_loggingAppium"]["com.example.app"]

    assert record["dynamic_unique_domains"] == [
        ["ads.example.com", "443"],
        ["stats.example.com", "8443"],
    ]
    assert len(record["dynamic_detailed_transfers"]) == 3
    assert record["dynamic_detailed_transfers"][2] == {
        "pii_type": "Device_Model",
        "domain": "stats.example.com",
        "port": "8443",
    }


def test_skips_malformed_and_unlabelled_lines(tmp_path: Path) -> None:
    write_log(
        tmp_path,
        "loggingManual",
        "com.example.app",
        "dynamic",
        ["{not json", json.dumps({"host": "x.example.com"}), request("Email_address")],
    )

    record = parse_logs(tmp_path)["case1_loggingManual"]["com.example.app"]

    assert record["dynamic_other_pii_count"] == 1
    assert record["dynamic_no_pii_count"] == 0


def test_app_without_labelled_requests_is_left_out(tmp_path: Path) -> None:
    write_log(tmp_path, "logging", "com.example.silent", "dynamic", ["{not json"])

    assert parse_logs(tmp_path)["case1_logging"] == {}


def test_results_survive_a_round_trip(tmp_path: Path) -> None:
    write_log(tmp_path, "loggingDynVsIdle", "com.example.app", "idle", [request("Fingerprint")])
    results = parse_logs(tmp_path)
    path = tmp_path / "out" / "results.json"

    save_results(results, path)

    assert load_results(path) == results
