"""Command-line entry point: ``parse`` the raw logs, ``report`` on the results."""

import argparse
from collections.abc import Sequence
from pathlib import Path

from traffic_analysis import metrics, plots
from traffic_analysis.cases import CASES_BY_KEY
from traffic_analysis.parsing import load_results, parse_logs, save_results

DEFAULT_DATA = Path("data/results.json")


def _parse(args: argparse.Namespace) -> int:
    if not args.logs_root.is_dir():
        print(f"error: {args.logs_root} is not a directory")
        return 1
    results = parse_logs(args.logs_root)
    save_results(results, args.output)
    apps = sum(len(campaign) for campaign in results.values())
    print(f"Wrote {args.output}: {apps} app captures in {len(results)} campaigns")
    return 0


def _report(args: argparse.Namespace) -> int:
    results = load_results(args.data)
    for key in args.cases or sorted(CASES_BY_KEY):
        case = CASES_BY_KEY[key]
        summary = metrics.summary(results, case)
        by_type = metrics.pii_type_counts(results, case)
        by_app = metrics.pii_type_counts_by_app(results, case)

        print(f"\n{case.title}\n{'=' * len(case.title)}")
        print(summary.to_string(float_format="{:.2f}".format))
        print(f"\nTransfers by PII type\n{by_type.to_string()}")

        written = [
            plots.plot_summary(summary, case, args.out / f"{key}_summary.png"),
            plots.plot_pii_types(by_type, case, args.out / f"{key}_pii_types.png"),
            plots.plot_pii_types_by_app(by_app, case, args.out / f"{key}_pii_types_by_app.png"),
        ]
        print("\nFigures: " + ", ".join(str(path) for path in written))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="traffic-analysis",
        description="Analyse personal data transfers in Android app network traffic.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    parse = commands.add_parser("parse", help="aggregate raw capture logs into a results file")
    parse.add_argument("logs_root", type=Path, help="directory with one folder per campaign")
    parse.add_argument("--output", type=Path, default=DEFAULT_DATA)
    parse.set_defaults(run=_parse)

    report = commands.add_parser("report", help="print the tables and draw the figures")
    report.add_argument("--data", type=Path, default=DEFAULT_DATA)
    report.add_argument("--out", type=Path, default=Path("figures"))
    report.add_argument(
        "--case",
        action="append",
        choices=sorted(CASES_BY_KEY),
        dest="cases",
        help="case to report on; repeat for several (default: all)",
    )
    report.set_defaults(run=_report)

    args = parser.parse_args(argv)
    return args.run(args)
