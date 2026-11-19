import argparse
from pathlib import Path

from system_inspector.report_generator import generate_report


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="system-inspector",
        description="Windows system security inspection tool.",
    )

    commands = parser.add_subparsers(dest="command", required=True)

    scan_command = commands.add_parser(
        "scan",
        help="Inspect the local system and generate a JSON report.",
    )
    scan_command.add_argument(
        "--output",
        type=Path,
        default=Path("reports/security-report.json"),
        help="Path where the JSON report will be saved.",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = create_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        try:
            report = generate_report(args.output)
        except (OSError, PermissionError) as error:
            print(f"Scan failed: {error}")
            return 1

        print("System inspection completed.")
        print(f"Hostname: {report['system']['hostname']}")
        print(f"Processes: {len(report['processes'])}")
        print(f"Listening ports: {len(report['listening_ports'])}")
        print(f"Report: {args.output.resolve()}")

        return 0

    return 1
