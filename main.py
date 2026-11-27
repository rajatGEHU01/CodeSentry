import argparse
import os

from pathlib import Path
from dataclasses import replace

from codesentry.core.config_loader import load_config
from codesentry.core.engine import AnalysisEngine
from codesentry.core.quality_gate import QualityGate

from codesentry.reports.console_report import ConsoleReporter
from codesentry.reports.json_report import JSONReporter


EXCLUDED_DIRECTORIES = {
    ".git",
    "venv",
    ".venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".vscode",
    "build",
    "dist",
    "reports_output"
}


SUPPORTED_EXTENSIONS = {
    ".cpp", ".cc", ".cxx",
    ".hpp", ".hh", ".hxx",
    ".py", ".sql",
    ".json", ".yaml", ".yml",
    ".env", ".ini", ".toml",
    ".cfg", ".txt", ".pem", ".key"
}


def load_files(directory: Path, max_file_size: int):

    files = {}
    skipped = {}

    for root, directories, filenames in os.walk(directory):

        directories[:] = sorted(
            name
            for name in directories
            if name not in EXCLUDED_DIRECTORIES
            and not (Path(root) / name).is_symlink()
        )

        for filename in sorted(filenames):

            path = Path(root) / filename

            relative_path = path.relative_to(
                directory
            ).as_posix()

            if (
                path.suffix.lower()
                not in SUPPORTED_EXTENSIONS
                and not filename.startswith(".env")
            ):

                continue

            if path.is_symlink():

                skipped[relative_path] = "Symbolic link"
                continue

            try:

                if path.stat().st_size > max_file_size:

                    skipped[relative_path] = (
                        "File exceeds size limit"
                    )

                    continue

                with path.open("rb") as file:

                    content = file.read(max_file_size + 1)

                if len(content) > max_file_size:

                    skipped[relative_path] = (
                        "File exceeds size limit"
                    )

                    continue

                files[relative_path] = content.decode(
                    "utf-8"
                )

            except (OSError, UnicodeDecodeError):

                skipped[relative_path] = (
                    "Unreadable or non-UTF-8 file"
                )

    return files, skipped


def display_quality_gate(result):

    print("\n" + "=" * 55)
    print("                 QUALITY GATE")
    print("=" * 55)

    print(f"STATUS: {result.status.value.upper()}")

    if result.passed:

        print("All quality requirements satisfied.")
        return

    print(
        f"Total violations: {len(result.violations)}"
    )

    for violation in result.violations:

        print(f"\nMetric: {violation.metric}")
        print(f"Actual: {violation.actual}")
        print(f"Allowed: {violation.allowed}")
        print(f"Reason: {violation.message}")


def main():

    parser = argparse.ArgumentParser(
        description="CodeSentry Static Analysis Engine"
    )

    parser.add_argument(
        "directory",
        nargs="?",
        default="samples"
    )

    parser.add_argument(
        "--output",
        default="reports_output/analysis.json"
    )

    parser.add_argument(
        "--config",
        default=".codesentry.json"
    )

    parser.add_argument(
        "--complexity",
        type=int,
        default=None
    )

    parser.add_argument(
        "--min-tokens",
        type=int,
        default=None
    )

    parser.add_argument(
        "--sql-dialect",
        default=None
    )

    parser.add_argument(
        "--disable-rule",
        action="append",
        default=[]
    )

    parser.add_argument(
        "--report-only",
        action="store_true",
        help="Do not fail on quality violations"
    )

    args = parser.parse_args()

    directory = Path(args.directory)

    if not directory.is_dir():

        parser.error(
            f"Directory does not exist: {directory}"
        )

    try:

        config, gate_config = load_config(args.config)

        overrides = {}

        if args.complexity is not None:

            overrides["cyclomatic_threshold"] = (
                args.complexity
            )

        if args.min_tokens is not None:

            overrides["min_duplicate_tokens"] = (
                args.min_tokens
            )

        if args.sql_dialect is not None:

            overrides["sql_dialect"] = args.sql_dialect

        if args.disable_rule:

            overrides["disabled_rules"] = (
                config.disabled_rules
                | frozenset(args.disable_rule)
            )

        config = replace(config, **overrides)

    except (ValueError, TypeError, OSError) as error:

        parser.error(
            f"Invalid configuration: {type(error).__name__}"
        )

    files, skipped = load_files(
        directory,
        config.max_file_size
    )

    engine = AnalysisEngine(config)

    report = engine.analyze_repository(files)

    report.skipped_files.update(skipped)

    quality_gate = QualityGate(gate_config)

    gate_result = quality_gate.evaluate(report)

    ConsoleReporter.display(report)

    display_quality_gate(gate_result)

    output = JSONReporter.save(
        report,
        args.output,
        gate_result
    )

    print(f"\nJSON report saved: {output}")

    if args.report_only and gate_result.exit_code == 1:

        return 0

    return gate_result.exit_code


if __name__ == "__main__":

    raise SystemExit(main())