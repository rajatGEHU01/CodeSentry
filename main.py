from pathlib import Path
from dataclasses import asdict

from codesentry.parsers.cpp_parser import CppParser
from codesentry.parsers.python_parser import PythonParser
from codesentry.parsers.language_detector import detect_language
from codesentry.parsers.tokenizer import tokenize

from codesentry.analyzers.duplicate import DuplicateDetector
from codesentry.analyzers.cyclomatic import CyclomaticAnalyzer
from codesentry.analyzers.halstead import HalsteadAnalyzer
from codesentry.analyzers.secrets import SecretDetector
from codesentry.analyzers.unsafe_functions import UnsafeFunctionAnalyzer
from codesentry.analyzers.sql_analyzer import SQLAnalyzer

from codesentry.core.models import Finding, Severity


def main():

    parsers = {
        "cpp": CppParser(),
        "python": PythonParser()
    }

    duplicate_detector = DuplicateDetector(min_tokens=20)
    cyclomatic = CyclomaticAnalyzer(threshold=10)
    halstead = HalsteadAnalyzer(volume_threshold=1000)

    secret_detector = SecretDetector()
    unsafe_analyzer = UnsafeFunctionAnalyzer()

    sql_analyzer = SQLAnalyzer(
        dialect=None,
        max_subquery_depth=2
    )

    repository_tokens = {}
    all_findings = []

    scanned_files = 0
    parsed_files = 0

    for path in sorted(Path("samples").rglob("*")):

        if not path.is_file():
            continue

        file_path = path.as_posix()
        language = detect_language(file_path)

        try:
            source = path.read_text(encoding="utf-8")

        except (UnicodeDecodeError, OSError):
            continue

        scanned_files += 1

        print(f"\n{'=' * 50}")
        print(f"FILE: {file_path}")
        print(f"{'=' * 50}")

        security_findings = secret_detector.analyze(
            source,
            file_path
        )

        all_findings.extend(security_findings)

        # SQL analysis
        if language == "sql":

            sql_findings = sql_analyzer.analyze(
                source,
                file_path
            )

            all_findings.extend(sql_findings)

            if not any(
                finding.rule_id == "SQL010"
                for finding in sql_findings
            ):
                parsed_files += 1

            print(f"SQL findings: {len(sql_findings)}")
            continue

        # C++ and Python analysis
        if language not in parsers:
            continue

        tree = parsers[language].parse(source)

        if tree.root_node.has_error:

            print("Syntax errors detected.")
            continue

        parsed_files += 1

        tokens = tokenize(
            tree.root_node,
            source
        )

        repository_tokens[file_path] = tokens

        unsafe_findings = unsafe_analyzer.analyze(
            tree.root_node,
            source,
            language,
            file_path
        )

        complexity_metrics, complexity_findings = (
            cyclomatic.analyze(
                tree.root_node,
                source,
                language,
                file_path
            )
        )

        halstead_metrics, halstead_findings = (
            halstead.analyze(
                tokens,
                language,
                file_path
            )
        )

        all_findings.extend(unsafe_findings)
        all_findings.extend(complexity_findings)
        all_findings.extend(halstead_findings)

        print(
            f"Security findings: "
            f"{len(security_findings) + len(unsafe_findings)}"
        )

        print("\nCYCLOMATIC COMPLEXITY")

        for function in complexity_metrics:

            print(
                f"{function.name}: "
                f"{function.complexity}"
            )

        print("\nHALSTEAD METRICS")

        for key, value in asdict(halstead_metrics).items():

            print(f"{key}: {value}")

    # Repository-wide duplication
    duplication = duplicate_detector.detect_repository(
        repository_tokens
    )

    for block in duplication.blocks:

        all_findings.append(
            Finding(
                rule_id="DUP001",
                message=(
                    f"Potential duplicate block of "
                    f"{block.token_count} tokens. "
                    f"Original: {block.original_file}:"
                    f"{block.original_start}"
                ),
                severity=Severity.MEDIUM,
                file_path=block.duplicate_file,
                start_line=block.duplicate_start,
                end_line=block.duplicate_end,
                suggestion=(
                    "Extract common logic into "
                    "a reusable function."
                )
            )
        )

    severity_order = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4
    }

    all_findings.sort(
        key=lambda finding: (
            severity_order[finding.severity.value],
            finding.file_path,
            finding.start_line
        )
    )

    print("\n========== REPOSITORY SUMMARY ==========")

    print(f"Files scanned: {scanned_files}")
    print(f"Files parsed: {parsed_files}")
    print(f"C++/Python tokens: {duplication.total_tokens}")
    print(f"Duplicated tokens: {duplication.duplicated_tokens}")
    print(f"Duplication: {duplication.duplication_percentage}%")
    print(f"Duplicate blocks: {len(duplication.blocks)}")
    print(f"Total findings: {len(all_findings)}")

    print("\n========== SEVERITY SUMMARY ==========")

    for severity in Severity:

        count = sum(
            finding.severity == severity
            for finding in all_findings
        )

        print(f"{severity.value.upper()}: {count}")

    print("\n========== ANALYSIS FINDINGS ==========")

    for finding in all_findings:

        print(
            f"\n[{finding.severity.value.upper()}] "
            f"{finding.rule_id}"
        )

        print(f"File: {finding.file_path}")
        print(f"Lines: {finding.start_line}-{finding.end_line}")
        print(f"Message: {finding.message}")
        print(f"Suggestion: {finding.suggestion}")


if __name__ == "__main__":
    main()