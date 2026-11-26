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


def main():

    parsers = {
        "cpp": CppParser(),
        "python": PythonParser()
    }

    duplicate_detector = DuplicateDetector(min_tokens=20)
    cyclomatic = CyclomaticAnalyzer(threshold=10)
    halstead = HalsteadAnalyzer(volume_threshold=1000)
    secret_detector = SecretDetector()

    repository_tokens = {}
    all_findings = []

    scanned_files = 0

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

        # Security scanning is language independent
        security_findings = secret_detector.analyze(
            source,
            file_path
        )

        all_findings.extend(security_findings)

        print(f"\n{'=' * 50}")
        print(f"FILE: {file_path}")
        print(f"{'=' * 50}")

        print(
            f"Security findings: {len(security_findings)}"
        )

        if language not in parsers:
            continue

        tree = parsers[language].parse(source)

        if tree.root_node.has_error:

            print("Syntax errors detected.")
            continue

        tokens = tokenize(tree.root_node, source)

        repository_tokens[file_path] = tokens

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

        all_findings.extend(complexity_findings)
        all_findings.extend(halstead_findings)

        print("\nCYCLOMATIC COMPLEXITY")

        for function in complexity_metrics:

            print(
                f"{function.name}: "
                f"{function.complexity} "
                f"(Lines {function.start_line}-"
                f"{function.end_line})"
            )

        print("\nHALSTEAD METRICS")

        for key, value in asdict(halstead_metrics).items():
            print(f"{key}: {value}")

    duplication = duplicate_detector.detect_repository(
        repository_tokens
    )

    print("\n========== REPOSITORY SUMMARY ==========")

    print(f"Files scanned: {scanned_files}")
    print(f"Files parsed: {len(repository_tokens)}")
    print(f"Total tokens: {duplication.total_tokens}")
    print(f"Duplicated tokens: {duplication.duplicated_tokens}")
    print(f"Duplication: {duplication.duplication_percentage}%")
    print(f"Duplicate blocks: {len(duplication.blocks)}")

    for block in duplication.blocks:

        print(
            f"\nDuplicate: {block.duplicate_file}:"
            f"{block.duplicate_start}-{block.duplicate_end}"
        )

        print(
            f"Original: {block.original_file}:"
            f"{block.original_start}-{block.original_end}"
        )

        print(f"Matching tokens: {block.token_count}")

    print("\n========== ANALYSIS FINDINGS ==========")

    print(f"Total findings: {len(all_findings)}")

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

    for finding in all_findings:

        print(
            f"\n[{finding.severity.value.upper()}] "
            f"{finding.rule_id}"
        )

        print(f"File: {finding.file_path}")
        print(f"Line: {finding.start_line}")
        print(f"Message: {finding.message}")
        print(f"Suggestion: {finding.suggestion}")


if __name__ == "__main__":
    main()