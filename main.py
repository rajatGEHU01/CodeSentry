from pathlib import Path
from dataclasses import asdict

from codesentry.parsers.cpp_parser import CppParser
from codesentry.parsers.python_parser import PythonParser
from codesentry.parsers.language_detector import detect_language
from codesentry.parsers.tokenizer import tokenize

from codesentry.analyzers.duplicate import DuplicateDetector
from codesentry.analyzers.cyclomatic import CyclomaticAnalyzer
from codesentry.analyzers.halstead import HalsteadAnalyzer


def main():

    parsers = {
        "cpp": CppParser(),
        "python": PythonParser()
    }

    duplicate_detector = DuplicateDetector(min_tokens=20)

    cyclomatic = CyclomaticAnalyzer(threshold=10)

    halstead = HalsteadAnalyzer(volume_threshold=1000)

    repository_tokens = {}
    all_findings = []

    for path in sorted(Path("samples").rglob("*")):

        if not path.is_file():
            continue

        file_path = path.as_posix()
        language = detect_language(file_path)

        if language not in parsers:
            continue

        source = path.read_text(encoding="utf-8")
        tree = parsers[language].parse(source)

        if tree.root_node.has_error:
            print(f"Skipping invalid syntax: {file_path}")
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

        print(f"\n{'=' * 50}")
        print(f"FILE: {file_path}")
        print(f"{'=' * 50}")

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

    print(f"Files analyzed: {len(repository_tokens)}")
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

    print("\n========== QUALITY FINDINGS ==========")

    print(f"Complexity findings: {len(all_findings)}")

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