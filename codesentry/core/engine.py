from dataclasses import asdict
from time import perf_counter

from codesentry.core.config import AnalysisConfig
from codesentry.core.report import (
    RepositoryReport,
    AnalysisError
)

from codesentry.core.models import (
    AnalysisResult,
    Finding,
    Severity,
    Token
)

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


class AnalysisEngine:

    def __init__(
        self,
        config: AnalysisConfig | None = None
    ):

        self.config = config or AnalysisConfig()

        self.parsers = {
            "cpp": CppParser(),
            "python": PythonParser()
        }

        self.duplicate_detector = DuplicateDetector(
            min_tokens=self.config.min_duplicate_tokens
        )

        self.cyclomatic = CyclomaticAnalyzer(
            threshold=self.config.cyclomatic_threshold
        )

        self.halstead = HalsteadAnalyzer(
            volume_threshold=self.config.halstead_volume_threshold
        )

        self.secret_detector = SecretDetector(
            entropy_threshold=self.config.entropy_threshold,
            min_entropy_length=self.config.min_entropy_length
        )

        self.unsafe_analyzer = UnsafeFunctionAnalyzer()

        self.sql_analyzer = SQLAnalyzer(
            dialect=self.config.sql_dialect,
            max_subquery_depth=self.config.max_subquery_depth
        )

    def run_analyzer(
        self,
        report,
        file_path,
        stage,
        operation
    ):

        try:
            return operation()

        except Exception as error:

            report.errors.append(
                AnalysisError(
                    file_path=file_path,
                    stage=stage,
                    message=type(error).__name__
                )
            )

            return None

    def analyze_file(
        self,
        file_path: str,
        source_code: str,
        report: RepositoryReport
    ) -> tuple[AnalysisResult, list[Token]]:

        language = detect_language(file_path)

        result = AnalysisResult(
            file_path=file_path,
            language=language or "unknown"
        )

        tokens = []

        # Language-independent secret detection
        if self.config.enable_secrets:

            findings = self.run_analyzer(
                report,
                file_path,
                "secrets",
                lambda: self.secret_detector.analyze(
                    source_code,
                    file_path
                )
            )

            if findings is not None:
                result.findings.extend(findings)

        # SQL analysis
        if language == "sql":

            if self.config.enable_sql:

                findings = self.run_analyzer(
                    report,
                    file_path,
                    "sql",
                    lambda: self.sql_analyzer.analyze(
                        source_code,
                        file_path
                    )
                )

                if findings is not None:

                    result.findings.extend(findings)

                    result.metrics["sql_findings"] = len(
                        findings
                    )

                    if any(
                        item.rule_id == "SQL010"
                        for item in findings
                    ):

                        report.errors.append(
                            AnalysisError(
                                file_path=file_path,
                                stage="sql",
                                message="SQL parsing failed"
                            )
                        )

            return result, tokens

        if language not in self.parsers:
            return result, tokens

        # Parse C++ or Python source
        tree = self.run_analyzer(
            report,
            file_path,
            "parser",
            lambda: self.parsers[language].parse(
                source_code
            )
        )

        if tree is None:
            return result, tokens

        if tree.root_node.has_error:

            report.errors.append(
                AnalysisError(
                    file_path=file_path,
                    stage="parser",
                    message="Source contains syntax errors"
                )
            )

            return result, tokens

        root = tree.root_node

        parsed_tokens = self.run_analyzer(
            report,
            file_path,
            "tokenizer",
            lambda: tokenize(root, source_code)
        )

        if parsed_tokens is not None:

            tokens = parsed_tokens
            result.metrics["token_count"] = len(tokens)

        # Unsafe function detection
        if self.config.enable_unsafe_functions:

            findings = self.run_analyzer(
                report,
                file_path,
                "unsafe_functions",
                lambda: self.unsafe_analyzer.analyze(
                    root,
                    source_code,
                    language,
                    file_path
                )
            )

            if findings is not None:
                result.findings.extend(findings)

        # Cyclomatic complexity
        if self.config.enable_cyclomatic:

            output = self.run_analyzer(
                report,
                file_path,
                "cyclomatic",
                lambda: self.cyclomatic.analyze(
                    root,
                    source_code,
                    language,
                    file_path
                )
            )

            if output is not None:

                metrics, findings = output

                result.metrics["cyclomatic"] = [
                    asdict(metric)
                    for metric in metrics
                ]

                result.findings.extend(findings)

        # Halstead metrics
        if (
            self.config.enable_halstead
            and parsed_tokens is not None
        ):

            output = self.run_analyzer(
                report,
                file_path,
                "halstead",
                lambda: self.halstead.analyze(
                    tokens,
                    language,
                    file_path
                )
            )

            if output is not None:

                metrics, findings = output

                result.metrics["halstead"] = asdict(
                    metrics
                )

                result.findings.extend(findings)

        return result, tokens

    def analyze_repository(
        self,
        files: dict[str, str]
    ) -> RepositoryReport:

        start_time = perf_counter()

        report = RepositoryReport()

        repository_tokens = {}
        file_results = {}

        for file_path, source_code in sorted(files.items()):

            if "\x00" in source_code:

                report.skipped_files[file_path] = (
                    "Binary content"
                )

                continue

            if (
                len(source_code.encode("utf-8"))
                > self.config.max_file_size
            ):

                report.skipped_files[file_path] = (
                    "File exceeds size limit"
                )

                continue

            result, tokens = self.analyze_file(
                file_path,
                source_code,
                report
            )

            report.files.append(result)
            file_results[file_path] = result

            if tokens:
                repository_tokens[file_path] = tokens

        # Repository-wide duplication analysis
        if self.config.enable_duplication:

            duplication = self.run_analyzer(
                report,
                "<repository>",
                "duplication",
                lambda: self.duplicate_detector.detect_repository(
                    repository_tokens
                )
            )

            if duplication is not None:

                report.duplication = duplication

                for block in duplication.blocks:

                    finding = Finding(
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

                    file_results[
                        block.duplicate_file
                    ].findings.append(finding)

        # Remove disabled rules and repeated findings
        for result in report.files:

            unique_findings = {}

            for finding in result.findings:

                if (
                    finding.rule_id
                    in self.config.disabled_rules
                ):
                    continue

                key = (
                    finding.rule_id,
                    finding.start_line,
                    finding.end_line,
                    finding.message
                )

                unique_findings[key] = finding

            result.findings = list(
                unique_findings.values()
            )

        report.duration_seconds = round(
            perf_counter() - start_time,
            4
        )

        return report