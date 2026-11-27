from dataclasses import dataclass, field, asdict

from codesentry.core.models import (
    AnalysisResult,
    DuplicationResult,
    Finding,
    Severity
)


@dataclass
class AnalysisError:

    file_path: str
    stage: str
    message: str


@dataclass
class RepositoryReport:

    files: list[AnalysisResult] = field(
        default_factory=list
    )

    duplication: DuplicationResult = field(
        default_factory=DuplicationResult
    )

    errors: list[AnalysisError] = field(
        default_factory=list
    )

    skipped_files: dict[str, str] = field(
        default_factory=dict
    )

    duration_seconds: float = 0.0

    @property
    def findings(self) -> list[Finding]:

        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4
        }

        findings = [
            finding
            for result in self.files
            for finding in result.findings
        ]

        return sorted(
            findings,
            key=lambda item: (
                severity_order[item.severity],
                item.file_path,
                item.start_line,
                item.rule_id
            )
        )

    @property
    def severity_counts(self) -> dict[str, int]:

        counts = {
            severity.value: 0
            for severity in Severity
        }

        for finding in self.findings:
            counts[finding.severity.value] += 1

        return counts

    def to_dict(self) -> dict:

        return {
            "summary": {
                "files_analyzed": len(self.files),
                "files_skipped": len(self.skipped_files),
                "total_findings": len(self.findings),
                "severity_counts": self.severity_counts,
                "analysis_errors": len(self.errors),
                "duration_seconds": self.duration_seconds
            },

            "duplication": {
                **asdict(self.duplication),
                "duplication_percentage":
                    self.duplication.duplication_percentage
            },

            "files": [
                asdict(result)
                for result in self.files
            ],

            "findings": [
                asdict(finding)
                for finding in self.findings
            ],

            "errors": [
                asdict(error)
                for error in self.errors
            ],

            "skipped_files": self.skipped_files
        }