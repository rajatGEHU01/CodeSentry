from dataclasses import dataclass, field

from pathlib import Path

from codesentry.core.engine import AnalysisEngine
from codesentry.core.config import AnalysisConfig

from codesentry.core.report import (
    RepositoryReport,
    AnalysisError
)

from codesentry.core.quality_gate import (
    QualityGate,
    QualityGateConfig,
    QualityGateResult
)

from codesentry.github.client import GitHubClient
from codesentry.github.events import PullRequestEvent

from codesentry.github.diff_parser import (
    DiffParser,
    DiffResult
)


@dataclass
class PullRequestAnalysis:

    event: PullRequestEvent

    report: RepositoryReport

    gate: QualityGateResult

    changed_files: int

    analyzed_files: int

    diffs: dict[str, DiffResult] = field(
        default_factory=dict
    )

    @property
    def findings(self):

        return self.report.findings

    def to_dict(self):

        return {
            "repository": self.event.full_repository_name,

            "pull_request": self.event.pull_number,

            "head_sha": self.event.head_sha,

            "changed_files": self.changed_files,

            "analyzed_files": self.analyzed_files,

            "analysis": self.report.to_dict(),

            "quality_gate": self.gate.to_dict()
        }


class PullRequestAnalyzer:

    SUPPORTED_EXTENSIONS = {
        ".cpp",
        ".cc",
        ".cxx",
        ".hpp",
        ".hh",
        ".hxx",
        ".py",
        ".sql",
        ".json",
        ".yaml",
        ".yml",
        ".env",
        ".ini",
        ".toml",
        ".cfg",
        ".txt",
        ".pem",
        ".key"
    }

    EXCLUDED_DIRECTORIES = {
        "venv",
        ".venv",
        "node_modules",
        "__pycache__",
        ".git",
        "build",
        "dist"
    }

    MAX_FILES = 300

    MAX_TOTAL_BYTES = 10_000_000

    def __init__(
        self,
        analysis_config: AnalysisConfig | None = None,
        gate_config: QualityGateConfig | None = None
    ):

        self.config = (
            analysis_config or AnalysisConfig()
        )

        self.gate_config = (
            gate_config or QualityGateConfig()
        )

        self.diff_parser = DiffParser()

    def is_supported(self, file_path: str) -> bool:

        path = Path(file_path)

        if any(
            part in self.EXCLUDED_DIRECTORIES
            for part in path.parts
        ):

            return False

        return (
            path.suffix.lower()
            in self.SUPPORTED_EXTENSIONS
            or path.name.startswith(".env")
        )

    def analyze(
        self,
        github: GitHubClient,
        event: PullRequestEvent
    ) -> PullRequestAnalysis:

        changed_files = github.get_pull_request_files(
            event.owner,
            event.repository,
            event.pull_number
        )

        sources = {}
        diffs = {}
        errors = []
        skipped = {}

        total_bytes = 0

        candidates = [
            file
            for file in changed_files
            if file.get("status") != "removed"
            and self.is_supported(file["filename"])
        ]

        if len(changed_files) >= 3000:

            errors.append(
                AnalysisError(
                    file_path="",
                    stage="pr_files",
                    message="PR file listing may be incomplete"
                )
            )

        if len(candidates) > self.MAX_FILES:

            errors.append(
                AnalysisError(
                    file_path="",
                    stage="pr_files",
                    message="PR analysis file limit exceeded"
                )
            )

        for file in candidates[:self.MAX_FILES]:

            file_path = file["filename"]

            if file.get("additions", 0) == 0:

                continue

            diff = self.diff_parser.parse(
                file.get("patch")
            )

            if (
                not diff.complete
                or len(diff.added_lines)
                != file.get("additions", 0)
                or len(diff.deleted_lines)
                != file.get("deletions", 0)
            ):

                errors.append(
                    AnalysisError(
                        file_path=file_path,
                        stage="diff",
                        message="Missing or incomplete patch"
                    )
                )

                continue

            try:

                # Fetch the exact PR commit.
                # Never fetch from a moving branch.

                source = github.get_file_content(
                    event.owner,
                    event.repository,
                    file_path,
                    event.head_sha
                )

                source_size = len(
                    source.encode("utf-8")
                )

                if source_size > self.config.max_file_size:

                    skipped[file_path] = (
                        "File size limit exceeded"
                    )

                    continue

                if (
                    total_bytes + source_size
                    > self.MAX_TOTAL_BYTES
                ):

                    skipped[file_path] = (
                        "Total PR size limit exceeded"
                    )

                    continue

                sources[file_path] = source

                diffs[file_path] = diff

                total_bytes += source_size

            except Exception as error:

                errors.append(
                    AnalysisError(
                        file_path=file_path,
                        stage="fetch_source",
                        message=type(error).__name__
                    )
                )

        engine = AnalysisEngine(self.config)

        report = engine.analyze_repository(sources)

        report.errors.extend(errors)

        report.skipped_files.update(skipped)

        # Detect PR updates that occurred during analysis.

        current_pr = github.get_pull_request(
            event.owner,
            event.repository,
            event.pull_number
        )

        if (
            current_pr["head"]["sha"] != event.head_sha
            or current_pr["base"]["sha"] != event.base_sha
        ):

            raise RuntimeError(
                "Pull request changed during analysis"
            )

        # Keep findings that overlap newly added lines.

        for result in report.files:

            diff = diffs.get(result.file_path)

            if diff is None:

                result.findings = []
                continue

            result.findings = [
                finding
                for finding in result.findings
                if diff.intersects(
                    finding.start_line,
                    finding.end_line
                )
            ]

        quality_gate = QualityGate(
            self.gate_config
        )

        gate_result = quality_gate.evaluate(report)

        return PullRequestAnalysis(
            event=event,
            report=report,
            gate=gate_result,
            changed_files=len(changed_files),
            analyzed_files=len(report.files),
            diffs=diffs
        )