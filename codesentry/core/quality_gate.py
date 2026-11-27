from dataclasses import dataclass, field, asdict
from enum import Enum

from codesentry.core.report import RepositoryReport


class GateStatus(str, Enum):

    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"


@dataclass(frozen=True)
class QualityGateConfig:

    max_critical: int = 0
    max_high: int = 0
    max_medium: int = 10
    max_low: int | None = None

    max_duplication: float = 15.0
    max_complexity: int = 15

    fail_on_analysis_errors: bool = True
    fail_on_skipped_files: bool = True

    def __post_init__(self):

        limits = [
            self.max_critical,
            self.max_high,
            self.max_medium,
            self.max_low
        ]

        for limit in limits:

            if limit is not None and limit < 0:
                raise ValueError(
                    "Finding limits cannot be negative"
                )

        if not 0 <= self.max_duplication <= 100:

            raise ValueError(
                "Duplication limit must be between 0 and 100"
            )

        if self.max_complexity < 1:

            raise ValueError(
                "Complexity limit must be positive"
            )


@dataclass
class GateViolation:

    metric: str
    actual: int | float
    allowed: int | float
    message: str


@dataclass
class QualityGateResult:

    status: GateStatus

    violations: list[GateViolation] = field(
        default_factory=list
    )

    @property
    def passed(self) -> bool:

        return self.status == GateStatus.PASSED

    @property
    def exit_code(self) -> int:

        return {
            GateStatus.PASSED: 0,
            GateStatus.FAILED: 1,
            GateStatus.ERROR: 2
        }[self.status]

    def to_dict(self) -> dict:

        return {
            "status": self.status.value,
            "passed": self.passed,
            "violations": [
                asdict(violation)
                for violation in self.violations
            ]
        }


class QualityGate:

    def __init__(
        self,
        config: QualityGateConfig | None = None
    ):

        self.config = config or QualityGateConfig()

    def evaluate(
        self,
        report: RepositoryReport
    ) -> QualityGateResult:

        violations = []
        incomplete_analysis = False

        def check(metric, actual, allowed, message):

            if allowed is None:
                return

            if actual > allowed:

                violations.append(
                    GateViolation(
                        metric=metric,
                        actual=actual,
                        allowed=allowed,
                        message=message
                    )
                )

        # Severity-based gates

        counts = report.severity_counts

        severity_limits = {
            "critical": self.config.max_critical,
            "high": self.config.max_high,
            "medium": self.config.max_medium,
            "low": self.config.max_low
        }

        for severity, allowed in severity_limits.items():

            check(
                metric=f"{severity}_findings",
                actual=counts[severity],
                allowed=allowed,
                message=(
                    f"{severity.upper()} findings "
                    "exceed the allowed limit."
                )
            )

        # Duplication gate

        check(
            metric="duplication_percentage",
            actual=report.duplication.duplication_percentage,
            allowed=self.config.max_duplication,
            message="Code duplication exceeds the allowed limit."
        )

        # Function-level complexity gate

        for result in report.files:

            functions = result.metrics.get(
                "cyclomatic", []
            )

            for function in functions:

                name = function["name"]
                complexity = function["complexity"]
                line = function["start_line"]

                check(
                    metric="cyclomatic_complexity",
                    actual=complexity,
                    allowed=self.config.max_complexity,
                    message=(
                        f"{result.file_path}:{line} - "
                        f"Function {name} exceeds "
                        "the complexity limit."
                    )
                )

        # Analysis completeness

        if (
            self.config.fail_on_analysis_errors
            and report.errors
        ):

            incomplete_analysis = True

            check(
                metric="analysis_errors",
                actual=len(report.errors),
                allowed=0,
                message="Analysis could not complete successfully."
            )

        if (
            self.config.fail_on_skipped_files
            and report.skipped_files
        ):

            incomplete_analysis = True

            check(
                metric="skipped_files",
                actual=len(report.skipped_files),
                allowed=0,
                message="Some source files could not be analyzed."
            )

        if incomplete_analysis:

            status = GateStatus.ERROR

        elif violations:

            status = GateStatus.FAILED

        else:

            status = GateStatus.PASSED

        return QualityGateResult(
            status=status,
            violations=violations
        )