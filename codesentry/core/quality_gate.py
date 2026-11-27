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

    max_duplication: float = 5.0
    max_complexity: int = 10

    fail_on_analysis_errors: bool = True
    fail_on_skipped_files: bool = True

    def __post_init__(self):

        limits = {
            "max_critical": self.max_critical,
            "max_high": self.max_high,
            "max_medium": self.max_medium,
            "max_low": self.max_low
        }

        for name, value in limits.items():

            if value is not None and value < 0:
                raise ValueError(
                    f"{name} cannot be negative"
                )

        if not 0 <= self.max_duplication <= 100:

            raise ValueError(
                "max_duplication must be between 0 and 100"
            )

        if self.max_complexity < 1:

            raise ValueError(
                "max_complexity must be positive"
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

    @staticmethod
    def check_limit(
        violations: list[GateViolation],
        metric: str,
        actual: int | float,
        allowed: int | float | None,
        message: str
    ):

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

    def evaluate(
        self,
        report: RepositoryReport
    ) -> QualityGateResult:

        violations = []

        config = self.config

        has_analysis_error = False

        # 1. Security and severity thresholds

        counts = report.severity_counts

        severity_limits = {
            "critical": config.max_critical,
            "high": config.max_high,
            "medium": config.max_medium,
            "low": config.max_low
        }

        for severity, allowed in severity_limits.items():

            actual = counts.get(severity, 0)

            self.check_limit(
                violations=violations,
                metric=f"{severity}_findings",
                actual=actual,
                allowed=allowed,
                message=(
                    f"{severity.capitalize()} severity findings: "
                    f"{actual} detected, {allowed} allowed."
                )
            )

        # 2. Duplicate code threshold

        duplication = (
            report.duplication.duplication_percentage
        )

        self.check_limit(
            violations=violations,
            metric="duplication",
            actual=duplication,
            allowed=config.max_duplication,
            message=(
                f"Code duplication is {duplication:.2f}%, "
                f"maximum allowed is "
                f"{config.max_duplication:.2f}%."
            )
        )

        # 3. Cyclomatic complexity threshold

        for file_result in report.files:

            functions = file_result.metrics.get(
                "cyclomatic",
                []
            )

            for function in functions:

                complexity = function["complexity"]

                function_name = function.get(
                    "name",
                    "unknown"
                )

                start_line = function.get(
                    "start_line",
                    1
                )

                self.check_limit(
                    violations=violations,
                    metric="cyclomatic_complexity",
                    actual=complexity,
                    allowed=config.max_complexity,
                    message=(
                        f"Function '{function_name}' in "
                        f"{file_result.file_path}:{start_line} "
                        f"has complexity {complexity}, "
                        f"maximum allowed is "
                        f"{config.max_complexity}."
                    )
                )

        # 4. Analysis error handling

        if config.fail_on_analysis_errors:

            error_count = len(report.errors)

            if error_count > 0:

                has_analysis_error = True

                violations.append(
                    GateViolation(
                        metric="analysis_errors",
                        actual=error_count,
                        allowed=0,
                        message=(
                            f"{error_count} analysis error(s) "
                            "prevented complete verification."
                        )
                    )
                )

        # 5. Skipped file handling

        if config.fail_on_skipped_files:

            skipped_count = len(report.skipped_files)

            if skipped_count > 0:

                has_analysis_error = True

                violations.append(
                    GateViolation(
                        metric="skipped_files",
                        actual=skipped_count,
                        allowed=0,
                        message=(
                            f"{skipped_count} file(s) could "
                            "not be analyzed."
                        )
                    )
                )

        # 6. Determine final quality gate status

        if has_analysis_error:

            status = GateStatus.ERROR

        elif violations:

            status = GateStatus.FAILED

        else:

            status = GateStatus.PASSED

        return QualityGateResult(
            status=status,
            violations=violations
        )