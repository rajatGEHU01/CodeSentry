import pytest

from codesentry.core.models import (
    Finding,
    Severity,
    AnalysisResult,
    DuplicationResult
)

from codesentry.core.report import (
    RepositoryReport,
    AnalysisError
)

from codesentry.core.quality_gate import (
    QualityGate,
    QualityGateConfig,
    GateStatus
)


def create_finding(severity=Severity.HIGH):

    return Finding(
        rule_id="TEST001",
        message="Test issue detected",
        severity=severity,
        file_path="sample.py",
        start_line=1,
        end_line=1,
        suggestion="Fix the detected issue"
    )


def create_report(findings=None, metrics=None):

    return RepositoryReport(
        files=[
            AnalysisResult(
                file_path="sample.py",
                language="python",
                findings=findings or [],
                metrics=metrics or {}
            )
        ]
    )


def test_clean_repository():

    report = RepositoryReport()

    result = QualityGate().evaluate(report)

    assert result.status == GateStatus.PASSED
    assert result.passed
    assert result.exit_code == 0
    assert len(result.violations) == 0


@pytest.mark.parametrize(
    "severity",
    [
        Severity.CRITICAL,
        Severity.HIGH
    ]
)
def test_security_failure(severity):

    report = create_report(
        findings=[create_finding(severity)]
    )

    result = QualityGate().evaluate(report)

    assert result.status == GateStatus.FAILED
    assert not result.passed
    assert result.exit_code == 1
    assert len(result.violations) > 0


def test_medium_allowed():

    report = create_report(
        findings=[
            create_finding(Severity.MEDIUM)
        ]
    )

    result = QualityGate().evaluate(report)

    assert result.status == GateStatus.PASSED


def test_custom_threshold():

    config = QualityGateConfig(
        max_high=1
    )

    report = create_report(
        findings=[
            create_finding(Severity.HIGH)
        ]
    )

    result = QualityGate(config).evaluate(report)

    assert result.status == GateStatus.PASSED


def test_duplication_failure():

    report = RepositoryReport(
        duplication=DuplicationResult(
            total_tokens=100,
            duplicated_tokens=30
        )
    )

    result = QualityGate().evaluate(report)

    assert result.status == GateStatus.FAILED

    assert any(
        violation.metric == "duplication"
        for violation in result.violations
    )

    violation = next(
        violation
        for violation in result.violations
        if violation.metric == "duplication"
    )

    assert violation.actual == 30.0
    assert violation.allowed == 5.0


def test_duplication_boundary():

    report = RepositoryReport(
        duplication=DuplicationResult(
            total_tokens=100,
            duplicated_tokens=5
        )
    )

    result = QualityGate().evaluate(report)

    assert result.status == GateStatus.PASSED
    assert result.passed

    # Verify that exceeding the boundary fails.

    report.duplication.duplicated_tokens = 6

    result = QualityGate().evaluate(report)

    assert result.status == GateStatus.FAILED


def test_complexity_failure():

    report = create_report(
        metrics={
            "cyclomatic": [
                {
                    "name": "complex_function",
                    "start_line": 1,
                    "end_line": 25,
                    "complexity": 20
                }
            ]
        }
    )

    result = QualityGate().evaluate(report)

    assert result.status == GateStatus.FAILED

    assert any(
        violation.metric == "cyclomatic_complexity"
        for violation in result.violations
    )


def test_analysis_error():

    report = RepositoryReport(
        errors=[
            AnalysisError(
                file_path="sample.py",
                stage="parsing",
                message="Parsing failed"
            )
        ]
    )

    result = QualityGate().evaluate(report)

    assert result.status == GateStatus.ERROR
    assert not result.passed
    assert result.exit_code == 2


def test_skipped_file():

    report = RepositoryReport(
        skipped_files={
            "large_file.cpp": "File size limit exceeded"
        }
    )

    result = QualityGate().evaluate(report)

    assert result.status == GateStatus.ERROR
    assert not result.passed


def test_invalid_configuration():

    with pytest.raises(ValueError):

        QualityGateConfig(
            max_critical=-1
        )

    with pytest.raises(ValueError):

        QualityGateConfig(
            max_duplication=101.0
        )


def test_serialization():

    report = create_report(
        findings=[
            create_finding(Severity.CRITICAL)
        ]
    )

    result = QualityGate().evaluate(report)

    data = result.to_dict()

    assert data["status"] == "failed"
    assert data["passed"] is False
    assert isinstance(data["violations"], list)
    assert len(data["violations"]) > 0

    violation = data["violations"][0]

    assert "metric" in violation
    assert "actual" in violation
    assert "allowed" in violation
    assert "message" in violation