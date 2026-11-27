import pytest

from codesentry.core.models import (
    AnalysisResult,
    Finding,
    Severity,
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


def make_report(severity):

    finding = Finding(
        rule_id="TEST001",
        message="Test finding",
        severity=severity,
        file_path="test.py",
        start_line=1,
        end_line=1
    )

    return RepositoryReport(
        files=[
            AnalysisResult(
                file_path="test.py",
                language="python",
                findings=[finding]
            )
        ]
    )


def test_clean_repository():

    result = QualityGate().evaluate(
        RepositoryReport()
    )

    assert result.status == GateStatus.PASSED
    assert result.passed
    assert result.exit_code == 0


@pytest.mark.parametrize(
    "severity",
    [Severity.CRITICAL, Severity.HIGH]
)
def test_security_failure(severity):

    result = QualityGate().evaluate(
        make_report(severity)
    )

    assert result.status == GateStatus.FAILED
    assert result.exit_code == 1


def test_medium_allowed():

    result = QualityGate().evaluate(
        make_report(Severity.MEDIUM)
    )

    assert result.passed


def test_custom_threshold():

    config = QualityGateConfig(max_medium=0)

    result = QualityGate(config).evaluate(
        make_report(Severity.MEDIUM)
    )

    assert not result.passed


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
        violation.metric == "duplication_percentage"
        for violation in result.violations
    )


def test_duplication_boundary():

    report = RepositoryReport(
        duplication=DuplicationResult(
            total_tokens=100,
            duplicated_tokens=15
        )
    )

    assert QualityGate().evaluate(report).passed


def test_complexity_failure():

    report = RepositoryReport(
        files=[
            AnalysisResult(
                file_path="test.py",
                language="python",
                metrics={
                    "cyclomatic": [
                        {
                            "name": "calculate",
                            "start_line": 1,
                            "end_line": 30,
                            "complexity": 20
                        }
                    ]
                }
            )
        ]
    )

    result = QualityGate().evaluate(report)

    assert not result.passed

    assert any(
        violation.metric == "cyclomatic_complexity"
        for violation in result.violations
    )


def test_analysis_error():

    report = RepositoryReport(
        errors=[
            AnalysisError(
                file_path="test.py",
                stage="parser",
                message="Invalid syntax"
            )
        ]
    )

    result = QualityGate().evaluate(report)

    assert result.status == GateStatus.ERROR
    assert result.exit_code == 2


def test_skipped_file():

    report = RepositoryReport(
        skipped_files={
            "large.py": "File exceeds size limit"
        }
    )

    result = QualityGate().evaluate(report)

    assert result.status == GateStatus.ERROR


def test_invalid_configuration():

    with pytest.raises(ValueError):

        QualityGateConfig(max_duplication=120)


def test_serialization():

    result = QualityGate().evaluate(
        make_report(Severity.HIGH)
    )

    data = result.to_dict()

    assert data["status"] == "failed"
    assert data["passed"] is False
    assert len(data["violations"]) == 1