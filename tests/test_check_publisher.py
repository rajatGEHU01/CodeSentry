from types import SimpleNamespace
from unittest.mock import Mock

from codesentry.core.models import Finding, Severity
from codesentry.core.report import RepositoryReport

from codesentry.github.diff_parser import DiffResult

from codesentry.github.check_publisher import (
    CheckPublisher
)


def create_event():

    return SimpleNamespace(
        owner="test-user",
        repository="test-repo",
        pull_number=1,
        head_sha="a" * 40,
        base_sha="b" * 40
    )


def create_finding(
    severity=Severity.HIGH,
    line=5
):

    return Finding(
        rule_id="PY001",
        message="Unsafe function detected",
        severity=severity,
        file_path="test.py",
        start_line=line,
        end_line=line,
        suggestion="Use a safe alternative"
    )


def create_analysis(
    findings=None,
    status="failed"
):

    return SimpleNamespace(
        event=create_event(),

        findings=findings or [],

        diffs={
            "test.py": DiffResult(
                added_lines=set(range(1, 101))
            )
        },

        report=RepositoryReport(),

        changed_files=1,

        analyzed_files=1,

        gate=SimpleNamespace(
            status=SimpleNamespace(value=status),
            violations=[],
            passed=status == "passed"
        )
    )


def test_create_check():

    github = Mock()

    github.request.return_value = {"id": 123}

    publisher = CheckPublisher()

    check_id = publisher.create_check(
        github,
        create_event()
    )

    assert check_id == 123

    payload = github.request.call_args.kwargs["json"]

    assert payload["status"] == "in_progress"

    assert payload["name"] == publisher.CHECK_NAME


def test_high_severity_annotation():

    analysis = create_analysis(
        [create_finding()]
    )

    annotations = CheckPublisher().build_annotations(
        analysis
    )

    assert len(annotations) == 1

    assert annotations[0]["annotation_level"] == "failure"

    assert annotations[0]["start_line"] == 5


def test_medium_severity_annotation():

    analysis = create_analysis(
        [create_finding(Severity.MEDIUM)]
    )

    annotations = CheckPublisher().build_annotations(
        analysis
    )

    assert annotations[0]["annotation_level"] == "warning"


def test_low_severity_annotation():

    analysis = create_analysis(
        [create_finding(Severity.LOW)]
    )

    annotations = CheckPublisher().build_annotations(
        analysis
    )

    assert annotations[0]["annotation_level"] == "notice"


def test_annotation_limit():

    findings = [
        create_finding(line=i)
        for i in range(1, 81)
    ]

    analysis = create_analysis(findings)

    annotations = CheckPublisher().build_annotations(
        analysis
    )

    assert len(annotations) == 50


def test_duplicate_annotations():

    finding = create_finding()

    analysis = create_analysis(
        [finding, finding]
    )

    annotations = CheckPublisher().build_annotations(
        analysis
    )

    assert len(annotations) == 1


def test_unchanged_line_ignored():

    analysis = create_analysis(
        [create_finding(line=200)]
    )

    annotations = CheckPublisher().build_annotations(
        analysis
    )

    assert annotations == []


def test_passed_check():

    github = Mock()

    analysis = create_analysis(status="passed")

    CheckPublisher().complete_check(
        github,
        123,
        analysis
    )

    payload = github.request.call_args.kwargs["json"]

    assert payload["conclusion"] == "success"

    assert payload["status"] == "completed"


def test_failed_check():

    github = Mock()

    analysis = create_analysis(status="failed")

    CheckPublisher().complete_check(
        github,
        123,
        analysis
    )

    payload = github.request.call_args.kwargs["json"]

    assert payload["conclusion"] == "failure"


def test_analysis_error_check():

    github = Mock()

    analysis = create_analysis(status="error")

    CheckPublisher().complete_check(
        github,
        123,
        analysis
    )

    payload = github.request.call_args.kwargs["json"]

    assert payload["conclusion"] == "failure"


def test_fail_check():

    github = Mock()

    CheckPublisher().fail_check(
        github,
        create_event(),
        123,
        "RuntimeError"
    )

    payload = github.request.call_args.kwargs["json"]

    assert payload["conclusion"] == "failure"

    assert payload["status"] == "completed"


def test_cancel_check():

    github = Mock()

    CheckPublisher().cancel_check(
        github,
        create_event(),
        123
    )

    payload = github.request.call_args.kwargs["json"]

    assert payload["conclusion"] == "cancelled"


def test_incomplete_diff():

    analysis = create_analysis(
        [create_finding()]
    )

    analysis.diffs["test.py"].complete = False

    assert (
        CheckPublisher().build_annotations(analysis)
        == []
    )