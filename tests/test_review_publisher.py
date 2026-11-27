from types import SimpleNamespace

from codesentry.core.models import Finding, Severity

from codesentry.github.diff_parser import DiffResult

from codesentry.github.review_publisher import (
    ReviewPublisher
)


def create_finding(
    line=5,
    severity=Severity.HIGH,
    rule="PY001"
):

    return Finding(
        rule_id=rule,
        message="Unsafe function detected",
        severity=severity,
        file_path="test.py",
        start_line=line,
        end_line=line,
        suggestion="Use a safer alternative"
    )


def create_analysis(findings, added_lines):

    return SimpleNamespace(
        findings=findings,
        diffs={
            "test.py": DiffResult(
                added_lines=set(added_lines)
            )
        }
    )


def test_inline_comment():

    analysis = create_analysis(
        [create_finding()],
        {5}
    )

    comments = ReviewPublisher().build_comments(
        analysis
    )

    assert len(comments) == 1

    assert comments[0]["line"] == 5

    assert comments[0]["side"] == "RIGHT"

    assert comments[0]["path"] == "test.py"

    assert "PY001" in comments[0]["body"]


def test_unchanged_line_ignored():

    analysis = create_analysis(
        [create_finding(line=5)],
        {10}
    )

    comments = ReviewPublisher().build_comments(
        analysis
    )

    assert comments == []


def test_duplicate_comments_removed():

    finding = create_finding()

    analysis = create_analysis(
        [finding, finding],
        {5}
    )

    comments = ReviewPublisher().build_comments(
        analysis
    )

    assert len(comments) == 1


def test_severity_priority():

    analysis = create_analysis(
        [
            create_finding(
                line=5,
                severity=Severity.LOW
            ),

            create_finding(
                line=6,
                severity=Severity.CRITICAL
            )
        ],
        {5, 6}
    )

    comments = ReviewPublisher().build_comments(
        analysis
    )

    assert comments[0]["line"] == 6


def test_comment_limit():

    findings = [
        create_finding(line=i)
        for i in range(1, 51)
    ]

    analysis = create_analysis(
        findings,
        range(1, 51)
    )

    comments = ReviewPublisher().build_comments(
        analysis
    )

    assert len(comments) == 30


def test_empty_findings():

    analysis = create_analysis(
        [],
        {5}
    )

    assert (
        ReviewPublisher().build_comments(analysis)
        == []
    )


def test_recommended_fix():

    finding = create_finding()

    comment = ReviewPublisher().build_comment(
        finding
    )

    assert "How to fix" in comment

    assert "Use a safer alternative" in comment


def test_incomplete_diff():

    analysis = create_analysis(
        [create_finding()],
        {5}
    )

    analysis.diffs["test.py"].complete = False

    assert (
        ReviewPublisher().build_comments(analysis)
        == []
    )


def test_missing_diff():

    analysis = SimpleNamespace(
        findings=[create_finding()],
        diffs={}
    )

    assert (
        ReviewPublisher().build_comments(analysis)
        == []
    )