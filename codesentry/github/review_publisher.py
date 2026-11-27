import hashlib
import json
import logging

from codesentry.github.report_format import (
    issue_title,
    render_summary,
    safe
)
from codesentry.github.client import GitHubClient
from codesentry.github.pr_analyzer import PullRequestAnalysis


logger = logging.getLogger("codesentry.review")


class ReviewPublisher:

    MAX_COMMENTS = 30

    SEVERITY_ORDER = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4
    }

    SEVERITY_ICONS = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🔵",
        "info": "⚪"
    }

    def get_review_endpoint(
        self,
        analysis: PullRequestAnalysis
    ) -> str:

        event = analysis.event

        return (
            f"/repos/{event.owner}/{event.repository}"
            f"/pulls/{event.pull_number}/reviews"
        )

    def generate_marker(
        self,
        analysis: PullRequestAnalysis
    ) -> str:

        findings = [
            {
                "rule": finding.rule_id,
                "path": finding.file_path,
                "start": finding.start_line,
                "end": finding.end_line,
                "severity": finding.severity.value,
                "message": finding.message,
                "suggestion": finding.suggestion
            }
            for finding in analysis.findings
        ]

        data = {
            "head": analysis.event.head_sha,
            "base": analysis.event.base_sha,
            "findings": findings,
            "gate": analysis.gate.to_dict()
        }

        serialized = json.dumps(
            data,
            sort_keys=True,
            ensure_ascii=False
        )

        fingerprint = hashlib.sha256(
            serialized.encode("utf-8")
        ).hexdigest()

        return (
            f"<!-- codesentry-review:{fingerprint} -->"
        )

    @staticmethod
    def safe_text(value, limit=1500):

        return safe(value, limit)

    def build_comment(self, finding) -> str:

        severity = finding.severity.value

        icon = self.SEVERITY_ICONS.get(
            severity,
            "⚪"
        )

        title = safe(issue_title(finding))

        rule = safe(finding.rule_id)

        recommendation = (
            finding.suggestion
            or "Review the affected code."
        )

        body = [
            f"### {icon} {title}",
            "",
            "| Property | Details |",
            "|---|---|",
            f"| Severity | **{severity.upper()}** |",
            f"| Rule | `{rule}` |",
            f"| File | {safe(finding.file_path, 250)} |",
            f"| Line | {finding.start_line} |",
            "",
            "#### Problem",
            "",
            safe(finding.message, 1500),
            "",
            "#### How to fix",
            "",
            safe(recommendation, 1500),
            ""
        ]

        if severity in ("critical", "high"):

            body.extend([
                "> This potential issue should be "
                "reviewed before merging.",
                ""
            ])

        body.extend([
            "---",
            "",
            "*Detected by CodeSentry Static Analysis Engine*"
        ])

        return "\n".join(body)

    def build_comments(
        self,
        analysis: PullRequestAnalysis
    ) -> list[dict]:

        comments = []
        seen = set()

        findings = sorted(
            analysis.findings,
            key=lambda finding: (
                self.SEVERITY_ORDER.get(
                    finding.severity.value,
                    99
                ),
                finding.file_path,
                finding.start_line,
                finding.rule_id
            )
        )

        for finding in findings:

            if len(comments) >= self.MAX_COMMENTS:
                break

            diff = analysis.diffs.get(
                finding.file_path
            )

            if diff is None or not diff.complete:
                continue

            matching_lines = sorted(
                line
                for line in diff.added_lines
                if (
                    finding.start_line
                    <= line
                    <= finding.end_line
                )
            )

            if not matching_lines:
                continue

            target_line = matching_lines[0]

            key = (
                finding.file_path,
                target_line,
                finding.rule_id
            )

            if key in seen:
                continue

            seen.add(key)

            comments.append({
                "path": finding.file_path,
                "line": target_line,
                "side": "RIGHT",
                "body": self.build_comment(finding)
            })

        return comments

    def build_summary(
        self,
        analysis: PullRequestAnalysis,
        comment_count: int
    ) -> str:

        total = len(analysis.findings)

        lines = [
            render_summary(analysis),
            "",
            "---",
            "",
            "## Review Coverage",
            "",
            "| Review metric | Result |",
            "|---|---:|",
            f"| Total findings | {total} |",
            f"| Inline comments | {comment_count} |",
            (
                f"| Findings without separate "
                f"inline comments | "
                f"{max(0, total - comment_count)} |"
            ),
            ""
        ]

        if total > comment_count:

            lines.extend([
                "Inline comments are limited to "
                "eligible changed lines and the "
                "configured comment limit.",
                ""
            ])

        lines.extend([
            "## Developer Next Steps",
            ""
        ])

        status = analysis.gate.status.value

        if status == "passed":

            lines.extend([
                "The configured quality gate has passed.",
                "",
                "Review any remaining findings "
                "before merging.",
                ""
            ])

        elif status == "error":

            lines.extend([
                "Analysis coverage is incomplete.",
                "",
                "Review the reported errors and "
                "retry the analysis.",
                ""
            ])

        else:

            lines.extend([
                "1. Review the reported findings.",
                "2. Apply the recommended corrections.",
                "3. Commit and push the updated code.",
                "4. CodeSentry will reanalyze the pull request.",
                "5. Verify the updated quality gate result.",
                ""
            ])

        lines.extend([
            "---",
            "",
            "*Automated static analysis powered by CodeSentry.*"
        ])

        summary = "\n".join(lines)

        marker = self.generate_marker(analysis)

        return summary[:60000] + "\n\n" + marker

    def already_published(
        self,
        github: GitHubClient,
        analysis: PullRequestAnalysis
    ) -> bool:

        marker = self.generate_marker(analysis)

        app = github.auth.get_app()

        bot_login = f"{app['slug']}[bot]"

        reviews = github.paginate(
            self.get_review_endpoint(analysis)
        )

        for review in reviews:

            user = review.get("user") or {}

            if user.get("login") != bot_login:
                continue

            if (
                review.get("commit_id")
                != analysis.event.head_sha
            ):
                continue

            if marker in (review.get("body") or ""):
                return True

        return False

    def publish(
        self,
        github: GitHubClient,
        analysis: PullRequestAnalysis
    ) -> dict | None:

        event = analysis.event

        if self.already_published(github, analysis):

            logger.info(
                "Identical review already published"
            )

            return None

        current_pr = github.get_pull_request(
            event.owner,
            event.repository,
            event.pull_number
        )

        if (
            current_pr["head"]["sha"] != event.head_sha
            or current_pr["base"]["sha"] != event.base_sha
            or current_pr.get("state") != "open"
            or current_pr.get("draft")
        ):

            logger.info(
                "Skipping outdated or inactive PR review"
            )

            return None

        comments = self.build_comments(analysis)

        summary = self.build_summary(
            analysis,
            len(comments)
        )

        payload = {
            "commit_id": event.head_sha,
            "body": summary,
            "event": "COMMENT"
        }

        if comments:

            payload["comments"] = comments

        response = github.request(
            "POST",
            self.get_review_endpoint(analysis),
            json=payload
        )

        logger.info(
            "GitHub review published | ID: %s | Comments: %s",
            response.get("id"),
            len(comments)
        )

        return response