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
        "high": "🔴",
        "medium": "🟠",
        "low": "🟡",
        "info": "🔵"
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

        text = str(value)[:limit]

        return (
            text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("@", "@\u200b")
        )

    def build_comment(self, finding) -> str:

        severity = finding.severity.value

        icon = self.SEVERITY_ICONS.get(
            severity,
            "⚪"
        )

        body = [
            f"{icon} **{safe(issue_title(finding))}**"
            f" — {severity.upper()}",

            "",

            "**Problem**",

            safe(finding.message, 1500)
        ]

        if finding.suggestion:

            body.extend([
                "",

                "**How to fix**",

                safe(finding.suggestion, 1500)
            ])

        body.extend([
            "",

            f"Rule: `{safe(finding.rule_id)}` · CodeSentry"
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

        return (
            render_summary(analysis)

            + f"\n\nInline comments: {comment_count}"

            + "\n\n"

            + self.generate_marker(analysis)
        )

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