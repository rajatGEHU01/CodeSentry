import logging

from datetime import datetime, timezone

from codesentry.github.client import GitHubClient
from codesentry.github.events import PullRequestEvent
from codesentry.github.pr_analyzer import PullRequestAnalysis


logger = logging.getLogger("codesentry.checks")


class CheckPublisher:

    CHECK_NAME = "CodeSentry / Quality Gate"

    MAX_ANNOTATIONS = 50

    SEVERITY_LEVELS = {
        "critical": "failure",
        "high": "failure",
        "medium": "warning",
        "low": "notice",
        "info": "notice"
    }

    SEVERITY_ORDER = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4
    }

    CONCLUSIONS = {
        "passed": "success",
        "failed": "failure",
        "error": "failure"
    }

    @staticmethod
    def timestamp():

        return datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )

    @staticmethod
    def endpoint(event: PullRequestEvent):

        return (
            f"/repos/{event.owner}/{event.repository}"
            "/check-runs"
        )

    @staticmethod
    def external_id(event: PullRequestEvent):

        return (
            f"codesentry:{event.pull_number}:"
            f"{event.head_sha}:{event.base_sha}"
        )

    def create_check(
        self,
        github: GitHubClient,
        event: PullRequestEvent
    ) -> int:

        payload = {
            "name": self.CHECK_NAME,

            "head_sha": event.head_sha,

            "status": "in_progress",

            "started_at": self.timestamp(),

            "external_id": self.external_id(event),

            "output": {
                "title": "CodeSentry analysis in progress",

                "summary": (
                    "Analyzing code quality, security, "
                    "complexity and duplication."
                )
            }
        }

        response = github.request(
            "POST",
            self.endpoint(event),
            json=payload
        )

        check_id = response["id"]

        logger.info(
            "Check run created | ID: %s",
            check_id
        )

        return check_id

    def build_annotations(
        self,
        analysis: PullRequestAnalysis
    ) -> list[dict]:

        annotations = []
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

            if len(annotations) >= self.MAX_ANNOTATIONS:
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

            severity = finding.severity.value

            message = finding.message

            if finding.suggestion:

                message += (
                    "\n\nRecommended fix: "
                    + finding.suggestion
                )

            annotations.append({
                "path": finding.file_path,

                "start_line": target_line,

                "end_line": target_line,

                "annotation_level":
                    self.SEVERITY_LEVELS.get(
                        severity,
                        "notice"
                    ),

                "title": (
                    f"{severity.upper()} | "
                    f"{finding.rule_id}"
                )[:255],

                "message": message[:60000]
            })

        return annotations

    def build_summary(
        self,
        analysis: PullRequestAnalysis
    ) -> str:

        report = analysis.report

        counts = report.severity_counts

        lines = [
            "## CodeSentry Static Analysis",
            "",
            f"**Quality Gate:** "
            f"{analysis.gate.status.value.upper()}",
            "",
            "| Metric | Result |",
            "|---|---:|",

            f"| Changed files | "
            f"{analysis.changed_files} |",

            f"| Analyzed files | "
            f"{analysis.analyzed_files} |",

            f"| Total findings | "
            f"{len(analysis.findings)} |",

            f"| Critical | "
            f"{counts.get('critical', 0)} |",

            f"| High | "
            f"{counts.get('high', 0)} |",

            f"| Medium | "
            f"{counts.get('medium', 0)} |",

            f"| Low | "
            f"{counts.get('low', 0)} |",

            f"| Info | "
            f"{counts.get('info', 0)} |",

            f"| Duplication | "
            f"{report.duplication.duplication_percentage}% |",

            f"| Analysis errors | "
            f"{len(report.errors)} |",

            f"| Skipped files | "
            f"{len(report.skipped_files)} |",

            f"| Analysis duration | "
            f"{report.duration_seconds:.2f}s |",

            ""
        ]

        if analysis.gate.violations:

            lines.extend([
                "### Quality Gate Violations",
                ""
            ])

            for violation in analysis.gate.violations[:30]:

                message = str(
                    violation.message
                )[:1000]

                message = (
                    message.replace("&", "&amp;")
                           .replace("<", "&lt;")
                           .replace(">", "&gt;")
                           .replace("@", "@\u200b")
                )

                lines.append(f"- {message}")

        elif analysis.gate.passed:

            lines.append(
                "All configured quality thresholds "
                "have been satisfied."
            )

        lines.extend([
            "",
            "### Analysis Scope",
            "",
            "- Python, C++ and SQL analysis",
            "- Unsafe function detection",
            "- Hardcoded secret detection",
            "- Cyclomatic complexity",
            "- Halstead complexity",
            "- Duplicate code detection",
            "",
            "Results apply to supported files within "
            "the analyzed pull request.",
            "",
            "Static analysis does not guarantee "
            "that code is free of vulnerabilities."
        ])

        return "\n".join(lines)

    def complete_check(
        self,
        github: GitHubClient,
        check_id: int,
        analysis: PullRequestAnalysis
    ) -> dict:

        status = analysis.gate.status.value

        conclusion = self.CONCLUSIONS.get(
            status,
            "failure"
        )

        titles = {
            "passed": "Quality gate passed",
            "failed": "Quality gate failed",
            "error": "Analysis incomplete or failed"
        }

        annotations = self.build_annotations(
            analysis
        )

        summary = self.build_summary(analysis)

        if len(analysis.findings) > len(annotations):

            summary += (
                "\n\nOnly a limited number of findings "
                "are displayed as annotations."
            )

        output = {
            "title": titles.get(
                status,
                "Analysis failed"
            ),

            "summary": summary[:60000]
        }

        if annotations:

            output["annotations"] = annotations

        payload = {
            "status": "completed",

            "conclusion": conclusion,

            "completed_at": self.timestamp(),

            "output": output
        }

        response = github.request(
            "PATCH",

            f"{self.endpoint(analysis.event)}/{check_id}",

            json=payload
        )

        logger.info(
            "Check completed | ID: %s | "
            "Conclusion: %s | Annotations: %s",

            check_id,

            conclusion,

            len(annotations)
        )

        return response

    def fail_check(
        self,
        github: GitHubClient,
        event: PullRequestEvent,
        check_id: int,
        error_type: str
    ) -> dict:

        payload = {
            "status": "completed",

            "conclusion": "failure",

            "completed_at": self.timestamp(),

            "output": {
                "title": "CodeSentry analysis failed",

                "summary": (
                    "The analysis could not be completed.\n\n"
                    f"Error type: {error_type}\n\n"
                    "Check the application logs and retry."
                )
            }
        }

        return github.request(
            "PATCH",

            f"{self.endpoint(event)}/{check_id}",

            json=payload
        )

    def cancel_check(
        self,
        github: GitHubClient,
        event: PullRequestEvent,
        check_id: int
    ) -> dict:

        payload = {
            "status": "completed",

            "conclusion": "cancelled",

            "completed_at": self.timestamp(),

            "output": {
                "title": "Analysis cancelled",

                "summary": (
                    "The pull request changed or became "
                    "inactive during analysis."
                )
            }
        }

        return github.request(
            "PATCH",

            f"{self.endpoint(event)}/{check_id}",

            json=payload
        )