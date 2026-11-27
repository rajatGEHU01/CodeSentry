import logging

from codesentry.github.auth import GitHubAuth
from codesentry.github.client import GitHubClient
from codesentry.github.events import PullRequestEvent

from codesentry.github.pr_analyzer import (
    PullRequestAnalyzer
)

from codesentry.github.review_publisher import (
    ReviewPublisher
)


logger = logging.getLogger("codesentry.handler")


class PullRequestHandler:

    def __init__(self, auth: GitHubAuth):

        self.auth = auth

        self.analyzer = PullRequestAnalyzer()

        self.publisher = ReviewPublisher()

    def process(self, event: PullRequestEvent):

        logger.info(
            "Processing PR #%s in %s",
            event.pull_number,
            event.full_repository_name
        )

        try:

            github = GitHubClient(
                self.auth,
                event.installation_id
            )

            pull_request = github.get_pull_request(
                event.owner,
                event.repository,
                event.pull_number
            )

            if (
                pull_request["head"]["sha"]
                != event.head_sha

                or pull_request["base"]["sha"]
                != event.base_sha
            ):

                logger.info(
                    "Skipping outdated PR event"
                )

                return

            if pull_request.get("state") != "open":

                logger.info(
                    "Skipping closed pull request"
                )

                return

            if pull_request.get("draft"):

                logger.info(
                    "Skipping draft pull request"
                )

                return

            analysis = self.analyzer.analyze(
                github,
                event
            )

            logger.info(
                "Changed files: %s",
                analysis.changed_files
            )

            logger.info(
                "Analyzed files: %s",
                analysis.analyzed_files
            )

            logger.info(
                "Total findings: %s",
                len(analysis.findings)
            )

            logger.info(
                "Quality gate: %s",
                analysis.gate.status.value
            )

            for finding in analysis.findings:

                logger.info(
                    "[%s] %s | %r:%s",

                    finding.severity.value.upper(),

                    finding.rule_id,

                    finding.file_path,

                    finding.start_line
                )

            for error in analysis.report.errors:

                logger.warning(
                    "Analysis error: %r | %s | %s",

                    error.file_path,

                    error.stage,

                    error.message
                )

            for violation in analysis.gate.violations:

                logger.warning(
                    "Gate violation: %s | Actual: %s | Allowed: %s",

                    violation.metric,

                    violation.actual,

                    violation.allowed
                )

            logger.info(
                "Pull request analysis completed"
            )

            self.publisher.publish(
                github,
                analysis
            )

        except Exception as error:

            logger.error(
                "PR processing failed: %s",
                type(error).__name__
            )