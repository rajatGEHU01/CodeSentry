import logging
import threading

from codesentry.github.auth import GitHubAuth
from codesentry.github.client import GitHubClient
from codesentry.github.events import PullRequestEvent

from codesentry.github.pr_analyzer import (
    PullRequestAnalyzer
)

from codesentry.github.review_publisher import (
    ReviewPublisher
)

from codesentry.github.check_publisher import (
    CheckPublisher
)


logger = logging.getLogger("codesentry.handler")


class PullRequestHandler:

    def __init__(self, auth: GitHubAuth):

        self.auth = auth

        self.publisher = ReviewPublisher()

        self.checks = CheckPublisher()

        self._active_jobs = set()

        self._lock = threading.Lock()

    @staticmethod
    def is_current(pull_request, event):

        return (
            pull_request["head"]["sha"]
            == event.head_sha

            and pull_request["base"]["sha"]
            == event.base_sha

            and pull_request.get("state") == "open"

            and not pull_request.get("draft")
        )

    def process(self, event: PullRequestEvent):

        job_key = (
            event.installation_id,
            event.full_repository_name,
            event.pull_number,
            event.head_sha,
            event.base_sha
        )

        with self._lock:

            if job_key in self._active_jobs:

                logger.info(
                    "Identical PR analysis already running"
                )

                return

            self._active_jobs.add(job_key)

        github = None

        check_id = None

        check_completed = False

        try:

            logger.info(
                "Processing PR #%s in %s",

                event.pull_number,

                event.full_repository_name
            )

            github = GitHubClient(
                self.auth,
                event.installation_id
            )

            pull_request = github.get_pull_request(
                event.owner,
                event.repository,
                event.pull_number
            )

            if not self.is_current(
                pull_request,
                event
            ):

                logger.info(
                    "Skipping outdated or inactive PR"
                )

                return

            # Create an in-progress GitHub check.

            check_id = self.checks.create_check(
                github,
                event
            )

            # Use a separate analyzer for each job.

            analyzer = PullRequestAnalyzer()

            analysis = analyzer.analyze(
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
                    "Gate violation: %s | "
                    "Actual: %s | Allowed: %s",

                    violation.metric,

                    violation.actual,

                    violation.allowed
                )

            # Check that the PR is still current.

            current_pr = github.get_pull_request(
                event.owner,
                event.repository,
                event.pull_number
            )

            if not self.is_current(
                current_pr,
                event
            ):

                self.checks.cancel_check(
                    github,
                    event,
                    check_id
                )

                check_completed = True

                return

            # Publish the official quality gate result.

            self.checks.complete_check(
                github,
                check_id,
                analysis
            )

            check_completed = True

            # Publish inline review comments separately.

            try:

                self.publisher.publish(
                    github,
                    analysis
                )

            except Exception as review_error:

                logger.error(
                    "Review publishing failed: %s",

                    type(review_error).__name__
                )

            logger.info(
                "Pull request analysis completed"
            )

        except Exception as error:

            logger.error(
                "PR processing failed: %s",

                type(error).__name__
            )

            if (
                github is not None

                and check_id is not None

                and not check_completed
            ):

                try:

                    current_pr = github.get_pull_request(
                        event.owner,
                        event.repository,
                        event.pull_number
                    )

                    if not self.is_current(
                        current_pr,
                        event
                    ):

                        self.checks.cancel_check(
                            github,
                            event,
                            check_id
                        )

                    else:

                        self.checks.fail_check(
                            github,
                            event,
                            check_id,
                            type(error).__name__
                        )

                except Exception:

                    try:

                        self.checks.fail_check(
                            github,
                            event,
                            check_id,
                            type(error).__name__
                        )

                    except Exception as check_error:

                        logger.error(
                            "Could not finalize check: %s",

                            type(check_error).__name__
                        )

        finally:

            with self._lock:

                self._active_jobs.discard(job_key)