import logging

from codesentry.github.auth import GitHubAuth
from codesentry.github.client import GitHubClient
from codesentry.github.events import PullRequestEvent


logger = logging.getLogger("codesentry.handler")


class PullRequestHandler:

    def __init__(self, auth: GitHubAuth):

        self.auth = auth

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

            # Ignore outdated webhook events
            current_sha = pull_request["head"]["sha"]

            if current_sha != event.head_sha:

                logger.info(
                    "Skipping outdated PR event"
                )

                return

            files = github.get_pull_request_files(
                event.owner,
                event.repository,
                event.pull_number
            )

            logger.info(
                "Changed files: %s",
                len(files)
            )

            for file in files:

                logger.info(
                    "File: %r | Status: %s | +%s | -%s",
                    file["filename"],
                    file["status"],
                    file.get("additions", 0),
                    file.get("deletions", 0)
                )

            logger.info(
                "PR file retrieval completed successfully"
            )

        except Exception as error:

            logger.error(
                "PR processing failed: %s",
                type(error).__name__
            )