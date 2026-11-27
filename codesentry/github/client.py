import base64
import logging

from urllib.parse import quote

import httpx

from codesentry.github.auth import GitHubAuth
from codesentry.github.retry import RetryPolicy


logger = logging.getLogger("codesentry.client")


class GitHubClient:

    def __init__(
        self,
        auth: GitHubAuth,
        installation_id: int
    ):

        self.auth = auth

        self.installation_id = installation_id

        self.api_url = auth.config.api_url

        self.client = auth.client

        self.retry_policy = RetryPolicy()

    def request(
        self,
        method,
        endpoint,
        **kwargs
    ):

        if not endpoint.startswith("/"):
            raise ValueError("Endpoint must start with /")

        url = self.api_url + endpoint

        method = method.upper()

        for attempt in range(2):

            token = self.auth.get_installation_token(
                self.installation_id
            )

            response = self.retry_policy.execute(
                method,

                lambda: self.client.request(
                    method,
                    url,
                    headers=self.auth.headers(token),
                    **kwargs
                )
            )

            if (
                response.status_code == 401
                and attempt == 0
            ):

                response.close()

                self.auth.invalidate_token(
                    self.installation_id
                )

                continue

            if self.retry_policy.is_rate_limited(
                response
            ):

                logger.warning(
                    "GitHub API rate limit reached"
                )

            response.raise_for_status()

            if response.status_code == 204:
                return None

            return response.json()

        raise RuntimeError(
            "GitHub authentication failed"
        )

    def paginate(
        self,
        endpoint,
        params=None,
        result_key=None
    ):

        results = []

        page = 1

        while True:

            query = dict(params or {})

            query.update({
                "per_page": 100,
                "page": page
            })

            data = self.request(
                "GET",
                endpoint,
                params=query
            )

            batch = (
                data[result_key]
                if result_key
                else data
            )

            results.extend(batch)

            if len(batch) < 100:
                break

            page += 1

        return results

    def get_repositories(self):

        return self.paginate(
            "/installation/repositories",
            result_key="repositories"
        )

    def get_repository(self, owner, repo):

        return self.request(
            "GET",
            f"/repos/{owner}/{repo}"
        )

    def get_pull_request(
        self,
        owner,
        repo,
        pull_number
    ):

        return self.request(
            "GET",
            f"/repos/{owner}/{repo}/pulls/{pull_number}"
        )

    def get_pull_request_files(
        self,
        owner,
        repo,
        pull_number
    ):

        return self.paginate(
            f"/repos/{owner}/{repo}"
            f"/pulls/{pull_number}/files"
        )

    def get_file_content(
        self,
        owner,
        repo,
        file_path,
        ref
    ):

        encoded_path = quote(
            file_path,
            safe="/"
        )

        data = self.request(
            "GET",

            f"/repos/{owner}/{repo}"
            f"/contents/{encoded_path}",

            params={"ref": ref}
        )

        if not isinstance(data, dict):
            raise ValueError("Requested path is not a file")

        if data.get("type") != "file":
            raise ValueError("Unsupported content type")

        if data.get("encoding") != "base64":
            raise ValueError("Unsupported file encoding")

        content = base64.b64decode(
            data["content"]
        )

        return content.decode("utf-8")