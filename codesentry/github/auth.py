import time
import threading

from datetime import datetime
from dataclasses import dataclass, field

import jwt
import httpx

from codesentry.github.config import GitHubConfig


@dataclass(frozen=True)
class InstallationToken:

    token: str = field(repr=False)
    expires_at: float

    def is_valid(self) -> bool:
        return time.time() < self.expires_at - 120


class GitHubAuth:

    def __init__(
        self,
        config: GitHubConfig,
        client: httpx.Client | None = None
    ):

        self.config = config
        self._owns_client = client is None
        self.client = client or httpx.Client(timeout=30.0)
        self._tokens = {}
        self._lock = threading.Lock()

    def generate_jwt(self) -> str:

        now = int(time.time())

        payload = {
            "iat": now - 60,
            "exp": now + 540,
            "iss": self.config.app_id
        }

        return jwt.encode(
            payload,
            self.config.private_key,
            algorithm="RS256"
        )

    @staticmethod
    def headers(token: str) -> dict:

        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "CodeSentry"
        }

    def get_installation_token(
        self,
        installation_id: int
    ) -> str:

        if installation_id <= 0:
            raise ValueError("Invalid installation ID")

        with self._lock:

            cached = self._tokens.get(installation_id)

            if cached and cached.is_valid():
                return cached.token

            url = (
                f"{self.config.api_url}"
                f"/app/installations/"
                f"{installation_id}/access_tokens"
            )

            response = self.client.post(
                url,
                headers=self.headers(self.generate_jwt())
            )

            response.raise_for_status()

            data = response.json()

            expiration = datetime.fromisoformat(
                data["expires_at"].replace("Z", "+00:00")
            ).timestamp()

            token = InstallationToken(
                token=data["token"],
                expires_at=expiration
            )

            self._tokens[installation_id] = token

            return token.token

    def invalidate_token(self, installation_id: int):

        with self._lock:
            self._tokens.pop(installation_id, None)

    def get_app(self) -> dict:

        response = self.client.get(
            f"{self.config.api_url}/app",
            headers=self.headers(self.generate_jwt())
        )

        response.raise_for_status()

        return response.json()

    def get_installations(self) -> list[dict]:

        installations = []
        page = 1

        while True:

            response = self.client.get(
                f"{self.config.api_url}/app/installations",
                headers=self.headers(self.generate_jwt()),
                params={
                    "per_page": 100,
                    "page": page
                }
            )

            response.raise_for_status()

            batch = response.json()
            installations.extend(batch)

            if len(batch) < 100:
                break

            page += 1

        return installations

    def close(self):

        if self._owns_client:
            self.client.close()