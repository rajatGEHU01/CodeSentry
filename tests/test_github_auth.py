from datetime import datetime, timedelta, timezone

import httpx

from codesentry.github.config import GitHubConfig
from codesentry.github.auth import GitHubAuth
from codesentry.github.client import GitHubClient


def make_config():

    return GitHubConfig(
        app_id="123456",
        private_key="mock-private-key"
    )


def test_installation_token_cache(monkeypatch):

    calls = []

    expiration = (
        datetime.now(timezone.utc)
        + timedelta(hours=1)
    ).isoformat()

    def handler(request):

        calls.append(request)

        return httpx.Response(
            201,
            json={
                "token": "mock-token",
                "expires_at": expiration
            }
        )

    transport = httpx.MockTransport(handler)

    with httpx.Client(transport=transport) as client:

        auth = GitHubAuth(
            make_config(),
            client
        )

        monkeypatch.setattr(
            auth,
            "generate_jwt",
            lambda: "mock-jwt"
        )

        first = auth.get_installation_token(100)
        second = auth.get_installation_token(100)

        assert first == "mock-token"
        assert first == second
        assert len(calls) == 1


def test_token_invalidation(monkeypatch):

    calls = []

    expiration = (
        datetime.now(timezone.utc)
        + timedelta(hours=1)
    ).isoformat()

    def handler(request):

        calls.append(request)

        return httpx.Response(
            201,
            json={
                "token": "mock-token",
                "expires_at": expiration
            }
        )

    transport = httpx.MockTransport(handler)

    with httpx.Client(transport=transport) as client:

        auth = GitHubAuth(
            make_config(),
            client
        )

        monkeypatch.setattr(
            auth,
            "generate_jwt",
            lambda: "mock-jwt"
        )

        auth.get_installation_token(100)

        auth.invalidate_token(100)

        auth.get_installation_token(100)

        assert len(calls) == 2


def test_pull_request_files(monkeypatch):

    def handler(request):

        assert request.headers[
            "Authorization"
        ] == "Bearer mock-token"

        return httpx.Response(
            200,
            json=[
                {
                    "filename": "main.py",
                    "status": "modified",
                    "additions": 5,
                    "deletions": 2
                }
            ]
        )

    transport = httpx.MockTransport(handler)

    with httpx.Client(transport=transport) as client:

        auth = GitHubAuth(
            make_config(),
            client
        )

        monkeypatch.setattr(
            auth,
            "get_installation_token",
            lambda installation_id: "mock-token"
        )

        github = GitHubClient(auth, 100)

        files = github.get_pull_request_files(
            "owner",
            "repository",
            1
        )

        assert len(files) == 1

        assert files[0]["filename"] == "main.py"


def test_file_content(monkeypatch):

    def handler(request):

        return httpx.Response(
            200,
            json={
                "type": "file",
                "encoding": "base64",
                "content": "cHJpbnQoMSk="
            }
        )

    transport = httpx.MockTransport(handler)

    with httpx.Client(transport=transport) as client:

        auth = GitHubAuth(
            make_config(),
            client
        )

        monkeypatch.setattr(
            auth,
            "get_installation_token",
            lambda installation_id: "mock-token"
        )

        github = GitHubClient(auth, 100)

        source = github.get_file_content(
            "owner",
            "repository",
            "main.py",
            "main"
        )

        assert source == "print(1)"