import os

from pathlib import Path
from dataclasses import dataclass, field
from dotenv import load_dotenv


@dataclass(frozen=True)
class GitHubConfig:

    app_id: str
    private_key: str = field(repr=False)

    api_url: str = "https://api.github.com"
    webhook_secret: str = field(default="", repr=False)

    @classmethod
    def from_env(cls):

        load_dotenv()

        app_id = os.getenv(
            "GITHUB_APP_ID", ""
        ).strip()

        private_key_path = os.getenv(
            "GITHUB_PRIVATE_KEY_PATH",
            "github-app.pem"
        )

        api_url = os.getenv(
            "GITHUB_API_URL",
            "https://api.github.com"
        ).rstrip("/")

        webhook_secret = os.getenv(
            "GITHUB_WEBHOOK_SECRET", ""
        )

        if not app_id.isdigit():
            raise ValueError(
                "GITHUB_APP_ID must be a numeric App ID"
            )

        key_path = Path(private_key_path)

        if not key_path.is_file():
            raise FileNotFoundError(
                "GitHub App private key not found"
            )

        private_key = key_path.read_text(
            encoding="utf-8"
        )

        return cls(
            app_id=app_id,
            private_key=private_key,
            api_url=api_url,
            webhook_secret=webhook_secret
        )