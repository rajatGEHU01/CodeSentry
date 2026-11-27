from codesentry.github.config import GitHubConfig
from codesentry.github.auth import GitHubAuth
from codesentry.github.client import GitHubClient


def main():

    config = GitHubConfig.from_env()

    auth = GitHubAuth(config)

    try:

        print("\n===== CODESENTRY GITHUB CONNECTION =====")

        app = auth.get_app()

        print("\nAuthentication successful!")
        print(f"App name: {app['name']}")
        print(f"App ID: {app['id']}")

        installations = auth.get_installations()

        print(
            f"\nInstallations found: "
            f"{len(installations)}"
        )

        if not installations:

            print(
                "Install the GitHub App "
                "on a repository first."
            )

            return

        for installation in installations:

            installation_id = installation["id"]

            account = installation["account"]["login"]

            print(f"\nAccount: {account}")
            print(f"Installation ID: {installation_id}")

            github = GitHubClient(
                auth,
                installation_id
            )

            repositories = github.get_repositories()

            print(
                f"Accessible repositories: "
                f"{len(repositories)}"
            )

            for repository in repositories:

                print(
                    f" - {repository['full_name']}"
                )

        print("\nGitHub connection verified successfully.")

    finally:

        auth.close()


if __name__ == "__main__":

    main()