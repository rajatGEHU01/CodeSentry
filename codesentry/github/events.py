from dataclasses import dataclass


SUPPORTED_ACTIONS = {
    "opened",
    "synchronize",
    "reopened",
    "ready_for_review"
}


@dataclass(frozen=True)
class PullRequestEvent:

    action: str

    installation_id: int

    owner: str
    repository: str

    pull_number: int

    head_sha: str
    base_sha: str

    head_ref: str
    base_ref: str

    head_repository: str

    is_draft: bool

    delivery_id: str

    @property
    def full_repository_name(self) -> str:

        return f"{self.owner}/{self.repository}"

    @classmethod
    def from_payload(
        cls,
        payload: dict,
        delivery_id: str
    ):

        pull_request = payload["pull_request"]
        repository = payload["repository"]

        head = pull_request["head"]
        base = pull_request["base"]

        head_repository = head.get("repo") or {}

        return cls(
            action=payload["action"],

            installation_id=int(
                payload["installation"]["id"]
            ),

            owner=repository["owner"]["login"],

            repository=repository["name"],

            pull_number=int(payload["number"]),

            head_sha=head["sha"],
            base_sha=base["sha"],

            head_ref=head["ref"],
            base_ref=base["ref"],

            head_repository=head_repository.get(
                "full_name", ""
            ),

            is_draft=bool(
                pull_request.get("draft", False)
            ),

            delivery_id=delivery_id
        )