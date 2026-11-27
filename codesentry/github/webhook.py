import hashlib
import hmac


class WebhookVerifier:

    def __init__(self, secret: str):

        if not secret:
            raise ValueError(
                "Webhook secret cannot be empty"
            )

        self.secret = secret.encode("utf-8")

    def generate_signature(self, payload: bytes) -> str:

        digest = hmac.new(
            self.secret,
            payload,
            hashlib.sha256
        ).hexdigest()

        return f"sha256={digest}"

    def verify(
        self,
        payload: bytes,
        signature: str | None
    ) -> bool:

        if not signature:
            return False

        if not signature.startswith("sha256="):
            return False

        if len(signature) != 71:
            return False

        expected = self.generate_signature(payload)

        return hmac.compare_digest(
            expected,
            signature
        )