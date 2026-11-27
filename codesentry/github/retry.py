import time
import random
import logging

from dataclasses import dataclass

import httpx


logger = logging.getLogger("codesentry.retry")


@dataclass(frozen=True)
class RetryConfig:

    max_attempts: int = 4

    base_delay: float = 1.0

    max_delay: float = 30.0

    def __post_init__(self):

        if self.max_attempts < 1:
            raise ValueError("Invalid attempt limit")

        if self.base_delay <= 0 or self.max_delay <= 0:
            raise ValueError("Invalid retry delay")


class RetryPolicy:

    SAFE_METHODS = {
        "GET",
        "HEAD",
        "OPTIONS"
    }

    RETRYABLE_STATUS = {
        429,
        500,
        502,
        503,
        504
    }

    def __init__(
        self,
        config: RetryConfig | None = None
    ):

        self.config = config or RetryConfig()

    def is_rate_limited(
        self,
        response: httpx.Response
    ) -> bool:

        if response.status_code == 429:
            return True

        if response.status_code != 403:
            return False

        if response.headers.get(
            "x-ratelimit-remaining"
        ) == "0":

            return True

        if "retry-after" in response.headers:
            return True

        try:

            message = str(
                response.json().get("message", "")
            ).lower()

            return "rate limit" in message

        except (ValueError, AttributeError):

            return False

    def should_retry(
        self,
        method: str,
        response: httpx.Response
    ) -> bool:

        if method.upper() not in self.SAFE_METHODS:
            return False

        return (
            response.status_code
            in self.RETRYABLE_STATUS

            or self.is_rate_limited(response)
        )

    def calculate_delay(
        self,
        attempt: int,
        response: httpx.Response | None = None
    ) -> float:

        if response is not None:

            retry_after = response.headers.get(
                "retry-after"
            )

            if retry_after:

                try:
                    return max(0.0, float(retry_after))

                except ValueError:
                    pass

            if response.headers.get(
                "x-ratelimit-remaining"
            ) == "0":

                reset = response.headers.get(
                    "x-ratelimit-reset"
                )

                if reset:

                    try:

                        return max(
                            0.0,
                            float(reset) - time.time() + 1
                        )

                    except ValueError:
                        pass

            if self.is_rate_limited(response):

                return 60.0 * (2 ** attempt)

        delay = min(
            self.config.max_delay,
            self.config.base_delay * (2 ** attempt)
        )

        jitter = random.uniform(0, delay * 0.25)

        return min(
            self.config.max_delay,
            delay + jitter
        )

    def execute(
        self,
        method: str,
        operation
    ) -> httpx.Response:

        method = method.upper()

        for attempt in range(
            self.config.max_attempts
        ):

            last_attempt = (
                attempt
                == self.config.max_attempts - 1
            )

            try:

                response = operation()

            except httpx.TransportError:

                if (
                    last_attempt
                    or method not in self.SAFE_METHODS
                ):

                    raise

                delay = self.calculate_delay(attempt)

                logger.warning(
                    "Transport error | Retry in %.2fs",
                    delay
                )

                time.sleep(delay)

                continue

            if (
                last_attempt
                or not self.should_retry(method, response)
            ):

                return response

            delay = self.calculate_delay(
                attempt,
                response
            )

            if delay > self.config.max_delay:

                logger.warning(
                    "Required retry delay exceeds limit"
                )

                return response

            logger.warning(
                "GitHub API status %s | Retry in %.2fs",
                response.status_code,
                delay
            )

            response.close()

            time.sleep(delay)

        raise RuntimeError("Retry attempts exhausted")