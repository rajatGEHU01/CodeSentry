from unittest.mock import Mock

import httpx
import pytest

from codesentry.github.retry import (
    RetryPolicy,
    RetryConfig
)


def test_success():

    operation = Mock(
        return_value=httpx.Response(200)
    )

    response = RetryPolicy().execute(
        "GET",
        operation
    )

    assert response.status_code == 200

    assert operation.call_count == 1


def test_retry_server_error(monkeypatch):

    monkeypatch.setattr(
        "codesentry.github.retry.time.sleep",
        lambda delay: None
    )

    operation = Mock(
        side_effect=[
            httpx.Response(503),
            httpx.Response(200)
        ]
    )

    response = RetryPolicy().execute(
        "GET",
        operation
    )

    assert response.status_code == 200

    assert operation.call_count == 2


def test_no_post_retry():

    operation = Mock(
        return_value=httpx.Response(503)
    )

    response = RetryPolicy().execute(
        "POST",
        operation
    )

    assert response.status_code == 503

    assert operation.call_count == 1


def test_rate_limit():

    response = httpx.Response(
        429,
        headers={"retry-after": "5"}
    )

    policy = RetryPolicy()

    assert policy.is_rate_limited(response)

    assert policy.calculate_delay(
        0,
        response
    ) == 5


def test_normal_forbidden():

    response = httpx.Response(403)

    assert not RetryPolicy().is_rate_limited(
        response
    )


def test_primary_rate_limit():

    response = httpx.Response(
        403,
        headers={
            "x-ratelimit-remaining": "0"
        }
    )

    assert RetryPolicy().is_rate_limited(
        response
    )


def test_retry_limit(monkeypatch):

    monkeypatch.setattr(
        "codesentry.github.retry.time.sleep",
        lambda delay: None
    )

    operation = Mock(
        return_value=httpx.Response(503)
    )

    policy = RetryPolicy(
        RetryConfig(max_attempts=3)
    )

    response = policy.execute(
        "GET",
        operation
    )

    assert response.status_code == 503

    assert operation.call_count == 3


def test_long_rate_limit_delay():

    operation = Mock(
        return_value=httpx.Response(
            429,
            headers={"retry-after": "600"}
        )
    )

    response = RetryPolicy().execute(
        "GET",
        operation
    )

    assert response.status_code == 429

    assert operation.call_count == 1


def test_transport_retry(monkeypatch):

    monkeypatch.setattr(
        "codesentry.github.retry.time.sleep",
        lambda delay: None
    )

    operation = Mock(
        side_effect=[
            httpx.ConnectError("Connection failed"),
            httpx.Response(200)
        ]
    )

    response = RetryPolicy().execute(
        "GET",
        operation
    )

    assert response.status_code == 200


def test_post_transport_error():

    operation = Mock(
        side_effect=httpx.ConnectError(
            "Connection failed"
        )
    )

    with pytest.raises(httpx.ConnectError):

        RetryPolicy().execute(
            "POST",
            operation
        )

    assert operation.call_count == 1