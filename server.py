import json
import logging
import asyncio

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, HTTPException

from codesentry.github.config import GitHubConfig
from codesentry.github.auth import GitHubAuth
from codesentry.github.webhook import WebhookVerifier

from codesentry.github.events import (
    PullRequestEvent,
    SUPPORTED_ACTIONS
)

from codesentry.github.handler import PullRequestHandler

from codesentry.github.job_queue import (
    AnalysisJobQueue,
    SubmissionStatus
)


logging.basicConfig(
    level=logging.INFO,
    format=(
        "%(asctime)s | %(levelname)s | "
        "%(name)s | %(message)s"
    )
)


logger = logging.getLogger("codesentry.server")


MAX_PAYLOAD_SIZE = 25 * 1024 * 1024


@asynccontextmanager
async def lifespan(app: FastAPI):

    config = GitHubConfig.from_env()

    verifier = WebhookVerifier(
        config.webhook_secret
    )

    auth = GitHubAuth(config)

    handler = PullRequestHandler(auth)

    job_queue = AnalysisJobQueue(
        handler=handler,
        workers=2,
        max_queue_size=50,
        delivery_ttl=3600
    )

    app.state.auth = auth

    app.state.verifier = verifier

    app.state.handler = handler

    app.state.job_queue = job_queue

    job_queue.start()

    logger.info("CodeSentry server started")

    try:

        yield

    finally:

        await asyncio.to_thread(
            job_queue.stop
        )

        auth.close()

        logger.info("CodeSentry server stopped")


app = FastAPI(
    title="CodeSentry",
    description=(
        "Automated code quality and security "
        "analysis for GitHub"
    ),
    version="0.2.0",
    lifespan=lifespan
)


@app.get("/")
async def root():

    return {
        "application": "CodeSentry",
        "github_app": "LIMECODE247",
        "status": "running",
        "version": "0.2.0"
    }


@app.get("/health")
async def health(request: Request):

    stats = request.app.state.job_queue.stats()

    if not stats["running"]:

        raise HTTPException(
            status_code=503,
            detail="Analysis queue unavailable"
        )

    return {
        "status": "healthy"
    }


@app.post("/webhook", status_code=202)
async def github_webhook(request: Request):

    signature = request.headers.get(
        "X-Hub-Signature-256"
    )

    event_type = request.headers.get(
        "X-GitHub-Event"
    )

    delivery_id = request.headers.get(
        "X-GitHub-Delivery"
    )

    payload_buffer = bytearray()

    async for chunk in request.stream():

        payload_buffer.extend(chunk)

        if len(payload_buffer) > MAX_PAYLOAD_SIZE:

            raise HTTPException(
                status_code=413,
                detail="Payload too large"
            )

    raw_payload = bytes(payload_buffer)

    verifier = request.app.state.verifier

    if not verifier.verify(
        raw_payload,
        signature
    ):

        raise HTTPException(
            status_code=401,
            detail="Invalid webhook signature"
        )

    if not event_type or not delivery_id:

        raise HTTPException(
            status_code=400,
            detail="Missing GitHub headers"
        )

    try:

        payload = json.loads(raw_payload)

    except (ValueError, UnicodeDecodeError):

        raise HTTPException(
            status_code=400,
            detail="Invalid JSON payload"
        )

    if not isinstance(payload, dict):

        raise HTTPException(
            status_code=400,
            detail="Invalid payload structure"
        )

    logger.info(
        "Received event: %r | Delivery: %r",
        event_type,
        delivery_id
    )

    if event_type == "ping":

        return {
            "status": "success",
            "message": "CodeSentry webhook connected"
        }

    if event_type != "pull_request":

        return {
            "status": "ignored",
            "reason": "Unsupported event"
        }

    action = payload.get("action")

    if (
        not isinstance(action, str)
        or action not in SUPPORTED_ACTIONS
    ):

        return {
            "status": "ignored",
            "reason": "Unsupported PR action"
        }

    try:

        event = PullRequestEvent.from_payload(
            payload,
            delivery_id
        )

    except (
        KeyError,
        TypeError,
        ValueError,
        AttributeError
    ):

        raise HTTPException(
            status_code=400,
            detail="Invalid pull request payload"
        )

    if event.is_draft:

        return {
            "status": "ignored",
            "reason": "Draft pull request"
        }

    job_queue = request.app.state.job_queue

    result = job_queue.submit(event)

    if result == SubmissionStatus.DUPLICATE:

        return {
            "status": "duplicate",
            "delivery_id": delivery_id
        }

    if result in {
        SubmissionStatus.FULL,
        SubmissionStatus.STOPPED
    }:

        raise HTTPException(
            status_code=503,
            detail="Analysis queue unavailable",
            headers={"Retry-After": "60"}
        )

    logger.info(
        "Job queued | PR #%s | Queue size: %s",
        event.pull_number,
        job_queue.stats()["queued"]
    )

    return {
        "status": "accepted",
        "repository": event.full_repository_name,
        "pull_request": event.pull_number,
        "delivery_id": delivery_id
    }