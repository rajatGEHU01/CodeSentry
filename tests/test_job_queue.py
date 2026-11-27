import threading

from types import SimpleNamespace
from unittest.mock import Mock

from codesentry.github.job_queue import (
    AnalysisJobQueue,
    SubmissionStatus
)


def create_event(delivery_id):

    return SimpleNamespace(
        delivery_id=delivery_id,
        pull_number=1
    )


def test_job_processing():

    handler = Mock()

    jobs = AnalysisJobQueue(handler)

    jobs.start()

    try:

        event = create_event("delivery-1")

        assert jobs.submit(event) == (
            SubmissionStatus.ACCEPTED
        )

        jobs.queue.join()

        handler.process.assert_called_once_with(
            event
        )

        assert jobs.stats()["processed"] == 1

    finally:

        jobs.stop()


def test_duplicate_delivery():

    handler = Mock()

    jobs = AnalysisJobQueue(handler)

    jobs.start()

    try:

        event = create_event("delivery-1")

        jobs.submit(event)

        jobs.queue.join()

        assert jobs.submit(event) == (
            SubmissionStatus.DUPLICATE
        )

        assert handler.process.call_count == 1

    finally:

        jobs.stop()


def test_stopped_queue():

    jobs = AnalysisJobQueue(Mock())

    assert jobs.submit(
        create_event("delivery-1")
    ) == SubmissionStatus.STOPPED


def test_multiple_deliveries():

    handler = Mock()

    jobs = AnalysisJobQueue(handler)

    jobs.start()

    try:

        for index in range(5):

            jobs.submit(
                create_event(f"delivery-{index}")
            )

        jobs.queue.join()

        assert handler.process.call_count == 5

        assert jobs.stats()["processed"] == 5

    finally:

        jobs.stop()


def test_worker_failure():

    handler = Mock()

    handler.process.side_effect = RuntimeError(
        "Test failure"
    )

    jobs = AnalysisJobQueue(handler)

    jobs.start()

    try:

        jobs.submit(
            create_event("delivery-1")
        )

        jobs.queue.join()

        assert jobs.stats()["failed"] == 1

    finally:

        jobs.stop()


def test_queue_capacity():

    started = threading.Event()

    release = threading.Event()

    handler = Mock()

    def process(event):

        started.set()

        release.wait(timeout=5)

    handler.process.side_effect = process

    jobs = AnalysisJobQueue(
        handler,
        workers=1,
        max_queue_size=1
    )

    jobs.start()

    try:

        assert jobs.submit(
            create_event("delivery-1")
        ) == SubmissionStatus.ACCEPTED

        assert started.wait(timeout=2)

        assert jobs.submit(
            create_event("delivery-2")
        ) == SubmissionStatus.ACCEPTED

        assert jobs.submit(
            create_event("delivery-3")
        ) == SubmissionStatus.FULL

    finally:

        release.set()

        jobs.stop()