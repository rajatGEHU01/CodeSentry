import time
import logging
import threading

from queue import Queue, Full
from collections import OrderedDict
from enum import Enum

from codesentry.github.events import PullRequestEvent


logger = logging.getLogger("codesentry.queue")


class SubmissionStatus(str, Enum):

    ACCEPTED = "accepted"

    DUPLICATE = "duplicate"

    FULL = "full"

    STOPPED = "stopped"


class AnalysisJobQueue:

    def __init__(
        self,
        handler,
        workers: int = 2,
        max_queue_size: int = 50,
        delivery_ttl: int = 3600,
        max_completed_deliveries: int = 10000
    ):

        if min(
            workers,
            max_queue_size,
            delivery_ttl,
            max_completed_deliveries
        ) <= 0:

            raise ValueError("Invalid queue configuration")

        self.handler = handler

        self.worker_count = workers

        self.delivery_ttl = delivery_ttl

        self.max_completed_deliveries = (
            max_completed_deliveries
        )

        self.queue = Queue(
            maxsize=max_queue_size
        )

        self._lock = threading.Lock()

        self._active_deliveries = set()

        self._completed_deliveries = OrderedDict()

        self._threads = []

        self._running = False

        self._processed = 0

        self._failed = 0

        self._duplicates = 0

    def cleanup_deliveries(self):

        now = time.monotonic()

        while self._completed_deliveries:

            delivery_id, timestamp = next(
                iter(self._completed_deliveries.items())
            )

            if now - timestamp < self.delivery_ttl:
                break

            self._completed_deliveries.pop(
                delivery_id,
                None
            )

    def start(self):

        with self._lock:

            if self._running:
                return

            if self._threads:
                raise RuntimeError(
                    "Queue cannot be restarted"
                )

            self._running = True

            for index in range(self.worker_count):

                worker = threading.Thread(
                    target=self.worker_loop,
                    name=f"codesentry-worker-{index + 1}",
                    daemon=True
                )

                self._threads.append(worker)

                worker.start()

        logger.info(
            "Analysis queue started | Workers: %s",
            self.worker_count
        )

    def submit(
        self,
        event: PullRequestEvent
    ) -> SubmissionStatus:

        delivery_id = event.delivery_id

        with self._lock:

            if not self._running:
                return SubmissionStatus.STOPPED

            self.cleanup_deliveries()

            if (
                delivery_id in self._active_deliveries
                or delivery_id in self._completed_deliveries
            ):

                self._duplicates += 1

                return SubmissionStatus.DUPLICATE

            try:

                self.queue.put_nowait(event)

            except Full:

                return SubmissionStatus.FULL

            self._active_deliveries.add(
                delivery_id
            )

            return SubmissionStatus.ACCEPTED

    def worker_loop(self):

        while True:

            event = self.queue.get()

            try:

                if event is None:
                    return

                succeeded = False

                try:

                    logger.info(
                        "Worker processing PR #%s",
                        event.pull_number
                    )

                    self.handler.process(event)

                    succeeded = True

                except Exception as error:

                    logger.error(
                        "Worker failed: %s",
                        type(error).__name__
                    )

                finally:

                    with self._lock:

                        self._active_deliveries.discard(
                            event.delivery_id
                        )

                        if succeeded:

                            self._processed += 1

                            self._completed_deliveries[
                                event.delivery_id
                            ] = time.monotonic()

                            while (
                                len(self._completed_deliveries)
                                > self.max_completed_deliveries
                            ):

                                self._completed_deliveries.popitem(
                                    last=False
                                )

                        else:

                            self._failed += 1

            finally:

                self.queue.task_done()

    def stats(self):

        with self._lock:

            return {
                "running": self._running,

                "workers": self.worker_count,

                "queued": self.queue.qsize(),

                "active_deliveries": len(
                    self._active_deliveries
                ),

                "processed": self._processed,

                "failed": self._failed,

                "duplicates": self._duplicates
            }

    def stop(self):

        with self._lock:

            if not self._running:
                return

            self._running = False

        for _ in self._threads:

            self.queue.put(None)

        for worker in self._threads:

            worker.join()

        logger.info("Analysis queue stopped")