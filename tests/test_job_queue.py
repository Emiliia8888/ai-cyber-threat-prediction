from src.infrastructure.queue.in_memory_job_queue import (
    InMemoryJobQueue,
)


def test_queue_starts_empty():
    queue = InMemoryJobQueue()

    assert queue.size() == 0
    assert queue.dequeue() is None


def test_enqueue_and_dequeue_job():
    queue = InMemoryJobQueue()

    job = {
        "job_id": "job-1",
        "events": [
            {
                "type": "port_scan",
                "source": "192.168.1.10",
                "timestamp": "2026-09-10 12:00:00",
            }
        ],
    }

    queue.enqueue(job)

    assert queue.size() == 1
    assert queue.dequeue() == job
    assert queue.size() == 0


def test_queue_is_fifo():
    queue = InMemoryJobQueue()

    first_job = {"job_id": "job-1"}
    second_job = {"job_id": "job-2"}

    queue.enqueue(first_job)
    queue.enqueue(second_job)

    assert queue.dequeue() == first_job
    assert queue.dequeue() == second_job
