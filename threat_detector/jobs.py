"""Background training jobs.

Training was synchronous: `POST /api/train` blocked the worker for the whole
fit, so a capture large enough to be interesting timed out the request, and two
overlapping requests raced each other onto the same model file.

Jobs run on a worker thread and their state lives in a small JSON file beside
the model. On disk rather than in memory for two reasons: progress survives a
restart, and under a multi-worker WSGI server the request that asks for status
is usually not handled by the worker that started the job.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any, Callable

from .config import Config

logger = logging.getLogger(__name__)

RUNNING = "running"
SUCCEEDED = "succeeded"
FAILED = "failed"

_lock = threading.Lock()


class JobInProgress(RuntimeError):
    """Raised when a training run is requested while one is already going."""


def _read(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def _write(path: Path, payload: dict) -> None:
    """Atomic, so a reader never sees a half-written status file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    scratch = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        scratch.write_text(json.dumps(payload, default=str))
        os.replace(scratch, path)
    finally:
        Path(scratch).unlink(missing_ok=True)


def _process_alive(pid: int | None) -> bool:
    if pid is None:
        return False
    try:
        os.kill(pid, 0)  # signal 0 only checks for existence
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists, owned by someone else
    return True


def status(config: Config) -> dict:
    """Current job state, reconciled against reality.

    A job whose process died — the container was restarted mid-fit, say — would
    otherwise stay "running" forever and block every future run.
    """
    record = _read(config.job_file)
    if record is None:
        return {"state": None}

    if record.get("state") == RUNNING and not _process_alive(record.get("pid")):
        record = {
            **record,
            "state": FAILED,
            "error": "Training stopped unexpectedly (the process is gone).",
            "finished_at": time.time(),
        }
        _write(config.job_file, record)
    return record


def start(config: Config, work: Callable[[Config], dict]) -> dict:
    """Begin a training run in the background and return its initial state."""
    with _lock:
        current = status(config)
        if current.get("state") == RUNNING:
            raise JobInProgress(
                "A training run is already in progress. Wait for it to finish, "
                "or check /api/status."
            )

        record = {
            "state": RUNNING,
            "started_at": time.time(),
            "finished_at": None,
            "pid": os.getpid(),
            "error": None,
            "result": None,
        }
        _write(config.job_file, record)

    thread = threading.Thread(
        target=_run, args=(config, work), name="training", daemon=True
    )
    thread.start()
    return record


def _run(config: Config, work: Callable[[Config], dict]) -> None:
    started = time.time()
    try:
        result: Any = work(config)
    except Exception as exc:
        logger.exception("Training failed")
        _write(config.job_file, {
            "state": FAILED,
            "started_at": started,
            "finished_at": time.time(),
            "pid": os.getpid(),
            # The message is shown to API clients, so keep it to what the
            # exception says rather than a traceback.
            "error": str(exc),
            "result": None,
        })
        return

    _write(config.job_file, {
        "state": SUCCEEDED,
        "started_at": started,
        "finished_at": time.time(),
        "pid": os.getpid(),
        "error": None,
        "result": result,
    })
    logger.info("Training finished in %.1fs", time.time() - started)


def wait(config: Config, timeout: float = 60.0, poll: float = 0.02) -> dict:
    """Block until the current run finishes. For the CLI and for tests."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        record = status(config)
        if record.get("state") != RUNNING:
            return record
        time.sleep(poll)
    raise TimeoutError(f"Training did not finish within {timeout}s")
