"""Publish complete native binaries without modifying an executing inode."""

import fcntl
import os
import shutil
import tempfile
from collections.abc import Callable
from pathlib import Path


def publish_executable(source: Path, destination: Path) -> None:
    """Readers see the old or new binary, including while a copy is in progress."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".publish-", dir=destination.parent) as temporary:
        complete = Path(temporary) / destination.name
        shutil.copy2(source, complete)
        os.replace(complete, destination)


def build_cached_executable(destination: Path, build: Callable[[Path], None]) -> bool:
    """One process builds a key; failures never publish a partial cache entry.

    Lock files remain in the disposable cache. Unlinking them would allow a
    waiter and a new caller to acquire different locks for the same cache key.
    The kernel releases the lock if a builder exits unexpectedly.
    """
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.with_name(destination.name + ".lock").open("a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if destination.is_file():
            return False
        with tempfile.TemporaryDirectory(prefix=".build-", dir=destination.parent) as temporary:
            complete = Path(temporary) / "analysis"
            build(complete)
            os.replace(complete, destination)
        return True
