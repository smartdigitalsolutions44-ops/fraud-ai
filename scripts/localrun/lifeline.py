"""A lifeline between the supervisor and one service, so a service never outlives it.

The supervisor starts each service as ``python lifeline.py <command...>`` with a pipe on the
lifeline's standard input that it never writes to. If the supervisor goes away for any reason
(stopped, crashed, killed by a test runner), the operating system closes that pipe, the
lifeline reads end-of-file and stops its service: SIGTERM (graceful) on POSIX, then a forced
stop after 10 seconds. That works the same on Linux, macOS and Windows, with no parent-death
signals and no Windows job objects.

Normal stops do not use this path: the supervisor signals the process group (the lifeline and
its service share it), the service shuts down, and the lifeline exits with its exit code.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading

GRACE_SECONDS = 10.0


def main(argv: list[str]) -> int:
    if not argv:
        print("usage: lifeline.py <command> [args...]", file=sys.stderr)
        return 2
    # The service shares the lifeline's process group, stdout and stderr.
    child = subprocess.Popen(argv, stdin=subprocess.DEVNULL)  # noqa: S603  # nosec B603

    def orphaned() -> None:
        sys.stdin.buffer.read()  # blocks until the supervisor's end of the pipe closes
        if child.poll() is not None:
            return
        child.terminate()  # SIGTERM on POSIX: the service shuts down gracefully
        try:
            child.wait(timeout=GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            child.kill()
        os._exit(1)

    threading.Thread(target=orphaned, daemon=True).start()
    # A stop signal sent to the group reaches the service directly; the lifeline only waits
    # for it, so it must not die first.
    for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        sig = getattr(signal, name, None)
        if sig is not None:
            signal.signal(sig, lambda signum, frame: None)
    return child.wait()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
