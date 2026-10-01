"""Port checks. A port in use is reported (with its owner where the OS lets us see it) and
never freed by force: the tooling does not kill processes it did not start."""

from __future__ import annotations

import errno
import socket
from dataclasses import dataclass

try:
    import psutil
except ImportError:  # pragma: no cover - setup installs it; owners are then "unknown"
    psutil = None


@dataclass(frozen=True)
class PortOwner:
    pid: int | None
    name: str | None

    def describe(self) -> str:
        if self.pid is None:
            return "an unknown process (run as administrator to see it)"
        return f"{self.name or 'process'} (PID {self.pid})"


def is_free(port: int, host: str = "127.0.0.1") -> bool:
    """True when nothing listens on ``host:port``.

    Binding (not connecting) is the reliable test, with the socket options the servers use:
    on POSIX ``SO_REUSEADDR`` (connections still closing in TIME_WAIT after a clean stop do
    not block a new listener, but a live listener does); on Windows ``SO_EXCLUSIVEADDRUSE``
    (there ``SO_REUSEADDR`` would let us bind over a live listener)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        exclusive = getattr(socket, "SO_EXCLUSIVEADDRUSE", None)
        if exclusive is not None:
            sock.setsockopt(socket.SOL_SOCKET, exclusive, 1)
        else:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
        except OSError as exc:
            if exc.errno in (errno.EADDRINUSE, errno.EACCES, getattr(errno, "WSAEADDRINUSE", -1)):
                return False
            raise
    return True


def is_listening(port: int, host: str = "127.0.0.1", timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def owner(port: int) -> PortOwner:
    """Who listens on ``port`` (best effort; never raises)."""
    if psutil is None:
        return PortOwner(None, None)
    try:
        connections = psutil.net_connections(kind="tcp")
    except (psutil.AccessDenied, OSError):
        return PortOwner(None, None)
    for conn in connections:
        if conn.status == psutil.CONN_LISTEN and conn.laddr and conn.laddr.port == port:
            if conn.pid is None:
                return PortOwner(None, None)
            try:
                return PortOwner(conn.pid, psutil.Process(conn.pid).name())
            except (psutil.Error, OSError):
                return PortOwner(conn.pid, None)
    return PortOwner(None, None)


def busy_message(port: int, setting: str) -> str:
    who = owner(port).describe()
    return (
        f"port {port} is already in use by {who}. Stop that program, or choose another "
        f"port: set {setting}=<port> in sentinel.local.env. (Nothing was stopped.)"
    )
