"""Best-effort PEP 578 observation of accidental in-process I/O."""

from __future__ import annotations

import os
from pathlib import Path
import sys
from typing import Any


WATCHED_EVENTS = frozenset({"socket.connect", "socket.getaddrinfo", "subprocess.Popen", "open"})


class RuntimeIOObserver:
    """Records relevant audit events; this is telemetry, not an isolation boundary."""

    def __init__(self, allowed_roots: tuple[Path, ...]) -> None:
        self._allowed = tuple(os.path.abspath(os.fspath(path)) for path in allowed_roots)
        self._active = False
        self._events: list[dict[str, Any]] = []

        def hook(event: str, args: tuple[Any, ...]) -> None:
            if not self._active or event not in WATCHED_EVENTS:
                return
            if event == "open" and self._open_is_allowed(args):
                return
            self._events.append({"event": event, "args": [self._bounded(value) for value in args[:4]]})

        sys.addaudithook(hook)

    @staticmethod
    def _bounded(value: Any) -> str:
        return repr(value)[:512]

    def _open_is_allowed(self, args: tuple[Any, ...]) -> bool:
        if not args or not isinstance(args[0], (str, bytes, os.PathLike)):
            return False
        try:
            candidate = os.path.abspath(os.fsdecode(args[0]))
            return any(candidate == root or candidate.startswith(root + os.sep) for root in self._allowed)
        except (OSError, TypeError, ValueError):
            return False

    def start(self) -> None:
        self._active = True

    def stop(self) -> None:
        self._active = False

    @property
    def events(self) -> tuple[dict[str, Any], ...]:
        return tuple(self._events)

    @property
    def network_events(self) -> tuple[dict[str, Any], ...]:
        return tuple(item for item in self._events if item["event"].startswith("socket."))

    @property
    def subprocess_events(self) -> tuple[dict[str, Any], ...]:
        return tuple(item for item in self._events if item["event"] == "subprocess.Popen")

    @property
    def external_open_events(self) -> tuple[dict[str, Any], ...]:
        return tuple(item for item in self._events if item["event"] == "open")
