"""Login throttling and per-client sessions (in-memory, single-process, thread-safe)."""

import hashlib
import math
import secrets
import threading
import time
from collections.abc import Callable

Clock = Callable[[], float]


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class LoginThrottle:
    """Exponential backoff per key after `free_attempts` failures.

    The delay doubles with each further failure (1s, 2s, 4s, ...) up to `max_delay`.
    A key is forgotten `window` seconds after its last failure. Memory is bounded
    by `max_keys` (oldest entries are evicted first).
    """

    def __init__(
        self,
        free_attempts: int,
        max_delay: float = 900.0,
        window: float = 3600.0,
        max_keys: int = 10_000,
        clock: Clock = time.monotonic,
    ) -> None:
        self._free: int = free_attempts
        self._max_delay: float = max_delay
        self._window: float = window
        self._max_keys: int = max_keys
        self._clock: Clock = clock
        self._mutex: threading.Lock = threading.Lock()
        # key -> (failures, locked_until, last_failure)
        self._state: dict[str, tuple[int, float, float]] = {}

    def retry_after(self, key: str) -> int:
        with self._mutex:
            entry = self._state.get(key)
            if entry is None:
                return 0
            _, locked_until, last = entry
            now: float = self._clock()
            if now - last > self._window:
                del self._state[key]
                return 0
            return math.ceil(locked_until - now) if locked_until > now else 0

    def record_failure(self, key: str) -> None:
        with self._mutex:
            now: float = self._clock()
            failures, _, last = self._state.get(key, (0, 0.0, now))
            if now - last > self._window:
                failures = 0
            failures += 1
            over: int = failures - self._free
            delay: float = min(2.0 ** (over - 1), self._max_delay) if over > 0 else 0.0
            self._state[key] = (failures, now + delay, now)
            if len(self._state) > self._max_keys:
                oldest: str = min(self._state, key=lambda k: self._state[k][2])
                del self._state[oldest]

    def record_success(self, key: str) -> None:
        with self._mutex:
            self._state.pop(key, None)


class SessionStore:
    """Random session tokens with an idle timeout. Only token digests are stored."""

    def __init__(self, idle_seconds: int, clock: Clock = time.monotonic) -> None:
        self._idle: int = idle_seconds
        self._clock: Clock = clock
        self._mutex: threading.Lock = threading.Lock()
        self._last_seen: dict[str, float] = {}

    def create(self) -> str:
        token: str = secrets.token_urlsafe(32)
        with self._mutex:
            self._last_seen[_digest(token)] = self._clock()
        return token

    def touch(self, token: str | None) -> bool:
        """Return True and refresh the idle timer if the token is a live session."""
        if not token:
            return False
        key: str = _digest(token)
        with self._mutex:
            last: float | None = self._last_seen.get(key)
            now: float = self._clock()
            if last is None or now - last > self._idle:
                self._last_seen.pop(key, None)
                return False
            self._last_seen[key] = now
            return True

    def seconds_left(self, token: str | None) -> int | None:
        """Seconds until auto-lock for a live session, without refreshing it."""
        if not token:
            return None
        with self._mutex:
            last: float | None = self._last_seen.get(_digest(token))
            if last is None:
                return None
            left: int = int(self._idle - (self._clock() - last))
            return left if left > 0 else None

    def revoke_all(self) -> None:
        with self._mutex:
            self._last_seen.clear()

    def purge(self) -> int:
        """Drop expired sessions; return how many remain."""
        with self._mutex:
            now: float = self._clock()
            for key in [k for k, t in self._last_seen.items() if now - t > self._idle]:
                del self._last_seen[key]
            return len(self._last_seen)
