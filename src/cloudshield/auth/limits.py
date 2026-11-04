import math
import threading

MAX_ADDRESSES = 10_000


class LoginLimiter:
    """Counts wrong passwords for each client address. After max_failures within window_seconds
    the address has to wait. It lives in the memory of one server process."""

    def __init__(self, max_failures: int = 5, window_seconds: int = 300) -> None:
        self.max_failures = max_failures
        self.window = window_seconds
        self.failures: dict[str, list[float]] = {}
        self.lock = threading.Lock()

    def recent(self, address: str, now: float) -> list[float]:
        return [t for t in self.failures.get(address, []) if now - t < self.window]

    def wait(self, address: str, now: float) -> int:
        """Seconds the address must wait before trying again, or 0."""
        with self.lock:
            recent = self.recent(address, now)
            if len(recent) < self.max_failures:
                return 0
            return math.ceil(self.window - (now - recent[len(recent) - self.max_failures]))

    def fail(self, address: str, now: float) -> None:
        with self.lock:
            if len(self.failures) >= MAX_ADDRESSES:
                # Forget addresses with nothing recent, so the table cannot grow without limit.
                self.failures = {a: ts for a in self.failures if (ts := self.recent(a, now))}
            self.failures[address] = [*self.recent(address, now), now]

    def clear(self, address: str) -> None:
        with self.lock:
            self.failures.pop(address, None)
