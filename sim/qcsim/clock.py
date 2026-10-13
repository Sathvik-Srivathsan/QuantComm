"""Virtual-time sim clock (B-43.1): uint64 microseconds, monotonic.

No wall-clock reads anywhere in this package (banned by construction:
this module imports neither time nor datetime — the banned-call scan
test proves it). Time advances only via the event scheduler: schedule()
enqueues (deadline, seq, label), advance() pops the earliest. No fixed
tick; ties break by insertion order (seq). Timestamps that cross into
audit/manifest records are virtual microseconds, never wall-clock.
"""
import heapq


class SimClock:
    """Monotonic uint64-microsecond event clock."""

    def __init__(self, start_us=0):
        if not isinstance(start_us, int) or start_us < 0:
            raise ValueError("start_us must be a non-negative int")
        if start_us > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("start_us exceeds uint64")
        self._now = start_us
        self._queue = []  # (deadline, seq, label)
        self._seq = 0
        self.counters = {"scheduled": 0, "advanced": 0}

    def now(self):
        """Current virtual time in microseconds (uint64 int)."""
        return self._now

    def schedule(self, delay_us, label=""):
        """Enqueue one event delay_us into the future. Returns deadline."""
        if not isinstance(delay_us, int) or delay_us < 0:
            raise ValueError("delay_us must be a non-negative int")
        deadline = self._now + delay_us
        if deadline > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("deadline exceeds uint64")
        heapq.heappush(self._queue, (deadline, self._seq, str(label)))
        self._seq += 1
        self.counters["scheduled"] += 1
        return deadline

    def advance(self):
        """Pop the earliest event. Returns (deadline, label) or None."""
        if not self._queue:
            return None
        deadline, _, label = heapq.heappop(self._queue)
        # Monotonic: scheduler deadlines never run backward (heap order
        # guarantees deadline >= _now for well-formed use; clamp is a
        # fail-safe, never a time source).
        if deadline < self._now:
            raise ValueError("scheduler went backward (corrupt queue)")
        self._now = deadline
        self.counters["advanced"] += 1
        return deadline, label

    def pending(self):
        """Number of queued events."""
        return len(self._queue)
