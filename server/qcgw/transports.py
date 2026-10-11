"""Host transports (B-42.3): loopback + TCP, identical interface.

Both endpoints expose send(frame)/recv()/close()/stats()/sweep(now):
frames in, frames out; fragmentation/reassembly internal. Faults are
deterministic every-N patterns (never random, never timed-asserted):
drop/dup/corrupt/truncate per fragment, adjacent-pair reorder within
one send burst, optional sleep (timing never asserted by tests).

Layering (documented mapping): endpoints fragment with per-direction
transport sequence numbers and reassemble with the shared Reassembler
keyed (far-end name, epoch 0, transport-seq). The (peer, epoch,
counter) KEY SHAPE is preserved; values are transport-scoped, so frame
bytes ride opaquely (no frame parsing here — any bytes transport).
Reassembly-key semantics from real (peer, epoch, counter) keys live in
the frag unit tests, not here.

TCP wire: each fragment length-prefixed u32BE (max = max_frame + frag
overhead; over-length prefix aborts the connection + alarm — never
allocates unbounded). Sockets blocking with timeouts (prototype;
same-thread scripted use). Loopback: in-process deques, same method
shapes (timeout params accepted, unused beyond signature parity).

max_frame defaults to the B-20.1 value computed from its formula
(QC_MAX_FRAME below; pytest const-guards it against qc_codec.h —
single source, never copied blindly). MTU is a test knob (default
1024, labeled — B-61 owns real values).
"""
import socket
import time

from .frag import Reassembler, split_frame

# B-20.1 single source, mirrored (const-guarded by test against
# qc_codec.h — never blindly copied: edit either side and the guard
# fires). Formula 62 + 2*FIELD is the C header's own arithmetic.
QC_CODEC_MAX_FIELD = 65535
QC_MAX_FRAME = 62 + 2 * QC_CODEC_MAX_FIELD
QC_MAX_FRAG_OVERHEAD = 8


class _Endpoint:
    """Shared endpoint machinery (private; factories are the API)."""

    def __init__(self, name, far_name, mtu, max_frame, faults,
                 send_fn, recv_fn, close_fn):
        if mtu < 9:
            raise ValueError("mtu below fragment header")
        if max_frame <= 0:
            raise ValueError("max_frame must be positive")
        self._name = name
        self._far = far_name
        self._mtu = mtu
        self._max_frame = max_frame
        self._faults = dict(faults or {})
        self._send_fn = send_fn
        self._recv_fn = recv_fn
        self._close_fn = close_fn
        self._reasm = Reassembler(max_frame)
        self._seq = 0
        self._fcount = {}
        self._closed = False
        self._stats = {
            "sent_frames": 0,
            "sent_frags": 0,
            "dropped_frags": 0,
            "duped_frags": 0,
            "corrupted_frags": 0,
            "truncated_frags": 0,
            "reordered_bursts": 0,
            "delivered": 0,
            "aborted_overlength": 0,
        }

    def _hit(self, name):
        # Per-fault counters (audit fix: a shared counter made every-N
        # patterns unpredictable across fault types; separate phases
        # read exactly as configured).
        every = self._faults.get(name, 0)
        if every <= 0:
            return False
        c = self._fcount.get(name, 0) + 1
        self._fcount[name] = c
        return (c % every) == 0

    def send(self, frame, now=0.0):
        """Fragment + fault + transmit one frame."""
        if self._closed:
            raise ValueError("endpoint closed")
        if not isinstance(frame, (bytes, bytearray)) or \
                len(frame) == 0:
            raise ValueError("frame must be nonempty bytes")
        if len(frame) > self._max_frame:
            raise ValueError("oversize frame refused pre-fragment")
        frags = split_frame(bytes(frame), self._mtu, self._max_frame)
        out = []
        for f in frags:
            if self._hit("drop_every"):
                self._stats["dropped_frags"] += 1
                continue
            if self._hit("truncate_every"):
                f = f[:max(1, len(f) // 2)]
                self._stats["truncated_frags"] += 1
            if self._hit("corrupt_every"):
                b = bytearray(f)
                b[-1] ^= 1
                f = bytes(b)
                self._stats["corrupted_frags"] += 1
            out.append(f)
            if self._hit("dup_every"):
                out.append(f)
                self._stats["duped_frags"] += 1
        # Adjacent-pair reorder, windowed across the burst.
        window = self._faults.get("reorder_window", 0)
        if window >= 2 and len(out) >= 2:
            for base in range(0, len(out), window):
                chunk = out[base:base + window]
                for i in range(0, len(chunk) - 1, 2):
                    chunk[i], chunk[i + 1] = chunk[i + 1], chunk[i]
                out[base:base + window] = chunk
            self._stats["reordered_bursts"] += 1
        delay = self._faults.get("delay_ms", 0)
        if delay > 0:
            time.sleep(delay / 1000.0)
        self._stats["sent_frames"] += 1
        self._stats["sent_frags"] += len(out)
        self._send_fn(out, now)
        return True

    def recv(self, now=0.0):
        """Drain one complete frame. Returns (status, bytes|None).

        Status: ok / empty / closed / aborted-overlength.
        """
        if self._closed:
            return "closed", None
        while True:
            item = self._recv_fn(now)
            if item is None:
                # Nothing more right now (partial reassembly state kept
                # for the next call; TCP may block to its timeout first
                # — documented blocking semantics).
                return "empty", None
            if isinstance(item, tuple):
                # Transport-level abort: close the connection (framing
                # desynced — staying open would misparse everything
                # after) and report once.
                self._stats["aborted_overlength"] += 1
                self.close()
                return item
            # Far-end names are transport-local labels (str); the
            # reassembly key needs bytes — encoded here at the single
            # call site (audit: passing str silently malformed every
            # fragment, caught by the parity tests).
            far = self._far.encode() if isinstance(self._far, str) \
                else bytes(self._far)
            status, frame = self._reasm.feed(far, 0, item, now)
            if status == "complete":
                self._stats["delivered"] += 1
                return "ok", frame
            # Incomplete or dropped: keep draining (loopback may hold
            # more; TCP may block to timeout and yield None above).

    def sweep(self, now=0.0):
        return self._reasm.sweep(now)

    def counters(self):
        out = dict(self._stats)
        out.update(self._reasm.counters)
        return out

    def close(self):
        self._closed = True
        self._close_fn()


def loopback_pair(mtu=1024, max_frame=QC_MAX_FRAME, faults_a=None,
                  faults_b=None):
    """In-process bidirectional pair (same interface as TCP)."""
    from collections import deque

    qa, qb = deque(), deque()

    def mk_send(q):
        def go(frags, _now):
            q.extend(frags)
        return go

    def mk_recv(q):
        def go(_now):
            return q.popleft() if q else None
        return go

    def noop():
        return None

    a = _Endpoint("a", "b", mtu, max_frame, faults_a or {},
                  mk_send(qb), mk_recv(qa), noop)
    b = _Endpoint("b", "a", mtu, max_frame, faults_b or {},
                  mk_send(qa), mk_recv(qb), noop)
    return a, b


def _read_frag(sock, buf, max_frame):
    """One framed read-step over a byte stream (private; tested).

    Returns fragment bytes, None (need more / timed out), or an
    (abort/closed, None) tuple. Over-length prefix aborts (never
    allocates unbounded); EOF closes. Blocking to the socket timeout.
    """
    while len(buf) < 4:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            return None
        if not chunk:
            return ("closed", None)
        buf.extend(chunk)
    size = int.from_bytes(bytes(buf[:4]), "big")
    if size > max_frame + QC_MAX_FRAG_OVERHEAD:
        return ("aborted-overlength", None)
    while len(buf) < 4 + size:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            return None
        if not chunk:
            return ("closed", None)
        buf.extend(chunk)
    frag = bytes(buf[4:4 + size])
    del buf[:4 + size]
    return frag


def tcp_pair(mtu=1024, max_frame=QC_MAX_FRAME, faults_a=None,
             faults_b=None, timeout_s=5.0):
    """TCP loopback pair over 127.0.0.1 (ephemeral port).

    Returns (ep_a, ep_b, port): the port lets tests drive raw adversarial
    bytes at either end (over-length abort path). Sequential scripted
    use (no threads): listener backlog holds the connect until accept
    runs. Blocking sockets with timeouts.
    """
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(timeout_s)
    port = listener.getsockname()[1]
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(timeout_s)
    client.connect(("127.0.0.1", port))
    server, _ = listener.accept()
    server.settimeout(timeout_s)
    listener.close()

    def mk_send(sock):
        def go(frags, _now):
            for f in frags:
                sock.sendall(len(f).to_bytes(4, "big") + f)
        return go

    def mk_recv(sock):
        buf = bytearray()

        def go(_now):
            return _read_frag(sock, buf, max_frame)
        return go

    def mk_close(sock):
        def go():
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()
        return go

    a = _Endpoint("a", "b", mtu, max_frame, faults_a or {},
                  mk_send(client), mk_recv(client), mk_close(client))
    b = _Endpoint("b", "a", mtu, max_frame, faults_b or {},
                  mk_send(server), mk_recv(server), mk_close(server))
    return a, b, port
