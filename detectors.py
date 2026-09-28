"""
detectors.py

Rule-based detectors that complement the autoencoder.

SynFloodDetector
    Flags many half-open TCP flows hitting the SAME target ip:port within a
    short window - the classic SYN flood / DoS pattern. A port scan touches
    many different ports once each, while a flood hammers ONE port over and
    over, so the two are easy to tell apart.
"""

import time
from collections import defaultdict, deque

# positions in the vector built by flow_features.FlowRecord.to_features()
IDX_TOTAL_PKTS = 1
IDX_SYN = 15
IDX_FIN = 18
IDX_PSH = 19


def target_of(key):
    """key = (ip_a, port_a, ip_b, port_b, proto).

    Heuristic: the side with the LOWER port is the server (target), the other
    side is the client / actor.  Returns (target_ip, target_port, actor_ip).
    """
    a_ip, a_port, b_ip, b_port, _proto = key
    if a_port <= b_port:
        return a_ip, a_port, b_ip
    return b_ip, b_port, a_ip


# A half-open flow is more than SYN / SYN-ACK / RST in practice: the server
# retransmits SYN-ACKs, and captures on the loopback interface see every
# packet twice. So allow a handful of packets, but no payload (PSH) and no
# clean close (FIN).
MAX_HALF_OPEN_PACKETS = 10


def is_half_open(feat_vec):
    """Flow started with a SYN but never carried data or closed cleanly."""
    return (feat_vec[IDX_SYN] >= 1
            and feat_vec[IDX_PSH] == 0
            and feat_vec[IDX_FIN] == 0
            and feat_vec[IDX_TOTAL_PKTS] <= MAX_HALF_OPEN_PACKETS)


class SynFloodDetector:
    def __init__(self, window_seconds=5.0, threshold=20):
        self.window = window_seconds
        self.threshold = threshold
        self.history = defaultdict(deque)  # (target_ip, target_port) -> deque[(ts, client_ip)]

    def check(self, feat_vec, key, ts=None):
        """Returns (is_flood, half_open_count, distinct_clients)."""
        if not is_half_open(feat_vec):
            return False, 0, 0
        ts = ts if ts is not None else time.time()
        t_ip, t_port, client = target_of(key)
        hist = self.history[(t_ip, t_port)]
        hist.append((ts, client))
        cutoff = ts - self.window
        while hist and hist[0][0] < cutoff:
            hist.popleft()
        if len(self.history) > 2000:  # keep memory bounded
            for k in [k for k, h in self.history.items() if not h or h[-1][0] < cutoff]:
                del self.history[k]
        return len(hist) >= self.threshold, len(hist), len({c for _, c in hist})