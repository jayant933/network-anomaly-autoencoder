"""
flow_features.py

Groups raw packets (from a pcap file or a live capture) into bidirectional
flows keyed by the 5-tuple, and computes a fixed-length numeric feature
vector per flow suitable for an autoencoder.

Works with scapy. Install with: pip install scapy
"""

import time
import statistics
from collections import defaultdict

try:
    from scapy.all import IP, TCP, UDP, sniff, rdpcap
except ImportError:
    raise SystemExit("Install scapy first: pip install scapy")

FLOW_TIMEOUT = 60.0  # seconds of inactivity before a flow is considered closed

FEATURE_NAMES = [
    "duration", "total_packets", "total_bytes",
    "fwd_packets", "bwd_packets", "fwd_bytes", "bwd_bytes",
    "pkt_size_mean", "pkt_size_std", "pkt_size_min", "pkt_size_max",
    "iat_mean", "iat_std", "iat_min", "iat_max",
    "syn_count", "ack_count", "rst_count", "fin_count", "psh_count",
    "pkts_per_sec", "bytes_per_sec",
    "fwd_bwd_pkt_ratio", "fwd_bwd_byte_ratio",
    "dst_port_wellknown",  # 1 if dst port < 1024 else 0
]


def _flow_key(pkt):
    """Return a canonical (direction-normalized) 5-tuple key."""
    if IP not in pkt:
        return None
    ip = pkt[IP]
    proto = ip.proto  # 6=TCP, 17=UDP
    if TCP in pkt:
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
    elif UDP in pkt:
        sport, dport = pkt[UDP].sport, pkt[UDP].dport
    else:
        return None

    a = (ip.src, sport)
    b = (ip.dst, dport)
    # normalize so (A,B) and (B,A) map to the same flow
    if a <= b:
        return (a[0], a[1], b[0], b[1], proto), True   # True = this pkt is "forward"
    else:
        return (b[0], b[1], a[0], a[1], proto), False


class FlowRecord:
    def __init__(self, key, first_ts):
        self.key = key
        self.start = first_ts
        self.last = first_ts
        self.fwd_sizes, self.bwd_sizes = [], []
        self.timestamps = []
        self.syn = self.ack = self.rst = self.fin = self.psh = 0
        self.dst_port = key[3]

    def add(self, pkt, ts, is_fwd):
        size = len(pkt)
        if is_fwd:
            self.fwd_sizes.append(size)
        else:
            self.bwd_sizes.append(size)
        self.timestamps.append(ts)
        self.last = ts

        if TCP in pkt:
            f = pkt[TCP].flags
            if f & 0x02:
                self.syn += 1
            if f & 0x10:
                self.ack += 1
            if f & 0x04:
                self.rst += 1
            if f & 0x01:
                self.fin += 1
            if f & 0x08:
                self.psh += 1

    def to_features(self):
        all_sizes = self.fwd_sizes + self.bwd_sizes
        duration = max(self.last - self.start, 1e-6)
        iats = [t2 - t1 for t1, t2 in zip(self.timestamps, self.timestamps[1:])]

        def safe_stat(fn, data, default=0.0):
            return fn(data) if data else default

        total_pkts = len(all_sizes)
        total_bytes = sum(all_sizes)

        return [
            duration,
            total_pkts,
            total_bytes,
            len(self.fwd_sizes),
            len(self.bwd_sizes),
            sum(self.fwd_sizes),
            sum(self.bwd_sizes),
            safe_stat(statistics.mean, all_sizes),
            safe_stat(statistics.pstdev, all_sizes) if len(all_sizes) > 1 else 0.0,
            safe_stat(min, all_sizes),
            safe_stat(max, all_sizes),
            safe_stat(statistics.mean, iats),
            safe_stat(statistics.pstdev, iats) if len(iats) > 1 else 0.0,
            safe_stat(min, iats),
            safe_stat(max, iats),
            self.syn, self.ack, self.rst, self.fin, self.psh,
            total_pkts / duration,
            total_bytes / duration,
            (len(self.fwd_sizes) + 1) / (len(self.bwd_sizes) + 1),
            (sum(self.fwd_sizes) + 1) / (sum(self.bwd_sizes) + 1),
            1.0 if self.dst_port < 1024 else 0.0,
        ]


def extract_flows_from_packets(packets):
    """Given an iterable of scapy packets, return a list of feature vectors
    (one per completed flow) plus the matching flow keys."""
    flows = {}
    closed = []

    for pkt in packets:
        if IP not in pkt:
            continue
        ts = float(pkt.time)
        result = _flow_key(pkt)
        if result is None:
            continue
        key, is_fwd = result

        # expire stale flows
        for k in [k for k, f in flows.items() if ts - f.last > FLOW_TIMEOUT]:
            closed.append(flows.pop(k))

        if key not in flows:
            flows[key] = FlowRecord(key, ts)
        flows[key].add(pkt, ts, is_fwd)

    closed.extend(flows.values())
    feats = [f.to_features() for f in closed if len(f.timestamps) >= 1]
    keys = [f.key for f in closed if len(f.timestamps) >= 1]
    return feats, keys


def extract_flows_from_pcap(path):
    packets = rdpcap(path)
    return extract_flows_from_packets(packets)


def live_flow_stream(iface, flow_timeout=FLOW_TIMEOUT, callback=None, count=0):
    """
    Sniff live traffic and emit closed flows as they complete.
    `callback(feature_vector, flow_key)` is called for each closed flow.
    Runs until interrupted (Ctrl+C) or `count` packets are captured.
    """
    flows = {}

    def _handle(pkt):
        if IP not in pkt:
            return
        ts = time.time()
        result = _flow_key(pkt)
        if result is None:
            return
        key, is_fwd = result

        for k in [k for k, f in flows.items() if ts - f.last > flow_timeout]:
            fr = flows.pop(k)
            if callback:
                callback(fr.to_features(), fr.key)

        if key not in flows:
            flows[key] = FlowRecord(key, ts)
        flows[key].add(pkt, ts, is_fwd)

    sniff(iface=iface, prn=_handle, store=False, count=count)
