"""
live_detect.py

Real-time zero-day / anomaly detection on live network flows.
Hybrid detection:
  1. Autoencoder reconstruction-error scoring (catches behavior anomalies,
     e.g. service probing / version detection).
  2. A rule-based "fan-out" port-scan detector (catches simple single-packet
     SYN scans that look small/normal to the autoencoder but are anomalous
     because ONE source IP touches MANY distinct destination ports quickly).

Usage (requires root / CAP_NET_RAW for live sniffing):
    sudo python live_detect.py --iface eth0 --model model.npz

Also supports scoring a pcap file instead of a live interface:
    python live_detect.py --pcap attack_test.pcap --model model.npz
"""

import argparse
import time
from collections import defaultdict

import numpy as np

from flow_features import live_flow_stream, extract_flows_from_pcap
from autoencoder_np import FlowAutoencoderNP


def score_vector(model, mean, std, vec):
    x = (np.array(vec, dtype=np.float64) - mean) / std
    x = x.reshape(1, -1)
    err = model.reconstruction_error(x)[0]
    return err


class PortScanDetector:
    """
    Tracks, per source IP, the set of distinct destination ports touched
    within a sliding time window. If a single source IP touches more than
    `port_threshold` distinct ports within `window_seconds`, it's flagged
    as a port scan - independent of the autoencoder's verdict.
    """

    def __init__(self, window_seconds=10.0, port_threshold=15):
        self.window = window_seconds
        self.threshold = port_threshold
        # src_ip -> list of (timestamp, dst_port)
        self.history = defaultdict(list)

    def check(self, src_ip, dst_port, ts=None):
        ts = ts if ts is not None else time.time()
        hist = self.history[src_ip]
        hist.append((ts, dst_port))
        # drop entries older than the window
        cutoff = ts - self.window
        while hist and hist[0][0] < cutoff:
            hist.pop(0)
        distinct_ports = len({p for _, p in hist})
        return distinct_ports >= self.threshold, distinct_ports


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--iface", help="network interface for live capture")
    ap.add_argument("--pcap", help="pcap file to score instead of live capture")
    ap.add_argument("--alert-multiplier", type=float, default=1.0,
                     help="multiply the trained threshold by this before alerting")
    ap.add_argument("--scan-window", type=float, default=10.0,
                     help="seconds for the port-scan fan-out window")
    ap.add_argument("--scan-port-threshold", type=int, default=15,
                     help="distinct ports from one source within the window to flag a scan")
    args = ap.parse_args()

    if not args.iface and not args.pcap:
        raise SystemExit("Provide --iface for live capture or --pcap for offline scoring.")

    model, mean, std, threshold = FlowAutoencoderNP.load(args.model)
    alert_threshold = threshold * args.alert_multiplier
    scanner = PortScanDetector(window_seconds=args.scan_window,
                                port_threshold=args.scan_port_threshold)

    print(f"Loaded model. Autoencoder alert threshold = {alert_threshold:.5f}")
    print(f"Port-scan rule: >= {args.scan_port_threshold} distinct ports from one "
          f"source within {args.scan_window}s\n")

    def handle_flow(feat_vec, key):
        src_ip, sport, dst_ip, dport, proto = key
        err = score_vector(model, mean, std, feat_vec)
        is_ae_alert = err > alert_threshold

        # check both directions - either side could be the "scanner"
        is_scan_a, count_a = scanner.check(src_ip, dport)
        is_scan_b, count_b = scanner.check(dst_ip, sport)
        is_scan = is_scan_a or is_scan_b
        scan_count = max(count_a, count_b)

        if is_scan:
            tag = "PORT SCAN"
        elif is_ae_alert:
            tag = "ALERT    "
        else:
            tag = "normal   "

        extra = f"  (fan-out={scan_count} ports)" if is_scan else ""
        print(f"[{tag}] ae_err={err:.5f}  {src_ip}:{sport} -> {dst_ip}:{dport} "
              f"(proto={proto}){extra}")

    if args.pcap:
        feats, keys = extract_flows_from_pcap(args.pcap)
        for f, k in zip(feats, keys):
            handle_flow(f, k)
    else:
        print(f"Sniffing on {args.iface} ... Ctrl+C to stop.")
        live_flow_stream(args.iface, callback=handle_flow)


if __name__ == "__main__":
    main()
