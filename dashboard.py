"""
dashboard.py

Live web dashboard for the network anomaly detector.
Runs flow capture + hybrid detection (autoencoder + port-scan rule) in a
background thread, and serves a small Flask API + HTML page that polls it.

Usage:
    # replay a pcap for a demo (no root needed)
    python3 dashboard.py --model model.npz --pcap attack_test.pcap

    # live capture (needs root)
    sudo python3 dashboard.py --model model.npz --iface eth0
"""

import argparse
import threading
import time
from collections import deque, Counter

from flask import Flask, jsonify, render_template

from flow_features import live_flow_stream, extract_flows_from_pcap
from autoencoder_np import FlowAutoencoderNP
from live_detect import score_vector, PortScanDetector

app = Flask(__name__)

MAX_FLOWS = 300
flows_lock = threading.Lock()
recent_flows = deque(maxlen=MAX_FLOWS)
stats = Counter()

# populated in main()
model = mean = std = alert_threshold = None
scanner = None


def process_flow(feat_vec, key):
    src_ip, sport, dst_ip, dport, proto = key
    err = score_vector(model, mean, std, feat_vec)
    is_ae_alert = err > alert_threshold

    is_scan_a, count_a = scanner.check(src_ip, dport)
    is_scan_b, count_b = scanner.check(dst_ip, sport)
    is_scan = is_scan_a or is_scan_b

    if is_scan:
        tag = "PORT SCAN"
    elif is_ae_alert:
        tag = "ALERT"
    else:
        tag = "normal"

    entry = {
        "time": time.strftime("%H:%M:%S"),
        "src": f"{src_ip}:{sport}",
        "dst": f"{dst_ip}:{dport}",
        "proto": "TCP" if proto == 6 else ("UDP" if proto == 17 else str(proto)),
        "error": round(float(err), 4),
        "tag": tag,
    }
    with flows_lock:
        recent_flows.appendleft(entry)
        stats[tag] += 1


@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/api/flows")
def api_flows():
    with flows_lock:
        return jsonify(list(recent_flows))


@app.route("/api/stats")
def api_stats():
    with flows_lock:
        return jsonify(dict(stats))


def start_capture(iface=None, pcap=None):
    if pcap:
        feats, keys = extract_flows_from_pcap(pcap)
        for f, k in zip(feats, keys):
            process_flow(f, k)
            time.sleep(0.08)  # slow the replay down so it feels "live" on the dashboard
    else:
        live_flow_stream(iface, callback=process_flow)


def main():
    global model, mean, std, alert_threshold, scanner

    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--iface", help="network interface for live capture")
    ap.add_argument("--pcap", help="pcap file to replay instead of live capture")
    ap.add_argument("--alert-multiplier", type=float, default=1.0)
    ap.add_argument("--port", type=int, default=5000)
    args = ap.parse_args()

    if not args.iface and not args.pcap:
        raise SystemExit("Provide --iface for live capture or --pcap to replay a file.")

    model, mean, std, threshold = FlowAutoencoderNP.load(args.model)
    alert_threshold = threshold * args.alert_multiplier
    scanner = PortScanDetector()

    t = threading.Thread(target=start_capture,
                          kwargs={"iface": args.iface, "pcap": args.pcap},
                          daemon=True)
    t.start()

    print(f"Dashboard running at http://127.0.0.1:{args.port}")
    app.run(host="0.0.0.0", port=args.port, debug=False)


if __name__ == "__main__":
    main()
