"""
dashboard.py

Live web dashboard for the network anomaly detector.

Detection layers (highest priority first):
  1. SYN FLOOD  - many half-open flows to one ip:port (rule-based)
  2. PORT SCAN  - one source touching many distinct ports (rule-based)
  3. ALERT      - autoencoder reconstruction error above threshold (ML)
Flows initiated by a whitelisted (trusted) IP are tagged "trusted" and skip
all detectors.

Dashboard extras: alerts-over-time trend, top attackers / top talkers,
trusted-IP management, email/desktop alerts, PDF/CSV export.

Usage:
    python3 dashboard.py --model model.npz --pcap attack_test.pcap
    sudo python3 dashboard.py --model model.npz --iface lo --flow-timeout 3
"""

import argparse
import threading
import time
from collections import deque, Counter, defaultdict

from flask import Flask, jsonify, render_template, Response, request

from flow_features import live_flow_stream, extract_flows_from_pcap
from autoencoder_np import FlowAutoencoderNP
from live_detect import score_vector, PortScanDetector
from detectors import SynFloodDetector, target_of
from whitelist import Whitelist
import alerts
import reports
import settings_store

app = Flask(__name__)

MAX_FLOWS = 300
TREND_BUCKET_SECONDS = 10
TREND_BUCKETS = 30  # 30 x 10s = last 5 minutes
FLAGGED = ("SYN FLOOD", "PORT SCAN", "ALERT")

# flows_lock protects everything in this block
flows_lock = threading.Lock()
recent_flows = deque(maxlen=MAX_FLOWS)
stats = Counter()
attacker_counts = Counter()              # actor ip -> flagged flows
attacker_types = defaultdict(Counter)    # actor ip -> {tag: count}
talker_bytes = Counter()                 # actor ip -> bytes
talker_flows = Counter()                 # actor ip -> flows
trend = {}                               # bucket start -> Counter(tag)

whitelist = Whitelist()

# populated in main()
model = mean = std = alert_threshold = None
scanner = None
flood_detector = None
smtp_config = None
settings_lock = threading.Lock()
dashboard_port = 5000  # own HTTP traffic on this port is ignored in live mode


def process_flow(feat_vec, key):
    src_ip, sport, dst_ip, dport, proto = key
    if dashboard_port in (sport, dport):
        return  # ignore the dashboard's own browser polling traffic

    t_ip, t_port, actor = target_of(key)  # server ip/port and the client (actor) ip
    err = score_vector(model, mean, std, feat_vec)
    detail = ""

    if whitelist.contains(actor):
        tag = "trusted"
    else:
        is_flood, half_open, n_clients = flood_detector.check(feat_vec, key)
        # port scan = one actor touching many distinct TARGET ports on one host
        is_scan, scan_count = scanner.check(f"{actor}->{t_ip}", t_port)
        if is_flood:
            tag = "SYN FLOOD"
            detail = (f", {half_open} half-open flows from {n_clients} "
                      f"client(s) in {flood_detector.window:.0f}s")
        elif is_scan:
            tag = "PORT SCAN"
            detail = f", fan-out={scan_count} ports"
        elif err > alert_threshold:
            tag = "ALERT"
        else:
            tag = "normal"

    now = time.time()
    proto_label = "TCP" if proto == 6 else ("UDP" if proto == 17 else str(proto))
    entry = {
        "time": time.strftime("%H:%M:%S"),
        "src": f"{src_ip}:{sport}",
        "dst": f"{dst_ip}:{dport}",
        "proto": proto_label,
        "error": round(float(err), 4),
        "tag": tag,
        "actor": actor,
    }
    bucket = int(now // TREND_BUCKET_SECONDS * TREND_BUCKET_SECONDS)

    with flows_lock:
        recent_flows.appendleft(entry)
        stats[tag] += 1
        talker_bytes[actor] += int(feat_vec[2])
        talker_flows[actor] += 1
        if tag in FLAGGED:
            attacker_counts[actor] += 1
            attacker_types[actor][tag] += 1
            trend.setdefault(bucket, Counter())[tag] += 1
            for old in sorted(trend)[:-TREND_BUCKETS * 2]:
                del trend[old]

    if tag in FLAGGED:
        notify_key = f"{actor}:{tag}"
        title = f"NetGuard AI - {tag}"
        message = (f"{src_ip}:{sport} -> {dst_ip}:{dport} ({proto_label}), "
                   f"error={entry['error']}{detail}")
        alerts.send_desktop_alert(title, message, key=notify_key)
        with settings_lock:
            cfg = smtp_config
        alerts.send_email_alert(
            cfg,
            subject=f"[NetGuard AI] {tag} detected from {actor}",
            body=f"{title}\n\n{message}",
            key=notify_key,
        )


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


@app.route("/api/trend")
def api_trend():
    """Flagged flows per 10s bucket for the last 5 minutes (zero-filled)."""
    now_bucket = int(time.time() // TREND_BUCKET_SECONDS * TREND_BUCKET_SECONDS)
    labels = []
    series = {"ALERT": [], "PORT SCAN": [], "SYN FLOOD": []}
    with flows_lock:
        for i in range(TREND_BUCKETS - 1, -1, -1):
            b = now_bucket - i * TREND_BUCKET_SECONDS
            counts = trend.get(b, {})
            labels.append(time.strftime("%H:%M:%S", time.localtime(b)))
            for tag in series:
                series[tag].append(counts.get(tag, 0))
    return jsonify({"labels": labels, "series": series})


@app.route("/api/top")
def api_top():
    with flows_lock:
        attackers = []
        for ip, n in attacker_counts.most_common():
            if whitelist.contains(ip):
                continue  # trusted since it was flagged - don't list it
            attackers.append({"ip": ip, "count": n, "types": dict(attacker_types[ip])})
            if len(attackers) == 5:
                break
        talkers = [{"ip": ip, "bytes": b, "flows": talker_flows[ip]}
                   for ip, b in talker_bytes.most_common(5)]
    return jsonify({"attackers": attackers, "talkers": talkers})


@app.route("/api/whitelist", methods=["GET"])
def get_whitelist():
    return jsonify({"entries": whitelist.entries()})


@app.route("/api/whitelist", methods=["POST"])
def set_whitelist():
    data = request.get_json(force=True, silent=True) or {}
    entries = data.get("entries", [])
    if not isinstance(entries, list):
        return jsonify({"error": "entries must be a list"}), 400
    try:
        saved = whitelist.set_entries(entries)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"status": "ok", "entries": saved})


@app.route("/api/settings", methods=["GET"])
def get_settings():
    with settings_lock:
        cfg = smtp_config
    if cfg:
        safe = {k: v for k, v in cfg.items() if k != "password"}
        safe["enabled"] = True
        safe["has_password"] = bool(cfg.get("password"))
        return jsonify(safe)
    return jsonify({"enabled": False})


@app.route("/api/settings", methods=["POST"])
def update_settings():
    global smtp_config
    data = request.get_json(force=True) or {}

    if not data.get("enabled"):
        with settings_lock:
            smtp_config = None
        settings_store.save_settings(None)
        return jsonify({"status": "disabled"})

    with settings_lock:
        existing_password = smtp_config.get("password") if smtp_config else ""

    new_config = {
        "host": data.get("host", "smtp.gmail.com"),
        "port": int(data.get("port", 587)),
        "user": data.get("user", ""),
        "password": data.get("password") or existing_password,
        "from_addr": data.get("from_addr", ""),
        "to_addr": data.get("to_addr", ""),
    }
    with settings_lock:
        smtp_config = new_config
    settings_store.save_settings(new_config)
    return jsonify({"status": "enabled"})


@app.route("/export/csv")
def export_csv():
    with flows_lock:
        data = reports.generate_csv_report(list(recent_flows), dict(stats))
    return Response(
        data,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=netguard_report.csv"},
    )


@app.route("/export/pdf")
def export_pdf():
    with flows_lock:
        data = reports.generate_pdf_report(list(recent_flows), dict(stats))
    return Response(
        data,
        mimetype="application/pdf",
        headers={"Content-Disposition": "attachment; filename=netguard_report.pdf"},
    )


def start_capture(iface=None, pcap=None, flow_timeout=5.0):
    if pcap:
        feats, keys = extract_flows_from_pcap(pcap)
        for f, k in zip(feats, keys):
            process_flow(f, k)
            time.sleep(0.08)
    else:
        live_flow_stream(iface, flow_timeout=flow_timeout, callback=process_flow)


def main():
    global model, mean, std, alert_threshold, scanner, flood_detector
    global smtp_config, dashboard_port

    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--iface", help="network interface for live capture")
    ap.add_argument("--pcap", help="pcap file to replay instead of live capture")
    ap.add_argument("--alert-multiplier", type=float, default=1.0)
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--flow-timeout", type=float, default=5.0,
                    help="live mode: seconds of inactivity before a flow is scored")
    ap.add_argument("--flood-window", type=float, default=5.0,
                    help="SYN flood: window in seconds")
    ap.add_argument("--flood-threshold", type=int, default=10,
                    help="SYN flood: half-open flows to one ip:port within the window")
    args = ap.parse_args()

    if not args.iface and not args.pcap:
        raise SystemExit("Provide --iface for live capture or --pcap to replay a file.")

    saved = settings_store.load_settings()
    if saved:
        smtp_config = saved
        print(f"Loaded saved email settings -> alerts to {saved.get('to_addr')}")
    else:
        print("Email alerts disabled (configure them from the dashboard's Email Alerts panel)")

    trusted = whitelist.entries()
    print(f"Trusted IPs loaded: {len(trusted)}" + (f" {trusted}" if trusted else ""))

    model, mean, std, threshold = FlowAutoencoderNP.load(args.model)
    alert_threshold = threshold * args.alert_multiplier
    scanner = PortScanDetector()
    flood_detector = SynFloodDetector(window_seconds=args.flood_window,
                                      threshold=args.flood_threshold)
    dashboard_port = args.port

    t = threading.Thread(
        target=start_capture,
        kwargs={"iface": args.iface, "pcap": args.pcap, "flow_timeout": args.flow_timeout},
        daemon=True,
    )
    t.start()

    print(f"Dashboard running at http://127.0.0.1:{args.port}")
    app.run(host="0.0.0.0", port=args.port, debug=False)


if __name__ == "__main__":
    main()