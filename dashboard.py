"""
dashboard.py

Live web dashboard for the network anomaly detector.
Runs flow capture + hybrid detection (autoencoder + port-scan rule) in a
background thread, and serves a small Flask API + HTML page that polls it.

Features:
  - Desktop notification (plyer) + optional email alert (smtplib) whenever
    a PORT SCAN or ALERT verdict fires, rate-limited per source IP.
  - /export/csv and /export/pdf routes to download a report of everything
    seen so far.
  - /api/settings (GET/POST) backs an in-dashboard Email Settings panel,
    so SMTP credentials can be configured from the UI and persist in a
    local, gitignored JSON file instead of needing CLI flags every run.

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

from flask import Flask, jsonify, render_template, Response, request

from flow_features import live_flow_stream, extract_flows_from_pcap
from autoencoder_np import FlowAutoencoderNP
from live_detect import score_vector, PortScanDetector
import alerts
import reports
import settings_store

app = Flask(__name__)

MAX_FLOWS = 300
flows_lock = threading.Lock()
recent_flows = deque(maxlen=MAX_FLOWS)
stats = Counter()

model = mean = std = alert_threshold = None
scanner = None
smtp_config = None
settings_lock = threading.Lock()
dashboard_port = 5000


def process_flow(feat_vec, key):
    src_ip, sport, dst_ip, dport, proto = key
    if dashboard_port in (sport, dport):
        return
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

    proto_label = "TCP" if proto == 6 else ("UDP" if proto == 17 else str(proto))
    entry = {
        "time": time.strftime("%H:%M:%S"),
        "src": f"{src_ip}:{sport}",
        "dst": f"{dst_ip}:{dport}",
        "proto": proto_label,
        "error": round(float(err), 4),
        "tag": tag,
    }
    with flows_lock:
        recent_flows.appendleft(entry)
        stats[tag] += 1

    if tag != "normal":
        notify_key = f"{src_ip}:{tag}"
        title = f"NetGuard AI - {tag}"
        message = f"{src_ip}:{sport} -> {dst_ip}:{dport} ({proto_label}), error={entry['error']}"
        alerts.send_desktop_alert(title, message, key=notify_key)
        with settings_lock:
            cfg = smtp_config
        alerts.send_email_alert(
            cfg,
            subject=f"[NetGuard AI] {tag} detected from {src_ip}",
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
    global model, mean, std, alert_threshold, scanner, smtp_config, dashboard_port

    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--iface", help="network interface for live capture")
    ap.add_argument("--pcap", help="pcap file to replay instead of live capture")
    ap.add_argument("--alert-multiplier", type=float, default=1.0)
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--flow-timeout", type=float, default=5.0)
    args = ap.parse_args()

    if not args.iface and not args.pcap:
        raise SystemExit("Provide --iface for live capture or --pcap to replay a file.")

    saved = settings_store.load_settings()
    if saved:
        smtp_config = saved
        print(f"Loaded saved email settings -> alerts to {saved.get('to_addr')}")
    else:
        print("Email alerts disabled (configure them from the dashboard's Email Settings panel)")

    model, mean, std, threshold = FlowAutoencoderNP.load(args.model)
    alert_threshold = threshold * args.alert_multiplier
    scanner = PortScanDetector()
    dashboard_port = args.port

    t = threading.Thread(target=start_capture,
                          kwargs={"iface": args.iface, "pcap": args.pcap, "flow_timeout": args.flow_timeout},
                          daemon=True)
    t.start()

    print(f"Dashboard running at http://127.0.0.1:{args.port}")
    app.run(host="0.0.0.0", port=args.port, debug=False)


if __name__ == "__main__":
    main()