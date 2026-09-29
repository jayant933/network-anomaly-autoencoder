# NetGuard AI — Real-Time Network Anomaly Detection

A hybrid network intrusion detection system that combines an **unsupervised
autoencoder** (for catching unknown/zero-day behavior anomalies) with
**rule-based detectors** (port-scan fan-out and SYN flood), served through a
live web dashboard with trusted-IP management, desktop/email alerting, and
downloadable reports.

## How it works

1. **Flow extraction** — raw packets (captured via `tcpdump`/Wireshark or
   live via `scapy`) are grouped into bidirectional flows keyed by the
   5-tuple (src IP, dst IP, src port, dst port, protocol).
2. **Feature engineering** — 25 statistical features are computed per flow:
   packet/byte counts, packet size stats, inter-arrival time stats, TCP flag
   counts, flow rate, and port-based signals.
3. **Autoencoder (pure NumPy, no PyTorch)** — a small feedforward
   bottleneck network (`25 → 20 → 14 → 8 → 14 → 20 → 25`) is trained *only*
   on benign traffic. Reconstruction error is used as an anomaly score —
   traffic that looks statistically different from anything seen during
   training (e.g. service/version probing) gets a high error and is
   flagged, even without ever having seen that specific attack before.
   Forward pass, backprop, and the Adam optimizer are all implemented from
   scratch in NumPy — no ML framework dependency, so the whole project
   installs in seconds with no GPU/CUDA requirement.
4. **Rule-based port-scan detector** — the autoencoder alone struggles with
   simple single-packet SYN scans (each individual flow is tiny and looks
   unremarkable). A layer tracks how many *distinct destination ports* a
   single source touches on one target within a sliding time window;
   crossing a threshold flags a classic port-scan fan-out pattern regardless
   of what the autoencoder says.
5. **Rule-based SYN flood detector** — tracks half-open TCP flows (SYN sent,
   no payload, never cleanly closed) landing on the *same* target ip:port
   within a short window. A port scan touches many different ports once
   each; a flood hammers one port repeatedly — the two patterns are
   distinguished by counting target ports vs. counting hits on one port.
6. **Trusted IPs (whitelist)** — any IP or CIDR range can be marked trusted
   from the dashboard. Traffic *initiated by* a trusted host is tagged
   `trusted` and skips every detector, so a vulnerability scanner or admin
   box doesn't generate constant false alerts.
7. **Live dashboard** — a Flask app runs detection in a background thread
   and serves a JSON API (`/api/flows`, `/api/stats`, `/api/trend`,
   `/api/top`, `/api/whitelist`, `/api/settings`) that a single-page
   dashboard polls every 1.5s.
8. **Alerting** — whenever a flow is flagged `ALERT`, `PORT SCAN`, or
   `SYN FLOOD`, a native desktop notification fires (via `plyer`), and — if
   configured — an email alert is sent (via `smtplib`). Both are
   rate-limited per source IP so a single attack doesn't spam dozens of
   notifications.
9. **Reporting** — the dashboard's Export buttons generate a PDF (via
   `reportlab`) or CSV snapshot of everything detected so far.

## Project structure

```
network-anomaly-autoencoder/
├── flow_features.py       # packet capture -> flow -> feature vector
├── autoencoder_np.py      # pure NumPy autoencoder (forward/backward/Adam)
├── train.py                # trains the autoencoder on benign-only pcap
├── live_detect.py          # CLI: hybrid detection (autoencoder + port-scan rule)
├── detectors.py             # SYN flood detector (rule-based, target-vs-actor logic)
├── whitelist.py              # trusted IP / CIDR persistence + lookup
├── dashboard.py                # Flask backend for the live web dashboard
├── alerts.py                    # desktop (plyer) + email (smtplib) alerting, rate-limited
├── reports.py                     # PDF (reportlab) / CSV report generation
├── settings_store.py                # local JSON persistence for email settings
├── templates/
│   └── dashboard.html                # dashboard frontend (Chart.js, modals, polls the API)
├── requirements.txt
└── .gitignore
```


## Install

```bash
pip install -r requirements.txt
```
(`scapy`, `numpy`, `flask`, `plyer`, `reportlab` — no PyTorch/CUDA needed,
so this is a light, fast install with no GPU dependency.)

Live capture requires root / `CAP_NET_RAW`.

## 1. Capture benign training traffic

```bash
sudo python3 -c "from scapy.all import sniff, wrpcap; \
pkts = sniff(iface='eth0', timeout=300); wrpcap('benign_traffic.pcap', pkts)"
```

Let this run for a few minutes during normal, everyday usage. No attack
traffic in this file — the autoencoder needs to learn what "normal" looks
like.

## 2. Train the autoencoder

```bash
python3 train.py --pcap benign_traffic.pcap --out model.npz
```

Extracts flow features, trains for 150 epochs, and picks an alert
threshold from the 99th percentile of validation reconstruction error
(`--threshold-pct` to adjust).

## 3. Generate test attack traffic

Only scan/flood hosts you own or are explicitly authorized to test.
Scanning `127.0.0.1` needs to be captured on the **`lo`** interface, not
your main network interface.

```bash
sudo python3 -c "from scapy.all import sniff, wrpcap; \
pkts = sniff(iface='lo', timeout=60); wrpcap('attack_test.pcap', pkts)"
# in a second terminal, within that 60s window:
nmap -sS 127.0.0.1
nmap -sV 127.0.0.1
```

## 4. Score the test traffic (CLI)

```bash
python3 live_detect.py --model model.npz --pcap attack_test.pcap
```

Each flow prints as `normal`, `ALERT` (autoencoder anomaly), or
`PORT SCAN` (fan-out rule triggered), with the reconstruction error and
fan-out count shown. (SYN flood detection lives in `dashboard.py` — the
CLI tool is autoencoder + port-scan only.)

## 5. Run the live dashboard

```bash
# demo mode - replay a captured pcap
python3 dashboard.py --model model.npz --pcap attack_test.pcap

# live mode - real traffic (needs root)
sudo python3 dashboard.py --model model.npz --iface eth0 --flow-timeout 3
```

Then open `http://127.0.0.1:5000` in a browser. The dashboard shows:

- A live scrolling flow feed, recent-alerts panel, and verdict breakdown
  chart (Normal / Alert / Port Scan / SYN Flood / Trusted).
- An **Alerts Over Time** line chart — the last 5 minutes in 10-second
  buckets, one line per detection type.
- **Top Attackers** (ranked by flagged flows, with a one-click *trust*
  button) and **Top Talkers** (ranked by bytes transferred).
- A **🛡 Trusted IPs** panel to add/remove trusted hosts or CIDR ranges.
- An **⚙ Email Alerts** panel to configure SMTP host/port/credentials and a
  recipient address without touching the CLI. Settings persist locally in
  `email_settings.json` (gitignored — credentials never get committed).
- **⬇ CSV** / **⬇ PDF** buttons to download a report of everything seen in
  the current session.

Desktop notifications fire automatically for any flagged verdict (no
configuration needed); email alerts additionally fire once configured in
the settings panel. Both are rate-limited per source IP.

## Demo commands (safe, localhost only)

```bash
# port scan
nmap -sS 127.0.0.1

# SYN flood - 100 SYNs at your own SSH port
sudo python3 -c "from scapy.all import IP, TCP, send; \
[send(IP(dst='127.0.0.1')/TCP(sport=40000+i, dport=22, flags='S'), verbose=0) for i in range(100)]"
```

## Notes / limitations

- **Threshold tuning is a real trade-off**: too sensitive and normal
  bursty traffic (large downloads, many browser tabs) gets flagged; too
  loose and slow/low-rate scans get missed. `--alert-multiplier`,
  `--scan-port-threshold`, `--flood-window`, and `--flood-threshold` let
  you tune this without retraining.
- **Port scan vs. SYN flood**: distinguished by *what's being counted* —
  distinct target ports from one actor (scan) vs. repeated half-open hits
  on one target port (flood). Both can technically fire in the same
  attack window; SYN FLOOD takes priority in that case.
- **Trust is directional**: only traffic *initiated by* a trusted IP is
  skipped, so a trusted admin box scanning a server is ignored, but an
  attacker targeting that same trusted box is not automatically ignored.
- **Retraining over time**: what counts as "normal" traffic drifts as
  usage patterns change, so the model should be retrained periodically
  rather than treated as permanent.
- **Flow-level, not payload-level**: detection works on flow statistics
  (sizes, timing, flags), not packet contents, so it won't catch attacks
  invisible at that level (e.g. an exploit sent over an otherwise
  normal-looking connection).
- **Email credentials**: stored only in a local, gitignored JSON file —
  never in code or pushed to GitHub. Gmail requires an App Password (not
  your account password) with 2-Step Verification enabled.
- No formal precision/recall evaluation has been done — detection has been
  validated against controlled `nmap` and `scapy` traffic on a single
  machine, not benchmarked on a labeled dataset.
- This is an educational, defensive-security project — not a production
  IDS. It's meant to demonstrate how anomaly-based network detection
  systems work internally, end to end.