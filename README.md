# NetGuard AI — Real-Time Network Anomaly Detection

A hybrid network intrusion detection system that combines an **unsupervised
autoencoder** (for catching unknown/zero-day behavior anomalies) with a
**rule-based port-scan detector** (for catching classic scanning activity),
served through a live web dashboard.

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
   unremarkable). A second, independent layer tracks how many *distinct
   destination ports* a single source IP touches within a sliding time
   window; crossing a threshold flags a classic port-scan fan-out pattern
   regardless of what the autoencoder says. This hybrid ML + rule-based
   design mirrors how real IDS/EDR products layer multiple detection
   techniques.
5. **Live dashboard** — a Flask app runs detection in a background thread
   and serves a small JSON API (`/api/flows`, `/api/stats`) that a
   single-page dashboard polls every 1.5s to show live flows, alert counts,
   and a verdict breakdown chart.

## Project structure


## Install

```bash
pip install -r requirements.txt
```
(Just `scapy`, `numpy`, and `flask` — no PyTorch/CUDA needed, so this is a
light, fast install with no GPU dependency.)

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

## 3. Generate test attack traffic with nmap

Only scan hosts/networks you own or are explicitly authorized to test.
Note: scanning `127.0.0.1` needs to be captured on the **`lo`** interface,
not your main network interface.

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
fan-out count shown.

## 5. Run the live dashboard

```bash
# demo mode - replay a captured pcap
python3 dashboard.py --model model.npz --pcap attack_test.pcap

# live mode - real traffic (needs root)
sudo python3 dashboard.py --model model.npz --iface eth0
```

Then open `http://127.0.0.1:5000` in a browser. The dashboard shows a live
scrolling flow feed, a recent-alerts panel, and a verdict breakdown chart,
all updating every 1.5 seconds.

## Notes / limitations

- **Threshold tuning is a real trade-off**: too sensitive and normal
  bursty traffic (large downloads, many browser tabs) gets flagged; too
  loose and slow/low-rate scans get missed. `--alert-multiplier` on
  `live_detect.py`/`dashboard.py` and `--scan-port-threshold` let you tune
  this without retraining.
- **Retraining over time**: what counts as "normal" traffic drifts as
  usage patterns change, so the model should be retrained periodically
  rather than treated as permanent.
- **Flow-level, not payload-level**: detection works on flow statistics
  (sizes, timing, flags), not packet contents, so it won't catch attacks
  that are invisible at that level (e.g. an exploit sent over an
  otherwise normal-looking connection). It complements, rather than
  replaces, payload-inspection tools.
- This is an educational, defensive-security project — not a production
  IDS. It's meant to demonstrate how anomaly-based network detection
  systems work internally, end to end.