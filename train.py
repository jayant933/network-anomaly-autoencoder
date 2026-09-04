"""
train.py

Train the flow autoencoder on BENIGN traffic only.
Uses pure NumPy (no torch/CUDA needed - light on disk and download size).

Usage:
    python train.py --pcap benign_traffic.pcap --out model.npz
"""

import argparse
import numpy as np

from flow_features import extract_flows_from_pcap
from autoencoder_np import FlowAutoencoderNP


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", required=True, help="pcap file of BENIGN traffic")
    ap.add_argument("--out", default="model.npz")
    ap.add_argument("--epochs", type=int, default=150)
    ap.add_argument("--batch-size", type=int, default=32)
    ap.add_argument("--lr", type=float, default=1e-3)
    ap.add_argument("--val-split", type=float, default=0.2)
    ap.add_argument("--threshold-pct", type=float, default=99.0,
                     help="percentile of val reconstruction error used as alert threshold")
    args = ap.parse_args()

    print(f"Extracting flows from {args.pcap} ...")
    feats, keys = extract_flows_from_pcap(args.pcap)
    if len(feats) < 20:
        raise SystemExit(f"Only {len(feats)} flows extracted — need more benign traffic to train on.")
    X = np.array(feats, dtype=np.float64)
    print(f"Extracted {X.shape[0]} flows, {X.shape[1]} features each.")

    mean = X.mean(axis=0)
    std = X.std(axis=0)
    std[std == 0] = 1.0
    Xn = (X - mean) / std

    n_val = max(1, int(len(Xn) * args.val_split))
    idx = np.random.permutation(len(Xn))
    val_idx, train_idx = idx[:n_val], idx[n_val:]
    X_train = Xn[train_idx]
    X_val = Xn[val_idx]

    model = FlowAutoencoderNP(input_dim=X.shape[1])

    print("Training...")
    for epoch in range(args.epochs):
        perm = np.random.permutation(len(X_train))
        total_loss = 0.0
        for i in range(0, len(X_train), args.batch_size):
            batch = X_train[perm[i:i + args.batch_size]]
            loss = model.train_batch(batch, lr=args.lr)
            total_loss += loss * len(batch)
        if (epoch + 1) % 20 == 0 or epoch == 0:
            print(f"  epoch {epoch+1}/{args.epochs}  train_loss={total_loss/len(X_train):.5f}")

    val_errs = model.reconstruction_error(X_val)
    threshold = float(np.percentile(val_errs, args.threshold_pct))
    print(f"Validation reconstruction error: mean={val_errs.mean():.5f} "
          f"p{args.threshold_pct}={threshold:.5f}")

    model.save(args.out, mean, std, threshold)
    print(f"Saved model + normalization + threshold to {args.out}")


if __name__ == "__main__":
    main()
