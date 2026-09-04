"""
autoencoder.py

Simple feedforward autoencoder for flow-level anomaly detection.
Install with: pip install torch
"""

import torch
import torch.nn as nn


class FlowAutoencoder(nn.Module):
    def __init__(self, input_dim, bottleneck=8):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 20),
            nn.ReLU(),
            nn.Linear(20, 14),
            nn.ReLU(),
            nn.Linear(14, bottleneck),
            nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(bottleneck, 14),
            nn.ReLU(),
            nn.Linear(14, 20),
            nn.ReLU(),
            nn.Linear(20, input_dim),
        )

    def forward(self, x):
        z = self.encoder(x)
        return self.decoder(z)


def reconstruction_error(model, x):
    """Per-sample mean squared reconstruction error. x: (N, D) tensor."""
    with torch.no_grad():
        recon = model(x)
        err = ((recon - x) ** 2).mean(dim=1)
    return err
