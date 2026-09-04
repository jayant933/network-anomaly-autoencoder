"""
autoencoder_np.py

Pure NumPy autoencoder (no PyTorch needed) - light on disk/download size.
Manual forward pass, backprop, and Adam optimizer for a small
feedforward bottleneck network: input -> 20 -> 14 -> 8 -> 14 -> 20 -> input

Install with: pip install numpy   (that's it, no torch/CUDA needed)
"""

import numpy as np


class FlowAutoencoderNP:
    def __init__(self, input_dim, seed=42):
        rng = np.random.RandomState(seed)
        self.sizes = [input_dim, 20, 14, 8, 14, 20, input_dim]
        # He initialization, good for ReLU nets
        self.W = [rng.randn(self.sizes[i], self.sizes[i + 1]) * np.sqrt(2.0 / self.sizes[i])
                  for i in range(len(self.sizes) - 1)]
        self.b = [np.zeros(self.sizes[i + 1]) for i in range(len(self.sizes) - 1)]

        # Adam optimizer state
        self.mW = [np.zeros_like(w) for w in self.W]
        self.vW = [np.zeros_like(w) for w in self.W]
        self.mb = [np.zeros_like(bb) for bb in self.b]
        self.vb = [np.zeros_like(bb) for bb in self.b]
        self.t = 0

    def forward(self, X):
        """X: (N, D). Returns list of activations and pre-activations (zs)."""
        a = X
        acts = [a]
        zs = []
        n_layers = len(self.W)
        for i in range(n_layers):
            z = a @ self.W[i] + self.b[i]
            zs.append(z)
            if i < n_layers - 1:
                a = np.maximum(0, z)  # ReLU on hidden layers
            else:
                a = z  # linear output layer
            acts.append(a)
        return acts, zs

    def backward(self, X, acts, zs):
        """Backprop for MSE loss = mean((output - X)^2). Returns grads for W, b."""
        N = X.shape[0]
        n_layers = len(self.W)
        output = acts[-1]

        dA = 2.0 * (output - X) / N  # dL/d(output)
        gradsW = [None] * n_layers
        gradsb = [None] * n_layers

        for i in reversed(range(n_layers)):
            if i < n_layers - 1:
                dZ = dA * (zs[i] > 0)  # ReLU derivative
            else:
                dZ = dA  # linear layer, no activation derivative
            gradsW[i] = acts[i].T @ dZ
            gradsb[i] = dZ.sum(axis=0)
            dA = dZ @ self.W[i].T

        return gradsW, gradsb

    def adam_step(self, gradsW, gradsb, lr=1e-3, beta1=0.9, beta2=0.999, eps=1e-8):
        self.t += 1
        for i in range(len(self.W)):
            self.mW[i] = beta1 * self.mW[i] + (1 - beta1) * gradsW[i]
            self.vW[i] = beta2 * self.vW[i] + (1 - beta2) * (gradsW[i] ** 2)
            mW_hat = self.mW[i] / (1 - beta1 ** self.t)
            vW_hat = self.vW[i] / (1 - beta2 ** self.t)
            self.W[i] -= lr * mW_hat / (np.sqrt(vW_hat) + eps)

            self.mb[i] = beta1 * self.mb[i] + (1 - beta1) * gradsb[i]
            self.vb[i] = beta2 * self.vb[i] + (1 - beta2) * (gradsb[i] ** 2)
            mb_hat = self.mb[i] / (1 - beta1 ** self.t)
            vb_hat = self.vb[i] / (1 - beta2 ** self.t)
            self.b[i] -= lr * mb_hat / (np.sqrt(vb_hat) + eps)

    def train_batch(self, X_batch, lr=1e-3):
        acts, zs = self.forward(X_batch)
        loss = np.mean((acts[-1] - X_batch) ** 2)
        gradsW, gradsb = self.backward(X_batch, acts, zs)
        self.adam_step(gradsW, gradsb, lr=lr)
        return loss

    def reconstruction_error(self, X):
        """Per-sample mean squared reconstruction error. X: (N, D)."""
        acts, _ = self.forward(X)
        return ((acts[-1] - X) ** 2).mean(axis=1)

    def save(self, path, mean, std, threshold):
        np.savez(path,
                  **{f"W{i}": w for i, w in enumerate(self.W)},
                  **{f"b{i}": b for i, b in enumerate(self.b)},
                  input_dim=self.sizes[0],
                  mean=mean, std=std, threshold=threshold)

    @classmethod
    def load(cls, path):
        data = np.load(path)
        input_dim = int(data["input_dim"])
        model = cls(input_dim)
        n_layers = len(model.W)
        model.W = [data[f"W{i}"] for i in range(n_layers)]
        model.b = [data[f"b{i}"] for i in range(n_layers)]
        return model, data["mean"], data["std"], float(data["threshold"])
