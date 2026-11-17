
import torch
from torch import nn


class SecurityAutoencoder(nn.Module):
    def __init__(self, input_size=6):
        super().__init__()

        self.encoder = nn.Sequential(
            nn.Linear(input_size, 4),
            nn.ReLU(),
            nn.Linear(4, 2),
        )

        self.decoder = nn.Sequential(
            nn.Linear(2, 4),
            nn.ReLU(),
            nn.Linear(4, input_size),
        )

    def forward(self, x):
        compressed = self.encoder(x)
        reconstructed = self.decoder(compressed)
        return reconstructed
