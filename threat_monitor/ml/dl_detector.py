from pathlib import Path

import torch

from .autoencoder import SecurityAutoencoder


MODEL_PATH = Path(__file__).resolve().parent / "autoencoder_model.pth"


class DeepLearningDetector:
    def __init__(self):
        if not MODEL_PATH.exists():
            raise FileNotFoundError(
                f"Trained model not found: {MODEL_PATH}"
            )

        torch.set_num_threads(1)

        # Load the saved model only once.
        checkpoint = torch.load(
            MODEL_PATH,
            map_location="cpu",
            weights_only=True,
        )

        self.features = checkpoint["features"]
        self.mean = torch.tensor(
            checkpoint["mean"], dtype=torch.float32
        )
        self.scale = torch.tensor(
            checkpoint["scale"], dtype=torch.float32
        )
        self.threshold = float(checkpoint["threshold"])

        self.model = SecurityAutoencoder(
            input_size=len(self.features)
        )
        self.model.load_state_dict(checkpoint["state_dict"])
        self.model.eval()

    def predict(self, log_data):
        values = []

        for feature in self.features:
            value = log_data.get(feature, 0)

            try:
                value = float(value)
            except (TypeError, ValueError):
                value = 0.0

            if not torch.isfinite(torch.tensor(value)):
                value = 0.0

            values.append(value)

        sample = torch.tensor(values, dtype=torch.float32)

        normalized = (sample - self.mean) / self.scale
        normalized = torch.nan_to_num(normalized)

        with torch.no_grad():
            reconstructed = self.model(normalized.unsqueeze(0))
            error = torch.mean(
                (reconstructed - normalized.unsqueeze(0)) ** 2
            ).item()

        return {
            "anomaly_score": round(error, 6),
            "threshold": round(self.threshold, 6),
            "is_anomaly": error > self.threshold,
        }