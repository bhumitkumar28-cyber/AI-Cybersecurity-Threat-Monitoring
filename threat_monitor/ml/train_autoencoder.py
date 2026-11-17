
from pathlib import Path

import pandas as pd
import torch
from torch import nn
from torch.utils.data import DataLoader, TensorDataset

from autoencoder import SecurityAutoencoder


ROOT = Path(__file__).resolve().parents[3]
DATA_PATH = ROOT / "sample_data" / "threat_training_data.csv"
MODEL_PATH = Path(__file__).resolve().parent / "autoencoder_model.pth"

FEATURES = [
    "failed_logins",
    "login_attempts",
    "unique_ips",
    "request_count",
    "anomaly_score",
    "port_activity",
]

torch.manual_seed(42)
torch.set_num_threads(1)


def main():
    if not DATA_PATH.exists():
        raise FileNotFoundError(f"Dataset not found: {DATA_PATH}")

    df = pd.read_csv(DATA_PATH)

    required = FEATURES + ["threat_type"]
    missing = [column for column in required if column not in df.columns]

    if missing:
        raise ValueError(f"Missing columns: {missing}")

    # Train the autoencoder on NORMAL examples only.
    normal = df[
        df["threat_type"].astype(str).str.upper() == "NORMAL"
    ].copy()

    if len(normal) < 3:
        raise ValueError(
            f"Only {len(normal)} NORMAL rows found. "
            "Add more representative normal examples before training."
        )

    values = normal[FEATURES].apply(
        pd.to_numeric, errors="coerce"
    )

    values = values.replace([float("inf"), float("-inf")], float("nan"))
    values = values.fillna(values.median()).fillna(0.0)

    mean = values.mean().to_numpy(dtype="float32")
    scale = values.std(ddof=0).to_numpy(dtype="float32")
    scale[scale < 1e-8] = 1.0

    normalized = (values.to_numpy(dtype="float32") - mean) / scale
    training_data = torch.tensor(normalized, dtype=torch.float32)

    model = SecurityAutoencoder(input_size=len(FEATURES))
    loader = DataLoader(
        TensorDataset(training_data),
        batch_size=min(8, len(training_data)),
        shuffle=True,
    )

    optimizer = torch.optim.Adam(model.parameters(), lr=0.005)
    loss_function = nn.MSELoss()

    model.train()

    for epoch in range(200):
        total_loss = 0.0

        for (batch,) in loader:
            optimizer.zero_grad()
            reconstructed = model(batch)
            loss = loss_function(reconstructed, batch)
            loss.backward()
            optimizer.step()
            total_loss += loss.item() * len(batch)

        if (epoch + 1) % 50 == 0:
            print(
                f"Epoch {epoch + 1}/200 | "
                f"Loss: {total_loss / len(training_data):.6f}"
            )

    model.eval()

    with torch.no_grad():
        reconstructed = model(training_data)
        errors = torch.mean(
            (reconstructed - training_data) ** 2, dim=1
        )

    # Initial demo threshold; validate it with more data later.
    threshold = torch.quantile(errors, 0.95).item()

    torch.save(
        {
            "state_dict": model.state_dict(),
            "features": FEATURES,
            "mean": mean.tolist(),
            "scale": scale.tolist(),
            "threshold": threshold,
        },
        MODEL_PATH,
    )

    print("\nTraining complete.")
    print("NORMAL training rows:", len(normal))
    print("Threshold:", round(threshold, 6))
    print("Saved model:", MODEL_PATH)


if __name__ == "__main__":
    main()
