import os

import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier


class ThreatPredictor:

    def __init__(self):

        self.model = RandomForestClassifier(
            n_estimators=100,
            random_state=42
        )

        self.trained = False

        self.feature_columns = [
            "failed_logins",
            "login_attempts",
            "unique_ips",
            "request_count",
            "anomaly_score",
            "port_activity"
        ]

    def train_from_csv(self, csv_path):

        if not os.path.exists(csv_path):
            raise FileNotFoundError(
                f"Training dataset not found: {csv_path}"
            )

        data = pd.read_csv(csv_path)

        X = data[self.feature_columns]
        y = data["threat_type"]

        self.model.fit(X, y)

        self.trained = True

        return {
            "status": "success",
            "samples": len(data),
            "threat_types": sorted(y.unique().tolist())
        }

    def train(self, X, y):

        X = np.asarray(X)
        y = np.asarray(y)

        self.model.fit(X, y)

        self.trained = True

    def predict(self, features):

        if not self.trained:
            return {
                "threat": "UNKNOWN",
                "probability": 0,
                "risk": "LOW"
            }

        # Convert input into DataFrame
        # so feature names match the training data
        features_df = pd.DataFrame(
            [features],
            columns=self.feature_columns
        )

        prediction = self.model.predict(features_df)[0]

        probabilities = self.model.predict_proba(features_df)[0]

        probability = float(max(probabilities)) * 100

        # NORMAL activity is not a security threat
        if prediction == "NORMAL":
            risk = "LOW"

        elif probability >= 80:
            risk = "CRITICAL"

        elif probability >= 60:
            risk = "HIGH"

        elif probability >= 40:
            risk = "MEDIUM"

        else:
            risk = "LOW"

        return {
            "threat": str(prediction),
            "probability": round(probability, 2),
            "risk": risk
        }

    def predict_from_values(
        self,
        failed_logins,
        login_attempts,
        unique_ips,
        request_count,
        anomaly_score,
        port_activity
    ):

        features = [
            failed_logins,
            login_attempts,
            unique_ips,
            request_count,
            anomaly_score,
            port_activity
        ]

        return self.predict(features)