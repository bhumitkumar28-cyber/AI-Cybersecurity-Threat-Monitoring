
from .behavior_analyzer import BehaviorAnalyzer


class DynamicRiskEngine:
    def __init__(self):
        self.weights = {
            "failed_logins": 20,
            "anomaly_score": 30,
            "ip_risk": 15,
            "unusual_time": 10,
            "unusual_location": 10,
            "event_severity": 15,
        }

        self.behavior_analyzer = BehaviorAnalyzer()

    @staticmethod
    def _clamp(value):
        return max(0.0, min(100.0, float(value)))

    def calculate_risk(
        self,
        failed_logins=0,
        anomaly_score=0,
        ip_risk=0,
        unusual_time=False,
        unusual_location=False,
        event_severity="LOW",
        log=None,
    ):
        # Failed Login Risk
        if failed_logins >= 10:
            failed_score = 100
        elif failed_logins >= 5:
            failed_score = 75
        elif failed_logins >= 3:
            failed_score = 50
        elif failed_logins >= 1:
            failed_score = 25
        else:
            failed_score = 0

        score = (
            failed_score * self.weights["failed_logins"] / 100
        )

        # ML Anomaly Risk
        anomaly_score = self._clamp(anomaly_score)
        score += (
            anomaly_score * self.weights["anomaly_score"] / 100
        )

        # IP Reputation Risk
        ip_risk = self._clamp(ip_risk)
        score += ip_risk * self.weights["ip_risk"] / 100

        # Contextual Risk
        if unusual_time:
            score += self.weights["unusual_time"]

        if unusual_location:
            score += self.weights["unusual_location"]

        # Event Severity
        severity_scores = {
            "LOW": 10,
            "MEDIUM": 40,
            "HIGH": 70,
            "CRITICAL": 100,
        }

        severity_value = severity_scores.get(
            str(event_severity).upper(), 10
        )

        score += (
            severity_value * self.weights["event_severity"] / 100
        )

        # User Behavior Analytics
        behavior_score = 0.0
        behavior_evidence = []

        if log is not None:
            behavior_score, behavior_evidence = (
                self.behavior_analyzer.analyze(log)
            )

            behavior_score = self._clamp(behavior_score)

            # Reserve 10% of the final score for behavior risk.
            # Scale existing components to make room for UBA.
            score = score * 0.90 + behavior_score * 0.10

        # Final Risk Score
        score = round(max(0.0, min(100.0, score)), 2)

        # Risk Classification
        if score >= 80:
            risk_level = "CRITICAL"
        elif score >= 60:
            risk_level = "HIGH"
        elif score >= 30:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        return {
            "risk_score": score,
            "risk_level": risk_level,
            "behavior_score": round(behavior_score, 2),
            "behavior_evidence": behavior_evidence,
        }
