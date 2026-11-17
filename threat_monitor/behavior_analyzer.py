
from datetime import timedelta

from .models import SecurityLog


class BehaviorAnalyzer:
    """
    Rule-based User Behavior Analytics (UBA).
    Returns a risk score and evidence for review.
    """

    def analyze(self, log: SecurityLog):
        score = 0
        evidence = []
        raw = log.raw_data if isinstance(log.raw_data, dict) else {}

        # 1. Unusual activity time
        hour = log.timestamp.hour

        if hour >= 22 or hour < 6:
            score += 20
            evidence.append(
                f"Activity outside the configured usual hours: {hour}:00"
            )

        # 2. Repeated failed authentication events
        if log.log_type == "AUTH":
            status = str(raw.get("status", "")).strip().lower()

            failed_statuses = {
                "fail", "failed", "failure",
                "denied", "invalid", "unsuccessful",
            }

            if status in failed_statuses:
                window_start = log.timestamp - timedelta(minutes=15)

                query = SecurityLog.objects.filter(
                    log_type="AUTH",
                    timestamp__gte=window_start,
                    timestamp__lte=log.timestamp,
                )

                if log.user_id is not None:
                    query = query.filter(user_id=log.user_id)

                # Count failures only, not all authentication events.
                failures = 0

                for event in query.only("raw_data").iterator():
                    event_data = (
                        event.raw_data
                        if isinstance(event.raw_data, dict)
                        else {}
                    )
                    event_status = str(
                        event_data.get("status", "")
                    ).strip().lower()

                    if event_status in failed_statuses:
                        failures += 1

                if failures >= 3:
                    score += min(40, failures * 8)
                    evidence.append(
                        f"{failures} failed authentication events "
                        "within 15 minutes"
                    )

        # 3. IP context
        # A public IP alone is not evidence of an attack.
        ip = str(
            raw.get("ip_address")
            or raw.get("source_ip")
            or ""
        ).strip()

        if ip:
            evidence.append(
                f"Observed source IP: {ip}; investigate its context "
                "before assigning malicious intent"
            )

        return min(score, 100), evidence
