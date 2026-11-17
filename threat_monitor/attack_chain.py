
from datetime import timedelta

from .models import SecurityLog, DetectedThreat


class AttackChainDetector:
    TEMPLATES = [
        {
            "name": "Recon to Brute Force",
            "sequence": ["scan", "auth_failure", "auth_success"],
            "severity": "HIGH",
        },
        {
            "name": "Credential Stuffing",
            "sequence": [
                "auth_failure",
                "auth_failure",
                "auth_success",
            ],
            "severity": "CRITICAL",
        },
    ]

    def detect(self, log: SecurityLog):
        window_start = log.timestamp - timedelta(minutes=5)

        query = SecurityLog.objects.filter(
            timestamp__gte=window_start,
            timestamp__lte=log.timestamp,
        )

        # Prefer the same user; for anonymous events, correlate
        # by source IP to avoid mixing unrelated activity.
        raw = log.raw_data if isinstance(log.raw_data, dict) else {}
        source_ip = (
            raw.get("ip_address") or raw.get("source_ip")
        )

        if log.user_id is not None:
            query = query.filter(user_id=log.user_id)
        elif source_ip:
            query = query.filter(user__isnull=True)

        events = list(query.order_by("timestamp", "id"))

        if log.user_id is None and source_ip:
            events = [
                event for event in events
                if self.get_ip(event) == source_ip
            ]

        actions = [self.normalize(event) for event in events]

        for template in self.TEMPLATES:
            if not self.contains(actions, template["sequence"]):
                continue

            threat_type = (
                f"Multi-Stage Attack: {template['name']}"
            )

            # Avoid creating the same threat repeatedly for one log.
            existing = DetectedThreat.objects.filter(
                log=log,
                threat_type=threat_type,
            ).first()

            if existing:
                return existing

            return DetectedThreat.objects.create(
                log=log,
                threat_type=threat_type,
                severity=template["severity"],
                description=(
                    "A suspicious sequence of correlated events "
                    "was observed within five minutes. "
                    "Analyst verification is required."
                ),
                recommended_action=(
                    "Review the source IP, authentication history, "
                    "affected account, and subsequent activity."
                ),
                ai_explanation=(
                    "Matched event sequence: "
                    + " -> ".join(template["sequence"])
                ),
            )

        return None

    @staticmethod
    def get_ip(log):
        raw = log.raw_data if isinstance(log.raw_data, dict) else {}
        return raw.get("ip_address") or raw.get("source_ip")

    @staticmethod
    def normalize(log):
        raw = log.raw_data if isinstance(log.raw_data, dict) else {}

        text = " ".join(
            str(value) for value in raw.values()
        ).lower()

        if log.log_type == "AUTH":
            status = str(raw.get("status", "")).strip().lower()

            failures = {
                "fail", "failed", "failure",
                "denied", "invalid", "unsuccessful",
            }
            successes = {
                "success", "successful", "succeeded",
                "authenticated", "login_success",
            }

            if status in failures:
                return "auth_failure"

            if status in successes:
                return "auth_success"

            return "other"

        if any(word in text for word in (
            "port scan", "port_scan", "scan detected",
            "reconnaissance",
        )):
            return "scan"

        return "other"

    @staticmethod
    def contains(actions, expected):
        n = len(expected)

        return any(
            actions[i:i + n] == expected
            for i in range(len(actions) - n + 1)
        )
