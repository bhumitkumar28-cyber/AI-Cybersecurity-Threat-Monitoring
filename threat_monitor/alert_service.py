from django.core.mail import send_mail
from .models import AlertRule

SEVERITY_RANK = {
    'LOW': 1,
    'MEDIUM': 2,
    'HIGH': 3,
    'CRITICAL': 4,
}


def threat_matches_rule(threat, rule):
    if not rule.enabled:
        return False

    threat_severity = SEVERITY_RANK.get(threat.severity, 0)
    required_severity = SEVERITY_RANK.get(rule.minimum_severity, 0)

    if threat_severity < required_severity:
        return False

    if threat.log.threat_score < rule.minimum_score:
        return False

    keywords = [
        keyword.strip().lower()
        for keyword in rule.custom_keywords.split(',')
        if keyword.strip()
    ]

    if keywords:
        searchable_text = (
            f"{threat.threat_type} "
            f"{threat.description} "
            f"{threat.log.raw_data}"
        ).lower()

        if not any(keyword in searchable_text for keyword in keywords):
            return False

    return True


def send_threat_alert(threat):
    rules = AlertRule.objects.filter(
        user=threat.log.user,
        enabled=True,
        email_enabled=True
    )

    for rule in rules:
        if not threat_matches_rule(threat, rule):
            continue

        subject = (
            f"[{threat.severity}] Security Alert: "
            f"{threat.threat_type}"
        )

        message = f"""
A security threat was detected.

Threat Type: {threat.threat_type}
Severity: {threat.severity}
Threat Score: {threat.log.threat_score}/100
Timestamp: {threat.log.timestamp}

Description:
{threat.description}

Recommended Action:
{threat.recommended_action}

AI Explanation:
{threat.ai_explanation}
"""

        send_mail(
            subject=subject,
            message=message,
            from_email=None,
            recipient_list=[rule.notification_email],
            fail_silently=False,
        )