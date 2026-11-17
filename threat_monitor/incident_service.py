
from .models import SecurityIncident


class IncidentService:

    @staticmethod
    def create_from_threat(threat):
        if threat.severity not in ("HIGH", "CRITICAL"):
            return None

        incident, created = SecurityIncident.objects.get_or_create(
            threat=threat,
            defaults={
                "title": f"{threat.threat_type} investigation",
            },
        )

        return incident

    @staticmethod
    def update_status(incident, user, status, note=""):
        valid_statuses = {
            choice[0]
            for choice in SecurityIncident.STATUS
        }

        if status not in valid_statuses:
            raise ValueError("Invalid incident status.")

        history = list(incident.resolution_history or [])
        history.append({
            "user": user.username,
            "status": status,
            "note": note,
        })

        incident.resolution_history = history
        incident.status = status
        incident.save(
            update_fields=[
                "resolution_history",
                "status",
                "updated_at",
            ]
        )

        return incident
