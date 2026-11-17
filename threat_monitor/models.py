
from django.db import models
from django.contrib.auth.models import User
from django.conf import settings


class SecurityLog(models.Model):
    LOG_TYPE_CHOICES = [
        ("AUTH", "Authentication"),
        ("FIREWALL", "Firewall"),
        ("NETWORK", "Network"),
    ]

    log_type = models.CharField(max_length=20, choices=LOG_TYPE_CHOICES)
    timestamp = models.DateTimeField()
    raw_data = models.JSONField()
    processed = models.BooleanField(default=False)
    threat_score = models.FloatField(default=0.0)
    threat_level = models.CharField(max_length=20, blank=True)
    anomaly_detected = models.BooleanField(default=False)
    ai_analysis = models.JSONField(blank=True, null=True)
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.get_log_type_display()} Log at {self.timestamp}"


class DetectedThreat(models.Model):
    THREAT_LEVEL_CHOICES = [
        ("LOW", "Low"),
        ("MEDIUM", "Medium"),
        ("HIGH", "High"),
        ("CRITICAL", "Critical"),
    ]

    log = models.ForeignKey(
        SecurityLog,
        on_delete=models.CASCADE,
        related_name="detected_threats",
    )
    threat_type = models.CharField(max_length=100)
    severity = models.CharField(max_length=20, choices=THREAT_LEVEL_CHOICES)
    description = models.TextField()
    recommended_action = models.TextField()
    ai_explanation = models.TextField(blank=True)
    detected_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.severity} Threat: {self.threat_type}"


class AlertRule(models.Model):
    SEVERITY_CHOICES = [
        ("LOW", "Low"),
        ("MEDIUM", "Medium"),
        ("HIGH", "High"),
        ("CRITICAL", "Critical"),
    ]

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="alert_rules",
    )
    name = models.CharField(max_length=100)
    enabled = models.BooleanField(default=True)
    minimum_severity = models.CharField(
        max_length=20,
        choices=SEVERITY_CHOICES,
        default="CRITICAL",
    )
    minimum_score = models.PositiveIntegerField(default=80)
    email_enabled = models.BooleanField(default=True)
    notification_email = models.EmailField()
    custom_keywords = models.TextField(
        blank=True,
        help_text="Comma-separated keywords, e.g. ransomware, malware, SQL injection",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.name} - {self.user.username}"


class ThreatIntelligence(models.Model):
    INDICATOR_TYPE_CHOICES = [
        ("IP", "IP Address"),
        ("DOMAIN", "Domain"),
        ("HASH", "File Hash"),
    ]

    THREAT_LEVEL_CHOICES = [
        ("LOW", "Low"),
        ("MEDIUM", "Medium"),
        ("HIGH", "High"),
        ("CRITICAL", "Critical"),
    ]

    indicator = models.CharField(max_length=255, db_index=True)
    indicator_type = models.CharField(
        max_length=20,
        choices=INDICATOR_TYPE_CHOICES,
    )
    threat_type = models.CharField(max_length=100, blank=True)
    severity = models.CharField(
        max_length=20,
        choices=THREAT_LEVEL_CHOICES,
        default="LOW",
    )
    confidence = models.PositiveIntegerField(default=0)
    source = models.CharField(
        max_length=100,
        default="Local Intelligence Feed",
    )
    description = models.TextField(blank=True)
    recommended_action = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

  
    class Meta:
        constraints = [
            models.CheckConstraint(
                check=models.Q(
                    confidence__gte=0,
                    confidence__lte=100,
                ),
                name="threat_intel_confidence_0_100",
            ),
        ]


    def __str__(self):
        return f"{self.indicator_type}: {self.indicator} - {self.severity}"


class SecurityIncident(models.Model):
    STATUS = [
        ("OPEN", "Open"),
        ("INVESTIGATING", "Investigating"),
        ("CONTAINED", "Contained"),
        ("RESOLVED", "Resolved"),
        ("FALSE_POSITIVE", "False Positive"),
    ]

    incident_id = models.CharField(
        max_length=20,
        unique=True,
        blank=True,
    )
    threat = models.ForeignKey(
        DetectedThreat,
        on_delete=models.CASCADE,
        related_name="incidents",
    )
    title = models.CharField(max_length=255)
    status = models.CharField(
        max_length=20,
        choices=STATUS,
        default="OPEN",
    )
    assignee = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="assigned_incidents",
    )
    notes = models.TextField(blank=True)
    resolution_history = models.JSONField(default=list)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def save(self, *args, **kwargs):
        if not self.incident_id:
            last = SecurityIncident.objects.order_by("-id").first()
            next_id = (last.id + 1) if last else 1
            self.incident_id = f"INC-{next_id:04d}"

        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.incident_id} - {self.title} ({self.status})"
