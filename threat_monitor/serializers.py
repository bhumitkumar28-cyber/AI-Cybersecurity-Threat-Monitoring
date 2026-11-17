from rest_framework import serializers
from .models import SecurityLog, DetectedThreat, AlertRule


class SecurityLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = SecurityLog
        fields = '__all__'
        read_only_fields = [
            'user',
            'processed',
            'threat_score',
            'threat_level',
            'anomaly_detected',
            'created_at',
        ]


class DetectedThreatSerializer(serializers.ModelSerializer):
    threat_score = serializers.FloatField(
        source='log.threat_score',
        read_only=True
    )

    class Meta:
        model = DetectedThreat
        fields = [
            'id',
            'log',
            'threat_type',
            'severity',
            'description',
            'recommended_action',
            'ai_explanation',
            'detected_at',
            'threat_score',
        ]


class AlertRuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = AlertRule
        fields = '__all__'
        read_only_fields = ['user', 'created_at', 'updated_at']