import os
from rest_framework import viewsets, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from django_filters.rest_framework import DjangoFilterBackend

from .models import SecurityLog, DetectedThreat, AlertRule

from .serializers import (
    SecurityLogSerializer,
    DetectedThreatSerializer,
    AlertRuleSerializer,
)

from .anomaly_detector import AnomalyDetector
from .risk_engine import DynamicRiskEngine
from .threat_predictor import ThreatPredictor
from rest_framework import viewsets, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from .risk_engine import DynamicRiskEngine
from .threat_predictor import ThreatPredictor
from django_filters.rest_framework import DjangoFilterBackend

from .models import SecurityLog, DetectedThreat, AlertRule
from .serializers import (
    SecurityLogSerializer,
    DetectedThreatSerializer,
    AlertRuleSerializer,
)
from rest_framework.decorators import action
from rest_framework.response import Response

from .risk_engine import DynamicRiskEngine

class SecurityLogViewSet(viewsets.ReadOnlyModelViewSet):

    serializer_class = SecurityLogSerializer

    permission_classes = [
        permissions.IsAuthenticated
    ]

    filter_backends = [
        DjangoFilterBackend
    ]

    filterset_fields = [
        'log_type',
        'threat_level',
        'anomaly_detected'
    ]

    def get_queryset(self):

        return SecurityLog.objects.filter(
            user=self.request.user
        ).order_by('-timestamp')

    @action(
        detail=True,
        methods=['post'],
        url_path='calculate-risk'
    )
    def calculate_risk(self, request, pk=None):

        # Get current log
        log = self.get_object()

        # Raw JSON data
        data = log.raw_data or {}

        # -----------------------------------------
        # Create ML detector
        # -----------------------------------------

        detector = AnomalyDetector()

        # -----------------------------------------
        # Get anomaly score
        # -----------------------------------------

        anomaly_score = detector.get_anomaly_score(
            data,
            log.log_type
        )

        # -----------------------------------------
        # Failed login count
        # -----------------------------------------

        failed_logins = data.get(
            'failed_logins',
            data.get(
                'failed_attempts',
                0
            )
        )

        # -----------------------------------------
        # IP risk
        # -----------------------------------------

        ip_risk = 0

        ip = data.get(
            'ip_address',
            data.get(
                'source_ip',
                ''
            )
        )

        if ip:

            private_ranges = [
                '192.168.',
                '10.',
                '172.16.',
                '172.17.',
                '172.18.',
                '172.19.',
                '172.20.',
                '172.21.',
                '172.22.',
                '172.23.',
                '172.24.',
                '172.25.',
                '172.26.',
                '172.27.',
                '172.28.',
                '172.29.',
                '172.30.',
                '172.31.'
            ]

            is_private = any(
                ip.startswith(pr)
                for pr in private_ranges
            )

            if not is_private:
                ip_risk = 70

        # -----------------------------------------
        # Event severity
        # -----------------------------------------

        event_severity = log.threat_level or "LOW"

        # -----------------------------------------
        # Unusual time
        # -----------------------------------------

        unusual_time = data.get(
            'unusual_time',
            False
        )

        # -----------------------------------------
        # Unusual location
        # -----------------------------------------

        unusual_location = data.get(
            'unusual_location',
            False
        )

        # -----------------------------------------
        # Dynamic Risk Engine
        # -----------------------------------------

        engine = DynamicRiskEngine()

        result = engine.calculate_risk(

            failed_logins=failed_logins,

            anomaly_score=anomaly_score,

            ip_risk=ip_risk,

            unusual_time=unusual_time,

            unusual_location=unusual_location,

            event_severity=event_severity
        )

        # -----------------------------------------
        # Save result to SecurityLog
        # -----------------------------------------

        log.threat_score = result[
            'risk_score'
        ]

        log.threat_level = result[
            'risk_level'
        ]

        log.anomaly_detected = (
            anomaly_score >= 50
        )

        log.processed = True

        log.save(
            update_fields=[
                'threat_score',
                'threat_level',
                'anomaly_detected',
                'processed'
            ]
        )

        # -----------------------------------------
        # Response
        # -----------------------------------------

        return Response({

            'success': True,

            'log_id': log.id,

            'anomaly_score': anomaly_score,

            'risk_score': result[
                'risk_score'
            ],

            'risk_level': result[
                'risk_level'
            ],

            'message':
                'Dynamic risk calculated successfully'
        })
class DetectedThreatViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = DetectedThreatSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ['severity', 'threat_type']

    def get_queryset(self):
        return DetectedThreat.objects.filter(
            log__user=self.request.user
        ).select_related('log').order_by('-detected_at')


class AlertRuleViewSet(viewsets.ModelViewSet):
    serializer_class = AlertRuleSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return AlertRule.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

class ThreatPredictionViewSet(viewsets.ViewSet):

    permission_classes = [
        permissions.IsAuthenticated
    ]

    @action(
        detail=False,
        methods=['post'],
        url_path='predict'
    )
    def predict(self, request):

        try:

            failed_logins = float(
                request.data.get('failed_logins', 0)
            )

            login_attempts = float(
                request.data.get('login_attempts', 0)
            )

            unique_ips = float(
                request.data.get('unique_ips', 0)
            )

            request_count = float(
                request.data.get('request_count', 0)
            )

            anomaly_score = float(
                request.data.get('anomaly_score', 0)
            )

            port_activity = float(
                request.data.get('port_activity', 0)
            )

            # Create predictor
            predictor = ThreatPredictor()

            # Project root:
            # AI-Cybersecurity-Threat-Monitoring
            project_root = os.path.dirname(
                os.path.dirname(
                    os.path.dirname(
                        os.path.abspath(__file__)
                    )
                )
            )

            csv_path = os.path.join(
                project_root,
                'sample_data',
                'threat_training_data.csv'
            )

            # Train model
            training_result = predictor.train_from_csv(
                csv_path
            )

            # Predict
            result = predictor.predict_from_values(

                failed_logins=failed_logins,

                login_attempts=login_attempts,

                unique_ips=unique_ips,

                request_count=request_count,

                anomaly_score=anomaly_score,

                port_activity=port_activity
            )

            return Response({

                'success': True,

                'prediction': result,

                'training': training_result

            })

        except Exception as e:

            return Response(
                {
                    'success': False,
                    'error': str(e)
                },
                status=400
            )