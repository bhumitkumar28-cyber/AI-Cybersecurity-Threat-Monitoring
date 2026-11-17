from .ml.dl_detector import DeepLearningDetector
import csv
import io
import json
from datetime import datetime, timedelta

import pandas as pd

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer

from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from django.db import models
from django.db.models import Count
from django.db.models.functions import TruncDate
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .ai_explainer import AIExplainer
from .anomaly_detector import AnomalyDetector
from .attack_chain import AttackChainDetector
from .behavior_analyzer import BehaviorAnalyzer
from .incident_service import IncidentService
from .models import (
    DetectedThreat,
    SecurityIncident,
    SecurityLog,
    ThreatIntelligence,
)
from .risk_engine import DynamicRiskEngine
from .security_copilot import SecurityCopilot
from .threat_classifier import ThreatClassifier
from .threat_intelligence import ThreatIntelligenceEngine


# Initialize reusable analysis components.
security_copilot = SecurityCopilot()
anomaly_detector = AnomalyDetector()
threat_classifier = ThreatClassifier()
ai_explainer = AIExplainer()
threat_intelligence_engine = ThreatIntelligenceEngine()

try:
    deep_learning_detector = DeepLearningDetector()
except Exception as exc:
    deep_learning_detector = None
    print(f"Deep Learning detector unavailable: {exc}")
# ============================================================
# RISK CALCULATION API
# ============================================================

@api_view(["POST"])
@permission_classes([IsAuthenticated])
def calculate_risk(request):
    data = request.data

    engine = DynamicRiskEngine()

    result = engine.calculate_risk(
        failed_logins=data.get("failed_logins", 0),
        anomaly_score=data.get("anomaly_score", 0),
        ip_risk=data.get("ip_risk", 0),
        unusual_time=data.get("unusual_time", False),
        unusual_location=data.get("unusual_location", False),
        event_severity=data.get("event_severity", "LOW"),
    )

    return Response(
        {
            "success": True,
            "message": "Risk calculated successfully",
            "data": result,
        },
        status=status.HTTP_200_OK,
    )


# ============================================================
# AUTHENTICATION
# ============================================================

def register_view(request):
    if request.method == "POST":
        form = UserCreationForm(request.POST)

        if form.is_valid():
            user = form.save()
            login(request, user)
            return redirect("dashboard")
    else:
        form = UserCreationForm()

    return render(request, "register.html", {"form": form})


def login_view(request):
    if request.method == "POST":
        form = AuthenticationForm(request, data=request.POST)

        if form.is_valid():
            user = form.get_user()
            login(request, user)
            return redirect("dashboard")
    else:
        form = AuthenticationForm()

    return render(request, "login.html", {"form": form})


def logout_view(request):
    logout(request)
    return redirect("login")


# ============================================================
# MAIN DASHBOARD
# ============================================================

@login_required
def dashboard_view(request):
    user_logs = SecurityLog.objects.filter(user=request.user)

    threats = (
        DetectedThreat.objects
        .select_related("log")
        .filter(log__user=request.user)
        .order_by("-detected_at")[:10]
    )

    threat_distribution = (
        DetectedThreat.objects
        .filter(log__user=request.user)
        .values("severity")
        .annotate(count=Count("id"))
    )

    context = {
        "total_logs": user_logs.count(),
        "threats": threats,
        "critical_threats": DetectedThreat.objects.filter(
            severity="CRITICAL",
            log__user=request.user,
        ).count(),
        "threat_distribution": list(threat_distribution),
        "open_incidents": SecurityIncident.objects.filter(
            threat__log__user=request.user,
        ).exclude(
            status__in=["RESOLVED", "FALSE_POSITIVE"],
        ).count(),
        "chain_count": DetectedThreat.objects.filter(
            log__user=request.user,
            threat_type__startswith="Multi-Stage Attack",
        ).count(),
        "review_count": DetectedThreat.objects.filter(
            log__user=request.user,
            severity__in=["HIGH", "CRITICAL"],
        ).count(),
    }

    return render(request, "dashboard.html", context)


# ============================================================
# LOG UPLOAD
# ============================================================

@login_required
def upload_logs_view(request):
    if request.method != "POST" or not request.FILES.get("log_file"):
        return render(request, "upload_logs.html")

    log_file = request.FILES["log_file"]
    file_type = request.POST.get("log_type", "AUTH").upper()

    if file_type not in {"AUTH", "FIREWALL", "NETWORK"}:
        return render(
            request,
            "upload_logs.html",
            {"error": "Invalid log type. Select AUTH, FIREWALL, or NETWORK."},
        )

    try:
        content = log_file.read().decode("utf-8-sig")

        if log_file.name.lower().endswith(".csv"):
            records = pd.read_csv(io.StringIO(content)).to_dict(
                orient="records"
            )

        elif log_file.name.lower().endswith(".json"):
            records = json.loads(content)

            if isinstance(records, dict):
                records = records.get("logs", [records])

            if not isinstance(records, list):
                raise ValueError("JSON must contain a list of log records.")

        elif log_file.name.lower().endswith(".txt"):
            records = [
                record
                for line in content.splitlines()
                if (record := parse_text_log(line))
            ]

        else:
            raise ValueError("Only CSV, JSON, and TXT files are supported.")

        for record in records:
            if not isinstance(record, dict):
                continue

            log_data = dict(record)
            timestamp_value = log_data.get("timestamp")

            if timestamp_value:
                timestamp = datetime.fromisoformat(
                    str(timestamp_value).replace("Z", "+00:00")
                )
                if timezone.is_aware(timestamp):
                    timestamp = timezone.localtime(timestamp).replace(
                        tzinfo=None
                    )
            else:
                timestamp = datetime.now()

            log_data["file_source"] = log_file.name

            log = SecurityLog.objects.create(
                log_type=file_type,
                timestamp=timestamp,
                raw_data=log_data,
                user=request.user,
            )

            process_log(log)

        return redirect("dashboard")

    except (
        UnicodeDecodeError,
        ValueError,
        TypeError,
        json.JSONDecodeError,
    ) as exc:
        return render(
            request,
            "upload_logs.html",
            {"error": f"Could not process the uploaded file: {exc}"},
        )


def parse_text_log(line):
    if "[" not in line or "]" not in line:
        return None

    parts = line.split("] ", 1)

    if len(parts) != 2:
        return None

    level = parts[0].strip("[")

    return {
        "level": level,
        "message": parts[1],
        "timestamp": datetime.now().isoformat(),
    }


# ============================================================
# REAL-TIME THREAT NOTIFICATIONS
# ============================================================

def broadcast_threat(threat):
    if not threat.log.user_id:
        return

    channel_layer = get_channel_layer()

    if channel_layer is None:
        return

    async_to_sync(channel_layer.group_send)(
        f"user_threats_{threat.log.user_id}",
        {
            "type": "send_threat_notification",
            "data": {
                "threat_id": threat.id,
                "type": threat.threat_type,
                "severity": threat.severity,
                "score": threat.log.threat_score,
                "description": threat.description,
                "detected_at": threat.detected_at.isoformat(),
            },
        },
    )


# ============================================================
# PROCESS ONE SECURITY LOG
# ============================================================

def process_log(log):
    raw_data = log.raw_data or {}

    if not isinstance(raw_data, dict):
        raw_data = {"message": str(raw_data)}
        log.raw_data = raw_data

    # 1. Threat intelligence
    intelligence_results = threat_intelligence_engine.analyze_log(
        raw_data
    )
    raw_data["threat_intelligence"] = intelligence_results

    # 2. Rule-based classification
    rules = threat_classifier.classify(raw_data, log.log_type) or []

    # 3. Anomaly detection
    log.anomaly_detected = anomaly_detector.detect(
        raw_data,
        log.log_type,
    )

    anomaly_score = anomaly_detector.get_anomaly_score(
        raw_data,
        log.log_type,
    )

    # 4. Failed login count
    failed_logins = raw_data.get(
        "failed_logins",
        raw_data.get("failed_attempts", 0),
    )

    try:
        failed_logins = max(0, int(failed_logins))
    except (TypeError, ValueError):
        failed_logins = 0

    event_status = str(raw_data.get("status", "")).lower()

    if (
        failed_logins == 0
        and log.log_type == "AUTH"
        and event_status in {
            "failure", "failed", "fail", "denied",
            "invalid", "unsuccessful",
        }
    ):
        failed_logins = 1

    # 5. IP context
    ip = str(
        raw_data.get("ip_address")
        or raw_data.get("source_ip")
        or ""
    ).strip()

    private_ranges = (
        "192.168.",
        "10.",
        "172.16.",
        "172.17.",
        "172.18.",
        "172.19.",
        "172.20.",
        "172.21.",
        "172.22.",
        "172.23.",
        "172.24.",
        "172.25.",
        "172.26.",
        "172.27.",
        "172.28.",
        "172.29.",
        "172.30.",
        "172.31.",
    )

    # This is only a contextual heuristic, not proof of malicious activity.
    ip_risk = 70 if ip and not ip.startswith(private_ranges) else 0

    # 6. Unusual time
    unusual_time = bool(raw_data.get("unusual_time", False))

    if log.timestamp and (
        log.timestamp.hour < 6 or log.timestamp.hour >= 22
    ):
        unusual_time = True

    # 7. Unusual location
    unusual_location = bool(raw_data.get("unusual_location", False))
    location = str(raw_data.get("location", "")).strip().lower()

    if location in {"unknown", "unavailable", "foreign"}:
        unusual_location = True

    # 8. Event severity
    severity_priority = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }
    event_severity = "LOW"

    for rule in rules:
        severity = str(rule.get("severity", "LOW")).upper()

        if severity_priority.get(severity, 1) > severity_priority[
            event_severity
        ]:
            event_severity = severity

    if not rules:
        raw_level = str(raw_data.get("level", "")).upper()

        if raw_level in severity_priority:
            event_severity = raw_level
        elif raw_level == "ALERT":
            event_severity = "HIGH"
        elif raw_level == "WARN":
            event_severity = "MEDIUM"



    # 8.5 Deep Learning anomaly detection
    dl_result = {
        "available": False,
        "reason": "Detector unavailable",
    }

    if deep_learning_detector is not None:
        try:
            from datetime import timedelta

            window_start = log.timestamp - timedelta(minutes=15)

            recent_logs = list(
                SecurityLog.objects.filter(
                    user=log.user,
                    timestamp__gte=window_start,
                    timestamp__lte=log.timestamp,
                ).only("log_type", "raw_data", "timestamp")[:500]
            )

            auth_logs = [
                item for item in recent_logs
                if item.log_type == "AUTH"
            ]

            failed_statuses = {
                "failure", "failed", "fail", "denied",
                "invalid", "unsuccessful",
            }

            failed_count = 0
            unique_ips = set()
            unique_ports = set()

            for item in recent_logs:
                data = item.raw_data or {}

                if not isinstance(data, dict):
                    data = {}

                status = str(data.get("status", "")).lower()

                if (
                    item.log_type == "AUTH"
                    and status in failed_statuses
                ):
                    failed_count += 1

                ip_value = (
                    data.get("ip_address")
                    or data.get("source_ip")
                )
                if ip_value:
                    unique_ips.add(str(ip_value))

                port_value = (
                    data.get("destination_port")
                    or data.get("dest_port")
                    or data.get("port")
                )
                if port_value is not None:
                    unique_ports.add(str(port_value))

            try:
                normalized_anomaly_score = float(anomaly_score)
                if normalized_anomaly_score > 1:
                    normalized_anomaly_score /= 100.0
            except (TypeError, ValueError):
                normalized_anomaly_score = 0.0

            dl_features = {
                "failed_logins": failed_count,
                "login_attempts": len(auth_logs),
                "unique_ips": len(unique_ips),
                "request_count": len(recent_logs),
                "anomaly_score": normalized_anomaly_score,
                "port_activity": len(unique_ports),
            }

            dl_result = deep_learning_detector.predict(dl_features)
            dl_result["available"] = True
            dl_result["features"] = dl_features

        except Exception as exc:
            # Keep the existing risk pipeline running.
            dl_result = {
                "available": False,
                "reason": str(exc),
            }
            print(f"Deep Learning prediction failed: {exc}")

    raw_data["deep_learning"] = dl_result
    # 9. Dynamic risk calculation
    risk_result = DynamicRiskEngine().calculate_risk(
        failed_logins=failed_logins,
        anomaly_score=anomaly_score,
        ip_risk=ip_risk,
        unusual_time=unusual_time,
        unusual_location=unusual_location,
        event_severity=event_severity,
    )

    # 10. Save the log before running correlated analysis
    log.threat_score = risk_result["risk_score"]
    log.threat_level = risk_result["risk_level"]
    log.raw_data = raw_data
    log.processed = True
    log.save()

    # 11. Create rule-based threats
    for rule in rules:
        threat, created = DetectedThreat.objects.get_or_create(
            log=log,
            threat_type=rule["type"],
            defaults={
                "severity": rule["severity"],
                "description": rule["description"],
                "recommended_action": rule["action"],
                "ai_explanation": ai_explainer.explain(rule, raw_data),
            },
        )

        if created:
            broadcast_threat(threat)

    # 12. User Behavior Analytics
    behavior_score, behavior_evidence = BehaviorAnalyzer().analyze(log)

    if behavior_score >= 40:
        behavior_threat, created = DetectedThreat.objects.get_or_create(
            log=log,
            threat_type="Behavioral Anomaly",
            defaults={
                "severity": "HIGH" if behavior_score >= 60 else "MEDIUM",
                "description": (
                    f"Behavioral risk score: {behavior_score}/100. "
                    + "; ".join(behavior_evidence)
                ),
                "recommended_action": (
                    "Review authentication history and related events."
                ),
                "ai_explanation": (
                    "Rule-based behavioral findings require analyst review."
                ),
            },
        )

        if created:
            broadcast_threat(behavior_threat)

    # 13. Attack-chain detection
    AttackChainDetector().detect(log)

    # 14. Incident creation for high-severity threats
    current_threats = DetectedThreat.objects.filter(
        log=log,
        severity__in=["HIGH", "CRITICAL"],
    )

    for threat in current_threats:
        IncidentService.create_from_threat(threat)


# ============================================================
# LOG AND THREAT DETAILS
# ============================================================

@login_required
def log_details_view(request, log_id):
    log = get_object_or_404(
        SecurityLog,
        id=log_id,
        user=request.user,
    )

    threats = DetectedThreat.objects.filter(log=log)

    raw_data = log.raw_data or {}
    deep_learning = (
        raw_data.get("deep_learning", {})
        if isinstance(raw_data, dict)
        else {}
    )

    if not isinstance(deep_learning, dict):
        deep_learning = {}

    indicators = [
        str(raw_data[field]).strip()
        for field in (
            "ip_address",
            "source_ip",
            "destination_ip",
        )
        if raw_data.get(field)
    ]

    intelligence_records = ThreatIntelligence.objects.filter(
        indicator__in=indicators,
        is_active=True,
    ) if indicators else ThreatIntelligence.objects.none()

    return render(
        request,
        "log_details.html",
        {
            "log": log,
            "threats": threats,
            "threat_intelligence": intelligence_records,
            "deep_learning": deep_learning,
            "raw_data_json": json.dumps(
                raw_data,
                indent=2,
                default=str,
            ),
        },
    )

@login_required
def threat_details_view(request, threat_id):
    threat = get_object_or_404(
        DetectedThreat,
        id=threat_id,
        log__user=request.user,
    )

    copilot = security_copilot.analyze(threat)

    return render(
        request,
        "threat_details.html",
        {
            "threat": threat,
            "copilot": copilot,
        },
    )


# ============================================================
# SEARCH AND FILTER
# ============================================================

@login_required
def search_logs_view(request):
    query = request.GET.get("q", "").strip()

    logs = SecurityLog.objects.filter(user=request.user)

    if query:
        logs = logs.filter(
            models.Q(timestamp__icontains=query)
            | models.Q(log_type__icontains=query)
            | models.Q(raw_data__icontains=query)
        )

    return render(
        request,
        "search_results.html",
        {
            "logs": logs,
            "query": query,
        },
    )


@login_required
def filter_threats_view(request):
    severity = request.GET.get("severity", "").upper()

    threats = DetectedThreat.objects.filter(
        log__user=request.user
    ).select_related("log")

    if severity in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        threats = threats.filter(severity=severity)

    return render(
        request,
        "threats_list.html",
        {
            "threats": threats,
            "severity": severity,
        },
    )


# ============================================================
# DASHBOARD API ENDPOINTS
# ============================================================

@login_required
def api_threat_distribution(request):
    distribution = (
        DetectedThreat.objects
        .filter(log__user=request.user)
        .values("severity")
        .annotate(count=Count("id"))
    )

    return JsonResponse({"distribution": list(distribution)})


@login_required
def api_recent_threats(request):
    threats = (
        DetectedThreat.objects
        .filter(log__user=request.user)
        .order_by("-detected_at")[:5]
    )

    data = [
        {
            "type": threat.threat_type,
            "severity": threat.severity,
            "time": threat.detected_at.isoformat(),
            "description": threat.description,
        }
        for threat in threats
    ]

    return JsonResponse({"threats": data})


@login_required
def api_logs_summary(request):
    summary = (
        SecurityLog.objects
        .filter(user=request.user)
        .values("log_type")
        .annotate(count=Count("id"))
    )

    return JsonResponse({"summary": list(summary)})


@login_required
def api_anomaly_stats(request):
    logs = SecurityLog.objects.filter(user=request.user)

    return JsonResponse(
        {
            "anomaly_count": logs.filter(anomaly_detected=True).count(),
            "normal_count": logs.filter(anomaly_detected=False).count(),
        }
    )


@login_required
def api_threat_trends(request):
    try:
        days = int(request.GET.get("days", 30))
    except (TypeError, ValueError):
        days = 30

    days = min(max(days, 7), 365)
    start_date = timezone.now() - timedelta(days=days)

    trends = (
        DetectedThreat.objects
        .filter(
            log__user=request.user,
            detected_at__gte=start_date,
        )
        .annotate(date=TruncDate("detected_at"))
        .values("date", "severity")
        .annotate(count=Count("id"))
        .order_by("date")
    )

    return JsonResponse(
        {
            "days": days,
            "trends": list(trends),
        }
    )


# ============================================================
# SAMPLE DATA
# ============================================================

@login_required
def sample_logs_view(request):
    if SecurityLog.objects.filter(user=request.user).exists():
        return redirect("dashboard")

    sample_records = [
        {
            "timestamp": "2023-10-01T08:23:15",
            "username": "admin",
            "ip_address": "192.168.1.100",
            "event_type": "login",
            "status": "success",
            "location": "Mumbai",
        },
        {
            "timestamp": "2023-10-01T08:45:22",
            "username": "john",
            "ip_address": "10.0.0.55",
            "event_type": "login",
            "status": "failure",
            "location": "Bangalore",
        },
        {
            "timestamp": "2023-10-01T08:45:35",
            "username": "john",
            "ip_address": "10.0.0.55",
            "event_type": "login",
            "status": "failure",
            "location": "Bangalore",
        },
        {
            "timestamp": "2023-10-01T08:46:01",
            "username": "john",
            "ip_address": "10.0.0.55",
            "event_type": "login",
            "status": "failure",
            "location": "Bangalore",
        },
        {
            "timestamp": "2023-10-01T08:46:28",
            "username": "john",
            "ip_address": "10.0.0.55",
            "event_type": "login",
            "status": "failure",
            "location": "Bangalore",
        },
        {
            "timestamp": "2023-10-01T10:05:18",
            "username": "root",
            "ip_address": "45.33.32.156",
            "event_type": "login",
            "status": "failure",
            "location": "Unknown",
        },
        {
            "timestamp": "2023-10-01T10:05:22",
            "username": "root",
            "ip_address": "45.33.32.156",
            "event_type": "login",
            "status": "failure",
            "location": "Unknown",
        },
        {
            "timestamp": "2023-10-01T10:05:26",
            "username": "root",
            "ip_address": "45.33.32.156",
            "event_type": "login",
            "status": "failure",
            "location": "Unknown",
        },
        {
            "timestamp": "2023-10-01T13:45:33",
            "level": "CRITICAL",
            "message": (
                "Port scan detected: multiple ports scanned on a host"
            ),
        },
    ]

    for record in sample_records:
        timestamp = datetime.fromisoformat(record["timestamp"])

        log = SecurityLog.objects.create(
            log_type=(
                "NETWORK" if "message" in record else "AUTH"
            ),
            timestamp=timestamp,
            raw_data=record,
            user=request.user,
        )

        process_log(log)

    return redirect("dashboard")


# ============================================================
# CSV THREAT REPORT
# ============================================================

@login_required
def export_threat_report(request):
    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = (
        'attachment; filename="security_threat_report.csv"'
    )

    writer = csv.writer(response)

    writer.writerow(
        [
            "Threat ID",
            "Threat Type",
            "Severity",
            "Threat Score",
            "Detected At",
            "Description",
            "Recommended Action",
        ]
    )

    threats = (
        DetectedThreat.objects
        .filter(log__user=request.user)
        .select_related("log")
        .order_by("-detected_at")
    )

    for threat in threats:
        writer.writerow(
            [
                threat.id,
                threat.threat_type,
                threat.severity,
                threat.log.threat_score,
                threat.detected_at.strftime("%Y-%m-%d %H:%M:%S"),
                threat.description,
                threat.recommended_action,
            ]
        )

    return response


# ============================================================
# THREAT INTELLIGENCE
# ============================================================

@login_required
def threat_intelligence_view(request):
    intelligence = ThreatIntelligence.objects.filter(
        is_active=True
    ).order_by("-updated_at")

    return render(
        request,
        "threat_intelligence.html",
        {
            "intelligence": intelligence,
            "total_indicators": intelligence.count(),
            "high_indicators": intelligence.filter(
                severity="HIGH"
            ).count(),
            "critical_indicators": intelligence.filter(
                severity="CRITICAL"
            ).count(),
        },
    )


@login_required
def api_threat_intelligence(request):
    indicator = request.GET.get("indicator", "").strip()

    if not indicator:
        return JsonResponse(
            {
                "success": False,
                "error": "Indicator is required.",
            },
            status=400,
        )

    results = threat_intelligence_engine.analyze_log(
        {"indicator": indicator}
    )

    return JsonResponse(
        {
            "success": True,
            "indicator": indicator,
            "results": results,
        }
    )


# ============================================================
# INCIDENT MANAGEMENT
# ============================================================

@login_required
def incident_list_view(request):
    incidents = (
        SecurityIncident.objects
        .filter(threat__log__user=request.user)
        .select_related("threat", "threat__log")
        .order_by("-created_at")
    )

    return render(
        request,
        "incident_list.html",
        {"incidents": incidents},
    )


@login_required
def incident_detail_view(request, incident_id):
    incident = get_object_or_404(
        SecurityIncident.objects.select_related("threat", "threat__log"),
        id=incident_id,
        threat__log__user=request.user,
    )

    return render(
        request,
        "incident_details.html",
        {"incident": incident},
    )


# ============================================================
# HUMAN REVIEW QUEUE
# ============================================================

@login_required
def review_queue_view(request):
    threats = (
        DetectedThreat.objects
        .filter(
            log__user=request.user,
            severity__in=["HIGH", "CRITICAL"],
        )
        .select_related("log")
        .order_by("-detected_at")
    )

    return render(
        request,
        "human_review_queue.html",
        {"threats": threats},
    )


# ============================================================
# MODEL PERFORMANCE DASHBOARD
# ============================================================

@login_required
def model_performance_view(request):
    user_logs = SecurityLog.objects.filter(user=request.user)

    user_threats = DetectedThreat.objects.filter(
        log__user=request.user
    )

    metrics = {
        "total_logs": user_logs.count(),
        "processed_logs": user_logs.filter(processed=True).count(),
        "anomalies_detected": user_logs.filter(
            anomaly_detected=True
        ).count(),
        "total_threats": user_threats.count(),
        "high_threats": user_threats.filter(severity="HIGH").count(),
        "critical_threats": user_threats.filter(
            severity="CRITICAL"
        ).count(),
    }

    return render(
        request,
        "model_performance.html",
        {
            "page_title": "Model Performance",
            "model_metrics": metrics,
        },
    )
