from django.contrib.auth.models import User

def get_user_logs(user):
    """Get all logs for a user"""
    from .models import SecurityLog
    return SecurityLog.objects.filter(user=user)

def get_user_threats(user):
    """Get all threats for a user"""
    from .models import DetectedThreat
    return DetectedThreat.objects.filter(log__user=user)

def calculate_threat_summary(user):
    """Calculate threat summary statistics"""
    from .models import SecurityLog, DetectedThreat
    
    total_logs = SecurityLog.objects.filter(user=user).count()
    total_threats = DetectedThreat.objects.filter(log__user=user).count()
    critical_threats = DetectedThreat.objects.filter(log__user=user, severity='CRITICAL').count()
    high_threats = DetectedThreat.objects.filter(log__user=user, severity='HIGH').count()
    medium_threats = DetectedThreat.objects.filter(log__user=user, severity='MEDIUM').count()
    low_threats = DetectedThreat.objects.filter(log__user=user, severity='LOW').count()
    
    return {
        'total_logs': total_logs,
        'total_threats': total_threats,
        'critical_threats': critical_threats,
        'high_threats': high_threats,
        'medium_threats': medium_threats,
        'low_threats': low_threats,
        'threat_rate': (total_threats / total_logs * 100) if total_logs > 0 else 0
    }
