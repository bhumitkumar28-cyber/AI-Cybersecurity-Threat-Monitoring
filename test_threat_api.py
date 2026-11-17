import os
import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
django.setup()

from django.contrib.auth import get_user_model
from rest_framework.test import APIRequestFactory, force_authenticate
from threat_monitor.api_views import ThreatPredictionViewSet


print("\n========================================")
print("   THREAT PREDICTION API TEST")
print("========================================\n")


# ----------------------------------------
# GET TEST USER
# ----------------------------------------

User = get_user_model()

user, created = User.objects.get_or_create(
    username="api_test_user"
)

if created:
    user.set_password("Test@12345")
    user.save()


# ----------------------------------------
# CREATE REQUEST
# ----------------------------------------

factory = APIRequestFactory()

data = {
    "failed_logins": 40,
    "login_attempts": 50,
    "unique_ips": 8,
    "request_count": 250,
    "anomaly_score": 0.90,
    "port_activity": 10
}


request = factory.post(
    "/api/threat-prediction/predict/",
    data,
    format="json"
)


# ----------------------------------------
# AUTHENTICATE REQUEST
# ----------------------------------------

force_authenticate(
    request,
    user=user
)


# ----------------------------------------
# CALL VIEWSET
# ----------------------------------------

view = ThreatPredictionViewSet.as_view({
    "post": "predict"
})

response = view(request)


# ----------------------------------------
# PRINT RESULT
# ----------------------------------------

print("HTTP STATUS:")
print(response.status_code)

print("\nAPI RESPONSE:")
print("----------------------------------------")
print(response.data)

print("\n========================================")
print("   API TEST COMPLETED")
print("========================================\n")