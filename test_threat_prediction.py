import os
import django

# Django setup
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
django.setup()

from threat_monitor.threat_predictor import ThreatPredictor


print("\n========================================")
print("   THREAT PREDICTION MODEL TEST")
print("========================================\n")


# Create predictor
predictor = ThreatPredictor()

print("[1] ThreatPredictor created")


# Training dataset path
csv_path = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "sample_data",
    "threat_training_data.csv"
)

print("[2] Training dataset:")
print(csv_path)


# Train model
result = predictor.train_from_csv(csv_path)

print("\n[3] MODEL TRAINING RESULT")
print("----------------------------------------")
print(result)


# Test 1 - Brute Force
print("\n[4] TEST: BRUTE FORCE")
print("----------------------------------------")

result1 = predictor.predict_from_values(
    failed_logins=40,
    login_attempts=50,
    unique_ips=8,
    request_count=250,
    anomaly_score=0.90,
    port_activity=10
)

print(result1)


# Test 2 - Normal activity
print("\n[5] TEST: NORMAL")
print("----------------------------------------")

result2 = predictor.predict_from_values(
    failed_logins=1,
    login_attempts=3,
    unique_ips=1,
    request_count=30,
    anomaly_score=0.05,
    port_activity=1
)

print(result2)


# Test 3 - DDoS
print("\n[6] TEST: DDOS")
print("----------------------------------------")

result3 = predictor.predict_from_values(
    failed_logins=8,
    login_attempts=15,
    unique_ips=25,
    request_count=1000,
    anomaly_score=0.90,
    port_activity=20
)

print(result3)


print("\n========================================")
print("   TEST COMPLETED")
print("========================================\n")