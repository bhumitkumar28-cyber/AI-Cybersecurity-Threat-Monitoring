import os
import requests
from dotenv import load_dotenv

load_dotenv()


class AIExplainer:
    def __init__(self):
        # Load API key from environment
        self.api_key = (
            os.getenv("OPENAI_API_KEY")
            or os.getenv("GEMINI_API_KEY")
        )

        if os.getenv("OPENAI_API_KEY"):
            self.provider = "openai"
        elif os.getenv("GEMINI_API_KEY"):
            self.provider = "gemini"
        else:
            self.provider = None

        if not self.api_key:
            print("⚠️ No API key found. Using fallback explanations.")

    def explain(self, threat, log_data):
        """Generate AI-powered threat explanation."""

        # If no API key, use heuristic explanation
        if not self.api_key:
            return self._heuristic_explanation(threat, log_data)

        try:
            if self.provider == "openai":
                return self._openai_explain(threat, log_data)

            elif self.provider == "gemini":
                return self._gemini_explain(threat, log_data)

        except Exception as e:
            print(f"⚠️ AI explanation failed: {e}")
            return self._heuristic_explanation(threat, log_data)

        return self._heuristic_explanation(threat, log_data)

    def _openai_explain(self, threat, log_data):
        """Generate explanation using OpenAI API."""

        prompt = f"""
You are a cybersecurity expert.

Explain the following threat in simple terms for a non-technical manager.

Threat Type: {threat.get('type', 'Unknown')}
Severity: {threat.get('severity', 'Unknown')}
Description: {threat.get('description', 'No description')}

Log Data:
{log_data}

Please explain:

1. What happened in simple terms
2. How serious this is
3. What the attacker might be trying to do
4. What the organization should do immediately

Keep the explanation under 150 words and avoid technical jargon.
"""

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        data = {
            "model": "gpt-3.5-turbo",
            "messages": [
                {
                    "role": "system",
                    "content": "You are a helpful cybersecurity assistant.",
                },
                {
                    "role": "user",
                    "content": prompt,
                },
            ],
            "max_tokens": 300,
            "temperature": 0.7,
        }

        response = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers=headers,
            json=data,
            timeout=30,
        )

        if response.status_code == 200:
            result = response.json()

            return (
                result["choices"][0]["message"]["content"]
                .strip()
            )

        return self._heuristic_explanation(threat, log_data)

    def _gemini_explain(self, threat, log_data):
        """Generate explanation using Google Gemini API."""

        prompt = f"""
You are a cybersecurity expert.

Explain the following threat in simple terms for a non-technical manager.

Threat Type: {threat.get('type', 'Unknown')}
Severity: {threat.get('severity', 'Unknown')}
Description: {threat.get('description', 'No description')}

Log Data:
{log_data}

Please explain:

1. What happened in simple terms
2. How serious this is
3. What the attacker might be trying to do
4. What the organization should do immediately

Keep the explanation under 150 words and avoid technical jargon.
"""

        headers = {
            "Content-Type": "application/json",
        }

        data = {
            "contents": [
                {
                    "parts": [
                        {
                            "text": prompt
                        }
                    ]
                }
            ]
        }

        response = requests.post(
            f"https://generativelanguage.googleapis.com/v1beta/"
            f"models/gemini-pro:generateContent?key={self.api_key}",
            headers=headers,
            json=data,
            timeout=30,
        )

        if response.status_code == 200:
            result = response.json()

            try:
                return (
                    result["candidates"][0]["content"]["parts"][0]["text"]
                    .strip()
                )
            except (KeyError, IndexError):
                return self._heuristic_explanation(
                    threat,
                    log_data
                )

        return self._heuristic_explanation(threat, log_data)

    def _heuristic_explanation(self, threat, log_data):
        """Generate explanation without an external AI API."""

        explanations = {
            "Brute Force Attempt":
                "Multiple failed login attempts for privileged accounts "
                "often indicate automated attacks trying to guess passwords.",

            "Suspicious External Login Attempt":
                "Login attempts from unfamiliar or blacklisted IP addresses "
                "may indicate attackers probing for weak credentials.",

            "SSH Access Denied":
                "Blocked SSH connections suggest potential unauthorized "
                "access attempts to your servers.",

            "Suspicious Traffic Blocked":
                "Firewall blocking traffic from known malicious IP ranges "
                "is preventing potential attacks.",

            "Port Scan Detected":
                "Network scanning activity typically precedes attacks as "
                "attackers map vulnerable services.",

            "Potential Compromise":
                "Critical alerts about possible compromise require immediate "
                "investigation and isolation.",

            "Traffic Anomaly":
                "Unusual traffic patterns could indicate data exfiltration "
                "or distributed denial-of-service activity.",
        }

        threat_type = threat.get("type", "Unknown")
        severity = threat.get("severity", "Unknown")

        return explanations.get(
            threat_type,
            f"Security analysis indicates {threat_type.lower()} "
            f"with {severity.lower()} severity. "
            "Review the log details and consider taking recommended actions."
        )