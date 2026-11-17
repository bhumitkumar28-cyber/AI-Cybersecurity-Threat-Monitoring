class SecurityCopilot:
    """
    AI Security Copilot for explaining detected cybersecurity threats.
    """

    MITRE_MAPPING = {
        'Brute Force Attempt': {
            'technique': 'T1110',
            'name': 'Brute Force',
            'explanation': (
                'Multiple failed login attempts against an account '
                'may indicate an automated password guessing attack.'
            ),
        },

        'Suspicious External Login Attempt': {
            'technique': 'T1078',
            'name': 'Valid Accounts',
            'explanation': (
                'A login attempt from an unusual external IP address '
                'may indicate the use of stolen or compromised credentials.'
            ),
        },

        'SSH Access Denied': {
            'technique': 'T1021.004',
            'name': 'Remote Services: SSH',
            'explanation': (
                'A blocked SSH connection indicates that a system '
                'attempted to access a remote SSH service.'
            ),
        },

        'Suspicious Traffic Blocked': {
            'technique': 'T1190',
            'name': 'Exploit Public-Facing Application',
            'explanation': (
                'Suspicious external traffic was blocked by the firewall. '
                'This may indicate reconnaissance or an attempted attack.'
            ),
        },

        'Port Scan Detected': {
            'technique': 'T1595',
            'name': 'Active Scanning',
            'explanation': (
                'The source IP scanned multiple ports. This is commonly '
                'used to discover open services and potential vulnerabilities.'
            ),
        },

        'Potential Compromise': {
            'technique': 'T1071.004',
            'name': 'Application Layer Protocol: DNS',
            'explanation': (
                'A suspicious DNS request may indicate command-and-control '
                'communication or possible system compromise.'
            ),
        },

        'Traffic Anomaly': {
            'technique': 'T1498',
            'name': 'Network Denial of Service',
            'explanation': (
                'Unusual traffic volume may indicate abnormal behavior, '
                'denial-of-service activity, or possible data exfiltration.'
            ),
        },

        'File Access': {
            'technique': 'T1005',
            'name': 'Data from Local System',
            'explanation': (
                'File access was recorded for security auditing. '
                'Review whether this activity was expected.'
            ),
        },
    }

    def analyze(self, threat):
        """
        Analyze a detected threat and return a Security Copilot response.
        """

        threat_info = self.MITRE_MAPPING.get(
            threat.threat_type,
            {
                'technique': 'N/A',
                'name': 'Unknown Technique',
                'explanation': (
                    'The system detected suspicious activity. '
                    'Review the raw log and recommended action.'
                ),
            }
        )

        if threat.severity == 'CRITICAL':
            priority = 'Immediate action is required.'

        elif threat.severity == 'HIGH':
            priority = 'High priority investigation is required.'

        elif threat.severity == 'MEDIUM':
            priority = 'Monitor and investigate this activity.'

        else:
            priority = 'Record this event and review if needed.'

        return {
            'title': 'Why is this alert critical?',
            'summary': threat_info['explanation'],
            'risk_score': int(threat.log.threat_score or 0),
            'severity': threat.severity,
            'mitre_id': threat_info['technique'],
            'mitre_name': threat_info['name'],
            'recommended_action': threat.recommended_action,
            'priority_message': priority,
            'ai_explanation': threat.ai_explanation,
        }