class ThreatClassifier:
    def __init__(self):
        self.rules = {
            'AUTH': [
                {
                    'condition': lambda data: data.get('status') == 'failure' and data.get('username') in ['root', 'admin'],
                    'type': 'Brute Force Attempt',
                    'severity': 'HIGH',
                    'description': 'Failed login attempt for privileged account',
                    'action': 'Block IP address and monitor for repeated attempts'
                },
                {
                    'condition': lambda data: data.get('status') == 'failure' and data.get('ip_address', '').startswith('45.33'),
                    'type': 'Suspicious External Login Attempt',
                    'severity': 'MEDIUM',
                    'description': 'Failed login attempt from suspicious IP range',
                    'action': 'Review IP reputation and consider blocking'
                },
                {
                    'condition': lambda data: data.get('event_type') == 'file_access' and data.get('username') == 'alice',
                    'type': 'File Access',
                    'severity': 'LOW',
                    'description': 'File access by user alice',
                    'action': 'Log for audit purposes'
                }
            ],
            'FIREWALL': [
                {
                    'condition': lambda data: data.get('action') == 'DENY' and data.get('port') == 22,
                    'type': 'SSH Access Denied',
                    'severity': 'MEDIUM',
                    'description': 'SSH access denied by firewall',
                    'action': 'Verify if this is expected traffic'
                },
                {
                    'condition': lambda data: data.get('action') == 'DENY' and data.get('source_ip', '').startswith('45.33'),
                    'type': 'Suspicious Traffic Blocked',
                    'severity': 'HIGH',
                    'description': 'Traffic from known suspicious IP blocked',
                    'action': 'Add IP to blocklist and investigate'
                }
            ],
            'NETWORK': [
                {
                    'condition': lambda data: 'scan' in data.get('message', '').lower(),
                    'type': 'Port Scan Detected',
                    'severity': 'CRITICAL',
                    'description': 'Network scanning activity detected',
                    'action': 'Immediately block source IP and conduct forensic analysis'
                },
                {
                    'condition': lambda data: data.get('level') == 'ALERT' and 'pwn' in data.get('message', '').lower(),
                    'type': 'Potential Compromise',
                    'severity': 'CRITICAL',
                    'description': 'Possible system compromise indicated',
                    'action': 'Isolate affected system and initiate incident response'
                },
                {
                    'condition': lambda data: data.get('level') == 'WARN' and 'high traffic' in data.get('message', '').lower(),
                    'type': 'Traffic Anomaly',
                    'severity': 'MEDIUM',
                    'description': 'Unusual network traffic volume detected',
                    'action': 'Monitor traffic patterns and check for DDoS indicators'
                }
            ]
        }
    
    def classify(self, log_data, log_type):
        """Classify a log entry based on security rules"""
        threats = []
        
        # Get rules for the log type
        rules = self.rules.get(log_type, [])
        
        # Check each rule
        for rule in rules:
            if rule['condition'](log_data):
                threats.append(rule)
        
        return threats
