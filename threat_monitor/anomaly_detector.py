import numpy as np
from sklearn.ensemble import IsolationForest


class AnomalyDetector:

    def __init__(self):

        # =====================================================
        # Isolation Forest ML Model
        # =====================================================

        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.1,
            random_state=42
        )

        self.trained = False

        # =====================================================
        # Feature Extractors
        # =====================================================

        self.feature_extractors = {
            'AUTH': self._extract_auth_features,
            'FIREWALL': self._extract_firewall_features,
            'NETWORK': self._extract_network_features
        }

    # =========================================================
    # AUTH FEATURES
    # =========================================================

    def _extract_auth_features(self, log_data):

        features = []

        # 1. Failed login
        if 'status' in log_data:
            features.append(
                1 if str(log_data['status']).lower() == 'failure'
                else 0
            )
        else:
            features.append(0)

        # 2. Privileged username
        if 'username' in log_data:

            features.append(
                1
                if str(log_data['username']).lower()
                in ['root', 'admin', 'administrator']
                else 0
            )

        else:
            features.append(0)

        # 3. External IP
        ip = log_data.get('ip_address', '')

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

        is_external = (
            1
            if ip and not any(
                str(ip).startswith(pr)
                for pr in private_ranges
            )
            else 0
        )

        features.append(is_external)

        # 4. Failed login count
        try:
            failed_logins = int(
                log_data.get('failed_logins', 0)
            )
        except (TypeError, ValueError):
            failed_logins = 0

        # Normalize 0-10 failed logins to 0-1
        features.append(
            min(failed_logins, 10) / 10
        )

        # 5 & 6. Reserved features
        features.extend([0, 0])

        return np.array(
            features,
            dtype=float
        ).reshape(1, -1)

    # =========================================================
    # FIREWALL FEATURES
    # =========================================================

    def _extract_firewall_features(self, log_data):

        features = []

        # 1. DENY action
        action = str(
            log_data.get('action', '')
        ).upper()

        features.append(
            1 if action == 'DENY' else 0
        )

        # 2. High-risk ports
        high_risk_ports = [
            22,
            23,
            3389,
            445,
            135,
            139,
            1433,
            3306,
            5432
        ]

        try:
            port = int(
                log_data.get('port', 0)
            )
        except (TypeError, ValueError):
            port = 0

        features.append(
            1 if port in high_risk_ports else 0
        )

        # 3. External source IP
        ip = log_data.get(
            'source_ip',
            ''
        )

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

        is_external = (
            1
            if ip and not any(
                str(ip).startswith(pr)
                for pr in private_ranges
            )
            else 0
        )

        features.append(is_external)

        # Reserved features
        features.extend([0, 0, 0])

        return np.array(
            features,
            dtype=float
        ).reshape(1, -1)

    # =========================================================
    # NETWORK FEATURES
    # =========================================================

    def _extract_network_features(self, log_data):

        features = []

        # 1. Network level
        level_scores = {
            'INFO': 0,
            'WARN': 1,
            'ALERT': 2,
            'CRITICAL': 3
        }

        level = str(
            log_data.get(
                'level',
                'INFO'
            )
        ).upper()

        features.append(
            level_scores.get(
                level,
                0
            )
        )

        # 2. Suspicious keywords
        message = str(
            log_data.get(
                'message',
                ''
            )
        ).lower()

        suspicious_keywords = [
            'scan',
            'attack',
            'pwn',
            'malicious',
            'injection'
        ]

        has_suspicious = (
            1
            if any(
                keyword in message
                for keyword in suspicious_keywords
            )
            else 0
        )

        features.append(
            has_suspicious
        )

        # 3. External IP
        ip = log_data.get(
            'ip_address',
            ''
        )

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

        is_external = (
            1
            if ip and not any(
                str(ip).startswith(pr)
                for pr in private_ranges
            )
            else 0
        )

        features.append(
            is_external
        )

        # Reserved features
        features.extend([0, 0, 0])

        return np.array(
            features,
            dtype=float
        ).reshape(1, -1)

    # =========================================================
    # TRAIN MODEL
    # =========================================================

    def train(self, logs_data):

        if not logs_data:
            return

        all_features = []

        batch_size = 1000

        for i in range(
            0,
            len(logs_data),
            batch_size
        ):

            batch = logs_data[
                i:i + batch_size
            ]

            batch_features = []

            for log_data in batch:

                log_type = log_data.get(
                    'log_type',
                    'AUTH'
                )

                extractor = self.feature_extractors.get(
                    log_type,
                    self._extract_auth_features
                )

                features = extractor(
                    log_data
                )

                batch_features.append(
                    features[0]
                )

            all_features.extend(
                batch_features
            )

        if all_features:

            self.model.fit(
                np.array(
                    all_features
                )
            )

            self.trained = True

    # =========================================================
    # ANOMALY SCORE
    # =========================================================

    def get_anomaly_score(
        self,
        log_data,
        log_type
    ):
        """
        Return normalized anomaly score from 0 to 100.

        0   = Normal
        100 = Highly anomalous

        This is an anomaly indicator,
        NOT attack probability.
        """

        extractor = self.feature_extractors.get(
            log_type,
            self._extract_auth_features
        )

        features = extractor(
            log_data
        )

        # =====================================================
        # ML MODEL IS TRAINED
        # =====================================================

        if self.trained:

            decision = self.model.decision_function(
                features
            )[0]

            # Isolation Forest:
            #
            # Higher value = more normal
            # Lower value  = more anomalous

            # Keep value within expected range
            decision = max(
                -0.5,
                min(
                    0.5,
                    float(decision)
                )
            )

            # Convert decision value to 0-100.
            #
            # +0.5 -> 0 anomaly
            #  0.0 -> 50 anomaly
            # -0.5 -> 100 anomaly

            score = (
                (0.5 - decision)
                / 1.0
            ) * 100

            score = max(
                0,
                min(
                    100,
                    score
                )
            )

            return round(
                score,
                2
            )

        # =====================================================
        # ML MODEL NOT TRAINED
        # =====================================================

        if self._heuristic_detection(
            log_data,
            log_type
        ):
            return 85.0

        return 10.0

    # =========================================================
    # DETECTION
    # =========================================================

    def detect(
        self,
        log_data,
        log_type
    ):
        """
        Detect whether a log entry is anomalous.
        """

        extractor = self.feature_extractors.get(
            log_type,
            self._extract_auth_features
        )

        features = extractor(
            log_data
        )

        # =====================================================
        # MODEL NOT TRAINED
        # =====================================================

        if not self.trained:

            return self._heuristic_detection(
                log_data,
                log_type
            )

        # =====================================================
        # ISOLATION FOREST PREDICTION
        # =====================================================

        prediction = self.model.predict(
            features
        )

        # -1 = anomaly
        #  1 = normal

        return prediction[0] == -1

    # =========================================================
    # HEURISTIC DETECTION
    # =========================================================

    def _heuristic_detection(
        self,
        log_data,
        log_type
    ):
        """
        Fallback detection when ML model
        has not been trained.
        """

        # =====================================================
        # AUTH
        # =====================================================

        if log_type == 'AUTH':

            ip = str(
                log_data.get(
                    'ip_address',
                    ''
                )
            )

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

            return (
                str(
                    log_data.get(
                        'status',
                        ''
                    )
                ).lower()
                == 'failure'

                and

                str(
                    log_data.get(
                        'username',
                        ''
                    )
                ).lower()
                in [
                    'root',
                    'admin',
                    'administrator'
                ]

                and

                ip != ''

                and

                not any(
                    ip.startswith(pr)
                    for pr in private_ranges
                )
            )

        # =====================================================
        # FIREWALL
        # =====================================================

        elif log_type == 'FIREWALL':

            ip = str(
                log_data.get(
                    'source_ip',
                    ''
                )
            )

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

            return (
                str(
                    log_data.get(
                        'action',
                        ''
                    )
                ).upper()
                == 'DENY'

                and

                ip != ''

                and

                not any(
                    ip.startswith(pr)
                    for pr in private_ranges
                )
            )

        # =====================================================
        # NETWORK
        # =====================================================

        elif log_type == 'NETWORK':

            level = str(
                log_data.get(
                    'level',
                    ''
                )
            ).upper()

            message = str(
                log_data.get(
                    'message',
                    ''
                )
            ).lower()

            return (
                level in [
                    'CRITICAL',
                    'ALERT'
                ]

                or

                'scan' in message

                or

                'attack' in message

                or

                'malicious' in message

                or

                'injection' in message
            )

        return False
