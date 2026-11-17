import ipaddress
import re

from .models import ThreatIntelligence


class ThreatIntelligenceEngine:

    def extract_indicators(self, raw_data):
        """
        Extract IP addresses, domains and hashes
        from security log data.
        """

        text = str(raw_data)

        indicators = []

        # -----------------------------
        # Extract IPv4 addresses
        # -----------------------------

        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

        for ip in re.findall(ip_pattern, text):

            try:
                ipaddress.ip_address(ip)

                indicators.append({
                    'indicator': ip,
                    'indicator_type': 'IP'
                })

            except ValueError:
                pass

        # -----------------------------
        # Extract domains
        # -----------------------------

        domain_pattern = (
            r'\b(?:[a-zA-Z0-9-]+\.)+'
            r'[a-zA-Z]{2,}\b'
        )

        for domain in re.findall(domain_pattern, text):

            # Ignore common/local domains
            if domain.lower() not in [
                'localhost',
                'example.com'
            ]:

                indicators.append({
                    'indicator': domain.lower(),
                    'indicator_type': 'DOMAIN'
                })

        # -----------------------------
        # Extract SHA256 hashes
        # -----------------------------

        hash_pattern = r'\b[a-fA-F0-9]{64}\b'

        for file_hash in re.findall(
            hash_pattern,
            text
        ):

            indicators.append({
                'indicator': file_hash.lower(),
                'indicator_type': 'HASH'
            })

        # Remove duplicates
        unique = []

        seen = set()

        for item in indicators:

            key = (
                item['indicator_type'],
                item['indicator']
            )

            if key not in seen:

                seen.add(key)
                unique.append(item)

        return unique

    def check_indicator(
        self,
        indicator,
        indicator_type
    ):
        """
        Check indicator against local
        Threat Intelligence database.
        """

        result = ThreatIntelligence.objects.filter(
            indicator=indicator,
            indicator_type=indicator_type,
            is_active=True
        ).first()

        if result:

            return {
                'found': True,
                'indicator': result.indicator,
                'indicator_type': result.indicator_type,
                'threat_type': result.threat_type,
                'severity': result.severity,
                'confidence': result.confidence,
                'source': result.source,
                'description': result.description,
                'recommended_action':
                    result.recommended_action
            }

        return {
            'found': False,
            'indicator': indicator,
            'indicator_type': indicator_type,
            'threat_type': 'Unknown',
            'severity': 'LOW',
            'confidence': 0,
            'source': 'Local Intelligence Feed',
            'description': 'No intelligence match found.',
            'recommended_action': 'Monitor indicator.'
        }

    def analyze_log(self, raw_data):

        indicators = self.extract_indicators(
            raw_data
        )

        results = []

        for item in indicators:

            result = self.check_indicator(
                item['indicator'],
                item['indicator_type']
            )

            results.append(result)

        return results