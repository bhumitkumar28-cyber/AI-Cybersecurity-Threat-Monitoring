from django.core.management.base import BaseCommand

from threat_monitor.models import ThreatIntelligence


class Command(BaseCommand):

    help = 'Create demo Threat Intelligence indicators'

    def handle(self, *args, **kwargs):

        indicators = [

            {
                'indicator': '45.33.32.156',
                'indicator_type': 'IP',
                'threat_type': 'Suspicious Activity',
                'severity': 'HIGH',
                'confidence': 85,
                'source': 'Demo Intelligence Feed',
                'description':
                    'This indicator is included in the project demo dataset for suspicious network activity.',
                'recommended_action':
                    'Monitor the IP and investigate repeated authentication or network events.'
            },

            {
                'indicator': 'xzqjklmno.pwn.com',
                'indicator_type': 'DOMAIN',
                'threat_type': 'Suspicious Domain',
                'severity': 'HIGH',
                'confidence': 80,
                'source': 'Demo Intelligence Feed',
                'description':
                    'Demo suspicious domain extracted from network security sample logs.',
                'recommended_action':
                    'Investigate DNS activity and block only after verification.'
            },

        ]


        for data in indicators:

            ThreatIntelligence.objects.update_or_create(

                indicator=data['indicator'],

                indicator_type=data['indicator_type'],

                defaults={
                    'threat_type':
                        data['threat_type'],

                    'severity':
                        data['severity'],

                    'confidence':
                        data['confidence'],

                    'source':
                        data['source'],

                    'description':
                        data['description'],

                    'recommended_action':
                        data['recommended_action'],

                    'is_active':
                        True,
                }
            )


        self.stdout.write(
            self.style.SUCCESS(
                'Threat Intelligence demo data created successfully.'
            )
        )