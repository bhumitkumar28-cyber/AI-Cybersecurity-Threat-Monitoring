"""
ASGI config for config project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/6.0/howto/deployment/asgi/
"""

import os

from django.core.asgi import get_asgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

application = get_asgi_application()
import os
from django.core.asgi import get_asgi_application
from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter
import threat_monitor.routing

os.environ.setdefault(
    'DJANGO_SETTINGS_MODULE',
    'cybersecurity_dashboard.settings'
)

application = ProtocolTypeRouter({
    'http': get_asgi_application(),

    'websocket': AuthMiddlewareStack(
        URLRouter(
            threat_monitor.routing.websocket_urlpatterns
        )
    ),
})