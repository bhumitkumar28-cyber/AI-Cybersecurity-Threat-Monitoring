from django.urls import path

from .consumers import ThreatConsumer


websocket_urlpatterns = [
    path('ws/threats/', ThreatConsumer.as_asgi()),
]