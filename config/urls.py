from django.contrib import admin
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

from threat_monitor.api_views import (
    SecurityLogViewSet,
    DetectedThreatViewSet,
    AlertRuleViewSet,
    ThreatPredictionViewSet,
)
router = DefaultRouter()
router.register('logs', SecurityLogViewSet, basename='logs')
router.register('threats', DetectedThreatViewSet, basename='threats')
router.register('alert-rules', AlertRuleViewSet, basename='alert-rules')
router.register(
    'threat-prediction',
    ThreatPredictionViewSet,
    basename='threat-prediction'
)
urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('threat_monitor.urls')),

    path('api/', include(router.urls)),

    path('api/schema/', SpectacularAPIView.as_view(), name='api-schema'),

    path(
        'api/docs/',
        SpectacularSwaggerView.as_view(url_name='api-schema'),
        name='swagger-ui'
    ),
]