from django.urls import path
from . import views
from .views import calculate_risk
from .api_views import ThreatPredictionViewSet
urlpatterns = [
    
    path('', views.dashboard_view, name='dashboard'),
    path('login/', views.login_view, name='login'),
    path('register/', views.register_view, name='register'),
    path('logout/', views.logout_view, name='logout'),
    path('upload/', views.upload_logs_view, name='upload_logs'),
    path('logs/<int:log_id>/', views.log_details_view, name='log_details'),
    path('threats/<int:threat_id>/', views.threat_details_view, name='threat_details'),
    path('search/', views.search_logs_view, name='search_logs'),
    path('filter-threats/', views.filter_threats_view, name='filter_threats'),
    path('api/threat-distribution/', views.api_threat_distribution, name='api_threat_distribution'),
    path('api/recent-threats/', views.api_recent_threats, name='api_recent_threats'),
    path('api/logs-summary/', views.api_logs_summary, name='api_logs_summary'),
    path('api/anomaly-stats/', views.api_anomaly_stats, name='api_anomaly_stats'),
    path('sample-data/', views.sample_logs_view, name='sample_logs'),
    path(
    'api/threat-trends/',
    views.api_threat_trends,
    name='api_threat_trends'
    ),

    path(
       'reports/export-threats/',
        views.export_threat_report,
        name='export_threat_report'
    ),
    path(
    "risk/calculate/",
    calculate_risk,
    name="calculate-risk"
),

path(
    'api/threat-prediction/predict/',
    ThreatPredictionViewSet.as_view({
        'post': 'predict'
    }),
    name='threat_prediction'
),  
path(
    'threat-intelligence/',
    views.threat_intelligence_view,
    name='threat_intelligence'
),

path(
    'api/threat-intelligence/check/',
    views.api_threat_intelligence,
    name='api_threat_intelligence'
),
path("incidents/", views.incident_list_view, name="incident_list"),
path("incidents/<int:incident_id>/", views.incident_detail_view, name="incident_detail"),
path("review-queue/", views.review_queue_view, name="review_queue"),
path("model-performance/", views.model_performance_view, name="model_performance"),
]
