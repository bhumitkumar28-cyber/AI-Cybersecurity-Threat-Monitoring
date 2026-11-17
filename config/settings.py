"""
Django settings for cybersecurity_dashboard project.
"""

import os
from pathlib import Path


# Base directory:
# backend/config/settings.py → backend/
BASE_DIR = Path(__file__).resolve().parent.parent


# Development-only secret key.
# Production mein isse .env file se load karna chahiye.
SECRET_KEY = os.getenv('SECRET_KEY', 'django-insecure-local-dev-key')

DEBUG = os.getenv('DEBUG', 'False') == 'True'

ALLOWED_HOSTS = os.getenv(
    'ALLOWED_HOSTS',
    'localhost,127.0.0.1'
).split(',')
CSRF_TRUSTED_ORIGINS = os.getenv(
    'CSRF_TRUSTED_ORIGINS', ''
).split(',') if os.getenv('CSRF_TRUSTED_ORIGINS') else []

# Application definition
INSTALLED_APPS = [
    # Daphne should be before django.contrib.staticfiles
    'daphne',

    # Django default apps
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    # Third-party apps
    'rest_framework',
    'drf_spectacular',
    'django_filters',
    'channels',

    # Local app
    'threat_monitor',
]


MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]


# Main URL file
ROOT_URLCONF = 'config.urls'


# Template configuration
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]


# Traditional WSGI entry point
WSGI_APPLICATION = 'config.wsgi.application'


# ASGI entry point for WebSocket / Django Channels
ASGI_APPLICATION = 'config.asgi.application'


# Database
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': Path(
            os.getenv('SQLITE_PATH', str(BASE_DIR / 'db.sqlite3'))
        ),
    }
}


# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': (
            'django.contrib.auth.password_validation.'
            'UserAttributeSimilarityValidator'
        ),
    },
    {
        'NAME': (
            'django.contrib.auth.password_validation.'
            'MinimumLengthValidator'
        ),
    },
    {
        'NAME': (
            'django.contrib.auth.password_validation.'
            'CommonPasswordValidator'
        ),
    },
    {
        'NAME': (
            'django.contrib.auth.password_validation.'
            'NumericPasswordValidator'
        ),
    },
]


# Internationalization
LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files
STATIC_URL = 'static/'

STATICFILES_DIRS = [
    BASE_DIR / 'threat_monitor' / 'static',
]

STATIC_ROOT = BASE_DIR / 'staticfiles'


# Media files
MEDIA_URL = '/media/'

MEDIA_ROOT = BASE_DIR / 'media'


# Default primary key
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


# Login URLs
LOGIN_URL = '/login/'

LOGIN_REDIRECT_URL = '/'

LOGOUT_REDIRECT_URL = '/login/'


# Security headers
SECURE_CONTENT_TYPE_NOSNIFF = True


# ----------------------------------------------------
# Django Channels / WebSocket configuration
# ----------------------------------------------------

# Local development aur testing ke liye.
# Iske liye Redis/Docker install karne ki need nahi hai.
CHANNEL_LAYERS = {
    'default': {
        'BACKEND': 'channels.layers.InMemoryChannelLayer',
    },
}


# ----------------------------------------------------
# Django REST Framework and Swagger / OpenAPI
# ----------------------------------------------------

REST_FRAMEWORK = {
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema',
    'DEFAULT_FILTER_BACKENDS': [
        'django_filters.rest_framework.DjangoFilterBackend',
    ],
}


SPECTACULAR_SETTINGS = {
    'TITLE': 'Cybersecurity Threat Monitoring API',
    'DESCRIPTION': (
        'REST API for uploading security logs, viewing detected threats, '
        'historical analytics, and user alert rules.'
    ),
    'VERSION': '1.0.0',
    'SERVE_INCLUDE_SCHEMA': False,
}


# ----------------------------------------------------
# Email settings
# ----------------------------------------------------

EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'

EMAIL_HOST = os.getenv('EMAIL_HOST', 'smtp.gmail.com')

EMAIL_PORT = int(os.getenv('EMAIL_PORT', 587))

EMAIL_USE_TLS = True

EMAIL_HOST_USER = os.getenv('EMAIL_HOST_USER')

EMAIL_HOST_PASSWORD = os.getenv('EMAIL_HOST_PASSWORD')

DEFAULT_FROM_EMAIL = os.getenv(
    'DEFAULT_FROM_EMAIL',
    EMAIL_HOST_USER
)