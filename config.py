"""
VAJRA-X Configuration Management
"""

import os
import re
import secrets
from pathlib import Path
from dotenv import load_dotenv
from typing import Optional

ENV_FILE = Path(__file__).parent / '.env'

if ENV_FILE.exists():
    load_dotenv(ENV_FILE)


class Config:
    @staticmethod
    def _looks_like_placeholder(value: Optional[str]) -> bool:
        if not value:
            return True
        normalized = value.strip().lower()
        placeholder_tokens = (
            'change-me', 'changeme', 'replace-me', 'your-secret', 'your_secret',
            'placeholder', 'example', 'dev-key-change-in-production', 'test-secret-key'
        )
        return any(token in normalized for token in placeholder_tokens)

    @staticmethod
    def _has_strong_password(value: Optional[str]) -> bool:
        if not value:
            return False
        return (
            len(value) >= 12
            and re.search(r'[A-Z]', value) is not None
            and re.search(r'[a-z]', value) is not None
            and re.search(r'\d', value) is not None
            and re.search(r'[^A-Za-z0-9]', value) is not None
        )

    # Flask
    FLASK_ENV: str = os.getenv('FLASK_ENV', 'development')

    DEBUG: bool = os.getenv('DEBUG', 'True').lower() == 'true'

    # Bug #13: Never fall back to a predictable hardcoded secret.
    # In development, auto-generate a random key. In production, MUST be set via env.
    SECRET_KEY: str = os.getenv('SECRET_KEY') or secrets.token_hex(32)

    # Database
    DATABASE_PATH: Path = Path(__file__).parent / 'database' / 'vajrax.db'

    DATABASE_URL: str = os.getenv(
        'DATABASE_URL',
        f'sqlite:///{DATABASE_PATH}'
    )

    SQLALCHEMY_DATABASE_URI = DATABASE_URL
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Session Security
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    # Bug #20: Overridden to True in ProductionConfig
    SESSION_COOKIE_SECURE = False

    # Server
    HOST: str = os.getenv('HOST', '127.0.0.1')
    PORT: int = int(os.getenv('PORT', 5000))
    WORKERS: int = int(os.getenv('WORKERS', 1))

    # JWT
    JWT_SECRET_KEY: str = os.getenv('JWT_SECRET_KEY') or secrets.token_hex(32)
    JWT_ACCESS_TOKEN_EXPIRES: int = int(os.getenv('JWT_ACCESS_TOKEN_EXPIRES', 3600))

    # Uploads
    UPLOAD_FOLDER: Path = Path(__file__).parent / 'static' / 'uploads'
    PROCESSED_FOLDER: Path = Path(__file__).parent / 'static' / 'processed'
    MAX_CONTENT_LENGTH: int = int(os.getenv('MAX_UPLOAD_SIZE', 104857600))  # 100 MB

    # AI
    YOLO_MODEL: str = os.getenv('YOLO_MODEL', 'yolov8n.pt')
    YOLO_CONFIDENCE_THRESHOLD: float = float(os.getenv('YOLO_CONFIDENCE_THRESHOLD', 0.45))
    YOLO_IOU_THRESHOLD: float = float(os.getenv('YOLO_IOU_THRESHOLD', 0.45))

    # Logging
    LOG_LEVEL: str = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FILE: str = os.getenv('LOG_FILE', 'logs/vajrax.log')

    # Redis
    REDIS_ENABLED: bool = os.getenv('REDIS_ENABLED', 'False').lower() == 'true'
    REDIS_URL: str = os.getenv('REDIS_URL', 'redis://localhost:6379/0')

    # APIs
    OPENWEATHER_API_KEY: Optional[str] = os.getenv('OPENWEATHER_API_KEY')
    GOOGLE_MAPS_API_KEY: Optional[str] = os.getenv('GOOGLE_MAPS_API_KEY')
    GROQ_API_KEY: Optional[str] = os.getenv('GROQ_API_KEY')

    # Default Admin Credentials
    ADMIN_USERNAME: str = os.getenv('ADMIN_USERNAME', 'mehak')
    ADMIN_PASSWORD: str = os.getenv('ADMIN_PASSWORD', 'ChangeMe@2024!')

    @classmethod
    def warn_if_default_admin_credentials(cls):
        if cls.ADMIN_PASSWORD == 'ChangeMe@2024!' or cls._looks_like_placeholder(cls.ADMIN_PASSWORD):
            print("WARNING: ADMIN_PASSWORD is still using the default value. Set a strong password in .env before deployment.")

    # Bug #22: Include both common dev ports in default CORS origins
    CORS_ALLOWED_ORIGINS: str = os.getenv(
        'CORS_ALLOWED_ORIGINS',
        'http://localhost:3000,http://localhost:5000,http://127.0.0.1:5000'
    )

    # Deployment
    DEPLOYMENT_ENV: str = os.getenv('DEPLOYMENT_ENV', 'development')

    # Rate limiting
    RATELIMIT_DEFAULT: str = os.getenv('RATELIMIT_DEFAULT', '200 per minute')
    RATELIMIT_STORAGE_URL: str = os.getenv('RATELIMIT_STORAGE_URL', 'memory://')

    @staticmethod
    def ensure_directories():
        Config.UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
        Config.PROCESSED_FOLDER.mkdir(parents=True, exist_ok=True)
        Path(Config.LOG_FILE).parent.mkdir(parents=True, exist_ok=True)


class DevelopmentConfig(Config):
    DEBUG = True
    TESTING = False


class ProductionConfig(Config):
    DEBUG = False
    TESTING = False

    # Bug #20: Enforce secure cookies in production
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_SAMESITE = "Strict"

    # Bug #13: Production MUST have explicit SECRET_KEY — raise early if missing
    @classmethod
    def validate(cls):
        secret_key = os.getenv('SECRET_KEY')
        jwt_secret_key = os.getenv('JWT_SECRET_KEY')
        admin_username = os.getenv('ADMIN_USERNAME')
        admin_password = os.getenv('ADMIN_PASSWORD')

        if not secret_key or cls._looks_like_placeholder(secret_key):
            raise RuntimeError(
                "FATAL: SECRET_KEY environment variable must be set to a non-placeholder value in production!"
            )
        if not jwt_secret_key or cls._looks_like_placeholder(jwt_secret_key):
            raise RuntimeError(
                "FATAL: JWT_SECRET_KEY environment variable must be set to a non-placeholder value in production!"
            )
        if not admin_username or cls._looks_like_placeholder(admin_username):
            raise RuntimeError(
                "FATAL: ADMIN_USERNAME must be set to a non-placeholder value in production!"
            )
        if not cls._has_strong_password(admin_password):
            raise RuntimeError(
                "FATAL: ADMIN_PASSWORD must be at least 12 characters and include upper/lower/number/special characters!"
            )


class TestingConfig(Config):
    DEBUG = True
    TESTING = True
    DATABASE_URL = 'sqlite:///:memory:'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False


def get_config():
    env = os.getenv('FLASK_ENV', 'development')

    if env == 'production':
        cfg = ProductionConfig()
        cfg.validate()
        return cfg

    elif env == 'testing':
        return TestingConfig()

    return DevelopmentConfig()