"""
GovernX Week 4 - Deployment & Configuration Management (Person 1: Backend Lead)

Environment configuration loader, secrets management, CORS security settings,
and deployment profile specifications for local, staging, and production clusters.
"""

import os
import json
import logging
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class AppConfig:
    """Master application configuration parameters"""
    app_name: str = "GovernX Cloud Compliance & Governance Platform"
    app_version: str = "1.0.0"
    environment: str = "development"          # 'development', 'staging', 'production'
    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = True
    api_key_enforced: bool = False             # Set to True in production
    jwt_secret_key: str = "governx-secret-production-key-2026"
    jwt_expiry_minutes: int = 60
    cache_ttl_seconds: int = 300
    rate_limit_per_minute: int = 120
    default_aws_region: str = "us-east-1"
    cors_origins: List[str] = None
    data_cache_dir: str = "./.cache"

    def __post_init__(self):
        # Override with environment variables if present
        self.app_name = os.getenv("GOVERNX_APP_NAME", self.app_name)
        self.app_version = os.getenv("GOVERNX_APP_VERSION", self.app_version)
        self.environment = os.getenv("GOVERNX_ENV", self.environment).lower()
        self.host = os.getenv("GOVERNX_HOST", self.host)
        self.port = int(os.getenv("GOVERNX_PORT", str(self.port)))
        self.debug = os.getenv("GOVERNX_DEBUG", str(self.debug)).lower() in ("true", "1", "yes")
        self.api_key_enforced = os.getenv("GOVERNX_ENFORCE_AUTH", str(self.api_key_enforced)).lower() in ("true", "1", "yes")
        self.jwt_secret_key = os.getenv("GOVERNX_JWT_SECRET", self.jwt_secret_key)
        self.cache_ttl_seconds = int(os.getenv("GOVERNX_CACHE_TTL", str(self.cache_ttl_seconds)))
        self.rate_limit_per_minute = int(os.getenv("GOVERNX_RATE_LIMIT", str(self.rate_limit_per_minute)))
        self.default_aws_region = os.getenv("AWS_DEFAULT_REGION", self.default_aws_region)

        if self.cors_origins is None:
            cors_raw = os.getenv("GOVERNX_CORS_ORIGINS", "")
            if cors_raw:
                self.cors_origins = [o.strip() for o in cors_raw.split(",") if o.strip()]
            else:
                self.cors_origins = [
                    "http://localhost:3000",
                    "http://localhost:5173",
                    "http://127.0.0.1:3000",
                    "http://127.0.0.1:8000"
                ]

    def get_safe_summary(self) -> Dict[str, Any]:
        """Return non-sensitive configuration parameters for logging and diagnostics"""
        data = asdict(self)
        data["jwt_secret_key"] = "********"
        return data


def load_deployment_config() -> AppConfig:
    """Factory function for initializing runtime configuration"""
    config = AppConfig()
    logger.info(f"Loaded GovernX configuration: env={config.environment}, debug={config.debug}, port={config.port}")
    return config


if __name__ == "__main__":
    cfg = load_deployment_config()
    print("\n[DEPLOYMENT CONFIG] Active Configuration:")
    for k, v in cfg.get_safe_summary().items():
        print(f"  {k:<25}: {v}")
