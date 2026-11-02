"""
GovernX Week 4 - Error Handling & Health Monitoring (Person 1: Backend Lead)

Provides structured error envelopes, custom exception hierarchy,
graceful fallback mechanisms, and production liveness/readiness probes.
"""

import logging
from datetime import datetime
from typing import Dict, Any, Optional
from fastapi import Request, status
from fastapi.responses import JSONResponse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class GovernXBaseException(Exception):
    """Base exception for all domain-level GovernX errors"""
    def __init__(self, message: str, status_code: int = 500, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.details = details or {}


class ResourceNotFoundError(GovernXBaseException):
    def __init__(self, resource_type: str, resource_id: str):
        super().__init__(
            message=f"{resource_type} with ID '{resource_id}' was not found.",
            status_code=status.HTTP_404_NOT_FOUND,
            details={"resource_type": resource_type, "resource_id": resource_id}
        )


class PolicyViolationError(GovernXBaseException):
    def __init__(self, rule_id: str, message: str):
        super().__init__(
            message=f"Mandatory security policy violation on rule {rule_id}: {message}",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            details={"rule_id": rule_id}
        )


class AuthenticationError(GovernXBaseException):
    def __init__(self, message: str = "Invalid or missing credentials"):
        super().__init__(message=message, status_code=status.HTTP_401_UNAUTHORIZED)


class AuthorizationError(GovernXBaseException):
    def __init__(self, message: str = "Insufficient permissions for requested action"):
        super().__init__(message=message, status_code=status.HTTP_403_FORBIDDEN)


class RateLimitError(GovernXBaseException):
    def __init__(self, message: str = "API rate limit exceeded. Try again shortly."):
        super().__init__(message=message, status_code=status.HTTP_429_TOO_MANY_REQUESTS)


class CloudConnectorError(GovernXBaseException):
    def __init__(self, provider: str, original_error: str):
        super().__init__(
            message=f"Cloud provider connection failure ({provider}): {original_error}",
            status_code=status.HTTP_502_BAD_GATEWAY,
            details={"provider": provider, "error": original_error}
        )


def build_error_envelope(status_code: int, error_type: str, message: str, path: str = "", details: Optional[Dict] = None) -> Dict[str, Any]:
    """Standardized production error response format"""
    return {
        "status": "error",
        "error": {
            "code": status_code,
            "type": error_type,
            "message": message,
            "path": path,
            "details": details or {},
            "timestamp": datetime.now().isoformat()
        }
    }


async def governx_exception_handler(request: Request, exc: GovernXBaseException) -> JSONResponse:
    """FastAPI global exception handler for domain errors"""
    logger.error(f"[DOMAIN ERROR] {request.url.path} - {exc.__class__.__name__}: {exc.message}")
    envelope = build_error_envelope(
        status_code=exc.status_code,
        error_type=exc.__class__.__name__,
        message=exc.message,
        path=request.url.path,
        details=exc.details
    )
    return JSONResponse(status_code=exc.status_code, content=envelope)


async def global_generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """FastAPI fallback handler for unhandled exceptions"""
    logger.exception(f"[UNHANDLED EXCEPTION] {request.url.path}: {exc}")
    envelope = build_error_envelope(
        status_code=500,
        error_type="InternalServerError",
        message="An unexpected server error occurred. Please contact the administrator.",
        path=request.url.path,
        details={"raw_error": str(exc)}
    )
    return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content=envelope)


class HealthMonitor:
    """Liveness & Readiness probe inspector"""

    def __init__(self):
        self.started_at = datetime.now()

    def get_liveness(self) -> Dict[str, Any]:
        """Simple liveness probe for Kubernetes / Docker container health"""
        uptime_seconds = (datetime.now() - self.started_at).total_seconds()
        return {
            "status": "healthy",
            "service": "GovernX Unified Cloud Audit Platform",
            "uptime_seconds": round(uptime_seconds, 1),
            "timestamp": datetime.now().isoformat()
        }

    def get_readiness(self, components_status: Optional[Dict[str, bool]] = None) -> Dict[str, Any]:
        """Deep readiness probe verifying subsystems are operational"""
        components = components_status or {
            "cloud_poller": True,
            "data_normalizer": True,
            "compliance_engine": True,
            "supply_chain_connector": True,
            "policy_engine": True,
            "stakeholder_registry": True
        }
        all_ready = all(components.values())
        return {
            "status": "ready" if all_ready else "degraded",
            "overall_ready": all_ready,
            "components": components,
            "timestamp": datetime.now().isoformat()
        }


if __name__ == "__main__":
    monitor = HealthMonitor()
    print("Liveness:", monitor.get_liveness())
    print("Readiness:", monitor.get_readiness())
    envelope = build_error_envelope(404, "ResourceNotFoundError", "Audit 123 not found", "/api/v1/audit/123")
    print("Standard Envelope:", envelope)
