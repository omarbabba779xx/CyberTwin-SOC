"""CyberTwin SOC — Custom middleware package."""

from .tenant import TenantScopeMiddleware

__all__ = ["TenantScopeMiddleware"]
