"""Stubs for real enterprise connectors.

Each stub is registered so `list_connectors()` advertises it as
"implemented: false" while the real REST integration is being built.
Calling any operation raises NotImplementedError with a clear hint.
"""

from __future__ import annotations

from typing import Any, Optional

from .base import (
    ConnectorResult, EDRConnector, ITSMConnector, SIEMConnector,
    SOARConnector, TIConnector,
)
from .registry import register


def _todo(name: str):
    raise NotImplementedError(
        f"Connector '{name}' is registered as a stub. Provide an "
        f"implementation by subclassing the kind interface and registering "
        f"it via @register before use."
    )


# ---- SIEM stubs ------------------------------------------------------------

@register
class SplunkSIEM(SIEMConnector):
    name = "splunk"
    _is_stub = True

    def check_connection(self) -> ConnectorResult:
        _todo(self.name)
    def search(self, query: str, *, limit: int = 100) -> ConnectorResult:
        _todo(self.name)
    def push_alert(self, alert: dict[str, Any]) -> ConnectorResult:
        _todo(self.name)


@register
class SentinelSIEM(SIEMConnector):
    name = "sentinel"
    _is_stub = True

    def check_connection(self) -> ConnectorResult:
        _todo(self.name)
    def search(self, query: str, *, limit: int = 100) -> ConnectorResult:
        _todo(self.name)
    def push_alert(self, alert: dict[str, Any]) -> ConnectorResult:
        _todo(self.name)


@register
class ElasticSIEM(SIEMConnector):
    name = "elastic"
    _is_stub = True

    def check_connection(self) -> ConnectorResult:
        _todo(self.name)
    def search(self, query: str, *, limit: int = 100) -> ConnectorResult:
        _todo(self.name)
    def push_alert(self, alert: dict[str, Any]) -> ConnectorResult:
        _todo(self.name)


# ---- SOAR stubs ------------------------------------------------------------

@register
class TheHiveSOAR(SOARConnector):
    """Thin shim that routes to backend.soar.thehive when used in production.

    Today registered as a stub so the registry is uniform; the existing
    backend.soar.TheHiveClient remains the canonical implementation.
    """
    name = "thehive"
    _is_stub = True

    def check_connection(self) -> ConnectorResult:
        _todo(self.name)
    def create_case(self, **kw): _todo(self.name)
    def add_observable(self, *a, **kw): _todo(self.name)
    def add_task(self, *a, **kw): _todo(self.name)


# ---- EDR / ITSM / TI stubs ------------------------------------------------

@register
class DefenderEDR(EDRConnector):
    name = "defender"
    _is_stub = True
    def check_connection(self) -> ConnectorResult: _todo(self.name)
    def isolate_host(self, *a, **kw): _todo(self.name)
    def hunt(self, *a, **kw): _todo(self.name)


@register
class CrowdStrikeEDR(EDRConnector):
    name = "crowdstrike"
    _is_stub = True
    def check_connection(self) -> ConnectorResult: _todo(self.name)
    def isolate_host(self, *a, **kw): _todo(self.name)
    def hunt(self, *a, **kw): _todo(self.name)


@register
class JiraITSM(ITSMConnector):
    name = "jira"
    _is_stub = True
    def check_connection(self) -> ConnectorResult: _todo(self.name)
    def create_ticket(self, **kw): _todo(self.name)


@register
class ServiceNowITSM(ITSMConnector):
    name = "servicenow"
    _is_stub = True
    def check_connection(self) -> ConnectorResult: _todo(self.name)
    def create_ticket(self, **kw): _todo(self.name)


@register
class MISPTIConnector(TIConnector):
    name = "misp"
    _is_stub = True
    def check_connection(self) -> ConnectorResult: _todo(self.name)
    def lookup(self, *a, **kw): _todo(self.name)


@register
class OpenCTITIConnector(TIConnector):
    name = "opencti"
    _is_stub = True
    def check_connection(self) -> ConnectorResult: _todo(self.name)
    def lookup(self, *a, **kw): _todo(self.name)
