"""
CyberTwin SOC - Enterprise Connectors (Phase 5)
=================================================
Pluggable, abstract interfaces for SIEM / SOAR / EDR / ITSM / TI providers.

Today this module ships:

  - `BaseConnector`               common contract
  - Five "Connector" interfaces   one per category (SIEM/SOAR/EDR/ITSM/TI)
  - Concrete `MockConnector`      offline-friendly, deterministic
  - Stubs (raise NotImplementedError) for Splunk / Sentinel / Elastic /
    Jira / MISP / OpenCTI - so the registry is shipped wired and ready
    to be filled with real API calls when credentials are available.

The registry exposes `get_connector(kind, name)` so endpoints can route
operations to the right backend without coupling to its implementation.
"""

from .base import (
    BaseConnector, SIEMConnector, SOARConnector, EDRConnector,
    ITSMConnector, TIConnector, ConnectorError, ConnectorResult,
)
from .registry import register, get_connector, list_connectors
from . import mock, stubs   # populate the registry on import

__all__ = [
    "BaseConnector", "SIEMConnector", "SOARConnector", "EDRConnector",
    "ITSMConnector", "TIConnector", "ConnectorError", "ConnectorResult",
    "register", "get_connector", "list_connectors",
]
