"""
CyberTwin SOC - Enterprise Connectors (Phase 5)
=================================================
Pluggable, abstract interfaces for SIEM / SOAR / EDR / ITSM / TI providers.

Today this module ships:

  - `BaseConnector`               common contract
  - Five "Connector" interfaces   one per category (SIEM/SOAR/EDR/ITSM/TI)
  - Concrete `MockConnector`      offline-friendly, deterministic
  - Production integrations: Splunk, TheHive, **Sentinel, Jira, MISP**
  - Remaining stubs (Elastic / OpenCTI / …) raising until implemented
    to be filled with real API calls when credentials are available.

The registry exposes `get_connector(kind, name)` so endpoints can route
operations to the right backend without coupling to its implementation.
"""

from .base import (
    BaseConnector, SIEMConnector, SOARConnector, EDRConnector,
    ITSMConnector, TIConnector, ConnectorError, ConnectorResult,
)
from .registry import register, get_connector, list_connectors
from . import mock, stubs   # noqa: F401  -- side-effect: populate registry
from . import thehive, splunk   # noqa: F401  -- register SIEM/SOAR
from . import sentinel, jira, misp   # noqa: F401  -- Sentinel / Jira / MISP

__all__ = [
    "BaseConnector", "SIEMConnector", "SOARConnector", "EDRConnector",
    "ITSMConnector", "TIConnector", "ConnectorError", "ConnectorResult",
    "register", "get_connector", "list_connectors",
]
