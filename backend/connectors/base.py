"""Abstract connector contracts."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional


class ConnectorError(Exception):
    """Raised by connector implementations on integration failures."""


@dataclass
class ConnectorResult:
    """Generic, JSON-serialisable connector response."""
    success: bool
    message: str = ""
    data: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------

class BaseConnector(ABC):
    """All connectors implement at minimum a connection check + describe()."""

    name: str = "base"
    kind: str = "unknown"   # siem | soar | edr | itsm | ti

    def __init__(self, **config: Any) -> None:
        self.config = config
        self._init_circuit_breaker()

    def _init_circuit_breaker(self) -> None:
        from .resilience import CircuitBreaker
        self._circuit_breaker = CircuitBreaker(name=f"{self.kind}/{self.name}")

    def describe(self) -> dict[str, Any]:
        return {"name": self.name, "kind": self.kind,
                "config_keys": sorted(self.config.keys())}

    @abstractmethod
    def check_connection(self) -> ConnectorResult: ...

    def health(self) -> ConnectorResult:
        """Run ``check_connection`` through the circuit breaker."""
        return self._circuit_breaker.call(self.check_connection)


# ---------------------------------------------------------------------------
# Per-kind interfaces
# ---------------------------------------------------------------------------

class SIEMConnector(BaseConnector):
    kind = "siem"

    @abstractmethod
    def search(self, query: str, *, limit: int = 100) -> ConnectorResult: ...

    @abstractmethod
    def push_alert(self, alert: dict[str, Any]) -> ConnectorResult: ...


class SOARConnector(BaseConnector):
    kind = "soar"

    @abstractmethod
    def create_case(self, *, title: str, description: str = "",
                    severity: str = "medium",
                    tags: Optional[list[str]] = None) -> ConnectorResult: ...

    @abstractmethod
    def add_observable(self, case_id: str, *, data_type: str,
                       data: str) -> ConnectorResult: ...

    @abstractmethod
    def add_task(self, case_id: str, *, title: str,
                 description: str = "") -> ConnectorResult: ...


class EDRConnector(BaseConnector):
    kind = "edr"

    @abstractmethod
    def isolate_host(self, host_id: str, *, reason: str) -> ConnectorResult: ...

    @abstractmethod
    def hunt(self, query: str) -> ConnectorResult: ...


class ITSMConnector(BaseConnector):
    kind = "itsm"

    @abstractmethod
    def create_ticket(self, *, summary: str, description: str = "",
                      priority: str = "medium",
                      labels: Optional[list[str]] = None) -> ConnectorResult: ...


class TIConnector(BaseConnector):
    kind = "ti"

    @abstractmethod
    def lookup(self, indicator: str, *,
               indicator_type: Optional[str] = None) -> ConnectorResult: ...
