"""Deterministic mock connectors used for tests, demos, and offline mode."""

from __future__ import annotations

import uuid
from typing import Any, Optional

from .base import (
    ConnectorResult, EDRConnector, ITSMConnector, SIEMConnector,
    SOARConnector, TIConnector,
)
from .registry import register


@register
class MockSIEM(SIEMConnector):
    name = "mock"

    def check_connection(self) -> ConnectorResult:
        return ConnectorResult(success=True, message="mock SIEM ready")

    def search(self, query: str, *, limit: int = 100) -> ConnectorResult:
        return ConnectorResult(success=True, message=f"matched 0 rows for '{query[:40]}'",
                               data={"events": [], "query": query, "limit": limit})

    def push_alert(self, alert: dict[str, Any]) -> ConnectorResult:
        return ConnectorResult(success=True, message="alert accepted",
                               data={"alert_id": alert.get("alert_id", "mock-1")})


@register
class MockSOAR(SOARConnector):
    name = "mock"

    def check_connection(self) -> ConnectorResult:
        return ConnectorResult(success=True, message="mock SOAR ready")

    def create_case(self, *, title: str, description: str = "",
                    severity: str = "medium",
                    tags: Optional[list[str]] = None) -> ConnectorResult:
        cid = f"MOCK-CASE-{uuid.uuid4().hex[:6].upper()}"
        return ConnectorResult(success=True, message="case created",
                               data={"case_id": cid, "title": title,
                                     "severity": severity, "tags": tags or []})

    def add_observable(self, case_id: str, *, data_type: str,
                       data: str) -> ConnectorResult:
        return ConnectorResult(success=True, message="observable added",
                               data={"case_id": case_id, "data_type": data_type,
                                     "data": data})

    def add_task(self, case_id: str, *, title: str,
                 description: str = "") -> ConnectorResult:
        return ConnectorResult(success=True, message="task created",
                               data={"case_id": case_id, "title": title})


@register
class MockEDR(EDRConnector):
    name = "mock"

    def check_connection(self) -> ConnectorResult:
        return ConnectorResult(success=True, message="mock EDR ready")

    def isolate_host(self, host_id: str, *, reason: str) -> ConnectorResult:
        return ConnectorResult(success=True, message="host isolated",
                               data={"host_id": host_id, "reason": reason})

    def hunt(self, query: str) -> ConnectorResult:
        return ConnectorResult(success=True, message="hunt completed",
                               data={"query": query, "matches": 0})


@register
class MockITSM(ITSMConnector):
    name = "mock"

    def check_connection(self) -> ConnectorResult:
        return ConnectorResult(success=True, message="mock ITSM ready")

    def create_ticket(self, *, summary: str, description: str = "",
                      priority: str = "medium",
                      labels: Optional[list[str]] = None) -> ConnectorResult:
        tid = f"MOCK-TKT-{uuid.uuid4().hex[:6].upper()}"
        return ConnectorResult(success=True, message="ticket created",
                               data={"ticket_id": tid, "summary": summary,
                                     "priority": priority, "labels": labels or []})


@register
class MockTI(TIConnector):
    name = "mock"

    def check_connection(self) -> ConnectorResult:
        return ConnectorResult(success=True, message="mock TI ready")

    def lookup(self, indicator: str, *,
               indicator_type: Optional[str] = None) -> ConnectorResult:
        # Deterministic: anything containing 'evil' is malicious in the mock TI.
        is_malicious = "evil" in indicator.lower()
        return ConnectorResult(success=True, message="lookup completed",
                               data={"indicator": indicator,
                                     "type": indicator_type,
                                     "malicious": is_malicious,
                                     "score": 95 if is_malicious else 5})
