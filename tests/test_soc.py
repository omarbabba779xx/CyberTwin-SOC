"""Tests for the SOC operational module (Phase 3): feedback, cases, suppressions."""

from __future__ import annotations

import pytest
from datetime import datetime, timedelta, timezone


# ---------------------------------------------------------------------------
# Module-scoped fixture: clean SOC tables before this file runs.
# (Tables are shared with the rest of the suite; we reset only the rows we
# create to avoid coupling to other tests.)
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _reset_soc_tables():
    from backend.soc.database import init_soc_tables, get_conn
    init_soc_tables()
    conn = get_conn()
    for tbl in ("alert_feedback", "case_comments", "case_evidence",
                "soc_cases", "suppressions"):
        conn.execute(f"DELETE FROM {tbl}")
    conn.commit()
    conn.close()
    yield


# ---------------------------------------------------------------------------
# 3.1 Alert feedback
# ---------------------------------------------------------------------------

class TestFeedback:

    def test_record_and_list(self):
        from backend.soc import record_feedback, list_feedback
        fb = record_feedback(
            alert_id="ALR-1", rule_id="RULE-001",
            verdict="false_positive", reason="benign script",
            analyst="alice", role="analyst",
        )
        assert fb.feedback_id > 0
        rows = list_feedback(alert_id="ALR-1")
        assert len(rows) == 1
        assert rows[0].verdict == "false_positive"

    def test_invalid_verdict_raises(self):
        from backend.soc import record_feedback
        with pytest.raises(ValueError):
            record_feedback(alert_id="A", rule_id="R", verdict="bogus",
                            analyst="x", role="analyst")

    def test_summary_aggregates(self):
        from backend.soc import record_feedback, feedback_summary
        for verdict in ("true_positive", "true_positive", "false_positive"):
            record_feedback(alert_id=f"A-{verdict}-{id(verdict)}",
                            rule_id="R", verdict=verdict,
                            analyst="a", role="analyst")
        s = feedback_summary()
        assert s["total_feedback"] == 3
        assert s["by_verdict"]["true_positive"] == 2
        assert s["by_verdict"]["false_positive"] == 1
        assert 0 < s["false_positive_rate"] <= 1.0

    def test_noisy_rule_detection(self):
        from backend.soc import record_feedback, list_noisy_rules
        # 4 FP, 1 TP -> noise_rate = 0.8 -> noisy
        for i in range(4):
            record_feedback(alert_id=f"A{i}", rule_id="R-NOISE",
                            verdict="false_positive", analyst="a", role="analyst")
        record_feedback(alert_id="A-tp", rule_id="R-NOISE",
                        verdict="true_positive", analyst="a", role="analyst")
        noisy = list_noisy_rules(min_total=3, fp_threshold=0.5)
        assert any(n["rule_id"] == "R-NOISE" for n in noisy)
        rule = next(n for n in noisy if n["rule_id"] == "R-NOISE")
        assert rule["noise_rate"] >= 0.5


# ---------------------------------------------------------------------------
# 3.2 Cases
# ---------------------------------------------------------------------------

class TestCases:

    def test_create_and_get(self):
        from backend.soc import create_case, get_case
        c = create_case(title="Phishing wave", description="Multiple users",
                        severity="high", created_by="alice",
                        alert_ids=["ALR-1", "ALR-2"],
                        mitre_techniques=["T1566.002"])
        assert c.case_id.startswith("CASE-")
        assert c.severity == "high"
        assert c.sla_due_at is not None

        fetched = get_case(c.case_id)
        assert fetched is not None
        assert fetched.title == "Phishing wave"
        assert fetched.alert_ids == ["ALR-1", "ALR-2"]

    def test_create_invalid_inputs(self):
        from backend.soc import create_case
        with pytest.raises(ValueError):
            create_case(title="ab", created_by="x")            # too short
        with pytest.raises(ValueError):
            create_case(title="Valid", severity="bogus", created_by="x")

    def test_list_filters(self):
        from backend.soc import create_case, list_cases
        create_case(title="High one", severity="high", created_by="x")
        create_case(title="Low one", severity="low", created_by="x")
        highs = list_cases(severity="high")
        assert all(c.severity == "high" for c in highs)
        assert len(highs) >= 1

    def test_assign_and_close(self):
        from backend.soc import create_case, assign_case, close_case
        c = create_case(title="Triage", severity="medium", created_by="x")
        assigned = assign_case(c.case_id, assignee="bob")
        assert assigned.assignee == "bob"
        assert assigned.status == "in_progress"

        closed = close_case(c.case_id, closure_reason="benign activity confirmed")
        assert closed.status == "closed"
        assert closed.closed_at is not None

    def test_close_requires_meaningful_reason(self):
        from backend.soc import create_case, close_case
        c = create_case(title="Short test case", severity="low", created_by="x")
        with pytest.raises(ValueError):
            close_case(c.case_id, closure_reason="ok")  # too short

    def test_comments_and_evidence_flow(self):
        from backend.soc import create_case, add_comment, add_evidence, get_case
        c = create_case(title="Investigation", severity="high", created_by="x")
        add_comment(c.case_id, author="alice", role="analyst",
                    body="Started triage at 09:00")
        add_evidence(c.case_id, type="alert", reference="ALR-42",
                     description="Initial alert", added_by="alice",
                     payload={"rule_id": "RULE-001"})

        full = get_case(c.case_id)
        assert len(full.comments) == 1 and full.comments[0].author == "alice"
        assert len(full.evidence) == 1
        assert full.evidence[0].payload == {"rule_id": "RULE-001"}

    def test_comment_on_unknown_case_raises(self):
        from backend.soc import add_comment
        with pytest.raises(ValueError):
            add_comment("CASE-DEAD", author="a", role="analyst", body="hi")


# ---------------------------------------------------------------------------
# 3.3 Suppressions
# ---------------------------------------------------------------------------

class TestSuppressions:

    def test_create_with_duration(self):
        from backend.soc import create_suppression, list_suppressions
        s = create_suppression(scope="rule", target="RULE-001",
                               reason="known benign in lab",
                               created_by="alice", duration_hours=2)
        assert s.suppression_id > 0
        active = list_suppressions(only_active=True)
        assert any(x.suppression_id == s.suppression_id for x in active)

    def test_must_have_expiration(self):
        from backend.soc import create_suppression
        with pytest.raises(ValueError):
            create_suppression(scope="rule", target="R", reason="testing only",
                               created_by="a")  # no expiration

    def test_invalid_scope(self):
        from backend.soc import create_suppression
        with pytest.raises(ValueError):
            create_suppression(scope="planet", target="x", reason="test reason",
                               created_by="a", duration_hours=1)

    def test_past_expiration_rejected(self):
        from backend.soc import create_suppression
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        with pytest.raises(ValueError):
            create_suppression(scope="rule", target="R", reason="testing past",
                               created_by="a", expires_at=past)

    def test_alert_suppression_check(self):
        from backend.soc import create_suppression, is_alert_suppressed
        create_suppression(scope="rule", target="RULE-007",
                           reason="lab benign", created_by="a",
                           duration_hours=1)
        is_supp, supp = is_alert_suppressed({"rule_id": "RULE-007"})
        assert is_supp and supp is not None
        is_supp2, _ = is_alert_suppressed({"rule_id": "RULE-OTHER"})
        assert not is_supp2

    def test_delete_marks_inactive(self):
        from backend.soc import create_suppression, delete_suppression, list_suppressions
        s = create_suppression(scope="user", target="alice",
                               reason="false positive on demo",
                               created_by="ops", duration_hours=1)
        assert delete_suppression(s.suppression_id, deleted_by="ops") is True
        active = list_suppressions(only_active=True)
        assert all(x.suppression_id != s.suppression_id for x in active)


# ---------------------------------------------------------------------------
# 3.4 AI Analyst evidence-first
# ---------------------------------------------------------------------------

class TestAIEvidence:

    def _alerts(self):
        return [{
            "alert_id": "ALR-1", "rule_id": "RULE-001", "rule_name": "PowerShell encoded",
            "tactic": "Execution", "technique_id": "T1059.001",
            "matched_events": [{
                "event_id": "evt-1",
                "command_line": "powershell -enc SGVsbG8=  password=hunter2",
                "timestamp": "2026-04-26T10:00:00",
            }],
        }]

    def test_no_alerts_no_strong_claim(self):
        from backend.ai_analyst import AIAnalyst
        out = AIAnalyst().analyse_with_evidence(
            scenario={}, alerts=[], incidents=[], scores={}, mitre_coverage={},
            timeline=[], logs_stats={"total_events": 0},
        )
        assert out["confidence"] == 0.0
        assert out["evidence"] == []
        assert "No alerts" in out["summary"]
        assert "limitations" in out and len(out["limitations"]) >= 1

    def test_evidence_links_event_to_rule(self):
        from backend.ai_analyst import AIAnalyst
        out = AIAnalyst().analyse_with_evidence(
            scenario={"id": "sc-1", "name": "test", "category": "phishing"},
            alerts=self._alerts(), incidents=[], scores={"detection_score": 60},
            mitre_coverage={}, timeline=[], logs_stats={"total_events": 50},
        )
        assert out["confidence"] > 0
        assert len(out["evidence"]) >= 1
        ev = out["evidence"][0]
        assert ev["event_id"] == "evt-1"
        assert ev["matched_rule"] == "RULE-001"
        # Secret in command_line MUST be redacted
        assert "hunter2" not in ev["value"]
        assert "[REDACTED]" in ev["value"]
        assert "T1059.001" in out["mitre"]
        assert "guardrails" in out
        assert "no_fabricated_iocs" in out["guardrails"]

    def test_low_evidence_produces_hypotheses_not_facts(self):
        from backend.ai_analyst import AIAnalyst
        # Single alert -> confidence < 0.6 -> hypotheses populated
        out = AIAnalyst().analyse_with_evidence(
            scenario={"category": "phishing"}, alerts=self._alerts(),
            incidents=[], scores={}, mitre_coverage={},
            timeline=[], logs_stats={"total_events": 10},
        )
        assert out["confidence"] < 0.6
        assert len(out["hypotheses"]) >= 1
        assert any("may" in h.lower() for h in out["hypotheses"])


# ---------------------------------------------------------------------------
# API integration tests (FastAPI TestClient)
# ---------------------------------------------------------------------------

class TestSocAPI:

    def test_post_feedback(self, client, auth_headers):
        r = client.post("/api/alerts/ALR-99/feedback",
                        json={"rule_id": "RULE-001", "verdict": "true_positive",
                              "reason": "real attack"}, headers=auth_headers)
        assert r.status_code == 200, r.text
        assert r.json()["verdict"] == "true_positive"

    def test_post_feedback_bad_verdict(self, client, auth_headers):
        r = client.post("/api/alerts/ALR-99/feedback",
                        json={"rule_id": "R", "verdict": "BAD"},
                        headers=auth_headers)
        assert r.status_code == 422  # pydantic validation error

    def test_feedback_summary_endpoint(self, client, auth_headers):
        client.post("/api/alerts/ALR-1/feedback",
                    json={"rule_id": "R", "verdict": "false_positive"},
                    headers=auth_headers)
        r = client.get("/api/alerts/feedback/summary", headers=auth_headers)
        assert r.status_code == 200
        body = r.json()
        assert body["total_feedback"] >= 1

    def test_full_case_lifecycle(self, client, auth_headers):
        # Create
        r = client.post("/api/cases", json={
            "title": "API integration case",
            "severity": "medium",
            "alert_ids": ["ALR-1"],
        }, headers=auth_headers)
        assert r.status_code == 200, r.text
        cid = r.json()["case_id"]

        # Patch description
        r = client.patch(f"/api/cases/{cid}",
                         json={"description": "updated"},
                         headers=auth_headers)
        assert r.status_code == 200
        assert r.json()["description"] == "updated"

        # Comment
        r = client.post(f"/api/cases/{cid}/comments",
                        json={"body": "starting investigation"},
                        headers=auth_headers)
        assert r.status_code == 200

        # Evidence
        r = client.post(f"/api/cases/{cid}/evidence",
                        json={"type": "alert", "reference": "ALR-1"},
                        headers=auth_headers)
        assert r.status_code == 200

        # Assign
        r = client.post(f"/api/cases/{cid}/assign",
                        json={"assignee": "bob"}, headers=auth_headers)
        assert r.status_code == 200
        assert r.json()["assignee"] == "bob"

        # Close
        r = client.post(f"/api/cases/{cid}/close",
                        json={"closure_reason": "verified false positive",
                              "final_status": "false_positive"},
                        headers=auth_headers)
        assert r.status_code == 200
        assert r.json()["status"] == "false_positive"
        assert len(r.json()["comments"]) == 1
        assert len(r.json()["evidence"]) == 1

    def test_case_404(self, client, auth_headers):
        r = client.get("/api/cases/CASE-DEAD", headers=auth_headers)
        assert r.status_code == 404

    def test_suppression_requires_admin(self, client, auth_headers, admin_headers):
        # analyst (auth_headers) cannot configure_system
        r1 = client.post("/api/suppressions",
                         json={"scope": "rule", "target": "RULE-X",
                               "reason": "lab test", "duration_hours": 1},
                         headers=auth_headers)
        assert r1.status_code == 403

        # admin can
        r2 = client.post("/api/suppressions",
                         json={"scope": "rule", "target": "RULE-X",
                               "reason": "lab benign positive", "duration_hours": 1},
                         headers=admin_headers)
        assert r2.status_code == 200, r2.text
        sid = r2.json()["suppression_id"]

        # Listing visible to analyst
        r = client.get("/api/suppressions", headers=auth_headers)
        assert r.status_code == 200
        assert r.json()["total"] >= 1

        # Delete requires admin again
        r = client.delete(f"/api/suppressions/{sid}", headers=auth_headers)
        assert r.status_code == 403
        r = client.delete(f"/api/suppressions/{sid}", headers=admin_headers)
        assert r.status_code == 200

    def test_suppression_must_expire(self, client, admin_headers):
        r = client.post("/api/suppressions",
                        json={"scope": "rule", "target": "R", "reason": "no expiry"},
                        headers=admin_headers)
        assert r.status_code == 400
