"""Regression tests for SQLAlchemy-backed SOC runtime CRUD."""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap


def test_soc_crud_uses_database_url_runtime(tmp_path):
    db_path = tmp_path / "soc_orm.db"
    env = os.environ.copy()
    env["DATABASE_URL"] = f"sqlite:///{db_path.as_posix()}"

    script = textwrap.dedent(
        """
        from backend.soc.database import init_soc_tables, use_orm
        from backend.soc import (
            add_comment, add_evidence, assign_case, close_case, create_case,
            create_suppression, delete_suppression, feedback_summary, get_case,
            list_cases, list_noisy_rules, list_suppressions, record_feedback,
        )

        assert use_orm() is True
        init_soc_tables()

        case = create_case(
            title="ORM investigation",
            description="PostgreSQL runtime path",
            severity="high",
            created_by="alice",
            alert_ids=["ALR-1"],
            incident_ids=["INC-1"],
            affected_hosts=["ws-01"],
            affected_users=["alice"],
            mitre_techniques=["T1059"],
            tags=["orm"],
            tenant_id="tenant-a",
        )
        assert case.case_id.startswith("CASE-")
        assert list_cases(tenant_id="tenant-b") == []
        assert len(list_cases(tenant_id="tenant-a")) == 1

        assigned = assign_case(case.case_id, assignee="bob", tenant_id="tenant-a")
        assert assigned.assignee == "bob"
        add_comment(case.case_id, author="alice", role="analyst", body="triage", tenant_id="tenant-a")
        add_evidence(
            case.case_id,
            type="alert",
            reference="ALR-1",
            added_by="alice",
            payload={"rule_id": "RULE-1"},
            tenant_id="tenant-a",
        )
        full = get_case(case.case_id, tenant_id="tenant-a")
        assert len(full.comments) == 1
        assert len(full.evidence) == 1
        assert full.evidence[0].payload == {"rule_id": "RULE-1"}

        closed = close_case(
            case.case_id,
            closure_reason="validated false positive",
            final_status="false_positive",
            tenant_id="tenant-a",
        )
        assert closed.status == "false_positive"
        assert closed.closed_at is not None

        for i in range(3):
            record_feedback(
                alert_id=f"ALR-{i}",
                rule_id="RULE-NOISY",
                verdict="false_positive",
                analyst="alice",
                role="analyst",
                tenant_id="tenant-a",
            )
        assert feedback_summary(tenant_id="tenant-a")["total_feedback"] == 3
        assert list_noisy_rules(tenant_id="tenant-a")[0]["rule_id"] == "RULE-NOISY"

        suppression = create_suppression(
            scope="rule",
            target="RULE-NOISY",
            reason="known benign lab pattern",
            created_by="alice",
            duration_hours=1,
            tenant_id="tenant-a",
        )
        assert len(list_suppressions(tenant_id="tenant-a")) == 1
        assert delete_suppression(suppression.suppression_id, deleted_by="alice", tenant_id="tenant-a")
        assert list_suppressions(tenant_id="tenant-a") == []
        """
    )

    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=os.getcwd(),
        env=env,
        text=True,
        capture_output=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
