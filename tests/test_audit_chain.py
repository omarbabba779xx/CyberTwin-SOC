"""Integration tests for the tamper-evident audit chain.

Verifies:
- log_action() writes a SHA-256 integrity_hash for every entry
- verify_audit_chain() returns valid=True on an untouched chain
- verify_audit_chain() returns valid=False with first_broken_id when
  any field of an entry is modified after-the-fact
- the chain is robust to legitimate appends
- the chain links each entry to its predecessor (predecessor change
  invalidates every successor)
"""
from __future__ import annotations

import sqlite3
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def isolated_audit_db(monkeypatch):
    """Point backend.audit at a fresh SQLite file for each test."""
    tmp_dir = tempfile.mkdtemp(prefix="audit-test-")
    tmp_db = Path(tmp_dir) / "audit_test.db"

    import backend.audit as audit_mod
    monkeypatch.setattr(audit_mod, "DB_PATH", tmp_db)

    # Disable Postgres path during tests
    monkeypatch.delenv("DATABASE_URL", raising=False)

    # Reset Redis-backed last-hash cache to genesis so each test starts fresh
    from backend.cache import cache
    cache.delete(audit_mod._REDIS_HASH_KEY)

    audit_mod.init_audit_table()
    yield tmp_db


def _read_all(db_path: Path) -> list[dict]:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM audit_log ORDER BY id ASC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


class TestHashChain:
    def test_each_entry_gets_integrity_hash(self, isolated_audit_db):
        from backend.audit import log_action

        log_action("LOGIN", username="alice", role="analyst", status="success")
        log_action("CASE_OPEN", username="alice", role="analyst",
                   resource="case-123", status="success")

        rows = _read_all(isolated_audit_db)
        assert len(rows) == 2
        for r in rows:
            assert r["integrity_hash"], f"Missing integrity_hash on entry {r['id']}"
            assert len(r["integrity_hash"]) == 64  # SHA-256 hex

    def test_consecutive_entries_have_different_hashes(self, isolated_audit_db):
        from backend.audit import log_action

        log_action("LOGIN", username="alice", role="analyst", status="success")
        log_action("LOGIN", username="alice", role="analyst", status="success")

        rows = _read_all(isolated_audit_db)
        # Two identical actions must still produce different hashes (chained on time + previous)
        assert rows[0]["integrity_hash"] != rows[1]["integrity_hash"]

    def test_verify_clean_chain_is_valid(self, isolated_audit_db):
        from backend.audit import log_action, verify_audit_chain

        for i in range(10):
            log_action(
                "ACTION",
                username=f"user{i}",
                role="analyst",
                resource=f"res-{i}",
                status="success",
                details={"i": i},
            )

        result = verify_audit_chain(limit=100)
        assert result["valid"] is True, result["message"]
        assert result["checked"] == 10
        assert result["first_broken_id"] is None


class TestTamperDetection:
    def test_modified_action_field_breaks_chain(self, isolated_audit_db):
        from backend.audit import log_action, verify_audit_chain

        log_action("LOGIN", username="alice", role="analyst", status="success")
        log_action("CASE_DELETE", username="alice", role="analyst",
                   resource="case-1", status="success")
        log_action("CASE_DELETE", username="alice", role="analyst",
                   resource="case-2", status="success")

        # Tamper: rewrite the action of entry 2 from "CASE_DELETE" to "LOGIN"
        # to cover up evidence that alice deleted a case.
        conn = sqlite3.connect(str(isolated_audit_db))
        conn.execute("UPDATE audit_log SET action = ? WHERE id = ?", ("LOGIN", 2))
        conn.commit()
        conn.close()

        result = verify_audit_chain(limit=100)
        assert result["valid"] is False
        assert result["first_broken_id"] == 2

    def test_modified_username_breaks_chain(self, isolated_audit_db):
        from backend.audit import log_action, verify_audit_chain

        log_action("LOGIN", username="alice", role="analyst", status="success")
        log_action("CASE_CLOSE", username="bob", role="analyst",
                   resource="case-1", status="success")

        conn = sqlite3.connect(str(isolated_audit_db))
        conn.execute("UPDATE audit_log SET username = ? WHERE id = ?", ("alice", 2))
        conn.commit()
        conn.close()

        result = verify_audit_chain(limit=100)
        assert result["valid"] is False
        assert result["first_broken_id"] == 2

    def test_modified_status_breaks_chain(self, isolated_audit_db):
        from backend.audit import log_action, verify_audit_chain

        log_action("LOGIN", username="attacker", role="unknown", status="failure")

        # Try to hide the failed login attempt by flipping status to success
        conn = sqlite3.connect(str(isolated_audit_db))
        conn.execute("UPDATE audit_log SET status = ? WHERE id = ?", ("success", 1))
        conn.commit()
        conn.close()

        result = verify_audit_chain(limit=100)
        assert result["valid"] is False

    def test_modified_predecessor_invalidates_successors(self, isolated_audit_db):
        """Changing entry N must invalidate all entries N+1, N+2, ..."""
        from backend.audit import log_action, verify_audit_chain

        for i in range(5):
            log_action("ACTION", username=f"user{i}", role="analyst", status="success")

        # Tamper with the FIRST entry — chain detection should flag it as
        # the first break (no later entry is safe because every successor
        # depends on its predecessor's hash).
        conn = sqlite3.connect(str(isolated_audit_db))
        conn.execute("UPDATE audit_log SET username = ? WHERE id = ?", ("evilroot", 1))
        conn.commit()
        conn.close()

        result = verify_audit_chain(limit=100)
        assert result["valid"] is False
        assert result["first_broken_id"] == 1


class TestVerifyEdgeCases:
    def test_empty_chain_is_valid(self, isolated_audit_db):
        from backend.audit import verify_audit_chain

        result = verify_audit_chain(limit=100)
        assert result["valid"] is True
        assert result["checked"] == 0
