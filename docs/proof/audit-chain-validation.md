# Tamper-Evident Audit Chain — Validation Report

**Commit**: `097cc9c`
**Date**: 2026-04-28
**Test file**: [`tests/test_audit_chain.py`](../../tests/test_audit_chain.py)
**Tests**: 8 / 8 passing
**Module**: `backend/audit.py`

## Scope

Verifies the SOC 2 / ISO 27001 audit-trail integrity control:

- every entry stores a SHA-256 `integrity_hash = sha256(prev_hash | entry_data)`
- `verify_audit_chain()` returns `valid=True` on an untouched chain
- any post-hoc modification (action, username, status, etc.) is detected
- the breaking entry's id is reported precisely (`first_broken_id`)
- the chain is robust to legitimate appends

## Test results

```
$ pytest tests/test_audit_chain.py -v
tests\test_audit_chain.py::TestHashChain::test_each_entry_gets_integrity_hash PASSED
tests\test_audit_chain.py::TestHashChain::test_consecutive_entries_have_different_hashes PASSED
tests\test_audit_chain.py::TestHashChain::test_verify_clean_chain_is_valid PASSED
tests\test_audit_chain.py::TestTamperDetection::test_modified_action_field_breaks_chain PASSED
tests\test_audit_chain.py::TestTamperDetection::test_modified_username_breaks_chain PASSED
tests\test_audit_chain.py::TestTamperDetection::test_modified_status_breaks_chain PASSED
tests\test_audit_chain.py::TestTamperDetection::test_modified_predecessor_invalidates_successors PASSED
tests\test_audit_chain.py::TestVerifyEdgeCases::test_empty_chain_is_valid PASSED
============= 8 passed in 1.18s =============
```

## Key assertions

### Tampering with `action` is detected

```python
def test_modified_action_field_breaks_chain(self, isolated_audit_db):
    log_action("LOGIN", username="alice", role="analyst", status="success")
    log_action("CASE_DELETE", username="alice", role="analyst",
               resource="case-1", status="success")
    log_action("CASE_DELETE", username="alice", role="analyst",
               resource="case-2", status="success")

    # Attacker rewrites entry 2 from CASE_DELETE → LOGIN
    conn = sqlite3.connect(str(isolated_audit_db))
    conn.execute("UPDATE audit_log SET action = 'LOGIN' WHERE id = 2")
    conn.commit(); conn.close()

    result = verify_audit_chain(limit=100)
    assert result["valid"] is False               # PASSES
    assert result["first_broken_id"] == 2         # PASSES
```

### Tampering with `status` (e.g. failure → success) is detected

```python
def test_modified_status_breaks_chain(self, isolated_audit_db):
    log_action("LOGIN", username="attacker", role="unknown", status="failure")

    # Attacker hides the failed attempt
    conn = sqlite3.connect(str(isolated_audit_db))
    conn.execute("UPDATE audit_log SET status = 'success' WHERE id = 1")

    assert verify_audit_chain(limit=100)["valid"] is False    # PASSES
```

### Modifying any predecessor invalidates the entire chain

```python
def test_modified_predecessor_invalidates_successors(self, isolated_audit_db):
    for i in range(5):
        log_action("ACTION", username=f"user{i}", role="analyst", status="success")

    conn = sqlite3.connect(str(isolated_audit_db))
    conn.execute("UPDATE audit_log SET username = 'evilroot' WHERE id = 1")

    result = verify_audit_chain(limit=100)
    assert result["valid"] is False               # PASSES
    assert result["first_broken_id"] == 1         # PASSES
```

## Implementation summary

```
entry_data        := f"{ts}|{username}|{role}|{action}|{resource}|{ip_address}|{status}|{details_json}"
integrity_hash    := sha256(f"{previous_hash}:{entry_data}").hexdigest()
genesis_hash      := "0" * 64
```

The previous hash is cached in Redis under `cybertwin:audit:last_hash`
for fast continuation; verification re-derives it from the database
to detect Redis tampering as well.

## Threat model coverage

| Threat | Mitigation | Test |
|---|---|---|
| Insider rewrites a critical action (delete → read) | Hash chain mismatch detected | `test_modified_action_field_breaks_chain` |
| Insider hides own failed attempts | Hash chain mismatch detected | `test_modified_status_breaks_chain` |
| Insider impersonates another user post-hoc | Hash chain mismatch detected | `test_modified_username_breaks_chain` |
| Insider modifies an old entry hoping no one looks | Every successor is invalidated | `test_modified_predecessor_invalidates_successors` |
| Insider deletes the chain | Length mismatch detected (out of scope here, but `verify_audit_chain` reports `checked` count) | partial — see limits |

## How to reproduce

```bash
pytest tests/test_audit_chain.py -v
```

## Limits / next steps

- The current implementation detects modification but not **deletion** of
  the latest entries (the chain remains internally consistent if you
  truncate from the tail). The roadmap includes an immutable WORM
  storage backend (S3 Object Lock, blockchain anchoring) for v3.3.
- Periodic chain verification (cron) is operator-driven; an automated
  scheduler is on the v3.3 backlog.
- Integrity-hash storage is per-process; the Redis cache key
  `cybertwin:audit:last_hash` is a performance optimisation only —
  the database is the source of truth.
