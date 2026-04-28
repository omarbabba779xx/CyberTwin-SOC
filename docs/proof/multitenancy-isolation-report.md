# Multi-Tenancy Isolation — Validation Report

**Commit**: `097cc9c`
**Date**: 2026-04-28
**Test file**: [`tests/test_tenant_isolation.py`](../../tests/test_tenant_isolation.py)
**Tests**: 12 / 12 passing

## Scope

Verifies that the v3.2 multi-tenancy implementation enforces runtime
isolation across three layers:

1. **JWT layer** — `tenant_id` claim is embedded in the access and refresh tokens.
2. **Middleware layer** — `TenantScopeMiddleware` extracts `tenant_id` from the JWT into `request.state`.
3. **Data layer** — `TenantRepository` automatically filters every query by `tenant_id`.

## Test results

```
$ pytest tests/test_tenant_isolation.py -v
tests\test_tenant_isolation.py::TestJWTTenantClaim::test_create_token_embeds_tenant_id PASSED
tests\test_tenant_isolation.py::TestJWTTenantClaim::test_default_tenant_when_omitted PASSED
tests\test_tenant_isolation.py::TestJWTTenantClaim::test_refresh_token_carries_tenant_id PASSED
tests\test_tenant_isolation.py::TestTenantMiddleware::test_no_auth_uses_default_tenant PASSED
tests\test_tenant_isolation.py::TestTenantMiddleware::test_jwt_with_tenant_propagates PASSED
tests\test_tenant_isolation.py::TestTenantMiddleware::test_invalid_jwt_falls_back_to_default PASSED
tests\test_tenant_isolation.py::TestTenantMiddleware::test_expired_jwt_falls_back_to_default PASSED
tests\test_tenant_isolation.py::TestTenantMiddleware::test_three_distinct_tenants_isolated_in_state PASSED
tests\test_tenant_isolation.py::TestTenantRepository::test_query_filters_by_tenant PASSED
tests\test_tenant_isolation.py::TestTenantRepository::test_get_by_id_blocks_cross_tenant_read PASSED
tests\test_tenant_isolation.py::TestTenantRepository::test_count_is_per_tenant PASSED
tests\test_tenant_isolation.py::TestTenantRepository::test_add_stamps_tenant_id_automatically PASSED
============= 12 passed in 1.96s =============
```

## Key assertions

### Tenant A cannot read Tenant B's records by id

```python
def test_get_by_id_blocks_cross_tenant_read(self, in_memory_db):
    sess = Session()
    b_widget = Widget(tenant_id="tenantB", name="secret-b")
    sess.add(b_widget); sess.commit()

    repo_a = TenantRepository(sess, tenant_id="tenantA")
    result = repo_a.get_by_id(Widget, b_widget.id)
    assert result is None  # PASSES
```

### tenant_id from JWT overrides any client-provided value

```python
def test_add_stamps_tenant_id_automatically(self, in_memory_db):
    repo = TenantRepository(sess, tenant_id="tenantA")
    spoofed = Widget(tenant_id="tenantB", name="spoof")
    repo.add(spoofed); sess.commit()

    stored = sess.query(Widget).filter_by(name="spoof").first()
    assert stored.tenant_id == "tenantA"   # PASSES
```

### JWT carries the tenant_id claim end-to-end

```python
def test_create_token_embeds_tenant_id(self):
    token = create_token("alice", "analyst", tenant_id="tenant-acme")
    decoded = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    assert decoded["tenant_id"] == "tenant-acme"   # PASSES
```

## Threat model coverage

| Threat | Mitigation | Test |
|---|---|---|
| Tenant A guesses tenant B's primary keys | Repository filters by `tenant_id` on every read | `test_get_by_id_blocks_cross_tenant_read` |
| Tenant A spoofs `tenant_id` in request payload | Middleware overrides from JWT, repository overrides from middleware | `test_add_stamps_tenant_id_automatically` |
| Forged / tampered JWT | JWT signature verification fails → fallback to "default" | `test_invalid_jwt_falls_back_to_default` |
| Expired JWT used to access tenant data | JWT decode fails → fallback to "default" | `test_expired_jwt_falls_back_to_default` |
| Concurrent tenants interleaved | Each request scopes its own `request.state.tenant_id` | `test_three_distinct_tenants_isolated_in_state` |

## How to reproduce

```bash
pytest tests/test_tenant_isolation.py -v
```

## Limits / next steps

- The current `TenantScopeMiddleware` falls back to `tenant_id="default"`
  when the JWT is missing or malformed. This is intentional for
  unauthenticated endpoints (`/health`, `/metrics`, `/api/auth/login`).
  Sensitive endpoints rely on `Depends(verify_token)` which rejects
  unauthenticated requests with 401 BEFORE reaching tenant-scoped code.
- Cross-tenant aggregation (e.g. global admin dashboards) requires an
  explicit `bypass_tenant_filter=True` option which is not yet exposed.
  Current admin views run inside the admin tenant only.
- The `TenantRepository.add()` overwrite is a defence-in-depth control;
  application code is still expected to never accept `tenant_id` from
  request bodies (Pydantic schemas do not include it).
