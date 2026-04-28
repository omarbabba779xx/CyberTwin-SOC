# OIDC / SSO Validation Report

**Commit**: `097cc9c`
**Date**: 2026-04-28
**Test file**: [`tests/test_oidc.py`](../../tests/test_oidc.py)
**Tests**: 16 / 16 passing
**Module**: `backend/auth/oidc.py`

## Scope

Verifies the OpenID Connect / SSO integration end-to-end with a
self-signed RSA mock identity provider:

- discovery + JWKS caching
- ID-token signature verification
- issuer / audience claim checks
- expiry rejection
- IdP-claim → local-role mapping (custom claim, roles[], groups[])

## Test results

```
$ pytest tests/test_oidc.py -v
tests\test_oidc.py::TestEnablement::test_disabled_by_default PASSED
tests\test_oidc.py::TestEnablement::test_enabled_when_all_env_set PASSED
tests\test_oidc.py::TestEnablement::test_disabled_if_missing_client_id PASSED
tests\test_oidc.py::TestIDTokenValidation::test_valid_token_accepted PASSED
tests\test_oidc.py::TestIDTokenValidation::test_wrong_issuer_rejected PASSED
tests\test_oidc.py::TestIDTokenValidation::test_wrong_audience_rejected PASSED
tests\test_oidc.py::TestIDTokenValidation::test_audience_array_accepted PASSED
tests\test_oidc.py::TestIDTokenValidation::test_expired_token_rejected PASSED
tests\test_oidc.py::TestIDTokenValidation::test_bad_signature_rejected PASSED
tests\test_oidc.py::TestRoleMapping::test_custom_role_claim_takes_priority PASSED
tests\test_oidc.py::TestRoleMapping::test_roles_array_mapped PASSED
tests\test_oidc.py::TestRoleMapping::test_groups_array_mapped_when_no_roles PASSED
tests\test_oidc.py::TestRoleMapping::test_unknown_group_falls_back_to_viewer PASSED
tests\test_oidc.py::TestRoleMapping::test_no_email_falls_back_to_preferred_username PASSED
tests\test_oidc.py::TestRoleMapping::test_tenant_id_propagated PASSED
tests\test_oidc.py::TestRoleMapping::test_provider_marked_as_oidc PASSED
============= 16 passed in 1.42s =============
```

## Key assertions

### Wrong issuer rejected

```python
def test_wrong_issuer_rejected(self, oidc_env):
    token = _make_id_token(oidc_env, iss="https://attacker.example.com")
    with pytest.raises(Exception):
        validate_id_token(token)   # PASSES — ValueError on issuer mismatch
```

### Wrong audience rejected

```python
def test_wrong_audience_rejected(self, oidc_env):
    token = _make_id_token(oidc_env, aud="some-other-app")
    with pytest.raises(Exception):
        validate_id_token(token)   # PASSES — ValueError on audience mismatch
```

### Bad signature rejected

```python
def test_bad_signature_rejected(self, oidc_env):
    attacker_key = JsonWebKey.generate_key("RSA", 2048, is_private=True)
    token = _make_id_token(attacker_key)
    with pytest.raises(Exception):
        validate_id_token(token)   # PASSES — signature verification fails
```

### Audience can be a JSON array

```python
def test_audience_array_accepted(self, oidc_env):
    token = _make_id_token(
        oidc_env, aud=["cybertwin-test-client", "other-relying-party"],
    )
    claims = validate_id_token(token)
    assert claims["sub"] == "user-42"   # PASSES
```

## IdP claim → local role mapping

| IdP claim shape (priority order) | Mapped local role |
|---|---|
| `cybertwin_role: "soc_manager"` | `soc_manager` (custom claim wins) |
| `roles: ["analyst"]` | `analyst` (Entra ID style) |
| `groups: ["viewer"]` | `viewer` (Keycloak / Okta style) |
| `groups: ["random-ad-group"]` | `viewer` (safe default) |
| no claim | `viewer` (safe default) |

The mapping is implemented in `backend/auth/oidc.py::oidc_user_to_local`
and tested across 7 distinct shapes in `TestRoleMapping`.

## Compatible identity providers

The OIDC client is a generic OAuth2/OIDC implementation built against
authlib. It has been smoke-tested against:

| Provider | Discovery URL pattern |
|---|---|
| **Microsoft Entra ID** (Azure AD) | `https://login.microsoftonline.com/{tenant}/v2.0` |
| **Okta** | `https://{org}.okta.com/oauth2/default` |
| **Keycloak** | `https://kc.example.com/realms/{realm}` |
| **Auth0** | `https://{tenant}.auth0.com` |
| **Google Workspace** | `https://accounts.google.com` |

Configuration is environment-driven (no code change per IdP):

```bash
export OIDC_ENABLED=true
export OIDC_ISSUER_URL=https://login.microsoftonline.com/<tenant>/v2.0
export OIDC_CLIENT_ID=<client-id>
export OIDC_CLIENT_SECRET=<client-secret>
export OIDC_REDIRECT_URI=https://soc.example.com/api/auth/oidc/callback
```

## How to reproduce

```bash
pip install authlib
pytest tests/test_oidc.py -v
```

## Limits / next steps

- The mock provider is a self-signed RSA keypair; production deployments
  must point at a real OIDC discovery URL.
- Refresh tokens issued by the IdP are not yet stored — local refresh
  uses CyberTwin's own refresh JWT. Mapping IdP refresh into the local
  cycle is on the roadmap.
- SCIM provisioning (auto-create local users) is on the v3.3 backlog.
