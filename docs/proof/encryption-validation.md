# AES-256-GCM Field Encryption — Validation Report

**Commit**: `097cc9c`
**Date**: 2026-04-28
**Test file**: [`tests/test_field_encryption.py`](../../tests/test_field_encryption.py)
**Tests**: 16 / 16 passing
**Module**: `backend/crypto/field_encrypt.py`

## Scope

Verifies field-level encryption used for sensitive connector secrets,
API keys, and tenant-scoped configuration:

- AES-256-GCM round-trip (no plaintext leak)
- per-tenant key derivation via HKDF-SHA256
- tenant A cannot decrypt tenant B's ciphertext
- nonce uniqueness (no IV reuse, even on identical plaintexts)
- GCM authentication tag detects any ciphertext modification
- key length validation rejects weak base keys

## Test results

```
$ pytest tests/test_field_encryption.py -v
tests\test_field_encryption.py::TestRoundtrip::test_encrypt_decrypt_preserves_plaintext PASSED
tests\test_field_encryption.py::TestRoundtrip::test_unicode_roundtrip PASSED
tests\test_field_encryption.py::TestRoundtrip::test_empty_string_roundtrip PASSED
tests\test_field_encryption.py::TestRoundtrip::test_long_payload_roundtrip PASSED
tests\test_field_encryption.py::TestTenantIsolation::test_tenant_b_cannot_decrypt_tenant_a PASSED
tests\test_field_encryption.py::TestTenantIsolation::test_different_tenants_different_keys PASSED
tests\test_field_encryption.py::TestTenantIsolation::test_same_tenant_same_key_deterministic PASSED
tests\test_field_encryption.py::TestTenantIsolation::test_three_tenants_isolated PASSED
tests\test_field_encryption.py::TestNonceUniqueness::test_same_plaintext_produces_different_ciphertexts PASSED
tests\test_field_encryption.py::TestNonceUniqueness::test_nonce_is_12_bytes_prefix PASSED
tests\test_field_encryption.py::TestNonceUniqueness::test_100_encryptions_no_nonce_collision PASSED
tests\test_field_encryption.py::TestTamperDetection::test_flipped_byte_in_ciphertext_fails PASSED
tests\test_field_encryption.py::TestTamperDetection::test_truncated_ciphertext_fails PASSED
tests\test_field_encryption.py::TestTamperDetection::test_wrong_base_key_fails PASSED
tests\test_field_encryption.py::TestKeyValidation::test_short_key_rejected PASSED
tests\test_field_encryption.py::TestKeyValidation::test_default_singleton_works PASSED
============= 16 passed in 0.34s =============
```

## Key assertions

### Tenant A cannot decrypt Tenant B's data

```python
def test_tenant_b_cannot_decrypt_tenant_a(self, encryptor):
    plaintext = "tenantA-secret-data"
    ct = encryptor.encrypt(plaintext, tenant_id="tenantA")
    with pytest.raises(Exception):
        encryptor.decrypt(ct, tenant_id="tenantB")   # PASSES
```

### Per-tenant keys are distinct (HKDF determinism)

```python
def test_different_tenants_different_keys(self, encryptor):
    key_a = encryptor.derive_tenant_key("tenantA")
    key_b = encryptor.derive_tenant_key("tenantB")
    assert key_a != key_b
    assert len(key_a) == len(key_b) == 32   # AES-256
```

### No nonce reuse across encryptions

```python
def test_100_encryptions_no_nonce_collision(self, encryptor):
    ciphertexts = [encryptor.encrypt("x", tenant_id="tenantA") for _ in range(100)]
    nonces = [base64.b64decode(ct)[:12] for ct in ciphertexts]
    assert len(set(nonces)) == 100   # PASSES — all unique
```

### GCM tag detects any tampering

```python
def test_flipped_byte_in_ciphertext_fails(self, encryptor):
    ct = encryptor.encrypt("authentic-payload", tenant_id="tenantA")
    raw = bytearray(base64.b64decode(ct))
    raw[20] ^= 0x01   # flip a single bit
    with pytest.raises(Exception):
        encryptor.decrypt(base64.b64encode(bytes(raw)).decode(),
                          tenant_id="tenantA")   # PASSES
```

## Algorithm details

| Parameter | Value | Rationale |
|---|---|---|
| Cipher | AES-256-GCM | NIST SP 800-38D, FIPS 140-3 approved |
| Key length | 32 bytes (256 bit) | maximum for AES |
| Nonce length | 12 bytes (96 bit) | recommended for GCM (NIST SP 800-38D §8.2) |
| KDF | HKDF-SHA256 | RFC 5869, salt=None, info=`cybertwin-soc:field-encrypt:{tenant_id}` |
| Auth tag length | 16 bytes (128 bit) | maximum strength, default for cryptography library |

Output format: `base64(nonce || ciphertext_with_auth_tag)` — 12-byte
nonce prefix + GCM ciphertext (which already includes the 16-byte tag).

## Threat model coverage

| Threat | Mitigation | Test |
|---|---|---|
| Database leak exposes API keys | Field encrypted at rest with tenant key | `test_encrypt_decrypt_preserves_plaintext` |
| Tenant A reads tenant B's encrypted column | HKDF key derivation produces distinct keys | `test_tenant_b_cannot_decrypt_tenant_a` |
| Attacker forges identical ciphertexts | Random 96-bit nonce ensures distinct outputs | `test_100_encryptions_no_nonce_collision` |
| Attacker modifies ciphertext (bit flip) | GCM auth tag verification fails | `test_flipped_byte_in_ciphertext_fails` |
| Attacker truncates ciphertext | GCM auth tag verification fails | `test_truncated_ciphertext_fails` |
| Weak base key passed | `__init__` rejects keys shorter than 32 bytes | `test_short_key_rejected` |

## Key management

| Aspect | Implementation |
|---|---|
| **Master key source** | `FIELD_ENCRYPTION_KEY` env var (base64-encoded 32 bytes) |
| **Per-tenant keys** | HKDF-SHA256 derivation from master key + tenant_id |
| **Key rotation** | Roadmap (v3.3): `FieldEncryptor.rotate(old_key, new_key)` re-encrypts all fields |
| **Key escrow** | Out of scope — operator responsibility (Vault, KMS, HSM) |
| **Default fallback** | When `FIELD_ENCRYPTION_KEY` is unset, an ephemeral random key is generated and a warning is logged. Data encrypted in this mode cannot survive a restart — this is intentional for local dev. |

## SQLAlchemy integration

The `EncryptedString` `TypeDecorator` provides transparent column-level
encryption:

```python
from backend.crypto.field_encrypt import EncryptedString

class TenantSecret(Base):
    __tablename__ = "tenant_secrets"
    tenant_id: Mapped[str] = mapped_column(String(80))
    api_key:    Mapped[str] = mapped_column(EncryptedString(length=2048))
```

Plaintext on read, ciphertext on write — no application-code change.

## How to reproduce

```bash
pip install cryptography
pytest tests/test_field_encryption.py -v
```

## Limits / next steps

- The `EncryptedString` decorator currently uses `tenant_id="default"`
  because TypeDecorators cannot easily access sibling-column values.
  For per-tenant column encryption, either:
  1. Use `FieldEncryptor.encrypt(plaintext, tenant_id)` explicitly in the
     repository layer (current pattern for connector secrets), or
  2. Wait for the SQLAlchemy event-hook integration on the v3.3 roadmap.
- Hardware security module (HSM) / KMS integration for key escrow is on
  the v3.3 backlog.
- Key rotation API is documented but not yet implemented.
