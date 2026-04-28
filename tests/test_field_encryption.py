"""Integration tests for AES-256-GCM field-level encryption.

Verifies:
- encrypt/decrypt roundtrip preserves plaintext
- per-tenant key derivation produces distinct ciphertexts
- tenant A cannot decrypt tenant B's ciphertext
- nonce is unique across encryptions (no IV reuse)
- ciphertext is base64 and contains the 12-byte nonce prefix
- corrupted ciphertext raises on decrypt (GCM tag check)
"""
from __future__ import annotations

import base64
import os

import pytest


@pytest.fixture
def encryptor():
    """Fresh FieldEncryptor with a known base key."""
    from backend.crypto.field_encrypt import FieldEncryptor
    base_key = os.urandom(32)
    return FieldEncryptor(base_key=base_key)


class TestRoundtrip:
    def test_encrypt_decrypt_preserves_plaintext(self, encryptor):
        plaintext = "secret-api-key-12345"
        ct = encryptor.encrypt(plaintext, tenant_id="tenantA")
        result = encryptor.decrypt(ct, tenant_id="tenantA")
        assert result == plaintext

    def test_unicode_roundtrip(self, encryptor):
        plaintext = "passe-mot d'ordre — naïveté 🔐"
        ct = encryptor.encrypt(plaintext, tenant_id="tenantA")
        assert encryptor.decrypt(ct, tenant_id="tenantA") == plaintext

    def test_empty_string_roundtrip(self, encryptor):
        ct = encryptor.encrypt("", tenant_id="tenantA")
        assert encryptor.decrypt(ct, tenant_id="tenantA") == ""

    def test_long_payload_roundtrip(self, encryptor):
        plaintext = "A" * 4096
        ct = encryptor.encrypt(plaintext, tenant_id="tenantA")
        assert encryptor.decrypt(ct, tenant_id="tenantA") == plaintext


class TestTenantIsolation:
    """Critical: tenant A's key must not decrypt tenant B's data."""

    def test_tenant_b_cannot_decrypt_tenant_a(self, encryptor):
        plaintext = "tenantA-secret-data"
        ct = encryptor.encrypt(plaintext, tenant_id="tenantA")

        with pytest.raises(Exception):
            encryptor.decrypt(ct, tenant_id="tenantB")

    def test_different_tenants_different_keys(self, encryptor):
        key_a = encryptor.derive_tenant_key("tenantA")
        key_b = encryptor.derive_tenant_key("tenantB")
        assert key_a != key_b
        assert len(key_a) == 32  # AES-256
        assert len(key_b) == 32

    def test_same_tenant_same_key_deterministic(self, encryptor):
        """HKDF must be deterministic for the same input."""
        k1 = encryptor.derive_tenant_key("tenantA")
        k2 = encryptor.derive_tenant_key("tenantA")
        assert k1 == k2

    def test_three_tenants_isolated(self, encryptor):
        secrets_per_tenant = {
            "tenantA": "secret-A",
            "tenantB": "secret-B",
            "tenantC": "secret-C",
        }
        ciphertexts = {
            t: encryptor.encrypt(s, tenant_id=t) for t, s in secrets_per_tenant.items()
        }

        for tenant, expected in secrets_per_tenant.items():
            assert encryptor.decrypt(ciphertexts[tenant], tenant_id=tenant) == expected

        for cross_tenant in ["tenantA", "tenantB", "tenantC"]:
            for foreign in ["tenantA", "tenantB", "tenantC"]:
                if foreign == cross_tenant:
                    continue
                with pytest.raises(Exception):
                    encryptor.decrypt(ciphertexts[cross_tenant], tenant_id=foreign)


class TestNonceUniqueness:
    """AES-GCM is catastrophic if a nonce is reused with the same key."""

    def test_same_plaintext_produces_different_ciphertexts(self, encryptor):
        plaintext = "identical"
        ct1 = encryptor.encrypt(plaintext, tenant_id="tenantA")
        ct2 = encryptor.encrypt(plaintext, tenant_id="tenantA")
        assert ct1 != ct2  # nonces differ → ciphertexts differ

    def test_nonce_is_12_bytes_prefix(self, encryptor):
        ct = encryptor.encrypt("payload", tenant_id="tenantA")
        raw = base64.b64decode(ct)
        # First 12 bytes are the nonce; remainder is ciphertext+tag
        assert len(raw) >= 12 + 16  # nonce + GCM tag minimum

    def test_100_encryptions_no_nonce_collision(self, encryptor):
        ciphertexts = [encryptor.encrypt("x", tenant_id="tenantA") for _ in range(100)]
        nonces = [base64.b64decode(ct)[:12] for ct in ciphertexts]
        assert len(set(nonces)) == 100  # all unique


class TestTamperDetection:
    """GCM authenticates ciphertext — any modification must fail decryption."""

    def test_flipped_byte_in_ciphertext_fails(self, encryptor):
        ct = encryptor.encrypt("authentic-payload", tenant_id="tenantA")
        raw = bytearray(base64.b64decode(ct))
        raw[20] ^= 0x01  # flip a bit in the ciphertext body
        tampered = base64.b64encode(bytes(raw)).decode("ascii")

        with pytest.raises(Exception):
            encryptor.decrypt(tampered, tenant_id="tenantA")

    def test_truncated_ciphertext_fails(self, encryptor):
        ct = encryptor.encrypt("authentic-payload", tenant_id="tenantA")
        raw = base64.b64decode(ct)
        truncated = base64.b64encode(raw[:-4]).decode("ascii")

        with pytest.raises(Exception):
            encryptor.decrypt(truncated, tenant_id="tenantA")

    def test_wrong_base_key_fails(self):
        from backend.crypto.field_encrypt import FieldEncryptor

        enc1 = FieldEncryptor(base_key=os.urandom(32))
        enc2 = FieldEncryptor(base_key=os.urandom(32))

        ct = enc1.encrypt("secret", tenant_id="tenantA")
        with pytest.raises(Exception):
            enc2.decrypt(ct, tenant_id="tenantA")


class TestKeyValidation:
    def test_short_key_rejected(self):
        from backend.crypto.field_encrypt import FieldEncryptor
        with pytest.raises(ValueError, match="at least 32 bytes"):
            FieldEncryptor(base_key=b"too-short")

    def test_default_singleton_works(self):
        """get_encryptor() should always return a usable encryptor."""
        from backend.crypto.field_encrypt import get_encryptor
        enc = get_encryptor()
        ct = enc.encrypt("test", tenant_id="default")
        assert enc.decrypt(ct, tenant_id="default") == "test"
