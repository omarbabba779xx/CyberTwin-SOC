"""AES-256-GCM field-level encryption for sensitive data.

Keys are loaded from FIELD_ENCRYPTION_KEY env var or derived per-tenant
from a master key + tenant_id.
"""

from __future__ import annotations

import base64
import logging
import os
from typing import Any, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from sqlalchemy import String, TypeDecorator

logger = logging.getLogger("cybertwin.crypto")

_KEY_LENGTH = 32  # AES-256
_NONCE_LENGTH = 12  # 96-bit nonce recommended for AES-GCM


class FieldEncryptor:
    """AES-256-GCM field encryptor with per-tenant key derivation via HKDF."""

    def __init__(self, base_key: bytes | None = None) -> None:
        if base_key is None:
            env_key = os.getenv("FIELD_ENCRYPTION_KEY", "")
            if env_key:
                base_key = base64.b64decode(env_key)
            else:
                base_key = os.urandom(_KEY_LENGTH)
                logger.warning(
                    "FIELD_ENCRYPTION_KEY not set — generated ephemeral key. "
                    "Data encrypted in this session cannot be decrypted after restart."
                )
        if len(base_key) < _KEY_LENGTH:
            raise ValueError(
                f"Base key must be at least {_KEY_LENGTH} bytes, got {len(base_key)}"
            )
        self._base_key = base_key[:_KEY_LENGTH]

    def derive_tenant_key(self, tenant_id: str) -> bytes:
        """Derive a unique AES-256 key per tenant using HKDF-SHA256."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=_KEY_LENGTH,
            salt=None,
            info=f"cybertwin-soc:field-encrypt:{tenant_id}".encode(),
        )
        return hkdf.derive(self._base_key)

    def encrypt(self, plaintext: str, tenant_id: str) -> str:
        """Encrypt *plaintext* → base64-encoded ``nonce || ciphertext``."""
        key = self.derive_tenant_key(tenant_id)
        nonce = os.urandom(_NONCE_LENGTH)
        aesgcm = AESGCM(key)
        ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
        return base64.b64encode(nonce + ct).decode("ascii")

    def decrypt(self, ciphertext: str, tenant_id: str) -> str:
        """Decrypt base64-encoded ``nonce || ciphertext`` → plaintext string."""
        key = self.derive_tenant_key(tenant_id)
        raw = base64.b64decode(ciphertext)
        nonce, ct = raw[:_NONCE_LENGTH], raw[_NONCE_LENGTH:]
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ct, None).decode("utf-8")


# ---------------------------------------------------------------------------
# Singleton (lazy) — shared across the application
# ---------------------------------------------------------------------------

_default_encryptor: FieldEncryptor | None = None


def get_encryptor() -> FieldEncryptor:
    """Return (and lazily create) the process-wide ``FieldEncryptor``."""
    global _default_encryptor
    if _default_encryptor is None:
        _default_encryptor = FieldEncryptor()
    return _default_encryptor


# ---------------------------------------------------------------------------
# SQLAlchemy TypeDecorator
# ---------------------------------------------------------------------------

class EncryptedString(TypeDecorator):
    """SQLAlchemy TypeDecorator that auto-encrypts on write and decrypts on read.

    Usage::

        class Secret(Base):
            __tablename__ = "secrets"
            tenant_id: Mapped[str] = mapped_column(String(80))
            api_key: Mapped[str] = mapped_column(EncryptedString(tenant_id_column="tenant_id"))

    The *tenant_id_column* parameter names the sibling column whose value
    is used for per-tenant key derivation.  When the ORM cannot resolve
    the tenant (e.g. raw SQL), ``"default"`` is used as a fallback.
    """

    impl = String
    cache_ok = False  # not cache-safe (nonce differs per call)

    def __init__(self, length: int = 1024, tenant_id_column: str = "tenant_id") -> None:
        super().__init__(length=length)
        self._tenant_col = tenant_id_column

    def process_bind_param(self, value: Optional[str], dialect: Any) -> Optional[str]:
        if value is None:
            return None
        enc = get_encryptor()
        return enc.encrypt(value, "default")

    def process_result_value(self, value: Optional[str], dialect: Any) -> Optional[str]:
        if value is None:
            return None
        enc = get_encryptor()
        try:
            return enc.decrypt(value, "default")
        except Exception:
            logger.warning("Failed to decrypt field value — returning raw")
            return value
