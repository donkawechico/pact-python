from __future__ import annotations

import base64
import json
import os
import re
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .models import (
    PactKeyHandling,
    PactPackedEncoding,
    PactPayloadLayout,
    PactProfile,
    PactProtocolConfig,
    PactRuntimeConfig,
)


class PactEngine:
    def encrypt(self, plaintext: str) -> str:
        raise NotImplementedError

    def decrypt(self, payload: str) -> str:
        raise NotImplementedError

    def matches_encrypted_payload(self, value: str) -> bool:
        raise NotImplementedError

    def find_encrypted_payloads(self, text: str) -> list[str]:
        if not text.strip():
            return []
        results: list[str] = []
        seen: set[str] = set()
        for token in re.split(r"\s+", text):
            for candidate in _candidate_tokens(token):
                if candidate not in seen and self.matches_encrypted_payload(candidate):
                    seen.add(candidate)
                    results.append(candidate)
        return results


class _DefaultPactEngine(PactEngine):
    def __init__(self, config: PactRuntimeConfig, secret: str) -> None:
        self.config = config
        self._secret = secret

    def encrypt(self, plaintext: str) -> str:
        if self.config.key_handling == PactKeyHandling.PASSPHRASE_PBKDF2:
            salt = _random_bytes(self.config.crypto.kdf.salt_bytes if self.config.crypto and self.config.crypto.kdf else 16)
            iv = _random_bytes(self.config.crypto.iv_bytes if self.config.crypto else 12)
            return self.encrypt_deterministic(plaintext, salt=salt, iv=iv)
        iv = _random_bytes(self.config.crypto.iv_bytes if self.config.crypto else 12)
        return self.encrypt_deterministic(plaintext, iv=iv)

    def encrypt_deterministic(self, plaintext: str, iv: bytes, salt: bytes | None = None) -> str:
        if self.config.key_handling == PactKeyHandling.PASSPHRASE_PBKDF2:
            if salt is None:
                raise ValueError("Passphrase mode requires a salt")
            key = _derive_key(
                self._secret,
                salt,
                self.config.crypto.kdf.iterations if self.config.crypto and self.config.crypto.kdf else 120_000,
            )
            ciphertext = _encrypt_text_with_key(plaintext, key, iv)
            if self.config.payload_layout == PactPayloadLayout.MULTIPART:
                return self.config.multipart_separator.join(
                    [
                        self.config.message_prefix,
                        _encode_segment(salt, self.config.packed_encoding, self.config.char_remap),
                        _encode_segment(iv, self.config.packed_encoding, self.config.char_remap),
                        _encode_segment(ciphertext, self.config.packed_encoding, self.config.char_remap),
                    ]
                )
            return self.config.message_prefix + _encode_segment(
                salt + iv + ciphertext,
                self.config.packed_encoding,
                self.config.char_remap,
            )

        ciphertext = _encrypt_text_with_key(plaintext, _decode_raw_aes_key(self._secret), iv)
        if self.config.payload_layout == PactPayloadLayout.MULTIPART:
            return self.config.multipart_separator.join(
                [
                    self.config.message_prefix,
                    _encode_segment(iv, self.config.packed_encoding, self.config.char_remap),
                    _encode_segment(ciphertext, self.config.packed_encoding, self.config.char_remap),
                ]
            )
        return self.config.message_prefix + _encode_segment(iv + ciphertext, self.config.packed_encoding, self.config.char_remap)

    def decrypt(self, payload: str) -> str:
        if self.config.payload_layout == PactPayloadLayout.MULTIPART:
            return self._decrypt_multipart(payload)
        return self._decrypt_packed(payload)

    def matches_encrypted_payload(self, value: str) -> bool:
        try:
            if self.config.payload_layout == PactPayloadLayout.MULTIPART:
                parts = value.split(self.config.multipart_separator)
                expected_parts = 4 if self.config.key_handling == PactKeyHandling.PASSPHRASE_PBKDF2 else 3
                return (
                    len(parts) == expected_parts
                    and parts[0] == self.config.message_prefix
                    and all(_decode_segment(part, self.config.packed_encoding, self.config.char_remap) is not None for part in parts[1:])
                )
            encoded = value.removeprefix(self.config.message_prefix)
            return (
                value.startswith(self.config.message_prefix)
                and encoded != ""
                and _decode_segment(encoded, self.config.packed_encoding, self.config.char_remap) is not None
            )
        except Exception:
            return False

    def _decrypt_multipart(self, payload: str) -> str:
        parts = payload.split(self.config.multipart_separator)
        if not parts or parts[0] != self.config.message_prefix:
            raise ValueError("Unsupported payload format")
        if self.config.key_handling == PactKeyHandling.PASSPHRASE_PBKDF2:
            if len(parts) != 4:
                raise ValueError("Unsupported payload format")
            salt = _require_decoded(parts[1], self.config)
            iv = _require_decoded(parts[2], self.config)
            ciphertext = _require_decoded(parts[3], self.config)
            key = _derive_key(
                self._secret,
                salt,
                self.config.crypto.kdf.iterations if self.config.crypto and self.config.crypto.kdf else 120_000,
            )
            return _decrypt_text_with_key(ciphertext, key, iv)
        if len(parts) != 3:
            raise ValueError("Unsupported payload format")
        iv = _require_decoded(parts[1], self.config)
        ciphertext = _require_decoded(parts[2], self.config)
        key = _decode_raw_aes_key(self._secret)
        return _decrypt_text_with_key(ciphertext, key, iv)

    def _decrypt_packed(self, payload: str) -> str:
        if not payload.startswith(self.config.message_prefix):
            raise ValueError("Unsupported payload format")
        packed_bytes = _require_decoded(payload.removeprefix(self.config.message_prefix), self.config)
        if self.config.key_handling == PactKeyHandling.PASSPHRASE_PBKDF2:
            salt_bytes = self.config.crypto.kdf.salt_bytes if self.config.crypto and self.config.crypto.kdf else 16
            iv_bytes = self.config.crypto.iv_bytes if self.config.crypto else 12
            if len(packed_bytes) <= salt_bytes + iv_bytes:
                raise ValueError("Packed payload too short")
            salt = packed_bytes[:salt_bytes]
            iv = packed_bytes[salt_bytes:salt_bytes + iv_bytes]
            ciphertext = packed_bytes[salt_bytes + iv_bytes:]
            key = _derive_key(
                self._secret,
                salt,
                self.config.crypto.kdf.iterations if self.config.crypto and self.config.crypto.kdf else 120_000,
            )
            return _decrypt_text_with_key(ciphertext, key, iv)
        iv_bytes = self.config.crypto.iv_bytes if self.config.crypto else 12
        if len(packed_bytes) <= iv_bytes:
            raise ValueError("Packed payload too short")
        iv = packed_bytes[:iv_bytes]
        ciphertext = packed_bytes[iv_bytes:]
        return _decrypt_text_with_key(ciphertext, _decode_raw_aes_key(self._secret), iv)


class _BoxPactEngine(PactEngine):
    def __init__(self, config: PactRuntimeConfig, secret: str | None) -> None:
        self.config = config
        self._secret = secret

    def encrypt(self, plaintext: str) -> str:
        payload_key = _random_bytes(32)
        payload_iv = _random_bytes(12)
        ephemeral_private_key = _random_bytes(32)
        return self.encrypt_deterministic(
            plaintext,
            payload_key=payload_key,
            payload_iv=payload_iv,
            ephemeral_private_key=ephemeral_private_key,
        )

    def encrypt_deterministic(
        self,
        plaintext: str,
        payload_key: bytes,
        payload_iv: bytes,
        ephemeral_private_key: bytes,
    ) -> str:
        if len(payload_key) != 32:
            raise ValueError("PACT box1 payload key must be 32 bytes")
        if len(payload_iv) != 12:
            raise ValueError("PACT box1 payload IV must be 12 bytes")
        if len(ephemeral_private_key) != 32:
            raise ValueError("PACT box1 ephemeral private key must be 32 bytes")
        if not self.config.recipients:
            raise ValueError("PACT box1 requires at least one recipient")

        ephemeral_private = x25519.X25519PrivateKey.from_private_bytes(ephemeral_private_key)
        ephemeral_public = ephemeral_private.public_key().public_bytes_raw()
        payload_ciphertext = _encrypt_text_with_key(plaintext, payload_key, payload_iv)

        recipients_payload = []
        for recipient in self.config.recipients:
            recipient_public = _decode_x25519_public_key(recipient.public_key)
            wrap_key, wrap_iv = _derive_box_wrap_key(ephemeral_private, recipient_public)
            wrapped_key = _encrypt_bytes_with_key(payload_key, wrap_key, wrap_iv)
            recipients_payload.append(
                {
                    "keyId": recipient.key_id,
                    "wrappedKey": _encode_base64url_bytes(wrapped_key),
                }
            )

        payload_json = {
            "profile": "pact-box1",
            "ephemeralPublicKey": _encode_base64url_bytes(ephemeral_public),
            "payloadIv": _encode_base64url_bytes(payload_iv),
            "recipients": recipients_payload,
            "ciphertext": _encode_base64url_bytes(payload_ciphertext),
        }
        encoded = _encode_base64url_bytes(_compact_json(payload_json).encode("utf-8"))
        return f"{self.config.message_prefix}{encoded}"

    def decrypt(self, payload: str) -> str:
        if not self._secret:
            raise ValueError("PACT box1 decryption requires an X25519 private key")
        private_key = _decode_x25519_private_key(self._secret)
        parsed = _parse_box_payload(payload, self.config.message_prefix)

        ephemeral_public = _decode_x25519_public_key(parsed["ephemeralPublicKey"])
        payload_key: bytes | None = None
        for recipient in parsed["recipients"]:
            try:
                wrap_key, wrap_iv = _derive_box_wrap_key(private_key, ephemeral_public)
                payload_key = _decrypt_bytes_with_key(
                    _decode_base64url_bytes(recipient["wrappedKey"]),
                    wrap_key,
                    wrap_iv,
                )
                break
            except Exception:
                continue
        if payload_key is None:
            raise ValueError("No wrapped payload key could be decrypted with the provided private key")

        return _decrypt_text_with_key(
            _decode_base64url_bytes(parsed["ciphertext"]),
            payload_key,
            _decode_base64url_bytes(parsed["payloadIv"]),
        )

    def matches_encrypted_payload(self, value: str) -> bool:
        try:
            _parse_box_payload(value, self.config.message_prefix)
            return True
        except Exception:
            return False


class PactEngineFactory:
    @staticmethod
    def create(config: PactProtocolConfig | PactRuntimeConfig, secret: str | None = None) -> PactEngine:
        runtime_config = config.normalize() if isinstance(config, PactProtocolConfig) else config
        validation = PactSecretValidator.validate(runtime_config, secret)
        if not validation.is_valid:
            raise ValueError(validation.message or "Invalid secret")
        if runtime_config.profile == PactProfile.PACT_BOX1:
            return _BoxPactEngine(runtime_config, secret)
        return _DefaultPactEngine(runtime_config, secret or "")

    @staticmethod
    def encrypt_deterministic(
        runtime_config: PactRuntimeConfig,
        plaintext: str,
        secret: str | None = None,
        iv: bytes | None = None,
        salt: bytes | None = None,
        payload_key: bytes | None = None,
        ephemeral_private_key: bytes | None = None,
    ) -> str:
        validation = PactSecretValidator.validate(runtime_config, secret)
        if not validation.is_valid:
            raise ValueError(validation.message or "Invalid secret")
        if runtime_config.profile == PactProfile.PACT_BOX1:
            return _BoxPactEngine(runtime_config, secret).encrypt_deterministic(
                plaintext,
                payload_key=payload_key or b"",
                payload_iv=iv or b"",
                ephemeral_private_key=ephemeral_private_key or b"",
            )
        if iv is None:
            raise ValueError("Deterministic encrypt requires iv")
        return _DefaultPactEngine(runtime_config, secret or "").encrypt_deterministic(
            plaintext,
            iv=iv,
            salt=salt,
        )


@dataclass(frozen=True)
class ValidationResult:
    is_valid: bool
    message: str | None = None

    @classmethod
    def valid(cls) -> ValidationResult:
        return cls(True, None)

    @classmethod
    def invalid(cls, message: str) -> ValidationResult:
        return cls(False, message)


class PactSecretValidator:
    @staticmethod
    def validate(config: PactRuntimeConfig, secret: str | None) -> ValidationResult:
        if config.profile == PactProfile.PACT_BOX1:
            if not secret or not secret.strip():
                return ValidationResult.valid()
            try:
                _decode_x25519_private_key(secret)
            except Exception:
                return ValidationResult.invalid("X25519 private key must decode to 32 bytes")
            return ValidationResult.valid()

        if not secret or not secret.strip():
            return ValidationResult.invalid("Secret cannot be blank")
        if config.key_handling == PactKeyHandling.PASSPHRASE_PBKDF2:
            return ValidationResult.valid()
        try:
            _decode_raw_aes_key(secret)
        except Exception:
            return ValidationResult.invalid("Raw AES key must decode to 16 or 32 bytes")
        return ValidationResult.valid()


def _random_bytes(length: int) -> bytes:
    return os.urandom(length)


def _candidate_tokens(token: str) -> list[str]:
    if not token.strip():
        return []
    trimmed = token.strip()
    trailing = trimmed.rstrip(".,!?)]}\"'")
    return [candidate for candidate in dict.fromkeys([trimmed, trailing]) if candidate]


def _derive_key(passphrase: str, salt: bytes, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def _derive_box_wrap_key(
    private_key: x25519.X25519PrivateKey,
    public_key: x25519.X25519PublicKey,
) -> tuple[bytes, bytes]:
    shared_secret = private_key.exchange(public_key)
    expanded = HKDF(
        algorithm=hashes.SHA256(),
        length=44,
        salt=None,
        info=b"pact-box1-wrap",
    ).derive(shared_secret)
    return expanded[:32], expanded[32:44]


def _encrypt_text_with_key(plaintext: str, key: bytes, iv: bytes) -> bytes:
    return AESGCM(key).encrypt(iv, plaintext.encode("utf-8"), None)


def _encrypt_bytes_with_key(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    return AESGCM(key).encrypt(iv, plaintext, None)


def _decrypt_text_with_key(ciphertext: bytes, key: bytes, iv: bytes) -> str:
    return AESGCM(key).decrypt(iv, ciphertext, None).decode("utf-8")


def _decrypt_bytes_with_key(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    return AESGCM(key).decrypt(iv, ciphertext, None)


def _apply_char_remap(value: str, remap: dict[str, str]) -> str:
    if not remap:
        return value
    return "".join(remap.get(char, char) for char in value)


def _invert_char_remap(value: str, remap: dict[str, str]) -> str:
    if not remap:
        return value
    inverse = {mapped: original for original, mapped in remap.items()}
    return "".join(inverse.get(char, char) for char in value)


def _encode_segment(value: bytes, encoding: PactPackedEncoding, remap: dict[str, str]) -> str:
    if encoding == PactPackedEncoding.URL_SAFE_NO_PADDING:
        encoded = base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")
    elif encoding == PactPackedEncoding.STANDARD_NO_PADDING:
        encoded = base64.b64encode(value).rstrip(b"=").decode("ascii")
    else:
        encoded = base64.a85encode(value, adobe=False, pad=False).decode("ascii")
    return _apply_char_remap(encoded, remap)


def _decode_segment(value: str, encoding: PactPackedEncoding, remap: dict[str, str]) -> bytes | None:
    normalized = _invert_char_remap(value, remap)
    try:
        if encoding == PactPackedEncoding.URL_SAFE_NO_PADDING:
            padded = normalized + ("=" * ((4 - len(normalized) % 4) % 4))
            return base64.urlsafe_b64decode(padded.encode("ascii"))
        if encoding == PactPackedEncoding.STANDARD_NO_PADDING:
            return _decode_flexible_base64(normalized)
        return base64.a85decode(normalized.encode("ascii"), adobe=False)
    except Exception:
        return None


def _require_decoded(value: str, config: PactRuntimeConfig) -> bytes:
    decoded = _decode_segment(value, config.packed_encoding, config.char_remap)
    if decoded is None:
        raise ValueError("Unsupported payload format")
    return decoded


def _decode_flexible_base64(value: str) -> bytes:
    normalized = value.replace(".", "+").replace("!", "/").replace("-", "+").replace("_", "/")
    padded = normalized + ("=" * ((4 - len(normalized) % 4) % 4))
    return base64.b64decode(padded.encode("ascii"), validate=True)


def _decode_raw_aes_key(value: str) -> bytes:
    raw = _decode_flexible_base64(value)
    if len(raw) not in {16, 32}:
        raise ValueError("Raw AES key must decode to 16 or 32 bytes")
    return raw


def _decode_x25519_private_key(value: str) -> x25519.X25519PrivateKey:
    raw = _decode_base64url_bytes(value)
    if len(raw) != 32:
        raise ValueError("X25519 private key must decode to 32 bytes")
    return x25519.X25519PrivateKey.from_private_bytes(raw)


def _decode_x25519_public_key(value: str) -> x25519.X25519PublicKey:
    raw = _decode_base64url_bytes(value)
    if len(raw) != 32:
        raise ValueError("X25519 public key must decode to 32 bytes")
    return x25519.X25519PublicKey.from_public_bytes(raw)


def _encode_base64url_bytes(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode_base64url_bytes(value: str) -> bytes:
    padded = value + ("=" * ((4 - len(value) % 4) % 4))
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def _compact_json(value: dict[str, object]) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True)


def _parse_box_payload(payload: str, message_prefix: str) -> dict[str, object]:
    if not payload.startswith(message_prefix):
        raise ValueError("Unsupported payload format")
    encoded = payload.removeprefix(message_prefix)
    root = json.loads(_decode_base64url_bytes(encoded).decode("utf-8"))
    if root.get("profile") != "pact-box1":
        raise ValueError("Unsupported payload format")
    recipients = root.get("recipients")
    if not isinstance(recipients, list) or not recipients:
        raise ValueError("Unsupported payload format")
    if not isinstance(root.get("ephemeralPublicKey"), str):
        raise ValueError("Unsupported payload format")
    if not isinstance(root.get("payloadIv"), str):
        raise ValueError("Unsupported payload format")
    if not isinstance(root.get("ciphertext"), str):
        raise ValueError("Unsupported payload format")
    for recipient in recipients:
        if not isinstance(recipient, dict):
            raise ValueError("Unsupported payload format")
        if not isinstance(recipient.get("keyId"), str) or not isinstance(recipient.get("wrappedKey"), str):
            raise ValueError("Unsupported payload format")
    return root
