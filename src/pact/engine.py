from __future__ import annotations

import base64
import os
import re
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

from .models import PactKeyHandling, PactPackedEncoding, PactPayloadLayout, PactProtocolConfig, PactRuntimeConfig


class PactEngine:
    def __init__(self, config: PactRuntimeConfig, secret: str) -> None:
        self.config = config
        self._secret = secret

    def encrypt(self, plaintext: str) -> str:
        if self.config.key_handling == PactKeyHandling.PASSPHRASE_PBKDF2:
            salt = _random_bytes(self.config.crypto.kdf.salt_bytes if self.config.crypto and self.config.crypto.kdf else 16)
            iv = _random_bytes(self.config.crypto.iv_bytes if self.config.crypto else 12)
            return self._encrypt_passphrase(plaintext, salt, iv)
        iv = _random_bytes(self.config.crypto.iv_bytes if self.config.crypto else 12)
        return self._encrypt_raw_key(plaintext, iv)

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
            key = _derive_key(self._secret, salt, self.config.crypto.kdf.iterations if self.config.crypto and self.config.crypto.kdf else 120_000)
            return _decrypt_with_key(ciphertext, key, iv)
        if len(parts) != 3:
            raise ValueError("Unsupported payload format")
        iv = _require_decoded(parts[1], self.config)
        ciphertext = _require_decoded(parts[2], self.config)
        key = _decode_raw_aes_key(self._secret)
        return _decrypt_with_key(ciphertext, key, iv)

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
            key = _derive_key(self._secret, salt, self.config.crypto.kdf.iterations if self.config.crypto and self.config.crypto.kdf else 120_000)
            return _decrypt_with_key(ciphertext, key, iv)
        iv_bytes = self.config.crypto.iv_bytes if self.config.crypto else 12
        if len(packed_bytes) <= iv_bytes:
            raise ValueError("Packed payload too short")
        iv = packed_bytes[:iv_bytes]
        ciphertext = packed_bytes[iv_bytes:]
        return _decrypt_with_key(ciphertext, _decode_raw_aes_key(self._secret), iv)

    def _encrypt_passphrase(self, plaintext: str, salt: bytes, iv: bytes) -> str:
        key = _derive_key(self._secret, salt, self.config.crypto.kdf.iterations if self.config.crypto and self.config.crypto.kdf else 120_000)
        ciphertext = _encrypt_with_key(plaintext, key, iv)
        if self.config.payload_layout == PactPayloadLayout.MULTIPART:
            return self.config.multipart_separator.join(
                [
                    self.config.message_prefix,
                    _encode_segment(salt, self.config.packed_encoding, self.config.char_remap),
                    _encode_segment(iv, self.config.packed_encoding, self.config.char_remap),
                    _encode_segment(ciphertext, self.config.packed_encoding, self.config.char_remap),
                ]
            )
        return self.config.message_prefix + _encode_segment(salt + iv + ciphertext, self.config.packed_encoding, self.config.char_remap)

    def _encrypt_raw_key(self, plaintext: str, iv: bytes) -> str:
        ciphertext = _encrypt_with_key(plaintext, _decode_raw_aes_key(self._secret), iv)
        if self.config.payload_layout == PactPayloadLayout.MULTIPART:
            return self.config.multipart_separator.join(
                [
                    self.config.message_prefix,
                    _encode_segment(iv, self.config.packed_encoding, self.config.char_remap),
                    _encode_segment(ciphertext, self.config.packed_encoding, self.config.char_remap),
                ]
            )
        return self.config.message_prefix + _encode_segment(iv + ciphertext, self.config.packed_encoding, self.config.char_remap)


class PactEngineFactory:
    @staticmethod
    def create(config: PactProtocolConfig | PactRuntimeConfig, secret: str) -> PactEngine:
        runtime_config = config.normalize() if isinstance(config, PactProtocolConfig) else config
        validation = PactSecretValidator.validate(runtime_config, secret)
        if not validation.is_valid:
            raise ValueError(validation.message or "Invalid secret")
        return PactEngine(runtime_config, secret)


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
    def validate(config: PactRuntimeConfig, secret: str) -> ValidationResult:
        if not secret.strip():
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


def _encrypt_with_key(plaintext: str, key: bytes, iv: bytes) -> bytes:
    return AESGCM(key).encrypt(iv, plaintext.encode("utf-8"), None)


def _decrypt_with_key(ciphertext: bytes, key: bytes, iv: bytes) -> str:
    plaintext = AESGCM(key).decrypt(iv, ciphertext, None)
    return plaintext.decode("utf-8")


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
    else:
        encoded = base64.b64encode(value).rstrip(b"=").decode("ascii")
    return _apply_char_remap(encoded, remap)


def _decode_segment(value: str, encoding: PactPackedEncoding, remap: dict[str, str]) -> bytes | None:
    normalized = _invert_char_remap(value, remap)
    try:
        if encoding == PactPackedEncoding.URL_SAFE_NO_PADDING:
            padded = normalized + ("=" * ((4 - len(normalized) % 4) % 4))
            return base64.urlsafe_b64decode(padded.encode("ascii"))
        return _decode_flexible_base64(normalized)
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
