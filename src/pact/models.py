from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class PactKeyHandling(str, Enum):
    PASSPHRASE_PBKDF2 = "PASSPHRASE_PBKDF2"
    RAW_BASE64_KEY = "RAW_BASE64_KEY"


class PactPayloadLayout(str, Enum):
    MULTIPART = "MULTIPART"
    PACKED = "PACKED"


class PactPackedEncoding(str, Enum):
    URL_SAFE_NO_PADDING = "URL_SAFE_NO_PADDING"
    STANDARD_NO_PADDING = "STANDARD_NO_PADDING"


@dataclass(frozen=True)
class PactKdfMetadata:
    type: str | None = None
    iterations: int | None = None
    salt_bytes: int | None = None


@dataclass(frozen=True)
class PactCryptoMetadata:
    algorithm: str | None = None
    iv_bytes: int | None = None
    tag_bits: int | None = None
    kdf: PactKdfMetadata | None = None

    def merge_and_validate(
        self,
        override: PactCryptoMetadata | None,
        key_handling: PactKeyHandling,
    ) -> PactCryptoMetadata:
        merged = PactCryptoMetadata(
            algorithm=override.algorithm if override and override.algorithm is not None else self.algorithm,
            iv_bytes=override.iv_bytes if override and override.iv_bytes is not None else self.iv_bytes,
            tag_bits=override.tag_bits if override and override.tag_bits is not None else self.tag_bits,
            kdf=override.kdf if override and override.kdf is not None else self.kdf,
        )
        if merged.algorithm != "aes-256-gcm":
            raise ValueError(f"Unsupported algorithm: {merged.algorithm}")
        if merged.iv_bytes != 12:
            raise ValueError(f"Unsupported IV size: {merged.iv_bytes}")
        if merged.tag_bits != 128:
            raise ValueError(f"Unsupported tag bits: {merged.tag_bits}")

        if key_handling == PactKeyHandling.PASSPHRASE_PBKDF2:
            kdf = merged.kdf
            if kdf is None:
                raise ValueError("PBKDF2 metadata is required for passphrase mode")
            if kdf.type != "pbkdf2-hmac-sha256":
                raise ValueError(f"Unsupported KDF: {kdf.type}")
            if kdf.iterations != 120_000:
                raise ValueError(f"Unsupported PBKDF2 iterations: {kdf.iterations}")
            if kdf.salt_bytes != 16:
                raise ValueError(f"Unsupported PBKDF2 salt bytes: {kdf.salt_bytes}")
        else:
            if merged.kdf is not None:
                raise ValueError("KDF metadata is not valid for raw key mode")

        return merged

    @classmethod
    def default_for(cls, key_handling: PactKeyHandling) -> PactCryptoMetadata:
        return PactCryptoMetadata(
            algorithm="aes-256-gcm",
            iv_bytes=12,
            tag_bits=128,
            kdf=(
                PactKdfMetadata(
                    type="pbkdf2-hmac-sha256",
                    iterations=120_000,
                    salt_bytes=16,
                )
                if key_handling == PactKeyHandling.PASSPHRASE_PBKDF2
                else None
            ),
        )


@dataclass(frozen=True)
class PactRuntimeConfig:
    message_prefix: str = "pact1"
    key_handling: PactKeyHandling = PactKeyHandling.PASSPHRASE_PBKDF2
    payload_layout: PactPayloadLayout = PactPayloadLayout.MULTIPART
    multipart_separator: str = ":"
    packed_encoding: PactPackedEncoding = PactPackedEncoding.URL_SAFE_NO_PADDING
    char_remap: dict[str, str] = field(default_factory=dict)
    crypto: PactCryptoMetadata | None = None

    def __post_init__(self) -> None:
        if self.crypto is None:
            object.__setattr__(self, "crypto", PactCryptoMetadata.default_for(self.key_handling))

    def to_protocol_config(self) -> PactProtocolConfig:
        return PactProtocolConfig(
            message_prefix=self.message_prefix,
            key_handling=self.key_handling,
            payload_layout=self.payload_layout,
            multipart_separator=self.multipart_separator,
            packed_encoding=self.packed_encoding,
            char_remap=dict(self.char_remap),
            crypto=self.crypto,
        )


@dataclass(frozen=True)
class PactProtocolConfig:
    message_prefix: str
    key_handling: PactKeyHandling
    payload_layout: PactPayloadLayout
    multipart_separator: str | None = None
    packed_encoding: PactPackedEncoding | None = None
    char_remap: dict[str, str] = field(default_factory=dict)
    crypto: PactCryptoMetadata | None = None
    extra_fields: dict[str, object] = field(default_factory=dict)

    def normalize(self) -> PactRuntimeConfig:
        separator = self.multipart_separator if self.multipart_separator is not None else ":"
        encoding = self.packed_encoding if self.packed_encoding is not None else PactPackedEncoding.URL_SAFE_NO_PADDING
        if not self.message_prefix.strip():
            raise ValueError("Message prefix cannot be blank")
        if self.payload_layout == PactPayloadLayout.MULTIPART and separator == "":
            raise ValueError("Multipart separator cannot be empty")
        _validate_remap(self.char_remap)
        normalized_crypto = PactCryptoMetadata.default_for(self.key_handling).merge_and_validate(
            self.crypto,
            self.key_handling,
        )
        return PactRuntimeConfig(
            message_prefix=self.message_prefix,
            key_handling=self.key_handling,
            payload_layout=self.payload_layout,
            multipart_separator=separator,
            packed_encoding=encoding,
            char_remap=dict(self.char_remap),
            crypto=normalized_crypto,
        )


def _validate_remap(remap: dict[str, str]) -> None:
    values = list(remap.values())
    if len(set(values)) != len(values):
        raise ValueError("Character remap values must be unique")
    for key, value in remap.items():
        if len(key) != 1:
            raise ValueError("Char remap keys must be single characters")
        if len(value) != 1:
            raise ValueError("Char remap values must be single characters")
