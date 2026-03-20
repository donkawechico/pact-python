from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class PactProfile(str, Enum):
    PACT_PSK1 = "PACT_PSK1"
    PACT_BOX1 = "PACT_BOX1"


class PactKeyHandling(str, Enum):
    PASSPHRASE_PBKDF2 = "PASSPHRASE_PBKDF2"
    RAW_BASE64_KEY = "RAW_BASE64_KEY"


class PactPayloadLayout(str, Enum):
    MULTIPART = "MULTIPART"
    PACKED = "PACKED"


class PactPackedEncoding(str, Enum):
    URL_SAFE_NO_PADDING = "URL_SAFE_NO_PADDING"
    STANDARD_NO_PADDING = "STANDARD_NO_PADDING"
    ASCII85 = "ASCII85"


@dataclass(frozen=True)
class PactRecipient:
    key_id: str
    public_key: str


@dataclass(frozen=True)
class PactProfileData:
    recipients: list[PactRecipient] = field(default_factory=list)


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
    profile: PactProfile | None = None
    recipients: list[PactRecipient] = field(default_factory=list)
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
        if self.profile == PactProfile.PACT_BOX1:
            if not self.recipients:
                raise ValueError("PACT box1 runtime configs require at least one recipient")
            return PactProtocolConfig(
                message_prefix=self.message_prefix,
                profile=PactProfile.PACT_BOX1,
                profile_data=PactProfileData(recipients=list(self.recipients)),
            )

        if self.key_handling != PactKeyHandling.RAW_BASE64_KEY:
            raise ValueError("Only raw-key runtime configs can be expressed as pact-psk1")
        if self.payload_layout != PactPayloadLayout.PACKED:
            raise ValueError("Only packed runtime configs can be expressed as pact-psk1")
        if self.packed_encoding != PactPackedEncoding.ASCII85:
            raise ValueError("Only ASCII85 packed runtime configs can be expressed as pact-psk1")
        if self.char_remap:
            raise ValueError("PACT psk1 does not support character remapping")
        if self.crypto != PactCryptoMetadata.default_for(PactKeyHandling.RAW_BASE64_KEY):
            raise ValueError("Only default AES-256-GCM raw-key crypto can be expressed as pact-psk1")

        return PactProtocolConfig(
            message_prefix=self.message_prefix,
            profile=PactProfile.PACT_PSK1,
        )


@dataclass(frozen=True)
class PactProtocolConfig:
    message_prefix: str
    profile: PactProfile
    profile_data: PactProfileData = field(default_factory=PactProfileData)
    extra_fields: dict[str, object] = field(default_factory=dict)

    def normalize(self) -> PactRuntimeConfig:
        if not self.message_prefix.strip():
            raise ValueError("Message prefix cannot be blank")

        if self.profile == PactProfile.PACT_PSK1:
            return PactRuntimeConfig(
                message_prefix=self.message_prefix,
                profile=PactProfile.PACT_PSK1,
                key_handling=PactKeyHandling.RAW_BASE64_KEY,
                payload_layout=PactPayloadLayout.PACKED,
                packed_encoding=PactPackedEncoding.ASCII85,
                char_remap={},
                crypto=PactCryptoMetadata.default_for(PactKeyHandling.RAW_BASE64_KEY),
            )

        return PactRuntimeConfig(
            message_prefix=self.message_prefix,
            profile=PactProfile.PACT_BOX1,
            recipients=list(self.profile_data.recipients),
        )
