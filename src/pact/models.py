from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum


class PactProfile(str, Enum):
    PACT_PSK1 = "PACT_PSK1"
    PACT_PSK2 = "PACT_PSK2"
    PACT_BOX1 = "PACT_BOX1"

    @classmethod
    def from_wire_name(cls, value: str) -> PactProfile:
        normalized = value.lower()
        if normalized == "pact-psk1":
            return cls.PACT_PSK1
        if normalized == "pact-psk2":
            return cls.PACT_PSK2
        if normalized == "pact-box1":
            return cls.PACT_BOX1
        raise ValueError(f"Unknown profile: {value}")

    @property
    def wire_name(self) -> str:
        if self == PactProfile.PACT_PSK1:
            return "pact-psk1"
        if self == PactProfile.PACT_PSK2:
            return "pact-psk2"
        return "pact-box1"


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
class PactTransportData:
    char_remap: dict[str, str] = field(default_factory=dict)


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
                transport_data=PactTransportData(char_remap=dict(self.char_remap)),
            )

        if self.key_handling != PactKeyHandling.RAW_BASE64_KEY:
            raise ValueError("Only raw-key runtime configs can be expressed as PACT shared-secret profiles")
        if self.payload_layout != PactPayloadLayout.PACKED:
            raise ValueError("Only packed runtime configs can be expressed as PACT shared-secret profiles")
        if self.crypto != PactCryptoMetadata.default_for(PactKeyHandling.RAW_BASE64_KEY):
            raise ValueError("Only default AES-256-GCM raw-key crypto can be expressed as PACT shared-secret profiles")

        if self.packed_encoding == PactPackedEncoding.ASCII85:
            return PactProtocolConfig(
                message_prefix=self.message_prefix,
                profile=PactProfile.PACT_PSK1,
                transport_data=PactTransportData(char_remap=dict(self.char_remap)),
            )
        if self.packed_encoding == PactPackedEncoding.STANDARD_NO_PADDING and not self.char_remap:
            return PactProtocolConfig(
                message_prefix=self.message_prefix,
                profile=PactProfile.PACT_PSK2,
            )
        if self.packed_encoding == PactPackedEncoding.STANDARD_NO_PADDING:
            return PactProtocolConfig(
                message_prefix=self.message_prefix,
                profile=PactProfile.PACT_PSK2,
                transport_data=PactTransportData(char_remap=dict(self.char_remap)),
            )
        raise ValueError("Runtime config does not match a standard PACT shared-secret profile")


@dataclass(frozen=True)
class PactProtocolConfig:
    message_prefix: str
    profile: PactProfile
    profile_data: PactProfileData = field(default_factory=PactProfileData)
    transport_data: PactTransportData = field(default_factory=PactTransportData)
    extra_fields: dict[str, object] = field(default_factory=dict)

    def normalize(self) -> PactRuntimeConfig:
        if not self.message_prefix:
            raise ValueError("messagePrefix must not be empty")
        if self.message_prefix == "pact":
            raise ValueError("messagePrefix must not be pact")
        if "[" in self.message_prefix or "]" in self.message_prefix:
            raise ValueError("messagePrefix must not contain brackets")
        _validate_remap(self.transport_data.char_remap)

        if self.profile == PactProfile.PACT_PSK1:
            return PactRuntimeConfig(
                message_prefix=self.message_prefix,
                profile=PactProfile.PACT_PSK1,
                key_handling=PactKeyHandling.RAW_BASE64_KEY,
                payload_layout=PactPayloadLayout.PACKED,
                packed_encoding=PactPackedEncoding.ASCII85,
                char_remap=dict(self.transport_data.char_remap),
                crypto=PactCryptoMetadata.default_for(PactKeyHandling.RAW_BASE64_KEY),
            )

        if self.profile == PactProfile.PACT_PSK2:
            return PactRuntimeConfig(
                message_prefix=self.message_prefix,
                profile=PactProfile.PACT_PSK2,
                key_handling=PactKeyHandling.RAW_BASE64_KEY,
                payload_layout=PactPayloadLayout.PACKED,
                packed_encoding=PactPackedEncoding.STANDARD_NO_PADDING,
                char_remap=dict(self.transport_data.char_remap),
                crypto=PactCryptoMetadata.default_for(PactKeyHandling.RAW_BASE64_KEY),
            )

        return PactRuntimeConfig(
            message_prefix=self.message_prefix,
            profile=PactProfile.PACT_BOX1,
            recipients=list(self.profile_data.recipients),
            char_remap=dict(self.transport_data.char_remap),
        )

    def with_transport(self, message_prefix: str | None = None, char_remap: dict[str, str] | None = None) -> PactProtocolConfig:
        updated = replace(
            self,
            message_prefix=self.message_prefix if message_prefix is None else message_prefix,
            transport_data=self.transport_data if char_remap is None else PactTransportData(char_remap=dict(char_remap)),
        )
        updated.normalize()
        return updated

    def with_profile(self, profile: PactProfile | str, char_remap: dict[str, str] | None = None) -> PactProtocolConfig:
        updated_profile = PactProfile.from_wire_name(profile) if isinstance(profile, str) else profile
        updates: dict[str, object] = {"profile": updated_profile}
        if updated_profile in {PactProfile.PACT_PSK1, PactProfile.PACT_PSK2}:
            updates["profile_data"] = PactProfileData()
        if char_remap is not None:
            updates["transport_data"] = PactTransportData(char_remap=dict(char_remap))
        updated = replace(self, **updates)
        updated.normalize()
        return updated


def _validate_remap(remap: dict[str, str]) -> None:
    for key, value in remap.items():
        if len(key) != 1:
            raise ValueError("transportData.charRemap key must be a single character")
        if len(value) != 1:
            raise ValueError("transportData.charRemap value must be a single character")
    values = list(remap.values())
    if len(values) != len(set(values)):
        raise ValueError("Character remap values must be unique")
