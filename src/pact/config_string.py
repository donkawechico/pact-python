from __future__ import annotations

import base64
import json
from typing import Any

from .models import (
    PactCryptoMetadata,
    PactKdfMetadata,
    PactKeyHandling,
    PactPackedEncoding,
    PactPayloadLayout,
    PactProtocolConfig,
)


class PactConfigString:
    _PREFIX = "pact"
    _VERSION = "v1"
    _DOT_BANG_ALIAS = "dot-bang-base64-no-padding"
    _DOT_BANG_REMAP = {"+": ".", "/": "!"}

    @classmethod
    def parse(cls, value: str) -> PactProtocolConfig:
        trimmed = value.strip()
        prefix = f"{cls._PREFIX}:{cls._VERSION}:"
        if not trimmed.startswith(prefix):
            raise ValueError(f"Config string must start with {prefix}")
        encoded_body = trimmed.removeprefix(prefix)
        root = json.loads(_decode_url_safe(encoded_body))

        message_prefix = _required_string(root, "messagePrefix")
        key_handling = cls._parse_key_handling(_required_string(root, "keyHandling"))
        payload_layout = cls._parse_payload_layout(_required_string(root, "payloadLayout"))
        multipart_separator = _optional_string(root, "multipartSeparator")
        packed_encoding_token = _optional_string(root, "packedEncoding")
        packed_encoding = cls._parse_packed_encoding(packed_encoding_token) if packed_encoding_token else None
        parsed_char_remap = _parse_char_remap(root.get("charRemap"))
        is_dot_bang_alias = (packed_encoding_token or "").lower() == cls._DOT_BANG_ALIAS
        if is_dot_bang_alias and parsed_char_remap and parsed_char_remap != cls._DOT_BANG_REMAP:
            raise ValueError("dot-bang-base64-no-padding cannot be combined with a conflicting charRemap")
        char_remap = cls._DOT_BANG_REMAP if is_dot_bang_alias else parsed_char_remap
        crypto = _parse_crypto_metadata(root.get("crypto"))

        known_keys = {
            "messagePrefix",
            "keyHandling",
            "payloadLayout",
            "multipartSeparator",
            "packedEncoding",
            "charRemap",
            "crypto",
            "protocolVersion",
        }
        extra_fields = {key: root[key] for key in sorted(root.keys()) if key not in known_keys}
        return PactProtocolConfig(
            message_prefix=message_prefix,
            key_handling=key_handling,
            payload_layout=payload_layout,
            multipart_separator=multipart_separator,
            packed_encoding=packed_encoding,
            char_remap=char_remap,
            crypto=crypto,
            extra_fields=extra_fields,
        )

    @classmethod
    def serialize(cls, config: PactProtocolConfig) -> str:
        use_dot_bang_alias = (
            config.packed_encoding == PactPackedEncoding.STANDARD_NO_PADDING
            and config.char_remap == cls._DOT_BANG_REMAP
        )
        root: dict[str, Any] = {
            "messagePrefix": config.message_prefix,
            "keyHandling": cls._serialize_key_handling(config.key_handling),
            "payloadLayout": cls._serialize_payload_layout(config.payload_layout),
        }
        if config.multipart_separator is not None:
            root["multipartSeparator"] = config.multipart_separator
        if config.packed_encoding is not None:
            root["packedEncoding"] = (
                cls._DOT_BANG_ALIAS
                if use_dot_bang_alias
                else cls._serialize_packed_encoding(config.packed_encoding)
            )
        if config.char_remap and not use_dot_bang_alias:
            root["charRemap"] = {key: config.char_remap[key] for key in sorted(config.char_remap)}
        if config.crypto is not None:
            root["crypto"] = _crypto_to_json(config.crypto)
        for key in sorted(config.extra_fields):
            if key not in root:
                root[key] = config.extra_fields[key]
        return f"{cls._PREFIX}:{cls._VERSION}:{_encode_url_safe(_compact_json(root))}"

    @staticmethod
    def _parse_key_handling(value: str) -> PactKeyHandling:
        normalized = value.lower()
        if normalized in {"passphrase-pbkdf2", "passphrase_pbkdf2"}:
            return PactKeyHandling.PASSPHRASE_PBKDF2
        if normalized in {"raw-base64-key", "raw_base64_key"}:
            return PactKeyHandling.RAW_BASE64_KEY
        raise ValueError(f"Unsupported key handling: {value}")

    @staticmethod
    def _parse_payload_layout(value: str) -> PactPayloadLayout:
        normalized = value.lower()
        if normalized == "multipart":
            return PactPayloadLayout.MULTIPART
        if normalized == "packed":
            return PactPayloadLayout.PACKED
        raise ValueError(f"Unsupported payload layout: {value}")

    @classmethod
    def _parse_packed_encoding(cls, value: str) -> PactPackedEncoding:
        normalized = value.lower()
        if normalized in {"base64url-no-padding", "url-safe-base64-no-padding", "url_safe_no_padding"}:
            return PactPackedEncoding.URL_SAFE_NO_PADDING
        if normalized in {
            "base64-standard-no-padding",
            "standard-base64-no-padding",
            "standard_no_padding",
            cls._DOT_BANG_ALIAS,
        }:
            return PactPackedEncoding.STANDARD_NO_PADDING
        raise ValueError(f"Unsupported packed encoding: {value}")

    @staticmethod
    def _serialize_key_handling(value: PactKeyHandling) -> str:
        if value == PactKeyHandling.PASSPHRASE_PBKDF2:
            return "passphrase-pbkdf2"
        return "raw-base64-key"

    @staticmethod
    def _serialize_payload_layout(value: PactPayloadLayout) -> str:
        if value == PactPayloadLayout.MULTIPART:
            return "multipart"
        return "packed"

    @staticmethod
    def _serialize_packed_encoding(value: PactPackedEncoding) -> str:
        if value == PactPackedEncoding.URL_SAFE_NO_PADDING:
            return "base64url-no-padding"
        return "base64-standard-no-padding"


def _required_string(root: dict[str, Any], key: str) -> str:
    value = root.get(key)
    if not isinstance(value, str):
        raise ValueError(f"Missing required field: {key}")
    return value


def _optional_string(root: dict[str, Any], key: str) -> str | None:
    value = root.get(key)
    return value if isinstance(value, str) else None


def _parse_char_remap(value: Any) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError("charRemap must be an object")
    remap: dict[str, str] = {}
    for key, mapped in value.items():
        if not isinstance(key, str) or len(key) != 1:
            raise ValueError("Char remap keys must be single characters")
        if not isinstance(mapped, str) or len(mapped) != 1:
            raise ValueError("Char remap values must be single characters")
        remap[key] = mapped
    return remap


def _parse_crypto_metadata(value: Any) -> PactCryptoMetadata | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError("crypto must be an object")
    kdf_value = value.get("kdf")
    kdf = None
    if kdf_value is not None:
        if not isinstance(kdf_value, dict):
            raise ValueError("kdf must be an object")
        kdf = PactKdfMetadata(
            type=_optional_string(kdf_value, "type"),
            iterations=kdf_value.get("iterations"),
            salt_bytes=kdf_value.get("saltBytes"),
        )
    return PactCryptoMetadata(
        algorithm=_optional_string(value, "algorithm"),
        iv_bytes=value.get("ivBytes"),
        tag_bits=value.get("tagBits"),
        kdf=kdf,
    )


def _crypto_to_json(value: PactCryptoMetadata) -> dict[str, Any]:
    root: dict[str, Any] = {}
    if value.algorithm is not None:
        root["algorithm"] = value.algorithm
    if value.iv_bytes is not None:
        root["ivBytes"] = value.iv_bytes
    if value.tag_bits is not None:
        root["tagBits"] = value.tag_bits
    if value.kdf is not None:
        kdf: dict[str, Any] = {}
        if value.kdf.type is not None:
            kdf["type"] = value.kdf.type
        if value.kdf.iterations is not None:
            kdf["iterations"] = value.kdf.iterations
        if value.kdf.salt_bytes is not None:
            kdf["saltBytes"] = value.kdf.salt_bytes
        root["kdf"] = kdf
    return root


def _compact_json(value: dict[str, Any]) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True)


def _encode_url_safe(value: str) -> str:
    return base64.urlsafe_b64encode(value.encode("utf-8")).rstrip(b"=").decode("ascii")


def _decode_url_safe(value: str) -> str:
    padded = value + ("=" * ((4 - len(value) % 4) % 4))
    return base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
