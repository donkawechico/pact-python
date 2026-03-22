from __future__ import annotations

import base64
import json
from typing import Any

from .models import PactProfile, PactProfileData, PactProtocolConfig, PactRecipient, PactTransportData


class PactConfigString:
    _PREFIX = "pact"
    _VERSION = "v1"

    @classmethod
    def parse(cls, value: str) -> PactProtocolConfig:
        trimmed = value.strip()
        prefix = f"{cls._PREFIX}:{cls._VERSION}:"
        if not trimmed.startswith(prefix):
            raise ValueError(f"Config string must start with {prefix}")
        encoded_body = trimmed.removeprefix(prefix)
        root = json.loads(_decode_url_safe(encoded_body))

        message_prefix = _required_string(root, "messagePrefix", error_message="Missing required field: messagePrefix")
        profile = cls._parse_profile(_required_string(root, "profile", error_message="Missing required field: profile"))
        profile_data = cls._parse_profile_data(profile, root.get("profileData"))
        transport_data = cls._parse_transport_data(root.get("transportData"))

        known_keys = {"messagePrefix", "profile", "profileData", "transportData", "protocolVersion"}
        extra_fields = {key: root[key] for key in sorted(root.keys()) if key not in known_keys}
        return PactProtocolConfig(
            message_prefix=message_prefix,
            profile=profile,
            profile_data=profile_data,
            transport_data=transport_data,
            extra_fields=extra_fields,
        )

    @classmethod
    def serialize(cls, config: PactProtocolConfig) -> str:
        root: dict[str, Any] = {
            "messagePrefix": config.message_prefix,
            "profile": cls._serialize_profile(config.profile),
        }
        profile_data_json = _profile_data_to_json(config.profile, config.profile_data)
        if profile_data_json is not None:
            root["profileData"] = profile_data_json
        transport_data_json = _transport_data_to_json(config.transport_data)
        if transport_data_json is not None:
            root["transportData"] = transport_data_json
        for key in sorted(config.extra_fields):
            if key not in root:
                root[key] = config.extra_fields[key]
        return f"{cls._PREFIX}:{cls._VERSION}:{_encode_url_safe(_compact_json(root))}"

    @staticmethod
    def _parse_profile(value: str) -> PactProfile:
        normalized = value.lower()
        if normalized == "pact-psk1":
            return PactProfile.PACT_PSK1
        if normalized == "pact-psk2":
            return PactProfile.PACT_PSK2
        if normalized == "pact-box1":
            return PactProfile.PACT_BOX1
        raise ValueError(f"Unknown profile: {value}")

    @staticmethod
    def _serialize_profile(value: PactProfile) -> str:
        if value == PactProfile.PACT_PSK1:
            return "pact-psk1"
        if value == PactProfile.PACT_PSK2:
            return "pact-psk2"
        return "pact-box1"

    @classmethod
    def _parse_profile_data(cls, profile: PactProfile, value: Any) -> PactProfileData:
        if profile == PactProfile.PACT_PSK1:
            if value is not None and (not isinstance(value, dict) or value):
                raise ValueError("PACT psk1 does not allow non-empty profileData")
            return PactProfileData()
        if profile == PactProfile.PACT_PSK2:
            if value is not None and (not isinstance(value, dict) or value):
                raise ValueError("PACT psk2 does not allow non-empty profileData")
            return PactProfileData()

        if not isinstance(value, dict):
            raise ValueError("Missing required profile field: profileData.recipients")
        recipients_value = value.get("recipients")
        if not isinstance(recipients_value, list) or not recipients_value:
            raise ValueError("Missing required profile field: profileData.recipients")

        recipients: list[PactRecipient] = []
        for index, recipient_value in enumerate(recipients_value):
            if not isinstance(recipient_value, dict):
                raise ValueError("Missing required profile field: profileData.recipients")
            key_id = _required_string(
                recipient_value,
                "keyId",
                error_message=f"Missing required profile field: profileData.recipients[{index}].keyId",
            )
            public_key = _required_string(
                recipient_value,
                "publicKey",
                error_message=f"Missing required profile field: profileData.recipients[{index}].publicKey",
            )
            if not _is_valid_x25519_public_key(public_key):
                raise ValueError(f"Invalid X25519 public key: profileData.recipients[{index}].publicKey")
            recipients.append(PactRecipient(key_id=key_id, public_key=public_key))
        return PactProfileData(recipients=recipients)

    @staticmethod
    def _parse_transport_data(value: Any) -> PactTransportData:
        if value is None:
            return PactTransportData()
        if not isinstance(value, dict):
            raise ValueError("transportData must be an object")
        remap_value = value.get("charRemap")
        if remap_value is None:
            return PactTransportData()
        if not isinstance(remap_value, dict):
            raise ValueError("transportData.charRemap must be an object")
        remap: dict[str, str] = {}
        for key, mapped in sorted(remap_value.items()):
            if not isinstance(key, str) or len(key) != 1:
                raise ValueError("transportData.charRemap key must be a single character")
            if not isinstance(mapped, str) or len(mapped) != 1:
                raise ValueError("transportData.charRemap value must be a single character")
            remap[key] = mapped
        if len(set(remap.values())) != len(remap.values()):
            raise ValueError("Character remap values must be unique")
        return PactTransportData(char_remap=remap)


def _required_string(root: dict[str, Any], key: str, error_message: str) -> str:
    value = root.get(key)
    if not isinstance(value, str):
        raise ValueError(error_message)
    return value


def _profile_data_to_json(profile: PactProfile, profile_data: PactProfileData) -> dict[str, Any] | None:
    if profile in {PactProfile.PACT_PSK1, PactProfile.PACT_PSK2}:
        return None
    return {
        "recipients": [
            {
                "keyId": recipient.key_id,
                "publicKey": recipient.public_key,
            }
            for recipient in profile_data.recipients
        ],
    }


def _transport_data_to_json(transport_data: PactTransportData) -> dict[str, Any] | None:
    if not transport_data.char_remap:
        return None
    return {
        "charRemap": {
            key: transport_data.char_remap[key]
            for key in sorted(transport_data.char_remap)
        }
    }


def _is_valid_x25519_public_key(value: str) -> bool:
    try:
        decoded = _decode_base64url_bytes(value)
        return len(decoded) == 32
    except Exception:
        return False


def _compact_json(value: dict[str, Any]) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True)


def _encode_url_safe(value: str) -> str:
    return base64.urlsafe_b64encode(value.encode("utf-8")).rstrip(b"=").decode("ascii")


def _decode_url_safe(value: str) -> str:
    return _decode_base64url_bytes(value).decode("utf-8")


def _decode_base64url_bytes(value: str) -> bytes:
    padded = value + ("=" * ((4 - len(value) % 4) % 4))
    return base64.urlsafe_b64decode(padded.encode("ascii"))
