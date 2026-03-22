from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import pytest

from pact import (
    PactConfigString,
    PactEngineFactory,
    PactKeyHandling,
    PactPackedEncoding,
    PactPayloadLayout,
    PactProfile,
    PactProfileData,
    PactProtocolConfig,
    PactRecipient,
    PactRuntimeConfig,
    PactSecretValidator,
    PactTransportData,
)


def test_serializes_and_parses_canonical_config_strings() -> None:
    config = PactProtocolConfig(
        message_prefix="pact1:",
        profile=PactProfile.PACT_PSK1,
    )

    serialized = PactConfigString.serialize(config)
    parsed = PactConfigString.parse(serialized)

    assert parsed.message_prefix == config.message_prefix
    assert parsed.profile == config.profile
    assert parsed.profile_data == config.profile_data
    assert parsed.transport_data == config.transport_data


def test_rejects_malformed_config_strings() -> None:
    with pytest.raises(ValueError):
        PactConfigString.parse("not-a-config")


def test_preserves_unknown_fields_during_round_trip() -> None:
    raw = json.dumps(
        {
            "messagePrefix": "pact1:",
            "profile": "pact-psk1",
            "futureFlag": "on",
        },
        separators=(",", ":"),
    )
    encoded = base64.urlsafe_b64encode(raw.encode("utf-8")).rstrip(b"=").decode("ascii")

    parsed = PactConfigString.parse(f"pact:v1:{encoded}")
    reserialized = PactConfigString.serialize(parsed)
    reparsed = PactConfigString.parse(reserialized)

    assert reparsed.extra_fields["futureFlag"] == "on"


def test_psk1_normalization_maps_to_compact_raw_key_runtime_defaults() -> None:
    normalized = PactProtocolConfig(
        message_prefix="pact1:",
        profile=PactProfile.PACT_PSK1,
    ).normalize()

    assert normalized.message_prefix == "pact1:"
    assert normalized.key_handling == PactKeyHandling.RAW_BASE64_KEY
    assert normalized.payload_layout == PactPayloadLayout.PACKED
    assert normalized.packed_encoding == PactPackedEncoding.ASCII85
    assert normalized.char_remap == {}


def test_psk2_normalization_maps_to_plain_base64_raw_key_runtime_defaults() -> None:
    normalized = PactProtocolConfig(
        message_prefix="[ENC]",
        profile=PactProfile.PACT_PSK2,
    ).normalize()

    assert normalized.message_prefix == "[ENC]"
    assert normalized.key_handling == PactKeyHandling.RAW_BASE64_KEY
    assert normalized.payload_layout == PactPayloadLayout.PACKED
    assert normalized.packed_encoding == PactPackedEncoding.STANDARD_NO_PADDING
    assert normalized.char_remap == {}


def test_transport_remap_lives_outside_the_profile() -> None:
    config = PactProtocolConfig(
        message_prefix="[ENC]",
        profile=PactProfile.PACT_PSK2,
        transport_data=PactTransportData(
            char_remap={"+": ".", "/": "!"},
        ),
    )

    normalized = config.normalize()

    assert normalized.profile == PactProfile.PACT_PSK2
    assert normalized.char_remap == {"+": ".", "/": "!"}
    assert normalized.to_protocol_config() == config


def test_box1_normalization_preserves_recipients_and_supports_round_trip() -> None:
    config = PactProtocolConfig(
        message_prefix="pact1:",
        profile=PactProfile.PACT_BOX1,
        profile_data=PactProfileData(
            recipients=[
                PactRecipient(
                    key_id="alice-main",
                    public_key="B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9_AsrhtHHw",
                )
            ]
        ),
    )
    runtime = config.normalize()

    assert runtime.profile == PactProfile.PACT_BOX1
    assert runtime.recipients == config.profile_data.recipients

    ciphertext = PactEngineFactory.create(runtime).encrypt("hello box")
    decrypted = PactEngineFactory.create(
        runtime,
        "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA",
    ).decrypt(ciphertext)
    assert decrypted == "hello box"


def test_validates_raw_keys() -> None:
    config = PactRuntimeConfig(
        key_handling=PactKeyHandling.RAW_BASE64_KEY,
        payload_layout=PactPayloadLayout.PACKED,
        packed_encoding=PactPackedEncoding.STANDARD_NO_PADDING,
    )

    assert not PactSecretValidator.validate(config, "abcd").is_valid
    assert PactSecretValidator.validate(config, "AAAAAAAAAAAAAAAAAAAAAA==").is_valid


def test_fixture_configs_round_trip() -> None:
    for file in _fixture_files("config/valid"):
        fixture = json.loads(file.read_text())
        parsed = PactConfigString.parse(fixture["canonicalString"])
        assert PactConfigString.serialize(parsed) == fixture["canonicalString"]


def test_invalid_fixture_configs_fail() -> None:
    for file in _fixture_files("config/invalid"):
        fixture = json.loads(file.read_text())
        candidate = fixture.get("pactString")
        if candidate is None:
            candidate = "pact:v1:" + base64.urlsafe_b64encode(
                json.dumps(fixture["json"], separators=(",", ":")).encode("utf-8")
            ).rstrip(b"=").decode("ascii")
        with pytest.raises(ValueError) as excinfo:
            PactConfigString.parse(candidate)
        assert fixture["expectedErrorContains"] in str(excinfo.value)


def test_crypto_fixtures_decrypt_and_reencrypt_deterministically() -> None:
    for file in _fixture_files("crypto"):
        fixture = json.loads(file.read_text())
        runtime = PactConfigString.parse(fixture["configString"]).normalize()
        deterministic_inputs = fixture["deterministicInputs"]
        iv = _decode_base64url(deterministic_inputs.get("ivBase64Url") or deterministic_inputs.get("payloadIvBase64Url"))
        salt = (
            _decode_base64url(deterministic_inputs["saltBase64Url"])
            if deterministic_inputs.get("saltBase64Url")
            else None
        )
        payload_key = (
            _decode_base64url(deterministic_inputs["payloadKeyBase64Url"])
            if deterministic_inputs.get("payloadKeyBase64Url")
            else None
        )
        ephemeral_private_key = (
            _decode_base64url(deterministic_inputs["ephemeralPrivateKeyBase64Url"])
            if deterministic_inputs.get("ephemeralPrivateKeyBase64Url")
            else None
        )

        engine = PactEngineFactory.create(runtime, fixture.get("secret"))
        assert engine.decrypt(fixture["ciphertext"]) == fixture["plaintext"]
        assert (
            PactEngineFactory.encrypt_deterministic(
                runtime,
                plaintext=fixture["plaintext"],
                secret=fixture.get("secret"),
                iv=iv,
                salt=salt,
                payload_key=payload_key,
                ephemeral_private_key=ephemeral_private_key,
            )
            == fixture["ciphertext"]
        )
        assert engine.matches_encrypted_payload(fixture["ciphertext"])
        assert engine.find_encrypted_payloads(f"before {fixture['ciphertext']} after") == [fixture["ciphertext"]]


def _fixture_files(relative_path: str) -> list[Path]:
    directory = _resolve_spec_dir() / "fixtures" / relative_path
    assert directory.is_dir(), (
        f"PACT spec fixture directory not found at {directory}. "
        "Set PACT_SPEC_DIR or PACT_SPEC_DIR=/path/to/pact."
    )
    return sorted(directory.glob("*.json"))


def _resolve_spec_dir() -> Path:
    env = os.getenv("PACT_SPEC_DIR")
    if env:
        return Path(env)
    return Path(__file__).resolve().parents[2] / "pact"


def _decode_base64url(value: str) -> bytes:
    padded = value + ("=" * ((4 - len(value) % 4) % 4))
    return base64.urlsafe_b64decode(padded.encode("ascii"))
