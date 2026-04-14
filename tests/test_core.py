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
    PactSecretGenerator,
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
        message_prefix="ENC",
        profile=PactProfile.PACT_PSK2,
    ).normalize()

    assert normalized.message_prefix == "ENC"
    assert normalized.key_handling == PactKeyHandling.RAW_BASE64_KEY
    assert normalized.payload_layout == PactPayloadLayout.PACKED
    assert normalized.packed_encoding == PactPackedEncoding.STANDARD_NO_PADDING
    assert normalized.char_remap == {}


def test_transport_remap_lives_outside_the_profile() -> None:
    config = PactProtocolConfig(
        message_prefix="ENC",
        profile=PactProfile.PACT_PSK2,
        transport_data=PactTransportData(
            char_remap={"+": ".", "/": "!"},
        ),
    )

    normalized = config.normalize()

    assert normalized.profile == PactProfile.PACT_PSK2
    assert normalized.char_remap == {"+": ".", "/": "!"}
    assert normalized.to_protocol_config() == config


def test_profile_wire_names_round_trip() -> None:
    assert PactProfile.PACT_PSK1.wire_name == "pact-psk1"
    assert PactProfile.PACT_PSK2.wire_name == "pact-psk2"
    assert PactProfile.PACT_BOX1.wire_name == "pact-box1"
    assert PactProfile.from_wire_name("pact-psk2") == PactProfile.PACT_PSK2


def test_protocol_config_helpers_validate_and_preserve_intent() -> None:
    key_pair = PactSecretGenerator.generate_key_pair()
    config = PactProtocolConfig(
        message_prefix="box",
        profile=PactProfile.PACT_BOX1,
        profile_data=PactProfileData(
            recipients=[PactRecipient(key_id="generated", public_key=key_pair.public_key)]
        ),
    )

    updated_transport = config.with_transport(message_prefix="ENC", char_remap={"+": ".", "/": "!"})
    updated_profile = updated_transport.with_profile("pact-psk2")

    assert updated_transport.message_prefix == "ENC"
    assert updated_transport.transport_data.char_remap == {"+": ".", "/": "!"}
    assert updated_profile.profile == PactProfile.PACT_PSK2
    assert updated_profile.profile_data.recipients == []
    assert updated_profile.transport_data.char_remap == {"+": ".", "/": "!"}


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


def test_generates_valid_shared_secrets_for_raw_key_profiles() -> None:
    config = PactProtocolConfig(message_prefix="ENC", profile=PactProfile.PACT_PSK2)
    secret = PactSecretGenerator.generate_shared_secret(config)
    runtime = config.normalize()

    assert PactSecretValidator.validate(runtime, secret).is_valid
    assert PactEngineFactory.create(runtime, secret).decrypt(
        PactEngineFactory.create(runtime, secret).encrypt("generated secret")
    ) == "generated secret"


def test_shared_secret_generation_rejects_passphrase_runtime_configs() -> None:
    config = PactRuntimeConfig(key_handling=PactKeyHandling.PASSPHRASE_PBKDF2)

    with pytest.raises(ValueError, match="raw-key profiles"):
        PactSecretGenerator.generate_shared_secret(config)


def test_generates_usable_box_key_pairs() -> None:
    key_pair = PactSecretGenerator.generate_key_pair()
    config = PactProtocolConfig(
        message_prefix="pact1",
        profile=PactProfile.PACT_BOX1,
        profile_data=PactProfileData(
            recipients=[PactRecipient(key_id="generated", public_key=key_pair.public_key)]
        ),
    )

    ciphertext = PactEngineFactory.create(config).encrypt("hello generated box")

    assert PactSecretValidator.validate(config.normalize(), key_pair.private_key).is_valid
    assert PactEngineFactory.create(config, key_pair.private_key).decrypt(ciphertext) == "hello generated box"

def test_encrypt_self_describing_uses_production_randomness() -> None:
    runtime = PactProtocolConfig(
        message_prefix="ENC",
        profile=PactProfile.PACT_PSK2,
        transport_data=PactTransportData(char_remap={"+": ".", "/": "!"}),
    ).normalize()
    secret = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"

    ciphertext = PactEngineFactory.encrypt_self_describing(runtime, "hello self describing", secret)

    assert ciphertext.startswith("[pact]:v1:")
    assert PactEngineFactory.create(runtime, secret).decrypt(ciphertext) == "hello self describing"
