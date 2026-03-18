import base64
import json

import pytest

from pact import (
    PactConfigString,
    PactCryptoMetadata,
    PactEngineFactory,
    PactKeyHandling,
    PactPackedEncoding,
    PactPayloadLayout,
    PactRuntimeConfig,
    PactSecretValidator,
)


def test_serializes_and_parses_canonical_config_strings() -> None:
    config = PactRuntimeConfig(
        message_prefix="[ENC]",
        key_handling=PactKeyHandling.RAW_BASE64_KEY,
        payload_layout=PactPayloadLayout.PACKED,
        packed_encoding=PactPackedEncoding.STANDARD_NO_PADDING,
        char_remap={"+": ".", "/": "!"},
        crypto=PactCryptoMetadata.default_for(PactKeyHandling.RAW_BASE64_KEY),
    ).to_protocol_config()

    serialized = PactConfigString.serialize(config)
    parsed = PactConfigString.parse(serialized)

    assert parsed.message_prefix == config.message_prefix
    assert parsed.key_handling == config.key_handling
    assert parsed.payload_layout == config.payload_layout
    assert parsed.packed_encoding == config.packed_encoding
    assert parsed.char_remap == config.char_remap


def test_rejects_malformed_config_strings() -> None:
    with pytest.raises(ValueError):
        PactConfigString.parse("not-a-config")


def test_preserves_unknown_fields_during_round_trip() -> None:
    raw = json.dumps(
        {
            "messagePrefix": "[ENC]",
            "keyHandling": "raw-base64-key",
            "payloadLayout": "packed",
            "packedEncoding": "standard-base64-no-padding",
            "futureFlag": "on",
        },
        separators=(",", ":"),
    )
    encoded = base64.urlsafe_b64encode(raw.encode("utf-8")).rstrip(b"=").decode("ascii")

    parsed = PactConfigString.parse(f"pact:v1:{encoded}")
    reserialized = PactConfigString.serialize(parsed)
    reparsed = PactConfigString.parse(reserialized)

    assert reparsed.extra_fields["futureFlag"] == "on"


def test_validates_raw_keys() -> None:
    config = PactRuntimeConfig(
        key_handling=PactKeyHandling.RAW_BASE64_KEY,
        payload_layout=PactPayloadLayout.PACKED,
        packed_encoding=PactPackedEncoding.STANDARD_NO_PADDING,
        crypto=PactCryptoMetadata.default_for(PactKeyHandling.RAW_BASE64_KEY),
    )

    assert not PactSecretValidator.validate(config, "abcd").is_valid
    assert PactSecretValidator.validate(config, "AAAAAAAAAAAAAAAAAAAAAA==").is_valid


def test_passphrase_multipart_round_trip_works() -> None:
    engine = PactEngineFactory.create(PactRuntimeConfig(), "shared secret")

    encrypted = engine.encrypt("hello world")

    assert engine.matches_encrypted_payload(encrypted)
    assert engine.decrypt(encrypted) == "hello world"


def test_raw_key_packed_round_trip_with_char_remap_works() -> None:
    engine = PactEngineFactory.create(
        PactRuntimeConfig(
            message_prefix="[ENC]",
            key_handling=PactKeyHandling.RAW_BASE64_KEY,
            payload_layout=PactPayloadLayout.PACKED,
            packed_encoding=PactPackedEncoding.STANDARD_NO_PADDING,
            char_remap={"+": ".", "/": "!"},
            crypto=PactCryptoMetadata.default_for(PactKeyHandling.RAW_BASE64_KEY),
        ),
        "AAAAAAAAAAAAAAAAAAAAAA==",
    )

    encrypted = engine.encrypt("Testing123")

    assert encrypted.startswith("[ENC]")
    assert engine.decrypt(encrypted) == "Testing123"
    assert engine.find_encrypted_payloads(f"before {encrypted} after") == [encrypted]


def test_uses_dot_bang_alias_for_canonical_standard_remap() -> None:
    config = PactRuntimeConfig(
        key_handling=PactKeyHandling.RAW_BASE64_KEY,
        payload_layout=PactPayloadLayout.PACKED,
        packed_encoding=PactPackedEncoding.STANDARD_NO_PADDING,
        char_remap={"+": ".", "/": "!"},
        crypto=PactCryptoMetadata.default_for(PactKeyHandling.RAW_BASE64_KEY),
    ).to_protocol_config()

    serialized = PactConfigString.serialize(config)
    parsed = PactConfigString.parse(serialized)

    assert "dot-bang-base64-no-padding" in base64.urlsafe_b64decode(
        serialized.removeprefix("pact:v1:") + "===",
    ).decode("utf-8")
    assert parsed.char_remap == {"+": ".", "/": "!"}
