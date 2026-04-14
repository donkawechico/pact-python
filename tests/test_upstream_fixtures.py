from __future__ import annotations

import base64
import json

import pytest

from pact import (
    PactConfigString,
    PactEngineFactory,
    PactProtocolConfig,
    PactProfile,
)

from tests.helpers.upstream_fixtures import (
    decode_base64url,
    fixture_files,
    load_fixture,
)


def test_fixture_configs_round_trip() -> None:
    for file in fixture_files("config/valid"):
        fixture = load_fixture(file)
        parsed = PactConfigString.parse(fixture["canonicalString"])
        assert PactConfigString.serialize(parsed) == fixture["canonicalString"]


def test_invalid_fixture_configs_fail() -> None:
    for file in fixture_files("config/invalid"):
        fixture = load_fixture(file)
        candidate = fixture.get("pactString")
        if candidate is None:
            candidate = "pact:v1:" + base64.urlsafe_b64encode(
                json.dumps(fixture["json"], separators=(",", ":")).encode("utf-8")
            ).rstrip(b"=").decode("ascii")

        with pytest.raises(ValueError) as excinfo:
            PactConfigString.parse(candidate)

        assert fixture["expectedErrorContains"] in str(excinfo.value)


def test_crypto_fixtures_decrypt_and_reencrypt_deterministically() -> None:
    for file in fixture_files("crypto"):
        fixture = load_fixture(file)
        runtime = PactConfigString.parse(fixture["configString"]).normalize()
        deterministic_inputs = fixture["deterministicInputs"]

        iv = decode_base64url(
            deterministic_inputs.get("ivBase64Url")
            or deterministic_inputs.get("payloadIvBase64Url")
        )
        salt = (
            decode_base64url(deterministic_inputs["saltBase64Url"])
            if deterministic_inputs.get("saltBase64Url")
            else None
        )
        payload_key = (
            decode_base64url(deterministic_inputs["payloadKeyBase64Url"])
            if deterministic_inputs.get("payloadKeyBase64Url")
            else None
        )
        ephemeral_private_key = (
            decode_base64url(deterministic_inputs["ephemeralPrivateKeyBase64Url"])
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
                self_describing="self-describing" in fixture["name"],
            )
            == fixture["ciphertext"]
        )
        assert engine.matches_encrypted_payload(fixture["ciphertext"])
        assert engine.find_encrypted_payloads(
            f"before {fixture['ciphertext']} after"
        ) == [fixture["ciphertext"]]


def test_invalid_self_describing_message_fixtures_fail() -> None:
    runtime = PactProtocolConfig(
        message_prefix="ENC",
        profile=PactProfile.PACT_PSK2,
    ).normalize()
    engine = PactEngineFactory.create(
        runtime,
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
    )

    for file in fixture_files("message/invalid"):
        fixture = load_fixture(file)

        with pytest.raises(ValueError) as excinfo:
            engine.decrypt(fixture["message"])

        assert fixture["expectedErrorContains"] in str(excinfo.value)