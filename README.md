# pact-python

`pact-python` is a Python implementation of **PACT**: **Portable Application-layer Cryptography Template**.

PACT is an experimental standard I am developing for sharing encryption
profiles and metadata easily between applications, for use in custom
encryption layers on top of existing apps. It is a work in progress.

This library provides:

- PACT config-string parsing and serialization
- protocol normalization into executable runtime config
- secret validation
- a bound encryption/decryption engine
- interoperability-oriented tests

## Status

PACT is a work in progress, and this repository is the Python implementation
track for that evolving standard.

## Install

```bash
pip install pact-python
```

For local development:

```bash
pip install -e ".[dev]"
pytest
```

## Main Types

- `PactConfigString`
- `PactProtocolConfig`
- `PactRuntimeConfig`
- `PactEngineFactory`
- `PactEngine`
- `PactSecretValidator`

## Typical Usage

Applications can use `pact-python` to:

- parse or generate a PACT config string
- validate and normalize protocol settings
- create an encryption/decryption engine from a shared secret
- encrypt outbound payloads and decrypt inbound payloads

## Example

```python
from pact import (
    PactConfigString,
    PactEngineFactory,
    PactRuntimeConfig,
)

config = PactRuntimeConfig().to_protocol_config()
config_string = PactConfigString.serialize(config)
parsed = PactConfigString.parse(config_string)

engine = PactEngineFactory.create(parsed, "shared secret")
payload = engine.encrypt("hello world")
plaintext = engine.decrypt(payload)
```
