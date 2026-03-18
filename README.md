# pact-python

`pact-python` is a Python implementation of **PACT**: **Portable Application-layer Cryptography Template**.

This library provides:

- PACT config-string parsing and serialization
- protocol normalization into executable runtime config
- secret validation
- a bound encryption/decryption engine
- interoperability-oriented tests

## Status

This repository is the Python implementation track for the PACT specification.

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

## Discord Bot Fit

This package is protocol-focused rather than Discord-specific. A bot can use it to:

- load a pasted PACT config string
- validate and normalize that config
- encrypt outgoing payloads
- detect and decrypt incoming payloads
- generate a canonical PACT config string for copy/paste into Android or other clients

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
