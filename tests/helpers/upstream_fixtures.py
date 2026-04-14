from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Any


def resolve_spec_dir() -> Path:
    env = os.getenv("PACT_SPEC_DIR")
    if env:
        return Path(env)
    return Path(__file__).resolve().parents[3] / "pact"


def fixture_dir(relative_path: str) -> Path:
    directory = resolve_spec_dir() / "fixtures" / relative_path
    assert directory.is_dir(), (
        f"PACT spec fixture directory not found at {directory}. "
        "Set PACT_SPEC_DIR or PACT_SPEC_DIR=/path/to/pact."
    )
    return directory


def fixture_files(relative_path: str) -> list[Path]:
    return sorted(fixture_dir(relative_path).glob("*.json"))


def load_fixture(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def decode_base64url(value: str) -> bytes:
    padded = value + ("=" * ((4 - len(value) % 4) % 4))
    return base64.urlsafe_b64decode(padded.encode("ascii"))