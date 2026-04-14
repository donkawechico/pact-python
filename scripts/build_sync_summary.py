from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SYNC_METADATA_DIR = ROOT / ".sync-metadata"
UPSTREAM_DIR = ROOT / ".sync-inputs" / "pact"


@dataclass(frozen=True)
class UpstreamSource:
    repo: str
    sha: str


def main() -> int:
    try:
        source = _load_upstream_source(SYNC_METADATA_DIR / "pact-source.json")
        pytest_summary = _read_optional_text(SYNC_METADATA_DIR / "pytest-summary.txt")

        commit_subject = _git_show(source.sha, ["--format=%s", "--no-patch"]).strip()
        commit_body = _git_show(source.sha, ["--format=%b", "--no-patch"]).strip()
        changed_files = _git_show(source.sha, ["--format=", "--name-only"]).splitlines()
        changed_files = [path.strip() for path in changed_files if path.strip()]

        categorized = _categorize_paths(changed_files)
        impact_labels = _infer_impact_labels(changed_files, commit_subject, commit_body)

        upstream_summary = _build_upstream_change_summary(
            source=source,
            commit_subject=commit_subject,
            commit_body=commit_body,
            changed_files=changed_files,
            categorized=categorized,
            impact_labels=impact_labels,
            pytest_summary=pytest_summary,
        )

        pr_body = _build_pr_body(
            source=source,
            commit_subject=commit_subject,
            categorized=categorized,
            impact_labels=impact_labels,
            pytest_summary=pytest_summary,
        )

        fixture_paths = [
            path
            for path in changed_files
            if path.startswith("fixtures/")
        ]

        SYNC_METADATA_DIR.mkdir(parents=True, exist_ok=True)
        (SYNC_METADATA_DIR / "upstream-change-summary.md").write_text(upstream_summary)
        (SYNC_METADATA_DIR / "changed-fixtures.txt").write_text(
            "\n".join(fixture_paths) + ("\n" if fixture_paths else "")
        )
        (SYNC_METADATA_DIR / "pr-body.md").write_text(pr_body)

        print("Wrote:")
        print(f"- {SYNC_METADATA_DIR / 'upstream-change-summary.md'}")
        print(f"- {SYNC_METADATA_DIR / 'changed-fixtures.txt'}")
        print(f"- {SYNC_METADATA_DIR / 'pr-body.md'}")
        return 0
    except Exception as exc:
        print(f"build_sync_summary.py failed: {exc}", file=sys.stderr)
        return 1


def _load_upstream_source(path: Path) -> UpstreamSource:
    if not path.is_file():
        raise FileNotFoundError(f"Upstream source metadata not found at {path}")

    data = json.loads(path.read_text())
    repo = data.get("repo")
    sha = data.get("sha")

    if not isinstance(repo, str) or not repo.strip():
        raise ValueError("pact-source.json missing valid string field: repo")
    if not isinstance(sha, str) or not sha.strip():
        raise ValueError("pact-source.json missing valid string field: sha")

    return UpstreamSource(repo=repo, sha=sha)


def _read_optional_text(path: Path) -> str:
    if not path.is_file():
        return ""
    return path.read_text().strip()


def _git_show(rev: str, extra_args: list[str]) -> str:
    if not UPSTREAM_DIR.is_dir():
        raise FileNotFoundError(f"Upstream checkout not found at {UPSTREAM_DIR}")

    result = subprocess.run(
        ["git", "-C", str(UPSTREAM_DIR), "show", rev, *extra_args],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"git show failed for rev {rev}: {result.stderr.strip() or result.stdout.strip()}"
        )
    return result.stdout


def _categorize_paths(paths: list[str]) -> dict[str, list[str]]:
    categories: dict[str, list[str]] = {
        "spec": [],
        "config_fixtures": [],
        "message_fixtures": [],
        "crypto_fixtures": [],
        "examples": [],
        "other_normative": [],
        "other": [],
    }

    for path in paths:
        if path == "SPEC.md":
            categories["spec"].append(path)
        elif path.startswith("fixtures/config/"):
            categories["config_fixtures"].append(path)
        elif path.startswith("fixtures/message/"):
            categories["message_fixtures"].append(path)
        elif path.startswith("fixtures/crypto/"):
            categories["crypto_fixtures"].append(path)
        elif path.startswith("examples/"):
            categories["examples"].append(path)
        elif path.startswith("fixtures/"):
            categories["other_normative"].append(path)
        else:
            categories["other"].append(path)

    return categories


def _infer_impact_labels(
    changed_files: list[str],
    commit_subject: str,
    commit_body: str,
) -> list[str]:
    haystack = "\n".join([commit_subject, commit_body, *changed_files]).lower()
    labels: list[str] = []

    if "psk1" in haystack:
        labels.append("pact-psk1")
    if "psk2" in haystack:
        labels.append("pact-psk2")
    if "box1" in haystack:
        labels.append("pact-box1")
    if "message/" in haystack or "self-describing" in haystack:
        labels.append("self-describing-messages")
    if "transport" in haystack or "remap" in haystack:
        labels.append("transport-remap")
    if "config/" in haystack:
        labels.append("config-parsing")
    if "crypto/" in haystack or "aes" in haystack or "x25519" in haystack:
        labels.append("crypto-contract")

    seen: set[str] = set()
    deduped: list[str] = []
    for label in labels:
        if label not in seen:
            deduped.append(label)
            seen.add(label)
    return deduped


def _build_upstream_change_summary(
    source: UpstreamSource,
    commit_subject: str,
    commit_body: str,
    changed_files: list[str],
    categorized: dict[str, list[str]],
    impact_labels: list[str],
    pytest_summary: str,
) -> str:
    lines: list[str] = []
    lines.append("# Upstream change summary")
    lines.append("")
    lines.append(f"- Repo: `{source.repo}`")
    lines.append(f"- SHA: `{source.sha}`")
    lines.append(f"- Commit subject: `{commit_subject}`")
    lines.append("")

    if commit_body:
        lines.append("## Commit body")
        lines.append("")
        lines.append("```text")
        lines.append(commit_body)
        lines.append("```")
        lines.append("")

    lines.append("## Changed files in triggering upstream commit")
    lines.append("")
    if changed_files:
        for path in changed_files:
            lines.append(f"- `{path}`")
    else:
        lines.append("- None detected")
    lines.append("")

    lines.append("## Normative change buckets")
    lines.append("")
    for title, key in [
        ("Spec", "spec"),
        ("Config fixtures", "config_fixtures"),
        ("Message fixtures", "message_fixtures"),
        ("Crypto fixtures", "crypto_fixtures"),
        ("Other normative", "other_normative"),
        ("Examples", "examples"),
        ("Other", "other"),
    ]:
        values = categorized[key]
        lines.append(f"### {title}")
        lines.append("")
        if values:
            for value in values:
                lines.append(f"- `{value}`")
        else:
            lines.append("- None")
        lines.append("")

    lines.append("## Likely impact areas")
    lines.append("")
    if impact_labels:
        for label in impact_labels:
            lines.append(f"- `{label}`")
    else:
        lines.append("- No obvious impact labels inferred")
    lines.append("")

    lines.append("## Current pytest summary")
    lines.append("")
    lines.append("```text")
    lines.append(pytest_summary or "No pytest summary captured.")
    lines.append("```")
    lines.append("")

    return "\n".join(lines)


def _build_pr_body(
    source: UpstreamSource,
    commit_subject: str,
    categorized: dict[str, list[str]],
    impact_labels: list[str],
    pytest_summary: str,
) -> str:
    lines: list[str] = []
    lines.append("This draft PR was opened automatically from an upstream PACT change.")
    lines.append("")
    lines.append("Upstream source:")
    lines.append(f"- Repo: `{source.repo}`")
    lines.append(f"- SHA: `{source.sha}`")
    lines.append(f"- Commit: `{commit_subject}`")
    lines.append("")

    lines.append("Normative surfaces touched:")
    touched = (
        categorized["spec"]
        + categorized["config_fixtures"]
        + categorized["message_fixtures"]
        + categorized["crypto_fixtures"]
        + categorized["other_normative"]
    )
    if touched:
        for path in touched:
            lines.append(f"- `{path}`")
    else:
        lines.append("- None detected")
    lines.append("")

    lines.append("Likely impact areas:")
    if impact_labels:
        for label in impact_labels:
            lines.append(f"- `{label}`")
    else:
        lines.append("- No obvious impact labels inferred")
    lines.append("")

    lines.append("Current fixture result:")
    lines.append("```text")
    lines.append(pytest_summary or "No pytest summary captured.")
    lines.append("```")
    lines.append("")

    lines.append("Review intent:")
    lines.append("- verify pact-python still matches upstream PACT fixtures")
    lines.append("- inspect parser/normalization/crypto drift")
    lines.append("- keep changes limited to pact-python behavior required by the upstream spec")
    lines.append("")

    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())