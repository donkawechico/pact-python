from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SYNC_METADATA_DIR = ROOT / ".sync-metadata"
UPSTREAM_DIR = ROOT / ".sync-inputs" / "pact"


@dataclass(frozen=True)
class UpstreamSource:
    repo: str
    sha: str
    previous_sha: str


def main() -> int:
    try:
        source = _load_upstream_source(SYNC_METADATA_DIR / "pact-source.json")
        pytest_summary = _read_optional_text(SYNC_METADATA_DIR / "pytest-summary.txt")

        summary_mode, commit_lines, changed_files = _collect_upstream_delta(source)
        categorized = _categorize_paths(changed_files)
        impact_labels = _infer_impact_labels(changed_files, commit_lines)

        upstream_summary = _build_upstream_change_summary(
            source=source,
            summary_mode=summary_mode,
            commit_lines=commit_lines,
            changed_files=changed_files,
            categorized=categorized,
            impact_labels=impact_labels,
            pytest_summary=pytest_summary,
        )

        pr_body = _build_pr_body(
            source=source,
            summary_mode=summary_mode,
            commit_lines=commit_lines,
            categorized=categorized,
            impact_labels=impact_labels,
            pytest_summary=pytest_summary,
        )

        fixture_paths = [path for path in changed_files if path.startswith("fixtures/")]

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
    repo = str(data.get("repo", "")).strip()
    sha = str(data.get("sha", "")).strip()
    previous_sha = str(data.get("previous_sha", "")).strip()

    if not repo:
        raise ValueError("pact-source.json missing valid string field: repo")
    if not sha:
        raise ValueError("pact-source.json missing valid string field: sha")

    return UpstreamSource(repo=repo, sha=sha, previous_sha=previous_sha)


def _read_optional_text(path: Path) -> str:
    if not path.is_file():
        return ""
    return path.read_text().strip()


def _collect_upstream_delta(source: UpstreamSource) -> tuple[str, list[str], list[str]]:
    current_subject = _git_show(source.sha, ["--format=%s", "--no-patch"]).strip()

    if source.previous_sha and source.previous_sha != source.sha:
        commit_lines = _git_log_range(f"{source.previous_sha}..{source.sha}")
        changed_files = _git_diff_name_only(f"{source.previous_sha}...{source.sha}")
        return "range", commit_lines, changed_files

    if source.previous_sha and source.previous_sha == source.sha:
        return "already_synced", [], []

    changed_files = _git_show(source.sha, ["--format=", "--name-only"]).splitlines()
    changed_files = [path.strip() for path in changed_files if path.strip()]
    commit_lines = [f"{source.sha}\t{current_subject}"]
    return "single", commit_lines, changed_files


def _git_show(rev: str, extra_args: list[str]) -> str:
    return _git(["show", rev, *extra_args])


def _git_diff_name_only(revspec: str) -> list[str]:
    output = _git(["diff", "--name-only", revspec])
    return [line.strip() for line in output.splitlines() if line.strip()]


def _git_log_range(revspec: str) -> list[str]:
    output = _git(["log", "--reverse", "--format=%H%x09%s", revspec])
    return [line.strip() for line in output.splitlines() if line.strip()]


def _git(args: list[str]) -> str:
    if not UPSTREAM_DIR.is_dir():
        raise FileNotFoundError(f"Upstream checkout not found at {UPSTREAM_DIR}")

    result = subprocess.run(
        ["git", "-C", str(UPSTREAM_DIR), *args],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        stderr = result.stderr.strip()
        stdout = result.stdout.strip()
        raise RuntimeError(stderr or stdout or f"git command failed: {' '.join(args)}")
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


def _infer_impact_labels(changed_files: list[str], commit_lines: list[str]) -> list[str]:
    haystack = "\n".join([*changed_files, *commit_lines]).lower()
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
    if "crypto/" in haystack or "aes" in haystack or "x25519" in haystack or "hkdf" in haystack:
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
    summary_mode: str,
    commit_lines: list[str],
    changed_files: list[str],
    categorized: dict[str, list[str]],
    impact_labels: list[str],
    pytest_summary: str,
) -> str:
    lines: list[str] = []
    lines.append("# Upstream change summary")
    lines.append("")
    lines.append(f"- Repo: `{source.repo}`")
    lines.append(f"- Previous synced upstream SHA: `{source.previous_sha or 'none'}`")
    lines.append(f"- Current upstream SHA: `{source.sha}`")
    lines.append(f"- Summary mode: `{summary_mode}`")
    lines.append("")

    if summary_mode == "already_synced":
        lines.append("## Range status")
        lines.append("")
        lines.append("Current upstream SHA matches the last merged upstream SHA on `pact-python/main`.")
        lines.append("")

    lines.append("## Upstream commits in scope")
    lines.append("")
    if commit_lines:
        for line in commit_lines:
            commit_sha, _, subject = line.partition("\t")
            lines.append(f"- `{commit_sha}` {subject}")
    else:
        lines.append("- No upstream commits in scope")
    lines.append("")

    lines.append("## Changed files in scope")
    lines.append("")
    if changed_files:
        for path in changed_files:
            lines.append(f"- `{path}`")
    else:
        lines.append("- No changed files in scope")
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
    summary_mode: str,
    commit_lines: list[str],
    categorized: dict[str, list[str]],
    impact_labels: list[str],
    pytest_summary: str,
) -> str:
    lines: list[str] = []
    lines.append("This draft PR was opened automatically from upstream PACT changes not yet accounted for in `pact-python/main`.")
    lines.append("")
    lines.append("Upstream source:")
    lines.append(f"- Repo: `{source.repo}`")
    lines.append(f"- Previous synced upstream SHA: `{source.previous_sha or 'none'}`")
    lines.append(f"- Current upstream SHA: `{source.sha}`")
    lines.append(f"- Summary mode: `{summary_mode}`")
    lines.append("")

    lines.append("Upstream commits in scope:")
    if commit_lines:
        for line in commit_lines:
            commit_sha, _, subject = line.partition("\t")
            lines.append(f"- `{commit_sha}` {subject}")
    else:
        lines.append("- No upstream commits in scope")
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
    lines.append("- inspect parser, normalization, message, and crypto drift across the full unaccounted upstream range")
    lines.append("- keep changes limited to pact-python behavior required by the upstream spec and fixtures")
    lines.append("")

    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())