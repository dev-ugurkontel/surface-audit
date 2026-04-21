"""Checks that relative Markdown links resolve inside the repository."""

from __future__ import annotations

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_IGNORED_DIRS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "build",
    "dist",
    "htmlcov",
}
_MARKDOWN_LINK_RE = re.compile(r"(?<!\!)\[[^\]]+\]\(([^)]+)\)")
_HEADING_RE = re.compile(r"^(#{1,6})\s+(.+)$")


def _markdown_files() -> list[Path]:
    files: list[Path] = []
    for path in _ROOT.rglob("*.md"):
        if any(part in _IGNORED_DIRS for part in path.relative_to(_ROOT).parts):
            continue
        files.append(path)
    return sorted(files)


def _slugify_heading(text: str) -> str:
    text = re.sub(r"<[^>]+>", "", text)
    text = re.sub(r"`([^`]+)`", r"\1", text)
    text = text.strip().lower()
    text = re.sub(r"[^\w\s-]", "", text)
    text = re.sub(r"[\s_]+", "-", text)
    return text.strip("-")


def _heading_anchors(path: Path) -> set[str]:
    anchors: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        match = _HEADING_RE.match(line)
        if match:
            anchors.add(_slugify_heading(match.group(2)))
    return anchors


def test_relative_markdown_links_resolve() -> None:
    markdown_files = _markdown_files()
    missing: list[str] = []

    for markdown_file in markdown_files:
        text = markdown_file.read_text(encoding="utf-8")
        for raw_target in _MARKDOWN_LINK_RE.findall(text):
            target = raw_target.strip()
            if target.startswith(("<", "http://", "https://", "mailto:", "#")):
                target = target.strip("<>")
            if not target or target.startswith(("http://", "https://", "mailto:", "#")):
                continue

            relative_target = target.strip("<>").split("#", 1)[0]
            if not relative_target:
                continue

            resolved = (markdown_file.parent / relative_target).resolve()
            if not resolved.exists():
                missing.append(f"{markdown_file.relative_to(_ROOT)} -> {relative_target}")

    assert missing == []


def test_relative_markdown_heading_anchors_resolve() -> None:
    markdown_files = _markdown_files()
    missing: list[str] = []

    for markdown_file in markdown_files:
        text = markdown_file.read_text(encoding="utf-8")
        for raw_target in _MARKDOWN_LINK_RE.findall(text):
            target = raw_target.strip().strip("<>")
            if (
                not target
                or target.startswith(("http://", "https://", "mailto:"))
                or "#" not in target
            ):
                continue

            target_path, anchor = target.split("#", 1)
            if not anchor:
                continue

            resolved = markdown_file if not target_path else (markdown_file.parent / target_path)
            resolved = resolved.resolve()
            if resolved.suffix != ".md" or not resolved.exists():
                continue

            anchors = _heading_anchors(resolved)
            if anchor.lower() not in anchors:
                missing.append(f"{markdown_file.relative_to(_ROOT)} -> {target}")

    assert missing == []
