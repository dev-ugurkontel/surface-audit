"""Checks that relative Markdown links resolve inside the repository."""

from __future__ import annotations

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_MARKDOWN_LINK_RE = re.compile(r"(?<!\!)\[[^\]]+\]\(([^)]+)\)")


def test_relative_markdown_links_resolve() -> None:
    markdown_files = sorted(_ROOT.rglob("*.md"))
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
