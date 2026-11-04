#!/usr/bin/env python3
"""Check that the research repository stays within its publication boundary."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SYNTHETIC_INPUTS = {
    "data/opnotes/example.ctd",
    "data/suricata/example.csv",
}
MITRE_PREFIX = "data/mitre/"
ALLOWED_DATA_PREFIXES = (
    "data/opnotes/",
    "data/suricata/",
    MITRE_PREFIX,
)
ALLOWED_DATA_FILES = {"data/README.md"}
PROHIBITED_EXTENSIONS = {
    ".7z",
    ".ctd",
    ".doc",
    ".docx",
    ".ipynb",
    ".log",
    ".pcap",
    ".pcapng",
    ".pdf",
    ".ppt",
    ".pptx",
    ".tar",
    ".tgz",
    ".xls",
    ".xlsx",
    ".zip",
}
PROHIBITED_PARTS = {
    ".ipynb_checkpoints",
    "outputs",
    "private_data",
    "results",
}
CONTENT_PATTERNS = {
    "key-shaped secret": re.compile(r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}"),
    "populated API key assignment": re.compile(
        r"""OPENAI_API_KEY\s*=\s*["'][^"']{8,}["']"""
    ),
    "machine-specific home path": re.compile(
        r"/(?:home|Users)/[A-Za-z0-9._-]+/"
    ),
    "participant-style identifier": re.compile(r"\bE\d{2}P\d{2}\b"),
}


def repository_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=ROOT,
        check=False,
        capture_output=True,
    )
    if result.returncode == 0:
        return [
            ROOT / name.decode("utf-8")
            for name in result.stdout.split(b"\0")
            if name and (ROOT / name.decode("utf-8")).is_file()
        ]
    return [
        path
        for path in ROOT.rglob("*")
        if path.is_file()
        and ".git" not in path.parts
        and ".venv" not in path.parts
        and "__pycache__" not in path.parts
    ]


def main() -> int:
    violations: list[str] = []
    for path in repository_files():
        relative = path.relative_to(ROOT).as_posix()
        synthetic = relative in SYNTHETIC_INPUTS
        allowed_data = (
            relative in ALLOWED_DATA_FILES
            or relative.startswith(ALLOWED_DATA_PREFIXES)
        )
        if relative.startswith("data/") and not allowed_data:
            violations.append(f"{relative}: unapproved public data location")
        if not synthetic and path.suffix.casefold() in PROHIBITED_EXTENSIONS:
            violations.append(f"{relative}: prohibited extension")
        if not synthetic and PROHIBITED_PARTS.intersection(path.relative_to(ROOT).parts):
            violations.append(f"{relative}: prohibited directory")
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        for label, pattern in CONTENT_PATTERNS.items():
            if pattern.search(text):
                violations.append(f"{relative}: {label}")
    if violations:
        print("Repository policy scan failed:", file=sys.stderr)
        for violation in violations:
            print(f"- {violation}", file=sys.stderr)
        return 1
    print(f"Repository policy scan passed ({len(repository_files())} files checked).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
