"""
Olympus Ripper — Terminal Utilities
(c) 2026 Olympus Cyber. All rights reserved.

Helpers for predictable terminal output across macOS, Windows, and CI.
"""

import os
import sys
from typing import Optional, TextIO


def should_use_color(no_color: bool = False, stream: Optional[TextIO] = None) -> bool:
    """Return True when ANSI color output should be emitted."""
    if no_color or os.environ.get("NO_COLOR") or os.environ.get("TERM") == "dumb":
        return False

    stream = stream or sys.stdout
    if not hasattr(stream, "isatty") or not stream.isatty():
        return False

    # Modern Windows Terminal, recent PowerShell, and GitHub Actions support ANSI.
    if os.name == "nt":
        return bool(
            os.environ.get("WT_SESSION")
            or os.environ.get("ANSICON")
            or os.environ.get("ConEmuANSI") == "ON"
            or os.environ.get("GITHUB_ACTIONS")
        )

    return True


def colorize(text: str, color_code: str, enabled: bool = True) -> str:
    """Wrap text in an ANSI color code when enabled."""
    if not enabled:
        return text
    return f"{color_code}{text}\033[0m"
