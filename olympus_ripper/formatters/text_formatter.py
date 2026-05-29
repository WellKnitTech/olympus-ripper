"""
Olympus Ripper — Text Output Formatter
(c) 2026 Olympus Cyber. All rights reserved.
"""

from datetime import datetime
from typing import TextIO
import sys


# Olympus Cyber brand colors for terminal (ANSI 256-color approximation)
class C:
    NAVY = "\033[38;2;15;43;91m"     # Deep Navy #0F2B5B
    BLUE = "\033[38;2;27;79;158m"    # Rich Blue #1B4F9E
    ACCENT = "\033[38;2;46;107;198m" # Medium Blue #2E6BC6
    BRIGHT = "\033[38;2;61;170;239m" # Bright Blue #3DAAEF
    SLATE = "\033[38;2;45;55;72m"    # Dark Slate #2D3748
    GRAY = "\033[38;2;107;123;141m"  # Slate Gray #6B7B8D
    RED = "\033[38;2;192;0;0m"       # Red #C00000
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


class TextFormatter:
    """Olympus-branded plaintext/ANSI output formatter."""

    def __init__(self, color: bool = True, output: TextIO = sys.stdout):
        self.color = color
        self.out = output

    def _c(self, code: str, text: str) -> str:
        if self.color:
            return f"{code}{text}{C.RESET}"
        return text

    def format(self, findings: list[dict], target: str = "") -> str:
        lines = []

        # Header
        lines.append(self._c(C.BLUE + C.BOLD, "=" * 72))
        lines.append(self._c(C.BRIGHT + C.BOLD, "  OLYMPUS RIPPER — Forensic Artifact Report"))
        lines.append(self._c(C.GRAY, f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"))
        if target:
            lines.append(self._c(C.GRAY, f"  Target: {target}"))
        lines.append(self._c(C.GRAY, f"  Findings: {len(findings)}"))
        lines.append(self._c(C.BLUE + C.BOLD, "=" * 72))
        lines.append("")

        # Group by plugin
        by_plugin: dict[str, list[dict]] = {}
        for f in findings:
            by_plugin.setdefault(f["plugin"], []).append(f)

        for plugin_name, plugin_findings in by_plugin.items():
            platform = plugin_findings[0].get("platform", "").upper()
            cat = plugin_findings[0].get("category", "")

            lines.append(self._c(C.ACCENT + C.BOLD, f"┌─ [{platform}] {plugin_name}"))
            lines.append(self._c(C.GRAY, f"│  Category: {cat}"))
            lines.append(self._c(C.ACCENT, "├" + "─" * 60))

            for f in plugin_findings:
                ts = f.get("timestamp", "")
                ts_str = f"  [{ts}]" if ts else ""
                mitre = f.get("mitre_att_ck", "")
                mitre_str = self._c(C.RED, f"  ({mitre})") if mitre else ""

                lines.append(
                    f"│  {self._c(C.BRIGHT, f.get('key', ''))}: "
                    f"{f.get('value', '')}{ts_str}{mitre_str}"
                )

                tags = f.get("tags", [])
                if tags:
                    lines.append(f"│    {self._c(C.GRAY, 'Tags: ' + ', '.join(tags))}")

            lines.append(self._c(C.ACCENT, "└" + "─" * 60))
            lines.append("")

        # Footer
        lines.append(self._c(C.BLUE + C.BOLD, "=" * 72))
        lines.append(self._c(C.GRAY, "  (c) 2026 Olympus Cyber | CONFIDENTIAL — DO NOT DISTRIBUTE"))
        lines.append(self._c(C.BLUE + C.BOLD, "=" * 72))

        return "\n".join(lines)

    def write(self, findings: list[dict], target: str = "") -> None:
        self.out.write(self.format(findings, target) + "\n")

    def write_to_file(self, findings: list[dict], filepath: str, target: str = "") -> None:
        # Write without color codes to file
        old_color = self.color
        self.color = False
        with open(filepath, "w") as f:
            f.write(self.format(findings, target) + "\n")
        self.color = old_color
