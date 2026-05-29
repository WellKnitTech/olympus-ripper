"""
Olympus Ripper — JSON Output Formatter
(c) 2026 Olympus Cyber. All rights reserved.
"""

import json
from datetime import datetime


class JSONFormatter:
    """Output findings as structured JSON."""

    def format(self, findings: list[dict], target: str = "") -> str:
        output = {
            "tool": "Olympus Ripper",
            "version": "1.0.0",
            "vendor": "Olympus Cyber",
            "generated": datetime.now().isoformat(),
            "target": target,
            "total_findings": len(findings),
            "findings": findings,
        }
        return json.dumps(output, indent=2, default=str)

    def write_to_file(self, findings: list[dict], filepath: str, target: str = "") -> None:
        with open(filepath, "w") as f:
            f.write(self.format(findings, target))
