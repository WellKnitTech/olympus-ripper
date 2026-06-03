"""
Olympus Ripper — CSV Output Formatter
(c) 2026 Olympus Cyber. All rights reserved.
"""

import csv
import io


class CSVFormatter:
    """Output findings as CSV for import into spreadsheets or SIEM."""

    FIELDS = [
        "plugin", "platform", "category", "source", "key",
        "value", "timestamp", "tags", "mitre_att_ck",
    ]

    def format(self, findings: list[dict], target: str = "") -> str:
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=self.FIELDS, extrasaction="ignore")
        writer.writeheader()
        for f in findings:
            row = {k: f.get(k, "") for k in self.FIELDS}
            if isinstance(row.get("tags"), list):
                row["tags"] = "|".join(row["tags"])
            writer.writerow(row)
        return buf.getvalue()

    def write_to_file(self, findings: list[dict], filepath: str, target: str = "") -> None:
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            f.write(self.format(findings, target))
