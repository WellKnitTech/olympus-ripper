"""
Olympus Ripper — Timeline Output Formatter
(c) 2026 Olympus Cyber. All rights reserved.

Generates bodyfile/TLN format for super-timeline analysis.
"""

import csv
import io


class TimelineFormatter:
    """
    Output timestamped findings in TLN (5-field) format for timeline analysis.

    TLN Format: Time|Source|Host|User|Description
    Compatible with log2timeline/plaso super-timeline workflows.
    """

    def format(self, findings: list[dict], target: str = "", hostname: str = "UNKNOWN") -> str:
        buf = io.StringIO()
        writer = csv.writer(buf, delimiter="|")
        writer.writerow(["Time", "Source", "Host", "User", "Description"])

        for f in findings:
            ts = f.get("timestamp", "")
            if not ts:
                continue

            source = f"OlympusRipper::{f.get('plugin', '')}"
            mitre = f.get("mitre_att_ck", "")
            mitre_tag = f" [{mitre}]" if mitre else ""
            desc = f"[{f.get('category', '')}] {f.get('key', '')}: {f.get('value', '')}{mitre_tag}"

            writer.writerow([ts, source, hostname, "", desc])

        return buf.getvalue()

    def write_to_file(
        self, findings: list[dict], filepath: str,
        target: str = "", hostname: str = "UNKNOWN"
    ) -> None:
        with open(filepath, "w", newline="") as f:
            f.write(self.format(findings, target, hostname))
