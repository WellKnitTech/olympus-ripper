"""
Olympus Ripper — macOS FSEvents Plugin
(c) 2026 Olympus Cyber. All rights reserved.

Parses FSEvents records (/.fseventsd/) to reconstruct file system
activity: file creation, modification, deletion, and renaming.
FSEvents survive file deletion — powerful for forensic timelines.
"""

import gzip
import struct
from datetime import datetime
from pathlib import Path
from ...plugin_base import ArtifactCategory, Finding, MacArtifactPlugin


class FSEventsPlugin(MacArtifactPlugin):
    name = "macos_fsevents"
    description = "Parse FSEvents journal for file system activity timeline"
    author = "Olympus Cyber"
    version = "1.0.0"
    category = ArtifactCategory.FILE_ACTIVITY
    artifact_type = "filesystem"
    default_paths = [
        ".fseventsd",
        "private/var/.fseventsd",
    ]

    @property
    def mitre_references(self) -> list[str]:
        return ["T1070.004"]

    # FSEvent flag bitmask
    FLAG_NAMES = {
        0x00000001: "Created",
        0x00000002: "Removed",
        0x00000004: "InodeMetaMod",
        0x00000008: "Renamed",
        0x00000010: "Modified",
        0x00000020: "Exchange",
        0x00000040: "FinderInfoMod",
        0x00000080: "DirCreated",
        0x00000100: "PermChange",
        0x00000200: "XAttrMod",
        0x00000400: "ExtAttrMod",
        0x00001000: "DocRevision",
        0x00004000: "ItemCloned",
        0x00010000: "IsFile",
        0x00020000: "IsDir",
        0x00040000: "IsSymLink",
        0x00080000: "IsHardLink",
        0x00100000: "IsLastHardLink",
        0x00800000: "Mount",
        0x01000000: "Unmount",
        0x02000000: "EndOfTransaction",
    }

    def _decode_flags(self, flags: int) -> list[str]:
        decoded = []
        for bit, name in self.FLAG_NAMES.items():
            if flags & bit:
                decoded.append(name)
        return decoded

    def _parse_fsevent_file(self, filepath: Path) -> list[tuple]:
        """Parse a single FSEvent file (may be gzipped)."""
        records = []

        try:
            # FSEvent files are gzip compressed
            try:
                with gzip.open(filepath, "rb") as f:
                    data = f.read()
            except gzip.BadGzipFile:
                with open(filepath, "rb") as f:
                    data = f.read()

            if len(data) < 12:
                return records

            # Check for DLS1 or DLS2 magic
            magic = data[:4]
            if magic not in (b"1SLD", b"2SLD"):
                return records

            version = 1 if magic == b"1SLD" else 2

            # Parse header
            offset = 12  # Skip header

            while offset < len(data) - 12:
                # Find null-terminated path string
                null_pos = data.find(b"\x00", offset)
                if null_pos == -1:
                    break

                path = data[offset:null_pos].decode("utf-8", errors="replace")
                offset = null_pos + 1

                # Read event ID and flags
                if version == 1:
                    if offset + 8 > len(data):
                        break
                    event_id = struct.unpack("<Q", data[offset:offset + 8])[0]
                    offset += 8
                    flags = struct.unpack("<I", data[offset:offset + 4])[0]
                    offset += 4
                else:  # version 2
                    if offset + 12 > len(data):
                        break
                    event_id = struct.unpack("<Q", data[offset:offset + 8])[0]
                    offset += 8
                    flags = struct.unpack("<I", data[offset:offset + 4])[0]
                    offset += 4

                records.append((path, event_id, flags))

        except Exception:
            pass

        return records

    def run(self, target: str, **kwargs) -> list[Finding]:
        findings = []
        target_path = Path(target)

        if not target_path.is_dir():
            findings.append(Finding(
                source="macos_fsevents", key="error",
                value=f"Expected directory: {target}",
                category=self.category,
            ))
            return findings

        # Parse all fsevent files
        fsevent_files = sorted(target_path.glob("*"))
        fsevent_files = [f for f in fsevent_files if f.is_file() and f.name != "fseventsd-uuid"]

        max_records = int(kwargs.get("max_records", 5000))
        total = 0

        for ef in fsevent_files:
            records = self._parse_fsevent_file(ef)
            for path, event_id, flags in records:
                if total >= max_records:
                    break

                decoded_flags = self._decode_flags(flags)
                if not decoded_flags:
                    continue

                tags = ["fsevents"]
                # Flag suspicious paths
                suspicious = False
                path_lower = path.lower()

                sus_paths = [
                    "/tmp/", "/private/tmp/", "/.hidden",
                    "/users/shared/", "launchagents", "launchdaemons",
                    "/library/cron", "/.ssh/", "sudoers",
                ]
                for sp in sus_paths:
                    if sp in path_lower:
                        tags.append("SUSPICIOUS_PATH")
                        suspicious = True
                        break

                # Flag deletions of security-relevant files
                if "Removed" in decoded_flags:
                    tags.append("deleted")
                    if any(x in path_lower for x in [".bash_history", ".zsh_history", ".log"]):
                        tags.append("ANTI_FORENSICS")
                        suspicious = True

                if "Created" in decoded_flags:
                    tags.append("created")
                if "Modified" in decoded_flags:
                    tags.append("modified")

                findings.append(Finding(
                    source=f".fseventsd/{ef.name}",
                    key=path,
                    value=f"EventID={event_id}, Flags={','.join(decoded_flags)}",
                    category=self.category,
                    tags=tags,
                    mitre_att_ck="T1070.004" if "ANTI_FORENSICS" in tags else None,
                ))

                total += 1

            if total >= max_records:
                findings.append(Finding(
                    source="macos_fsevents",
                    key="truncated",
                    value=f"Output limited to {max_records} records. Use --max-records to increase.",
                    category=self.category,
                ))
                break

        return findings
