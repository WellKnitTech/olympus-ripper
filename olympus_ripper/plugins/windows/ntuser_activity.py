"""
Olympus Ripper — NTUSER.DAT User Activity Plugin
(c) 2026 Olympus Cyber. All rights reserved.

Extracts UserAssist, RecentDocs, TypedPaths, Run/RunOnce keys,
MRU lists, and other user-specific artifacts from NTUSER.DAT.
"""

import struct
from datetime import datetime, timezone
from ...plugin_base import ArtifactCategory, Finding, RegistryPlugin

try:
    from Registry import Registry
except ImportError:
    Registry = None


def rot13(s: str) -> str:
    """Decode ROT13 — UserAssist values are ROT13 encoded."""
    result = []
    for c in s:
        if "a" <= c <= "z":
            result.append(chr((ord(c) - ord("a") + 13) % 26 + ord("a")))
        elif "A" <= c <= "Z":
            result.append(chr((ord(c) - ord("A") + 13) % 26 + ord("A")))
        else:
            result.append(c)
    return "".join(result)


def filetime_to_datetime(ft: int) -> datetime | None:
    """Convert Windows FILETIME (100-ns intervals since 1601-01-01) to datetime."""
    if ft == 0 or ft is None:
        return None
    try:
        EPOCH_DIFF = 116444736000000000
        timestamp = (ft - EPOCH_DIFF) / 10000000
        return datetime.fromtimestamp(timestamp, tz=timezone.utc)
    except (ValueError, OverflowError, OSError):
        return None


class NTUserAssistPlugin(RegistryPlugin):
    name = "ntuser_userassist"
    description = "Extract UserAssist execution history (ROT13 decoded) from NTUSER.DAT"
    author = "Olympus Cyber"
    version = "1.0.0"
    category = ArtifactCategory.EXECUTION
    hive_type = "NTUSER"
    registry_keys = [
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist",
    ]

    @property
    def mitre_references(self) -> list[str]:
        return ["T1059"]

    # Known UserAssist GUIDs
    GUIDS = {
        "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}": "Executable",
        "{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}": "Shortcut",
    }

    def run(self, target: str, **kwargs) -> list[Finding]:
        findings = []

        if Registry is None:
            return findings

        try:
            reg = Registry.Registry(target)
        except Exception:
            return findings

        try:
            ua_key = reg.open(
                "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist"
            )
        except Registry.RegistryKeyNotFoundException:
            return findings

        for guid_key in ua_key.subkeys():
            guid = guid_key.name()
            ua_type = self.GUIDS.get(guid, "Unknown")

            try:
                count_key = guid_key.subkey("Count")
            except Registry.RegistryKeyNotFoundException:
                continue

            for val in count_key.values():
                if val.name() == "(default)":
                    continue

                # Decode ROT13 name
                decoded_name = rot13(val.name())
                data = val.value()

                run_count = None
                last_executed = None

                if isinstance(data, bytes):
                    # Vista+ format: offset 4 = run count, offset 60 = FILETIME
                    if len(data) >= 72:
                        run_count = struct.unpack("<I", data[4:8])[0]
                        ft = struct.unpack("<Q", data[60:68])[0]
                        last_executed = filetime_to_datetime(ft)
                    # XP format: offset 4 = session, offset 8 = count, offset 16 = FILETIME
                    elif len(data) >= 16:
                        run_count = struct.unpack("<I", data[4:8])[0]

                value_parts = [f"Type={ua_type}"]
                if run_count is not None:
                    value_parts.append(f"RunCount={run_count}")

                findings.append(Finding(
                    source=f"UserAssist\\{guid}\\Count",
                    key=decoded_name,
                    value=", ".join(value_parts),
                    timestamp=last_executed,
                    category=self.category,
                    tags=["userassist", "execution", ua_type.lower()],
                    mitre_att_ck="T1059",
                ))

        return findings


class NTUserRecentDocsPlugin(RegistryPlugin):
    name = "ntuser_recentdocs"
    description = "Extract RecentDocs MRU (recently opened files) from NTUSER.DAT"
    author = "Olympus Cyber"
    version = "1.0.0"
    category = ArtifactCategory.USER_ACTIVITY
    hive_type = "NTUSER"
    registry_keys = [
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs",
    ]

    def run(self, target: str, **kwargs) -> list[Finding]:
        findings = []

        if Registry is None:
            return findings

        try:
            reg = Registry.Registry(target)
        except Exception:
            return findings

        try:
            rd_key = reg.open(
                "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs"
            )
        except Registry.RegistryKeyNotFoundException:
            return findings

        # Process each extension subkey
        for subkey in rd_key.subkeys():
            ext = subkey.name()
            for val in subkey.values():
                if val.name() == "MRUListEx":
                    continue
                data = val.value()
                if isinstance(data, bytes) and len(data) > 0:
                    # Extract filename from binary data (null-terminated UTF-16)
                    try:
                        null_pos = data.find(b"\x00\x00")
                        if null_pos > 0:
                            filename = data[:null_pos + 1].decode("utf-16-le", errors="replace")
                        else:
                            filename = data[:100].decode("utf-16-le", errors="replace")

                        findings.append(Finding(
                            source=f"RecentDocs\\{ext}",
                            key=f"Recent ({ext})",
                            value=filename.strip("\x00"),
                            timestamp=subkey.timestamp(),
                            category=self.category,
                            tags=["recentdocs", "mru", ext.lower()],
                        ))
                    except Exception:
                        pass

        return findings


class NTUserTypedPathsPlugin(RegistryPlugin):
    name = "ntuser_typedpaths"
    description = "Extract TypedPaths (Explorer address bar history) from NTUSER.DAT"
    author = "Olympus Cyber"
    version = "1.0.0"
    category = ArtifactCategory.USER_ACTIVITY
    hive_type = "NTUSER"
    registry_keys = [
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths",
    ]

    def run(self, target: str, **kwargs) -> list[Finding]:
        findings = []

        if Registry is None:
            return findings

        try:
            reg = Registry.Registry(target)
        except Exception:
            return findings

        try:
            tp_key = reg.open(
                "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths"
            )
            for val in tp_key.values():
                if val.name() == "(default)":
                    continue
                findings.append(Finding(
                    source="Explorer\\TypedPaths",
                    key=val.name(),
                    value=val.value(),
                    timestamp=tp_key.timestamp(),
                    category=self.category,
                    tags=["typed_paths", "explorer"],
                ))
        except Registry.RegistryKeyNotFoundException:
            pass

        return findings


class NTUserRunPlugin(RegistryPlugin):
    name = "ntuser_run"
    description = "Extract user-level Run/RunOnce persistence from NTUSER.DAT"
    author = "Olympus Cyber"
    version = "1.0.0"
    category = ArtifactCategory.PERSISTENCE
    hive_type = "NTUSER"
    registry_keys = [
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    ]

    @property
    def mitre_references(self) -> list[str]:
        return ["T1547.001"]

    def run(self, target: str, **kwargs) -> list[Finding]:
        findings = []

        if Registry is None:
            return findings

        try:
            reg = Registry.Registry(target)
        except Exception:
            return findings

        for key_path in self.registry_keys:
            try:
                key = reg.open(key_path)
                for val in key.values():
                    if val.name() == "(default)":
                        continue

                    tags = ["autorun", "persistence", "user_level"]
                    value_data = val.value()

                    if isinstance(value_data, str):
                        vd_lower = value_data.lower()
                        sus = ["powershell", "cmd.exe", "mshta", "wscript",
                               "cscript", "rundll32", "\\temp\\", "\\appdata\\"]
                        for s in sus:
                            if s in vd_lower:
                                tags.append("SUSPICIOUS")
                                break

                    findings.append(Finding(
                        source=key_path,
                        key=val.name(),
                        value=value_data,
                        timestamp=key.timestamp(),
                        category=self.category,
                        tags=tags,
                        mitre_att_ck="T1547.001",
                    ))
            except Exception:
                continue

        return findings
