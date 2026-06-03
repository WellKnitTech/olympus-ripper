"""
Olympus Ripper — macOS Quarantine Events Plugin
(c) 2026 Olympus Cyber. All rights reserved.

Parses the QuarantineEventsV2 SQLite database which tracks
all files downloaded via quarantine-aware applications (Safari,
Chrome, Mail, AirDrop, etc.). Critical for tracking initial access.
"""

from datetime import datetime, timezone, timedelta
from ...plugin_base import ArtifactCategory, Finding, MacArtifactPlugin
from ...sqlite_utils import connect_sqlite_readonly

MAC_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)


class QuarantineEventsPlugin(MacArtifactPlugin):
    name = "macos_quarantine"
    description = "Extract downloaded file history from QuarantineEventsV2 (com.apple.LaunchServices)"
    author = "Olympus Cyber"
    version = "1.0.0"
    category = ArtifactCategory.FILE_ACTIVITY
    artifact_type = "sqlite"
    default_paths = [
        "Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2",
        # User-level path (under ~/Library)
    ]

    @property
    def mitre_references(self) -> list[str]:
        return ["T1566.001", "T1204.002"]

    # Agent bundle IDs of interest
    AGENT_MAP = {
        "com.apple.Safari": "Safari",
        "com.google.Chrome": "Chrome",
        "com.apple.mail": "Mail",
        "com.apple.sharingd": "AirDrop",
        "com.apple.curl": "curl",
        "org.mozilla.firefox": "Firefox",
        "com.microsoft.edgemac": "Edge",
        "com.tinyspeck.slackmacgap": "Slack",
    }

    def run(self, target: str, **kwargs) -> list[Finding]:
        findings = []

        try:
            conn = connect_sqlite_readonly(target, row_factory=True)
            cursor = conn.cursor()
        except Exception as e:
            findings.append(Finding(
                source="macos_quarantine", key="error",
                value=f"Failed to open QuarantineEvents: {e}",
                category=self.category,
            ))
            return findings

        try:
            cursor.execute("""
                SELECT LSQuarantineEventIdentifier,
                       LSQuarantineTimeStamp,
                       LSQuarantineAgentBundleIdentifier,
                       LSQuarantineAgentName,
                       LSQuarantineDataURLString,
                       LSQuarantineOriginURLString,
                       LSQuarantineSenderName,
                       LSQuarantineSenderAddress,
                       LSQuarantineTypeNumber
                FROM LSQuarantineEvent
                ORDER BY LSQuarantineTimeStamp DESC
            """)

            for row in cursor.fetchall():
                ts = None
                raw_ts = row["LSQuarantineTimeStamp"]
                if raw_ts:
                    try:
                        ts = MAC_EPOCH + timedelta(seconds=raw_ts)
                    except (ValueError, OverflowError):
                        pass

                agent_bundle = row["LSQuarantineAgentBundleIdentifier"] or ""
                agent_name = row["LSQuarantineAgentName"] or self.AGENT_MAP.get(agent_bundle, agent_bundle)
                data_url = row["LSQuarantineDataURLString"] or ""
                origin_url = row["LSQuarantineOriginURLString"] or ""
                sender_name = row["LSQuarantineSenderName"] or ""
                sender_addr = row["LSQuarantineSenderAddress"] or ""
                qtype = row["LSQuarantineTypeNumber"]

                # Type: 0=web download, 1=email attachment, 2=message attachment, etc.
                type_map = {
                    0: "WebDownload",
                    1: "EmailAttachment",
                    2: "MessageAttachment",
                    3: "CalendarAttachment",
                    4: "OtherAttachment",
                }
                type_str = type_map.get(qtype, f"Type{qtype}")

                tags = ["quarantine", "download", type_str.lower()]

                # Suspicious file extensions
                if data_url:
                    ext_lower = data_url.lower()
                    sus_exts = [".dmg", ".pkg", ".app", ".command", ".sh",
                                ".scpt", ".terminal", ".jar", ".py",
                                ".zip", ".rar", ".iso"]
                    for ext in sus_exts:
                        if ext_lower.endswith(ext):
                            tags.append("executable_download")
                            break

                value_parts = [f"Agent={agent_name}", f"Type={type_str}"]
                if data_url:
                    value_parts.append(f"URL={data_url}")
                if origin_url and origin_url != data_url:
                    value_parts.append(f"Origin={origin_url}")
                if sender_name:
                    value_parts.append(f"Sender={sender_name}")
                if sender_addr:
                    value_parts.append(f"SenderAddr={sender_addr}")

                findings.append(Finding(
                    source="QuarantineEventsV2",
                    key=f"Download via {agent_name}",
                    value=", ".join(value_parts),
                    timestamp=ts,
                    category=self.category,
                    tags=tags,
                    mitre_att_ck="T1566.001" if qtype == 1 else "T1204.002",
                ))

        except Exception as e:
            findings.append(Finding(
                source="macos_quarantine", key="parse_error",
                value=f"Error parsing QuarantineEvents: {e}",
                category=self.category,
            ))
        finally:
            conn.close()

        return findings
