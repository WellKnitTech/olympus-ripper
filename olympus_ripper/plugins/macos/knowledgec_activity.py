"""
Olympus Ripper — macOS KnowledgeC.db Plugin
(c) 2026 Olympus Cyber. All rights reserved.

Parses the KnowledgeC database for user activity: app usage,
device lock/unlock, screen time, web visits, and interactions.
Note: macOS 13+ migrates much of this to Biome format.
"""

from datetime import datetime, timezone, timedelta
from typing import Optional
from ...plugin_base import ArtifactCategory, Finding, MacArtifactPlugin
from ...sqlite_utils import connect_sqlite_readonly


# macOS Absolute Time epoch: 2001-01-01 00:00:00 UTC
MAC_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)


def mac_absolute_to_datetime(mac_ts: float) -> Optional[datetime]:
    """Convert Mac Absolute Time to datetime."""
    if mac_ts is None or mac_ts == 0:
        return None
    try:
        return MAC_EPOCH + timedelta(seconds=mac_ts)
    except (ValueError, OverflowError):
        return None


class KnowledgeCActivityPlugin(MacArtifactPlugin):
    name = "macos_knowledgec"
    description = "Extract app usage, device activity, and user behavior from KnowledgeC.db"
    author = "Olympus Cyber"
    version = "1.0.0"
    category = ArtifactCategory.USER_ACTIVITY
    artifact_type = "sqlite"
    default_paths = [
        "private/var/db/CoreDuet/Knowledge/knowledgeC.db",
        "Library/Application Support/Knowledge/knowledgeC.db",
    ]

    # Stream types of forensic interest
    INTERESTING_STREAMS = {
        "/app/inFocus": "App In Focus",
        "/app/activity": "App Activity",
        "/app/install": "App Install",
        "/app/intents": "App Intents",
        "/device/isLocked": "Device Lock State",
        "/device/isPluggedIn": "Device Plugged In",
        "/display/isBacklit": "Display Backlit",
        "/safari/history": "Safari History",
        "/app/webUsage": "Web Usage",
        "/audio/outputRoute": "Audio Output",
        "/device/batteryPercentage": "Battery Level",
    }

    def run(self, target: str, **kwargs) -> list[Finding]:
        findings = []

        try:
            conn = connect_sqlite_readonly(target, row_factory=True)
            cursor = conn.cursor()
        except Exception as e:
            findings.append(Finding(
                source="macos_knowledgec", key="error",
                value=f"Failed to open KnowledgeC.db: {e}",
                category=self.category,
            ))
            return findings

        try:
            # Get all object types (streams)
            cursor.execute("""
                SELECT ZOBJECT.Z_PK, ZOBJECT.ZSTREAMNAME, ZOBJECT.ZVALUESTRING,
                       ZOBJECT.ZSTARTDATE, ZOBJECT.ZENDDATE,
                       ZOBJECT.ZCREATIONDATE,
                       ZSOURCE.ZBUNDLEID
                FROM ZOBJECT
                LEFT JOIN ZSOURCE ON ZOBJECT.ZSOURCE = ZSOURCE.Z_PK
                ORDER BY ZOBJECT.ZSTARTDATE DESC
                LIMIT 5000
            """)

            for row in cursor.fetchall():
                stream = row["ZSTREAMNAME"]
                if stream not in self.INTERESTING_STREAMS:
                    continue

                stream_label = self.INTERESTING_STREAMS[stream]
                value = row["ZVALUESTRING"] or ""
                bundle_id = row["ZBUNDLEID"] or ""

                start_ts = mac_absolute_to_datetime(row["ZSTARTDATE"])
                end_ts = mac_absolute_to_datetime(row["ZENDDATE"])

                # Calculate duration if both timestamps present
                duration_str = ""
                if start_ts and end_ts and end_ts > start_ts:
                    dur = (end_ts - start_ts).total_seconds()
                    if dur < 3600:
                        duration_str = f", Duration={dur:.0f}s"
                    else:
                        duration_str = f", Duration={dur / 3600:.1f}h"

                display_value = value or bundle_id
                if bundle_id and value and bundle_id != value:
                    display_value = f"{value} ({bundle_id})"

                tags = ["knowledgec", stream.strip("/").replace("/", "_")]

                # Flag interesting patterns
                if stream == "/device/isLocked" and value == "0":
                    tags.append("device_unlocked")
                elif stream == "/app/install":
                    tags.append("app_installed")

                findings.append(Finding(
                    source=f"KnowledgeC/{stream}",
                    key=f"{stream_label}",
                    value=f"{display_value}{duration_str}",
                    timestamp=start_ts,
                    category=self.category,
                    tags=tags,
                ))

        except Exception as e:
            findings.append(Finding(
                source="macos_knowledgec", key="parse_error",
                value=f"Error parsing KnowledgeC.db: {e}",
                category=self.category,
            ))
        finally:
            conn.close()

        return findings
