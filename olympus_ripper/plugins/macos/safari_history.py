"""
Olympus Ripper — macOS Safari History Plugin
(c) 2026 Olympus Cyber. All rights reserved.

Parses Safari's History.db and Downloads.plist for browsing activity
and download history. Useful for reconstructing user activity timelines.
"""

import sqlite3
from datetime import datetime, timezone, timedelta
from ...plugin_base import ArtifactCategory, Finding, MacArtifactPlugin

MAC_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)


class SafariHistoryPlugin(MacArtifactPlugin):
    name = "macos_safari_history"
    description = "Extract Safari browsing history and downloads"
    author = "Olympus Cyber"
    version = "1.0.0"
    category = ArtifactCategory.USER_ACTIVITY
    artifact_type = "sqlite"
    default_paths = [
        "Library/Safari/History.db",
    ]

    def run(self, target: str, **kwargs) -> list[Finding]:
        findings = []

        try:
            conn = sqlite3.connect(f"file:{target}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
        except Exception as e:
            findings.append(Finding(
                source="macos_safari_history", key="error",
                value=f"Failed to open Safari History.db: {e}",
                category=self.category,
            ))
            return findings

        try:
            cursor.execute("""
                SELECT
                    history_items.url,
                    history_items.domain_expansion,
                    history_visits.visit_time,
                    history_visits.title,
                    history_items.visit_count
                FROM history_items
                JOIN history_visits ON history_items.id = history_visits.history_item
                ORDER BY history_visits.visit_time DESC
                LIMIT 2000
            """)

            for row in cursor.fetchall():
                ts = None
                visit_time = row["visit_time"]
                if visit_time:
                    try:
                        ts = MAC_EPOCH + timedelta(seconds=visit_time)
                    except (ValueError, OverflowError):
                        pass

                url = row["url"] or ""
                title = row["title"] or ""
                domain = row["domain_expansion"] or ""
                visit_count = row["visit_count"] or 0

                tags = ["safari", "browsing_history"]

                findings.append(Finding(
                    source="Safari/History.db",
                    key=f"Visit: {domain or title[:50]}",
                    value=f"URL={url}, Title={title}, Visits={visit_count}",
                    timestamp=ts,
                    category=self.category,
                    tags=tags,
                ))

        except Exception as e:
            findings.append(Finding(
                source="macos_safari_history", key="parse_error",
                value=f"Error parsing Safari history: {e}",
                category=self.category,
            ))
        finally:
            conn.close()

        return findings
