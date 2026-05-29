"""
Olympus Ripper — macOS TCC.db Plugin
(c) 2026 Olympus Cyber. All rights reserved.

Parses the Transparency, Consent, and Control database to extract
application permissions (camera, microphone, accessibility, FDA, etc.).
Critical for detecting unauthorized access grants and persistence.
"""

import sqlite3
from datetime import datetime, timezone
from ...plugin_base import ArtifactCategory, Finding, MacArtifactPlugin


class TCCPermissionsPlugin(MacArtifactPlugin):
    name = "macos_tcc"
    description = "Extract TCC.db application permissions (camera, mic, accessibility, FDA)"
    author = "Olympus Cyber"
    version = "1.0.0"
    category = ArtifactCategory.PERMISSIONS
    artifact_type = "sqlite"
    default_paths = [
        "/Library/Application Support/com.apple.TCC/TCC.db",
        "private/var/db/tcc/TCC.db",  # System-level (root)
    ]

    @property
    def mitre_references(self) -> list[str]:
        return ["T1548", "T1562.001"]

    # Human-readable service names
    SERVICE_MAP = {
        "kTCCServiceAccessibility": "Accessibility",
        "kTCCServiceCamera": "Camera",
        "kTCCServiceMicrophone": "Microphone",
        "kTCCServiceScreenCapture": "Screen Capture",
        "kTCCServiceSystemPolicyAllFiles": "Full Disk Access",
        "kTCCServiceSystemPolicyDesktopFolder": "Desktop Access",
        "kTCCServiceSystemPolicyDocumentsFolder": "Documents Access",
        "kTCCServiceSystemPolicyDownloadsFolder": "Downloads Access",
        "kTCCServiceSystemPolicyNetworkVolumes": "Network Volumes",
        "kTCCServiceSystemPolicyRemovableVolumes": "Removable Volumes",
        "kTCCServiceSystemPolicySysAdminFiles": "Admin Files",
        "kTCCServiceAddressBook": "Contacts",
        "kTCCServiceCalendar": "Calendar",
        "kTCCServiceReminders": "Reminders",
        "kTCCServicePhotos": "Photos",
        "kTCCServiceMediaLibrary": "Media Library",
        "kTCCServiceAppleEvents": "Apple Events / Automation",
        "kTCCServiceListenEvent": "Input Monitoring",
        "kTCCServicePostEvent": "Posting Events",
        "kTCCServiceLocation": "Location Services",
        "kTCCServiceBluetoothAlways": "Bluetooth",
        "kTCCServiceFileProviderDomain": "File Provider",
        "kTCCServiceFileProviderPresence": "File Provider Presence",
        "kTCCServiceEndpointSecurityClient": "Endpoint Security",
    }

    # High-risk services that warrant extra scrutiny
    HIGH_RISK_SERVICES = {
        "kTCCServiceAccessibility",
        "kTCCServiceScreenCapture",
        "kTCCServiceSystemPolicyAllFiles",
        "kTCCServiceEndpointSecurityClient",
        "kTCCServiceCamera",
        "kTCCServiceMicrophone",
        "kTCCServiceListenEvent",
    }

    def run(self, target: str, **kwargs) -> list[Finding]:
        findings = []

        try:
            conn = sqlite3.connect(f"file:{target}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
        except Exception as e:
            findings.append(Finding(
                source="macos_tcc", key="error",
                value=f"Failed to open TCC.db: {e}",
                category=self.category,
            ))
            return findings

        try:
            # Query access table — schema varies by macOS version
            try:
                cursor.execute("""
                    SELECT service, client, client_type, auth_value,
                           auth_reason, last_modified, flags
                    FROM access
                    ORDER BY last_modified DESC
                """)
            except sqlite3.OperationalError:
                # Older schema
                cursor.execute("""
                    SELECT service, client, client_type, allowed,
                           NULL as auth_reason, last_modified, 0 as flags
                    FROM access
                    ORDER BY last_modified DESC
                """)

            for row in cursor.fetchall():
                service = row["service"]
                client = row["client"]
                client_type = row["client_type"]

                # auth_value: 0=denied, 1=unknown, 2=allowed, 3=limited
                try:
                    auth = row["auth_value"]
                except (IndexError, KeyError):
                    auth = row["allowed"] if "allowed" in row.keys() else 0

                auth_map = {0: "DENIED", 1: "UNKNOWN", 2: "ALLOWED", 3: "LIMITED"}
                auth_str = auth_map.get(auth, str(auth))

                # Client type: 0=bundle_id, 1=absolute_path
                client_type_str = "bundle_id" if client_type == 0 else "path"

                service_name = self.SERVICE_MAP.get(service, service)

                # Timestamp
                ts = None
                last_mod = row["last_modified"]
                if last_mod and last_mod > 0:
                    try:
                        # macOS TCC uses Unix epoch (seconds since 2001-01-01 for some versions)
                        # Try standard Unix first
                        ts = datetime.fromtimestamp(last_mod, tz=timezone.utc)
                        # Sanity check — if year < 2000, it might be Mac Absolute Time
                        if ts.year < 2000:
                            mac_epoch = datetime(2001, 1, 1, tzinfo=timezone.utc)
                            ts = datetime.fromtimestamp(
                                last_mod + mac_epoch.timestamp(), tz=timezone.utc
                            )
                    except (ValueError, OverflowError, OSError):
                        ts = None

                tags = ["tcc", "permission", auth_str.lower()]
                is_high_risk = service in self.HIGH_RISK_SERVICES

                if is_high_risk and auth in (2, 3):
                    tags.append("HIGH_RISK_GRANT")

                if auth == 2 and is_high_risk:
                    tags.append("REVIEW_REQUIRED")

                findings.append(Finding(
                    source=f"TCC.db/access",
                    key=f"{service_name} -> {client}",
                    value=f"Auth={auth_str}, ClientType={client_type_str}",
                    timestamp=ts,
                    category=self.category,
                    tags=tags,
                    mitre_att_ck="T1548" if is_high_risk and auth == 2 else None,
                ))

        except Exception as e:
            findings.append(Finding(
                source="macos_tcc", key="parse_error",
                value=f"Error parsing TCC.db: {e}",
                category=self.category,
            ))
        finally:
            conn.close()

        return findings
