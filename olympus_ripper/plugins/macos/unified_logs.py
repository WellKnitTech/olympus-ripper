"""
Olympus Ripper — macOS Unified Log Parser Plugin
(c) 2026 Olympus Cyber. All rights reserved.

Parses macOS unified logs using the `log` command or tracev3 files
to extract security-relevant events: process execution, auth events,
network activity, and system modifications.
"""

import json
import subprocess
from datetime import datetime
from pathlib import Path
from ...plugin_base import ArtifactCategory, Finding, HostPlatform, MacArtifactPlugin


class UnifiedLogPlugin(MacArtifactPlugin):
    name = "macos_unified_logs"
    description = "Extract security events from macOS Unified Logs (process exec, auth, network)"
    author = "Olympus Cyber"
    version = "1.0.0"
    category = ArtifactCategory.SECURITY
    artifact_type = "log"
    default_paths = [
        "private/var/db/diagnostics",
        "private/var/db/uuidtext",
    ]

    @property
    def mitre_references(self) -> list[str]:
        return ["T1059", "T1078"]

    @property
    def supported_hosts(self) -> list[HostPlatform]:
        # Apple's `log` command is only available on macOS hosts.
        return [HostPlatform.MACOS]

    # Predicate filters for security-relevant log events
    SECURITY_PREDICATES = {
        "process_exec": {
            "predicate": 'subsystem == "com.apple.execpolicy" OR '
                        'subsystem == "com.apple.processmanager" OR '
                        'eventMessage CONTAINS "exec" OR '
                        'eventMessage CONTAINS "spawn"',
            "label": "Process Execution",
            "category": ArtifactCategory.EXECUTION,
            "mitre": "T1059",
        },
        "auth_events": {
            "predicate": 'subsystem == "com.apple.Authorization" OR '
                        'subsystem == "com.apple.opendirectoryd" OR '
                        'eventMessage CONTAINS "authentication" OR '
                        'eventMessage CONTAINS "login"',
            "label": "Authentication",
            "category": ArtifactCategory.CREDENTIALS,
            "mitre": "T1078",
        },
        "network_activity": {
            "predicate": 'subsystem == "com.apple.networkd" OR '
                        'subsystem == "com.apple.nesessionmanager" OR '
                        'subsystem == "com.apple.CFNetwork"',
            "label": "Network Activity",
            "category": ArtifactCategory.NETWORK,
            "mitre": "T1071",
        },
        "gatekeeper": {
            "predicate": 'subsystem == "com.apple.syspolicy.exec" OR '
                        'subsystem == "com.apple.ManagedClient" OR '
                        'eventMessage CONTAINS "Gatekeeper" OR '
                        'eventMessage CONTAINS "notarization"',
            "label": "Gatekeeper / Code Signing",
            "category": ArtifactCategory.SECURITY,
            "mitre": "T1553.001",
        },
        "tcc_events": {
            "predicate": 'subsystem == "com.apple.TCC"',
            "label": "TCC Permission Changes",
            "category": ArtifactCategory.PERMISSIONS,
            "mitre": "T1548",
        },
    }

    def run(self, target: str, **kwargs) -> list[Finding]:
        """
        target: path to a logarchive directory or 'live' for current system.

        Uses macOS `log` command to query logs. Will only work on macOS
        or when a logarchive is available.
        """
        findings = []
        target_path = Path(target)

        # Check if we can use the log command
        log_cmd = "/usr/bin/log"
        if not Path(log_cmd).exists():
            findings.append(Finding(
                source="macos_unified_logs",
                key="info",
                value="macOS `log` command not available. Run on macOS with a .logarchive or live system.",
                category=self.category,
            ))
            return findings

        # Determine if we're reading an archive or live logs
        archive_flag = []
        if target_path.is_dir() and target_path.suffix == ".logarchive":
            archive_flag = ["--archive", str(target_path)]
        elif target_path.is_dir() and (target_path / "diagnostics").is_dir():
            # Mounted volume — look for logarchive
            logarchives = list(target_path.glob("**/*.logarchive"))
            if logarchives:
                archive_flag = ["--archive", str(logarchives[0])]
            else:
                findings.append(Finding(
                    source="macos_unified_logs",
                    key="info",
                    value="No .logarchive found in target directory.",
                    category=self.category,
                ))
                return findings

        # Query each security predicate
        for pred_name, pred_info in self.SECURITY_PREDICATES.items():
            try:
                cmd = [
                    log_cmd, "show",
                    *archive_flag,
                    "--predicate", pred_info["predicate"],
                    "--style", "json",
                    "--last", kwargs.get("timespan", "24h"),
                ]

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=60,
                )

                if result.returncode != 0:
                    continue

                # Parse JSON output
                try:
                    entries = json.loads(result.stdout)
                except json.JSONDecodeError:
                    continue

                # Limit entries per predicate to avoid flooding
                max_entries = int(kwargs.get("max_per_category", 100))
                for entry in entries[:max_entries]:
                    ts = None
                    ts_str = entry.get("timestamp", "")
                    if ts_str:
                        try:
                            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                        except (ValueError, TypeError):
                            pass

                    process = entry.get("processImagePath", "")
                    subsystem = entry.get("subsystem", "")
                    message = entry.get("eventMessage", "")

                    # Truncate long messages
                    if len(message) > 300:
                        message = message[:300] + "..."

                    findings.append(Finding(
                        source=f"UnifiedLog/{subsystem}",
                        key=f"{pred_info['label']}: {process}",
                        value=message,
                        timestamp=ts,
                        category=pred_info["category"],
                        tags=["unified_log", pred_name],
                        mitre_att_ck=pred_info["mitre"],
                    ))

            except subprocess.TimeoutExpired:
                findings.append(Finding(
                    source="macos_unified_logs",
                    key=f"timeout_{pred_name}",
                    value=f"Log query timed out for predicate: {pred_name}",
                    category=self.category,
                ))
            except Exception as e:
                findings.append(Finding(
                    source="macos_unified_logs",
                    key=f"error_{pred_name}",
                    value=f"Error querying logs: {e}",
                    category=self.category,
                ))

        return findings
