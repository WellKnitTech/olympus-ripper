"""
Olympus Ripper — macOS LaunchAgents/LaunchDaemons Persistence Plugin
(c) 2026 Olympus Cyber. All rights reserved.

Scans LaunchAgent and LaunchDaemon plist files for persistence mechanisms.
Flags suspicious entries: non-Apple, hidden, running as root, etc.
"""

import os
import plistlib
from pathlib import Path
from ...plugin_base import ArtifactCategory, Finding, MacArtifactPlugin


class LaunchPersistencePlugin(MacArtifactPlugin):
    name = "macos_launch_persistence"
    description = "Scan LaunchAgents and LaunchDaemons for persistence mechanisms"
    author = "Olympus Cyber"
    version = "1.0.0"
    category = ArtifactCategory.PERSISTENCE
    artifact_type = "plist"
    default_paths = [
        "/Library/LaunchAgents",
        "/Library/LaunchDaemons",
        "/System/Library/LaunchAgents",
        "/System/Library/LaunchDaemons",
    ]

    @property
    def mitre_references(self) -> list[str]:
        return ["T1543.001", "T1543.004"]

    # Known Apple bundle ID prefixes (not exhaustive but catches most)
    APPLE_PREFIXES = [
        "com.apple.", "com.openssh.", "org.ntp.", "org.postfix.",
    ]

    SUSPICIOUS_INDICATORS = [
        "/tmp/", "/private/tmp/", "/Users/Shared/",
        "curl ", "wget ", "python", "osascript",
        "base64", "openssl", "nc ", "ncat",
        "/dev/tcp/", "bash -c", "sh -c",
    ]

    def _is_apple(self, label: str, program: str) -> bool:
        """Check if a launch item appears to be Apple-signed."""
        for prefix in self.APPLE_PREFIXES:
            if label.startswith(prefix):
                return True
        if program and ("/System/Library" in program or "/usr/libexec" in program):
            return True
        return False

    def run(self, target: str, **kwargs) -> list[Finding]:
        """
        target: path to a LaunchAgents or LaunchDaemons directory,
                or a specific .plist file.
        """
        findings = []
        target_path = Path(target)

        if target_path.is_file() and target_path.suffix == ".plist":
            plist_files = [target_path]
        elif target_path.is_dir():
            plist_files = list(target_path.glob("*.plist"))
        else:
            return findings

        for pf in plist_files:
            try:
                with open(pf, "rb") as f:
                    plist = plistlib.load(f)
            except Exception as e:
                findings.append(Finding(
                    source=str(pf),
                    key=f"Parse Error: {pf.name}",
                    value=f"Could not parse plist: {e}",
                    category=self.category,
                    tags=["parse_error"],
                ))
                continue

            label = plist.get("Label", pf.stem)

            # Extract program info
            program = plist.get("Program", "")
            program_args = plist.get("ProgramArguments", [])
            if not program and program_args:
                program = program_args[0] if program_args else ""
            full_cmd = " ".join(program_args) if program_args else program

            # Execution triggers
            run_at_load = plist.get("RunAtLoad", False)
            keep_alive = plist.get("KeepAlive", False)
            start_interval = plist.get("StartInterval")
            start_calendar = plist.get("StartCalendarInterval")
            watch_paths = plist.get("WatchPaths", [])

            # User context
            user_name = plist.get("UserName", "")
            group_name = plist.get("GroupName", "")

            # Build description
            triggers = []
            if run_at_load:
                triggers.append("RunAtLoad")
            if keep_alive:
                triggers.append("KeepAlive")
            if start_interval:
                triggers.append(f"Interval={start_interval}s")
            if start_calendar:
                triggers.append("CalendarInterval")
            if watch_paths:
                triggers.append(f"WatchPaths={watch_paths}")

            is_apple = self._is_apple(label, program)
            tags = ["launch_item"]

            # Determine directory type
            dir_name = pf.parent.name
            if "LaunchDaemon" in dir_name:
                tags.append("daemon")
                is_daemon = True
            else:
                tags.append("agent")
                is_daemon = False

            # Suspicious indicators
            suspicious = False
            sus_reasons = []

            if not is_apple:
                tags.append("third_party")

                for ind in self.SUSPICIOUS_INDICATORS:
                    if ind in full_cmd:
                        suspicious = True
                        sus_reasons.append(f"suspicious_cmd: {ind.strip()}")

                if is_daemon and not user_name:
                    # Daemon running as root with no explicit user
                    tags.append("runs_as_root")

                # Check for hidden or dot-prefixed files
                if program and (
                    "/." in program or program.startswith(".")
                ):
                    suspicious = True
                    sus_reasons.append("hidden_path")

            if suspicious:
                tags.append("SUSPICIOUS")

            value_parts = [f"Cmd={full_cmd or 'N/A'}"]
            if triggers:
                value_parts.append(f"Triggers={','.join(triggers)}")
            if user_name:
                value_parts.append(f"User={user_name}")
            if sus_reasons:
                value_parts.append(f"Flags={','.join(sus_reasons)}")

            findings.append(Finding(
                source=str(pf),
                key=f"{'Daemon' if is_daemon else 'Agent'}: {label}",
                value=", ".join(value_parts),
                category=self.category,
                tags=tags,
                mitre_att_ck="T1543.004" if is_daemon else "T1543.001",
            ))

        return findings
