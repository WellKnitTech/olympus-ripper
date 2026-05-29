"""
Olympus Ripper — macOS Login Items & Startup Plugin
(c) 2026 Olympus Cyber. All rights reserved.

Extracts login items from various macOS persistence locations:
- backgrounditems.btm (managed login items, macOS 13+)
- loginitems.plist (legacy)
- loginwindow.plist
"""

import plistlib
import sqlite3
from pathlib import Path
from ...plugin_base import ArtifactCategory, Finding, MacArtifactPlugin


class LoginItemsPlugin(MacArtifactPlugin):
    name = "macos_login_items"
    description = "Extract login items and startup applications from macOS"
    author = "Olympus Cyber"
    version = "1.0.0"
    category = ArtifactCategory.PERSISTENCE
    artifact_type = "plist"
    default_paths = [
        "Library/Preferences/com.apple.loginwindow.plist",
        "Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm",
        "private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm",
    ]

    @property
    def mitre_references(self) -> list[str]:
        return ["T1547.015"]

    def run(self, target: str, **kwargs) -> list[Finding]:
        findings = []
        target_path = Path(target)

        if target_path.suffix == ".plist":
            findings.extend(self._parse_loginwindow_plist(target))
        elif target_path.suffix == ".btm":
            findings.extend(self._parse_btm(target))
        else:
            # Try both
            findings.extend(self._parse_loginwindow_plist(target))
            findings.extend(self._parse_btm(target))

        return findings

    def _parse_loginwindow_plist(self, path: str) -> list[Finding]:
        findings = []
        try:
            with open(path, "rb") as f:
                plist = plistlib.load(f)

            # AutoLaunchedApplicationDictionary
            auto_launch = plist.get("AutoLaunchedApplicationDictionary_v2", [])
            if not auto_launch:
                auto_launch = plist.get("AutoLaunchedApplicationDictionary", [])

            for item in auto_launch:
                if isinstance(item, dict):
                    app_path = item.get("Path", "")
                    hidden = item.get("Hide", False)

                    tags = ["login_item", "auto_launch"]
                    if hidden:
                        tags.append("hidden")

                    findings.append(Finding(
                        source=path,
                        key="Login Item",
                        value=f"Path={app_path}, Hidden={hidden}",
                        category=self.category,
                        tags=tags,
                        mitre_att_ck="T1547.015",
                    ))

            # LoginHook / LogoutHook (deprecated but still functional)
            login_hook = plist.get("LoginHook", "")
            logout_hook = plist.get("LogoutHook", "")

            if login_hook:
                findings.append(Finding(
                    source=path,
                    key="LoginHook (DEPRECATED)",
                    value=login_hook,
                    category=self.category,
                    tags=["login_hook", "persistence", "SUSPICIOUS"],
                    mitre_att_ck="T1037.002",
                ))

            if logout_hook:
                findings.append(Finding(
                    source=path,
                    key="LogoutHook (DEPRECATED)",
                    value=logout_hook,
                    category=self.category,
                    tags=["logout_hook", "persistence"],
                ))

        except Exception:
            pass

        return findings

    def _parse_btm(self, path: str) -> list[Finding]:
        """Parse backgrounditems.btm (binary plist or SQLite depending on version)."""
        findings = []

        # Try plist first
        try:
            with open(path, "rb") as f:
                plist = plistlib.load(f)

            items = plist.get("$objects", [])
            for item in items:
                if isinstance(item, dict):
                    url = item.get("NS.relative", "") or item.get("NS.string", "")
                    if url and ("file://" in str(url) or "/" in str(url)):
                        findings.append(Finding(
                            source=path,
                            key="Background Login Item",
                            value=str(url),
                            category=self.category,
                            tags=["btm", "login_item"],
                            mitre_att_ck="T1547.015",
                        ))
            return findings
        except Exception:
            pass

        # Try SQLite (macOS 14+ BackgroundItems-v4.btm)
        try:
            conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM sqlite_master WHERE type='table'")
            tables = [r[1] for r in cursor.fetchall()]

            if "items" in tables:
                cursor.execute("SELECT identifier, url, type FROM items")
                for row in cursor.fetchall():
                    findings.append(Finding(
                        source=path,
                        key=f"BTM Item: {row[0] or 'unknown'}",
                        value=f"URL={row[1] or 'N/A'}, Type={row[2] or 'N/A'}",
                        category=self.category,
                        tags=["btm", "login_item"],
                        mitre_att_ck="T1547.015",
                    ))
            conn.close()
        except Exception:
            pass

        return findings
