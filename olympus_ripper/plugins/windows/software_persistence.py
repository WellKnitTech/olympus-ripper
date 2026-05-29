"""
Olympus Ripper — SOFTWARE Hive Persistence & Installed Apps Plugin
(c) 2026 Olympus Cyber. All rights reserved.

Extracts Run/RunOnce keys, installed software, uninstall entries,
and other persistence mechanisms from the SOFTWARE hive.
"""

from ...plugin_base import ArtifactCategory, Finding, RegistryPlugin

try:
    from Registry import Registry
except ImportError:
    Registry = None


class SoftwarePersistencePlugin(RegistryPlugin):
    name = "software_persistence"
    description = "Extract Run keys, scheduled tasks, and persistence from SOFTWARE hive"
    author = "Olympus Cyber"
    version = "1.0.0"
    category = ArtifactCategory.PERSISTENCE
    hive_type = "SOFTWARE"
    registry_keys = [
        "Microsoft\\Windows\\CurrentVersion\\Run",
        "Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "Microsoft\\Windows\\CurrentVersion\\RunServices",
        "Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
        "Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
        "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    ]

    @property
    def mitre_references(self) -> list[str]:
        return ["T1547.001", "T1547.004"]

    def run(self, target: str, **kwargs) -> list[Finding]:
        findings = []

        if Registry is None:
            findings.append(Finding(
                source="software_persistence", key="error",
                value="python-registry not installed",
                category=self.category,
            ))
            return findings

        try:
            reg = Registry.Registry(target)
        except Exception as e:
            findings.append(Finding(
                source="software_persistence", key="error",
                value=f"Failed to open SOFTWARE hive: {e}",
                category=self.category,
            ))
            return findings

        # Check all Run key variants
        for key_path in self.registry_keys:
            try:
                key = reg.open(key_path)
                for val in key.values():
                    if val.name() == "(default)":
                        continue

                    value_data = val.value()
                    tags = ["autorun", "persistence"]

                    # Suspicious path detection
                    if isinstance(value_data, str):
                        vd_lower = value_data.lower()
                        sus_indicators = [
                            "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp",
                            "powershell", "cmd.exe", "mshta", "wscript",
                            "cscript", "rundll32", "regsvr32", "certutil",
                            "bitsadmin", "-enc", "-encodedcommand",
                            "downloadstring", "invoke-expression",
                        ]
                        for ind in sus_indicators:
                            if ind in vd_lower:
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
            except (Registry.RegistryKeyNotFoundException, Exception):
                continue

        return findings


class SoftwareInstalledAppsPlugin(RegistryPlugin):
    name = "software_installed"
    description = "Extract installed applications from SOFTWARE\\Uninstall keys"
    author = "Olympus Cyber"
    version = "1.0.0"
    category = ArtifactCategory.APPLICATION
    hive_type = "SOFTWARE"
    registry_keys = [
        "Microsoft\\Windows\\CurrentVersion\\Uninstall",
        "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
    ]

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
                for subkey in key.subkeys():
                    app_name = None
                    app_version = None
                    install_date = None
                    publisher = None
                    install_location = None

                    for val in subkey.values():
                        vn = val.name()
                        if vn == "DisplayName":
                            app_name = val.value()
                        elif vn == "DisplayVersion":
                            app_version = val.value()
                        elif vn == "InstallDate":
                            install_date = val.value()
                        elif vn == "Publisher":
                            publisher = val.value()
                        elif vn == "InstallLocation":
                            install_location = val.value()

                    if app_name:
                        parts = [f"Version={app_version or 'N/A'}"]
                        if publisher:
                            parts.append(f"Publisher={publisher}")
                        if install_date:
                            parts.append(f"Installed={install_date}")
                        if install_location:
                            parts.append(f"Location={install_location}")

                        findings.append(Finding(
                            source=f"{key_path}\\{subkey.name()}",
                            key=app_name,
                            value=", ".join(parts),
                            timestamp=subkey.timestamp(),
                            category=self.category,
                            tags=["installed_app"],
                        ))
            except (Registry.RegistryKeyNotFoundException, Exception):
                continue

        return findings


class SoftwareNetworkListPlugin(RegistryPlugin):
    name = "software_networklist"
    description = "Extract network profiles and connection history from SOFTWARE hive"
    author = "Olympus Cyber"
    version = "1.0.0"
    category = ArtifactCategory.NETWORK
    hive_type = "SOFTWARE"
    registry_keys = [
        "Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles",
        "Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Unmanaged",
    ]

    @property
    def mitre_references(self) -> list[str]:
        return ["T1016"]

    def run(self, target: str, **kwargs) -> list[Finding]:
        findings = []

        if Registry is None:
            return findings

        try:
            reg = Registry.Registry(target)
        except Exception:
            return findings

        try:
            profiles_key = reg.open(
                "Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles"
            )
            for subkey in profiles_key.subkeys():
                profile_name = None
                description = None
                managed = None

                for val in subkey.values():
                    if val.name() == "ProfileName":
                        profile_name = val.value()
                    elif val.name() == "Description":
                        description = val.value()
                    elif val.name() == "Managed":
                        managed = val.value()

                if profile_name:
                    findings.append(Finding(
                        source=f"NetworkList\\Profiles\\{subkey.name()}",
                        key=f"Network Profile: {profile_name}",
                        value=f"Description={description or 'N/A'}, Managed={managed}",
                        timestamp=subkey.timestamp(),
                        category=self.category,
                        tags=["network_profile", "wifi_history"],
                    ))
        except Exception:
            pass

        return findings
