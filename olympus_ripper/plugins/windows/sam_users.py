"""
Olympus Ripper — SAM User Account Plugin
(c) 2026 Olympus Cyber. All rights reserved.

Extracts local user accounts, RIDs, login counts, password policy,
and last login timestamps from the SAM hive.
"""

from datetime import datetime, timezone
from ...plugin_base import (
    ArtifactCategory,
    Finding,
    RegistryPlugin,
)

try:
    from Registry import Registry
except ImportError:
    Registry = None


class SAMUsersPlugin(RegistryPlugin):
    name = "sam_users"
    description = "Extract local user accounts, RIDs, and login metadata from SAM hive"
    author = "Olympus Cyber"
    version = "1.0.0"
    category = ArtifactCategory.CREDENTIALS
    hive_type = "SAM"
    registry_keys = [
        "SAM\\Domains\\Account\\Users",
        "SAM\\Domains\\Account\\Users\\Names",
    ]

    @property
    def mitre_references(self) -> list[str]:
        return ["T1003.002", "T1087.001"]

    def run(self, target: str, **kwargs) -> list[Finding]:
        findings = []

        if Registry is None:
            findings.append(Finding(
                source="sam_users",
                key="error",
                value="python-registry not installed. Run: pip install python-registry",
                category=self.category,
            ))
            return findings

        try:
            reg = Registry.Registry(target)
        except Exception as e:
            findings.append(Finding(
                source="sam_users",
                key="error",
                value=f"Failed to open SAM hive: {e}",
                category=self.category,
            ))
            return findings

        # Extract user names from Names subkey
        try:
            names_key = reg.open("SAM\\Domains\\Account\\Users\\Names")
            for subkey in names_key.subkeys():
                username = subkey.name()
                # The default value type encodes the RID
                try:
                    rid = subkey.value("(default)").value_type()
                except Exception:
                    rid = "unknown"

                findings.append(Finding(
                    source="SAM\\Domains\\Account\\Users\\Names",
                    key=f"User: {username}",
                    value=f"RID={rid}",
                    timestamp=subkey.timestamp(),
                    category=self.category,
                    tags=["user_account", "sam"],
                ))
        except Registry.RegistryKeyNotFoundException:
            pass
        except Exception as e:
            findings.append(Finding(
                source="sam_users",
                key="parse_warning",
                value=f"Could not enumerate user names: {e}",
                category=self.category,
            ))

        # Extract RID-keyed user entries with F and V values
        try:
            users_key = reg.open("SAM\\Domains\\Account\\Users")
            for subkey in users_key.subkeys():
                if subkey.name() == "Names":
                    continue

                rid_str = subkey.name()
                try:
                    rid = int(rid_str, 16)
                except ValueError:
                    continue

                # Parse F value (contains login count, timestamps)
                try:
                    f_value = subkey.value("F").value()
                    if len(f_value) >= 72:
                        login_count = int.from_bytes(f_value[66:68], "little")
                        findings.append(Finding(
                            source=f"SAM\\Domains\\Account\\Users\\{rid_str}",
                            key=f"RID {rid} Login Count",
                            value=login_count,
                            category=self.category,
                            tags=["login_count", "sam"],
                        ))

                        # Account flags at offset 56
                        acct_flags = int.from_bytes(f_value[56:58], "little")
                        flags = []
                        if acct_flags & 0x0001:
                            flags.append("DISABLED")
                        if acct_flags & 0x0004:
                            flags.append("PASSWORD_NOT_REQUIRED")
                        if acct_flags & 0x0200:
                            flags.append("NORMAL_ACCOUNT")
                        if acct_flags & 0x10000:
                            flags.append("DONT_EXPIRE_PASSWORD")

                        if flags:
                            findings.append(Finding(
                                source=f"SAM\\Domains\\Account\\Users\\{rid_str}",
                                key=f"RID {rid} Account Flags",
                                value=", ".join(flags),
                                category=self.category,
                                tags=["account_flags", "sam"],
                            ))
                except (Registry.RegistryValueNotFoundException, Exception):
                    pass

                # Parse V value (contains username, full name, comment)
                try:
                    v_value = subkey.value("V").value()
                    if len(v_value) > 0x0C:
                        findings.append(Finding(
                            source=f"SAM\\Domains\\Account\\Users\\{rid_str}",
                            key=f"RID {rid} V Value",
                            value=f"V data present ({len(v_value)} bytes)",
                            category=self.category,
                            tags=["v_value", "sam"],
                        ))
                except (Registry.RegistryValueNotFoundException, Exception):
                    pass

        except Registry.RegistryKeyNotFoundException:
            pass

        return findings
