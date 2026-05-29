"""
Olympus Ripper — SYSTEM Services Plugin
(c) 2026 Olympus Cyber. All rights reserved.

Extracts services, drivers, and network configuration from the SYSTEM hive.
Identifies potential persistence mechanisms and suspicious services.
"""

from ...plugin_base import ArtifactCategory, Finding, RegistryPlugin

try:
    from Registry import Registry
except ImportError:
    Registry = None


class SystemServicesPlugin(RegistryPlugin):
    name = "system_services"
    description = "Extract services, drivers, and startup configuration from SYSTEM hive"
    author = "Olympus Cyber"
    version = "1.0.0"
    category = ArtifactCategory.PERSISTENCE
    hive_type = "SYSTEM"
    registry_keys = [
        "ControlSet001\\Services",
        "ControlSet001\\Control\\ComputerName\\ComputerName",
        "ControlSet001\\Control\\TimeZoneInformation",
        "Select",
    ]

    @property
    def mitre_references(self) -> list[str]:
        return ["T1543.003", "T1569.002"]

    def _get_current_controlset(self, reg) -> str:
        try:
            select_key = reg.open("Select")
            current = select_key.value("Current").value()
            return f"ControlSet{current:03d}"
        except Exception:
            return "ControlSet001"

    def run(self, target: str, **kwargs) -> list[Finding]:
        findings = []

        if Registry is None:
            findings.append(Finding(
                source="system_services", key="error",
                value="python-registry not installed",
                category=self.category,
            ))
            return findings

        try:
            reg = Registry.Registry(target)
        except Exception as e:
            findings.append(Finding(
                source="system_services", key="error",
                value=f"Failed to open SYSTEM hive: {e}",
                category=self.category,
            ))
            return findings

        cs = self._get_current_controlset(reg)

        # Computer name
        try:
            cn_key = reg.open(f"{cs}\\Control\\ComputerName\\ComputerName")
            comp_name = cn_key.value("ComputerName").value()
            findings.append(Finding(
                source=f"{cs}\\Control\\ComputerName",
                key="ComputerName",
                value=comp_name,
                category=ArtifactCategory.SYSTEM_INFO,
                tags=["hostname"],
            ))
        except Exception:
            pass

        # Timezone
        try:
            tz_key = reg.open(f"{cs}\\Control\\TimeZoneInformation")
            tz_name = tz_key.value("TimeZoneKeyName").value()
            findings.append(Finding(
                source=f"{cs}\\Control\\TimeZoneInformation",
                key="TimeZone",
                value=tz_name,
                category=ArtifactCategory.SYSTEM_INFO,
                tags=["timezone"],
            ))
        except Exception:
            pass

        # Services enumeration
        try:
            svc_key = reg.open(f"{cs}\\Services")
            for subkey in svc_key.subkeys():
                svc_name = subkey.name()

                try:
                    start_type = subkey.value("Start").value()
                except Exception:
                    start_type = None

                try:
                    svc_type = subkey.value("Type").value()
                except Exception:
                    svc_type = None

                try:
                    image_path = subkey.value("ImagePath").value()
                except Exception:
                    image_path = None

                try:
                    display_name = subkey.value("DisplayName").value()
                except Exception:
                    display_name = svc_name

                # Map start types
                start_map = {
                    0: "Boot",
                    1: "System",
                    2: "Automatic",
                    3: "Manual",
                    4: "Disabled",
                }
                start_str = start_map.get(start_type, str(start_type))

                # Type mapping
                type_map = {
                    1: "Kernel Driver",
                    2: "File System Driver",
                    16: "Own Process",
                    32: "Share Process",
                    256: "Interactive",
                }
                type_str = type_map.get(svc_type, str(svc_type))

                # Flag suspicious indicators
                tags = ["service"]
                suspicious = False

                if image_path:
                    ip_lower = image_path.lower()
                    # Flag services running from temp, appdata, or unusual paths
                    sus_paths = ["\\temp\\", "\\tmp\\", "\\appdata\\", "\\users\\public\\",
                                 "\\programdata\\", "powershell", "cmd.exe /c",
                                 "mshta", "rundll32", "regsvr32", "wscript", "cscript"]
                    for sp in sus_paths:
                        if sp in ip_lower:
                            tags.append("SUSPICIOUS_PATH")
                            suspicious = True
                            break

                if start_type in (0, 1, 2) and image_path:
                    # Auto-start services are interesting for persistence
                    tags.append("auto_start")

                    findings.append(Finding(
                        source=f"{cs}\\Services\\{svc_name}",
                        key=f"Service: {display_name}",
                        value=f"Start={start_str}, Type={type_str}, Path={image_path or 'N/A'}",
                        timestamp=subkey.timestamp(),
                        category=self.category,
                        tags=tags,
                        mitre_att_ck="T1543.003" if suspicious else None,
                    ))

        except Registry.RegistryKeyNotFoundException:
            pass

        return findings


class SystemNetworkPlugin(RegistryPlugin):
    name = "system_network"
    description = "Extract network interface configuration and history from SYSTEM hive"
    author = "Olympus Cyber"
    version = "1.0.0"
    category = ArtifactCategory.NETWORK
    hive_type = "SYSTEM"
    registry_keys = [
        "ControlSet001\\Services\\Tcpip\\Parameters\\Interfaces",
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

        # Get current control set
        try:
            select_key = reg.open("Select")
            current = select_key.value("Current").value()
            cs = f"ControlSet{current:03d}"
        except Exception:
            cs = "ControlSet001"

        # Network interfaces
        try:
            intf_key = reg.open(f"{cs}\\Services\\Tcpip\\Parameters\\Interfaces")
            for subkey in intf_key.subkeys():
                guid = subkey.name()

                try:
                    ip = subkey.value("DhcpIPAddress").value()
                except Exception:
                    try:
                        ip = subkey.value("IPAddress").value()
                        if isinstance(ip, list):
                            ip = ip[0] if ip else "N/A"
                    except Exception:
                        ip = "N/A"

                try:
                    dhcp_server = subkey.value("DhcpServer").value()
                except Exception:
                    dhcp_server = "N/A"

                try:
                    domain = subkey.value("Domain").value()
                except Exception:
                    domain = ""

                if ip and ip not in ("N/A", "0.0.0.0", ""):
                    findings.append(Finding(
                        source=f"{cs}\\Services\\Tcpip\\Parameters\\Interfaces\\{guid}",
                        key=f"Network Interface {guid[:8]}...",
                        value=f"IP={ip}, DHCP Server={dhcp_server}, Domain={domain}",
                        timestamp=subkey.timestamp(),
                        category=self.category,
                        tags=["network", "interface"],
                    ))
        except Exception:
            pass

        return findings
