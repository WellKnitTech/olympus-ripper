# Olympus Ripper

**Hybrid Forensic Artifact Parser** — by Olympus Cyber

A Python CLI tool that parses both Windows Registry hives and macOS forensic artifacts through a unified plugin architecture. Inspired by Harlan Carvey's RegRipper, rebuilt for cross-platform IR workflows on macOS and Windows analyst hosts.

## Install

```bash
# Clone and install
cd olympus-ripper
pip install -e .

# Or install dependencies directly
pip install regipy python-registry
```

## Quick Start

```bash
# Parse a Windows Registry hive
oripper rip /path/to/SAM

# Parse a macOS TCC database
oripper rip /path/to/TCC.db

# Scan a mounted forensic image
oripper volume /Volumes/Evidence

# List available plugins
oripper list

# JSON output for SIEM ingest
oripper rip /path/to/NTUSER.DAT -f json -o findings.json

# Timeline output for plaso integration
oripper rip /path/to/SOFTWARE -f timeline -o timeline.tln

# Run specific plugins
oripper rip /path/to/SYSTEM -p system_services system_network

# Filter by category
oripper rip /path/to/NTUSER.DAT -c persistence
```

## Plugin Architecture

### Windows Registry Plugins

| Plugin | Hive | Category | MITRE | Description |
|--------|------|----------|-------|-------------|
| `sam_users` | SAM | credentials | T1003.002, T1087.001 | Local user accounts, RIDs, login counts |
| `system_services` | SYSTEM | persistence | T1543.003, T1569.002 | Services, drivers, auto-start entries |
| `system_network` | SYSTEM | network | T1016 | Network interfaces, DHCP, DNS config |
| `software_persistence` | SOFTWARE | persistence | T1547.001, T1547.004 | Run/RunOnce keys, autorun entries |
| `software_installed` | SOFTWARE | application | — | Installed applications (Uninstall keys) |
| `software_networklist` | SOFTWARE | network | T1016 | Network profiles, WiFi history |
| `ntuser_userassist` | NTUSER | execution | T1059 | UserAssist execution history (ROT13 decoded) |
| `ntuser_recentdocs` | NTUSER | user_activity | — | Recently opened files (MRU) |
| `ntuser_typedpaths` | NTUSER | user_activity | — | Explorer address bar history |
| `ntuser_run` | NTUSER | persistence | T1547.001 | User-level Run/RunOnce keys |

### macOS Artifact Plugins

| Plugin | Artifact | Category | MITRE | Description |
|--------|----------|----------|-------|-------------|
| `macos_tcc` | TCC.db | permissions | T1548, T1562.001 | Camera, mic, FDA, accessibility grants |
| `macos_knowledgec` | KnowledgeC.db | user_activity | — | App usage, device lock/unlock, screen time |
| `macos_launch_persistence` | LaunchAgents/Daemons | persistence | T1543.001, T1543.004 | Plist-based persistence mechanisms |
| `macos_login_items` | Login Items | persistence | T1547.015 | Login items, startup apps, hooks |
| `macos_quarantine` | QuarantineEventsV2 | file_activity | T1566.001, T1204.002 | Download history with source tracking |
| `macos_unified_logs` | Unified Logs | security | T1059, T1078 | Process exec, auth, network, Gatekeeper |
| `macos_fsevents` | .fseventsd | file_activity | T1070.004 | File system activity journal |
| `macos_safari_history` | History.db | user_activity | — | Safari browsing and download history |

## Usage Examples

### Single Plugin Runs

```bash
# Run only the SAM users plugin against a SAM hive
oripper rip /evidence/SAM -p sam_users

# Run only the services plugin against SYSTEM
oripper rip /evidence/SYSTEM -p system_services

# Run two specific plugins against NTUSER.DAT
oripper rip /evidence/NTUSER.DAT -p ntuser_userassist ntuser_run

# Run only macOS TCC plugin against a TCC database
oripper rip /evidence/TCC.db -p macos_tcc
```

### Filter by Platform, Category, or Hive Type

```bash
# All Windows persistence plugins against a SOFTWARE hive
oripper rip /evidence/SOFTWARE -c persistence

# All NTUSER plugins (auto-filters by hive type)
oripper rip /evidence/NTUSER.DAT

# List only macOS plugins
oripper list --platform macos

# List only persistence-category plugins
oripper list --category persistence

# List only plugins that target the SYSTEM hive
oripper list --hive-type SYSTEM
```

### macOS Persistence Hunting

```bash
# Scan LaunchAgents and LaunchDaemons for persistence
oripper rip /Library/LaunchDaemons/com.suspicious.plist -p macos_launch_persistence

# Check login items for startup persistence
oripper rip ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm -p macos_login_items

# Full persistence sweep against a mounted macOS image
oripper volume /Volumes/Macintosh\ HD -c persistence

# Run all macOS persistence plugins and export JSON for SIEM
oripper volume /Volumes/Evidence --platform macos -f json -o mac_persistence.json
```

### macOS Live Collection (run as root)

```bash
# TCC permissions — who has FDA, camera, mic, accessibility
sudo oripper rip /Library/Application\ Support/com.apple.TCC/TCC.db

# Quarantine events — download history with source URLs
oripper rip ~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2

# KnowledgeC — app usage, lock/unlock times
oripper rip ~/Library/Application\ Support/Knowledge/knowledgeC.db

# Safari browsing history
oripper rip ~/Library/Safari/History.db -p macos_safari_history

# FSEvents — filesystem activity journal
oripper rip /.fseventsd -p macos_fsevents
```

### Output and Hashing

```bash
# JSON output with automatic SHA-256 hash index
oripper rip /evidence/SAM -f json -o sam_findings.json
# Creates: sam_findings.json + oripper_hashindex_<timestamp>.json

# Timeline for plaso integration
oripper rip /evidence/SOFTWARE -f timeline -o timeline.tln --hostname WORKSTATION01

# CSV for spreadsheet analysis
oripper volume /Volumes/Evidence -f csv -o full_sweep.csv
```

### Integrity Verification

```bash
# First run auto-generates baseline manifest
oripper list

# If tool files are modified, you'll see an integrity warning
# Accept the current state as the new baseline:
oripper rehash
```

Integrity manifests are stored in a user-writable application config directory instead of the installed package directory. Set `ORIPPER_CONFIG_DIR` to choose a config directory, or `ORIPPER_INTEGRITY_MANIFEST` to point at a specific manifest file for testing or controlled deployments.

## Writing Custom Plugins

Create a `.py` file in any directory and point `--plugin-dir` at it:

```python
from olympus_ripper.plugin_base import MacArtifactPlugin, ArtifactCategory, Finding

class MyPlugin(MacArtifactPlugin):
    name = "my_custom_plugin"
    description = "Parse a custom artifact"
    author = "Your Name"
    version = "1.0.0"
    category = ArtifactCategory.SECURITY
    artifact_type = "sqlite"
    default_paths = ["/path/to/artifact.db"]

    def run(self, target, **kwargs):
        findings = []
        # Your parsing logic here
        findings.append(Finding(
            source="my_artifact",
            key="something_interesting",
            value="the extracted data",
            category=self.category,
            tags=["custom"],
        ))
        return findings
```

```bash
oripper rip /path/to/artifact.db -P /path/to/my/plugins/
```

## Output Formats

| Format | Flag | Use Case |
|--------|------|----------|
| Text (ANSI) | `-f text` | Terminal review with Olympus branding |
| JSON | `-f json` | SIEM ingest, API integration, scripted analysis |
| CSV | `-f csv` | Spreadsheet import, pivot tables |
| Timeline (TLN) | `-f timeline` | Super-timeline integration with plaso/log2timeline |

## Requirements

- Python 3.9+
- Host OS: macOS or Windows
- `python-registry` — Windows Registry hive parsing
- `regipy` — Extended Registry artifact extraction

## Support Matrix

| Host OS | Windows Registry artifacts | macOS artifacts | Notes |
|---------|----------------------------|-----------------|-------|
| macOS | Supported | Supported | Recommended host for macOS live collection and Unified Logs because the `macos_unified_logs` plugin uses Apple's `/usr/bin/log` command. |
| Windows | Supported | Supported for offline SQLite, plist, and filesystem artifacts | Unified Logs are degraded on Windows because Apple's `/usr/bin/log` command is not available. Use exported artifacts where possible. |
| Linux | Not currently targeted | Not currently targeted | Linux may work for some pure-Python offline parsing, but it is not part of the supported host matrix. |

Artifact platform scope is currently limited to Windows and macOS. Linux artifact parsing is not implemented.

## License

MIT License — see [LICENSE](LICENSE) for details.
