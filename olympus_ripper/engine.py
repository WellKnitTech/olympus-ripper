"""
Olympus Ripper — Core Engine
(c) 2026 Olympus Cyber. All rights reserved.

Plugin discovery, loading, and execution orchestration.
"""

import importlib
import inspect
import os
import pkgutil
import sys
import time
from pathlib import Path
from typing import Optional

from .plugin_base import (
    ArtifactCategory,
    ArtifactPlatform,
    Finding,
    MacArtifactPlugin,
    OlympusPlugin,
    RegistryPlugin,
)


class PluginRegistry:
    """Discovers and manages all available plugins."""

    def __init__(self):
        self._plugins: dict[str, type[OlympusPlugin]] = {}
        self._loaded = False

    def discover(self, extra_dirs: Optional[list[str]] = None) -> None:
        """Auto-discover plugins from built-in and optional external directories."""
        # Built-in plugins
        builtin_pkg_windows = "olympus_ripper.plugins.windows"
        builtin_pkg_macos = "olympus_ripper.plugins.macos"

        for pkg_name in [builtin_pkg_windows, builtin_pkg_macos]:
            try:
                pkg = importlib.import_module(pkg_name)
                pkg_path = getattr(pkg, "__path__", None)
                if pkg_path is None:
                    continue
                for importer, modname, ispkg in pkgutil.iter_modules(pkg_path):
                    if modname.startswith("_"):
                        continue
                    full_name = f"{pkg_name}.{modname}"
                    try:
                        mod = importlib.import_module(full_name)
                        self._register_from_module(mod)
                    except Exception as e:
                        print(f"[!] Failed to load plugin module {full_name}: {e}")
            except ImportError:
                pass

        # External plugin directories
        if extra_dirs:
            for d in extra_dirs:
                self._load_external_dir(d)

        self._loaded = True

    def _register_from_module(self, mod) -> None:
        """Find all OlympusPlugin subclasses in a module and register them."""
        for attr_name in dir(mod):
            attr = getattr(mod, attr_name)
            if (
                inspect.isclass(attr)
                and issubclass(attr, OlympusPlugin)
                and attr not in (OlympusPlugin, RegistryPlugin, MacArtifactPlugin)
                and not inspect.isabstract(attr)
            ):
                try:
                    instance = attr()
                    self._plugins[instance.name] = attr
                except Exception:
                    pass

    def _load_external_dir(self, dirpath: str) -> None:
        """Load .py plugin files from an external directory."""
        p = Path(dirpath)
        if not p.is_dir():
            return
        sys.path.insert(0, str(p))
        for f in p.glob("*.py"):
            if f.name.startswith("_"):
                continue
            modname = f.stem
            try:
                mod = importlib.import_module(modname)
                self._register_from_module(mod)
            except Exception as e:
                print(f"[!] Failed to load external plugin {f}: {e}")
        sys.path.pop(0)

    def list_plugins(
        self,
        platform: Optional[ArtifactPlatform] = None,
        category: Optional[ArtifactCategory] = None,
        hive_type: Optional[str] = None,
    ) -> list[OlympusPlugin]:
        """List available plugins, optionally filtered."""
        results = []
        for cls in self._plugins.values():
            inst = cls()
            if platform and inst.platform != platform:
                continue
            if category and inst.category != category:
                continue
            if hive_type and isinstance(inst, RegistryPlugin) and inst.hive_type.upper() != hive_type.upper():
                continue
            results.append(inst)
        return sorted(results, key=lambda p: (p.platform.value, p.name))

    def get_plugin(self, name: str) -> Optional[OlympusPlugin]:
        """Get a plugin by name."""
        cls = self._plugins.get(name)
        return cls() if cls else None


class RipperEngine:
    """
    Main execution engine for Olympus Ripper.

    Orchestrates plugin discovery, target analysis, and result collection.
    """

    def __init__(self, plugin_dirs: Optional[list[str]] = None, quiet: bool = False):
        self.registry = PluginRegistry()
        self.registry.discover(extra_dirs=plugin_dirs)
        self.quiet = quiet
        self._results: list[dict] = []

    def _log(self, msg: str) -> None:
        if not self.quiet:
            print(msg)

    def detect_target_type(self, path: str) -> Optional[str]:
        """
        Detect what kind of forensic target a file/directory is.

        Returns one of:
          - 'registry_hive' (with hive_type detected)
          - 'plist'
          - 'sqlite'
          - 'log_archive'
          - 'mounted_volume'
          - None (unknown)
        """
        p = Path(path)

        if not p.exists():
            return None

        # Directory — could be a mounted volume or log archive
        if p.is_dir():
            # Check for macOS volume structure
            if (p / "System" / "Library").is_dir() or (p / "private" / "var").is_dir():
                return "mounted_volume"
            # Check for log archive (.logarchive)
            if p.suffix == ".logarchive":
                return "log_archive"
            return None

        # File-based detection
        suffix = p.suffix.lower()
        name = p.name.upper()

        # Plist
        if suffix == ".plist":
            return "plist"

        # SQLite databases (TCC.db, KnowledgeC.db, etc.)
        if suffix == ".db" or suffix == ".sqlite":
            return "sqlite"

        # Registry hive detection by reading magic bytes
        try:
            with open(path, "rb") as f:
                magic = f.read(4)
                if magic == b"regf":
                    return "registry_hive"
        except (IOError, PermissionError):
            pass

        # Hive detection by filename convention
        hive_names = {"SAM", "SYSTEM", "SOFTWARE", "SECURITY", "NTUSER.DAT", "USRCLASS.DAT", "DEFAULT"}
        if name in hive_names or name.replace(".DAT", "") in hive_names:
            return "registry_hive"

        return None

    def detect_hive_type(self, path: str) -> Optional[str]:
        """Detect which Windows Registry hive type a file is."""
        name = Path(path).name.upper()
        mapping = {
            "SAM": "SAM",
            "SYSTEM": "SYSTEM",
            "SOFTWARE": "SOFTWARE",
            "SECURITY": "SECURITY",
            "DEFAULT": "DEFAULT",
            "NTUSER.DAT": "NTUSER",
            "USRCLASS.DAT": "USRCLASS",
        }
        for key, hive in mapping.items():
            if name.startswith(key):
                return hive
        return None

    def rip(
        self,
        target: str,
        plugins: Optional[list[str]] = None,
        platform: Optional[ArtifactPlatform] = None,
        category: Optional[ArtifactCategory] = None,
        hive_type: Optional[str] = None,
    ) -> list[dict]:
        """
        Run plugins against a target and collect findings.

        Args:
            target: Path to hive file, artifact file, or mounted volume
            plugins: Specific plugin names to run (None = auto-detect)
            platform: Filter to Windows or macOS plugins
            category: Filter by artifact category
            hive_type: For registry hives, specify type (SAM, SYSTEM, etc.)
        """
        start = time.time()

        target_type = self.detect_target_type(target)
        self._log(f"[*] Target: {target}")
        self._log(f"[*] Detected type: {target_type or 'unknown'}")

        # Auto-detect platform and hive type
        if target_type == "registry_hive":
            platform = ArtifactPlatform.WINDOWS
            if not hive_type:
                hive_type = self.detect_hive_type(target)
            self._log(f"[*] Hive type: {hive_type or 'unknown'}")
        elif target_type in ("plist", "sqlite", "mounted_volume", "log_archive"):
            platform = ArtifactPlatform.MACOS

        # Select plugins
        if plugins:
            selected = [self.registry.get_plugin(n) for n in plugins]
            selected = [p for p in selected if p is not None]
        else:
            selected = self.registry.list_plugins(
                platform=platform,
                category=category,
                hive_type=hive_type,
            )

        if not selected:
            self._log("[!] No matching plugins found for this target.")
            return []

        self._log(f"[*] Running {len(selected)} plugin(s)...\n")

        all_findings = []
        for plugin in selected:
            self._log(f"  [{plugin.platform.value.upper()}] {plugin.name}: {plugin.description}")
            try:
                findings = plugin.run(target)
                for f in findings:
                    entry = {
                        "plugin": plugin.name,
                        "platform": plugin.platform.value,
                        "category": plugin.category.value,
                        **f.to_dict(),
                    }
                    all_findings.append(entry)
                self._log(f"    -> {len(findings)} finding(s)")
            except Exception as e:
                self._log(f"    -> ERROR: {e}")

        elapsed = time.time() - start
        self._log(f"\n[*] Complete. {len(all_findings)} total findings in {elapsed:.2f}s")

        self._results = all_findings
        return all_findings

    def rip_volume(
        self,
        volume_path: str,
        plugins: Optional[list[str]] = None,
    ) -> list[dict]:
        """
        Rip all supported artifacts from a mounted macOS volume or
        a directory containing extracted artifacts.
        """
        self._log(f"[*] Scanning volume: {volume_path}")

        p = Path(volume_path)
        all_findings = []

        # Run macOS plugins with default path resolution
        mac_plugins = self.registry.list_plugins(platform=ArtifactPlatform.MACOS)
        if plugins:
            mac_plugins = [mp for mp in mac_plugins if mp.name in plugins]

        for plugin in mac_plugins:
            if isinstance(plugin, MacArtifactPlugin):
                for default_path in plugin.default_paths:
                    # Resolve relative to volume mount
                    full_path = p / default_path.lstrip("/")
                    if full_path.exists():
                        self._log(f"  [MACOS] {plugin.name}: {full_path}")
                        try:
                            findings = plugin.run(str(full_path))
                            for f in findings:
                                entry = {
                                    "plugin": plugin.name,
                                    "platform": plugin.platform.value,
                                    "category": plugin.category.value,
                                    **f.to_dict(),
                                }
                                all_findings.append(entry)
                            self._log(f"    -> {len(findings)} finding(s)")
                        except Exception as e:
                            self._log(f"    -> ERROR: {e}")

        # Check for Windows Registry hives in common locations
        hive_locations = [
            "Windows/System32/config/SAM",
            "Windows/System32/config/SYSTEM",
            "Windows/System32/config/SOFTWARE",
            "Windows/System32/config/SECURITY",
        ]
        for hloc in hive_locations:
            hive_path = p / hloc
            if hive_path.exists():
                hive_type = self.detect_hive_type(str(hive_path))
                win_plugins = self.registry.list_plugins(
                    platform=ArtifactPlatform.WINDOWS,
                    hive_type=hive_type,
                )
                for wp in win_plugins:
                    self._log(f"  [WINDOWS] {wp.name}: {hive_path}")
                    try:
                        findings = wp.run(str(hive_path))
                        for f in findings:
                            entry = {
                                "plugin": wp.name,
                                "platform": wp.platform.value,
                                "category": wp.category.value,
                                **f.to_dict(),
                            }
                            all_findings.append(entry)
                        self._log(f"    -> {len(findings)} finding(s)")
                    except Exception as e:
                        self._log(f"    -> ERROR: {e}")

        self._results = all_findings
        return all_findings
