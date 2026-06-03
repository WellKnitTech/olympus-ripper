"""
Olympus Ripper — Integrity Verification
(c) 2026 Olympus Cyber. All rights reserved.

Self-hash verification on startup + output file hash index.
"""

import hashlib
import json
import os
import sys
import datetime
from pathlib import Path
from .terminal import colorize


# -- Colors for warnings --
_Y = "\033[38;5;178m"   # gold/yellow
_R = "\033[38;5;196m"   # red
_G = "\033[38;5;34m"    # green
_d = "\033[38;5;243m"   # dim
_W = "\033[38;5;231m"   # white
_RST = "\033[0m"


def _utc_iso() -> str:
    """Return a UTC ISO-8601 timestamp with a Z suffix."""
    return (
        datetime.datetime.now(datetime.timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def sha256_file(filepath: str) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    """Compute SHA-256 hash of bytes."""
    return hashlib.sha256(data).hexdigest()


# -- Self-Integrity Check --

# Files that are part of the tool's core (relative to package root)
CORE_FILES = [
    "__init__.py",
    "cli.py",
    "engine.py",
    "integrity.py",
    "plugin_base.py",
    "sqlite_utils.py",
]

MANIFEST_FILE = "integrity_manifest.json"
APP_DIR_NAME = "OlympusRipper"
ENV_MANIFEST_PATH = "ORIPPER_INTEGRITY_MANIFEST"
ENV_CONFIG_DIR = "ORIPPER_CONFIG_DIR"


def _get_package_dir() -> Path:
    """Get the olympus_ripper package directory."""
    return Path(__file__).parent


def _get_default_config_dir() -> Path:
    """Return a user-writable config directory for integrity state."""
    override = os.environ.get(ENV_CONFIG_DIR)
    if override:
        return Path(override).expanduser()

    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        if base:
            return Path(base) / APP_DIR_NAME

    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / APP_DIR_NAME

    xdg_config = os.environ.get("XDG_CONFIG_HOME")
    if xdg_config:
        return Path(xdg_config) / "olympus-ripper"
    return Path.home() / ".config" / "olympus-ripper"


def get_manifest_path() -> Path:
    """Return the integrity manifest path, honoring test/user overrides."""
    override = os.environ.get(ENV_MANIFEST_PATH)
    if override:
        return Path(override).expanduser()
    return _get_default_config_dir() / MANIFEST_FILE


def generate_manifest() -> dict:
    """
    Generate a hash manifest for all core files.
    Returns dict: {filename: sha256_hash}
    """
    pkg = _get_package_dir()
    manifest = {}
    for fname in CORE_FILES:
        fpath = pkg / fname
        if fpath.exists():
            manifest[fname] = sha256_file(str(fpath))
    return manifest


def save_manifest() -> str:
    """Generate and save the integrity manifest. Returns the manifest path."""
    manifest = generate_manifest()
    manifest_path = pkg / MANIFEST_FILE
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump({
            "generated": _utc_iso(),
            "tool": "Olympus Ripper",
            "algorithm": "SHA-256",
            "files": manifest,
        }, f, indent=2)
    return str(manifest_path)


def verify_self_integrity(quiet: bool = False, color: bool = True) -> bool:
    """
    Verify the tool's own source files against the stored manifest.

    Returns True if all files match or no manifest exists (first run).
    Returns False if any file has been modified.
    Always continues execution — this is a WARNING, not a block.
    """
    manifest_path = get_manifest_path()

    if not manifest_path.exists():
        # First run — generate manifest
        if not quiet:
            print(colorize("  [INTEGRITY] No manifest found — generating baseline...", _d, color))
        try:
            save_manifest()
        except OSError as e:
            if not quiet:
                print(colorize(f"  [INTEGRITY] WARNING: Could not write manifest: {e}", _Y, color))
            return True
        if not quiet:
            print(colorize("  [INTEGRITY] Baseline manifest created.", _G, color))
        return True

    # Load stored manifest
    try:
        with open(manifest_path, encoding="utf-8") as f:
            stored = json.load(f)
    except (json.JSONDecodeError, IOError):
        if not quiet:
            print(colorize("  [INTEGRITY] WARNING: Manifest file corrupt — regenerating.", _Y, color))
        try:
            save_manifest()
        except OSError as e:
            if not quiet:
                print(colorize(f"  [INTEGRITY] WARNING: Could not rewrite manifest: {e}", _Y, color))
        return True

    stored_files = stored.get("files", {})
    current = generate_manifest()
    modified = []
    missing = []

    for fname, expected_hash in stored_files.items():
        if fname not in current:
            missing.append(fname)
        elif current[fname] != expected_hash:
            modified.append(fname)

    if not modified and not missing:
        if not quiet:
            print(colorize("  [INTEGRITY] All core files verified — SHA-256 match.", _G, color))
        return True

    # -- WARNING BLOCK --
    print()
    if color:
        print(f"  {_R}╔══════════════════════════════════════════════════════════╗{_RST}")
        print(f"  {_R}║{_RST}  {_Y}⚠  INTEGRITY WARNING — TOOL FILES MODIFIED{_RST}              {_R}║{_RST}")
        print(f"  {_R}╠══════════════════════════════════════════════════════════╣{_RST}")
        for fname in modified:
            print(f"  {_R}║{_RST}  {_W}CHANGED:{_RST} {fname:<48}{_R}║{_RST}")
        for fname in missing:
            print(f"  {_R}║{_RST}  {_W}MISSING:{_RST} {fname:<48}{_R}║{_RST}")
        print(f"  {_R}║{_RST}                                                          {_R}║{_RST}")
        print(f"  {_R}║{_RST}  {_d}Tool source has been altered since last baseline.{_RST}       {_R}║{_RST}")
        print(f"  {_R}║{_RST}  {_d}Findings may not be forensically defensible.{_RST}             {_R}║{_RST}")
        print(f"  {_R}║{_RST}  {_d}Run: oripper rehash  to accept current state.{_RST}            {_R}║{_RST}")
        print(f"  {_R}╚══════════════════════════════════════════════════════════╝{_RST}")
    else:
        print("  +----------------------------------------------------------+")
        print("  |  INTEGRITY WARNING - TOOL FILES MODIFIED                 |")
        print("  +----------------------------------------------------------+")
        for fname in modified:
            print(f"  |  CHANGED: {fname:<48}|")
        for fname in missing:
            print(f"  |  MISSING: {fname:<48}|")
        print("  |                                                          |")
        print("  |  Tool source has been altered since last baseline.       |")
        print("  |  Findings may not be forensically defensible.            |")
        print("  |  Run: oripper rehash  to accept current state.           |")
        print("  +----------------------------------------------------------+")
    print()

    return False


# -- Output File Hashing --

def hash_output_file(filepath: str) -> dict:
    """
    Hash a single output file. Returns metadata dict.
    """
    p = Path(filepath)
    stat = p.stat()
    return {
        "file": p.name,
        "path": str(p.resolve()),
        "sha256": sha256_file(filepath),
        "size_bytes": stat.st_size,
        "created": _utc_iso(),
    }


def write_hash_index(output_files: list[str], target: str, hostname: str = "UNKNOWN") -> str:
    """
    Write a hash index file alongside the output files.

    Creates <first_output_dir>/oripper_hashindex_<timestamp>.json
    containing SHA-256 hashes of all output files plus metadata.

    Returns the path to the hash index file.
    """
    if not output_files:
        return ""

    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
    first_dir = str(Path(output_files[0]).parent)
    index_path = os.path.join(first_dir, f"oripper_hashindex_{ts}.json")

    entries = []
    for fpath in output_files:
        if os.path.exists(fpath):
            entries.append(hash_output_file(fpath))

    index = {
        "tool": "Olympus Ripper",
        "version": None,  # filled by caller
        "timestamp": _utc_iso(),
        "target": target,
        "hostname": hostname,
        "algorithm": "SHA-256",
        "files": entries,
    }

    # Import version at call time to avoid circular imports
    try:
        from . import __version__
        index["version"] = __version__
    except ImportError:
        pass

    with open(index_path, "w", encoding="utf-8") as f:
        json.dump(index, f, indent=2)

    return index_path
