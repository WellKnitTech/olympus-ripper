"""
Olympus Ripper — Plugin Base Classes
(c) 2026 Olympus Cyber. All rights reserved.

All plugins inherit from OlympusPlugin. Two subtypes exist:
  - RegistryPlugin: parses Windows Registry hive artifacts
  - MacArtifactPlugin: parses macOS forensic artifacts
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional
import json


class ArtifactPlatform(Enum):
    WINDOWS = "windows"
    MACOS = "macos"


class ArtifactCategory(Enum):
    PERSISTENCE = "persistence"
    EXECUTION = "execution"
    CREDENTIALS = "credentials"
    NETWORK = "network"
    SYSTEM_INFO = "system_info"
    USER_ACTIVITY = "user_activity"
    PERMISSIONS = "permissions"
    FILE_ACTIVITY = "file_activity"
    APPLICATION = "application"
    TIMELINE = "timeline"
    SECURITY = "security"


@dataclass
class Finding:
    """Single forensic finding from a plugin."""
    source: str                          # e.g., "SAM\\Domains\\Account\\Users"
    key: str                             # artifact key/name
    value: Any                           # parsed value
    timestamp: Optional[datetime] = None # associated timestamp if available
    category: ArtifactCategory = ArtifactCategory.SYSTEM_INFO
    tags: list[str] = field(default_factory=list)
    raw: Optional[bytes] = None          # raw bytes for hex dump if needed
    mitre_att_ck: Optional[str] = None   # e.g., "T1547.001"

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "key": self.key,
            "value": str(self.value),
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "category": self.category.value,
            "tags": self.tags,
            "mitre_att_ck": self.mitre_att_ck,
        }


class OlympusPlugin(ABC):
    """Base class for all Olympus Ripper plugins."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Short plugin name, e.g., 'sam_users'."""

    @property
    @abstractmethod
    def description(self) -> str:
        """One-line description of what this plugin extracts."""

    @property
    @abstractmethod
    def author(self) -> str:
        """Plugin author."""

    @property
    @abstractmethod
    def version(self) -> str:
        """Semver string."""

    @property
    @abstractmethod
    def platform(self) -> ArtifactPlatform:
        """Target platform."""

    @property
    @abstractmethod
    def category(self) -> ArtifactCategory:
        """Primary artifact category."""

    @property
    def mitre_references(self) -> list[str]:
        """MITRE ATT&CK technique IDs this plugin covers."""
        return []

    @abstractmethod
    def run(self, target: str, **kwargs) -> list[Finding]:
        """
        Execute the plugin against a target.

        For RegistryPlugin: target = path to hive file
        For MacArtifactPlugin: target = path to artifact file or mounted volume
        """

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name} platform={self.platform.value}>"


class RegistryPlugin(OlympusPlugin):
    """Base for Windows Registry hive plugins."""

    platform = ArtifactPlatform.WINDOWS

    @property
    @abstractmethod
    def hive_type(self) -> str:
        """Which hive: SAM, SYSTEM, SOFTWARE, NTUSER, SECURITY, USRCLASS."""

    @property
    @abstractmethod
    def registry_keys(self) -> list[str]:
        """Registry key paths this plugin reads."""


class MacArtifactPlugin(OlympusPlugin):
    """Base for macOS artifact plugins."""

    platform = ArtifactPlatform.MACOS

    @property
    @abstractmethod
    def artifact_type(self) -> str:
        """Artifact type: plist, sqlite, log, filesystem, etc."""

    @property
    @abstractmethod
    def default_paths(self) -> list[str]:
        """
        Default paths on a live macOS system or mounted image
        where this artifact is found.
        """
