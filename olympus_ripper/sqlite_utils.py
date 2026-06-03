"""
Olympus Ripper — SQLite Utilities
(c) 2026 Olympus Cyber. All rights reserved.

Cross-platform helpers for opening forensic SQLite databases safely.
"""

import sqlite3
from pathlib import Path


def sqlite_readonly_uri(path: str) -> str:
    """
    Build a SQLite read-only file URI from a filesystem path.

    Path.as_uri() handles platform-specific path forms and escapes spaces or
    other URI-sensitive characters, which is especially important for Windows
    drive-letter paths such as C:\\Evidence\\TCC.db.
    """
    return f"{Path(path).resolve().as_uri()}?mode=ro"


def connect_sqlite_readonly(path: str, row_factory: bool = False) -> sqlite3.Connection:
    """Open a SQLite database read-only using a cross-platform file URI."""
    conn = sqlite3.connect(sqlite_readonly_uri(path), uri=True)
    if row_factory:
        conn.row_factory = sqlite3.Row
    return conn
