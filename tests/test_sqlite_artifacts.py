import sqlite3

import pytest

from olympus_ripper.plugins.macos.tcc_permissions import TCCPermissionsPlugin
from olympus_ripper.sqlite_utils import connect_sqlite_readonly, sqlite_readonly_uri


def test_sqlite_readonly_helper_handles_spaces_and_unicode(tmp_path):
    db_path = tmp_path / "artifact db ✓.sqlite"
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE sample (value TEXT)")
    conn.execute("INSERT INTO sample VALUES (?)", ("olympus ✓",))
    conn.commit()
    conn.close()

    uri = sqlite_readonly_uri(str(db_path))
    assert uri.startswith("file:")
    assert uri.endswith("?mode=ro")

    ro_conn = connect_sqlite_readonly(str(db_path), row_factory=True)
    try:
        row = ro_conn.execute("SELECT value FROM sample").fetchone()
        assert row["value"] == "olympus ✓"
        with pytest.raises(sqlite3.OperationalError):
            ro_conn.execute("INSERT INTO sample VALUES ('blocked')")
    finally:
        ro_conn.close()


def test_tcc_plugin_parses_fixture_database(tmp_path):
    db_path = tmp_path / "TCC fixture.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE access (
            service TEXT,
            client TEXT,
            client_type INTEGER,
            auth_value INTEGER,
            auth_reason INTEGER,
            last_modified INTEGER,
            flags INTEGER
        )
        """
    )
    conn.execute(
        "INSERT INTO access VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            "kTCCServiceSystemPolicyAllFiles",
            "com.example.agent",
            0,
            2,
            4,
            1_700_000_000,
            0,
        ),
    )
    conn.commit()
    conn.close()

    findings = TCCPermissionsPlugin().run(str(db_path))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.key == "Full Disk Access -> com.example.agent"
    assert finding.value == "Auth=ALLOWED, ClientType=bundle_id"
    assert "HIGH_RISK_GRANT" in finding.tags
    assert finding.mitre_att_ck == "T1548"
