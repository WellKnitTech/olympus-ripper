import json

from olympus_ripper.cli import show_olympus_banner
from olympus_ripper.integrity import get_manifest_path, save_manifest, verify_self_integrity
from olympus_ripper.plugin_base import HostPlatform
from olympus_ripper.plugins.macos.unified_logs import UnifiedLogPlugin
from olympus_ripper.plugins.windows.sam_users import SAMUsersPlugin
from olympus_ripper.terminal import should_use_color


def test_integrity_manifest_uses_user_config_dir(monkeypatch, tmp_path):
    monkeypatch.setenv("ORIPPER_CONFIG_DIR", str(tmp_path))
    manifest_path = get_manifest_path()

    assert manifest_path == tmp_path / "integrity_manifest.json"
    assert "olympus_ripper" not in manifest_path.parts

    saved_path = save_manifest()
    assert saved_path == str(manifest_path)
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert "sqlite_utils.py" in data["files"]
    assert "terminal.py" in data["files"]
    assert verify_self_integrity(quiet=True, color=False) is True


def test_plain_banner_and_color_detection(capsys):
    assert should_use_color(no_color=True) is False

    show_olympus_banner(color=False)
    output = capsys.readouterr().out

    assert "Olympus Ripper" in output
    assert "\033[" not in output
    assert "████" not in output


def test_plugin_host_metadata():
    assert SAMUsersPlugin().supported_hosts == [HostPlatform.MACOS, HostPlatform.WINDOWS]
    assert UnifiedLogPlugin().supported_hosts == [HostPlatform.MACOS]
