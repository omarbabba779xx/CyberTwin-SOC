"""Atomic Red Team catalogue integration tests."""

from __future__ import annotations


def _write_atomic_fixture(root):
    technique_dir = root / "atomics" / "T1003"
    technique_dir.mkdir(parents=True)
    (technique_dir / "T1003.yaml").write_text(
        """
attack_technique: T1003
display_name: OS Credential Dumping
atomic_tests:
  - name: Safe metadata fixture
    auto_generated_guid: 00000000-0000-0000-0000-000000000001
    description: Reads only metadata in CyberTwin tests.
    supported_platforms:
      - windows
    input_arguments:
      dump_path:
        description: Path placeholder
        type: path
        default: C:\\Temp\\sample.dmp
    executor:
      name: powershell
      elevation_required: true
      command: Write-Host "command should not be exposed by default"
      cleanup_command: Write-Host "cleanup should not be exposed by default"
""".strip(),
        encoding="utf-8",
    )


def test_atomic_loader_returns_sanitized_metadata(tmp_path):
    from backend.mitre.atomic_red_team import load_atomic_technique

    _write_atomic_fixture(tmp_path)
    data = load_atomic_technique("T1003", root=tmp_path)

    assert data["technique_id"] == "T1003"
    assert data["display_name"] == "OS Credential Dumping"
    assert data["atomic_test_count"] == 1
    assert data["supported_platforms"] == ["windows"]
    assert data["executors"] == ["powershell"]
    assert "command" not in data["tests"][0]
    assert "cleanup_command" not in data["tests"][0]


def test_atomic_loader_can_include_commands_for_internal_tools(tmp_path):
    from backend.mitre.atomic_red_team import load_atomic_technique

    _write_atomic_fixture(tmp_path)
    data = load_atomic_technique("T1003", root=tmp_path, include_commands=True)

    assert "command" in data["tests"][0]
    assert "cleanup_command" in data["tests"][0]


def test_atomic_api_uses_configured_local_catalogue(client, auth_headers, tmp_path, monkeypatch):
    _write_atomic_fixture(tmp_path)
    monkeypatch.setenv("ATOMIC_RED_TEAM_PATH", str(tmp_path))

    summary = client.get("/api/mitre/atomic-red-team", headers=auth_headers)
    assert summary.status_code == 200
    assert summary.json()["available"] is True
    assert "T1003" in summary.json()["techniques"]

    detail = client.get("/api/mitre/atomic-red-team/T1003", headers=auth_headers)
    assert detail.status_code == 200
    body = detail.json()
    assert body["atomic_test_count"] == 1
    assert "command" not in body["tests"][0]
