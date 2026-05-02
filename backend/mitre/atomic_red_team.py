"""Safe Atomic Red Team catalogue integration.

Atomic Red Team contains executable test definitions. CyberTwin consumes it as
local metadata only: technique names, platforms, executors, dependencies, and
argument names. Commands are intentionally omitted from API-facing summaries.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Any, Optional

import yaml

_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_MAX_ATOMIC_YAML_BYTES = 512 * 1024


def _atomics_dir(root: Path) -> Path:
    """Accept either the Atomic Red Team repo root or its atomics/ directory."""
    if (root / "atomics").is_dir():
        return root / "atomics"
    return root


def configured_atomic_root() -> Optional[Path]:
    """Return ATOMIC_RED_TEAM_PATH when configured, else None."""
    raw = os.getenv("ATOMIC_RED_TEAM_PATH", "").strip()
    if not raw:
        return None
    return Path(raw).expanduser().resolve()


def atomic_catalog_status(root: Optional[Path] = None) -> dict[str, Any]:
    """Describe whether a local Atomic Red Team catalogue is available."""
    root = root or configured_atomic_root()
    if root is None:
        return {
            "configured": False,
            "available": False,
            "reason": "Set ATOMIC_RED_TEAM_PATH to a local atomic-red-team checkout.",
        }

    atomics = _atomics_dir(root)
    if not atomics.is_dir():
        return {
            "configured": True,
            "available": False,
            "root": str(root),
            "reason": "No atomics directory found at ATOMIC_RED_TEAM_PATH.",
        }

    technique_dirs = [p for p in atomics.iterdir() if p.is_dir() and _TECHNIQUE_RE.fullmatch(p.name)]
    return {
        "configured": True,
        "available": True,
        "root": str(root),
        "atomics_dir": str(atomics),
        "technique_count": len(technique_dirs),
        "schema": "atomic-red-team-yaml",
        "compatibility": "ATT&CK v19 metadata-compatible",
        **_git_metadata(root),
    }


def _git_metadata(root: Path) -> dict[str, Any]:
    """Return non-sensitive Git metadata for a local Atomic checkout."""
    git_dir = root / ".git"
    if not git_dir.exists():
        return {}
    try:
        commit = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--short=12", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            timeout=2,
        ).stdout.strip()
        date = subprocess.run(
            ["git", "-C", str(root), "log", "-1", "--format=%cI"],
            check=True,
            capture_output=True,
            text=True,
            timeout=2,
        ).stdout.strip()
        subject = subprocess.run(
            ["git", "-C", str(root), "log", "-1", "--format=%s"],
            check=True,
            capture_output=True,
            text=True,
            timeout=2,
        ).stdout.strip()
        return {
            "upstream_commit": commit,
            "upstream_commit_date": date,
            "upstream_commit_subject": subject,
        }
    except Exception:
        return {}


def list_atomic_techniques(root: Optional[Path] = None, *, limit: int = 2000) -> list[str]:
    """List available ATT&CK technique IDs from a local Atomic Red Team checkout."""
    root = root or configured_atomic_root()
    if root is None:
        return []
    atomics = _atomics_dir(root)
    if not atomics.is_dir():
        return []
    technique_ids = sorted(
        p.name for p in atomics.iterdir()
        if p.is_dir() and _TECHNIQUE_RE.fullmatch(p.name)
    )
    return technique_ids[:limit]


def load_atomic_technique(
    technique_id: str,
    root: Optional[Path] = None,
    *,
    include_commands: bool = False,
) -> Optional[dict[str, Any]]:
    """Load one Atomic Red Team technique YAML as sanitized metadata."""
    if not _TECHNIQUE_RE.fullmatch(technique_id):
        raise ValueError("Invalid ATT&CK technique id")

    root = root or configured_atomic_root()
    if root is None:
        return None

    atomics = _atomics_dir(root)
    yaml_path = atomics / technique_id / f"{technique_id}.yaml"
    if not yaml_path.is_file():
        return None
    if yaml_path.stat().st_size > _MAX_ATOMIC_YAML_BYTES:
        raise ValueError(f"Atomic YAML exceeds {_MAX_ATOMIC_YAML_BYTES // 1024} KB")

    data = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
    tests = []
    platform_set: set[str] = set()
    executor_set: set[str] = set()

    for item in data.get("atomic_tests") or []:
        if not isinstance(item, dict):
            continue
        platforms = [str(p) for p in item.get("supported_platforms") or []]
        platform_set.update(platforms)

        executor = item.get("executor") or {}
        executor_name = str(executor.get("name") or "")
        if executor_name:
            executor_set.add(executor_name)

        entry = {
            "name": str(item.get("name") or ""),
            "guid": str(item.get("auto_generated_guid") or ""),
            "description": str(item.get("description") or "").strip(),
            "supported_platforms": platforms,
            "executor": executor_name,
            "elevation_required": bool(executor.get("elevation_required") or False),
            "input_arguments": sorted((item.get("input_arguments") or {}).keys()),
            "dependency_count": len(item.get("dependencies") or []),
            "validation_plan": _build_validation_plan(
                technique_id=technique_id,
                platforms=platforms,
                executor=executor_name,
                dependency_count=len(item.get("dependencies") or []),
            ),
        }
        if include_commands:
            entry["command"] = str(executor.get("command") or "")
            entry["cleanup_command"] = str(executor.get("cleanup_command") or "")
        tests.append(entry)

    return {
        "technique_id": str(data.get("attack_technique") or technique_id),
        "display_name": str(data.get("display_name") or ""),
        "source_path": str(yaml_path),
        "atomic_test_count": len(tests),
        "supported_platforms": sorted(platform_set),
        "executors": sorted(executor_set),
        "tests": tests,
    }


def _build_validation_plan(
    *,
    technique_id: str,
    platforms: list[str],
    executor: str,
    dependency_count: int,
) -> dict[str, Any]:
    """Return a safe, command-free validation plan for one Atomic test."""
    telemetry = ["process_creation", "authentication", "file_activity"]
    if any(p in {"linux", "macos"} for p in platforms):
        telemetry.extend(["auditd", "shell_history"])
    if any(p in {"windows"} for p in platforms):
        telemetry.extend(["windows_event", "sysmon"])

    return {
        "mode": "metadata_only_guidance",
        "technique_id": technique_id,
        "executor": executor,
        "supported_platforms": platforms,
        "dependency_count": dependency_count,
        "prechecks": [
            "Run only in an isolated lab tenant or approved validation range.",
            "Confirm logging sources are enabled before any external exercise.",
            "Record owner, change window, expected alert, and rollback contact.",
        ],
        "telemetry_to_watch": sorted(set(telemetry)),
        "expected_soc_artifacts": [
            "Normalized ingestion event",
            "Detection alert mapped to the ATT&CK technique",
            "SOC case or analyst feedback entry",
            "Coverage Center status update",
        ],
        "safety": "CyberTwin does not expose or execute Atomic command bodies through this API.",
    }
