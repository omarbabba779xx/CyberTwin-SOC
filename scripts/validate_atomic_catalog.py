"""Validate a local Atomic Red Team checkout against CyberTwin's safe parser."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.mitre.atomic_red_team import atomic_catalog_status, list_atomic_techniques, load_atomic_technique


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", required=True, help="Path to atomic-red-team checkout or atomics directory")
    parser.add_argument("--limit", type=int, default=50, help="Maximum techniques to parse")
    args = parser.parse_args()

    root = Path(args.path).expanduser().resolve()
    status = atomic_catalog_status(root)
    if not status.get("available"):
        print(json.dumps({"ok": False, "status": status}, indent=2))
        return 2

    parsed = 0
    failures: list[dict[str, str]] = []
    leaked_commands: list[str] = []
    for technique_id in list_atomic_techniques(root, limit=args.limit):
        try:
            technique = load_atomic_technique(technique_id, root=root)
            parsed += 1
        except Exception as exc:
            failures.append({"technique_id": technique_id, "error": str(exc)})
            continue
        for test in (technique or {}).get("tests", []):
            if "command" in test or "cleanup_command" in test:
                leaked_commands.append(technique_id)
            if not test.get("validation_plan"):
                failures.append({"technique_id": technique_id, "error": "missing validation_plan"})

    result = {
        "ok": not failures and not leaked_commands,
        "status": status,
        "parsed": parsed,
        "failures": failures,
        "leaked_commands": sorted(set(leaked_commands)),
    }
    print(json.dumps(result, indent=2, default=str))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
