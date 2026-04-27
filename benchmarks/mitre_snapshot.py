"""Generate a MITRE ATT&CK coverage snapshot for the proof folder.

Usage:
    python -m benchmarks.mitre_snapshot

Writes ``docs/proof/mitre-coverage-snapshot.json``. This snapshot reflects
*static* coverage (rule_mapped vs not_covered) — i.e. the answer to "which
techniques does CyberTwin SOC have at least one detection rule for?",
without running any simulation.
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.coverage.calculator import CoverageCalculator  # noqa: E402
from backend.detection.engine import DetectionEngine  # noqa: E402
from backend.mitre.attack_data import MITRE_TACTICS, MITRE_TECHNIQUES  # noqa: E402


def main() -> int:
    engine = DetectionEngine()
    calc = CoverageCalculator(rules=engine._rules)
    records, summary = calc.compute()

    by_tactic: dict[str, dict] = defaultdict(
        lambda: {"name": "", "covered": 0, "total": 0, "high_risk_gaps": 0}
    )
    for record in records:
        bucket = by_tactic[record.tactic_id]
        bucket["name"] = MITRE_TACTICS.get(record.tactic_id, {}).get("name", record.tactic_id)
        bucket["total"] += 1
        if record.status.value != "not_covered":
            bucket["covered"] += 1
        if record.status.value == "not_covered" and record.tactic_id in (
            "TA0001", "TA0002", "TA0003", "TA0004", "TA0005",
            "TA0010", "TA0011", "TA0040",
        ):
            bucket["high_risk_gaps"] += 1

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "rules_loaded": len(engine._rules),
        "techniques_in_catalog": len(MITRE_TECHNIQUES),
        "tactics_in_catalog": len(MITRE_TACTICS),
        "summary": {
            "catalog_total": summary.catalog_total,
            "rule_mapped": summary.rule_mapped,
            "validated": summary.validated,
            "failed": summary.failed,
            "untested": summary.untested,
            "not_covered": summary.not_covered,
            "high_risk_gaps": summary.high_risk_gaps,
            "rule_mapped_pct": round(
                summary.rule_mapped / summary.catalog_total * 100, 2
            ) if summary.catalog_total else 0.0,
        },
        "by_status": summary.by_status,
        "by_tactic": dict(by_tactic),
    }

    out_dir = Path(__file__).resolve().parent.parent / "docs" / "proof"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / "mitre-coverage-snapshot.json"
    out_file.write_text(json.dumps(payload, indent=2, sort_keys=False))
    print(
        f"Saved snapshot: {payload['summary']['rule_mapped']}/"
        f"{payload['summary']['catalog_total']} techniques rule-mapped "
        f"({payload['summary']['rule_mapped_pct']}%)"
    )
    print(f"  -> {out_file}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
