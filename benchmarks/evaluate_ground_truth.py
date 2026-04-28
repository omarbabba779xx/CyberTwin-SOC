#!/usr/bin/env python3
"""Aggregate precision / recall across `datasets/ground_truth/*/manifest.json`."""
from __future__ import annotations

import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from backend.detection.engine import DetectionEngine  # noqa: E402


def _manifest_paths() -> list[Path]:
    base = _ROOT / "datasets" / "ground_truth"
    return sorted(base.glob("*/manifest.json"))


def evaluate_one(manifest_path: Path) -> dict:
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    engine = DetectionEngine(load_sigma=False)
    alerts = engine.analyse(data["events"])
    fired_set = {a["rule_id"] for a in alerts}

    expected = set(data.get("expected_rule_ids") or [])
    forb = set(data.get("forbidden_rule_ids") or [])
    max_allowed_raw = data.get("max_alerts_allowed")

    tp_set = expected & fired_set
    fn_set = expected - fired_set
    fp_set = fired_set - expected - forb
    forb_hits = forb & fired_set

    if expected:
        recall = len(tp_set) / len(expected)
        precision = (len(tp_set) / len(fired_set)) if fired_set else 0.0
    elif max_allowed_raw is not None:
        max_allow = int(max_allowed_raw)
        precision = 1.0 if len(alerts) <= max_allow else 0.0
        recall = None
    else:
        precision = 1.0 if not fired_set else 0.0
        recall = None

    return {
        "id": data["id"],
        "manifest": str(manifest_path.relative_to(_ROOT)),
        "fired": sorted(fired_set),
        "expected": sorted(expected),
        "precision": precision,
        "recall": recall,
        "unexpected_extra": sorted(fp_set),
        "missed": sorted(fn_set),
        "forbidden_hits": sorted(forb_hits),
        "alert_count": len(alerts),
    }


def main() -> int:
    manifests = _manifest_paths()
    if not manifests:
        print("No manifests found under datasets/ground_truth/", file=sys.stderr)
        return 1

    agg_tp = agg_fp = agg_fn = 0
    for manifest in manifests:
        row = evaluate_one(manifest)
        print(json.dumps(row, indent=2))
        fired = set(row["fired"])
        exp = set(row["expected"])
        if exp:
            agg_tp += len(exp & fired)
            agg_fp += len(fired - exp)
            agg_fn += len(exp - fired)

    print("-----")
    if agg_tp + agg_fp > 0 and agg_tp + agg_fn > 0:
        micro_p = agg_tp / (agg_tp + agg_fp)
        micro_r = agg_tp / (agg_tp + agg_fn)
        print(f"Micro-averaged precision (attack scenarios only): {micro_p:.4f}")
        print(f"Micro-averaged recall (attack scenarios only):    {micro_r:.4f}")
    else:
        print("(Micro averages skipped — no expected_rule_ids in manifests)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
