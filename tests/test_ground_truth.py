"""Ground-truth manifests under `datasets/ground_truth/` — precision / recall."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from backend.detection.engine import DetectionEngine

_ROOT = Path(__file__).resolve().parents[1]
MANIFESTS = sorted((_ROOT / "datasets" / "ground_truth").glob("*/manifest.json"))


@pytest.mark.parametrize("manifest_path", MANIFESTS, ids=lambda p: p.parent.name)
def test_ground_truth_manifest(manifest_path: Path):
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    engine = DetectionEngine(load_sigma=False)
    alerts = engine.analyse(data["events"])
    fired = {a["rule_id"] for a in alerts}
    expected = set(data.get("expected_rule_ids") or [])
    forb = set(data.get("forbidden_rule_ids") or [])
    max_alerts = data.get("max_alerts_allowed")

    forbidden_hits = forb & fired
    assert not forbidden_hits, (
        f"{data['id']}: forbidden rules fired: {forbidden_hits}"
    )

    if expected:
        missed = expected - fired
        assert not missed, (
            f"{data['id']}: expected rules not fired (recall gap): {missed}. "
            f"Fired={fired}"
        )
        extra = fired - expected - forb
        # Allow additional true positives from overlapping rules on same events
        # but document when it happens for auditability.
        if extra:
            pytest.fail(
                f"{data['id']}: unexpected rule_ids {extra} — tighten manifest or "
                f"narrow synthetic events. Fired={fired}"
            )
    else:
        if max_alerts is not None:
            assert len(alerts) <= int(max_alerts), (
                f"{data['id']}: benign noise cap exceeded: {len(alerts)} alerts "
                f"(max {max_alerts}) fired={fired}"
            )
        else:
            assert not fired, f"{data['id']}: benign scenario produced alerts {fired}"
