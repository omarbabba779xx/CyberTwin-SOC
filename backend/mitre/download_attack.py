"""
CyberTwin SOC — MITRE ATT&CK Bundle Downloader
================================================
Downloads the full MITRE ATT&CK Enterprise STIX bundle from GitHub
and converts it to a flat JSON file (techniques_bundle.json).

Full dataset: ~196 techniques + 411 sub-techniques = ~607 total entries.

Usage::

    python -m backend.mitre.download_attack
    # or
    from backend.mitre.download_attack import ensure_bundle
    ensure_bundle()          # downloads if not cached
    techniques = load_bundle()   # returns dict[tid -> {...}]
"""

from __future__ import annotations

import json
import logging
import urllib.request
from pathlib import Path
from typing import Any

logger = logging.getLogger("cybertwin.mitre.download")

_BUNDLE_FILE = Path(__file__).parent / "techniques_bundle.json"

_ATTACK_URLS = [
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-14.1.json",
]

_TACTIC_SHORT = {
    "initial-access":        "TA0001",
    "execution":             "TA0002",
    "persistence":           "TA0003",
    "privilege-escalation":  "TA0004",
    "defense-evasion":       "TA0005",
    "credential-access":     "TA0006",
    "discovery":             "TA0007",
    "lateral-movement":      "TA0008",
    "collection":            "TA0009",
    "exfiltration":          "TA0010",
    "command-and-control":   "TA0011",
    "impact":                "TA0040",
    "resource-development":  "TA0042",
    "reconnaissance":        "TA0043",
}


def _parse_stix_bundle(bundle: dict) -> dict[str, dict[str, str]]:
    """Convert a MITRE ATT&CK STIX bundle into a flat technique dict."""
    techniques: dict[str, dict[str, str]] = {}

    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
            continue

        # Extract MITRE technique ID
        tid = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                tid = ref.get("external_id", "")
                break
        if not tid or not tid.startswith("T"):
            continue

        # Extract primary tactic
        tactics = [
            p.get("phase_name", "")
            for p in obj.get("kill_chain_phases", [])
            if p.get("kill_chain_name") == "mitre-attack"
        ]
        tactic_id = _TACTIC_SHORT.get(tactics[0], "TA0001") if tactics else "TA0001"

        # Truncate description
        desc = (obj.get("description") or "").replace("\n", " ")
        if len(desc) > 400:
            desc = desc[:397] + "…"

        techniques[tid] = {
            "name": obj.get("name", ""),
            "tactic": tactic_id,
            "description": desc,
            "platforms": ", ".join(obj.get("x_mitre_platforms", [])),
            "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
        }

    return techniques


def _download_bundle() -> dict:
    """Try each mirror URL until one succeeds."""
    for url in _ATTACK_URLS:
        try:
            logger.info("Downloading MITRE ATT&CK bundle from %s …", url)
            req = urllib.request.Request(url, headers={"User-Agent": "CyberTwin-SOC/3.0"})
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            logger.info("Download OK (objects: %d)", len(data.get("objects", [])))
            return data
        except Exception as exc:
            logger.warning("Mirror %s failed: %s", url, exc)
    raise RuntimeError("All MITRE ATT&CK mirror URLs failed")


def ensure_bundle(force: bool = False) -> Path:
    """
    Download and cache the full ATT&CK Enterprise bundle.
    Returns the path to the cached file.
    Skips download if the file already exists (unless *force* is True).
    """
    if _BUNDLE_FILE.exists() and not force:
        logger.info("Bundle already cached at %s", _BUNDLE_FILE)
        return _BUNDLE_FILE

    raw = _download_bundle()
    techniques = _parse_stix_bundle(raw)

    _BUNDLE_FILE.parent.mkdir(parents=True, exist_ok=True)
    _BUNDLE_FILE.write_text(
        json.dumps({"techniques": techniques, "count": len(techniques)}, indent=2),
        encoding="utf-8",
    )
    logger.info("Saved %d techniques to %s", len(techniques), _BUNDLE_FILE)
    return _BUNDLE_FILE


def load_bundle() -> dict[str, dict[str, str]]:
    """
    Load the cached technique bundle (dict keyed by technique ID).
    Downloads it first if not cached.
    Falls back to an empty dict on failure.
    """
    if not _BUNDLE_FILE.exists():
        try:
            ensure_bundle()
        except Exception as exc:
            logger.error("Could not load ATT&CK bundle: %s", exc)
            return {}

    try:
        data = json.loads(_BUNDLE_FILE.read_text(encoding="utf-8"))
        return data.get("techniques", {})
    except Exception as exc:
        logger.error("Bundle parse error: %s", exc)
        return {}


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    path = ensure_bundle(force=True)
    bundle = load_bundle()
    techs = [t for t in bundle if not bundle[t].get("is_subtechnique")]
    subs = [t for t in bundle if bundle[t].get("is_subtechnique")]
    print(f"\nBundle: {len(bundle)} total entries")
    print(f"  Base techniques:  {len(techs)}")
    print(f"  Sub-techniques:   {len(subs)}")
    print(f"  Saved to: {path}")
