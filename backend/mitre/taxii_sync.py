"""
CyberTwin SOC — MITRE ATT&CK TAXII 2.1 Sync
==============================================
Fetches the latest MITRE ATT&CK Enterprise techniques from the official
TAXII 2.1 server (https://attack-taxii.mitre.org) and updates the local
attack_data.py cache file.

If taxii2-client or stix2 are not installed, raises ImportError gracefully.
Falls back to the embedded static dataset if the TAXII server is unreachable.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger("cybertwin.taxii")

_CACHE_FILE = Path(__file__).parent / "taxii_cache.json"
_TAXII_ROOT = "https://attack-taxii.mitre.org"
_ENTERPRISE_COLLECTION = "95ecc380-afe9-11e4-9b6c-751b66dd541e"


def _fetch_via_taxii2client() -> list[dict[str, Any]]:
    """Fetch techniques from MITRE TAXII 2.1 using taxii2-client + stix2."""
    from taxii2client.v21 import Server
    import stix2

    server = Server(_TAXII_ROOT)
    api_root = server.api_roots[0]
    collection_obj = None
    for col in api_root.collections:
        if _ENTERPRISE_COLLECTION in str(col.id):
            collection_obj = col
            break
    if collection_obj is None:
        raise ValueError("Enterprise ATT&CK collection not found on TAXII server")

    bundle = stix2.parse(
        json.dumps(collection_obj.get_objects()),
        allow_custom=True
    )
    techniques = []
    for obj in bundle.get("objects", []):
        if getattr(obj, "type", "") != "attack-pattern":
            continue
        if getattr(obj, "revoked", False):
            continue
        ext = getattr(obj, "external_references", [])
        tid = ""
        for ref in ext:
            if getattr(ref, "source_name", "") == "mitre-attack":
                tid = getattr(ref, "external_id", "")
                break
        if not tid:
            continue
        tactics = [
            p.get("phase_name", "").replace("-", " ").title()
            for p in getattr(obj, "kill_chain_phases", [])
            if "mitre-attack" in str(p.get("kill_chain_name", ""))
        ]
        techniques.append({
            "id": tid,
            "name": getattr(obj, "name", ""),
            "description": getattr(obj, "description", "")[:300],
            "tactics": tactics,
        })
    return techniques


def _fetch_via_rest() -> list[dict[str, Any]]:
    """Fallback: fetch via plain HTTPS REST if taxii2-client not installed."""
    import urllib.request
    import urllib.error

    url = f"{_TAXII_ROOT}/taxii2/"
    headers = {
        "Accept": "application/taxii+json;version=2.1",
        "User-Agent": "CyberTwin-SOC/3.0",
    }
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
            return data.get("objects", [])[:20]
    except urllib.error.URLError as exc:
        raise RuntimeError(f"TAXII REST request failed: {exc}") from exc


def sync_from_taxii() -> int:
    """
    Sync MITRE ATT&CK Enterprise techniques from the TAXII 2.1 server.
    Saves results to taxii_cache.json and updates the MITRE_TECHNIQUES dict.
    Returns the number of techniques synced.
    """
    techniques: list[dict[str, Any]] = []

    try:
        logger.info("Fetching MITRE ATT&CK from TAXII 2.1 server...")
        techniques = _fetch_via_taxii2client()
        logger.info("TAXII2 client fetch: %d techniques", len(techniques))
    except ImportError:
        logger.warning("taxii2-client/stix2 not installed — trying REST fallback")
        try:
            techniques = _fetch_via_rest()
        except Exception as exc:
            logger.error("REST fallback also failed: %s", exc)
            raise
    except Exception as exc:
        logger.error("TAXII sync failed: %s", exc)
        raise

    if not techniques:
        raise RuntimeError("TAXII sync returned 0 techniques")

    _CACHE_FILE.write_text(
        json.dumps({"techniques": techniques, "count": len(techniques)}, indent=2),
        encoding="utf-8",
    )

    _apply_to_attack_data(techniques)
    logger.info("TAXII sync complete: %d techniques saved to cache", len(techniques))
    return len(techniques)


def _apply_to_attack_data(techniques: list[dict]) -> None:
    """Merge freshly fetched techniques into the in-memory MITRE_TECHNIQUES dict."""
    try:
        from backend.mitre.attack_data import MITRE_TECHNIQUES, MITRE_TACTICS

        _TACTIC_NAME_TO_ID = {v.get("name", "").lower(): k for k, v in MITRE_TACTICS.items()}

        for tech in techniques:
            tid = tech.get("id", "")
            if not tid:
                continue
            tactic_name = tech.get("tactics", [""])[0] if tech.get("tactics") else ""
            tactic_id = _TACTIC_NAME_TO_ID.get(tactic_name.lower(), "TA0001")
            if tid not in MITRE_TECHNIQUES:
                MITRE_TECHNIQUES[tid] = {
                    "name": tech.get("name", ""),
                    "tactic": tactic_id,
                    "description": tech.get("description", ""),
                }
        logger.info("Applied %d techniques to in-memory MITRE_TECHNIQUES dict", len(techniques))
    except Exception as exc:
        logger.warning("Could not apply TAXII results to attack_data: %s", exc)


def load_cached() -> list[dict[str, Any]]:
    """Load the last saved TAXII cache without fetching."""
    if _CACHE_FILE.exists():
        try:
            data = json.loads(_CACHE_FILE.read_text(encoding="utf-8"))
            return data.get("techniques", [])
        except Exception:
            pass
    return []
