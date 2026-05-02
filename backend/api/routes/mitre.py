"""MITRE ATT&CK reference data, gap analysis, Sigma rules, and TAXII sync."""

from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from backend.audit import log_action
from backend.auth import require_permission

from ..deps import PROJECT_ROOT, _client_ip, _safe_path, limiter, orchestrator as _orchestrator

router = APIRouter(tags=["mitre"])

_MAX_SIGMA_BYTES = 256 * 1024


def _tenant_id(user: dict) -> str:
    return user.get("tenant_id") or "default"


def _tenant_slug(tenant_id: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_-]", "-", tenant_id)[:48] or "default"


def _scenario_visible_to_tenant(scenario: dict, tenant_id: str) -> bool:
    owner = scenario.get("tenant_id")
    return owner in (None, "", "global", tenant_id)


@router.get("/api/threat-intel")
@limiter.limit("60/minute")
def get_threat_intel(request: Request, user=Depends(require_permission("view_results"))):
    """Aggregate IOCs from all scenario definitions."""
    tenant = _tenant_id(user)
    intel: dict = {
        "threat_actors": [],
        "iocs": {
            "ip_addresses": [], "domains": [], "file_hashes": [],
            "urls": [], "email_addresses": [], "cves": [], "tools": [],
        },
        "references": [],
    }
    for _sid, scenario in _orchestrator.attack_engine._scenarios.items():
        if not _scenario_visible_to_tenant(scenario, tenant):
            continue
        if "threat_actor" in scenario:
            intel["threat_actors"].append(scenario["threat_actor"])
        if "references" in scenario:
            intel["references"].extend(scenario["references"])
        for phase in scenario.get("phases", []):
            ioc = phase.get("ioc", phase.get("iocs", {}))
            if isinstance(ioc, dict):
                for key in ["ip_addresses", "ips", "external_ips"]:
                    intel["iocs"]["ip_addresses"].extend(ioc.get(key, []))
                for key in ["domains", "domain"]:
                    intel["iocs"]["domains"].extend(ioc.get(key, []))
                for key in ["file_hashes", "hashes", "sha256"]:
                    val = ioc.get(key, {})
                    if isinstance(val, dict):
                        intel["iocs"]["file_hashes"].extend(val.values())
                    elif isinstance(val, list):
                        intel["iocs"]["file_hashes"].extend(val)
                for key in ["urls", "url"]:
                    intel["iocs"]["urls"].extend(ioc.get(key, []))
                for key in ["cves", "cve"]:
                    intel["iocs"]["cves"].extend(ioc.get(key, []))
                for key in ["tools", "tool"]:
                    intel["iocs"]["tools"].extend(ioc.get(key, []))
            indicators = phase.get("indicators", {})
            if isinstance(indicators, dict):
                for key in ["cve"]:
                    v = indicators.get(key)
                    if v:
                        intel["iocs"]["cves"].append(v) if isinstance(v, str) else intel["iocs"]["cves"].extend(v)
                for key in ["tools", "tool"]:
                    v = indicators.get(key)
                    if v:
                        if isinstance(v, list):
                            intel["iocs"]["tools"].extend(v)
                        elif isinstance(v, str):
                            intel["iocs"]["tools"].append(v)
                for key in ["url"]:
                    v = indicators.get(key)
                    if v and isinstance(v, str):
                        intel["iocs"]["urls"].append(v)
                for key in ["sender"]:
                    v = indicators.get(key)
                    if v and isinstance(v, str):
                        intel["iocs"]["email_addresses"].append(v)
    for key in intel["iocs"]:
        intel["iocs"][key] = list(set(intel["iocs"][key]))
    intel["references"] = list(set(str(r) for r in intel["references"]))
    return intel


@router.get("/api/mitre/tactics")
@limiter.limit("60/minute")
def get_mitre_tactics(request: Request, user=Depends(require_permission("view_results"))):
    from backend.mitre.attack_data import MITRE_TACTICS
    return dict(MITRE_TACTICS)


@router.get("/api/mitre/techniques")
@limiter.limit("60/minute")
def get_mitre_techniques(request: Request, user=Depends(require_permission("view_results"))):
    from backend.mitre.attack_data import MITRE_TECHNIQUES
    return MITRE_TECHNIQUES


@router.get("/api/mitre/atomic-red-team")
@limiter.limit("30/minute")
def get_atomic_red_team_catalogue(
    request: Request,
    limit: int = Query(default=500, ge=1, le=2000),
    user=Depends(require_permission("view_results")),
):
    """Return safe metadata about a local Atomic Red Team checkout."""
    from backend.mitre.atomic_red_team import atomic_catalog_status, list_atomic_techniques

    status = atomic_catalog_status()
    if not status.get("available"):
        return status
    return {**status, "techniques": list_atomic_techniques(limit=limit)}


@router.get("/api/mitre/atomic-red-team/{technique_id}")
@limiter.limit("30/minute")
def get_atomic_red_team_technique(
    request: Request,
    technique_id: str,
    user=Depends(require_permission("view_results")),
):
    """Return sanitized Atomic Red Team metadata for one ATT&CK technique."""
    from backend.mitre.atomic_red_team import atomic_catalog_status, load_atomic_technique

    status = atomic_catalog_status()
    if not status.get("available"):
        raise HTTPException(404, status.get("reason", "Atomic Red Team catalogue is not configured"))
    try:
        technique = load_atomic_technique(technique_id)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    if technique is None:
        raise HTTPException(404, f"Atomic Red Team technique '{technique_id}' not found")
    return technique


@router.get("/api/mitre/gap-analysis/{scenario_id}")
@limiter.limit("30/minute")
def mitre_gap_analysis(request: Request, scenario_id: str,
                       user=Depends(require_permission("view_results"))):
    from backend.mitre.attack_data import MITRE_TACTICS, MITRE_TECHNIQUES
    from ..deps import _get_cached_result
    result = _get_cached_result(scenario_id, tenant_id=_tenant_id(user))
    detected_tids = {a.get("technique_id", "") for a in result.get("alerts", [])}
    gap: dict = {"covered": [], "uncovered": [], "coverage_pct": 0.0, "by_tactic": {}}
    for tid, tech in MITRE_TECHNIQUES.items():
        tactic_id = tech.get("tactic", "")
        tactic_name = MITRE_TACTICS.get(tactic_id, {}).get("name", tactic_id)
        entry = {"technique_id": tid, "technique_name": tech["name"], "tactic": tactic_name}
        if any(tid == d or d.startswith(tid + ".") or tid.startswith(d + ".") for d in detected_tids):
            gap["covered"].append(entry)
        else:
            gap["uncovered"].append(entry)
        gap["by_tactic"].setdefault(tactic_name, {"covered": 0, "total": 0})
        gap["by_tactic"][tactic_name]["total"] += 1
        if entry in gap["covered"]:
            gap["by_tactic"][tactic_name]["covered"] += 1
    total = len(MITRE_TECHNIQUES)
    gap["coverage_pct"] = round(len(gap["covered"]) / total * 100, 1) if total else 0.0
    return gap


@router.post("/api/sigma/upload")
@limiter.limit("10/minute")
async def upload_sigma_rule(request: Request, user=Depends(require_permission("manage_scenarios"))):
    from backend.detection.sigma_loader import SigmaLoader
    body = await request.body()
    if len(body) > _MAX_SIGMA_BYTES:
        raise HTTPException(413, f"Sigma rule too large (>{_MAX_SIGMA_BYTES} bytes)")
    try:
        rule = SigmaLoader.load_from_yaml(body.decode("utf-8"))
    except Exception as exc:
        raise HTTPException(400, f"Invalid Sigma rule: {exc}")
    tenant = _tenant_id(user)
    sigma_dir = PROJECT_ROOT / "data" / "sigma_rules" / _tenant_slug(tenant)
    sigma_dir.mkdir(parents=True, exist_ok=True)
    rule_file = _safe_path(sigma_dir, rule.rule_id, ".yml")
    rule_file.write_bytes(body)
    log_action("UPLOAD_SIGMA_RULE", username=user["sub"], role=user.get("role"),
               tenant_id=tenant,
               resource=rule.rule_id, ip_address=_client_ip(request))
    return {"status": "registered", "rule_id": rule.rule_id,
            "name": rule.name, "severity": rule.severity}


@router.get("/api/sigma/rules")
@limiter.limit("30/minute")
def list_sigma_rules(request: Request, user=Depends(require_permission("view_results"))):
    sigma_dir = PROJECT_ROOT / "data" / "sigma_rules" / _tenant_slug(_tenant_id(user))
    if not sigma_dir.exists():
        return []
    return [{"filename": f.name, "rule_id": f.stem, "size": f.stat().st_size}
            for f in sigma_dir.glob("*.yml")]


@router.post("/api/mitre/sync-taxii")
@limiter.limit("2/hour")
async def sync_mitre_taxii(request: Request, user=Depends(require_permission("configure_system"))):
    import asyncio
    from backend.mitre.taxii_sync import sync_from_taxii
    loop = asyncio.get_event_loop()
    try:
        count = await loop.run_in_executor(None, sync_from_taxii)
        log_action("TAXII_SYNC", username=user["sub"], role=user.get("role"),
                   tenant_id=_tenant_id(user),
                   ip_address=_client_ip(request), details={"techniques_synced": count})
        return {"status": "synced", "techniques_updated": count}
    except Exception as exc:
        raise HTTPException(502, f"TAXII sync failed: {exc}")
