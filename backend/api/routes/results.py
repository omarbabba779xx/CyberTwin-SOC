"""Simulation result endpoints (cache-backed)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from backend.auth import require_permission
from backend.cache import cache

from ..deps import _get_cached_result, limiter

router = APIRouter(tags=["results"])


@router.get("/api/results/{scenario_id}")
@limiter.limit("60/minute")
def get_full_results(request: Request, scenario_id: str,
                     user=Depends(require_permission("view_results"))):
    return _get_cached_result(scenario_id)


@router.get("/api/results/{scenario_id}/alerts")
@limiter.limit("60/minute")
def get_alerts(request: Request, scenario_id: str,
               user=Depends(require_permission("view_results"))):
    return _get_cached_result(scenario_id)["alerts"]


@router.get("/api/results/{scenario_id}/incidents")
@limiter.limit("60/minute")
def get_incidents(request: Request, scenario_id: str,
                  user=Depends(require_permission("view_results"))):
    return _get_cached_result(scenario_id)["incidents"]


@router.get("/api/results/{scenario_id}/timeline")
@limiter.limit("60/minute")
def get_timeline(request: Request, scenario_id: str,
                 user=Depends(require_permission("view_results"))):
    return _get_cached_result(scenario_id)["timeline"]


@router.get("/api/results/{scenario_id}/scores")
@limiter.limit("60/minute")
def get_scores(request: Request, scenario_id: str,
               user=Depends(require_permission("view_results"))):
    result = cache.get(f"result:{scenario_id}")
    if result is None:
        raise HTTPException(404, "No results found. Run a simulation first.")
    return result["scores"]


@router.get("/api/results/{scenario_id}/mitre")
@limiter.limit("60/minute")
def get_mitre_coverage(request: Request, scenario_id: str,
                       user=Depends(require_permission("view_results"))):
    return _get_cached_result(scenario_id)["mitre_coverage"]


@router.get("/api/results/{scenario_id}/report")
@limiter.limit("60/minute")
def get_report(request: Request, scenario_id: str,
               user=Depends(require_permission("view_results"))):
    return _get_cached_result(scenario_id)["report"]


@router.get("/api/results/{scenario_id}/logs")
@limiter.limit("60/minute")
def get_logs(request: Request, scenario_id: str, limit: int = 200, offset: int = 0,
             user=Depends(require_permission("view_results"))):
    logs = _get_cached_result(scenario_id)["logs"]
    return {"total": len(logs), "offset": offset, "limit": limit,
            "data": logs[offset: offset + limit]}


@router.get("/api/results/{scenario_id}/ai-analysis")
@limiter.limit("60/minute")
def get_ai_analysis(request: Request, scenario_id: str,
                    user=Depends(require_permission("view_results"))):
    result = _get_cached_result(scenario_id)
    ai = result.get("ai_analysis")
    if ai is None:
        raise HTTPException(404, "AI analysis not available.")
    return ai


@router.get("/api/results/{scenario_id}/statistics")
@limiter.limit("60/minute")
def get_statistics(request: Request, scenario_id: str,
                   user=Depends(require_permission("view_results"))):
    return _get_cached_result(scenario_id)["logs_statistics"]


@router.get("/api/results/{scenario_id}/benchmark")
@limiter.limit("30/minute")
def get_benchmark(request: Request, scenario_id: str,
                  user=Depends(require_permission("view_results"))):
    from backend.scoring import ScoringEngine
    result = _get_cached_result(scenario_id)
    engine = ScoringEngine()
    scores = result["scores"]
    return {
        "scenario_id": scenario_id,
        "nist_csf": engine.nist_csf_benchmark(scores),
        "cis_controls": engine.cis_controls_benchmark(scores),
    }


@router.get("/api/results/{scenario_id}/anomalies")
@limiter.limit("30/minute")
def get_anomalies(request: Request, scenario_id: str,
                  user=Depends(require_permission("view_results"))):
    from backend.detection.anomaly import AnomalyDetector
    result = _get_cached_result(scenario_id)
    detector = AnomalyDetector()
    anomalies = detector.detect(result["logs"])
    return {"total": len(anomalies), "anomalies": anomalies}


@router.get("/api/results/{scenario_id}/ai-evidence")
@limiter.limit("30/minute")
def get_ai_evidence_analysis(request: Request, scenario_id: str,
                              user=Depends(require_permission("view_results"))):
    """Evidence-first AI analysis with PII masking and strict schema."""
    result = _get_cached_result(scenario_id)
    from backend.ai_analyst import AIAnalyst
    return AIAnalyst().analyse_with_evidence(
        scenario=result.get("scenario", {}),
        alerts=result.get("alerts", []),
        incidents=result.get("incidents", []),
        scores=result.get("scores", {}),
        mitre_coverage=result.get("mitre_coverage", {}),
        timeline=result.get("timeline", []),
        logs_stats=result.get("logs_statistics", {}),
    )
