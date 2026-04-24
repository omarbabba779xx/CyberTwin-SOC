"""
CyberTwin SOC — LLM-Powered Analyst
======================================
Provides real AI analysis of simulation results using a locally-running
Ollama instance (Mistral / Llama3 / Phi-3). Falls back automatically to
the rule-based NLG engine (backend.ai_analyst) when Ollama is unavailable.

Configuration (via .env):
    OLLAMA_BASE_URL=http://localhost:11434   (default)
    OLLAMA_MODEL=mistral                     (default)
    LLM_TIMEOUT_SECONDS=60                  (default)
    LLM_ENABLED=true                        (set false to force NLG fallback)
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

logger = logging.getLogger("cybertwin.llm")

_OLLAMA_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
_OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "mistral")
_LLM_TIMEOUT = int(os.getenv("LLM_TIMEOUT_SECONDS", "60"))
_LLM_ENABLED = os.getenv("LLM_ENABLED", "true").lower() not in ("false", "0", "no")


# ---------------------------------------------------------------------------
# Prompt builder
# ---------------------------------------------------------------------------

def _build_prompt(results: dict[str, Any]) -> str:
    scores = results.get("scores", {})
    alerts = results.get("alerts", [])
    incidents = results.get("incidents", [])
    scenario = results.get("scenario", {})

    top_alerts = sorted(alerts, key=lambda a: {
        "critical": 4, "high": 3, "medium": 2, "low": 1
    }.get(a.get("severity", "low"), 0), reverse=True)[:8]

    alert_summary = "\n".join(
        f"  - [{a.get('severity','?').upper()}] {a.get('rule_name','?')}: {a.get('description','')[:120]}"
        for a in top_alerts
    )

    techniques = list({a.get("technique_id", "") for a in alerts if a.get("technique_id")})[:10]

    return f"""You are an expert SOC analyst and threat intelligence specialist. Analyze the following cyber attack simulation results and provide a professional incident report.

## Simulation Context
- **Scenario**: {scenario.get('name', 'Unknown')}
- **Threat Actor**: {scenario.get('threat_actor', {}).get('name', 'Unknown')} ({scenario.get('threat_actor', {}).get('origin', '?')})
- **Severity**: {scenario.get('severity', 'unknown').upper()}
- **Total Alerts**: {len(alerts)}
- **Total Incidents**: {len(incidents)}

## Detection Scores
- Overall Security Score: {scores.get('overall_score', 0)}/100
- Detection Score: {scores.get('detection_score', 0)}/100
- MITRE Coverage: {scores.get('coverage_score', 0)}/100
- Response Time Score: {scores.get('response_score', 0)}/100
- Visibility Score: {scores.get('visibility_score', 0)}/100
- Risk Level: {scores.get('risk_level', 'Unknown')}
- Maturity Level: {scores.get('maturity_level', 'Unknown')}

## Top Alerts Triggered
{alert_summary if alert_summary else "  No alerts triggered."}

## MITRE ATT&CK Techniques Detected
{', '.join(techniques) if techniques else 'None detected'}

## Instructions
Provide a structured incident report with these sections:
1. **Executive Summary** (3-4 sentences for C-level audience)
2. **Attack Chain Analysis** (step-by-step attacker progression)
3. **Critical Findings** (most dangerous gaps/detections)
4. **Immediate Actions Required** (prioritized remediation steps)
5. **Strategic Recommendations** (long-term security improvements)

Be specific, technical where appropriate, and actionable. Reference MITRE ATT&CK techniques explicitly.
"""


# ---------------------------------------------------------------------------
# Ollama client
# ---------------------------------------------------------------------------

def _query_ollama(prompt: str) -> str | None:
    """Send a prompt to Ollama and return the response text, or None on failure."""
    try:
        import httpx
        payload = {
            "model": _OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.3,
                "top_p": 0.9,
                "num_predict": 1500,
            },
        }
        resp = httpx.post(
            f"{_OLLAMA_URL}/api/generate",
            json=payload,
            timeout=_LLM_TIMEOUT,
        )
        if resp.status_code == 200:
            data = resp.json()
            return data.get("response", "").strip()
        logger.warning("Ollama returned HTTP %d", resp.status_code)
        return None
    except ImportError:
        logger.warning("httpx not installed — Ollama unavailable")
        return None
    except Exception as exc:
        logger.warning("Ollama request failed: %s", exc)
        return None


def _check_ollama_available() -> bool:
    """Ping Ollama health endpoint."""
    try:
        import httpx
        resp = httpx.get(f"{_OLLAMA_URL}/api/tags", timeout=3)
        return resp.status_code == 200
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Response parser
# ---------------------------------------------------------------------------

def _parse_llm_response(text: str, results: dict[str, Any]) -> dict[str, Any]:
    """Parse the LLM markdown response into structured sections."""
    sections: dict[str, str] = {
        "executive_summary": "",
        "attack_chain_analysis": "",
        "critical_findings": "",
        "immediate_actions": "",
        "strategic_recommendations": "",
    }
    header_map = {
        "executive summary": "executive_summary",
        "attack chain": "attack_chain_analysis",
        "critical finding": "critical_findings",
        "immediate action": "immediate_actions",
        "strategic recommendation": "strategic_recommendations",
    }
    current_key = None
    current_lines: list[str] = []

    for line in text.split("\n"):
        header_match = False
        for keyword, key in header_map.items():
            if keyword in line.lower() and line.strip().startswith("#"):
                if current_key and current_lines:
                    sections[current_key] = "\n".join(current_lines).strip()
                current_key = key
                current_lines = []
                header_match = True
                break
        if not header_match and current_key:
            current_lines.append(line)

    if current_key and current_lines:
        sections[current_key] = "\n".join(current_lines).strip()

    if not any(sections.values()):
        sections["executive_summary"] = text[:1000]

    scores = results.get("scores", {})
    return {
        "source": "llm_ollama",
        "model": _OLLAMA_MODEL,
        "generated_by": f"Ollama ({_OLLAMA_MODEL})",
        "overall_assessment": scores.get("risk_level", "Unknown"),
        "executive_narrative": sections["executive_summary"] or text[:500],
        "attack_chain_analysis": sections["attack_chain_analysis"],
        "critical_findings": sections["critical_findings"],
        "immediate_actions": sections["immediate_actions"],
        "strategic_recommendations": sections["strategic_recommendations"],
        "severity_assessment": scores.get("maturity_level", ""),
        "full_report": text,
    }


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def analyse_with_llm(results: dict[str, Any]) -> dict[str, Any]:
    """
    Attempt LLM analysis via Ollama. Falls back to rule-based NLG if unavailable.

    Returns the standard ai_analysis dict consumed by the frontend.
    """
    if _LLM_ENABLED and _check_ollama_available():
        prompt = _build_prompt(results)
        response_text = _query_ollama(prompt)
        if response_text:
            logger.info("LLM analysis complete (model=%s, chars=%d)", _OLLAMA_MODEL, len(response_text))
            return _parse_llm_response(response_text, results)
        logger.warning("LLM returned empty response — falling back to NLG")
    else:
        if _LLM_ENABLED:
            logger.info("Ollama not reachable at %s — using NLG fallback", _OLLAMA_URL)
        else:
            logger.info("LLM disabled (LLM_ENABLED=false) — using NLG fallback")

    from backend.ai_analyst import AIAnalyst
    analyst = AIAnalyst()
    nlg_result = analyst.analyse_incident(
        scenario=results.get("scenario", {}),
        alerts=results.get("alerts", []),
        incidents=results.get("incidents", []),
        scores=results.get("scores", {}),
        mitre_coverage=results.get("mitre_coverage", {}),
        timeline=results.get("timeline", []),
        logs_stats=results.get("logs_statistics", {}),
    )
    nlg_result["source"] = "nlg_fallback"
    nlg_result["generated_by"] = "Rule-based NLG (Ollama unavailable)"
    return nlg_result
