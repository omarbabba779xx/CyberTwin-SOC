"""Scenario classification and IOC / host / user / tactic extraction."""

from __future__ import annotations

import re
from typing import Any

from .constants import _SCENARIO_KEYWORDS
from .helpers import _is_private_ip


class ExtractorMixin:
    """Provides scenario classification + extractor methods on AIAnalyst."""

    @staticmethod
    def _classify_scenario(scenario: dict) -> str:
        blob = " ".join([
            scenario.get("id", ""),
            scenario.get("name", ""),
            scenario.get("description", ""),
            scenario.get("category", ""),
        ]).lower()
        best, best_score = "unknown", 0
        for stype, keywords in _SCENARIO_KEYWORDS.items():
            hits = sum(1 for kw in keywords if kw in blob)
            if hits > best_score:
                best, best_score = stype, hits
        return best

    @staticmethod
    def _detection_rate_band(scores: dict) -> str:
        det = scores.get("detection_score", 0)
        if det >= 75:
            return "high"
        if det >= 40:
            return "medium"
        return "low"

    @staticmethod
    def _extract_affected_hosts(
        alerts: list[dict], timeline: list[dict],
    ) -> list[str]:
        hosts: set[str] = set()
        for a in alerts:
            h = a.get("affected_host") or a.get("src_host")
            if h:
                hosts.add(h)
        for t in timeline:
            if t.get("is_malicious") and t.get("src_host"):
                hosts.add(t["src_host"])
        return sorted(hosts)

    @staticmethod
    def _extract_affected_users(
        alerts: list[dict], timeline: list[dict],
    ) -> list[str]:
        users: set[str] = set()
        for a in alerts:
            u = a.get("affected_user") or a.get("user")
            if u:
                users.add(u)
        for t in timeline:
            if t.get("is_malicious") and t.get("user"):
                users.add(t["user"])
        return sorted(users)

    @staticmethod
    def _extract_tactics(scenario: dict, alerts: list[dict]) -> list[str]:
        tactics: list[str] = []
        seen: set[str] = set()
        for p in scenario.get("phases", []):
            t = p.get("tactic", "")
            if t and t not in seen:
                tactics.append(t)
                seen.add(t)
        for a in alerts:
            t = a.get("tactic", "")
            if t and t not in seen:
                tactics.append(t)
                seen.add(t)
        return tactics

    @staticmethod
    def _extract_iocs(
        scenario: dict, alerts: list[dict], timeline: list[dict],
    ) -> dict[str, list[str]]:
        ips: set[str] = set()
        domains: set[str] = set()
        hashes: set[str] = set()
        accounts: set[str] = set()
        emails: set[str] = set()
        urls: set[str] = set()

        ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        domain_re = re.compile(r"\b[a-zA-Z0-9-]+\.[a-zA-Z]{2,}\b")
        hash_re = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
        email_re = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.]+\b")

        for phase in scenario.get("phases", []):
            indicators = phase.get("indicators", {})
            for key, val in indicators.items():
                if not isinstance(val, str):
                    continue
                if "ip" in key.lower():
                    ips.add(val)
                if "domain" in key.lower():
                    domains.add(val)
                if "url" in key.lower():
                    urls.add(val)
                if "sender" in key.lower() or "email" in key.lower():
                    emails.add(val)
                if "hash" in key.lower():
                    hashes.add(val)

            target_user = phase.get("target_user")
            if target_user:
                accounts.add(target_user)

        for a in alerts:
            desc = a.get("description", "")
            ips.update(ip_re.findall(desc))
            domains.update(d for d in domain_re.findall(desc) if "." in d and not d[0].isdigit())
            hashes.update(hash_re.findall(desc))
            emails.update(email_re.findall(desc))

        for t in timeline:
            if not t.get("is_malicious"):
                continue
            desc = t.get("description", "")
            ips.update(ip_re.findall(desc))
            hashes.update(hash_re.findall(desc))
            emails.update(email_re.findall(desc))
            if t.get("user"):
                accounts.add(t["user"])

        external_ips = {ip for ip in ips if not _is_private_ip(ip)}
        internal_ips = {ip for ip in ips if _is_private_ip(ip)}

        return {
            "external_ips": sorted(external_ips),
            "internal_ips": sorted(internal_ips),
            "domains": sorted(domains),
            "urls": sorted(urls),
            "file_hashes": sorted(hashes),
            "compromised_accounts": sorted(accounts),
            "email_addresses": sorted(emails),
        }
