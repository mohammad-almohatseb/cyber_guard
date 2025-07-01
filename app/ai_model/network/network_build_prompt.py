from __future__ import annotations

"""Generate an LLM‑ready *network* prompt by fetching the latest
information‑gathering and vulnerability‑assessment documents, then feeding
those through ``build_network_prompt_from_docs.build_prompt_from_docs``.

The output prompt is multi‑line (analyst instructions + example) exactly
like your web workflow, so downstream code can swap
``build_web_prompt`` ↔ ``build_network_prompt`` without further refactoring.
"""

import asyncio
import logging
import re
from types import SimpleNamespace as NS
from typing import Any, Dict, List, Optional, Tuple

from app.api.models.information import NetworkInfoGathering
from app.api.models.vuln_assessment import NetworkVulnerabilityAssessmentModel
from app.ai_model.network.build_network_prompt_from_docs import build_prompt_from_docs

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────
async def build_network_prompt(network: str) -> str:  # noqa: D401
    """Return a fully‑formed prompt for *network* ready for the LLM."""

    info_doc, vuln_doc = await _fetch_latest_docs(network)
    if not info_doc or not vuln_doc:
        raise ValueError(f"Docs not found for network '{network}'")

    prompt = build_prompt_from_docs(
        _filter_info(info_doc),
        _filter_vuln(vuln_doc),
    )
    logger.debug("[PROMPT for %s]\n%s", network, prompt)
    return prompt


# ──────────────────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────────────────
async def _fetch_latest_docs(
    network: str,
) -> Tuple[
    Optional[NetworkInfoGatheringModel],
    Optional[NetworkVulnerabilityAssessmentModel],
]:
    """Fetch newest info & vuln docs concurrently (case‑insensitive)."""

    ci = _ci_regex(network)
    info_q = NetworkInfoGatheringModel.find_one(ci, sort=[("timestamp", -1)])
    vuln_q = NetworkVulnerabilityAssessmentModel.find_one(ci, sort=[("timestamp", -1)])
    return await asyncio.gather(info_q, vuln_q)


def _filter_info(info: NetworkInfoGatheringModel) -> NS:
    """Transform NetworkInfoGatheringModel → SimpleNamespace expected by builder."""

    payload: Dict[str, Any] = {
        "network": getattr(info, "network", getattr(info, "target", "")),
        "os": getattr(info, "os", "Unknown"),
        "services": sorted(getattr(info, "services", [])),  # list[str]
        "firewall_detected": "Yes" if getattr(info, "firewall_detected", False) else "No",
        "firewall_desc": getattr(info, "firewall_description", "N/A"),
    }
    return NS(**payload)


def _filter_vuln(vuln: NetworkVulnerabilityAssessmentModel) -> NS:
    """Transform NetworkVulnerabilityAssessmentModel → SimpleNamespace."""

    # Collate CVE dicts from any field names you store them in
    cve_dicts: List[Dict[str, str]] = []
    for field in ("cve_data", "server_cve_data", "service_cve_data"):
        cve_dicts += getattr(vuln, field, []) or []

    cves: List[str] = [
        f"{c['id']} ({c.get('description', '').strip()})"
        for c in cve_dicts
        if isinstance(c, dict) and c.get("id")
    ]

    payload = {
        "issues": getattr(vuln, "issues", []) or [],
        "cves": cves,
        "cvss": getattr(vuln, "cvss", "N/A"),
    }
    return NS(**payload)


def _ci_regex(network: str) -> Dict[str, Any]:
    """Case‑insensitive exact match on *network* or *target* field."""
    regex = {"$regex": f"^{re.escape(network)}$", "$options": "i"}
    return {"$or": [{"network": regex}, {"target": regex}]}


__all__: list[str] = ["build_network_prompt"]
