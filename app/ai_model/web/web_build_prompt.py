from __future__ import annotations

import asyncio
import logging
import re
from types import SimpleNamespace as NS
from typing import Any, Dict, List, Optional, Tuple

from app.api.models.information import WebInfoGatheringModel
from app.api.models.vuln_assessment import WebVulnerabilityAssessmentModel
from app.ai_model.web.build_web_prompt_from_docs import build_prompt_from_docs

logger = logging.getLogger(__name__)

async def build_web_prompt(domain: str) -> str:  # noqa: D401
    """Return a fully‑formed prompt for *domain* ready for the LLM."""

    info_doc, vuln_doc = await _fetch_latest_docs(domain)
    if not info_doc or not vuln_doc:
        raise ValueError(f"Docs not found for domain '{domain}'")

    prompt = build_prompt_from_docs(
        _filter_info(info_doc),
        _filter_vuln(vuln_doc),
    )
    logger.debug("[PROMPT for %s]\n%s", domain, prompt)
    return prompt

async def _fetch_latest_docs(
    domain: str,
) -> Tuple[
    Optional[WebInfoGatheringModel],
    Optional[WebVulnerabilityAssessmentModel],
]:
    """Fetch newest info & vuln docs concurrently (case‑insensitive)."""

    ci = _ci_regex(domain)

    # always exists fallback to _id if timestamp absent
    info_q = WebInfoGatheringModel.find_one(ci, sort=[("timestamp", -1)])
    vuln_q = WebVulnerabilityAssessmentModel.find_one(ci, sort=[("timestamp", -1)])

    return await asyncio.gather(info_q, vuln_q)


def _filter_info(info: WebInfoGatheringModel) -> NS:
    """Squash WebInfoGatheringModel → SimpleNamespace expected by builder."""

    headers: Dict[str, str] = {}
    for h in info.https_headers or []:
        if isinstance(h, dict):
            headers[h.get("header", "unknown")] = h.get("status", "")

    payload: Dict[str, Any] = {
        "subdomain": info.target,
        "status_code": getattr(info, "status_code", "N/A"),
        "waf": "Detected" if info.waf_detections else "Not Detected",
        "parameters": ", ".join(getattr(info, "parameters", [])) or "N/A",
        "headers": headers,
    }
    return NS(**payload)


def _filter_vuln(vuln: WebVulnerabilityAssessmentModel) -> NS:
    """Squash WebVulnerabilityAssessmentModel → SimpleNamespace."""

    hdrs: Dict[str, str] = {}
    issues: List[str] = []

    for chunk in vuln.https_headers_data or []:
        for h in chunk:
            if not isinstance(h, dict):
                continue
            hdrs[h.get("header", "unknown")] = h.get("status", "")
            if desc := h.get("description"):
                issues.append(desc)

    cves = [
        f"{c['id']} ({c.get('description', '')})"
        for c in (vuln.server_cve_data or []) + (vuln.service_cve_data or [])
        if isinstance(c, dict) and c.get("id")
    ]

    payload: Dict[str, Any] = {
        "headers": hdrs,
        "issues": list(dict.fromkeys(issues)),  # dedupe keep‑order
        "cves": cves,
                "bypass_payloads": getattr(vuln, "bypass_payloads", [
            "filter=' OR '1'='1",
            "filter=admin'--",
            "filter=%27%20OR%201%3D1--",
        ]),
    }
    return NS(**payload)


def _ci_regex(domain: str) -> Dict[str, Any]:
    """Case‑insensitive exact match on target *or* subdomain."""
    regex = {"$regex": f"^{re.escape(domain)}$", "$options": "i"}
    return {"$or": [{"target": regex}, {"subdomain": regex}]}


__all__: list[str] = ["build_web_prompt"]