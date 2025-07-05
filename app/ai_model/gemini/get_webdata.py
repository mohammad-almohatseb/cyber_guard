from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Any, Dict, List, Tuple,Union
from textwrap import dedent

from fastapi import HTTPException, status
from pydantic import BaseModel, Field, ValidationError, validator
# ── ODM models ─────────────────────────────────────────────────────────────
from app.api.models.ai_collection import AiCollection
from app.api.models.information import WebInfoGatheringModel
from app.api.models.vuln_assessment import WebVulnerabilityAssessmentModel
from app.api.models.vuln_exploiting import WebVulnerabilityExploitingModel

__all__ = [
    "get_webtarget_data",
    "build_gemini_web_prompt",
    "PromptConfig",
]

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════
# 1 ▸ Config / Schemas
# ═══════════════════════════════════════

class PromptConfig(BaseModel):
    """Runtime knobs for prompt generation."""

    executive_summary_words: int = 200
    include_raw_block: bool = False
    severity_map: Dict[str, str] = {
        "0.0-3.9": "Low",
        "4.0-6.9": "Medium",
        "7.0-8.9": "High",
        "9.0-10.0": "Critical",
    }
    extra_sections: List[str] = []

    @validator("extra_sections", pre=True, always=True)
    def _ensure_list(cls, v):  # noqa: N805
        return v or []


class OperationalData(BaseModel):
    """Flat, validated structure consumed by the prompt builder."""

    domain: str
    waf: str = "unknown"

    technologies: List[str] = Field(default_factory=list)
    headers: Dict[str, str] = Field(default_factory=dict)

    issues: List[str] = Field(default_factory=list)
    cvss: float = 0.0
    cves: List[str] = Field(default_factory=list)
    remediation: List[str] = Field(default_factory=list)

    exploits: List[str] = Field(default_factory=list)
    exploit_success: bool = False
    exploit_evidence: List[str] = Field(default_factory=list)

    collected_at: datetime = Field(default_factory=datetime.utcnow)


# ═══════════════════════════════════════
# 2 ▸ DB helpers
# ═══════════════════════════════════════

_FIELD_MAP: Dict[Any, Tuple[str, ...]] = {
    WebInfoGatheringModel: ("target", "domain", "host", "url"),
    WebVulnerabilityAssessmentModel: ("target", "domain", "host"),
    WebVulnerabilityExploitingModel: ("target", "domain", "host"),
    AiCollection: ("target", "domain", "host"),
}


async def _find_doc(model: Any, domain: str) -> Any | None:
    """Return the first document where any mapped field equals *domain*."""

    for field in _FIELD_MAP.get(model, ("target",)):
        if hasattr(model, field):
            doc = await model.find_one(getattr(model, field) == domain)
            if doc:
                return doc
    return None


def _extract_technologies_from_info(info_doc: Any) -> List[str]:
    """Extract technologies from server_info in info document."""
    if not info_doc:
        return []
    
    technologies = []
    
    # Extract from server_info
    server_info = getattr(info_doc, "server_info", [])
    if isinstance(server_info, list):
        for server in server_info:
            if isinstance(server, dict):
                server_name = server.get("server")
                if server_name and server_name != "Unknown":
                    technologies.append(server_name)
                    
                os_name = server.get("os")
                if os_name and os_name != "Unknown":
                    technologies.append(os_name)
    
    return list(set(technologies))  # Remove duplicates


def _extract_headers_from_info(info_doc: Any) -> Dict[str, str]:
    """Extract headers from https_headers in info document."""
    if not info_doc:
        return {}
    
    headers = {}
    
    # Extract from https_headers
    https_headers = getattr(info_doc, "https_headers", [])
    if isinstance(https_headers, list):
        for header_info in https_headers:
            if isinstance(header_info, dict):
                observed_headers = header_info.get("observed_headers")
                if observed_headers and isinstance(observed_headers, dict):
                    headers.update(observed_headers)
                    
                security_headers = header_info.get("security_headers")
                if security_headers and isinstance(security_headers, dict):
                    headers.update(security_headers)
    
    return headers


def _extract_waf_status(info_doc: Any) -> str:
    """Extract WAF status from waf_detections."""
    if not info_doc:
        return "unknown"
    
    waf_detections = getattr(info_doc, "waf_detections", [])
    if isinstance(waf_detections, list) and waf_detections:
        first_waf = waf_detections[0]
        if isinstance(first_waf, dict):
            has_waf = first_waf.get("has_waf", False)
            waf_name = first_waf.get("waf_name")
            
            if has_waf and waf_name:
                return waf_name
            elif has_waf:
                return "detected"
            else:
                return "none"
    
    return "unknown"


def _extract_vulnerabilities_from_assessment(vuln_doc: Any) -> Tuple[List[str], float, List[str]]:
    """Extract vulnerabilities, CVSS, and CVEs from vulnerability assessment."""
    if not vuln_doc:
        return [], 0.0, []
    
    issues = []
    max_cvss = 0.0
    cves = []
    
    # Extract from all_expected_vulns
    all_vulns = getattr(vuln_doc, "all_expected_vulns", {})
    if isinstance(all_vulns, dict):
        for vuln_type, vuln_list in all_vulns.items():
            if isinstance(vuln_list, list):
                for vuln in vuln_list:
                    if isinstance(vuln, dict):
                        url = vuln.get("url", "")
                        confidence = vuln.get("confidence", "")
                        evidence = vuln.get("evidence", "")
                        
                        issue_desc = f"{vuln_type}: {url}"
                        if confidence:
                            issue_desc += f" (Confidence: {confidence})"
                        if evidence:
                            issue_desc += f" - {evidence}"
                        
                        issues.append(issue_desc)
    
    # Extract from server_cve_data
    server_cves = getattr(vuln_doc, "server_cve_data", [])
    if isinstance(server_cves, list):
        for cve_info in server_cves:
            if isinstance(cve_info, dict):
                cve_id = cve_info.get("id")
                if cve_id:
                    cves.append(cve_id)
                    
                cvss_score = cve_info.get("cvss_score", 0)
                if isinstance(cvss_score, (int, float)):
                    max_cvss = max(max_cvss, float(cvss_score))
                    
                description = cve_info.get("description", "")
                if description:
                    issues.append(f"CVE {cve_id}: {description}")
    
    # Extract from https_headers_data (missing security headers)
    headers_data = getattr(vuln_doc, "https_headers_data", [])
    if isinstance(headers_data, list):
        for header_group in headers_data:
            if isinstance(header_group, list):
                for header_info in header_group:
                    if isinstance(header_info, dict):
                        header_name = header_info.get("header")
                        status = header_info.get("status")
                        description = header_info.get("description")
                        
                        if status == "missing" and header_name and description:
                            issues.append(f"Missing {header_name}: {description}")
    
    # Extract from certificate_data
    cert_data = getattr(vuln_doc, "certificate_data", [])
    if isinstance(cert_data, list):
        for cert_info in cert_data:
            if isinstance(cert_info, dict):
                has_tls = cert_info.get("has_tls", True)
                severity = cert_info.get("severity", "").lower()
                
                if not has_tls:
                    issues.append("TLS/SSL: No TLS certificate detected")
                    if severity == "high":
                        max_cvss = max(max_cvss, 7.0)  # High severity for no TLS
    
    return issues, max_cvss, cves


def _extract_exploitation_data(exploit_doc: Any) -> Tuple[List[str], bool, List[str]]:
    """Extract exploitation data from exploiting document."""
    if not exploit_doc:
        return [], False, []
    
    exploits = []
    exploit_success = False
    exploit_evidence = []
    
    # Extract SQL injection data
    sql_data = getattr(exploit_doc, "sql_injection_data", [])
    if isinstance(sql_data, list):
        for sql_result in sql_data:
            if isinstance(sql_result, dict):
                exploit_success = True
                db_name = sql_result.get("Database_name", "")
                uname = sql_result.get("Uname", "")
                email = sql_result.get("Email", "")
                
                exploit_desc = f"SQL Injection successful - Database: {db_name}"
                exploits.append(exploit_desc)
                exploit_evidence.append(f"Extracted data: Username={uname}, Email={email}")
    
    # Extract XSS data
    xss_data = getattr(exploit_doc, "xss_data", [])
    if isinstance(xss_data, list):
        for xss_result in xss_data:
            if isinstance(xss_result, dict):
                exploit_success = True
                payload = xss_result.get("payload", "")
                attack_type = xss_result.get("attack_type", "")
                url = xss_result.get("url_injected", "")
                
                exploit_desc = f"XSS ({attack_type}) - Payload: {payload[:50]}..."
                exploits.append(exploit_desc)
                exploit_evidence.append(f"Vulnerable URL: {url}")
    
    # Extract Path Traversal data
    path_data = getattr(exploit_doc, "path_traversal_data", [])
    if isinstance(path_data, list):
        for path_result in path_data:
            if isinstance(path_result, dict) and path_result.get("vulnerable", False):
                exploit_success = True
                payload = path_result.get("payload", "")
                url = path_result.get("url", "")
                pattern = path_result.get("pattern_matched", "")
                
                exploit_desc = f"Path Traversal - Payload: {payload}"
                exploits.append(exploit_desc)
                exploit_evidence.append(f"URL: {url}, Pattern matched: {pattern}")
    
    return exploits, exploit_success, exploit_evidence


# ═══════════════════════════════════════
# 3 ▸ Aggregation API
# ══════════════════════════════════════


async def get_webtarget_data(domain: str) -> Dict[str, Any]:
    """Return `{operational, risk_ai, meta}` or raise 404 if domain is unknown."""

    info, vuln, explo, risk = await asyncio.gather(
        _find_doc(WebInfoGatheringModel, domain),
        _find_doc(WebVulnerabilityAssessmentModel, domain),
        _find_doc(WebVulnerabilityExploitingModel, domain),
        _find_doc(AiCollection, domain),
    )

    if not any([info, vuln, explo, risk]):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Domain not found")

    # Extract data using the new helper functions
    waf_status = _extract_waf_status(info)
    technologies = _extract_technologies_from_info(info)
    headers = _extract_headers_from_info(info)
    
    issues, cvss_score, cves = _extract_vulnerabilities_from_assessment(vuln)
    exploits, exploit_success, exploit_evidence = _extract_exploitation_data(explo)

    op_raw = {
        "domain": domain,
        "waf": waf_status,
        "technologies": technologies,
        "headers": headers,
        "issues": issues,
        "cvss": cvss_score,
        "cves": cves,
        "remediation": [],  # You can add remediation extraction logic here if needed
        "exploits": exploits,
        "exploit_success": exploit_success,
        "exploit_evidence": exploit_evidence,
    }
    
    logger.debug(f"op_raw for {domain}: {op_raw}")

    try:
        operational = OperationalData(**op_raw)
    except ValidationError as err:
        logger.error("Operational validation failed: %s", err.errors())
        logger.error("Raw operational data: %s", op_raw)
        raise HTTPException(500, "Operational data invalid") from err

    return {
        "operational": operational.dict(),  # validated, JSON‑serialisable
        "risk_ai": risk.dict() if risk else None,  # Convert to dict, unfiltered
        "meta": {
            "retrieved": datetime.utcnow().isoformat(),
            "hits": {
                "info": bool(info),
                "vuln": bool(vuln),
                "exploit": bool(explo),
                "risk_ai": bool(risk),
            },
        },
    }

def _create_clean_tech_summary(op: Dict[str, Any], risk_ai_data: Dict[str, Any] = None) -> str:
    """Create a clean, formatted technical summary without formatting artifacts."""
    
    summary_parts = []
    
    # Technologies
    if op.get('technologies'):
        tech_list = ", ".join(op['technologies'][:10])
        summary_parts.append(f"Technologies Detected: {tech_list}")
    
    # Vulnerabilities  
    if op.get('issues'):
        vuln_count = len(op['issues'])
        summary_parts.append(f"Vulnerabilities Found: {vuln_count} issues identified")
        # Add first few vulnerabilities as examples
        for i, issue in enumerate(op['issues'][:5], 1):
            summary_parts.append(f"  {i}. {issue[:100]}...")
    
    # CVEs
    if op.get('cves'):
        cve_list = ", ".join(op['cves'][:5])
        summary_parts.append(f"CVEs Identified: {cve_list}")
    
    # Exploits
    if op.get('exploits'):
        exploit_count = len(op['exploits'])
        summary_parts.append(f"Successful Exploits: {exploit_count} confirmed")
        for exploit in op['exploits'][:3]:
            summary_parts.append(f"  - {exploit}")
    
    # Evidence
    if op.get('exploit_evidence'):
        summary_parts.append("Exploitation Evidence:")
        for evidence in op['exploit_evidence'][:3]:
            summary_parts.append(f"  - {evidence}")
    
    # Headers
    if op.get('headers'):
        header_count = len(op['headers'])
        summary_parts.append(f"HTTP Headers Analyzed: {header_count} headers reviewed")
    
    # AI Risk Data
    if risk_ai_data:
        summary_parts.append("AI Risk Assessment: Additional risk data available")
    
    return "\n".join(summary_parts)




def _severity(cvss: float, cfg: "PromptConfig") -> str:
    """Convert CVSS score to severity level."""
    if cvss >= 9.0:
        return "Critical"
    elif cvss >= 7.0:
        return "High"
    elif cvss >= 4.0:
        return "Medium"
    elif cvss > 0.0:
        return "Low"
    else:
        return "Informational"

def build_gemini_web_prompt(
    operational: Union[Dict[str, Any], "OperationalData"],
    cfg: "PromptConfig" | None = None,
    risk_ai_data: Dict[str, Any] | None = None,
) -> str:
    professional_prompt = """
Create a professional cybersecurity assessment report in HTML format. Follow these STRICT rules:

CRITICAL FORMATTING REQUIREMENTS:
1. Output ONLY HTML content - NO markdown, NO \\n characters, NO literal newlines
2. Use proper HTML structure with <p>, <div>, <br>, <ul>, <ol> tags
3. All styling must use inline Tailwind classes
4. Replace every placeholder with realistic content
5. Use professional cybersecurity terminology
6. I don't see /n in the output.
7. you should know your output will be rendered in a browser. without filtering 
8. I need a professional report, not a copy-paste from a blog post.
9. I need a professional design 
DESIGN REQUIREMENTS:
- Modern dark theme with proper contrast
- Professional typography and spacing
- Responsive tables and code blocks
- Clean, executive-level presentation

CONTENT STRUCTURE:
Generate a complete HTML report with these sections filled with detailed, realistic content:

the most important thing I don't want see /n in the output.
make the design professional.
please without /n in the output.

try to avoid "Bad value “\"en\"” for attribute “lang” on element “html”: The language subtag “\"en\"” is not a valid language subtag."
try to avoid "“"” in an unquoted attribute value. Probable causes: Attributes running together or a URL query string in an unquoted attribute value."
try to avoid Internal encoding declaration named an unsupported chararacter encoding “\"utf-8\"”.
try to avoid "Element “head” is missing a required instance of child element “title”."
you should avoid any error and issue 

prepared by CyberGuard Tool 
your Info the report just from the data I give you. 

"""



    return professional_prompt.strip()


