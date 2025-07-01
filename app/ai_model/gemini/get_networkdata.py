from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Any, Dict, List, Tuple, Union

from fastapi import HTTPException, status
from pydantic import BaseModel, Field, ValidationError, validator

# ── ODM models ─────────────────────────────────────────────────────────────
from app.api.models.information import NetworkInfoGathering
from app.api.models.vuln_assessment import NetworkVulnerabilityAssessmentModel
from app.api.models.vuln_exploiting import NetworkVulnerabilityExploitingModel
from app.api.models.ai_collection import AI_RISK_REPORT

__all__ = [
    "get_networktarget_data",
    "build_gemini_network_prompt",
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


class NetworkOperationalData(BaseModel):
    """Flat, validated structure consumed by the network prompt builder."""

    ip_address: str
    hostname: str = "unknown"
    
    open_ports: List[Dict[str, Any]] = Field(default_factory=list)
    services: List[Dict[str, Any]] = Field(default_factory=list)
    os_detection: Dict[str, Any] = Field(default_factory=dict)
    
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
    NetworkInfoGathering: ("target", "ip_address", "host"),
    NetworkVulnerabilityAssessmentModel: ("target", "ip_address", "host"),
    NetworkVulnerabilityExploitingModel: ("target", "ip_address", "host"),
    AI_RISK_REPORT: ("target", "ip_address", "host"),
}


async def _find_doc(model: Any, ip_address: str) -> Any | None:
    """Return the first document where any mapped field equals *ip_address*."""

    for field in _FIELD_MAP.get(model, ("target",)):
        if hasattr(model, field):
            doc = await model.find_one(getattr(model, field) == ip_address)
            if doc:
                return doc
    return None


def _extract_network_info_from_doc(info_doc: Any) -> Tuple[str, List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    """Extract network information from info document."""
    if not info_doc:
        return "unknown", [], [], {}
    
    hostname = getattr(info_doc, "hostname", "unknown") or "unknown"
    open_ports = []
    services = []
    os_detection = {}
    
    # Extract port scan results
    port_scan_data = getattr(info_doc, "port_scan_data", [])
    if isinstance(port_scan_data, list):
        for port_info in port_scan_data:
            if isinstance(port_info, dict):
                port = port_info.get("port")
                state = port_info.get("state", "unknown")
                protocol = port_info.get("protocol", "tcp")
                service = port_info.get("service", "unknown")
                version = port_info.get("version", "")
                
                if port and state == "open":
                    port_dict = {
                        "port": port,
                        "protocol": protocol,
                        "state": state,
                        "service": service,
                        "version": version
                    }
                    open_ports.append(port_dict)
                    
                    if service and service != "unknown":
                        service_dict = {
                            "port": port,
                            "service": service,
                            "version": version,
                            "protocol": protocol
                        }
                        services.append(service_dict)
    
    # Extract OS detection
    os_info = getattr(info_doc, "os_detection", {})
    if isinstance(os_info, dict):
        os_detection = os_info
    elif isinstance(os_info, list) and os_info:
        os_detection = os_info[0] if isinstance(os_info[0], dict) else {}
    
    return hostname, open_ports, services, os_detection


def _extract_vulnerabilities_from_assessment(vuln_doc: Any) -> Tuple[List[str], float, List[str]]:
    """Extract vulnerabilities, CVSS, and CVEs from network vulnerability assessment."""
    if not vuln_doc:
        return [], 0.0, []
    
    issues = []
    max_cvss = 0.0
    cves = []
    
    # Extract from service vulnerabilities
    service_vulns = getattr(vuln_doc, "service_vulnerabilities", [])
    if isinstance(service_vulns, list):
        for vuln in service_vulns:
            if isinstance(vuln, dict):
                port = vuln.get("port")
                service = vuln.get("service", "unknown")
                vulnerability = vuln.get("vulnerability", "")
                severity = vuln.get("severity", "")
                
                if vulnerability:
                    issue_desc = f"Port {port}/{service}: {vulnerability}"
                    if severity:
                        issue_desc += f" (Severity: {severity})"
                    issues.append(issue_desc)
    
    # Extract from CVE data
    cve_data = getattr(vuln_doc, "cve_data", [])
    if isinstance(cve_data, list):
        for cve_info in cve_data:
            if isinstance(cve_info, dict):
                cve_id = cve_info.get("cve_id")
                if cve_id:
                    cves.append(cve_id)
                    
                cvss_score = cve_info.get("cvss_score", 0)
                if isinstance(cvss_score, (int, float)):
                    max_cvss = max(max_cvss, float(cvss_score))
                    
                description = cve_info.get("description", "")
                if description:
                    issues.append(f"CVE {cve_id}: {description}")
    
    # Extract from SSL/TLS vulnerabilities
    ssl_vulns = getattr(vuln_doc, "ssl_vulnerabilities", [])
    if isinstance(ssl_vulns, list):
        for ssl_vuln in ssl_vulns:
            if isinstance(ssl_vuln, dict):
                port = ssl_vuln.get("port")
                vulnerability = ssl_vuln.get("vulnerability", "")
                severity = ssl_vuln.get("severity", "medium")
                
                if vulnerability:
                    issues.append(f"SSL/TLS Port {port}: {vulnerability}")
                    if severity.lower() == "high":
                        max_cvss = max(max_cvss, 7.0)
                    elif severity.lower() == "medium":
                        max_cvss = max(max_cvss, 4.0)
    
    return issues, max_cvss, cves


def _extract_exploitation_data(exploit_doc: Any) -> Tuple[List[str], bool, List[str]]:
    """Extract exploitation data from network exploiting document."""
    if not exploit_doc:
        return [], False, []
    
    exploits = []
    exploit_success = False
    exploit_evidence = []
    
    # Extract service exploitation attempts
    service_exploits = getattr(exploit_doc, "service_exploits", [])
    if isinstance(service_exploits, list):
        for exploit in service_exploits:
            if isinstance(exploit, dict):
                port = exploit.get("port")
                service = exploit.get("service", "unknown")
                exploit_type = exploit.get("exploit_type", "")
                success = exploit.get("success", False)
                payload = exploit.get("payload", "")
                response = exploit.get("response", "")
                
                if success:
                    exploit_success = True
                    exploit_desc = f"Service Exploitation - {service} on port {port}"
                    if exploit_type:
                        exploit_desc += f" ({exploit_type})"
                    exploits.append(exploit_desc)
                    
                    if payload:
                        exploit_evidence.append(f"Payload used: {payload}")
                    if response:
                        exploit_evidence.append(f"Response: {response[:100]}...")
    
    # Extract brute force attacks
    brute_force_data = getattr(exploit_doc, "brute_force_data", [])
    if isinstance(brute_force_data, list):
        for bf_attack in brute_force_data:
            if isinstance(bf_attack, dict):
                port = bf_attack.get("port")
                service = bf_attack.get("service", "unknown")
                success = bf_attack.get("success", False)
                credentials = bf_attack.get("credentials", {})
                
                if success:
                    exploit_success = True
                    exploit_desc = f"Brute Force - {service} on port {port}"
                    exploits.append(exploit_desc)
                    
                    username = credentials.get("username", "")
                    password = credentials.get("password", "")
                    if username and password:
                        exploit_evidence.append(f"Credentials found: {username}:{password}")
    
    # Extract other network exploits
    network_exploits = getattr(exploit_doc, "network_exploits", [])
    if isinstance(network_exploits, list):
        for exploit in network_exploits:
            if isinstance(exploit, dict):
                exploit_type = exploit.get("type", "")
                success = exploit.get("success", False)
                description = exploit.get("description", "")
                evidence = exploit.get("evidence", "")
                
                if success:
                    exploit_success = True
                    exploit_desc = f"Network Exploit - {exploit_type}"
                    if description:
                        exploit_desc += f": {description}"
                    exploits.append(exploit_desc)
                    
                    if evidence:
                        exploit_evidence.append(evidence)
    
    return exploits, exploit_success, exploit_evidence


# ═══════════════════════════════════════
# 3 ▸ Aggregation API
# ═══════════════════════════════════════

def _severity(cvss: float, cfg: PromptConfig) -> str:
    for rng, sev in cfg.severity_map.items():
        lo, hi = map(float, rng.split("-"))
        if lo <= cvss <= hi:
            return sev
    return "Unknown"


async def get_networktarget_data(ip_address: str) -> Dict[str, Any]:
    """Return `{operational, risk_ai, meta}` or raise 404 if IP address is unknown."""

    info, vuln, explo, risk = await asyncio.gather(
        _find_doc(NetworkInfoGathering, ip_address),
        _find_doc(NetworkVulnerabilityAssessmentModel, ip_address),
        _find_doc(NetworkVulnerabilityExploitingModel, ip_address),
        _find_doc(AI_RISK_REPORT, ip_address),
    )

    if not any([info, vuln, explo, risk]):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="IP address not found")

    # Extract data using the helper functions
    hostname, open_ports, services, os_detection = _extract_network_info_from_doc(info)
    issues, cvss_score, cves = _extract_vulnerabilities_from_assessment(vuln)
    exploits, exploit_success, exploit_evidence = _extract_exploitation_data(explo)

    op_raw = {
        "ip_address": ip_address,
        "hostname": hostname,
        "open_ports": open_ports,
        "services": services,
        "os_detection": os_detection,
        "issues": issues,
        "cvss": cvss_score,
        "cves": cves,
        "remediation": [],  # You can add remediation extraction logic here if needed
        "exploits": exploits,
        "exploit_success": exploit_success,
        "exploit_evidence": exploit_evidence,
    }
    
    logger.debug(f"op_raw for {ip_address}: {op_raw}")

    try:
        operational = NetworkOperationalData(**op_raw)
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


def build_gemini_network_prompt(
    operational: Union[Dict[str, Any], "NetworkOperationalData"],
    cfg: "PromptConfig" | None = None,
    risk_ai_data: Dict[str, Any] | None = None,
) -> str:
    """
    Generate a professional network security report prompt that produces clean,
    properly formatted markdown without formatting issues.
    """
    cfg = cfg or PromptConfig()
    op: Dict[str, Any] = (
        operational.dict() if isinstance(operational, NetworkOperationalData) else operational
    )

    # ── Report metadata ─────────────────────────────────────────
    report_date = datetime.utcnow().strftime("%B %d, %Y")
    report_id = f"NSR-{datetime.utcnow().strftime('%Y%m%d')}-{op['ip_address'].replace('.', '')[:8].upper()}"
    
    # ── Clean technical data formatting ──────────────────────────
    tech_summary = _create_clean_network_summary(op, risk_ai_data)
    
    # ── Professional instruction prompt ──────────────────────────
    professional_prompt = f"""You are a Senior Network Security Consultant creating an enterprise-grade network security assessment report.

CRITICAL FORMATTING REQUIREMENTS:
- Use ONLY proper markdown syntax
- NO literal \\n characters in output
- NO escaped characters or formatting artifacts
- Clean, readable professional formatting
- Proper spacing and line breaks

TARGET INFORMATION:
- IP Address: {op['ip_address']}
- Hostname: {op['hostname']}
- Report ID: {report_id}
- Assessment Date: {report_date}
- Overall Risk Score: {op['cvss']} ({_severity(op['cvss'], cfg)})
- OS Detection: {op.get('os_detection', {}).get('name', 'Unknown')}

TECHNICAL DATA TO USE:
{tech_summary}

CREATE A PROFESSIONAL REPORT FOLLOWING THIS EXACT STRUCTURE:

# Network Security Assessment Report

## Report Information
| Field | Value |
|-------|-------|
| Target IP Address | {op['ip_address']} |
| Hostname | {op['hostname']} |
| Report ID | {report_id} |
| Assessment Date | {report_date} |
| Prepared By | CyberGuard Network Security Team |
| Classification | CONFIDENTIAL |

---

## Executive Summary

Write a 150-word executive summary covering:
- Network security posture assessment
- Attack surface analysis
- Number of vulnerabilities by severity
- Key business risks identified
- Priority recommendations

## Assessment Overview

### Scope
Detail what network segments and services were tested.

### Methodology
Our assessment followed:
- NIST Cybersecurity Framework
- OWASP Network Security Testing Guide
- Industry penetration testing standards

### Tools & Timeline
List primary tools (Nmap, Metasploit, custom scripts) and assessment duration.

## Network Infrastructure Analysis

### Host Information
Present discovered host information in a clean table format.

### Service Discovery
Analyze open ports and running services.

### Operating System Detection
Detail OS fingerprinting results.

## Risk Assessment Summary

### Overall Risk Rating
Provide clear risk rating with justification.

### Vulnerability Summary
| Severity | Count | CVSS Range | Priority |
|----------|--------|------------|----------|
| Critical | X | 9.0-10.0 | Immediate |
| High | X | 7.0-8.9 | Urgent |
| Medium | X | 4.0-6.9 | Important |
| Low | X | 0.1-3.9 | Monitor |

## Detailed Findings

For each vulnerability found, create a section like this:

### Finding X: [Vulnerability Name]

**Severity:** [Level] | **CVSS:** [Score] | **Port:** [Port/Service]

**Description:**
Clear technical description of the vulnerability.

**Business Impact:**
Explain real-world consequences.

**Technical Evidence:**
```
Include relevant technical proof
```

**Remediation:**
1. Immediate actions required
2. Long-term solutions needed

## Exploitation Summary

Detail any successful exploits and their impact.

### Compromised Services
If any services were successfully exploited, detail:
- Attack vector used
- Level of access gained
- Data or systems compromised
- Evidence obtained

## Remediation Roadmap

### Immediate Actions (0-30 days)
List critical fixes for high-risk vulnerabilities.

### Short-term Actions (30-90 days)
List important security improvements.

### Long-term Improvements (90+ days)
List strategic network security enhancements.

## Security Architecture Recommendations

### Network Segmentation
Recommend improved network isolation strategies.

### Access Controls
Suggest authentication and authorization improvements.

### Monitoring & Detection
Recommend network monitoring and intrusion detection systems.

## Conclusion

Summarize key findings and strategic recommendations for network security improvement.

## Appendices

### Technical Details
Additional technical information and command outputs.

### CVE References
List all identified CVEs with descriptions.

### Network Diagrams
Include relevant network topology information.

---

FORMATTING RULES YOU MUST FOLLOW:
1. Use proper markdown headers (# ## ###)
2. Create clean tables with proper alignment
3. Use code blocks with language tags when appropriate
4. NO literal \\n characters - use proper line breaks
5. Keep consistent spacing throughout
6. Use bullet points and numbered lists appropriately
7. Include severity badges using text (Critical, High, Medium, Low)
8. Make all content professional and readable

Base ALL content on the technical data provided. Do NOT invent information.
If data is missing, state "Information not available in current assessment."

Create a clean, professional report that executives and technical teams can both understand and act upon."""

    logger.debug(f"Clean professional network prompt generated for {op['ip_address']}")
    return professional_prompt


def _create_clean_network_summary(op: Dict[str, Any], risk_ai_data: Dict[str, Any] = None) -> str:
    """Create a clean, formatted network technical summary without formatting artifacts."""
    
    summary_parts = []
    
    # Open Ports
    if op.get('open_ports'):
        port_count = len(op['open_ports'])
        port_list = ", ".join([f"{p['port']}/{p['protocol']}" for p in op['open_ports'][:10]])
        summary_parts.append(f"Open Ports: {port_count} ports detected")
        summary_parts.append(f"  Ports: {port_list}")
    
    # Services
    if op.get('services'):
        service_count = len(op['services'])
        summary_parts.append(f"Services Detected: {service_count} services identified")
        for service in op['services'][:5]:
            port = service.get('port', 'N/A')
            name = service.get('service', 'Unknown')
            version = service.get('version', '')
            summary_parts.append(f"  - Port {port}: {name} {version}".strip())
    
    # OS Detection
    if op.get('os_detection'):
        os_info = op['os_detection']
        os_name = os_info.get('name', 'Unknown')
        os_version = os_info.get('version', '')
        summary_parts.append(f"Operating System: {os_name} {os_version}".strip())
    
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
    
    # AI Risk Data
    if risk_ai_data:
        summary_parts.append("AI Risk Assessment: Additional risk data available")
    
    return "\n".join(summary_parts)


# Alternative simplified prompt for better results
def build_simple_network_prompt(
    operational: Union[Dict[str, Any], "NetworkOperationalData"],
    cfg: "PromptConfig" | None = None,
    risk_ai_data: Dict[str, Any] | None = None,
) -> str:
    """
    Simplified version that focuses on clean output without complex formatting.
    """
    cfg = cfg or PromptConfig()
    op: Dict[str, Any] = (
        operational.dict() if isinstance(operational, NetworkOperationalData) else operational
    )

    # Simple, clean data presentation
    vuln_summary = ""
    if op.get('issues'):
        vuln_summary = f"Found {len(op['issues'])} vulnerabilities"
    
    exploit_summary = ""
    if op.get('exploits'):
        exploit_summary = f"Successfully exploited {len(op['exploits'])} services"

    services_list = ""
    if op.get('services'):
        services_list = ', '.join([f"{s.get('service', 'Unknown')} ({s.get('port', 'N/A')})" 
                                  for s in op['services'][:5]])

    return f"""Create a professional network security report in clean markdown format.

STRICT FORMATTING REQUIREMENTS:
- Use proper markdown syntax only
- No escaped characters or \\n literals
- Clean tables and headers
- Professional business language

REPORT DATA:
IP Address: {op['ip_address']}
Hostname: {op['hostname']}
CVSS Score: {op['cvss']} ({_severity(op['cvss'], cfg)} severity)
Operating System: {op.get('os_detection', {}).get('name', 'Unknown')}
Open Ports: {len(op.get('open_ports', []))} ports
Services: {services_list or 'None identified'}
{vuln_summary}
{exploit_summary}

Vulnerabilities Found:
{_format_network_vuln_list(op.get('issues', []))}

CVEs: {', '.join(op.get('cves', ['None']))}

Exploits: {_format_network_exploit_list(op.get('exploits', []))}

Open Ports and Services:
{_format_port_service_list(op.get('open_ports', []), op.get('services', []))}

Create a report with these sections:
1. Executive Summary (150 words max)
2. Network Infrastructure Overview
3. Risk Assessment  
4. Key Findings (one section per major vulnerability)
5. Exploitation Results
6. Remediation Plan
7. Conclusion

Use professional language appropriate for executives and technical staff.
Base everything on the data provided above - do not invent details.
Format cleanly in markdown without any formatting artifacts."""


def _format_network_vuln_list(issues: List[str]) -> str:
    """Format network vulnerability list cleanly."""
    if not issues:
        return "No vulnerabilities identified"
    
    formatted = []
    for i, issue in enumerate(issues[:10], 1):
        # Clean up the issue text
        clean_issue = issue.replace('\n', ' ').strip()
        formatted.append(f"{i}. {clean_issue}")
    
    if len(issues) > 10:
        formatted.append(f"... and {len(issues) - 10} additional issues")
    
    return "\n".join(formatted)


def _format_network_exploit_list(exploits: List[str]) -> str:
    """Format network exploit list cleanly."""
    if not exploits:
        return "No successful exploits"
    
    formatted = []
    for exploit in exploits[:5]:
        clean_exploit = exploit.replace('\n', ' ').strip()
        formatted.append(f"- {clean_exploit}")
    
    return "\n".join(formatted)


def _format_port_service_list(open_ports: List[Dict[str, Any]], services: List[Dict[str, Any]]) -> str:
    """Format port and service information cleanly."""
    if not open_ports:
        return "No open ports detected"
    
    formatted = []
    for port_info in open_ports[:10]:
        port = port_info.get('port', 'N/A')
        protocol = port_info.get('protocol', 'tcp')
        service = port_info.get('service', 'unknown')
        version = port_info.get('version', '')
        
        port_desc = f"Port {port}/{protocol}"
        if service != 'unknown':
            port_desc += f" - {service}"
            if version:
                port_desc += f" {version}"
        
        formatted.append(f"- {port_desc}")
    
    if len(open_ports) > 10:
        formatted.append(f"... and {len(open_ports) - 10} additional ports")
    
    return "\n".join(formatted)