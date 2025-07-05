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
from app.api.models.ai_collection import AiCollection

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
    AiCollection: ("target", "ip_address", "host"),
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
        _find_doc(AiCollection, ip_address),
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



def build_gemini_network_prompt(
    operational: Union[Dict[str, Any], "NetworkOperationalData"],
    cfg: "PromptConfig" | None = None,
    risk_ai_data: Dict[str, Any] | None = None,
) -> str:
    """
    Generate an enterprise-grade **HTML** prompt for a network security assessment
    (was Markdown in the original version).
    """
    cfg = cfg or PromptConfig()
    op: Dict[str, Any] = (
        operational.dict() if isinstance(operational, NetworkOperationalData) else operational
    )

    # ─── Report metadata ────────────────────────────────────────────────────────
    report_date = datetime.utcnow().strftime("%B %d, %Y")
    report_id   = f"NSR-{datetime.utcnow().strftime('%Y%m%d')}-{op['ip_address'].replace('.', '')[:8].upper()}"

    # ─── Technical data (already HTML-clean) ────────────────────────────────────
    tech_summary = _create_clean_network_summary(op, risk_ai_data)

    # ─── Assemble prompt in HTML ────────────────────────────────────────────────
    professional_prompt = f"""
OUTPUT RULES – READ CAREFULLY
1. Reply with **ONLY** valid HTML for the report (no Markdown).
2. Do **NOT** wrap the HTML in back-ticks or code fences.
3. Do **NOT** add apologies, introductions, or closing remarks.
4. Start with <article class="cyberguard-report"> and end with </article>.
5. Write real line breaks, not JSON escapes (“\\n”).

DESIGN GUIDELINES
• Root wrapper: <article class="cyberguard-report prose prose-invert max-w-none"> … </article>.
• Headings: h1 → 3xl bold, h2 → 2xl semibold, h3 → xl semibold, each with top margin.
• Tables: class="min-w-full text-left border-collapse" + zebra rows (`odd:bg-slate-800`).
• Code blocks: <pre class="bg-slate-900 p-4 rounded-lg overflow-x-auto"><code>…</code></pre>.
• Use Tailwind utility classes freely for spacing and readability.

<!-- ————  BEGIN REPORT  ———— -->
<article class="cyberguard-report prose prose-invert max-w-none">

<h1 class="text-3xl font-bold">Network Security Assessment Report</h1>

<h2 class="mt-8 text-2xl font-semibold">Report Information</h2>
<table class="min-w-full text-left border-collapse">
  <thead>
    <tr><th>Field</th><th>Value</th></tr>
  </thead>
  <tbody>
    <tr class="odd:bg-slate-800"><td>Target IP Address</td><td>{op['ip_address']}</td></tr>
    <tr class="odd:bg-slate-800"><td>Hostname</td><td>{op['hostname']}</td></tr>
    <tr class="odd:bg-slate-800"><td>Report&nbsp;ID</td><td>{report_id}</td></tr>
    <tr class="odd:bg-slate-800"><td>Assessment Date</td><td>{report_date}</td></tr>
    <tr class="odd:bg-slate-800"><td>Prepared&nbsp;By</td><td>CyberGuard&nbsp;Network&nbsp;Security&nbsp;Team</td></tr>
    <tr class="odd:bg-slate-800"><td>Classification</td><td>CONFIDENTIAL</td></tr>
  </tbody>
</table>

<hr/>

<h2 class="mt-8 text-2xl font-semibold">Executive Summary</h2>
<p><em>≈ 150 words covering:</em></p>
<ul>
  <li>Network security posture assessment</li>
  <li>Attack surface analysis</li>
  <li>Number of vulnerabilities by severity</li>
  <li>Key business risks identified</li>
  <li>Priority recommendations</li>
</ul>

<h2 class="mt-8 text-2xl font-semibold">Assessment Overview</h2>

<h3 class="mt-6 text-xl font-semibold">Scope</h3>
<p>Detail what network segments and services were tested.</p>

<h3 class="mt-6 text-xl font-semibold">Methodology</h3>
<p>Our assessment followed:</p>
<ul>
  <li>NIST Cybersecurity Framework</li>
  <li>OWASP Network Security Testing Guide</li>
  <li>Industry penetration testing standards</li>
</ul>

<h3 class="mt-6 text-xl font-semibold">Tools &amp; Timeline</h3>
<p>List primary tools (Nmap, Metasploit, custom scripts) and assessment duration.</p>

<h2 class="mt-8 text-2xl font-semibold">Network Infrastructure Analysis</h2>
<h3 class="mt-6 text-xl font-semibold">Host Information</h3>
<p>Present discovered host information in a clean table.</p>

<h3 class="mt-6 text-xl font-semibold">Service Discovery</h3>
<p>Analyze open ports and running services.</p>

<h3 class="mt-6 text-xl font-semibold">Operating System Detection</h3>
<p>Detail OS fingerprinting results.</p>

<h2 class="mt-8 text-2xl font-semibold">Risk Assessment Summary</h2>
<h3 class="mt-6 text-xl font-semibold">Overall Risk Rating</h3>
<p>Provide clear risk rating with justification.</p>

<h3 class="mt-6 text-xl font-semibold">Vulnerability Summary</h3>
<table class="min-w-full text-left border-collapse">
  <thead>
    <tr>
      <th>Severity</th><th>Count</th><th>CVSS Range</th><th>Priority</th>
    </tr>
  </thead>
  <tbody>
    <tr class="odd:bg-slate-800"><td>Critical</td><td>X</td><td>9.0-10.0</td><td>Immediate</td></tr>
    <tr class="odd:bg-slate-800"><td>High</td><td>X</td><td>7.0-8.9</td><td>Urgent</td></tr>
    <tr class="odd:bg-slate-800"><td>Medium</td><td>X</td><td>4.0-6.9</td><td>Important</td></tr>
    <tr class="odd:bg-slate-800"><td>Low</td><td>X</td><td>0.1-3.9</td><td>Monitor</td></tr>
  </tbody>
</table>

<h2 class="mt-8 text-2xl font-semibold">Detailed Findings</h2>
<p>For each vulnerability, create a section like this:</p>

<h3 class="mt-6 text-xl font-semibold">Finding X: <span class="vuln-name">[Vulnerability&nbsp;Name]</span></h3>
<p><strong>Severity:</strong> [Level] | <strong>CVSS:</strong> [Score] | <strong>Port:</strong> [Port/Service]</p>

<p><strong>Description:</strong> Clear technical description of the vulnerability.</p>
<p><strong>Business Impact:</strong> Explain real-world consequences.</p>

<p><strong>Technical Evidence:</strong></p>
<pre class="bg-slate-900 p-4 rounded-lg overflow-x-auto"><code><!-- evidence --></code></pre>

<p><strong>Remediation:</strong></p>
<ol>
  <li>Immediate actions required</li>
  <li>Long-term solutions needed</li>
</ol>

<h2 class="mt-8 text-2xl font-semibold">Exploitation Summary</h2>
<p>Detail any successful exploits and their impact.</p>

<h3 class="mt-6 text-xl font-semibold">Compromised Services</h3>
<ul>
  <li>Attack vector used</li>
  <li>Level of access gained</li>
  <li>Data or systems compromised</li>
  <li>Evidence obtained</li>
</ul>

<h2 class="mt-8 text-2xl font-semibold">Remediation Roadmap</h2>

<h3 class="mt-6 text-xl font-semibold">Immediate (0-30 days)</h3>
<p>List critical fixes for high-risk vulnerabilities.</p>

<h3 class="mt-6 text-xl font-semibold">Short-term (30-90 days)</h3>
<p>List important security improvements.</p>

<h3 class="mt-6 text-xl font-semibold">Long-term (90+ days)</h3>
<p>List strategic network security enhancements.</p>

<h2 class="mt-8 text-2xl font-semibold">Security Architecture Recommendations</h2>
<h3 class="mt-6 text-xl font-semibold">Network Segmentation</h3>
<p>Recommend improved network isolation strategies.</p>

<h3 class="mt-6 text-xl font-semibold">Access Controls</h3>
<p>Suggest authentication and authorization improvements.</p>

<h3 class="mt-6 text-xl font-semibold">Monitoring &amp; Detection</h3>
<p>Recommend network monitoring and intrusion detection systems.</p>

<h2 class="mt-8 text-2xl font-semibold">Conclusion</h2>
<p>Summarize key findings and strategic recommendations for network security improvement.</p>

<h2 class="mt-8 text-2xl font-semibold">Appendices</h2>
<h3 class="mt-6 text-xl font-semibold">Technical Details</h3>
<p>Additional technical information and command outputs.</p>

<h3 class="mt-6 text-xl font-semibold">CVE References</h3>
<p>List all identified CVEs with descriptions.</p>

<h3 class="mt-6 text-xl font-semibold">Network Diagrams</h3>
<p>Include relevant network topology information.</p>

<hr/>

<!-- Injected technical data summary -->
{tech_summary}

</article>
<!-- ————  END REPORT  ———— -->
"""


    return professional_prompt.strip()



