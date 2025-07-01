from textwrap import dedent
from typing import Dict, List, Any
import json

__all__ = ["build_prompt_from_docs"]

# ──────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────

def _clean_string(s: Any, max_len: int = 100) -> str:
    """Clean and truncate a string for safe JSON output."""
    if not s:
        return "N/A"

    clean = str(s).strip()
    clean = clean.replace("\n", " ").replace("\r", " ").replace("\t", " ")
    clean = " ".join(clean.split())
    return clean[:max_len] if len(clean) > max_len else clean


def _safe_list(items: List[str] | None, max_items: int = 5, item_max_len: int = 80) -> List[str]:
    """Return a cleaned, length‑limited list."""
    if not items:
        return []

    result: List[str] = []
    for item in items[:max_items]:
        c = _clean_string(item, item_max_len)
        if c and c != "N/A":
            result.append(c)
    return result


# ──────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────

def build_prompt_from_docs(info_doc: Any, vuln_doc: Any) -> str:  # noqa: D401
    """Create a network‑focused prompt suitable for LLM JSON output."""

    # Extract + clean **info** fields
    network = _clean_string(getattr(info_doc, "network", getattr(info_doc, "target", "")), 50)
    os_name = _clean_string(getattr(info_doc, "os", ""), 50)
    firewall = _clean_string(getattr(info_doc, "firewall_detected", ""), 10)
    fw_desc = _clean_string(getattr(info_doc, "firewall_desc", ""), 100)
    services = _safe_list(getattr(info_doc, "services", None), max_items=6, item_max_len=20)

    # Extract + clean **vuln** fields
    issues = _safe_list(getattr(vuln_doc, "issues", None))
    cves = _safe_list(getattr(vuln_doc, "cves", None))
    cvss = _clean_string(getattr(vuln_doc, "cvss", ""), 10)

    # Compose prompt
    prompt = dedent(
        f"""
        You are a network‑security analyst. Create a JSON risk assessment report.

        INPUT DATA:
        - Network: {network or 'unknown'}
        - OS: {os_name or 'unknown'}
        - Services: {', '.join(services) or 'unknown'}
        - Firewall Present: {firewall or 'unknown'}
        - Firewall Desc: {fw_desc or 'N/A'}
        - Issues: {len(issues)} identified
        - CVEs: {len(cves)} related
        - CVSS: {cvss or 'N/A'}

        REQUIREMENTS:
        1. Output **valid JSON** only—no markdown, no code fences.
        2. Use exactly the structure in the example below.
        3. Keep every string value ≤ 100 characters.
        4. Finish the output with the literal token JSON_END on its own line.

        EXAMPLE:
        {{
          "risk_score": 6.5,
          "priority_level": "Medium",
          "critical_hosts": [{{
            "ip": "10.10.64.0/24",
            "risk_score": 6.5,
            "issues": [
              "No known CVEs detected.",
              "CIS Control 12: No firewall detected, network vulnerable to unauthorized access and attacks.",
              "ISO 27001 A.13.1.1: Lack of perimeter defense increases risk of lateral movement and data breach.",
              "OWASP Network Security: Missing firewall protection exposes network to reconnaissance and exploitation."
            ]
          }}],
          "summary": {{
            "total_hosts": 94,
            "high_risk_hosts": 12,
            "recommendation": "Patch all identified CVEs immediately. Deploy or enhance firewall with strict ingress/egress rules following CIS Control 12. Implement network segmentation and zero‑trust models per ISO 27001 A.13.1.1. Conduct regular vulnerability scanning and penetration testing. Enable continuous network monitoring and incident response capabilities."
          }}
        }}
        JSON_END

        Based on the INPUT DATA above, generate your JSON report:
        """
    ).strip()

    return prompt
