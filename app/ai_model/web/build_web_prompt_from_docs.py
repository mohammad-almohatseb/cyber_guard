from textwrap import dedent
from typing import Dict, List, Any
import json

__all__ = ["build_prompt_from_docs"]

def _clean_string(s: Any, max_len: int = 100) -> str:
    """Clean and truncate string for safe JSON output."""
    if not s:
        return "N/A"
    
    # Convert to string and clean
    clean = str(s).strip()
    # Remove problematic characters
    clean = clean.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ')
    # Remove extra spaces
    clean = ' '.join(clean.split())
    # Truncate
    return clean[:max_len] if len(clean) > max_len else clean

def _safe_headers(headers: Dict[str, str] | None, max_headers: int = 5) -> Dict[str, str]:
    """Return a clean, limited headers dict."""
    if not headers:
        return {}
    
    result = {}
    count = 0
    for k, v in headers.items():
        if count >= max_headers:
            break
        
        clean_key = _clean_string(k, 30)
        clean_value = _clean_string(v, 50)
        
        if clean_key and clean_value and clean_key != "N/A":
            result[clean_key] = clean_value
            count += 1
    
    return result

def _safe_list(items: List[str] | None, max_items: int = 4) -> List[str]:
    """Return a clean, limited list."""
    if not items:
        return []
    
    result = []
    for item in items[:max_items]:
        clean_item = _clean_string(item, 80)
        if clean_item and clean_item != "N/A":
            result.append(clean_item)
    
    return result

def build_prompt_from_docs(info_doc: Any, vuln_doc: Any) -> str:
    """Build a simple, safe prompt for JSON generation."""
    
    # Extract and clean data
    subdomain = _clean_string(getattr(info_doc, 'subdomain', ''), 50)
    status_code = _clean_string(getattr(info_doc, 'status_code', ''), 10)
    waf = _clean_string(getattr(info_doc, 'waf', ''), 20)
    
    headers = _safe_headers(getattr(info_doc, 'headers', None))
    issues = _safe_list(getattr(vuln_doc, 'issues', None))
    cves = _safe_list(getattr(vuln_doc, 'cves', None))
    
    # Create simple prompt
    prompt = f"""You are a cybersecurity analyst. Create a JSON risk assessment report.

INPUT DATA:
- Target: {subdomain or 'unknown'}
- Status: {status_code or 'unknown'}
- WAF: {waf or 'unknown'}
- Headers: {len(headers)} found
- Issues: {len(issues)} identified
- CVEs: {len(cves)} related

REQUIREMENTS:
1. Output valid JSON only
2. Use exactly this structure
3. Keep all strings under 100 characters
4. End with JSON_END marker

EXAMPLE:
{{
  "risk_score": 6.5,
  "priority_level": "medium",
  "subdomain": "example.com",
  "cvss": 6.0,
  "issues": ["Missing security headers", "Outdated server version"],
  "remediation": ["Add security headers", "Update server"],
  "headers": {{"Server": "Apache", "X-Frame-Options": "DENY"}},
  "summary": "Medium risk - security improvements needed"
}}
JSON_END

Based on the input data above, generate your JSON report:
"""

    return prompt.strip()