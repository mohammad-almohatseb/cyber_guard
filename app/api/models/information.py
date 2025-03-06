from pydantic import BaseModel
from datetime import datetime
from typing import List, Dict, Any

class cvefindings(BaseModel):
    open_ports: List[str]
    server_version: List[str]
    waf_detection: List[str]
    technologies: List[str]
    certificate: List[str]
    dns_info: List[str]

class subdomainInfo(BaseModel):
    subdomain: str
    open_ports: List[int]
    server_info: Dict[str, str]
    waf_detection: str
    reverse_ip_lookup: List[str]
    email_enumeration: Dict[str, List[str]]
    technologies: List[str]
    javascript_data: Dict[str, List[str]]
    directory_enumeration: List[str]
    certificate_details: Dict[str, Any]
    login_portals: List[str]
    username_enumeration: List[str]
    security_headers: Dict[str, Any]
    dns_info: Dict[str, Any]
    internal_links: List[str]
    waybackurls: List[str]
    cve_findings: cvefindings


class DomainInfo(BaseModel):
    target_url: str
    subdomains: List[subdomainInfo]
    open_ports: List[int]
    server_info: Dict[str, str]
    waf_detection: str
    reverse_ip_lookup: List[str]
    email_enumeration: Dict[str, List[str]]
    technologies: List[str]
    javascript_data: Dict[str, List[str]]
    directory_enumeration: List[str]
    certificate_details: Dict[str, Any]
    login_portals: List[str]
    username_enumeration: List[str]
    security_headers: Dict[str, Any]
    dns_info: Dict[str, Any]
    internal_links: List[str]
    waybackurls: List[str]
    cve_findings: cvefindings
    created_at: datetime = datetime.utcnow()
