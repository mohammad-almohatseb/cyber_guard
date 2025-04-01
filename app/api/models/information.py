from datetime import datetime
from typing import List, Optional

from beanie import Document
from beanie.odm.fields import PydanticObjectId
from pydantic import BaseModel, Field


class ArchiveURL(BaseModel):
    url: str
    timestamp: Optional[str] = None


class CertificateDetails(BaseModel):
    issuer: Optional[str] = None
    subject: Optional[str] = None
    valid_from: Optional[str] = None
    valid_to: Optional[str] = None


class CVEDiscovery(BaseModel):
    cve_id: str
    description: Optional[str] = None
    severity: Optional[str] = None


class DirectoryEnumeration(BaseModel):
    directory: str
    status_code: int


class DNSInformation(BaseModel):
    record_type: str
    record_value: str


class EmailEnumeration(BaseModel):
    email: str
    source: Optional[str] = None


class InternalLink(BaseModel):
    url: str
    anchor_text: Optional[str] = None


class LoginPortal(BaseModel):
    url: str
    method: Optional[str] = None


class OpenPort(BaseModel):
    ip: str
    port: int
    service: Optional[str] = None


class ReverseIPLookup(BaseModel):
    ip: str
    domains: List[str]


class SensitiveJSFile(BaseModel):
    url: str
    content_snippet: Optional[str] = None


class ServerInfo(BaseModel):
    ip: str
    server: Optional[str] = None
    version: Optional[str] = None


class Subdomain(BaseModel):
    subdomain: str
    ip: Optional[str] = None


class TechnologyInfo(BaseModel):
    name: str
    version: Optional[str] = None


class UsernameEnumeration(BaseModel):
    username: str
    source: Optional[str] = None


class WAFDetection(BaseModel):
    detected: bool
    vendor: Optional[str] = None


class WebInfoGatheringModel(Document):
    id: Optional[PydanticObjectId] = Field(default_factory=PydanticObjectId, alias="_id")
    target: str
    target_type: str  # "web" or "network"
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    archives_urls: List[ArchiveURL] = []
    certificate_details: List[CertificateDetails] = []
    cve_discoveries: List[CVEDiscovery] = []
    directories: List[DirectoryEnumeration] = []
    dns_information: List[DNSInformation] = []
    email_enumerations: List[EmailEnumeration] = []
    internal_links: List[InternalLink] = []
    login_portals: List[LoginPortal] = []
    open_ports: List[OpenPort] = []
    reverse_ip_lookups: List[ReverseIPLookup] = []
    sensitive_js_files: List[SensitiveJSFile] = []
    server_info: List[ServerInfo] = []
    subdomains: List[Subdomain] = []
    technology_info: List[TechnologyInfo] = []
    username_enumerations: List[UsernameEnumeration] = []
    waf_detections: List[WAFDetection] = []

    class Settings:
        # Specify the collection name
        name = "info_gathering"