from datetime import datetime
from typing import Annotated, List, Optional
from typing import Optional, List, Dict

from beanie import Document, Indexed
from beanie.odm.fields import PydanticObjectId
from pydantic import Field

from app.api.models.BaseModelNoNone import BaseModelNoNone


class WebVulnerabilityAssessmentModel(Document, BaseModelNoNone):
    id: PydanticObjectId = Field(default_factory=PydanticObjectId, alias="_id")

    target: Optional[str] = None
    waf_cve_data: Optional[List] = None
    server_cve_data: Optional[List] = None
    service_cve_data: Optional[List] = None
    dirictory_analysis_data: Optional[List] = None   # ← typo stays if intentional
    https_headers_data: Optional[List] = None
    certificate_data: Optional[List] = None
    all_expected_vulns: Optional[Dict[str, List]] = None
    class settings:
        name = "web_vulnerability_assessment"
    
    
class NetworkVulnerabilityAssessmentModel(Document,BaseModelNoNone):
    id: PydanticObjectId = Field(default_factory=PydanticObjectId, alias="_id")
    target: Annotated[str, Indexed(unique=True)]
    timestamp: Optional[datetime] = Field(default_factory=datetime.now, alias="timestamp")
    os_detection_data: Optional[List] = None
    waf_cve_data: Optional[List] = None
    detected_services_data: Optional[List] = None
    

    class settings:
        name = "network_vulnerability_assessment"