from datetime import datetime
from typing import Annotated, List, Optional
from typing import Optional, List

from beanie import Document, Indexed
from beanie.odm.fields import PydanticObjectId
from pydantic import Field

from app.api.models.BaseModelNoNone import BaseModelNoNone


class WebVulnerabilityAssessmentModel(Document,BaseModelNoNone):
    id: PydanticObjectId = Field(default_factory=PydanticObjectId, alias="_id")
    cve_data: Optional[List] = None
    
    class settings:
        name = "web_vulnerability_assessment"
    
    
class NetworkVulnerabilityAssessmentModel(Document,BaseModelNoNone):
    id: PydanticObjectId = Field(default_factory=PydanticObjectId, alias="_id")
    target: Annotated[str, Indexed(unique=True)]
    target_type: Optional[str]
    timestamp: datetime = Field(default_factory=datetime.now, alias="timestamp")
    vulnerabilities: Optional[List] = None
    
    class settings:
        name = "network_vulnerability_assessment"