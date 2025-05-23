from datetime import timezone, datetime
from typing import Annotated, List, Optional
from typing import Optional, List

from beanie import Document, Indexed
from beanie.odm.fields import PydanticObjectId
from pydantic import Field

from app.api.models.BaseModelNoNone import BaseModelNoNone


class WebInfoGatheringModel(Document,BaseModelNoNone):
    id: PydanticObjectId = Field(default_factory=PydanticObjectId, alias="_id")
    target: Annotated[str, Indexed(unique=True)]
    target_type: Optional[str]
    archive_urls: Optional[List] = None
    certificate_details: Optional[List] = None
    cve_discoveries: Optional[List] = None
    directories: Optional[List[str]] = None
    open_ports: Optional[List] = None
    server_info: Optional[List] = None
    subdomains: Optional[List] = None
    technology_info: Optional[List] = None
    username_enumerations: Optional[List] = None
    waf_detections: Optional[List] = None
    input_validation: Optional[List] = None
    https_headers: Optional[List[dict]] = None
    
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc).replace(tzinfo=None)
        )

    class Settings:
        name = "web_info_gathering"
        
        
class NetworkInfoGathering(Document,BaseModelNoNone):
    id: PydanticObjectId = Field(default_factory=PydanticObjectId, alias="_id")
    target: Annotated[str, Indexed(unique=True)]
    alive_hosts: Optional[List] = None
    firewall_info: Optional[List] = None
    detected_services: Optional[List] = None
    os_detection: Optional[List] = None

    class Settings:
        name = "network_info_gathering"

        