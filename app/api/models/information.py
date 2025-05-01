from datetime import datetime
from typing import Any, List, Optional
from typing import Optional, Dict, List

from beanie import Document
from beanie.odm.fields import PydanticObjectId
from pydantic import BaseModel, Field


class WebInfoGatheringModel(Document):
    id: PydanticObjectId = Field(default_factory=PydanticObjectId, alias="_id")
    target: Optional[str]
    target_type: Optional[str]
    timestamp: datetime = Field(default_factory=datetime.now, alias="timestamp")
    archive_urls: Optional[List] = None
    certificate_details: Optional[List] = None
    cve_discoveries: Optional[List] = None
    directories: Optional[List[str]] = None
    email_enumerations: Optional[List] = None
    open_ports: Optional[List] = None
    server_info: Optional[List] = None
    subdomains: Optional[List] = None
    technology_info: Optional[List] = None
    username_enumerations: Optional[List] = None
    waf_detections: Optional[List] = None
    input_validation: Optional[List] = None
    https_headers: Optional[List[dict]] = None


    class Settings:
        name = "info_gathering"


        