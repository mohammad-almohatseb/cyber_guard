from datetime import datetime, timezone
from beanie import Document, PydanticObjectId
from pydantic import Field

from app.api.models.BaseModelNoNone import BaseModelNoNone


class AiCollection(Document,BaseModelNoNone):
    id: PydanticObjectId = Field(default_factory=PydanticObjectId, alias="_id")
    report_type: str
    target: str
    prompt: str
    resutlt: dict
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc).replace(tzinfo=None))